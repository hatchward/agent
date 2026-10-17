import { chmod, mkdir, mkdtemp, readdir, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

/**
 * Recording fakes for the external commands the agent-image scripts call.
 *
 * Every invocation of a fake writes one record to `$FAKE_LOG/<seq>.<name>`:
 * argv NUL-separated on the first line, then the fake's entire environment as
 * `KEY=value` lines — so "not present" in a parsed record means unset, and a
 * negative assertion cannot pass by omission. Behaviour is
 * steered by FAKE_* variables the bodies below read. Assertions read the
 * records back with `calls()`; nothing asserts on the fake's own behaviour.
 */
export interface FakeBin {
  dir: string;
  log: string;
  root: string;
}

export interface Call {
  argv: string[];
  env: Record<string, string>;
}

const RECORDER = `
_fake_record() {
  n=$(ls "$FAKE_LOG" 2>/dev/null | wc -l | tr -d ' ')
  f="$FAKE_LOG/$(printf '%04d' "$n").$FAKE_NAME"
  : > "$f"
  for a in "$@"; do printf '%s\\0' "$a" >> "$f"; done
  printf '\\n' >> "$f"
  env >> "$f"
}
`;

const BODIES: Record<string, string> = {
  // Succeeds when the URL matches the FAKE_CURL_OK extended regex (a `-6`
  // request instead matches FAKE_CURL6_OK). Else exit 7.
  //
  // api.github.com/meta answers like the real endpoint: HTTP status
  // FAKE_CURL_META_STATUS (default 200) printed for `-w`, an `etag:` header
  // carrying FAKE_CURL_META_ETAG written to the `-D` file, and the body
  // FAKE_CURL_META_JSON written to the `-o` file on a 200. A request whose
  // If-None-Match equals FAKE_CURL_META_ETAG gets a 304 and no body.
  //
  // Proxy-mode canaries are distinguished by flag, not just URL, so a test can
  // pin the *shape* of the call the script makes, not only its outcome:
  //   --noproxy present  → a deliberately direct probe; governed by
  //                        FAKE_CURL_NOPROXY_OK / FAKE_CURL6_NOPROXY_OK (a `-6`
  //                        request uses the v6 variant). Defaults to failing
  //                        (exit 7), matching a working proxy-mode lockdown;
  //                        set the *_OK var to simulate the lockdown failing
  //                        open, which the script must treat as fatal.
  //   --proxy present    → the positive canary through the MITM proxy;
  //                        governed by FAKE_CURL_PROXY_OK. Records the
  //                        --cacert argument so a test can assert it was
  //                        given AGENT_CA_FILE.
  curl: `
url=""; v6=0; noproxy=0; proxied=0; out=""; hdr=""; wfmt=""; inm=""
prev=""
for a in "$@"; do
  case "$a" in http://*|https://*) url="$a";; -6) v6=1;; esac
  case "$prev" in
    --noproxy) noproxy=1;; --proxy) proxied=1;;
    -o) out="$a";; -D) hdr="$a";; -w) wfmt="$a";;
    -H) case "$a" in "If-None-Match: "*) inm="\${a#If-None-Match: }";; esac;;
  esac
  prev="$a"
done
if [ "$proxied" = 1 ]; then
  ok="\${FAKE_CURL_PROXY_OK-}"
  if [ -n "$ok" ] && printf '%s' "$url" | grep -Eq "$ok"; then exit 0; fi
  exit 7
fi
if [ "$noproxy" = 1 ]; then
  ok="\${FAKE_CURL_NOPROXY_OK-}"; [ "$v6" = 0 ] || ok="\${FAKE_CURL6_NOPROXY_OK-}"
  if [ -n "$ok" ] && printf '%s' "$url" | grep -Eq "$ok"; then exit 0; fi
  exit 7
fi
ok="\${FAKE_CURL_OK-}"; [ "$v6" = 0 ] || ok="\${FAKE_CURL6_OK-}"
if [ -n "$ok" ] && printf '%s' "$url" | grep -Eq "$ok"; then
  case "$url" in *api.github.com/meta*)
    status="\${FAKE_CURL_META_STATUS-200}"
    etag="\${FAKE_CURL_META_ETAG-}"
    if [ -n "$etag" ] && [ "$inm" = "$etag" ]; then status=304; fi
    if [ -n "$hdr" ]; then
      printf 'HTTP/2 %s\\r\\n' "$status" > "$hdr"
      [ -z "$etag" ] || printf 'etag: %s\\r\\n' "$etag" >> "$hdr"
    fi
    body=""; [ "$status" != 200 ] || body="\${FAKE_CURL_META_JSON-}"
    if [ -n "$out" ]; then printf '%s' "$body" > "$out"; else printf '%s' "$body"; fi
    [ -z "$wfmt" ] || printf '%s' "$status"
    ;;
  esac
  exit 0
fi
[ -z "$wfmt" ] || printf '000'
exit 7
`,
  // getent ahostsv4 <host> → FAKE_GETENT_MAP="host=ip ip;host2=ip" (always
  // exit 0, matching real getent's "printed nothing" shape when a domain
  // resolves to nothing). FAKE_GETENT_MAP_<n>, when set, replaces it once the
  // `sleep` fake has run n times — the refresher's tick n.
  //
  // getent hosts <host> is the proxy-mode DNS canary: it fails (exit 2, nothing printed) unless the host is listed in
  // FAKE_GETENT_HOSTS_OK (comma-separated) — simulating DNS staying reachable
  // despite the lockdown, which the script must treat as fatal.
  getent: `
sub="$1"; host="$2"
case "$sub" in
  hosts)
    if printf '%s\\n' "\${FAKE_GETENT_HOSTS_OK-}" | tr ',' '\\n' | grep -qx "$host"; then
      printf '203.0.113.5 %s\\n' "$host"
      exit 0
    fi
    exit 2
    ;;
esac
n=$(ls "$FAKE_LOG" | grep -c '[.]sleep$')
eval "map=\\\${FAKE_GETENT_MAP_$n-\\\${FAKE_GETENT_MAP-}}"
printf '%s\\n' "$map" | tr ';' '\\n' | while IFS='=' read -r h ips; do
  if [ "$h" = "$host" ]; then
    for ip in $ips; do printf '%s STREAM %s\\n' "$ip" "$host"; done
  fi
done
exit 0
`,
  // ip -o link show → FAKE_IP_LINKS (';'-separated lines); ip -6 route show default → FAKE_IP6_ROUTE
  ip: `
case "$*" in
  *"-6 route show default"*) [ -z "\${FAKE_IP6_ROUTE-}" ] || printf '%s\\n' "$FAKE_IP6_ROUTE";;
  *"link show"*) printf '%s\\n' "\${FAKE_IP_LINKS-1: lo: <LOOPBACK,UP>}" | tr ';' '\\n';;
esac
exit 0
`,
  iptables: `[ "\${FAKE_IPTABLES_FAIL-0}" = "1" ] && exit 1; exit 0`,
  ip6tables: `[ "\${FAKE_IP6TABLES_FAIL-0}" = "1" ] && exit 1; exit 0`,
  // update-ca-certificates takes no meaningful args in this repo's usage; just record the call.
  "update-ca-certificates": `exit 0`,
};

/**
 * Writes a real, valid self-signed EC certificate (PEM) to `path` using the
 * system `openssl` — so proxy-mode CA validation tests exercise the actual
 * `openssl x509 -noout` check the script runs, not a stand-in for it.
 */
export async function makeTestCert(path: string): Promise<void> {
  const key = `${path}.key`;
  const proc = Bun.spawn(
    [
      "openssl",
      "req",
      "-x509",
      "-newkey",
      "ec",
      "-pkeyopt",
      "ec_paramgen_curve:prime256v1",
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=hatchward-proxy-smoke",
      "-keyout",
      key,
      "-out",
      path,
    ],
    { stdout: "ignore", stderr: "ignore" },
  );
  const code = await proc.exited;
  if (code !== 0)
    throw new Error("openssl failed to generate a test certificate");
}

export async function makeFakeBin(
  names: string[],
  extra: Record<string, string> = {},
): Promise<FakeBin> {
  const root = await mkdtemp(join(tmpdir(), "hatchward-agent-fakes-"));
  const dir = join(root, "bin");
  const log = join(root, "log");
  await mkdir(dir);
  await mkdir(log);
  for (const name of names) {
    const body = extra[name] ?? BODIES[name] ?? "exit 0\n";
    await Bun.write(
      join(dir, name),
      `#!/bin/sh\nFAKE_NAME=${name}\n${RECORDER}\n_fake_record "$@"\n${body}\n`,
    );
    await chmod(join(dir, name), 0o755);
  }
  return { dir, log, root };
}

async function parseRecord(path: string): Promise<Call> {
  const text = await readFile(path, "utf8");
  const newline = text.indexOf("\n");
  const argvPart = text.slice(0, newline);
  const argv = argvPart.split("\0");
  argv.pop(); // trailing NUL terminator
  const env: Record<string, string> = {};
  for (const line of text.slice(newline + 1).split("\n")) {
    const eq = line.indexOf("=");
    // `env` prints one line per variable; a continuation line of a multi-line
    // value has no '=' at a sane position and is not a variable of interest.
    if (eq <= 0 || !/^[A-Za-z_][A-Za-z0-9_]*$/u.test(line.slice(0, eq)))
      continue;
    env[line.slice(0, eq)] = line.slice(eq + 1);
  }
  return { argv, env };
}

/** Every recorded invocation of `name`, in call order. */
export async function calls(fake: FakeBin, name: string): Promise<Call[]> {
  const files = (await readdir(fake.log))
    .filter((f) => f.endsWith(`.${name}`))
    .sort();
  return Promise.all(files.map((f) => parseRecord(join(fake.log, f))));
}

/** Every recorded invocation of any fake, in global call order. */
export async function sequence(
  fake: FakeBin,
): Promise<{ name: string; argv: string[] }[]> {
  const files = (await readdir(fake.log)).sort();
  return Promise.all(
    files.map(async (f) => ({
      name: f.slice(f.indexOf(".") + 1),
      argv: (await parseRecord(join(fake.log, f))).argv,
    })),
  );
}

export interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

/**
 * Runs a script with the fake bin first on PATH and only the environment
 * given here (plus the recorder wiring). Nothing from the test process's
 * own environment leaks in, so a decoy set there cannot satisfy an assertion.
 */
export async function runScript(
  script: string,
  fake: FakeBin,
  env: Record<string, string>,
  options: { stdin?: string; args?: string[] } = {},
): Promise<RunResult> {
  const child = Bun.spawn(["bash", script, ...(options.args ?? [])], {
    env: {
      PATH: `${fake.dir}:/usr/bin:/bin`,
      FAKE_LOG: fake.log,
      ...env,
    },
    stdin: options.stdin === undefined ? "ignore" : new Blob([options.stdin]),
    stdout: "pipe",
    stderr: "pipe",
  });
  const [stdout, stderr, code] = await Promise.all([
    new Response(child.stdout).text(),
    new Response(child.stderr).text(),
    child.exited,
  ]);
  return { code, stdout, stderr };
}

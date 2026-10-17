import { afterEach, expect, test } from "bun:test";
import { chmod, mkdir, mkdtemp, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  calls,
  makeFakeBin,
  makeTestCert,
  runScript,
  sequence,
} from "./lib/fakes";

const script = join(import.meta.dir, "../agent-entrypoint.sh");
const cleanups: (() => Promise<void>)[] = [];

afterEach(async () => {
  await Promise.all(cleanups.splice(0).map((c) => c()));
});

// setpriv is the privilege-drop seam. Its fake records the call, then runs the
// command it was asked to drop into (`env HOME=... PATH=... <cmd>`), so the
// commands the entrypoint runs "as agent" are themselves recorded as fakes.
const SETPRIV_BODY = `
while [ $# -gt 0 ]; do
  case "$1" in
    --no-new-privs) shift; break;;
    *) shift;;
  esac
done
exec "$@"
`;

// A stand-in for the CMD: records argv/env like every fake and reports how
// many bytes reached its stdin.
const FINAL_BODY = `printf 'stdin_bytes=%s stdin_is_devnull=%s\\n' "$(cat | wc -c | tr -d ' ')" "$([ /dev/stdin -ef /dev/null ] && echo 1 || echo 0)"`;

// git: symbolic-ref answers with FAKE_GIT_DEFAULT_BRANCH; check-ref-format
// refuses names starting with '-'; everything else succeeds silently.
const GIT_BODY = `
case "$*" in
  *"symbolic-ref --short refs/remotes/origin/HEAD"*) printf 'origin/%s\\n' "\${FAKE_GIT_DEFAULT_BRANCH-main}";;
  *"check-ref-format --branch -"*) exit 1;;
esac
exit 0
`;

// gh: `auth login --with-token` consumes stdin; record what it received so the
// test can prove the token travelled on stdin and nowhere else.
const GH_BODY = `
case "$*" in
  *"auth login --with-token"*) cat > "$FAKE_LOG/gh-login-stdin";;
esac
exit 0
`;

// stat -c %u <path>: FAKE_STAT_UIDS="<path>=<uid>;<path>=<uid>" per path, else FAKE_STAT_UID, else 1000.
const STAT_BODY = `
u="$(printf '%s\\n' "\${FAKE_STAT_UIDS-}" | tr ';' '\\n' | awk -F= -v p="$3" '$1==p{print $2}')"
printf '%s\\n' "\${u:-\${FAKE_STAT_UID-1000}}"`;
const ID_BODY = `printf '1000\\n'`;

const FAKES = [
  "init-firewall",
  "setpriv",
  "final",
  "git",
  "gh",
  "stat",
  "id",
  "chown",
  "update-ca-certificates",
];

async function fixture(options: { git?: boolean; files?: string[] } = {}) {
  const fake = await makeFakeBin(FAKES, {
    setpriv: SETPRIV_BODY,
    final: FINAL_BODY,
    git: GIT_BODY,
    gh: GH_BODY,
    stat: STAT_BODY,
    id: ID_BODY,
  });
  const work = await mkdtemp(join(tmpdir(), "hatchward-entrypoint-"));
  cleanups.push(() => rm(fake.root, { force: true, recursive: true }));
  cleanups.push(() => rm(work, { force: true, recursive: true }));
  const workspace = join(work, "workspace");
  const home = join(work, "home");
  const runDir = join(work, "run");
  await mkdir(workspace);
  await mkdir(home);
  await mkdir(runDir);
  if (options.git) await mkdir(join(workspace, ".git"));
  for (const f of options.files ?? []) await Bun.write(join(workspace, f), "");
  return { fake, work, workspace, home, runDir };
}

function baseEnv(
  f: { workspace: string; home: string; runDir: string },
  extra: Record<string, string> = {},
) {
  return {
    AGENT_WORKSPACE: f.workspace,
    AGENT_HOME: f.home,
    AGENT_RUN_DIR: f.runDir,
    ...extra,
  };
}

async function run(
  f: { fake: Awaited<ReturnType<typeof fixture>>["fake"] } & {
    workspace: string;
    home: string;
    runDir: string;
  },
  extra: Record<string, string> = {},
  options: { stdin?: string } = {},
) {
  return runScript(script, f.fake, baseEnv(f, extra), {
    args: ["final"],
    ...options,
  });
}

test("the firewall runs before anything else and the command is exec'd as agent with dropped privileges", async () => {
  const f = await fixture({ git: true });
  const r = await run(f);
  expect(r.code).toBe(0);
  const seq = await sequence(f.fake);
  expect(seq[0]?.name).toBe("init-firewall");
  const drops = await calls(f.fake, "setpriv");
  const last = drops.at(-1);
  expect(last?.argv.slice(0, 6)).toEqual([
    "--reuid=agent",
    "--regid=agent",
    "--init-groups",
    "--inh-caps=-all",
    "--bounding-set=-all",
    "--no-new-privs",
  ]);
  const envIndex = last?.argv.indexOf("env") ?? -1;
  expect(envIndex).toBeGreaterThan(0);
  expect(last?.argv.at(-1)).toBe("final");
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.HOME).toBe(f.home);
  expect(final?.env.PATH).toContain(`${f.home}/.local/bin`);
});

test("provisioning output goes to stderr and fd 1 is left to the command", async () => {
  const f = await fixture({ git: true });
  const r = await run(f);
  expect(r.stdout).toBe("stdin_bytes=0 stdin_is_devnull=1\n");
});

test("a provided workspace with .git and no AGENT_REPO is left untouched", async () => {
  const f = await fixture({ git: true });
  const r = await run(f);
  expect(r.code).toBe(0);
  const git = (await calls(f.fake, "git")).map((c) => c.argv.join(" "));
  expect(git.some((a) => /clone|fetch|reset|checkout|clean/.test(a))).toBe(
    false,
  );
});

test("an empty workspace with no AGENT_REPO warns but still runs the command", async () => {
  const f = await fixture();
  const r = await run(f);
  expect(r.code).toBe(0);
  expect(r.stderr).toContain(
    "agent-entrypoint: WARNING — /workspace is empty and AGENT_REPO is unset; nothing to provision",
  );
  expect(await calls(f.fake, "final")).toHaveLength(1);
});

test("self-clone mode clones an empty workspace over HTTPS with plain git, then syncs to the branch tip", async () => {
  const f = await fixture();
  const r = await run(f, {
    AGENT_REPO: "octocat/Hello-World",
    AGENT_BASE_BRANCH: "release",
    AGENT_CLONE_ARGS: "--filter=blob:none",
  });
  expect(r.code).toBe(0);
  const git = (await calls(f.fake, "git")).map((c) => c.argv);
  expect(git[0]).toEqual([
    "-C",
    f.workspace,
    "check-ref-format",
    "--branch",
    "release",
  ]);
  expect(git[1]).toEqual([
    "clone",
    "-q",
    "--filter=blob:none",
    "--branch",
    "release",
    "https://github.com/octocat/Hello-World.git",
    f.workspace,
  ]);
  const rest = git.slice(2).map((a) => a.join(" "));
  const inWorkspace = `-C ${f.workspace}`;
  expect(rest).toEqual([
    `${inWorkspace} remote set-head origin --auto`,
    `${inWorkspace} fetch -q origin +refs/heads/release:refs/remotes/origin/release`,
    `${inWorkspace} checkout -q -B release origin/release`,
    `${inWorkspace} reset -q --hard origin/release`,
    `${inWorkspace} clean -q -fd`,
    `${inWorkspace} worktree prune`,
    `${inWorkspace} submodule -q update --init --recursive`,
    `config --global --add safe.directory ${f.workspace}`,
    "config --global user.name hatchward-agent",
    "config --global user.email agent@hatchward.invalid",
  ]);
  // Every git call ran as agent, not root.
  const drops = await calls(f.fake, "setpriv");
  expect(drops.filter((d) => d.argv.includes("git"))).toHaveLength(git.length);
});

test("self-clone mode accepts a full https URL and defaults the branch to origin's HEAD", async () => {
  const f = await fixture({ git: true });
  const r = await run(f, {
    AGENT_REPO: "https://gitlab.example/group/repo.git",
    FAKE_GIT_DEFAULT_BRANCH: "develop",
  });
  expect(r.code).toBe(0);
  const git = (await calls(f.fake, "git")).map((c) => c.argv.join(" "));
  expect(git.some((a) => a.startsWith("clone"))).toBe(false);
  expect(git).toContain(
    `-C ${f.workspace} symbolic-ref --short refs/remotes/origin/HEAD`,
  );
  expect(git).toContain(
    `-C ${f.workspace} checkout -q -B develop origin/develop`,
  );
});

test("an AGENT_REPO that is not owner/name or an https URL is fatal before any network call", async () => {
  for (const bad of ["-evil", "a/b/c", "ssh://git@github.com/a/b", "a b/c"]) {
    const f = await fixture();
    const r = await run(f, { AGENT_REPO: bad });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      `agent-entrypoint: FATAL — AGENT_REPO '${bad}' must be owner/name or an https:// URL`,
    );
    expect(await calls(f.fake, "git")).toHaveLength(0);
  }
});

test("an AGENT_REPO URL carrying credentials is fatal", async () => {
  const f = await fixture();
  const r = await run(f, {
    AGENT_REPO: "https://x:ghp_sentinel@github.com/o/r",
  });
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_REPO must not carry credentials; use GH_TOKEN_FILE",
  );
  expect(r.stderr).not.toContain("ghp_sentinel");
  expect(await calls(f.fake, "git")).toHaveLength(0);
});

test("an AGENT_WORKDIR that escapes the workspace is fatal", async () => {
  for (const bad of ["../etc", "/etc", "apps/../../x", ".."]) {
    const f = await fixture({ git: true });
    const r = await run(f, { AGENT_WORKDIR: bad });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      `agent-entrypoint: FATAL — AGENT_WORKDIR '${bad}' must be a relative path inside /workspace`,
    );
    expect(await calls(f.fake, "final")).toHaveLength(0);
  }
});

test("a variable outside AGENT_STAGE_VARS is not staged and reaches the command untouched", async () => {
  const f = await fixture({ git: true });
  await run(f, { OPENAI_API_KEY: "not-a-secret-here" });
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.OPENAI_API_KEY).toBe("not-a-secret-here");
  await expect(
    stat(join(f.runDir, "secrets/openai_api_key")),
  ).rejects.toThrow();
});

test("an AGENT_BASE_BRANCH that git refuses is fatal", async () => {
  const f = await fixture();
  const r = await run(f, { AGENT_REPO: "o/r", AGENT_BASE_BRANCH: "-x" });
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_BASE_BRANCH '-x' is not a valid branch name",
  );
});

test("a workspace owned by another uid is chowned recursively; an agent-owned one is not touched", async () => {
  const foreign = await fixture({ git: true });
  await run(foreign, { FAKE_STAT_UID: "0" });
  expect((await calls(foreign.fake, "chown")).map((c) => c.argv)).toEqual([
    ["-R", "agent:agent", foreign.workspace],
  ]);
  const owned = await fixture({ git: true });
  await run(owned, { FAKE_STAT_UID: "1000" });
  expect(await calls(owned.fake, "chown")).toHaveLength(0);
  // The docker cp shape: the directory is agent-owned, its contents are root's.
  const copied = await fixture({ git: true });
  await run(copied, {
    FAKE_STAT_UIDS: `${copied.workspace}=1000;${join(copied.workspace, ".git")}=0`,
  });
  expect((await calls(copied.fake, "chown")).map((c) => c.argv)).toEqual([
    ["-R", "agent:agent", copied.workspace],
  ]);
});

test("a non-TTY stdin is captured to the manifest file and the command's stdin is /dev/null", async () => {
  const f = await fixture({ git: true });
  const manifest = '{"agent":{"prompt":"hi"}}';
  const r = await run(f, {}, { stdin: manifest });
  expect(r.code).toBe(0);
  expect(await Bun.file(join(f.runDir, "manifest.json")).text()).toBe(manifest);
  expect((await stat(join(f.runDir, "manifest.json"))).mode & 0o777).toBe(
    0o600,
  );
  expect((await calls(f.fake, "chown")).map((c) => c.argv)).toContainEqual([
    "agent:agent",
    join(f.runDir, "manifest.json"),
  ]);
  expect(r.stdout).toBe("stdin_bytes=0 stdin_is_devnull=1\n");
});

test("secret files are copied for the agent, the _FILE variables are re-pointed, and values never enter argv", async () => {
  const f = await fixture({ git: true });
  const key = join(f.work, "anthropic");
  const gh = join(f.work, "github");
  await Bun.write(key, "sk-sentinel-anthropic\n");
  await Bun.write(gh, "ghp_sentinel\n");
  const r = await run(f, {
    AGENT_STAGE_VARS: "GH_TOKEN ANTHROPIC_API_KEY",
    ANTHROPIC_API_KEY_FILE: key,
    GH_TOKEN_FILE: gh,
  });
  expect(r.code).toBe(0);
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.ANTHROPIC_API_KEY_FILE).toBe(
    join(f.runDir, "secrets/anthropic_api_key"),
  );
  expect(final?.env.GH_TOKEN_FILE).toBe(join(f.runDir, "secrets/gh_token"));
  expect(final?.env.GH_TOKEN).toBeUndefined();
  expect(final?.env.ANTHROPIC_API_KEY).toBeUndefined();
  expect(
    await Bun.file(join(f.runDir, "secrets/anthropic_api_key")).text(),
  ).toBe("sk-sentinel-anthropic\n");
  expect(
    (await stat(join(f.runDir, "secrets/anthropic_api_key"))).mode & 0o777,
  ).toBe(0o400);
  // The directory is handed to the agent after every copy is written: root
  // (no CAP_DAC_OVERRIDE) cannot create files in a directory it does not own,
  // and the agent cannot traverse one root owns.
  expect((await stat(join(f.runDir, "secrets"))).mode & 0o777).toBe(0o700);
  const chowns = (await calls(f.fake, "chown")).map((c) => c.argv.join(" "));
  const dirChown = chowns.indexOf(`agent:agent ${join(f.runDir, "secrets")}`);
  const lastFileChown = Math.max(
    chowns.indexOf(
      `agent:agent ${join(f.runDir, "secrets/anthropic_api_key")}`,
    ),
    chowns.indexOf(`agent:agent ${join(f.runDir, "secrets/gh_token")}`),
  );
  expect(dirChown).toBeGreaterThan(lastFileChown);
  // gh receives the token on stdin, once, and configures git.
  expect(await Bun.file(join(f.fake.log, "gh-login-stdin")).text()).toBe(
    "ghp_sentinel\n",
  );
  const ghCalls = (await calls(f.fake, "gh")).map((c) => c.argv.join(" "));
  expect(ghCalls).toEqual(["auth login --with-token", "auth setup-git"]);
  // No recorded argv anywhere carries a secret value.
  const everything = (await sequence(f.fake)).flatMap((s) => s.argv);
  expect(everything.join("\n")).not.toContain("sentinel");
  expect(r.stdout + r.stderr).not.toContain("sentinel");
});

test("a secret passed as a plain variable is staged to a file and removed from the environment", async () => {
  const f = await fixture({ git: true });
  const r = await run(f, { GH_TOKEN: "ghp_sentinel_plain" });
  expect(r.code).toBe(0);
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.GH_TOKEN).toBeUndefined();
  expect(final?.env.GH_TOKEN_FILE).toBe(join(f.runDir, "secrets/gh_token"));
  expect(await Bun.file(join(f.runDir, "secrets/gh_token")).text()).toBe(
    "ghp_sentinel_plain\n",
  );
  expect(await Bun.file(join(f.fake.log, "gh-login-stdin")).text()).toBe(
    "ghp_sentinel_plain\n",
  );
  const everything = (await sequence(f.fake)).flatMap((s) => s.argv);
  expect(everything.join("\n")).not.toContain("sentinel");
});

test("without a GitHub token, gh is never invoked", async () => {
  const f = await fixture({ git: true });
  await run(f);
  expect(await calls(f.fake, "gh")).toHaveLength(0);
});

test("AGENT_WORKDIR is where the command starts and CLAUDE_PROJECT_DIR follows it", async () => {
  const f = await fixture({ git: true });
  await mkdir(join(f.workspace, "apps/api"), { recursive: true });
  const final = await makeFakeBin(["final"], { final: "pwd" });
  cleanups.push(() => rm(final.root, { force: true, recursive: true }));
  const r = await runScript(
    script,
    f.fake,
    {
      ...baseEnv(f, { AGENT_WORKDIR: "apps/api" }),
      PATH: `${f.fake.dir}:${final.dir}:/usr/bin:/bin`,
    },
    { args: ["sh", "-c", "pwd; printf '%s\\n' \"$CLAUDE_PROJECT_DIR\""] },
  );
  expect(r.code).toBe(0);
  expect(r.stdout).toBe(
    `${join(f.workspace, "apps/api")}\n${join(f.workspace, "apps/api")}\n`,
  );
});

test("HATCHWARD_ASSIGNMENT_ACTION_SOCKET passes through to the command untouched", async () => {
  const f = await fixture({ git: true });
  await run(f, {
    HATCHWARD_ASSIGNMENT_ACTION_SOCKET: "/run/hatchward/actions.sock",
  });
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.HATCHWARD_ASSIGNMENT_ACTION_SOCKET).toBe(
    "/run/hatchward/actions.sock",
  );
});

// --- Proxy mode (contract 2) -------------------------------------------------
// AGENT_PROXY_URL set: before init-firewall runs at all, the runner's CA must
// be trusted and a set of client-specific env vars exported so every
// downstream tool (git, gh, the final command) routes through the proxy and
// trusts its MITM leaf. AGENT_CA_TRUST_DIR stands in for
// /usr/local/share/ca-certificates so the test never touches the real trust
// store.

const PROXY_URL = "http://hatchward:tok3n@10.99.0.1:18080";

async function proxyFixture(options: { git?: boolean } = {}) {
  const f = await fixture(options);
  const caFile = join(f.work, "proxy-ca.pem");
  await makeTestCert(caFile);
  const trustDir = join(f.work, "ca-trust");
  await mkdir(trustDir);
  return { ...f, caFile, trustDir };
}

function proxyEnv(
  f: {
    workspace: string;
    home: string;
    runDir: string;
    caFile: string;
    trustDir: string;
  },
  extra: Record<string, string> = {},
) {
  return baseEnv(f, {
    AGENT_PROXY_URL: PROXY_URL,
    AGENT_CA_FILE: f.caFile,
    AGENT_CA_TRUST_DIR: f.trustDir,
    ...extra,
  });
}

test("proxy mode: the CA is installed before init-firewall and before the first setpriv", async () => {
  const f = await proxyFixture({ git: true });
  const r = await run(f, proxyEnv(f));
  expect(r.code).toBe(0);
  const seq = await sequence(f.fake);
  const updateCa = seq.findIndex((s) => s.name === "update-ca-certificates");
  const firewall = seq.findIndex((s) => s.name === "init-firewall");
  const firstSetpriv = seq.findIndex((s) => s.name === "setpriv");
  expect(updateCa).toBeGreaterThan(-1);
  expect(updateCa).toBeLessThan(firewall);
  expect(updateCa).toBeLessThan(firstSetpriv);
  expect(await Bun.file(join(f.trustDir, "hatchward-proxy.crt")).text()).toBe(
    await Bun.file(f.caFile).text(),
  );
});

test("proxy mode: a missing AGENT_CA_FILE is fatal before anything runs", async () => {
  const f = await proxyFixture({ git: true });
  const env = proxyEnv(f);
  delete (env as Record<string, string>).AGENT_CA_FILE;
  const r = await run(f, env);
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_CA_FILE is required and must be readable when AGENT_PROXY_URL is set",
  );
  expect(await calls(f.fake, "final")).toHaveLength(0);
  expect(await calls(f.fake, "init-firewall")).toHaveLength(0);
});

test("proxy mode: an unreadable AGENT_CA_FILE is fatal before anything runs", async () => {
  const f = await proxyFixture({ git: true });
  const r = await run(
    f,
    proxyEnv(f, { AGENT_CA_FILE: join(f.work, "does-not-exist.pem") }),
  );
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_CA_FILE is required and must be readable when AGENT_PROXY_URL is set",
  );
  expect(await calls(f.fake, "final")).toHaveLength(0);
});

test("proxy mode: a non-PEM AGENT_CA_FILE is fatal before anything runs", async () => {
  const f = await proxyFixture({ git: true });
  const notPem = join(f.work, "not-a-cert.pem");
  await Bun.write(notPem, "this is definitely not a certificate\n");
  const r = await run(f, proxyEnv(f, { AGENT_CA_FILE: notPem }));
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    `agent-entrypoint: FATAL — AGENT_CA_FILE '${notPem}' is not a valid PEM certificate`,
  );
  expect(await calls(f.fake, "final")).toHaveLength(0);
  expect(await calls(f.fake, "update-ca-certificates")).toHaveLength(0);
});

test("proxy mode: AGENT_FIREWALL=0 is refused", async () => {
  const f = await proxyFixture({ git: true });
  const r = await run(f, proxyEnv(f, { AGENT_FIREWALL: "0" }));
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_FIREWALL=0 is not allowed when AGENT_PROXY_URL is set",
  );
  expect(await calls(f.fake, "final")).toHaveLength(0);
  expect(await calls(f.fake, "init-firewall")).toHaveLength(0);
});

test("proxy mode: a NO_PROXY carrying anything but loopback names is refused", async () => {
  const f = await proxyFixture({ git: true });
  for (const bad of ["github.com", "localhost,api.anthropic.com", "*"]) {
    const r = await run(f, proxyEnv(f, { NO_PROXY: bad }));
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(
      `agent-entrypoint: FATAL — NO_PROXY '${bad}' must contain only loopback names when AGENT_PROXY_URL is set`,
    );
    expect(await calls(f.fake, "final")).toHaveLength(0);
  }
  // lower-case no_proxy is checked too.
  const r = await run(f, proxyEnv(f, { no_proxy: "evil.example" }));
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — NO_PROXY 'evil.example' must contain only loopback names when AGENT_PROXY_URL is set",
  );
});

test("proxy mode: a loopback-only NO_PROXY is accepted", async () => {
  const f = await proxyFixture({ git: true });
  const r = await run(f, proxyEnv(f, { NO_PROXY: "localhost,127.0.0.1,::1" }));
  expect(r.code).toBe(0);
  expect(await calls(f.fake, "final")).toHaveLength(1);
});

test("proxy mode: AGENT_ALLOW_DOMAINS is ignored with a warning, not a fatal error", async () => {
  const f = await proxyFixture({ git: true });
  const r = await run(f, proxyEnv(f, { AGENT_ALLOW_DOMAINS: "extra.example" }));
  expect(r.code).toBe(0);
  expect(r.stderr).toContain(
    "agent-entrypoint: WARNING — AGENT_ALLOW_DOMAINS is ignored when AGENT_PROXY_URL is set (proxy allowlist is enforced by the runner)",
  );
});

test("proxy mode: the proxy env vars reach git, gh and the final command, and git is configured system-wide", async () => {
  const f = await proxyFixture({ git: true });
  const r = await run(f, proxyEnv(f, { GH_TOKEN: "hatchward-proxy-managed" }));
  expect(r.code).toBe(0);
  const expected: Record<string, string> = {
    NODE_EXTRA_CA_CERTS: f.caFile,
    SSL_CERT_FILE: f.caFile,
    SSL_CERT_DIR: "/etc/ssl/certs",
    CURL_CA_BUNDLE: f.caFile,
    GIT_SSL_CAINFO: f.caFile,
    REQUESTS_CA_BUNDLE: f.caFile,
    PIP_CERT: f.caFile,
    CARGO_HTTP_CAINFO: f.caFile,
    AWS_CA_BUNDLE: f.caFile,
    DENO_CERT: "/etc/ssl/certs/ca-certificates.crt",
    DENO_TLS_CA_STORE: "system,mozilla",
    UV_NATIVE_TLS: "1",
    NODE_USE_ENV_PROXY: "1",
    CARGO_NET_GIT_FETCH_WITH_CLI: "true",
  };
  const final = (await calls(f.fake, "final")).at(-1);
  for (const [k, v] of Object.entries(expected)) {
    expect(final?.env[k]).toBe(v);
  }
  // Every git and gh invocation during provisioning saw the full var set too —
  // not just one representative variable each. Provisioning runs before the
  // final command, so an implementation that exports these only right before
  // the final exec would leave git/gh unable to reach a MITM proxy in
  // reality; nothing checking a single variable per tool would catch that.
  const anyGit = (await calls(f.fake, "git")).at(0);
  const ghCall = (await calls(f.fake, "gh")).at(0);
  for (const [k, v] of Object.entries(expected)) {
    expect(anyGit?.env[k]).toBe(v);
    expect(ghCall?.env[k]).toBe(v);
  }
  // git is configured system-wide with the proxy and its CA.
  const gitConfigs = (await calls(f.fake, "git")).map((c) => c.argv.join(" "));
  expect(gitConfigs).toContain(`config --system http.proxy ${PROXY_URL}`);
  expect(gitConfigs).toContain(`config --system http.sslCAInfo ${f.caFile}`);
});

// --- Project setup (AGENT_SETUP) ---------------------------------------------
// The workspace ships an executable bin/setup that hands off to the recording
// `setup-probe` fake, so the setup step shows up in the global call sequence
// with its argv, environment and working directory. `timeout` is faked as well
// (macOS has none): it runs the command and returns 124 if it outlives the
// limit, the shape GNU timeout gives the entrypoint.

const TIMEOUT_BODY = `
while [ $# -gt 0 ]; do
  case "$1" in
    -k) shift 2;;
    -*) shift;;
    *) break;;
  esac
done
secs="$1"; shift
mark="$FAKE_LOG.timed-out"
"$@" & pid=$!
(
  sleep "$secs" & s=$!
  trap 'kill "$s"; exit 0' TERM
  wait "$s"; touch "$mark"; kill -TERM "$pid"
) >/dev/null 2>&1 & watcher=$!
wait "$pid"; rc=$?
kill "$watcher" 2>/dev/null
[ -e "$mark" ] && exit 124
exit "$rc"
`;

const PROBE_BODY = `
pwd > "$FAKE_LOG.setup-pwd"
echo setup-says-stdout
echo setup-says-stderr >&2
[ -z "\${FAKE_SETUP_SLEEP-}" ] || exec sleep "$FAKE_SETUP_SLEEP"
exit "\${FAKE_SETUP_EXIT-0}"
`;

const SETUP_SCRIPT = `#!/bin/sh\nexec setup-probe "$@"\n`;

async function setupFixture(
  options: { dir?: string; script?: string; mode?: number } = {},
) {
  const f = await fixture({ git: true });
  const extra = await makeFakeBin(["setup-probe", "timeout"], {
    "setup-probe": PROBE_BODY,
    timeout: TIMEOUT_BODY,
  });
  cleanups.push(() => rm(extra.root, { force: true, recursive: true }));
  // Share one log so the probe lands in the same sequence as the other fakes.
  const fake = { ...f.fake, dir: `${f.fake.dir}:${extra.dir}` };
  const binDir = join(f.workspace, options.dir ?? "", "bin");
  await mkdir(binDir, { recursive: true });
  const path = join(binDir, options.script ?? "setup");
  await Bun.write(path, SETUP_SCRIPT);
  await chmod(path, options.mode ?? 0o755);
  return { ...f, fake };
}

const SETUP_ENV = { AGENT_REPO: "o/r", AGENT_SETUP: "bin/setup --quiet" };

test("setup: unset leaves the boot unchanged and logs nothing about setup", async () => {
  const f = await setupFixture();
  const r = await run(f, { AGENT_REPO: "o/r" });
  expect(r.code).toBe(0);
  expect(r.stderr).not.toContain("setup");
  expect(await calls(f.fake, "setup-probe")).toHaveLength(0);
  expect(await calls(f.fake, "timeout")).toHaveLength(0);
});

test("setup: runs after the tree is synced and git is configured, in the project dir, before the command", async () => {
  const f = await setupFixture();
  const r = await run(f, SETUP_ENV);
  expect(r.code).toBe(0);
  expect(r.stderr).toContain(
    "agent-entrypoint: running project setup: bin/setup --quiet",
  );
  const seq = (await sequence(f.fake)).map(
    (s) => `${s.name} ${s.argv.join(" ")}`,
  );
  const at = (prefix: string) => seq.findIndex((s) => s.startsWith(prefix));
  const probe = at("setup-probe");
  expect(probe).toBeGreaterThan(at(`git -C ${f.workspace} reset -q --hard`));
  expect(probe).toBeGreaterThan(at(`git -C ${f.workspace} clean -q -fd`));
  expect(probe).toBeGreaterThan(at("git config --global user.email"));
  expect(probe).toBeLessThan(at("final"));
  expect(seq[probe]).toBe("setup-probe --quiet");
  expect((await Bun.file(`${f.fake.log}.setup-pwd`).text()).trim()).toBe(
    f.workspace,
  );
  const t = (await calls(f.fake, "timeout")).at(-1);
  expect(t?.argv).toEqual(["-k", "10", "600", "./bin/setup", "--quiet"]);
});

test("setup: honours AGENT_WORKDIR for both the path and the working directory", async () => {
  const f = await setupFixture({ dir: "apps/api" });
  const r = await run(f, { ...SETUP_ENV, AGENT_WORKDIR: "apps/api" });
  expect(r.code).toBe(0);
  expect((await Bun.file(`${f.fake.log}.setup-pwd`).text()).trim()).toBe(
    join(f.workspace, "apps/api"),
  );
});

test("setup: runs as the agent with an empty capability set", async () => {
  const f = await setupFixture();
  await run(f, SETUP_ENV);
  const drop = (await calls(f.fake, "setpriv")).find((c) =>
    c.argv.includes("timeout"),
  );
  expect(drop?.argv.slice(0, 6)).toEqual([
    "--reuid=agent",
    "--regid=agent",
    "--init-groups",
    "--inh-caps=-all",
    "--bounding-set=-all",
    "--no-new-privs",
  ]);
});

test("setup: no staged-secret variable reaches the script; AGENT_SETUP_PHASE and AGENT_SANDBOXED do", async () => {
  const f = await setupFixture();
  const r = await run(f, {
    ...SETUP_ENV,
    AGENT_STAGE_VARS: "GH_TOKEN ANTHROPIC_API_KEY EXTRA_SECRET",
    GH_TOKEN: "ghp_sentinel",
    ANTHROPIC_API_KEY: "sk-sentinel",
    EXTRA_SECRET: "x-sentinel",
    CLAUDE_CODE_OAUTH_TOKEN_FILE: "/run/secrets/oauth",
  });
  expect(r.code).toBe(0);
  const probe = (await calls(f.fake, "setup-probe")).at(-1);
  expect(probe?.env.AGENT_SETUP_PHASE).toBe("1");
  expect(probe?.env.AGENT_SANDBOXED).toBe("1");
  for (const k of Object.keys(probe?.env ?? {})) {
    expect(k.endsWith("_FILE")).toBe(false);
  }
  expect(Object.values(probe?.env ?? {}).join("\n")).not.toContain("sentinel");
  // The command itself still gets its staged files.
  const final = (await calls(f.fake, "final")).at(-1);
  expect(final?.env.GH_TOKEN_FILE).toBe(join(f.runDir, "secrets/gh_token"));
  expect(final?.env.AGENT_SETUP_PHASE).toBeUndefined();
});

test("setup: its stdout and stderr both go to stderr; stdout belongs to the command", async () => {
  const f = await setupFixture();
  const r = await run(f, SETUP_ENV);
  expect(r.code).toBe(0);
  expect(r.stdout).toBe("stdin_bytes=0 stdin_is_devnull=1\n");
  expect(r.stderr).toContain("setup-says-stdout");
  expect(r.stderr).toContain("setup-says-stderr");
});

test("setup: a non-zero exit aborts the boot with exit 3", async () => {
  const f = await setupFixture();
  const r = await run(f, { ...SETUP_ENV, FAKE_SETUP_EXIT: "5" });
  expect(r.code).toBe(3);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — setup failed (exit 5): bin/setup --quiet",
  );
  expect(await calls(f.fake, "final")).toHaveLength(0);
});

test("setup: a timeout aborts the boot with exit 3", async () => {
  const f = await setupFixture();
  const r = await run(f, {
    ...SETUP_ENV,
    AGENT_SETUP_TIMEOUT: "1",
    FAKE_SETUP_SLEEP: "5",
  });
  expect(r.code).toBe(3);
  expect(r.stderr).toContain("agent-entrypoint: setup timed out after 1s");
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — setup failed (exit 124): bin/setup --quiet",
  );
  expect(await calls(f.fake, "final")).toHaveLength(0);
}, 20_000);

test("setup: an absolute, escaping, missing or non-executable path is refused by name", async () => {
  const cases: [string, string, number?][] = [
    [
      "/bin/sh",
      "AGENT_SETUP '/bin/sh' must be a relative path inside the project",
    ],
    [
      "../x/setup",
      "AGENT_SETUP '../x/setup' must be a relative path inside the project",
    ],
    [
      "bin/../../setup",
      "AGENT_SETUP 'bin/../../setup' must be a relative path inside the project",
    ],
    ["bin/missing", "AGENT_SETUP 'bin/missing' does not exist in the project"],
    ["bin/setup", "AGENT_SETUP 'bin/setup' is not executable", 0o644],
  ];
  for (const [cmd, line, mode] of cases) {
    const f = await setupFixture({ mode });
    const r = await run(f, { AGENT_REPO: "o/r", AGENT_SETUP: cmd });
    expect(r.code).toBe(1);
    expect(r.stderr).toContain(`agent-entrypoint: FATAL — ${line}`);
    expect(await calls(f.fake, "setup-probe")).toHaveLength(0);
    expect(await calls(f.fake, "final")).toHaveLength(0);
  }
}, 20_000);

test("setup: a malformed AGENT_SETUP_TIMEOUT is refused", async () => {
  const f = await setupFixture();
  const r = await run(f, { ...SETUP_ENV, AGENT_SETUP_TIMEOUT: "10m" });
  expect(r.code).toBe(1);
  expect(r.stderr).toContain(
    "agent-entrypoint: FATAL — AGENT_SETUP_TIMEOUT '10m' must be a positive number of seconds",
  );
});

test("setup: skipped with a log line in provided-workspace mode", async () => {
  const f = await setupFixture();
  const r = await run(f, { AGENT_SETUP: "bin/setup" });
  expect(r.code).toBe(0);
  expect(r.stderr).toContain(
    "agent-entrypoint: AGENT_SETUP is ignored in provided-workspace mode (AGENT_REPO is unset)",
  );
  expect(await calls(f.fake, "setup-probe")).toHaveLength(0);
  expect(await calls(f.fake, "final")).toHaveLength(1);
});

test("setup: proxy mode hands the proxy environment to the script", async () => {
  const f = await setupFixture();
  const caFile = join(f.work, "proxy-ca.pem");
  await makeTestCert(caFile);
  const trustDir = join(f.work, "ca-trust");
  await mkdir(trustDir);
  const r = await run(f, proxyEnv({ ...f, caFile, trustDir }, SETUP_ENV));
  expect(r.code).toBe(0);
  const probe = (await calls(f.fake, "setup-probe")).at(-1);
  expect(probe?.env.HTTPS_PROXY).toBe(PROXY_URL);
  expect(probe?.env.https_proxy).toBe(PROXY_URL);
  expect(probe?.env.SSL_CERT_FILE).toBe(caFile);
  expect(probe?.env.NODE_EXTRA_CA_CERTS).toBe(caFile);
});

#!/usr/bin/env bash
# Smoke test for the agent images: runs the built containers the way the docs
# and the runner launch them and checks the contract from the outside.
#
#   ./smoke.sh <base image> <claude image>
#
# Needs a Docker daemon with bridge networking and NET_ADMIN available (any
# Linux host, GitHub's ubuntu runners, Docker Desktop), python3 on the host
# for the throwaway HTTP listener in check 3 and the case 9 MITM proxy, and
# openssl on the host for case 9's throwaway CA. The fake-driven bun tests
# under tests/ cover the scripts' logic; this covers what fakes
# cannot: the real privilege drop, real iptables, a real clone through the
# firewall, the runner's create/cp/start launch shape, and AGENT_SETUP
# running a cloned project's script under the real privilege drop and timeout.
set -euo pipefail

base="${1:?base image}"
claude="${2:?claude image}"

# Every container run sends its stderr to $last_stderr; a failing check, or a
# command that exits non-zero under set -e, prints it so CI shows the cause.
tmp="$(mktemp -d)"
last_stderr="$tmp/last-stderr"
: > "$last_stderr"
on_error() {
  echo "smoke: FAIL — command exited $1 at line $2" >&2
  echo "smoke: last container stderr:" >&2
  tail -n 30 "$last_stderr" >&2 || true
}
trap 'on_error $? $LINENO' ERR

# The launch flags the docs publish and the runner will pass (PR 3).
CAPS=(--cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add CHOWN
  --cap-add DAC_READ_SEARCH --cap-add SETUID --cap-add SETGID --cap-add SETPCAP
  --security-opt no-new-privileges --pids-limit 512)

pass() { echo "smoke: ok — $*"; }
fail() {
  echo "smoke: FAIL — $*" >&2
  echo "smoke: last container stderr:" >&2
  tail -n 30 "$last_stderr" >&2 || true
  exit 1
}
contains() {
  # A newline inside a fixed-string pattern is a pattern *list* to grep, and the
  # empty member matches everything — refuse it rather than pass vacuously.
  case "$2" in *$'\n'*) fail "$3: pattern must be a single line";; esac
  printf '%s' "$1" | grep -qF -- "$2" || fail "$3: expected to find '$2'"
}

listener_pid=""
mitm_pid=""
cleanup() {
  if [ -n "$listener_pid" ]; then
    kill "$listener_pid" 2>/dev/null || true
    wait "$listener_pid" 2>/dev/null || true
  fi
  if [ -n "$mitm_pid" ]; then
    kill "$mitm_pid" 2>/dev/null || true
    wait "$mitm_pid" 2>/dev/null || true
  fi
  # The entrypoint chowns a bind-mounted /workspace to its internal agent uid
  # (case 9's proxy-ws/claude-proxy-ws/mise-proxy-ws); undo that as root,
  # inside a throwaway container, before the host tries to rm -rf $tmp —
  # otherwise the un-owned .keep files make cleanup itself fail. --entrypoint
  # bypasses tini/agent-entrypoint (which would drop to the unprivileged
  # agent user before running our command) so this actually runs as root.
  for ws in "$tmp/proxy-ws" "$tmp/claude-proxy-ws" "$tmp/mise-proxy-ws"; do
    [ -d "$ws" ] || continue
    docker run --rm --entrypoint chmod -v "$ws":/ws "$base" -R a+rwX /ws >/dev/null 2>&1 || true
  done
  rm -rf "$tmp"
  docker rm -f smoke-runner-shape smoke-refresh >/dev/null 2>&1 || true
}
trap cleanup EXIT

# 1. Identity and privileges of the exec'd command.
out="$(docker run --rm "${CAPS[@]}" "$base" sh -c '
  printf "uid=%s user=%s\n" "$(id -u)" "$(id -un)"
  command -v sudo >/dev/null && echo HAS_SUDO || echo no-sudo
  grep -E "^(CapBnd|CapPrm|CapEff|CapAmb|NoNewPrivs):" /proc/self/status' 2>"$last_stderr")"
contains "$out" "uid=1000 user=agent" "uid/user"
contains "$out" "no-sudo" "sudo absent"
for cap in CapBnd CapPrm CapEff CapAmb; do
  printf '%s' "$out" | grep -Eq "^$cap:\s+0+$" || fail "$cap is not empty: $(printf '%s' "$out" | grep "^$cap")"
done
contains "$out" "NoNewPrivs:	1" "no_new_privs"
contains "$(cat "$last_stderr")" "init-firewall: default-DROP active" "firewall summary on stderr"
pass "runs as agent with no capabilities, no sudo, no_new_privs"

# 2. Self-clone of a public repository through the firewall.
out="$(docker run --rm "${CAPS[@]}" -e AGENT_REPO=octocat/Hello-World "$base" \
  sh -c 'printf "head=%s\n" "$(git -C /workspace rev-parse HEAD)"; printf "git_owner=%s\n" "$(stat -c %U /workspace/.git)"' 2>"$last_stderr")"
printf '%s' "$out" | grep -Eq '^head=[0-9a-f]{40}$' || fail "clone: no commit hash in: $out"
contains "$out" "git_owner=agent" "workspace owned by agent"
pass "self-clone works through the firewall"

# 3. Egress: host and public internet blocked, allowlisted host reachable. The
# GitHub probe omits -f on purpose: unauthenticated API calls are rate-limited
# and a 403 still proves the connection was allowed through.
python3 -m http.server 18080 --bind 0.0.0.0 >/dev/null 2>&1 &
listener_pid=$!
sleep 1
probe='
  curl -fsS --max-time 4 -o /dev/null http://host.docker.internal:18080/ && echo HOST_OPEN || echo host-blocked
  curl -fsS --max-time 4 -o /dev/null https://example.com && echo EXAMPLE_OPEN || echo example-blocked
  curl -sS --max-time 8 -o /dev/null https://api.github.com/ && echo github-ok || echo GITHUB_BLOCKED'
out="$(docker run --rm "${CAPS[@]}" --add-host host.docker.internal:host-gateway \
  -e AGENT_ALLOW_DOMAINS=host.docker.internal "$base" sh -c "$probe" 2>"$last_stderr")"
contains "$out" "host-blocked" "host unreachable even when allowlisted by name"
contains "$out" "example-blocked" "example.com blocked"
contains "$out" "github-ok" "api.github.com reachable"
contains "$(cat "$last_stderr")" "dropping non-public address" "private address warning"
out="$(docker run --rm "${CAPS[@]}" --add-host host.docker.internal:host-gateway \
  -e AGENT_FIREWALL=0 -e AGENT_UNSAFE_NO_FIREWALL=1 "$base" sh -c "$probe" 2>"$last_stderr")"
contains "$out" "HOST_OPEN" "host reachable with the firewall disabled (proves the listener works)"
pass "egress policy: host and internet blocked, allowlist reachable"

# 4. Without NET_ADMIN the container refuses to start.
code=0
docker run --rm "$base" true >"$tmp/out4" 2>"$last_stderr" || code=$?
[ "$code" -ne 0 ] || fail "container started without NET_ADMIN"
contains "$(cat "$last_stderr")" "init-firewall: FATAL — cannot use iptables" "fail-closed without caps"
pass "fails closed without NET_ADMIN"

# 5. Default Claude CMD with no credential: contract error, nothing on stdout.
code=0
docker run --rm "${CAPS[@]}" -e AGENT_REPO=octocat/Hello-World -e AGENT_PROMPT=hello "$claude" \
  >"$tmp/out5" 2>"$last_stderr" || code=$?
[ "$code" -eq 2 ] || fail "expected exit 2 without a credential, got $code"
[ ! -s "$tmp/out5" ] || fail "stdout was not empty: $(cat "$tmp/out5")"
contains "$(cat "$last_stderr")" "agent-claude: no model credential" "credential guard"
out="$(docker run --rm "${CAPS[@]}" "$claude" claude --version 2>"$last_stderr")"
[ -n "$out" ] || fail "claude --version printed nothing"
pass "claude layer: credential guard and CLI present ($out)"

# 6. A toolchain install through the firewall (what "agent installs what it needs" relies on).
out="$(docker run --rm "${CAPS[@]}" "$base" sh -c 'mise use -g node@lts >/dev/null && node --version' 2>"$last_stderr")"
printf '%s' "$out" | grep -Eq '^v[0-9]+' || fail "mise node install: $out"
pass "mise installs node through the firewall ($out)"

# 7. The runner's launch shape: create, cp a root-owned tree, start with the
# manifest on stdin, and a command that never sees that stdin. `create -i` is
# load-bearing: without OpenStdin at create time, `start -a -i` attaches no
# stdin at all and the manifest silently never arrives.
mkdir -p "$tmp/ws/.git"
echo "x" > "$tmp/ws/file"
printf '{"agent":{"prompt":"From manifest","model":"m"},"task":{"fields":[{"field":"title","value":"T"}]}}' > "$tmp/manifest.json"
docker create -i --name smoke-runner-shape "${CAPS[@]}" --workdir /workspace "$base" \
  sh -c 'printf "manifest=%s\n" "$(stat -c "%a %U" /run/hatchward/manifest.json)"; printf "prompt=%s\n" "$(jq -r .agent.prompt /run/hatchward/manifest.json)"; printf "file_owner=%s\n" "$(stat -c %U /workspace/file)"; printf "stdin_bytes=%s\n" "$(cat | wc -c | tr -d " ")"' >/dev/null
docker cp "$tmp/ws/." smoke-runner-shape:/workspace
out="$(docker start -a -i smoke-runner-shape < "$tmp/manifest.json" 2>"$last_stderr")"
docker rm -f smoke-runner-shape >/dev/null
contains "$out" "manifest=600 agent" "manifest mode/owner"
contains "$out" "prompt=From manifest" "manifest prompt readable"
contains "$out" "file_owner=agent" "docker cp'd tree re-owned by agent"
contains "$out" "stdin_bytes=0" "command stdin detached"
pass "runner launch shape: manifest captured, tree re-owned, stdin detached"

# 8. A secret file owned by a foreign uid, mounted read-only, is readable by the agent.
echo "sk-smoke-sentinel" > "$tmp/secret"
chmod 600 "$tmp/secret"
if chown 4242 "$tmp/secret" 2>/dev/null || sudo -n chown 4242 "$tmp/secret" 2>/dev/null; then
  out="$(docker run --rm "${CAPS[@]}" --mount "type=bind,src=$tmp/secret,dst=/run/secrets/anthropic_api_key,readonly" \
    -e ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key \
    -e AGENT_STAGE_VARS=ANTHROPIC_API_KEY "$base" \
    sh -c 'printf "staged=%s\n" "$(cat "$ANTHROPIC_API_KEY_FILE")"; printf "raw_in_env=%s\n" "$(env | grep -c "^ANTHROPIC_API_KEY=" || true)"' 2>"$last_stderr")"
  contains "$out" "staged=sk-smoke-sentinel" "foreign-uid secret readable via the staged copy"
  contains "$out" "raw_in_env=0" "raw value absent from the environment"
  pass "secret staging works for a foreign-uid host file"
else
  echo "smoke: skipped — cannot chown to a foreign uid on this host (needs root)"
fi

# 9. Proxy mode (contract 2): a host-side MITM stands in for the runner's
# real credential-injecting egress proxy. It never reaches the real
# internet — every allowed host is a fake upstream this script serves —
# and it does not rewrite a sentinel into a real credential (the runner's
# job, out of scope here); it only proves the sentinel arrived, logging one
# line per inner request in the format the assertions below grep for.
proxy_mode_supported=1
mise_check_supported=1
if ! command -v openssl >/dev/null 2>&1; then
  echo "smoke: skipped case 9 — openssl not found on host"
  proxy_mode_supported=0
fi
if [ "$proxy_mode_supported" = 1 ]; then
  mitm_dir="$tmp/mitm"
  mkdir -p "$mitm_dir/certs"
  ca_key="$mitm_dir/ca.key"
  ca_crt="$mitm_dir/ca.crt"
  openssl ecparam -genkey -name prime256v1 -noout -out "$ca_key" 2>/dev/null
  openssl req -x509 -new -key "$ca_key" -sha256 -days 2 \
    -subj "/CN=hatchward-smoke-ca" -out "$ca_crt" 2>/dev/null
  for h in api.anthropic.com api.github.com github.com nodejs.org mise-versions.jdx.dev; do
    openssl ecparam -genkey -name prime256v1 -noout -out "$mitm_dir/certs/$h.key" 2>/dev/null
    openssl req -new -key "$mitm_dir/certs/$h.key" -subj "/CN=$h" -out "$mitm_dir/certs/$h.csr" 2>/dev/null
    printf 'subjectAltName=DNS:%s\n' "$h" > "$mitm_dir/certs/$h.ext"
    openssl x509 -req -in "$mitm_dir/certs/$h.csr" -CA "$ca_crt" -CAkey "$ca_key" \
      -CAcreateserial -days 2 -sha256 -extfile "$mitm_dir/certs/$h.ext" \
      -out "$mitm_dir/certs/$h.crt" 2>/dev/null
  done

  # A real node tarball + checksums, fetched once from the real nodejs.org
  # and cached across runs, so mise's install (checksum verified, no gpg in
  # this image so the .sig is unused but served for fidelity) and the later
  # `node -e "fetch(...)"` check exercise a real, working node binary rather
  # than a stand-in that would only prove the download plumbing, not that
  # NODE_USE_ENV_PROXY actually works. NODE_USE_ENV_PROXY needs Node ≥ 24; an
  # older pin here would make that specific assertion fail for a reason
  # unrelated to this image's contract. A failure to fetch it (no internet
  # egress on this host) only skips the mise/node sub-check below — every
  # other case 9 assertion (canaries, gh, git, claude) needs no such tarball.
  node_version="24.20.0"
  node_arch="$(docker run --rm -i "${CAPS[@]}" "$base" uname -m < /dev/null 2>/dev/null || true)"
  case "$node_arch" in
    aarch64) node_arch="arm64" ;;
    x86_64) node_arch="x64" ;;
    *) node_arch="" ;;
  esac
  cache_dir="${XDG_CACHE_HOME:-$HOME/.cache}/hatchward-agent-smoke/node/$node_version-$node_arch"
  node_tarball="$mitm_dir/node.tar.gz.missing"
  node_shasums="$mitm_dir/shasums.txt.missing"
  node_sig="$mitm_dir/sig.txt.missing"
  : > "$node_tarball"; : > "$node_shasums"; : > "$node_sig"
  if [ -z "$node_arch" ]; then
    echo "smoke: skipped case 9's mise/node check — could not determine the container's architecture"
    mise_check_supported=0
  else
    mkdir -p "$cache_dir"
    real_tarball="$cache_dir/node.tar.gz"
    real_shasums="$cache_dir/SHASUMS256.txt"
    real_sig="$cache_dir/SHASUMS256.txt.sig"
    if [ ! -s "$real_tarball" ] || [ ! -s "$real_shasums" ]; then
      echo "smoke: case 9 — fetching a real node-v$node_version-linux-$node_arch tarball once (cached under $cache_dir)"
      curl -fsSL -o "$real_tarball" \
        "https://nodejs.org/dist/v$node_version/node-v$node_version-linux-$node_arch.tar.gz" || true
      curl -fsSL -o "$real_shasums" "https://nodejs.org/dist/v$node_version/SHASUMS256.txt" || true
      curl -fsSL -o "$real_sig" "https://nodejs.org/dist/v$node_version/SHASUMS256.txt.sig" || true
    fi
    if [ -s "$real_tarball" ] && [ -s "$real_shasums" ]; then
      node_tarball="$real_tarball"; node_shasums="$real_shasums"; node_sig="$real_sig"
    else
      echo "smoke: skipped case 9's mise/node check — could not fetch a real node tarball from this host (no internet egress?)"
      mise_check_supported=0
    fi
  fi
fi

if [ "$proxy_mode_supported" = 1 ]; then
  cat > "$mitm_dir/proxy.py" <<'PYEOF'
#!/usr/bin/env python3
"""Host-side MITM proxy for agent smoke case 9 (proxy mode, contract 2).

Stands in for the runner's real credential-injecting egress proxy: it
terminates TLS for a fixed set of hosts with per-host leaf certificates
signed by a throwaway CA, and serves canned "upstream" responses instead of
reaching the real internet. It does not rewrite a sentinel into a real
credential (that is the runner's job, out of scope here) — it only proves
the sentinel arrived, by logging one line per inner HTTP request:

  ua=<user-agent> connect=<CONNECT host:port> sni=<TLS SNI> proxyauth=ok|missing cred=<header-name>=<header-value>

Usage: proxy.py <port> <certdir> <expected-proxy-auth-header-value>
                 <logfile> <node-tarball> <node-shasums> <node-sig>
                 <node-version> <node-arch>

Reads are done a byte at a time off the raw socket for the request line and
headers (never through a buffered file object): a BufferedReader would read
ahead past the CONNECT request into the TLS ClientHello bytes that follow it
on the same socket, and those bytes would then be invisible to
ssl.wrap_socket, which operates on the raw file descriptor. Bodies (small,
in practice — client requests here are never the 50+ MB node tarball, that
direction is response-only) are read in a loop instead.
"""

import json
import os
import socket
import ssl
import sys
import threading

PORT = int(sys.argv[1])
CERTDIR = sys.argv[2]
EXPECTED_AUTH = sys.argv[3]
LOGFILE = sys.argv[4]
NODE_TARBALL = sys.argv[5]
NODE_SHASUMS = sys.argv[6]
NODE_SIG = sys.argv[7]
NODE_VERSION = sys.argv[8]
NODE_ARCH = sys.argv[9]

ALLOWED_HOSTS = {
    "api.anthropic.com",
    "api.github.com",
    "github.com",
    "nodejs.org",
    "mise-versions.jdx.dev",
}

_log_lock = threading.Lock()


def log(line):
    with _log_lock:
        with open(LOGFILE, "a") as f:
            f.write(line + "\n")


def readline_raw(sock):
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            break
        buf += b
        if buf.endswith(b"\n"):
            break
    return bytes(buf)


def read_n(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(min(65536, n - len(buf)))
        if not chunk:
            break
        buf += chunk
    return buf


def read_request(sock):
    """Reads one HTTP/1.1 request off a raw socket. Returns
    (method, path, headers-dict, body-bytes) or None at EOF."""
    request_line = readline_raw(sock)
    if not request_line:
        return None
    try:
        method, path, _version = request_line.decode("iso-8859-1").strip().split(" ", 2)
    except ValueError:
        return None
    headers = {}
    while True:
        line = readline_raw(sock)
        if line in (b"\r\n", b"\n", b""):
            break
        raw = line.decode("iso-8859-1").rstrip("\r\n")
        if ":" not in raw:
            continue
        k, v = raw.split(":", 1)
        headers[k.strip().lower()] = v.strip()
    length = int(headers.get("content-length", "0") or 0)
    body = read_n(sock, length) if length else b""
    return method, path, headers, body


def write_response(sock, status, reason, headers, body):
    if isinstance(body, str):
        body = body.encode()
    out = f"HTTP/1.1 {status} {reason}\r\n".encode()
    headers = dict(headers)
    headers.setdefault("Content-Length", str(len(body)))
    headers.setdefault("Connection", "close")
    for k, v in headers.items():
        out += f"{k}: {v}\r\n".encode()
    out += b"\r\n"
    sock.sendall(out + body)


# --- Fake upstreams ----------------------------------------------------------

def anthropic_messages(headers, body):
    try:
        req = json.loads(body or b"{}")
    except json.JSONDecodeError:
        req = {}
    model = req.get("model", "claude-smoke")
    stream = bool(req.get("stream"))
    reply_text = "HATCHWARD_SMOKE_REPLY"
    if stream:
        events = []

        def ev(name, data):
            events.append(f"event: {name}\ndata: {json.dumps(data)}\n\n")

        ev("message_start", {
            "type": "message_start",
            "message": {
                "id": "msg_smoke", "type": "message", "role": "assistant",
                "content": [], "model": model, "stop_reason": None,
                "stop_sequence": None,
                "usage": {"input_tokens": 1, "output_tokens": 0},
            },
        })
        ev("content_block_start", {
            "type": "content_block_start", "index": 0,
            "content_block": {"type": "text", "text": ""},
        })
        ev("content_block_delta", {
            "type": "content_block_delta", "index": 0,
            "delta": {"type": "text_delta", "text": reply_text},
        })
        ev("content_block_stop", {"type": "content_block_stop", "index": 0})
        ev("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": "end_turn", "stop_sequence": None},
            "usage": {"output_tokens": 5},
        })
        ev("message_stop", {"type": "message_stop"})
        body_out = "".join(events)
        return 200, "OK", {"Content-Type": "text/event-stream; charset=utf-8"}, body_out
    payload = {
        "id": "msg_smoke", "type": "message", "role": "assistant",
        "model": model,
        "content": [{"type": "text", "text": reply_text}],
        "stop_reason": "end_turn", "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 5},
    }
    return 200, "OK", {"Content-Type": "application/json"}, json.dumps(payload)


def pktline(s):
    if isinstance(s, str):
        s = s.encode()
    return f"{len(s) + 4:04x}".encode() + s


def git_upload_pack_advertisement():
    service = pktline("# service=git-upload-pack\n") + b"0000"
    ref = pktline(
        "0000000000000000000000000000000000000000 capabilities^{}\x00"
        "multi_ack thin-pack side-band side-band-64k ofs-delta\n"
    ) + b"0000"
    return service + ref


def github_api(path, headers):
    # `gh auth login --with-token` validates the token against the API root,
    # then queries GraphQL for the "Logged in as <user>" line; `gh api user`
    # (the smoke assertion) hits REST /user directly. All three get the same
    # canned identity.
    if path in ("/", "") or path.startswith("/user"):
        return 200, "OK", {"Content-Type": "application/json"}, json.dumps({"login": "smoke"})
    if path.startswith("/graphql"):
        return (
            200, "OK", {"Content-Type": "application/json"},
            json.dumps({"data": {"viewer": {"login": "smoke"}}}),
        )
    if "info/refs" in path and "git-upload-pack" in path:
        if "authorization" not in headers:
            return 401, "Unauthorized", {"WWW-Authenticate": 'Basic realm="hatchward-smoke"'}, ""
        return (
            200, "OK",
            {"Content-Type": "application/x-git-upload-pack-advertisement"},
            git_upload_pack_advertisement(),
        )
    return 404, "Not Found", {}, ""


def node_toml():
    return (
        "[versions]\n"
        f"\"{NODE_VERSION}\" = {{ created_at = 2024-01-01T00:00:00.000Z }}\n"
    )


def route(connect_host, method, path, headers, body):
    if connect_host == "api.anthropic.com" and path.startswith("/v1/messages"):
        return anthropic_messages(headers, body)
    if connect_host in ("api.github.com", "github.com"):
        return github_api(path, headers)
    if connect_host == "mise-versions.jdx.dev":
        if path.startswith("/data/node.toml"):
            return 200, "OK", {"Content-Type": "text/plain"}, node_toml()
        if path.startswith("/api/tools/node"):
            return 200, "OK", {"Content-Type": "application/json"}, "{}"
        return 404, "Not Found", {}, ""
    if connect_host == "nodejs.org":
        want_tar = f"/dist/v{NODE_VERSION}/node-v{NODE_VERSION}-linux-{NODE_ARCH}.tar.gz"
        want_sums = f"/dist/v{NODE_VERSION}/SHASUMS256.txt"
        want_sig = f"/dist/v{NODE_VERSION}/SHASUMS256.txt.sig"
        if path == want_tar:
            with open(NODE_TARBALL, "rb") as f:
                return 200, "OK", {"Content-Type": "application/gzip"}, f.read()
        if path == want_sums:
            with open(NODE_SHASUMS, "rb") as f:
                return 200, "OK", {"Content-Type": "text/plain"}, f.read()
        if path == want_sig:
            with open(NODE_SIG, "rb") as f:
                return 200, "OK", {"Content-Type": "application/octet-stream"}, f.read()
        return 404, "Not Found", {}, ""
    return 404, "Not Found", {}, ""


def cred_field(headers):
    if "x-api-key" in headers:
        return f"x-api-key={headers['x-api-key']}"
    if "authorization" in headers:
        return f"Authorization={headers['authorization']}"
    return "-"


def handle_tls_session(tls, connect_host, connect_port, sni):
    try:
        parsed = read_request(tls)
        if parsed is None:
            return
        method, path, headers, body = parsed
        ua = headers.get("user-agent", "-")
        log(
            f"ua={ua} connect={connect_host}:{connect_port} sni={sni} "
            f"proxyauth=ok cred={cred_field(headers)}"
        )
        status, reason, resp_headers, resp_body = route(connect_host, method, path, headers, body)
        write_response(tls, status, reason, resp_headers, resp_body)
    except Exception as exc:  # noqa: BLE001 - smoke harness, log and move on
        log(f"ERROR inner handler for {connect_host}: {exc!r}")


def handle_connection(conn, addr):
    try:
        parsed = read_request(conn)
        if parsed is None:
            return
        method, target, headers, _body = parsed
        if method != "CONNECT":
            write_response(conn, 405, "Method Not Allowed", {}, "")
            return
        host, _, port = target.partition(":")
        port = port or "443"
        ua = headers.get("user-agent", "-")
        auth = headers.get("proxy-authorization")
        if auth != EXPECTED_AUTH:
            log(f"ua={ua} connect={host}:{port} sni=- proxyauth=missing cred=-")
            write_response(
                conn, 407, "Proxy Authentication Required",
                {"Proxy-Authenticate": 'Basic realm="hatchward"'}, "",
            )
            return
        if host not in ALLOWED_HOSTS or port != "443":
            write_response(conn, 403, "Forbidden", {}, "")
            return
        # A CONNECT response carries no Content-Length/body framing at all —
        # write the tunnel-establishment line directly rather than through
        # write_response, which would add headers that confuse the client's
        # HTTP/1.1 framing right before the TLS handshake begins.
        conn.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        certfile = os.path.join(CERTDIR, host + ".crt")
        keyfile = os.path.join(CERTDIR, host + ".key")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sni_holder = {}

        def sni_cb(sslsock, server_name, sslctx):
            sni_holder["name"] = server_name

        ctx.sni_callback = sni_cb
        ctx.load_cert_chain(certfile, keyfile)
        tls = ctx.wrap_socket(conn, server_side=True)
        try:
            handle_tls_session(tls, host, port, sni_holder.get("name"))
        finally:
            try:
                tls.close()
            except Exception:
                pass
        return
    except Exception as exc:  # noqa: BLE001
        log(f"ERROR connection from {addr}: {exc!r}")
    finally:
        try:
            conn.close()
        except Exception:
            pass


def main():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", PORT))
    srv.listen(64)
    open(LOGFILE, "a").close()
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_connection, args=(conn, addr), daemon=True).start()


if __name__ == "__main__":
    main()
PYEOF

  mitm_port=18443
  mitm_log="$mitm_dir/mitm.log"
  proxy_user="hatchward"
  proxy_pass="smoke-$$-$(date +%s)"
  proxy_auth_header="Basic $(printf '%s:%s' "$proxy_user" "$proxy_pass" | base64 | tr -d '\n')"
  python3 "$mitm_dir/proxy.py" "$mitm_port" "$mitm_dir/certs" "$proxy_auth_header" \
    "$mitm_log" "$node_tarball" "$node_shasums" "$node_sig" "$node_version" "$node_arch" \
    > "$mitm_dir/proxy.out" 2>&1 &
  mitm_pid=$!
  # Wait for the listener rather than a fixed sleep.
  for _ in 1 2 3 4 5 6 7 8 9 10; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$mitm_port") 2>/dev/null; then exec 3<&- 3>&-; break; fi
    sleep 0.5
  done

  proxy_url="http://$proxy_user:$proxy_pass@host.docker.internal:$mitm_port"
  proxy_ws="$tmp/proxy-ws"
  mkdir -p "$proxy_ws"
  : > "$proxy_ws/.keep"
  PROXY_FLAGS=(--add-host host.docker.internal:host-gateway
    --mount "type=bind,src=$ca_crt,dst=/run/hatchward/proxy-ca.pem,readonly"
    -e AGENT_PROXY_URL="$proxy_url" -e AGENT_CA_FILE=/run/hatchward/proxy-ca.pem)

  # Negative canaries + gh, run together in one boot: DNS and both IP-literal
  # families must be unreachable, and gh (given the sentinel) must resolve its
  # identity through the MITM.
  out="$(docker run --rm "${CAPS[@]}" "${PROXY_FLAGS[@]}" -v "$proxy_ws":/workspace \
    -e GH_TOKEN=hatchward-proxy-managed "$base" sh -c '
      getent hosts example.com >/dev/null 2>&1 && echo DNS_OPEN || echo dns-blocked
      curl --noproxy "*" --connect-timeout 4 -o /dev/null -s https://1.1.1.1/ && echo IP4_OPEN || echo ip4-blocked
      curl -6 --noproxy "*" --connect-timeout 4 -o /dev/null -s https://[2606:4700:4700::1111]/ && echo IP6_OPEN || echo ip6-blocked
      gh api user' 2>"$last_stderr")"
  contains "$out" "dns-blocked" "proxy mode: DNS unreachable inside the container"
  contains "$out" "ip4-blocked" "proxy mode: direct IPv4 literal unreachable"
  contains "$out" "ip6-blocked" "proxy mode: direct IPv6 literal unreachable"
  contains "$out" "smoke" "gh api user through the MITM"
  contains "$(cat "$mitm_log")" "connect=api.github.com:443 sni=api.github.com proxyauth=ok cred=Authorization=token hatchward-proxy-managed" \
    "gh's REST call carried the sentinel"
  pass "proxy mode: DNS/IP-literal canaries fail, gh reaches its fake upstream"

  # git ls-remote against the fake github.com: 401 first, then Basic
  # smoke:<sentinel> — gh's stored login ("smoke"), not "x-access-token".
  out="$(docker run --rm "${CAPS[@]}" "${PROXY_FLAGS[@]}" -v "$proxy_ws":/workspace \
    -e GH_TOKEN=hatchward-proxy-managed "$base" sh -c \
    'git ls-remote https://github.com/octocat/Hello-World.git; echo GIT_EXIT=$?' 2>"$last_stderr")"
  contains "$out" "GIT_EXIT=0" "git ls-remote succeeded through the MITM"
  git_cred_b64="$(printf 'smoke:hatchward-proxy-managed' | base64 | tr -d '\n')"
  contains "$(cat "$mitm_log")" "connect=github.com:443 sni=github.com proxyauth=ok cred=Authorization=Basic $git_cred_b64" \
    "git retried with Basic smoke:<sentinel> after the 401"
  pass "proxy mode: git ls-remote retries with Basic auth after 401"

  # claude -p hi --max-turns 1, both credential shapes.
  claude_ws="$tmp/claude-proxy-ws"
  mkdir -p "$claude_ws"
  : > "$claude_ws/.keep"
  : > "$mitm_log"
  out="$(docker run --rm "${CAPS[@]}" "${PROXY_FLAGS[@]}" -v "$claude_ws":/workspace \
    -e AGENT_PROMPT=hi -e AGENT_MAX_TURNS=1 -e ANTHROPIC_API_KEY=hatchward-proxy-managed \
    "$claude" 2>"$last_stderr")"
  contains "$out" "HATCHWARD_SMOKE_REPLY" "claude printed the MITM's canned reply (API-key sentinel)"
  contains "$(cat "$mitm_log")" \
    "sni=api.anthropic.com proxyauth=ok cred=x-api-key=hatchward-proxy-managed" \
    "claude's request carried the API-key sentinel to the MITM"
  pass "proxy mode: claude -p hi --max-turns 1 works with the Anthropic API-key sentinel"

  : > "$mitm_log"
  out="$(docker run --rm "${CAPS[@]}" "${PROXY_FLAGS[@]}" -v "$claude_ws":/workspace \
    -e AGENT_PROMPT=hi -e AGENT_MAX_TURNS=1 -e CLAUDE_CODE_OAUTH_TOKEN=hatchward-proxy-managed \
    "$claude" 2>"$last_stderr")"
  contains "$out" "HATCHWARD_SMOKE_REPLY" "claude printed the MITM's canned reply (OAuth sentinel)"
  contains "$(cat "$mitm_log")" \
    "sni=api.anthropic.com proxyauth=ok cred=Authorization=Bearer hatchward-proxy-managed" \
    "claude's request carried the OAuth sentinel to the MITM"
  pass "proxy mode: claude -p hi --max-turns 1 works with the OAuth sentinel"

  # mise + node through the tunnel, then Node's own fetch (NODE_USE_ENV_PROXY).
  if [ "$mise_check_supported" = 1 ]; then
    mise_ws="$tmp/mise-proxy-ws"
    mkdir -p "$mise_ws"
    out="$(docker run --rm "${CAPS[@]}" "${PROXY_FLAGS[@]}" -v "$mise_ws":/workspace "$base" sh -c \
      'mise use -g node@lts >/dev/null 2>&1 && node --version && node -e "fetch(\"https://api.github.com/user\").then(r=>r.json()).then(j=>console.log(\"FETCH_OK \"+j.login)).catch(e=>{console.error(String(e));process.exit(1)})"' \
      2>"$last_stderr")"
    printf '%s' "$out" | grep -Eq '^v[0-9]+' || fail "proxy mode: mise node install through the MITM: $out"
    contains "$out" "FETCH_OK smoke" "node's global fetch honored NODE_USE_ENV_PROXY through the MITM"
    pass "proxy mode: mise use -g node@lts and node's own fetch work through the MITM"
  fi

  echo "smoke: case 9 MITM log:"
  cat "$mitm_log" >&2
fi

# 10. Project setup (AGENT_SETUP) after a real self-clone. AGENT_SETUP must
# name an executable inside the clone, so the script arrives the way a
# project's own file would: AGENT_CLONE_ARGS points git clone at a bind-mounted
# template directory, which git copies (mode included) into the clone's .git/.
# The script reports to stderr, where the entrypoint sends setup output.
# SMOKE_SECRET is always staged, so the *_FILE check never passes vacuously; a
# GH_TOKEN joins it only when the host provides a real one (SMOKE_GH_TOKEN or
# GH_TOKEN), because the entrypoint validates it with gh auth login first.
mkdir -p "$tmp/setup-template"
cat > "$tmp/setup-template/smoke-setup" <<'SETUPEOF'
#!/bin/sh
case "$1" in
  report)
    printf 'setup: uid=%s pwd=%s phase=%s\n' "$(id -u)" "$(pwd)" "${AGENT_SETUP_PHASE:-}"
    printf 'setup: file_vars=%s\n' "$(env | grep -c '_FILE=' || true)"
    grep -E '^Cap(Eff|Bnd):' /proc/self/status | sed 's/^/setup: /'
    ;;
  hang) exec sleep 600 ;;
  fail) exit 7 ;;
esac
SETUPEOF
chmod 755 "$tmp/setup-template/smoke-setup"
setup_token="${SMOKE_GH_TOKEN:-${GH_TOKEN:-}}"
setup_stage="SMOKE_SECRET"
[ -z "$setup_token" ] || setup_stage="GH_TOKEN SMOKE_SECRET"
SETUP_RUN=(docker run --rm "${CAPS[@]}"
  --mount "type=bind,src=$tmp/setup-template,dst=/smoke-template,readonly"
  -e AGENT_REPO=octocat/Hello-World -e AGENT_CLONE_ARGS=--template=/smoke-template)
# The token reaches docker through its environment, never its argv.
out="$(GH_TOKEN="$setup_token" SMOKE_SECRET=smoke-setup-sentinel "${SETUP_RUN[@]}" \
  -e GH_TOKEN -e SMOKE_SECRET -e AGENT_STAGE_VARS="$setup_stage" \
  -e AGENT_SETUP=".git/smoke-setup report" "$base" \
  sh -c 'env | grep -c _FILE= | sed s/^/agent_file_vars=/' 2>"$last_stderr")"
setup_err="$(cat "$last_stderr")"
contains "$setup_err" "running project setup: .git/smoke-setup report" "setup announced"
contains "$setup_err" "setup: uid=1000 pwd=/workspace phase=1" "setup identity and project dir"
for cap in CapEff CapBnd; do
  printf '%s' "$setup_err" | grep -Eq "^setup: $cap:\s+0+$" \
    || fail "setup $cap is not empty: $(printf '%s' "$setup_err" | grep "^setup: $cap" || true)"
done
contains "$setup_err" "setup: file_vars=0" "no *_FILE secret variable in the setup env"
staged_count="$(echo "$setup_stage" | wc -w | tr -d ' ')"
contains "$out" "agent_file_vars=$staged_count" "agent command still sees the staged *_FILE variables"
if [ -n "$setup_token" ]; then
  pass "project setup: runs as agent with no capabilities in the project dir, GH_TOKEN and other secrets withheld"
else
  pass "project setup: runs as agent with no capabilities in the project dir, staged secrets withheld (no host GH_TOKEN; GH_TOKEN not exercised)"
fi

code=0
started="$(date +%s)"
"${SETUP_RUN[@]}" -e AGENT_SETUP=".git/smoke-setup hang" -e AGENT_SETUP_TIMEOUT=3 "$base" true \
  >"$tmp/out10" 2>"$last_stderr" || code=$?
elapsed=$(( $(date +%s) - started ))
[ "$code" -eq 3 ] || fail "expected exit 3 from a hanging setup, got $code"
[ ! -s "$tmp/out10" ] || fail "stdout was not empty: $(cat "$tmp/out10")"
contains "$(cat "$last_stderr")" "setup timed out after 3s" "timeout reported"
contains "$(cat "$last_stderr")" "FATAL — setup failed (exit 124)" "timeout exit status"
[ "$elapsed" -lt 120 ] || fail "hanging setup took ${elapsed}s to be killed"
pass "project setup: timeout kills a hanging script, container exits 3"

code=0
"${SETUP_RUN[@]}" -e AGENT_SETUP=".git/smoke-setup fail" "$base" true \
  >"$tmp/out10" 2>"$last_stderr" || code=$?
[ "$code" -eq 3 ] || fail "expected exit 3 from a failing setup, got $code"
contains "$(cat "$last_stderr")" "FATAL — setup failed (exit 7)" "setup failure status"
pass "project setup: a failing script exits 3"

# 11. The firewall refresher: a root process the agent can neither signal nor
# bypass, ticking (every 2s here) without widening the allowlist. The checks
# are the container's CMD, so they run as the real agent, after the drop; a
# `docker exec` would run as root and prove nothing.
docker rm -f smoke-refresh >/dev/null 2>&1 || true
docker run -d --name smoke-refresh "${CAPS[@]}" -e AGENT_FIREWALL_REFRESH=2 "$base" sh -c '
  sleep 6
  printf "uid=%s\n" "$(id -u)"
  # -o: mid-tick, the subshells of the refresher share its command line.
  pid="$(pgrep -u root -o -xf "bash /usr/local/bin/agent-firewall-refresh")"
  [ -n "$pid" ] && echo refresher-running || echo NO_REFRESHER
  printf "refresher_ppid=%s\n" "$(ps -o ppid= -p "$pid" | tr -d " ")"
  kill "$pid" 2>/dev/null && echo KILLED || echo kill-refused
  kill -9 "$pid" 2>/dev/null && echo KILLED9 || echo kill9-refused
  iptables -A OUTPUT -d 1.1.1.1 -j ACCEPT 2>/dev/null && echo IPTABLES_OK || echo iptables-refused
  sleep 3
  [ -d "/proc/$pid" ] && echo refresher-alive || echo REFRESHER_GONE
  curl -fsS --max-time 4 -o /dev/null https://example.com && echo EXAMPLE_OPEN || echo example-blocked
  curl -sS --max-time 8 -o /dev/null https://api.github.com/ && echo github-ok || echo GITHUB_BLOCKED
  echo checks-done
  sleep 60' >/dev/null
for _ in $(seq 1 60); do
  docker logs smoke-refresh 2>/dev/null | grep -q checks-done && break
  sleep 1
done
code=0
check="$(docker exec -u root smoke-refresh agent-egress-check 2>&1)" || code=$?
out="$(docker logs smoke-refresh 2>"$last_stderr")"
docker rm -f smoke-refresh >/dev/null
contains "$out" "uid=1000" "checks ran as the agent"
contains "$out" "refresher-running" "refresher started as root"
contains "$out" "refresher_ppid=1" "refresher orphaned to tini, which reaps it"
contains "$out" "kill-refused" "agent cannot SIGTERM the refresher"
contains "$out" "kill9-refused" "agent cannot SIGKILL the refresher"
contains "$out" "iptables-refused" "agent cannot run iptables"
contains "$out" "refresher-alive" "refresher survives the agent's attempts"
contains "$out" "example-blocked" "example.com still blocked after refresh ticks"
contains "$out" "github-ok" "api.github.com reachable"
contains "$(cat "$last_stderr")" "agent-firewall-refresh: refreshing every 2s" "refresher start line"
[ "$code" -le 1 ] || fail "agent-egress-check exited $code: $check"
contains "$check" "ok	github.com" "agent-egress-check reports coverage"
pass "firewall refresher: root-owned, unkillable by the agent, allowlist intact"

echo "smoke: all checks passed"

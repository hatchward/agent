# Agent container image — design

The operator-facing contract is `README.md`; this is the design record.

Status: approved 2026-09-05 after two rounds of six critic passes, first drafted inside
hatchward/core and extracted into this repository the same day. The hatchward side
(runner launch, `~/.hatchward/secrets/`) lands as a hatchward pull request written
against §7.

## 1. Problem

A coding agent that runs unattended with `--dangerously-skip-permissions` needs a place
to run where the worst it can do is bounded: no reach into the host or the LAN, no
credential it can leak into a process list or a config file, no privilege it can escalate,
and a workspace whose state is known. It also has to work for any code base, so the image
cannot bake one project's toolchain or services.

Hatchward's runner (`hostedrunner/worker.go`) already creates a container per assignment
— `docker create --network none`, `docker cp` of the operator's workspace, the execution
manifest on stdin, an action socket bind-mounted at `/run/hatchward/actions.sock` — but no
image exists to fill `manifest.agent.image`, and that path grants no network and no
credentials, so no model-backed agent can run in it.

## 2. Decisions

| Decision | Choice | Rejected |
|---|---|---|
| Scope | Image plus the runner change | Image only — the image contract would have been rewritten the day the runner adopted it |
| Toolchains | Minimal image; the agent installs what it needs in user space via mise; build libraries baked | Per-language image variants; repo-owned setup hook; `sudo apt-get` for the agent (root in a `NET_ADMIN` container can flush the firewall) |
| Workspace | Two modes: self-clone when `AGENT_REPO` is set, provided workspace otherwise | Manifest-derived clone fallback (turns an empty operator directory into a network clone of a cloud-named repository) |
| Invocation | Env-driven default CMD, prompt on stdin to the CLI; the runner's manifest honored as a prompt/model source | Passthrough-only command; manifest-only |
| Firewall | Kept, generic allowlist composed from `allow-domains.d/*` + `AGENT_ALLOW_DOMAINS`, private ranges filtered | Dropping it; opt-in |
| Privilege drop | `setpriv` with empty bounding and inheritable sets, `no_new_privs` | `gosu` (leaves the bounding set intact; any setuid binary is a route back to root with `NET_ADMIN`) |
| Base | Debian trixie-slim, digest pinned | bookworm (superseded) |
| Versioning | Release tags: `:base-vX.Y.Z`, `:claude-vX.Y.Z`; Dockerfiles never edited for a version | Commit SHAs in tags; `BASE_IMAGE` default pointing at a version |
| Registry | `ghcr.io/hatchward/agent:{base,claude}`, pushed with the workflow's `GITHUB_TOKEN` | A `ghcr.io/hatchward` namespace (needs a GitHub org that does not exist and a classic PAT) and `ghcr.io/hatchward/core-agent` — both reversed during review |
| Credentials | Runner-local files under `~/.hatchward/secrets/`, outside `runner.yml` | Cloud-issued per-assignment tokens (control-plane scope); runner process environment |
| Output | `json` by default; quiet stderr | `stream-json` default (a 200-turn verbose stream exceeds the runner's 1 MiB cap) |

### Docker Sandboxes, considered

Docker's own product for this problem (`sbx`, docs.docker.com/ai/sandboxes) appeared
during implementation. It runs each agent in a microVM with a host-side proxy that
enforces a hostname allowlist and injects credentials into outbound headers so the agent
never sees the real value — a stronger boundary than this image's in-container iptables,
and exactly the SNI-proxy follow-up §5 names. It is not a replacement for this design:
it is a developer-machine CLI driven by `sbx run/create/exec`, requires Docker Desktop
or Docker's sbx daemon plus a Docker account login, gives the agent `sudo` and a nested
Docker Engine by design, and offers no launch path that fits the runner's
create/cp/start-with-manifest shape or its `docker` dependency. Two ideas are worth
borrowing later: host-side credential injection (the runner already holds the secret
files, so a proxy could inject them instead of mounting them) and a runner backend that
targets `sbx` where it is installed, treating the microVM as the isolation and this
image's contract as what runs inside it.

## 3. Layout

```
Dockerfile                   → ghcr.io/hatchward/agent:base
agent-entrypoint.sh          root phase, then setpriv → agent → exec
init-firewall.sh             default-DROP + allowlist
lib/prompt.sh                prompt / model / secret resolution, firewall guard
allow-domains.d/base         hosts every layer needs
allow-ranges.d/github        GitHub's published CIDRs, snapshot
smoke.sh                     real-container checks (CI and local)
README.md                    operator contract
claude/
  Dockerfile                 → ghcr.io/hatchward/agent:claude
  agent-claude.sh            default CMD
  allow-domains.d/claude     api.anthropic.com, claude.ai
tests/                       bun tests driving the scripts with recording fakes
.github/workflows/ci.yml     check, build + smoke; publish on v* tags
```

## 4. Entrypoint

Root phase, in order:

1. `init-firewall`. Nothing below runs with unrestricted egress.
2. Ownership: `chown -R agent /workspace` only when the directory or its first entry is
   not agent-owned (a `docker cp` writes root-owned files; a warm agent-owned volume
   costs nothing).
3. Stdin: if not a TTY, saved to `/run/hatchward/manifest.json` (0600, agent) and stdin
   reopened from `/dev/null`. The manifest must never reach `bash` or the CLI as input.
4. Secrets: for each name in `AGENT_STAGE_VARS` (base: `GH_TOKEN`; the Claude layer adds
   `ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN`), a value from
   `$NAME` or the file named by `$NAME_FILE` becomes an agent-owned 0400 copy under
   `/run/hatchward/secrets/`; `$NAME_FILE` is re-pointed at the copy and `$NAME` unset.
   Bind-mounted host files are typically unreadable by uid 1000, which is why root
   copies them (needs `DAC_READ_SEARCH`). A GitHub token goes to `gh auth login
   --with-token` on stdin, then `gh auth setup-git`, so git's credential helper works
   with no token in the environment.
5. Provision. Self-clone mode validates `AGENT_REPO` (`owner/name` or `https://`) and
   `AGENT_BASE_BRANCH` (`git check-ref-format --branch`) before any network call, clones
   an empty workspace with plain `git clone -q` (`gh repo clone` requires
   authentication even for public repositories), then `remote set-head origin --auto`,
   branch = `AGENT_BASE_BRANCH` or origin HEAD, `fetch`, `checkout -B`, `reset --hard`,
   `clean -fd`, `worktree prune`, `submodule update --init --recursive`. Provided-workspace
   mode touches nothing; an empty workspace only warns here (a debugging shell must
   still be possible) and the CLI-layer CMD makes it exit 2.
6. `safe.directory` and commit identity for the agent user only — root never runs git.
7. `exec setpriv --reuid=agent --regid=agent --init-groups --inh-caps=-all
   --bounding-set=-all --no-new-privs env HOME=/home/agent PATH=… "$@"`.

All entrypoint output is on stderr; fd 1 belongs to the command. Root-only paths are
env-overridable (`AGENT_WORKSPACE`, `AGENT_HOME`, `AGENT_RUN_DIR`, `AGENT_ALLOW_DIR`,
`AGENT_RESOLV_CONF`, `AGENT_USER`, `AGENT_LIB_DIR`) so the scripts run under tests outside
the image. Which variables are staged as secrets is `AGENT_STAGE_VARS`, set by each CLI
layer's Dockerfile (base: `GH_TOKEN`), so the base never learns a CLI's credential names.

## 5. Firewall

Gather addresses while egress is open, then lock down. Specifically:

- No non-loopback interface → one log line and exit 0. `--network none` is already
  stricter than these rules; failing there would be wrong, not fail-closed. An interface
  with unusable iptables is fatal.
- The iptables binary is chosen directly (`iptables-nft`, then `-legacy`, then
  `iptables`); no `update-alternatives` writes at runtime.
- Allowlist = every file in `allow-domains.d/` ∪ `AGENT_ALLOW_DOMAINS` (hostnames only;
  IP literals and CIDRs are refused there) ∪ the CIDRs in `allow-ranges.d/*`. Each host is
  resolved three times and the answers unioned. Resolved addresses and CIDRs in loopback,
  RFC 1918, link-local, CGNAT, multicast, reserved, benchmark or documentation ranges are
  dropped with a warning whatever their source.
- GitHub's published ranges ship as a snapshot in `allow-ranges.d/github` and are refreshed
  from `api.github.com/meta` at boot when that unauthenticated call is not rate-limited —
  it routinely is on CI runners, and without the ranges a `git clone` can connect to a
  github.com address the boot-time resolution never saw.
- IPv6: fatal when a v6 default route exists and ip6tables cannot be applied; a v6
  negative canary runs when a route exists.
- `AGENT_FIREWALL=0` writes `/run/hatchward/firewall-disabled`; a CMD that would run
  `--dangerously-skip-permissions` refuses unless `AGENT_UNSAFE_NO_FIREWALL=1`.
- **Proxy mode (contract 2, `AGENT_PROXY_URL` set):** the allowlist gather above is
  skipped entirely — `allow-domains.d/*` and `allow-ranges.d/*` are both inert — and
  egress is locked to exactly one destination: the proxy itself. Docker's embedded DNS
  resolver (`127.0.0.11`) is `REJECT`ed before the loopback `ACCEPT`, so a hostname
  lookup fails fast instead of hanging. Three canaries run before the
  `$AGENT_RUN_DIR/proxy-mode` marker is written: `getent hosts example.com` must fail
  (DNS is dead), a direct `curl --noproxy '*'` to an IPv4 and an IPv6 literal must both
  fail with a connect error (no path around the proxy), and a proxied
  `curl --proxy "$AGENT_PROXY_URL" --cacert "$AGENT_CA_FILE"` to `api.github.com` must
  succeed within 3 tries — this one is **fatal**, not a warning, because it is the
  agent's only egress path in this mode.

### Threat model

The firewall blocks the host, the LAN, sibling containers and casual egress, with port
53 to the configured resolver as the one hole. It is **not** exfiltration control: the
agent holds the credentials it was given and can reach every allowlisted host;
`pypi.org`, `files.pythonhosted.org`, `rubygems.org`, `deb.debian.org`, the
`githubusercontent.com` hosts and others sit on Fastly or Cloudflare anycast addresses
shared with arbitrary third-party sites, and DNS is an open low-bandwidth channel.
Addresses are resolved once at boot, so a CDN rotation can drop a host mid-run.

**Contract 2 closes most of that.** With `AGENT_PROXY_URL` set, the container never
holds the real Anthropic key or GitHub token — the runner hands it the sentinel
`hatchward-proxy-managed` instead, and a runner-owned MITM proxy (outside this image;
see hatchward/core's `internal/egressproxy`) rewrites the sentinel to the real
credential only on requests to the handful of hosts it injects for. The image's own
contribution is entirely defensive, not the injection itself: it trusts the runner's CA
(so the MITM leaf verifies), routes every client through the proxy (the env vars in
§4/README), and narrows the firewall to "the proxy and nothing else" so there is no path
to smuggle the sentinel to a real, non-proxied endpoint. `lib/prompt.sh`'s
`agent_require_proxy_or_secret` refuses the sentinel unless `init-firewall`'s own
`proxy-mode` marker is present, so a caller cannot hand a CLI layer the sentinel string
without an actual proxy in front of it. What contract 2 does **not** claim: it trusts the
proxy's allowlist and injection rules (a bug there is out of this image's blast radius to
prevent), and a client with its own trust store or its own non-env-driven proxy
configuration (a JVM, Bazel, anything that ignores `HTTPS_PROXY`/`NODE_EXTRA_CA_CERTS`)
is unsupported — its TLS handshake against the MITM leaf simply fails closed, which is
the safe direction but not a silent success.

The repository's contents are trusted as code: the CMD pre-trusts `/workspace` so the
repository's `.claude/settings.json` hooks fire in a headless run, which also means the
repository's hooks and MCP configuration execute with the agent's credentials.

## 6. Claude layer

`FROM ${BASE_IMAGE}` (default `agent:base`, the README's local build tag; the
smoke workflow passes the tag it just built and the publish job will pass the published
base by digest), Claude Code at a pinned `CLAUDE_VERSION` installed for the agent
user with auto-update disabled. `agent-claude`:

1. `agent_require_firewall`.
2. Empty workspace → exit 2 (`pre-clone the workspace or set AGENT_REPO`).
3. Prompt: `AGENT_PROMPT` → `AGENT_PROMPT_FILE` → manifest `.agent.prompt` plus a
   `## Task` section rendered from `.task.fields` (the control plane does not render
   task fields into the prompt template; without this the agent never sees its task).
4. Model: `AGENT_MODEL` → manifest `.agent.model` → none.
5. Credential: `ANTHROPIC_API_KEY`, else `CLAUDE_CODE_OAUTH_TOKEN` (each from the
   variable or its `_FILE`), exported into this shell immediately before `exec`; else
   exit 2.
6. Pre-trust: only `hasTrustDialogAccepted` and `hasCompletedProjectOnboarding` for the
   project directory in `~/.claude.json`.
7. `exec claude --dangerously-skip-permissions -p --output-format ${AGENT_OUTPUT_FORMAT:-json}
   [--verbose for stream-json] --max-turns ${AGENT_MAX_TURNS:-200} [--model m]` with the
   prompt on stdin.

### What a CLI layer must supply

`allow-domains.d/<cli>`, an `ENV AGENT_STAGE_VARS` line, `agent-<cli>.sh` built on
`lib/prompt.sh`, and its CLI's headless trust/config write. Codex (`codex/`, `:codex`) is the next
layer: the Codex CLI is an npm package (node via mise at build time), headless is
`codex exec --json --sandbox danger-full-access` (its own sandbox cannot run inside an
unprivileged container), trust is `~/.codex/config.toml`, egress is `api.openai.com
auth.openai.com chatgpt.com`.

## 7. Contract with the runner

See `README.md` for the operator table. Invariants the runner PR is
written against:

- The manifest arrives on stdin and is consumed by the entrypoint; the CLI reads
  `.agent.prompt`, `.agent.model`, `.task.fields` from the saved file. **The runner must
  `docker create -i`**: without `OpenStdin` set at create time, `docker start -a -i`
  attaches no stdin and the manifest silently never arrives — found by the smoke test
  against the runner's current argv, which lacks `-i`. PR 3 adds it.
- A pre-populated `/workspace` (via `docker cp`) is accepted as-is and re-owned.
- `--network none` is accepted (firewall skipped). With a network, the container needs
  `NET_ADMIN NET_RAW CHOWN DAC_READ_SEARCH SETUID SETGID SETPCAP` and nothing else;
  `--security-opt no-new-privileges` is compatible.
- Secrets arrive as files, named by `*_FILE`; values never appear in argv or environment.
- The prompt never appears in argv.
- `HATCHWARD_ASSIGNMENT_ACTION_SOCKET` passes through. The socket file must be readable
  and writable by uid 1000 (the runner chmods it 0666 inside its 0700 directory). Unix
  socket bind mounts do not cross Docker Desktop's VM boundary on macOS.
- Output is quiet by default; combined stdout+stderr is capped at 1 MiB by the runner.
- Exit 2 is a contract error with a named line; 1 with a `FATAL —` line is the firewall or
  an entrypoint validation failure; any other status is git's, gh's, or the CLI's own.

The runner change (PR 3) adds an operator-controlled image policy to `runner.yml`
(`runtime.agentImages`): only a matching `manifest.agent.image` receives a network, the
capabilities above and the secret files; anything else keeps today's `--network none`,
no capabilities and no secrets. Without that gate, a project revision could name any
image and receive the operator's credentials on the LAN. Secrets live under
`~/.hatchward/secrets/<projectId>/` with `_default/` as the fallback, are validated as
regular 0600/0400 files under a non-symlink 0700 directory, and are staged per assignment
as 0444 copies in a 0700 temporary directory (bind mounts expose the host inode, which
uid 1000 cannot read) that is removed with the container.

## 8. Testing

Two layers, deliberately:

**Fake-driven bun tests** (`tests/`) run the scripts with a PATH of
recording fakes (`lib/fakes.ts`): every fake writes NUL-separated argv and the named
environment variables to a log; the tests assert on those records and on exact stderr
lines plus exit codes, each refusal beside a happy path. The scripts are bash 3.2
compatible so these run on macOS and Linux alike. Hops pinned, with the mutation that
severs each:

| Value | Hop | Severing mutation |
|---|---|---|
| `GH_TOKEN` | env or `_FILE` → staged copy | drop the copy |
| | → `gh auth login --with-token` on **stdin** | pass as argv or env |
| | → `setup-git` under `HOME=/home/agent` | drop `HOME=` |
| | → final exec env has only `GH_TOKEN_FILE` | keep `GH_TOKEN` exported |
| | never in any recorded argv / stdout / stderr | `set -x`, URL-embedded token |
| prompt | `AGENT_PROMPT` → file → manifest (+task) | reorder, drop task render |
| | → CMD guard exit 2 | delete the guard |
| | → `claude` **stdin** | `-p "$prompt"` |
| model | `AGENT_MODEL` → manifest → absent | emit `--model ""` |

**Real-container smoke** (`smoke.sh`, run by `ci.yml` on
every image change and locally): uid/caps/no_new_privs; self-clone through the firewall;
host listener unreachable even when allowlisted by name, example.com blocked,
api.github.com reachable, host reachable with the firewall disabled (proves the
listener); no `NET_ADMIN` → exact FATAL line; Claude CMD without a credential → exit 2,
empty stdout; mise installs node through the firewall; the runner's create/cp/start
shape with a manifest on stdin; a foreign-uid 0600 secret readable via the staged copy.

Known gaps: the ip6tables fatal path is fakes-only (CI bridges have no IPv6); arm64 is
built and smoked locally, amd64 in CI.

## 9. Follow-ups

- `codex/` (`:codex`).
- Runner-side per-assignment log split (stderr to `~/.hatchward/logs/`, digest stdout only).
- GitHub App installation tokens replacing the operator's `github_token`.
- `hatchward-action` helper for the action socket; a TCP bridge for macOS hosts.
- SNI egress proxy replacing the boot-time IP allowlist.
- Image digest pinning in project configuration; Renovate for the base digest, mise and
  Claude pins.

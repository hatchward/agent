# hatchward/agent

The sandbox a coding agent runs in: one container per run, for any code base. Built for
the [hatchward](https://github.com/hatchward/core) runner and usable by hand.

What the sandbox guarantees: the agent runs as an unprivileged user with an empty
capability set and no way back to root; egress is default-DROP with a hostname
allowlist and no path to the host or LAN; credentials arrive as files staged for the
agent and never appear in argv or the environment; the prompt travels on stdin; the
workspace is either cloned fresh or used exactly as provided.

| Image | Source | Adds |
|---|---|---|
| `ghcr.io/hatchward/agent:base` | `Dockerfile` | Debian trixie, git + git-lfs, gh, jq, tini, the egress firewall, a uid-1000 `agent` user, mise |
| `ghcr.io/hatchward/agent:claude` | `claude/Dockerfile` | Claude Code CLI (pinned) and the `agent-claude` CMD |

Versions will be release tags: `:base-vX.Y.Z` and `:claude-vX.Y.Z` immutable, `:base`
and `:claude` moving; project configuration must pin a versioned tag. **Nothing publishes
these images until the first release tag.** `ci.yml` builds and smoke-tests every push; a
`v*` tag publishes both images with the workflow's own `GITHUB_TOKEN`. To build locally
(the Claude layer's `BASE_IMAGE` defaults to the tag this recipe produces):

```bash
docker build -t agent:base .
docker build -f claude/Dockerfile -t agent:claude .
./smoke.sh agent:base agent:claude
```

`smoke.sh` needs a Docker daemon and `python3` on the host (for a throwaway listener and,
in case 9, a MITM proxy standing in for the runner's), plus `openssl` for case 9's
throwaway CA.

Contract-3 images add the [portable macOS/Linux runtime](docs/portable-runtime.md),
selected explicitly by the hosted runner. The standard entrypoint documented
below remains available for existing Linux launches.

## What a run looks like

`tini` → `agent-entrypoint` (root) → `setpriv` drops to `agent` with an empty capability
bounding set → the command (`agent-claude` by default, or whatever you pass).

The root phase, in order: apply the firewall; re-own `/workspace` if a `docker cp` or a
foreign volume left it root-owned; save a non-TTY stdin as
`/run/hatchward/manifest.json` and detach stdin; stage secrets as agent-owned `0400`
files; authenticate `gh` over stdin; provision the repository; run the project's
`AGENT_SETUP` command, if one is set, as the agent; drop privileges.
Everything the entrypoint prints goes to stderr. fd 1 belongs to the command.

## Launching it by hand

Secrets and the prompt travel in an env file, never on the command line. `/run/secrets/`
below is only where this example mounts the host file; the image copies whatever the
`_FILE` variable points at to `/run/hatchward/secrets/` regardless.

```bash
envf="$(mktemp)"; chmod 600 "$envf"
cat > "$envf" <<EOF
ANTHROPIC_API_KEY_FILE=/run/secrets/anthropic_api_key
AGENT_PROMPT=Fix the failing test in apps/api and open a PR.
EOF
docker run --rm \
  --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --cap-add CHOWN \
  --cap-add DAC_READ_SEARCH --cap-add SETUID --cap-add SETGID --cap-add SETPCAP \
  --security-opt no-new-privileges --pids-limit 512 --cpus 2 --memory 3g \
  --mount type=bind,src="$HOME/.hatchward/secrets/_default/anthropic_api_key",dst=/run/secrets/anthropic_api_key,readonly \
  -v agent-ws-01:/workspace --env-file "$envf" -e AGENT_REPO=owner/repo \
  agent:claude
rm -f "$envf"
```

`NET_ADMIN` and `NET_RAW` are for the firewall, `CHOWN` for the workspace and secret
copies, `DAC_READ_SEARCH` so root can read a secret file owned by another uid, and
`SETUID`/`SETGID`/`SETPCAP` for the privilege drop. Nothing is granted to the agent
process itself. `--init` is unnecessary; `tini` is the image's entrypoint.

## Contract

| Variable | Layer | Meaning |
|---|---|---|
| `AGENT_REPO` | base | `owner/name` (GitHub) or an `https://` URL. Set: **self-clone mode** — an empty `/workspace` is cloned, then force-synced to the branch tip on every boot. Unset: **provided-workspace mode** — `/workspace` is used as found and never touched. |
| `AGENT_BASE_BRANCH` | base | Branch to sync in self-clone mode; default is the remote's default branch. |
| `AGENT_CLONE_ARGS` | base | Extra `git clone` arguments, e.g. `--filter=blob:none`. |
| `AGENT_WORKDIR` | base | Relative path under `/workspace` to start in; also becomes `CLAUDE_PROJECT_DIR`. |
| `AGENT_SETUP` | base | Command to run after provisioning, in the project dir. A word list, not a shell string, e.g. `bin/setup`. Unset or empty: no setup (the default). Self-clone mode only; see [Project setup](#project-setup). |
| `AGENT_SETUP_TIMEOUT` | base | Seconds before the setup command is killed. Default `600`. |
| `GH_TOKEN` / `GH_TOKEN_FILE` | base | GitHub token for private clones and pushes. Use a fine-grained token scoped to one repository, per project (a classic PAT needs `repo` and `read:org`; a GitHub App installation token is not accepted by `gh auth login` yet). It is staged to a file and given to `gh auth login` on stdin; the raw value is removed from the environment. |
| `AGENT_STAGE_VARS` | base (set by each CLI layer's Dockerfile) | Space-separated variable names the entrypoint stages as secrets. Base: `GH_TOKEN`; Claude adds `ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN`. |
| `AGENT_SANDBOXED` | base | Always `1`. A repository's hooks can key on it to know they run inside this sandbox. |
| `AGENT_GIT_NAME`, `AGENT_GIT_EMAIL` | base | Commit identity. Defaults `hatchward-agent` / `agent@hatchward.invalid`. |
| `AGENT_ALLOW_DOMAINS` | base | Extra egress hostnames, space or comma separated. Hostnames only; anything resolving to a private address is dropped anyway. |
| `AGENT_FIREWALL` | base | `0` disables the firewall (debugging only). The CLI-layer CMD then refuses to run unless `AGENT_UNSAFE_NO_FIREWALL=1`. |
| `AGENT_VERBOSE` | base | `1` logs the effective egress allowlist on stderr. |
| `HATCHWARD_ASSIGNMENT_ACTION_SOCKET` | base | Set by the runner; passed through untouched. Unix-socket bind mounts work on Linux hosts only. |
| stdin | base | A non-TTY stdin is saved as `/run/hatchward/manifest.json` (the runner's execution manifest) and detached. The caller must close stdin; a pipe held open blocks the boot. |
| `AGENT_PROMPT` / `AGENT_PROMPT_FILE` | CLI layer | The prompt, in that order of precedence; else the manifest's `agent.prompt` with its `task.fields` rendered as a `## Task` section. |
| `AGENT_MODEL` | CLI layer | The model; else the manifest's `agent.model`; else the CLI default. Claude passes it as `--model`. |
| `AGENT_MAX_TURNS` | claude | `--max-turns`, default 200. |
| `AGENT_OUTPUT_FORMAT` | claude | `json` (default, final result only), `stream-json` (adds `--verbose`), or `text`. The runner caps combined output at 1 MiB. |
| `ANTHROPIC_API_KEY` / `CLAUDE_CODE_OAUTH_TOKEN` (+ `_FILE`) | claude | Model credential; the file form is preferred. Exported only into the exec'd `claude` process. |
| `AGENT_PROXY_URL` | base (contract 2) | `http://user:token@host:port` of a runner-owned MITM proxy. Set: **proxy mode** — the firewall drops the domain allowlist and locks egress to this one address; `AGENT_CA_FILE` becomes required. |
| `AGENT_CA_FILE` | base (contract 2) | PEM certificate of the proxy's CA. Required and validated (`openssl x509 -noout`) when `AGENT_PROXY_URL` is set; installed into the system trust store before anything else runs. |
| `AGENT_CA_TRUST_DIR` | base (contract 2) | Where the CA is installed as `hatchward-proxy.crt`. Overridable for tests only; defaults to `/usr/local/share/ca-certificates`. |

Exit codes: `3` is a project setup failure — the `AGENT_SETUP` command exited non-zero or
timed out — with a `FATAL — setup failed (exit N): <cmd>` line, so a runner can tell a
project bug from an image bug. `2` is a contract error — no prompt, no credential, an empty workspace, or the
firewall disabled without the override — always with a named line on stderr. `1` with a
`FATAL —` line is the firewall or a validation failure in the entrypoint — in proxy mode
this also covers a missing/unreadable/non-PEM `AGENT_CA_FILE`, `AGENT_FIREWALL=0`, an
over-broad `NO_PROXY`/`no_proxy`, an unresolvable or malformed `AGENT_PROXY_URL`, and any
of the three proxy-mode canaries failing, and an `AGENT_SETUP` path that is absolute,
escapes the project, is missing or is not executable. Any other non-zero status is the failing tool's
own: `git` or `gh` during provisioning (their message, no `FATAL` line), or, once the CMD
has started, the agent CLI's.

## Project setup

A fresh clone is rarely ready to work in: generated env files, `core.hooksPath`,
installed dependencies and a prepared database are gitignored or machine-local. A project
that ships a "get a fresh clone ready" script opts in by naming it:

```bash
docker run … -e AGENT_REPO=owner/repo -e AGENT_SETUP="bin/setup" agent:claude
```

After the repository is at the remote tip and git identity is set, the entrypoint runs
`./bin/setup` in the project dir (`AGENT_WORKDIR` honoured) as the agent user, with an
empty capability set and the firewall already on, under `timeout AGENT_SETUP_TIMEOUT`
(default 600 seconds). The first word must be a relative path to an executable file
inside the project; the rest are its arguments, split on whitespace with no shell
interpretation.

- The script sees `AGENT_SETUP_PHASE=1` and `AGENT_SANDBOXED=1`, so it can skip server
  starts and interactive prompts. Its stdin is `/dev/null`.
- No staged-secret variable (`GH_TOKEN_FILE`, `ANTHROPIC_API_KEY_FILE`,
  `CLAUDE_CODE_OAUTH_TOKEN_FILE`, or anything in `AGENT_STAGE_VARS`) is in its
  environment. The staged files still exist on disk and are readable by the agent user:
  the guarantee is no environment handle, not isolation.
- In proxy mode it keeps the proxy and CA variables, so it reaches package registries
  the same way `git` does.
- Its stdout and stderr both go to the container's stderr.
- A non-zero exit or a timeout aborts the boot with exit `3`.
- It runs on every boot, including a warm volume, so **the command must be safe to
  re-run**. Stock Rails `bin/setup` starts a dev server unless told not to; pass the flag
  that stops it (`AGENT_SETUP="bin/setup --skip-server"`).
- Provided-workspace mode skips it with a log line: that mode promises the workspace is
  used as found.

Services the script depends on, such as Postgres, are the derived image's job to start
before this entrypoint runs.

## Proxy mode (contract 2)

`AGENT_PROXY_URL` set replaces the domain allowlist with a single trusted egress path: a
runner-owned MITM proxy that injects real credentials on behalf of sentinel values the
container never resolves into secrets itself. Before `init-firewall` runs at all,
`agent-entrypoint` validates and trusts `AGENT_CA_FILE`, then exports the same client env
vars to every provisioning step (`git`, `gh`) and the final command:
`NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `SSL_CERT_DIR`, `CURL_CA_BUNDLE`,
`GIT_SSL_CAINFO`, `REQUESTS_CA_BUNDLE`, `PIP_CERT`, `CARGO_HTTP_CAINFO`, `AWS_CA_BUNDLE`,
`DENO_CERT`, `DENO_TLS_CA_STORE=system,mozilla`, `UV_NATIVE_TLS=1`,
`NODE_USE_ENV_PROXY=1`, `CARGO_NET_GIT_FETCH_WITH_CLI=true`,
`HTTP_PROXY`/`HTTPS_PROXY`/`http_proxy`/`https_proxy=$AGENT_PROXY_URL`; `git config
--system http.proxy`/`http.sslCAInfo` cover clones done outside a CLI layer's own
git invocations. `allow-domains.d/*` and `allow-ranges.d/*` are both **inert** in this
mode — nothing in them is read — and `AGENT_ALLOW_DOMAINS` is ignored with a warning
rather than a fatal error, since a caller migrating from contract 1 may still set it.

Sentinel handling: the runner hands the container `hatchward-proxy-managed` in place of a
real `ANTHROPIC_API_KEY`/`CLAUDE_CODE_OAUTH_TOKEN`/`GH_TOKEN`. `lib/prompt.sh`'s
`agent_require_proxy_or_secret` (available for a CLI layer to call in place of
`agent_resolve_secret` when it wants proxy-mode support — `claude/agent-claude.sh` does not
yet opt in) accepts that exact value only when `init-firewall` has
written `$AGENT_RUN_DIR/proxy-mode` — proving a real proxy lockdown actually ran — and
refuses it (exit 2) otherwise, so a caller cannot pass the sentinel through to a real
endpoint by accident. Per client: Claude Code and Node's global `fetch` derive
`Proxy-Authorization: Basic` from the URL userinfo and need `NODE_USE_ENV_PROXY=1`; `gh`
and `git` (libcurl) do the same natively; `npm` and `mise` (reqwest) likewise. **Not
supported**: the JVM, Bazel, and anything else with its own trust store or its own
non-env-driven proxy configuration — their TLS handshake against the proxy's leaf
certificate fails closed rather than silently succeeding.

Secrets in the container: `/run/hatchward/secrets/<name>` (`0400`, agent-owned) — copies
made in the root phase from `$NAME` or `$NAME_FILE`. The `_FILE` variables are re-pointed
at the copies; the raw variables are unset before the drop.

## Firewall

Default-DROP on input, output and forward, then: loopback, established traffic, port 53
to the configured resolver, and the allowlist. The allowlist is the union of every file
in `/etc/hatchward/allow-domains.d/` (the base list plus one file per CLI layer) and
`AGENT_ALLOW_DOMAINS`. Hostnames are resolved at boot (three times each, so round-robin
answers are unioned); addresses in loopback, RFC 1918, link-local, CGNAT, multicast or
reserved ranges are dropped with a warning whatever their source. Static CIDRs in
`/etc/hatchward/allow-ranges.d/*` are permitted too — the base ships a snapshot of GitHub's
published ranges, refreshed live from `api.github.com/meta` when that call is not
rate-limited — so GitHub's rotating addresses stay reachable. A container
with no non-loopback interface (`--network none`) skips the firewall; one with an
interface but no `NET_ADMIN` refuses to start.

**What this is and is not.** It blocks the host, the LAN, sibling containers and casual
egress. It is not exfiltration control: the agent holds the credentials it was given and
can reach every allowlisted host, several of which share CDN addresses with the rest of
the internet, and DNS is an open channel. A hostname-aware egress proxy is the follow-up
that would close that.

### Project-specific egress hosts

Hosts only one project needs (an issue tracker, a package registry, a webhook endpoint)
belong in the launcher, not in the image's `allow-domains.d/base`. Pass them per run:

```sh
docker run ... -e AGENT_ALLOW_DOMAINS="api.notion.com hooks.slack.com sentry.io" ghcr.io/hatchward/agent:claude-v0.4.0
```

They are unioned with the baked-in lists, resolved at boot, and filtered like any other
entry. Hostnames only, space or comma separated. In proxy mode the variable is ignored
(see above): the runner's proxy owns the allowlist.

## Extending: what a CLI layer supplies

A layer image (`<cli>/`) builds `FROM` the base and adds exactly four
things: `allow-domains.d/<cli>` with the hosts its CLI needs (and, if it needs fixed
ranges, `allow-ranges.d/<cli>`), an `ENV AGENT_STAGE_VARS`
line naming its credential variables (keep `GH_TOKEN`), `agent-<cli>.sh` as the CMD, built
on `/usr/local/lib/hatchward/prompt.sh` (`agent_require_firewall`, `agent_resolve_prompt`,
`agent_resolve_model`, `agent_resolve_secret`), and whatever trust or config file its CLI
needs to run headless. The prompt goes to the CLI on stdin,
the credential is exported only into the exec'd process, and the CLI is `exec`'d so
`docker stop` reaches it.

## Running under the hatchward runner

**Today's hatchward runner does not launch this image usefully.** Its `worker.go`
(`src/cli/internal/hostedrunner/` in hatchward/core) creates
the container with `--network none`, no capabilities, no `-i` and no secret mounts, so
the firewall is skipped, no credential arrives and the manifest never reaches the
container. The runner change is a separate hatchward pull request written against this
contract:
provided-workspace mode, `docker create -i` with the flags above (`-i` is what lets
`start -a -i` attach stdin at all), `docker cp` of the operator's checkout into
`/workspace`, `docker start -a -i` with the execution manifest on stdin, secret files
staged from `~/.hatchward/secrets/`. The image then reads the prompt and model from the
manifest. An empty operator directory is a contract error: pre-clone the repository into
the workspace root. Combined stdout and stderr are capped at 1 MiB by the runner, which
is why the image is quiet by default and `json` is the default output format.

## Releasing

```bash
bin/release --dry-run 0.1.0   # every check, no tag
bin/release 0.1.0             # tag main's live tip and push; ci.yml publishes
```

The tag is the version. `bin/release` refuses unless the version moves forward past the
newest remote tag, the commit is on `main` (the live tip by default), CI's `check` and
`build-smoke` succeeded on that commit, `.github/releases/v<version>.md` and a matching
`CHANGELOG.md` entry exist in that commit's tree, and the tag does not exist yet. The
publish job then pushes `:base`, `:claude`, `:base-v<version>`, `:claude-v<version>` and
creates the GitHub release from the notes file.

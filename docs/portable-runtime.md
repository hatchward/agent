# Portable runtime (contract 3)

Contract-3 images expose an explicit `/usr/local/bin/hatchward-bootstrap`
entrypoint for the hosted runner. The standard image entrypoint still supports
its existing Linux firewall/provisioning mode. The portable mode requires a
Linux Docker engine (including the Linux VM provided by Docker Desktop on macOS)
with `/dev/fuse` and the default Docker security profile permitting FUSE mounts.
The native macOS runner talks to that engine through Docker exec streams.

The runner launches a read-only root, no network, no IPC shared-memory filesystem,
and a private Docker volume at `/hatchward-backing`. Startup requires only
SYS_ADMIN, CHOWN, SETUID, SETGID and SETPCAP. No host directory, Docker socket,
privileged mode, or unconfined profile is part of this contract.

`HATCHWARD_DISK_MIB` is the total size of an ext4 filesystem image, including
filesystem metadata. Workspace, home (including copied CLI installations), `/tmp`
and `/run` share this fixed capacity. Available payload space is smaller. The real Claude installation alone exceeds
256 MiB; provision at least 1 GiB for runtime validation and budget additional
space for the repository and toolchains. A full
filesystem fails writes; there is no unbounded or RAM-backed fallback. The
immutable root remains read-only and the backing image is root-only. FUSE mounts
use default_permissions,nosuid,nodev so kernel permission checks also protect
Unix socket path traversal. FUSE daemon, gateway, workload and final supervisor have empty
capability sets and no-new-privileges. The trusted bootstrap executes the dropped
supervisor before publishing readiness; neither image CMD nor imported code runs
during privileged setup. Every privileged helper pins a read-only system PATH,
uses absolute privilege-drop/interpreter paths, and ignores Python environment
configuration; agent-installed executables cannot shadow bootstrap tools during
channel replenishment.

The gateway runs as uid 10002, separately from workload uid 1000. It accepts only
loopback proxy and assignment action traffic. Host channel attachment requires
access to `/run/hatchward/bridge/control.sock` inside a private 0700 directory;
the workload cannot attach to it. Up to `org.hatchward.agent.slots` (48)
single-use Docker exec channels carry bytes to fixed host endpoints. The channel
starts with a P (proxy) or A (actions) dispatch byte, or C plus one endpoint index
byte for a companion endpoint (below), then
uses bounded D data frames and F half-close frames (one-byte kind, four-byte
big-endian length). Explicit half-close avoids Docker exec stdout waiting for
process exit before the peer can send its response. `/run/hatchward/actions.sock` points at the
public gateway socket; neither that socket nor the proxy supplies unrestricted
host networking.

After `/run/hatchward/ready` appears, `hatchward-configure` accepts stdin JSON
`{"ca":"public PEM CA","proxyUrl":"http://hatchward:token@127.0.0.1:3128","env":{}}`.
Empty CA and proxy enable networkless execution. Credential keys are restricted
to GitHub/Anthropic credential names and values must be the literal
`hatchward-proxy-managed`; real provider credentials remain on the host. The
only other keys are the routed repository (below), whose values are real. It
creates a bounded CA bundle and protected runtime configuration. `hatchward-import`
extracts a stdin tar as the agent, without adopting archive owners or privileged
modes. `hatchward-run COMMAND...` accepts a JSON execution manifest on stdin,
prepares agent-owned Git configuration, and executes the inspected image CMD as
uid 1000 with empty capabilities. The runner removes the assignment container and
private volume on completion or cancellation. A gateway or FUSE child exit terminates
the supervisor so daemon failure cannot silently leave a usable sandbox; ordinary
adopted workload children are reaped without terminating the assignment.

## Declared secrets and companion endpoints (`org.hatchward.agent.features`)

Images labelled `org.hatchward.agent.features="declared-env,endpoints,ssh-client"`
accept two more `hatchward-configure` keys. Every other key is still rejected.

- **`declaredEnv`** (`declared-env`): a list of at most 16 `{"name", "sentinel"}`
  entries. `sentinel` must be exactly `hatchward-secret-` + the lowercased name; the
  host proxy swaps it for the value. `name` must match `^[A-Z][A-Z0-9_]{0,63}$` and
  must not be `PATH`, `HOME`, `USER`, `SHELL`, `NODE_OPTIONS`, `BASH_ENV`, `ENV`,
  `HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`, `ALL_PROXY`, or start with `LD_`, `GIT_`,
  `AGENT_`, `HATCHWARD_`, `ANTHROPIC_`, `CLAUDE_`, `GH_`, `GITHUB_` or `SSH_`.
  Requires the proxy and CA.
- **`endpoints`** (`endpoints`): at most 32 entries
  `{"index", "name", "listen", "env"?, "sshHosts"?}`.
  - `index` is a unique byte (0–255): the runner's endpoint-table index.
  - `name` matches `^[a-z][a-z0-9-]{0,31}$` and is unique.
  - `listen` is `{"unix": NAME}` (same pattern; not `actions`, `reload` or `control`)
    or `{"tcp": PORT, "address"?: ADDR}`: port 1024–65535, address in `127.0.0.0/8`
    (default `127.0.0.1`), never `127.0.0.1:3128`, no two endpoints on one listener.
  - `env` (at most 8) holds values the runner generated from the listener, so each
    must equal the endpoint's own address, port, socket path
    (`/run/hatchward/NAME.sock`) or URL host (the address, or the percent-encoded
    socket path). Names follow the `declaredEnv` rules and are unique across `env`,
    `declaredEnv` and every endpoint. The one exception is `SSH_AUTH_SOCK`, accepted
    only on a Unix endpoint and only naming that endpoint's own socket.
  - `sshHosts` (`ssh-client`; at most 4, requires the proxy):
    `{"host", "port", "hostKeys"}` with a lowercase hostname, a port 1–65535 and 1–8
    pinned OpenSSH public keys.

With endpoints, `hatchward-configure` (uid 0, no capabilities) writes, into the
root-owned `/run/hatchward`:

- `endpoints.json` (`0444`): `{"endpoints": [{"index", "name", "unix" | "tcp" + "address"}]}`;
- for each Unix endpoint, a symlink `/run/hatchward/NAME.sock` →
  `/run/hatchward/gateway/NAME.sock`;
- with `sshHosts`, `ssh_config` and `known_hosts` (`0444`). Each host gets
  `ProxyCommand /usr/local/bin/hatchward-connect %h %p`, `UserKnownHostsFile
  /run/hatchward/known_hosts`, `StrictHostKeyChecking yes`, its `Port` when only one
  is pinned, and `IdentityAgent` when the endpoint is a Unix socket. The image's
  `/etc/ssh/ssh_config.d/hatchward.conf` includes it.

It then connects to `/run/hatchward/gateway/reload.sock` and waits up to 5 s for the
byte `1`. Anything else, or a timeout, exits non-zero, and `config.json` is not
written, so `hatchward-run` refuses to start. The gateway (uid 10002) answers each
`reload.sock` connection by re-reading `endpoints.json`, binding the listeners it has
not bound yet (Unix sockets `0666` under `/run/hatchward/gateway/`, TCP on the
loopback address), and replying `1`, or `0` if the table is missing or invalid, a
bind fails, or an already-bound index changed. Reload is idempotent and binds only
what the root-owned table names, so the socket is `0666`. A connection to an
endpoint listener waits for a host channel like proxy and action traffic do, and
opens it with `C` plus the endpoint's index. The declared and endpoint env join the
image command's environment.

`hatchward-connect HOST PORT` opens an HTTP `CONNECT` through `$HTTPS_PROXY`, sending
the proxy URL's user and password as `Proxy-Authorization: Basic`, and relays stdio
over the tunnel. A non-2xx answer exits non-zero with the status line.

## Routed repository (`org.hatchward.agent.clone="1"`)

Images labelled `org.hatchward.agent.clone="1"` can clone the assignment's
repository themselves instead of receiving the runner's local folder through
`hatchward-import`. The runner uses this when a project routes tickets across
several repositories.

1. **Configure.** The `hatchward-configure` `env` object may carry two more
   keys beside the credential sentinels. Their values are real, not the sentinel:
   - `AGENT_REPO` must match `^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$` (the whole value;
     a trailing newline is rejected).
   - `AGENT_BASE_BRANCH` must pass `git check-ref-format --branch` and must not
     start with `-`. It may be absent. It is rejected without `AGENT_REPO`.

   Any other value is rejected like any other bad key: a non-zero exit with the
   generic configure error. `AGENT_REPO` needs network, so the proxy and CA must
   be configured, as for the credential keys.
2. **Clone.** With `AGENT_REPO` configured, the runner skips `hatchward-import`,
   so `/workspace` starts empty. `hatchward-run` first writes the manifest and the
   agent's Git configuration, then clones before it executes the image command:
   `git clone [--branch AGENT_BASE_BRANCH] https://github.com/AGENT_REPO.git /workspace`,
   then `git submodule update --init --recursive`. It runs as uid 1000 with the
   workload environment: the configured proxy, the CA bundle, and
   `GH_TOKEN=hatchward-proxy-managed`. Git authenticates through
   `gh auth git-credential` with that sentinel, which the host proxy swaps for
   the real token, as the standard entrypoint does. Without `AGENT_BASE_BRANCH`
   the clone checks out the remote's default branch. Terminal prompts are off,
   so a missing credential fails instead of hanging. The checkout matches the
   standard entrypoint's self-clone of an empty workspace: local branch = base
   branch at the remote tip, `origin` = `https://github.com/AGENT_REPO.git`,
   `origin/HEAD` set, and submodules initialised. `AGENT_REPO` and
   `AGENT_BASE_BRANCH` stay in the image command's environment.
3. **Failure.** If the clone or submodule step fails, `hatchward-run` exits 1
   without running the image command. It prints one stderr line:
   `hatchward-run: clone of OWNER/NAME failed: CAUSE`. `CAUSE` is git's first
   `fatal:`/`error:` line, capped at 400 characters, with the proxy URL, its
   token and any URL userinfo replaced by `[redacted]`. Other preparation
   failures keep the generic `hatchward-run: workload preparation failed`.
4. **Unchanged without `AGENT_REPO`.** No clone runs and no Git command beyond
   the existing configuration runs.

The bounded filesystem is served by fuse2fs 1.47.4, built from a pinned,
checksum-verified e2fsprogs release in the `Dockerfile`'s `fuse2fs` stage.
Debian trixie's 1.47.2 ignores `O_TRUNC` on open, so a shorter rewrite (a git
submodule's `.git` file, any shell `>` over an existing file) kept the old
tail; trixie has no newer package or backport. `docker_runtime.py` asserts that
`O_TRUNC` truncates and that the routed-repository clone initialises a submodule.

It is mounted with fuse2fs `fakeroot`. fuse2fs (1.47.4 included) otherwise
refuses `open(O_CREAT|O_RDWR, 0444)`, the call git uses for every loose object,
so no git write (clone, add, commit) could succeed.
`fakeroot` only skips fuse2fs's own permission checks. The kernel still enforces
modes and ownership through `default_permissions`, and new files are still owned
by the caller. `docker_runtime.py` asserts that the workload cannot chmod, chown,
unlink or create in root-owned paths.

Validation commands (local, no publishing):

```sh
docker build -t agent:macos-base .
docker build -f claude/Dockerfile --build-arg BASE_IMAGE=agent:macos-base -t agent:macos-claude .
python3 -m unittest discover -s runtime/tests -p 'test_*.py'
python3 runtime/tests/docker_runtime.py agent:macos-base
```

`docker_runtime.py` checks actual import/run behavior, git object writes,
`O_TRUNC`, the routed-repository clone with a submodule (against bare fixture repositories through
`url.insteadOf`, since the container has no network; this does not exercise the
proxy path to github.com) and its failure line, all persistent process
capability sets, protected paths, adversarial PATH shadowing, and shared filesystem
exhaustion, orphan reaping, and shutdown on gateway failure. Pass a second size argument (for example `1024`) to test the Claude
image, which also executes `claude --version`. Native Linux
validation and full hosted assignment evidence are tracked separately by the
runner integration; passing this test alone is not proof of the complete product.

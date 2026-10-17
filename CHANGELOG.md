# Changelog

All notable changes to the agent images are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows
[Semantic Versioning](https://semver.org/). Each entry is condensed from that version's
`.github/releases/<tag>.md`, which the publish job turns into the GitHub release.

## [Unreleased]

### Added
- `AGENT_FIREWALL_REFRESH` (default `60`, `0` disables): a root-owned
  `agent-firewall-refresh` loop re-resolves the allowlisted hostnames for the life of
  the run and appends rules for new public addresses. It fixes intermittent timeouts to
  GitHub hosts whose DNS rotates through addresses outside GitHub's published ranges.
  Additive only, with the same non-public filter as at boot, and capped by
  `AGENT_FIREWALL_RULE_CAP` (default `2048`). GitHub's ranges are re-fetched every ten
  ticks with the stored ETag. Off in proxy mode.
- `agent-egress-check` (run as root): reports whether every address the allowlist
  resolves to right now is covered by a rule.
- Boot logs the address count from each allowlist source and the meta fetch outcome;
  `AGENT_VERBOSE=1` adds each resolved address.

### Changed
- `allow-ranges.d/github` snapshot refreshed from `api.github.com/meta`.
- Additive; no contract change. With `AGENT_FIREWALL_REFRESH=0` the firewall behaves as
  in 0.5.0.

## [0.5.0]

### Added
- `AGENT_SETUP` / `AGENT_SETUP_TIMEOUT`: run a project-declared setup command (such as
  `bin/setup`) after provisioning, as the agent, with no staged-secret variables in its
  environment. Failure or timeout exits `3`. Unset, the boot is unchanged. Additive; no
  contract change.

## [0.4.0]

### Changed
- Images move to `ghcr.io/hatchward/agent`; the source label, package name, and
  docs follow the repository's move to the hatchward organization. No contract change.

## [0.3.0]

### Added
- Portable image contract 3 for native macOS runners using Docker Desktop:
  bounded Docker exec transport for model proxy and assignment actions, fixed-size
  ext4/FUSE storage, and capability-free workloads with host-held credentials.
- Private control-socket enforcement, immutable privileged helper paths, runtime
  daemon supervision, and actual Docker isolation/concurrency/cleanup tests.

### Changed
- Contract-3 execution requires a matching runner and explicit image trust.
  Workspace, home, temporary files, and runtime state share the assignment disk
  ceiling; the Claude image needs at least 1 GiB plus repository/build capacity.

## [0.2.0] - unreleased

### Added
- Image contract 2: proxy mode. `AGENT_PROXY_URL` (+ `AGENT_CA_FILE`) routes every
  client — `git`, `gh`, the agent CLI, `mise`, `npm`, Node's `fetch` — through a
  runner-owned MITM proxy instead of the domain allowlist: the firewall drops to a
  single ACCEPT for the proxy address and rejects Docker's embedded DNS resolver
  outright, `agent-entrypoint` trusts the proxy's CA and exports the client env vars
  every provisioning step and the final command need, and `lib/prompt.sh` gains
  `agent_require_proxy_or_secret`, which accepts the runner's credential sentinel only
  when the firewall's own proxy-mode marker proves a real lockdown is in effect.
  `allow-domains.d/*` and `allow-ranges.d/*` are inert in this mode.
- `smoke.sh` case 9: a host-side MITM fake proxy exercises the full sentinel-to-header
  path for both the Anthropic API-key and OAuth-token sentinels, `gh`, `git`, `mise` and
  Node's `fetch`, alongside the proxy-mode firewall's DNS and IP-literal canaries.

## [0.1.0] - unreleased

### Added
- `ghcr.io/influpert/agent:base`: Debian trixie (digest-pinned), git + git-lfs, gh, jq,
  tini, mise, a uid-1000 `agent` user, the default-DROP egress firewall with a composable
  hostname allowlist and shipped GitHub ranges, secret staging as agent-owned files, two
  workspace provisioning modes, and a `setpriv` privilege drop to an empty capability set.
- `ghcr.io/influpert/agent:claude`: Claude Code 2.1.236 and the `agent-claude` CMD that runs
  one headless session with the prompt on stdin and the credential only in its process.
- `smoke.sh`, the fake-driven test suite, `ci.yml` (check, build + smoke, publish on `v*`
  tags) and `bin/release`.

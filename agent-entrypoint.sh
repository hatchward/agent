#!/usr/bin/env bash
# Entrypoint for the hatchward agent image.
#
# Runs as root only long enough to apply the egress firewall, fix workspace
# ownership, capture stdin, stage secrets and provision the repository; then it
# drops to the unprivileged "agent" user with an empty capability bounding set
# and execs the command (the CLI layer's CMD, or whatever the caller passed).
# One root process outlives the drop: agent-firewall-refresh, which keeps the
# egress allowlist current and which the agent user cannot signal.
#
# Two provisioning modes:
#   self-clone          AGENT_REPO is set: clone an empty /workspace over HTTPS,
#                       then force-sync to the tip of AGENT_BASE_BRANCH (or the
#                       remote's default branch) on every boot.
#   provided workspace  AGENT_REPO is unset: /workspace is whatever the caller
#                       mounted or copied in (the hatchward runner does
#                       `docker cp`); it is not touched.
#
# Everything this script prints goes to stderr. fd 1 belongs to the command,
# whose stdout the runner captures. Runtime paths are overridable so the script
# runs under tests outside the image.
set -euo pipefail
# Never trace (a SHELLOPTS=xtrace in the environment would print secret values)
# and create every file closed until its mode is set explicitly.
set +x
umask 077

AGENT_WORKSPACE="${AGENT_WORKSPACE:-/workspace}"
AGENT_HOME="${AGENT_HOME:-/home/agent}"
AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"
AGENT_USER="${AGENT_USER:-agent}"
AGENT_PATH="$AGENT_HOME/.local/share/mise/shims:$AGENT_HOME/.local/bin:$PATH"
# Secret variables staged for the agent: a value in $NAME or a path in
# $NAME_FILE. CLI layers extend the list with their own credential names.
AGENT_STAGE_VARS="${AGENT_STAGE_VARS:-GH_TOKEN}"

log() { echo "agent-entrypoint: $*" >&2; }
fatal() { log "FATAL — $*"; exit 1; }

# 0. Proxy mode (contract 2): AGENT_PROXY_URL routes every client through a
# runner-owned MITM proxy instead of the domain allowlist. This must happen
# before init-firewall — the CA has to be trusted and the client env vars
# exported before ANYTHING (including provisioning's own git/gh calls, and
# init-firewall's own positive canary) makes a TLS connection.
if [ -n "${AGENT_PROXY_URL:-}" ]; then
  AGENT_CA_TRUST_DIR="${AGENT_CA_TRUST_DIR:-/usr/local/share/ca-certificates}"
  if [ -z "${AGENT_CA_FILE:-}" ] || [ ! -r "$AGENT_CA_FILE" ]; then
    fatal "AGENT_CA_FILE is required and must be readable when AGENT_PROXY_URL is set"
  fi
  openssl x509 -noout -in "$AGENT_CA_FILE" >/dev/null 2>&1 \
    || fatal "AGENT_CA_FILE '$AGENT_CA_FILE' is not a valid PEM certificate"
  [ "${AGENT_FIREWALL:-1}" != "0" ] \
    || fatal "AGENT_FIREWALL=0 is not allowed when AGENT_PROXY_URL is set"

  # NO_PROXY/no_proxy must carry only loopback names: anything else would let
  # a client bypass the proxy (and its CA-trust, and the firewall's single
  # allowed destination) for the hosts it names.
  loopback_only() {
    for tok in $(printf '%s' "$1" | tr ',' ' '); do
      case "$tok" in
        localhost|127.0.0.1|::1) ;;
        *) return 1 ;;
      esac
    done
    return 0
  }
  for var in NO_PROXY no_proxy; do
    val="${!var:-}"
    [ -z "$val" ] || loopback_only "$val" \
      || fatal "NO_PROXY '$val' must contain only loopback names when AGENT_PROXY_URL is set"
  done

  if [ -n "${AGENT_ALLOW_DOMAINS:-}" ]; then
    log "WARNING — AGENT_ALLOW_DOMAINS is ignored when AGENT_PROXY_URL is set (proxy allowlist is enforced by the runner)"
  fi

  mkdir -p "$AGENT_CA_TRUST_DIR"
  cp "$AGENT_CA_FILE" "$AGENT_CA_TRUST_DIR/hatchward-proxy.crt"
  update-ca-certificates

  export NODE_EXTRA_CA_CERTS="$AGENT_CA_FILE"
  export SSL_CERT_FILE="$AGENT_CA_FILE"
  export SSL_CERT_DIR="/etc/ssl/certs"
  export CURL_CA_BUNDLE="$AGENT_CA_FILE"
  export GIT_SSL_CAINFO="$AGENT_CA_FILE"
  export REQUESTS_CA_BUNDLE="$AGENT_CA_FILE"
  export PIP_CERT="$AGENT_CA_FILE"
  export CARGO_HTTP_CAINFO="$AGENT_CA_FILE"
  export AWS_CA_BUNDLE="$AGENT_CA_FILE"
  export DENO_CERT="/etc/ssl/certs/ca-certificates.crt"
  export DENO_TLS_CA_STORE="system,mozilla"
  export UV_NATIVE_TLS="1"
  export NODE_USE_ENV_PROXY="1"
  export CARGO_NET_GIT_FETCH_WITH_CLI="true"
  export HTTP_PROXY="$AGENT_PROXY_URL"
  export HTTPS_PROXY="$AGENT_PROXY_URL"
  export http_proxy="$AGENT_PROXY_URL"
  export https_proxy="$AGENT_PROXY_URL"

  git config --system http.proxy "$AGENT_PROXY_URL"
  git config --system http.sslCAInfo "$AGENT_CA_FILE"
fi

# The privilege drop: the agent user with every capability removed from the
# bounding and inheritable sets and no way to regain one. One definition, used
# by as_agent for the provisioning steps and by the final exec.
DROP=(setpriv --reuid="$AGENT_USER" --regid="$AGENT_USER" --init-groups
  --inh-caps=-all --bounding-set=-all --no-new-privs
  env HOME="$AGENT_HOME" PATH="$AGENT_PATH")
as_agent() { "${DROP[@]}" "$@"; }

# 1. Firewall first: nothing below may run with unrestricted egress.
refresh="${AGENT_FIREWALL_REFRESH:-60}"
case "$refresh" in
  ''|*[!0-9]*) fatal "AGENT_FIREWALL_REFRESH '$refresh' must be a whole number of seconds" ;;
esac
init-firewall

# Keep the allowlist current for the life of the run: a root-owned loop that
# re-resolves the same hostnames and appends rules for new public addresses.
# Only when init-firewall left an allowlist in force (its state file), so never
# with AGENT_FIREWALL=0, in proxy mode, or with no egress interface. Launched
# from a subshell that exits at once, so it is orphaned to tini, which reaps
# it; the exec'd command, which keeps this PID, never has it as a child. Off
# fd 1, and with none of this phase's environment: the raw secret variables
# are still set here.
if [ -f "$AGENT_RUN_DIR/firewall-seen" ] && [ -z "${AGENT_PROXY_URL:-}" ] \
  && [ "${AGENT_FIREWALL:-1}" != "0" ]; then
  if [ "$refresh" = 0 ]; then
    log "firewall refresh disabled via AGENT_FIREWALL_REFRESH=0"
  else
    (setsid env -i PATH="$PATH" AGENT_RUN_DIR="$AGENT_RUN_DIR" AGENT_FIREWALL_REFRESH="$refresh" \
      ${AGENT_LIB_DIR:+AGENT_LIB_DIR="$AGENT_LIB_DIR"} \
      ${AGENT_FIREWALL_RULE_CAP:+AGENT_FIREWALL_RULE_CAP="$AGENT_FIREWALL_RULE_CAP"} \
      agent-firewall-refresh </dev/null >&2 &)
  fi
fi

# The run dir must stay traversable by the agent (umask 077 above would make a
# fresh one root-only): its files are agent-owned, the directory is root's.
mkdir -p "$AGENT_RUN_DIR" "$AGENT_WORKSPACE"
chmod 755 "$AGENT_RUN_DIR"
agent_uid="$(id -u "$AGENT_USER")"

# 2. Ownership. A named volume or a `docker cp`'d tree arrives root-owned; the
# recursive chown is paid only when something is actually foreign.
owner_of() { stat -c %u "$1"; }
needs_chown=0
[ "$(owner_of "$AGENT_WORKSPACE")" = "$agent_uid" ] || needs_chown=1
if [ "$needs_chown" = 0 ]; then
  first_entry="$(find "$AGENT_WORKSPACE" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)"
  if [ -n "$first_entry" ] && [ "$(owner_of "$first_entry")" != "$agent_uid" ]; then
    needs_chown=1
  fi
fi
[ "$needs_chown" = 0 ] || chown -R "$AGENT_USER:$AGENT_USER" "$AGENT_WORKSPACE"

# 3. Stdin. The hatchward runner writes the execution manifest to stdin. Save
# it for the CLI layer and make sure no later process can read stdin as input.
manifest="$AGENT_RUN_DIR/manifest.json"
if [ ! -t 0 ]; then
  log "reading the manifest from stdin (the caller must close it)"
  cat > "$manifest"
  if [ -s "$manifest" ]; then
    chmod 600 "$manifest"
    chown "$AGENT_USER:$AGENT_USER" "$manifest"
  else
    rm -f "$manifest"
  fi
  exec </dev/null
fi

# 4. Secrets. A value may arrive as $NAME or as a file named by $NAME_FILE.
# Either way it ends up as an agent-owned 0400 copy under the run dir, the
# $NAME_FILE variable points at the copy, and the raw $NAME is removed from
# the environment so no descendant of the agent inherits a value.
secrets_dir="$AGENT_RUN_DIR/secrets"
# Root creates the 0700 directory and writes the copies into it, then hands the
# directory to the agent once staging is done. The order matters: this root has
# no CAP_DAC_OVERRIDE, so it cannot create files inside a directory it does not
# own, and the agent cannot traverse one root owns.
ensure_secrets_dir() {
  [ -d "$secrets_dir" ] && return 0
  mkdir -p "$secrets_dir"
  chmod 700 "$secrets_dir"
}
stage_secret() {
  local name="$1" file_var="${1}_FILE" value src dest
  dest="$secrets_dir/$(printf '%s' "$name" | tr '[:upper:]' '[:lower:]')"
  value="${!name:-}"
  src="${!file_var:-}"
  if [ -n "$value" ]; then
    ensure_secrets_dir
    printf '%s\n' "$value" > "$dest"
  elif [ -n "$src" ]; then
    [ -r "$src" ] || fatal "$file_var='$src' is not readable"
    ensure_secrets_dir
    cp "$src" "$dest"
  else
    return 0
  fi
  chmod 400 "$dest"
  chown "$AGENT_USER:$AGENT_USER" "$dest"
  unset "$name"
  export "$file_var=$dest"
}
[ ! -d "$secrets_dir" ] || rm -rf "$secrets_dir"
for name in $AGENT_STAGE_VARS; do
  stage_secret "$name"
done
[ ! -d "$secrets_dir" ] || chown "$AGENT_USER:$AGENT_USER" "$secrets_dir"

# GitHub auth: the token goes to gh on stdin and is stored in the agent's own
# gh hosts file, so git's credential helper works without a token in env.
if [ -n "${GH_TOKEN_FILE:-}" ]; then
  as_agent gh auth login --with-token < "$GH_TOKEN_FILE"
  as_agent gh auth setup-git
fi

# 5. Provision.
repo_url=""
if [ -n "${AGENT_REPO:-}" ]; then
  case "$AGENT_REPO" in
    https://*@*) fatal "AGENT_REPO must not carry credentials; use GH_TOKEN_FILE" ;;
    https://*) repo_url="$AGENT_REPO" ;;
    *)
      if printf '%s' "$AGENT_REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$'; then
        repo_url="https://github.com/$AGENT_REPO.git"
      else
        fatal "AGENT_REPO '$AGENT_REPO' must be owner/name or an https:// URL"
      fi
      ;;
  esac
fi

branch="${AGENT_BASE_BRANCH:-}"
if [ -n "$repo_url" ]; then
  clone_args=""
  if [ -n "$branch" ]; then
    as_agent git -C "$AGENT_WORKSPACE" check-ref-format --branch "$branch" >/dev/null 2>&1 \
      || fatal "AGENT_BASE_BRANCH '$branch' is not a valid branch name"
    clone_args="--branch $branch"
  fi
  if [ ! -d "$AGENT_WORKSPACE/.git" ]; then
    # shellcheck disable=SC2086 # AGENT_CLONE_ARGS and clone_args are word lists by contract
    as_agent git clone -q ${AGENT_CLONE_ARGS:-} $clone_args "$repo_url" "$AGENT_WORKSPACE"
  fi
  as_agent git -C "$AGENT_WORKSPACE" remote set-head origin --auto >/dev/null
  if [ -z "$branch" ]; then
    branch="$(as_agent git -C "$AGENT_WORKSPACE" symbolic-ref --short refs/remotes/origin/HEAD | sed 's|^origin/||')"
    [ -n "$branch" ] || fatal "could not determine the default branch of $repo_url; set AGENT_BASE_BRANCH"
  fi
  # A dirty or stale tree is impossible after this: the branch is exactly the
  # remote tip. clean -fd keeps ignored paths (a warm volume's dependency caches).
  as_agent git -C "$AGENT_WORKSPACE" fetch -q origin "+refs/heads/$branch:refs/remotes/origin/$branch"
  as_agent git -C "$AGENT_WORKSPACE" checkout -q -B "$branch" "origin/$branch"
  as_agent git -C "$AGENT_WORKSPACE" reset -q --hard "origin/$branch"
  as_agent git -C "$AGENT_WORKSPACE" clean -q -fd
  as_agent git -C "$AGENT_WORKSPACE" worktree prune
  as_agent git -C "$AGENT_WORKSPACE" submodule -q update --init --recursive
elif [ -z "$(find "$AGENT_WORKSPACE" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  log "WARNING — /workspace is empty and AGENT_REPO is unset; nothing to provision"
fi

# The agent, not root, gets the safe.directory entry: root never runs git here.
as_agent git config --global --add safe.directory "$AGENT_WORKSPACE"
as_agent git config --global user.name "${AGENT_GIT_NAME:-hatchward-agent}"
as_agent git config --global user.email "${AGENT_GIT_EMAIL:-agent@hatchward.invalid}"

project_dir="$AGENT_WORKSPACE"
if [ -n "${AGENT_WORKDIR:-}" ]; then
  case "/$AGENT_WORKDIR/" in
    //*|*/../*) fatal "AGENT_WORKDIR '$AGENT_WORKDIR' must be a relative path inside /workspace" ;;
  esac
  project_dir="$AGENT_WORKSPACE/$AGENT_WORKDIR"
  [ -d "$project_dir" ] || fatal "AGENT_WORKDIR '$AGENT_WORKDIR' does not exist under /workspace"
fi
cd "$project_dir"

# 6. Project setup. AGENT_SETUP names a command the project ships (usually
# bin/setup) to get a fresh clone ready: hooks, dependencies, generated env
# files. It is repository code, so it runs as the agent, with no handle on any
# staged secret, under a timeout; a failure aborts the boot with exit 3 rather
# than start the agent in a half-prepared workspace.
setup_cmd=()
read -r -a setup_cmd <<< "${AGENT_SETUP:-}" || true
if [ "${#setup_cmd[@]}" -gt 0 ]; then
  if [ -z "$repo_url" ]; then
    log "AGENT_SETUP is ignored in provided-workspace mode (AGENT_REPO is unset)"
  else
    setup_timeout="${AGENT_SETUP_TIMEOUT:-600}"
    case "$setup_timeout" in
      ''|*[!0-9]*|0) fatal "AGENT_SETUP_TIMEOUT '$setup_timeout' must be a positive number of seconds" ;;
    esac
    setup_exe="${setup_cmd[0]}"
    case "/$setup_exe/" in
      //*|*/../*) fatal "AGENT_SETUP '$setup_exe' must be a relative path inside the project" ;;
    esac
    [ -f "$project_dir/$setup_exe" ] \
      || fatal "AGENT_SETUP '$setup_exe' does not exist in the project"
    as_agent test -x "$project_dir/$setup_exe" \
      || fatal "AGENT_SETUP '$setup_exe' is not executable"
    setup_unset=()
    for name in GH_TOKEN ANTHROPIC_API_KEY CLAUDE_CODE_OAUTH_TOKEN $AGENT_STAGE_VARS; do
      setup_unset+=(-u "$name" -u "${name}_FILE")
    done
    setup_cmd[0]="./$setup_exe"
    log "running project setup: $AGENT_SETUP"
    setup_status=0
    "${DROP[@]}" env "${setup_unset[@]}" AGENT_SETUP_PHASE=1 AGENT_SANDBOXED=1 \
      timeout -k 10 "$setup_timeout" "${setup_cmd[@]}" </dev/null >&2 || setup_status=$?
    if [ "$setup_status" != 0 ]; then
      [ "$setup_status" != 124 ] || log "setup timed out after ${setup_timeout}s"
      log "FATAL — setup failed (exit $setup_status): $AGENT_SETUP"
      exit 3
    fi
  fi
fi

# 7. Drop privileges and hand over.
export CLAUDE_PROJECT_DIR="$project_dir"
exec "${DROP[@]}" "$@"

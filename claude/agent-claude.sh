#!/usr/bin/env bash
# Default CMD of ghcr.io/hatchward/agent:claude — run one headless Claude Code
# session against /workspace and exit with its status.
#
# agent-entrypoint has already applied the firewall, provisioned the workspace,
# staged secrets as files and dropped privileges: this runs as the agent user.
# It resolves the prompt, model and credential through lib/prompt.sh (env,
# *_FILE, or the runner's manifest), pre-trusts the workspace so the repo's
# .claude/settings.json hooks fire in a run with no trust dialog, and execs
# claude with the prompt on stdin — never in argv — and the credential only in
# the exec'd process's environment.
#
# Exit 2 is a contract error (nothing to run); anything else is claude's own.
set -euo pipefail

AGENT_LIB_DIR="${AGENT_LIB_DIR:-/usr/local/lib/hatchward}"
AGENT_WORKSPACE="${AGENT_WORKSPACE:-/workspace}"
# shellcheck source=../lib/prompt.sh
# shellcheck disable=SC1091 # resolved at runtime from AGENT_LIB_DIR
. "$AGENT_LIB_DIR/prompt.sh"

fatal() { echo "agent-claude: $*" >&2; exit 2; }

agent_require_firewall || exit $?

if [ -z "$(find "$AGENT_WORKSPACE" -mindepth 1 -maxdepth 1 -print -quit 2>/dev/null)" ]; then
  fatal "/workspace is empty — pre-clone the workspace or set AGENT_REPO"
fi

prompt="$(agent_resolve_prompt)" || exit $?
model="$(agent_resolve_model)"

# The credential is exported here, for the exec'd claude only: this shell is
# replaced by exec, so no other process ever inherits it.
if value="$(agent_resolve_secret ANTHROPIC_API_KEY)"; then
  export ANTHROPIC_API_KEY="$value"
elif value="$(agent_resolve_secret CLAUDE_CODE_OAUTH_TOKEN)"; then
  export CLAUDE_CODE_OAUTH_TOKEN="$value"
else
  fatal "no model credential — set ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN (or their _FILE forms)"
fi
unset value

# Pre-trust the project. Claude Code ignores an untrusted folder's
# .claude/settings.json, and a headless -p run has no dialog to accept it in.
# Only the two trust keys are written; nothing else about the project changes.
project_dir="${CLAUDE_PROJECT_DIR:-$AGENT_WORKSPACE}"
trust_file="$HOME/.claude.json"
[ -s "$trust_file" ] || echo '{}' > "$trust_file"
tmp="$(mktemp)"
if ! jq --arg dir "$project_dir" \
  '.projects[$dir].hasTrustDialogAccepted = true | .projects[$dir].hasCompletedProjectOnboarding = true' \
  "$trust_file" > "$tmp"; then
  fatal "could not write the workspace trust entry to $trust_file"
fi
mv "$tmp" "$trust_file"

format="${AGENT_OUTPUT_FORMAT:-json}"
args=(--dangerously-skip-permissions -p --output-format "$format")
[ "$format" != "stream-json" ] || args+=(--verbose)
args+=(--max-turns "${AGENT_MAX_TURNS:-200}")
[ -z "$model" ] || args+=(--model "$model")

exec claude "${args[@]}" < <(printf '%s\n' "$prompt")

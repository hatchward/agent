#!/usr/bin/env bash
# agent-firewall-refresh: keep the egress allowlist current for the life of a
# run.
#
# init-firewall resolves every allowlisted hostname once, at boot. GitHub's
# DNS rotates between addresses that are not all in its published ranges (some
# sit in Azure blocks that api.github.com/meta does not list), so a later
# lookup can hand a client an address no rule covers, and the connection
# times out. This root-owned loop, started by agent-entrypoint after the
# firewall is up and before the privilege drop, re-resolves the same hostnames
# every AGENT_FIREWALL_REFRESH seconds and appends an ACCEPT rule for any new
# public address. A client's SYN retransmits while it waits, so a connection
# caught in the gap succeeds once the rule lands.
#
# WHAT IT KEEPS: only hostnames from the boot-time allowlist
# ($AGENT_RUN_DIR/firewall-domains) are resolved, and every address passes the
# same non_public_v4 filter as at boot. Additive only: nothing is removed
# mid-run, and AGENT_FIREWALL_RULE_CAP bounds the total.
#
# Every 10 ticks it also re-fetches api.github.com/meta, conditionally on the
# stored ETag; a failure or a rate limit keeps the current rules.
#
# Runtime paths are overridable so the script can run under tests.
# AGENT_FIREWALL_REFRESH_TICKS (tests only) stops the loop after that many ticks.
set -uo pipefail

AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"
AGENT_LIB_DIR="${AGENT_LIB_DIR:-/usr/local/lib/hatchward}"
interval="${AGENT_FIREWALL_REFRESH:-60}"
cap="${AGENT_FIREWALL_RULE_CAP:-2048}"
ticks="${AGENT_FIREWALL_REFRESH_TICKS:-0}"
META_EVERY=10

# shellcheck source=lib/firewall.sh
. "$AGENT_LIB_DIR/firewall.sh"

log() { echo "agent-firewall-refresh: $*" >&2; }
fatal() { log "FATAL — $*"; exit 1; }

for pair in "AGENT_FIREWALL_REFRESH=$interval" "AGENT_FIREWALL_RULE_CAP=$cap"; do
  case "${pair#*=}" in
    ''|*[!0-9]*) fatal "${pair%%=*} '${pair#*=}' must be a whole number" ;;
  esac
done
if [ "$interval" = 0 ]; then
  log "disabled via AGENT_FIREWALL_REFRESH=0"
  exit 0
fi

domains="$AGENT_RUN_DIR/firewall-domains"
seen="$AGENT_RUN_DIR/firewall-seen"
etag="$AGENT_RUN_DIR/github-meta.etag"
dropped="$AGENT_RUN_DIR/firewall-refresh-dropped"
for f in "$domains" "$seen" "$AGENT_RUN_DIR/firewall-iptables"; do
  [ -f "$f" ] || fatal "$f is missing; init-firewall has not applied an allowlist"
done
IPT="$(cat "$AGENT_RUN_DIR/firewall-iptables")"
: > "$dropped"

seen_load "$seen"
cap_logged=0

# allow <address-or-CIDR> <source>: one appended ACCEPT. The OUTPUT policy is
# DROP with no terminal rule, so an appended ACCEPT takes effect at once.
allow() {
  if [ "${#SEEN_TEXT[@]}" -ge "$cap" ]; then
    if [ "$cap_logged" = 0 ]; then
      log "WARNING — rule cap $cap reached; not adding $1 for $2 or anything after it"
      cap_logged=1
    fi
    return 0
  fi
  if ! "$IPT" -A OUTPUT -d "$1" -j ACCEPT </dev/null; then
    log "WARNING — could not add a rule for $1 ($2)"
    return 0
  fi
  echo "$1" >> "$seen"
  seen_add "$1"
  log "allowed $1 for $2"
}

# Non-public answers are refused exactly as at boot, and reported once each.
refuse() {
  grep -qxF "$1 $2" "$dropped" && return 0
  echo "$1 $2" >> "$dropped"
  log "WARNING — dropping non-public address $1 for $2"
}

refresh_hosts() {
  local d ip
  while IFS= read -r d <&3; do
    [ -n "$d" ] || continue
    for ip in $(resolve_v4_union "$d"); do
      if non_public_v4 "$ip"; then refuse "$ip" "$d"; continue; fi
      seen_covers "$ip" || allow "$ip" "$d"
    done
  done 3< "$domains"
}

refresh_meta() {
  local body status cidr
  body="$(mktemp)"
  status="$(github_meta_fetch "$body" "$etag")"
  case "$status" in
    ok)
      while IFS= read -r cidr <&3; do
        [ -n "$cidr" ] || continue
        if non_public_v4 "$cidr"; then refuse "$cidr" "api.github.com/meta"; continue; fi
        seen_covers "$cidr" || allow "$cidr" "api.github.com/meta"
      done 3< <(github_meta_ranges "$body")
      ;;
    unchanged) ;;
    *) log "WARNING — api.github.com/meta fetch $status; keeping the current rules" ;;
  esac
  rm -f "$body"
}

log "refreshing every ${interval}s (${#SEEN_TEXT[@]} rules loaded, cap $cap)"
tick=0
while :; do
  sleep "$interval"
  tick=$((tick + 1))
  refresh_hosts
  [ $((tick % META_EVERY)) -ne 0 ] || refresh_meta
  if [ "$ticks" != 0 ] && [ "$tick" -ge "$ticks" ]; then break; fi
done

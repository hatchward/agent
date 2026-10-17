#!/usr/bin/env bash
# agent-egress-check: resolve every allowlisted hostname now and report, for
# each address returned, whether the firewall in force would let it through.
#
#   docker exec -u root <container> agent-egress-check
#
# Root is needed to read the rules (iptables -C). An exact address is checked
# against the kernel's rule set; anything else against the CIDRs init-firewall
# and agent-firewall-refresh loaded. One line per address on stdout:
#
#   ok         <host> <address> <covering rule>
#   UNCOVERED  <host> <address>
#   non-public <host> <address>   (refused by design, not a gap)
#
# Exits 1 when any address is uncovered, 2 when there is no allowlist to check.
set -uo pipefail

AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"
AGENT_LIB_DIR="${AGENT_LIB_DIR:-/usr/local/lib/hatchward}"

# shellcheck source=lib/firewall.sh
. "$AGENT_LIB_DIR/firewall.sh"

for f in firewall-domains firewall-seen firewall-iptables; do
  if [ ! -f "$AGENT_RUN_DIR/$f" ]; then
    echo "agent-egress-check: $AGENT_RUN_DIR/$f is missing; no allowlist is in force" >&2
    exit 2
  fi
done
IPT="$(cat "$AGENT_RUN_DIR/firewall-iptables")"

ranges="$(mktemp)"
trap 'rm -f "$ranges"' EXIT
grep -F / "$AGENT_RUN_DIR/firewall-seen" > "$ranges" || true
seen_load "$ranges"

rc=0
while IFS= read -r d <&3; do
  [ -n "$d" ] || continue
  for ip in $(resolve_v4_union "$d"); do
    if non_public_v4 "$ip"; then
      printf 'non-public\t%s\t%s\n' "$d" "$ip"
    elif "$IPT" -C OUTPUT -d "$ip" -j ACCEPT </dev/null 2>/dev/null; then
      printf 'ok\t%s\t%s\t%s\n' "$d" "$ip" "$ip"
    elif seen_covers "$ip"; then
      printf 'ok\t%s\t%s\t%s\n' "$d" "$ip" "$SEEN_MATCH"
    else
      printf 'UNCOVERED\t%s\t%s\n' "$d" "$ip"
      rc=1
    fi
  done
done 3< "$AGENT_RUN_DIR/firewall-domains"
exit "$rc"

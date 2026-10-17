#!/usr/bin/env bash
# Shared egress-allowlist helpers. Sourced, not executed, by init-firewall (boot),
# agent-firewall-refresh (the root background loop) and agent-egress-check
# (the debug probe). One definition of the address filter and of resolution,
# so a refreshed address passes exactly the check a boot-time one did.
#
# State init-firewall leaves in $AGENT_RUN_DIR (root-owned) for the others:
#   firewall-domains    the effective hostname allowlist, one per line
#   firewall-seen       every address or CIDR with an OUTPUT ACCEPT rule
#   firewall-iptables   the iptables binary the rules were applied with
#   github-meta.etag    ETag of the last api.github.com/meta answer
#
# Written for bash 3.2 as well as 5: no associative arrays, no mapfile.

# Non-public IPv4 ranges: loopback, RFC1918, link-local, CGNAT, multicast,
# reserved (class E), benchmark, documentation, "this network", broadcast.
# Matches a bare address or a CIDR (the GitHub meta list is CIDRs).
non_public_v4() {
  case "$1" in
    0.*|10.*|127.*|169.254.*|192.168.*|255.255.255.255) return 0 ;;
    172.1[6-9].*|172.2[0-9].*|172.3[01].*) return 0 ;;
    100.6[4-9].*|100.[7-9][0-9].*|100.1[01][0-9].*|100.12[0-7].*) return 0 ;;
    22[4-9].*|23[0-9].*|24[0-9].*|25[0-5].*) return 0 ;;
    198.1[89].*|192.0.0.*|192.0.2.*|198.51.100.*|203.0.113.*) return 0 ;;
  esac
  return 1
}

resolve_v4() {
  getent ahostsv4 "$1" 2>/dev/null | awk '{print $1}' | sort -u || true
}

# Resolve a hostname several times: round-robin records (github.com hands
# out one of several addresses per query) would otherwise leave the address a
# later client gets outside the rule set.
resolve_v4_union() {
  { resolve_v4 "$1"; resolve_v4 "$1"; resolve_v4 "$1"; } | sort -u
}

# --- CIDR coverage, without a fork per comparison ---------------------------
# v4_int <a.b.c.d> sets V4_INT.
v4_int() {
  local IFS=.
  # shellcheck disable=SC2086 # splitting on '.' is the point
  set -- $1
  V4_INT=$(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 ))
}

# seen_load <file> reads the loaded set into parallel arrays SEEN_TEXT,
# SEEN_NET and SEEN_MASK.
seen_load() {
  SEEN_TEXT=(); SEEN_NET=(); SEEN_MASK=()
  [ -f "$1" ] || return 0
  local entry
  while IFS= read -r entry; do
    [ -n "$entry" ] || continue
    seen_add "$entry"
  done < "$1"
}

# seen_add <address-or-CIDR> extends the in-memory set (the caller appends the
# file). A bare address is a /32.
seen_add() {
  local n="${#SEEN_TEXT[@]}" bits=32
  [ "${1%/*}" = "$1" ] || bits="${1#*/}"
  v4_int "${1%/*}"
  SEEN_TEXT[n]="$1"
  if [ "$bits" -eq 0 ]; then SEEN_MASK[n]=0; else SEEN_MASK[n]=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF )); fi
  SEEN_NET[n]=$(( V4_INT & SEEN_MASK[n] ))
}

# seen_covers <address-or-CIDR>: true when one entry of the loaded set covers
# all of it (an entry no narrower, containing its network); sets SEEN_MATCH.
seen_covers() {
  local i=0 n="${#SEEN_TEXT[@]}" bits=32 mask net
  [ "${1%/*}" = "$1" ] || bits="${1#*/}"
  if [ "$bits" -eq 0 ]; then mask=0; else mask=$(( (0xFFFFFFFF << (32 - bits)) & 0xFFFFFFFF )); fi
  v4_int "${1%/*}"
  net=$(( V4_INT & mask ))
  while [ "$i" -lt "$n" ]; do
    if [ $(( SEEN_MASK[i] & mask )) -eq "${SEEN_MASK[i]}" ] \
      && [ $(( net & SEEN_MASK[i] )) -eq "${SEEN_NET[i]}" ]; then
      # shellcheck disable=SC2034 # read by the caller
      SEEN_MATCH="${SEEN_TEXT[i]}"
      return 0
    fi
    i=$((i + 1))
  done
  return 1
}

# --- GitHub's published ranges ----------------------------------------------
# github_meta_fetch <body-out> <etag-file>: one conditional GET of
# api.github.com/meta. Prints the outcome: ok (body written, ETag stored),
# unchanged (304 against the stored ETag), rate-limited (403/429) or failed.
# Never -f: the status code is what distinguishes a rate limit from an outage.
github_meta_fetch() {
  local body="$1" etag_file="$2" headers code
  local args=(-sS --connect-timeout 5 --max-time 10 -o "$body" -w '%{http_code}')
  headers="$(mktemp)"
  args+=(-D "$headers")
  if [ -s "$etag_file" ]; then args+=(-H "If-None-Match: $(cat "$etag_file")"); fi
  code="$(curl "${args[@]}" https://api.github.com/meta 2>/dev/null)" || code=000
  case "$code" in
    200)
      if [ -s "$body" ] && jq -e . "$body" >/dev/null 2>&1; then
        tr -d '\r' < "$headers" | awk 'tolower($1) == "etag:" {print $2}' | tail -n 1 > "$etag_file"
        echo ok
      else
        echo failed
      fi
      ;;
    304) echo unchanged ;;
    403|429) echo rate-limited ;;
    *) echo failed ;;
  esac
  rm -f "$headers"
}

# github_meta_ranges <body>: the IPv4 web/api/git CIDRs, one per line.
github_meta_ranges() {
  jq -r '(.web // []) + (.api // []) + (.git // []) | unique | .[]' "$1" 2>/dev/null | grep -F '.' || true
}

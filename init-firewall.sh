#!/usr/bin/env bash
# Egress firewall for the agent sandbox: default-DROP plus a hostname allowlist.
#
# Runs as root from agent-entrypoint before any agent code executes. The
# allowlist is assembled from /etc/hatchward/allow-domains.d/* (one file per
# image layer) plus AGENT_ALLOW_DOMAINS at runtime.
#
# WHAT IT GUARANTEES: no path from the container to the host, the LAN, sibling
# containers, or the public internet except (a) port 53 to the configured
# resolver and (b) the allowlisted hosts. Resolved addresses inside private,
# loopback, link-local, CGNAT or multicast ranges are dropped whatever their
# source, so an allowlist entry cannot re-open the host path.
#
# WHAT IT DOES NOT GUARANTEE: exfiltration control. The agent holds whatever
# credentials it was given and can reach every allowlisted host; several of
# those sit on shared CDN addresses. The spec records this as a residual.
#
# FAIL-CLOSED: if there is an egress interface and the rules cannot be applied,
# or the negative canary shows egress is not restricted, exit 1 so the
# entrypoint refuses to run an unprotected agent. AGENT_FIREWALL=0 skips the
# firewall (debugging only) and leaves a marker the CLI-layer CMD checks.
#
# Runtime paths are overridable so the script can run under tests.
set -euo pipefail

AGENT_ALLOW_DIR="${AGENT_ALLOW_DIR:-/etc/hatchward/allow-domains.d}"
AGENT_RANGES_DIR="${AGENT_RANGES_DIR:-/etc/hatchward/allow-ranges.d}"
AGENT_RUN_DIR="${AGENT_RUN_DIR:-/run/hatchward}"
AGENT_RESOLV_CONF="${AGENT_RESOLV_CONF:-/etc/resolv.conf}"
AGENT_LIB_DIR="${AGENT_LIB_DIR:-/usr/local/lib/hatchward}"

# shellcheck source=lib/firewall.sh
. "$AGENT_LIB_DIR/firewall.sh"

log() { echo "init-firewall: $*" >&2; }
fatal() { log "FATAL — $*"; exit 1; }
verbose() { if [ "${AGENT_VERBOSE:-0}" = "1" ]; then log "$@"; fi; }

mkdir -p "$AGENT_RUN_DIR"
# State for agent-firewall-refresh is written only once this run's rules are
# applied; a restarted container must not inherit the previous run's.
rm -f "$AGENT_RUN_DIR/firewall-domains" "$AGENT_RUN_DIR/firewall-seen" \
  "$AGENT_RUN_DIR/firewall-iptables" "$AGENT_RUN_DIR/github-meta.etag"

if [ "${AGENT_FIREWALL:-1}" = "0" ]; then
  log "DISABLED via AGENT_FIREWALL=0 — agent can reach host services"
  : > "$AGENT_RUN_DIR/firewall-disabled"
  exit 0
fi

# --- Is there anything to firewall? -----------------------------------------
# --network none leaves only loopback; that is stricter than these rules, so
# there is nothing to apply and nothing to refuse.
if ! ip -o link show | grep -v ': lo:' | grep -q .; then
  log "no egress interface; firewall not required"
  exit 0
fi

# --- Proxy mode (contract 2) --------------------------------------------------
# AGENT_PROXY_URL set: egress is locked to the proxy alone, nothing else. No
# allowlist is gathered — allow-domains.d and allow-ranges.d are both dead in
# this mode — and Docker's embedded DNS resolver (127.0.0.11) is rejected
# outright so a hostname lookup cannot leak a destination outside the proxy.
# agent-entrypoint has already validated AGENT_CA_FILE and exported it (and
# the client env vars) before this script runs.
#
# The URL is parsed and the host resolved BEFORE touching iptables at all, so
# a malformed AGENT_PROXY_URL or an unresolvable proxy host is fatal with
# zero firewall calls made — no half-applied ruleset to clean up.
if [ -n "${AGENT_PROXY_URL:-}" ]; then
  proxy_host="$(printf '%s' "$AGENT_PROXY_URL" | sed -En 's#^[a-zA-Z][a-zA-Z0-9+.-]*://([^/@]*@)?([^/:]+)(:([0-9]+))?/?$#\2#p')"
  proxy_port="$(printf '%s' "$AGENT_PROXY_URL" | sed -En 's#^[a-zA-Z][a-zA-Z0-9+.-]*://([^/@]*@)?([^/:]+)(:([0-9]+))?/?$#\4#p')"
  [ -n "$proxy_host" ] || fatal "AGENT_PROXY_URL '$AGENT_PROXY_URL' is not a valid proxy URL"
  proxy_port="${proxy_port:-80}"

  is_ipv4_literal() {
    printf '%s' "$1" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
  }

  if is_ipv4_literal "$proxy_host"; then
    proxy_ip="$proxy_host"
  else
    proxy_ip="$(resolve_v4 "$proxy_host" | head -n1)"
    [ -n "$proxy_ip" ] || fatal "could not resolve proxy host '$proxy_host'"
  fi

  # --- iptables backend ------------------------------------------------------
  IPT=""
  for candidate in iptables-nft iptables-legacy iptables; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -L -n >/dev/null 2>&1; then
      IPT="$candidate"
      break
    fi
  done
  [ -n "$IPT" ] || fatal "cannot use iptables (needs --cap-add=NET_ADMIN and a netfilter-capable kernel)"

  IP6T=""
  for candidate in ip6tables-nft ip6tables-legacy ip6tables; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -L -n >/dev/null 2>&1; then
      IP6T="$candidate"
      break
    fi
  done

  for chain in INPUT OUTPUT FORWARD; do "$IPT" -P "$chain" ACCEPT; done
  "$IPT" -F

  # Docker's embedded DNS resolver: even loopback-adjacent, it must not be
  # reachable in proxy mode, so a hostname lookup cannot bypass the proxy.
  "$IPT" -A OUTPUT -p udp -d 127.0.0.11 -j REJECT
  "$IPT" -A OUTPUT -p tcp -d 127.0.0.11 -j REJECT

  "$IPT" -A OUTPUT -o lo -j ACCEPT
  "$IPT" -A INPUT -i lo -j ACCEPT
  "$IPT" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  "$IPT" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

  # The proxy itself is the only private address ever ACCEPTed.
  "$IPT" -A OUTPUT -d "$proxy_ip" -p tcp --dport "$proxy_port" -j ACCEPT

  "$IPT" -P OUTPUT DROP
  "$IPT" -P INPUT DROP
  "$IPT" -P FORWARD DROP

  # IPv6 lockdown is unchanged from non-proxy mode.
  has_v6_route=0
  if ip -6 route show default 2>/dev/null | grep -q .; then has_v6_route=1; fi
  if [ -n "$IP6T" ]; then
    "$IP6T" -F
    "$IP6T" -A OUTPUT -o lo -j ACCEPT
    "$IP6T" -A INPUT -i lo -j ACCEPT
    "$IP6T" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    "$IP6T" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    "$IP6T" -P OUTPUT DROP
    "$IP6T" -P INPUT DROP
    "$IP6T" -P FORWARD DROP
    if [ "$has_v6_route" = 1 ] && curl -6 -fsS --connect-timeout 4 --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
      fatal "example.com is reachable over IPv6; default-DROP is NOT in effect"
    fi
  elif [ "$has_v6_route" = 1 ]; then
    fatal "IPv6 default route present but ip6tables is unusable"
  else
    log "no IPv6 route; skipping ip6tables"
  fi

  # --- Canaries: prove the lockdown actually holds before the marker is written.
  # DNS must not resolve anything: a hostname lookup that still works means the
  # allowlist gathering was skipped but the resolver path was not sealed.
  if getent hosts example.com >/dev/null 2>&1; then
    fatal "example.com resolved via DNS; proxy-mode lockdown is NOT in effect"
  fi

  # Direct IP-literal probes (bypassing DNS entirely) must also fail — both
  # families. --noproxy '*' is required: the proxy env is already exported by
  # this point in the real boot sequence, so a bare curl would itself route
  # through the proxy and prove nothing about the lockdown.
  if curl --noproxy '*' --connect-timeout 4 --max-time 5 -fsS -o /dev/null https://1.1.1.1/ 2>/dev/null; then
    fatal "1.1.1.1 is reachable directly; proxy-mode lockdown is NOT in effect"
  fi
  # shellcheck disable=SC2102 # the brackets are a URL literal, not a glob range
  if curl -6 --noproxy '*' --connect-timeout 4 --max-time 5 -fsS -o /dev/null https://[2606:4700:4700::1111]/ 2>/dev/null; then
    fatal "[2606:4700:4700::1111] is reachable directly; proxy-mode lockdown is NOT in effect"
  fi

  # Positive: the proxy itself must actually work, trusting the runner's CA.
  # This is fatal, not a warning — without it the agent has no egress at all.
  ok=0
  for _ in 1 2 3; do
    if curl -sS --connect-timeout 4 --max-time 8 --proxy "$AGENT_PROXY_URL" --cacert "${AGENT_CA_FILE:-}" -o /dev/null https://api.github.com/ 2>/dev/null; then
      ok=1
      break
    fi
  done
  [ "$ok" = 1 ] || fatal "api.github.com is unreachable through the proxy after 3 tries; proxy-mode lockdown may be too tight"

  : > "$AGENT_RUN_DIR/proxy-mode"
  log "proxy-mode default-DROP active — egress locked to $proxy_host:$proxy_port"
  exit 0
fi

# --- iptables backend --------------------------------------------------------
# Pick the binary directly rather than rewriting /etc/alternatives at runtime.
IPT=""
for candidate in iptables-nft iptables-legacy iptables; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -L -n >/dev/null 2>&1; then
    IPT="$candidate"
    break
  fi
done
[ -n "$IPT" ] || fatal "cannot use iptables (needs --cap-add=NET_ADMIN and a netfilter-capable kernel)"

IP6T=""
for candidate in ip6tables-nft ip6tables-legacy ip6tables; do
  if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -L -n >/dev/null 2>&1; then
    IP6T="$candidate"
    break
  fi
done

# --- Allowlist ---------------------------------------------------------------
# One hostname per line in allow-domains.d files; '#' starts a comment.
# AGENT_ALLOW_DOMAINS adds more, separated by spaces or commas.
hostname_ok() {
  # A dotted name whose labels are not all numeric: an IP literal or a CIDR is
  # refused so the env cannot inject raw ranges.
  printf '%s' "$1" | grep -Eq '^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$' \
    && ! printf '%s' "$1" | grep -Eq '^[0-9.]+$'
}

domains_file="$(mktemp)"
addr_file="$(mktemp)"
trap 'rm -f "$domains_file" "$addr_file" "${meta_body:-}"' EXIT

if [ -d "$AGENT_ALLOW_DIR" ]; then
  for f in "$AGENT_ALLOW_DIR"/*; do
    [ -f "$f" ] || continue
    sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" | grep -v '^$' >> "$domains_file" || true
  done
fi
for d in $(printf '%s' "${AGENT_ALLOW_DOMAINS:-}" | tr ',' ' '); do
  hostname_ok "$d" || fatal "AGENT_ALLOW_DOMAINS entry '$d' is not a hostname"
  echo "$d" >> "$domains_file"
done
sort -u -o "$domains_file" "$domains_file"

# --- Gather phase (egress still open): resolve to addresses -------------------
# non_public_v4 and resolve_v4_union live in lib/firewall.sh, shared with the
# refresher so a later address passes the same filter as a boot-time one.
n_resolved=0
while IFS= read -r d; do
  [ -n "$d" ] || continue
  found=0
  for ip in $(resolve_v4_union "$d"); do
    if non_public_v4 "$ip"; then
      log "WARNING — dropping non-public address $ip for $d"
      continue
    fi
    echo "$ip" >> "$addr_file"
    verbose "resolved $d -> $ip"
    n_resolved=$((n_resolved + 1))
    found=1
  done
  [ "$found" = 1 ] || log "WARNING — '$d' resolved to no public IPv4 address; it will be unreachable"
done < "$domains_file"

# Static ranges shipped in the image (allow-ranges.d/*: one CIDR per line, '#'
# comments). GitHub's published ranges live here as a snapshot, because the
# live api.github.com/meta fetch below is rate-limited for unauthenticated
# callers and CI runners hit that limit routinely. Filtered like everything
# else, so a file cannot smuggle in a private range.
n_static=0
if [ -d "$AGENT_RANGES_DIR" ]; then
  for f in "$AGENT_RANGES_DIR"/*; do
    [ -f "$f" ] || continue
    while IFS= read -r cidr; do
      [ -n "$cidr" ] || continue
      if non_public_v4 "$cidr"; then
        log "WARNING — dropping non-public range $cidr from $(basename "$f")"
        continue
      fi
      echo "$cidr" >> "$addr_file"
      n_static=$((n_static + 1))
    done < <(sed -e 's/#.*//' -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' "$f" | grep -v '^$' || true)
  done
fi

# GitHub's live published ranges, when reachable: its endpoints rotate across
# addresses a single boot-time resolution would miss. Best effort — a failure
# leaves the snapshot and the resolved addresses in place. The ETag is kept so
# the refresher's later fetches cost a 304 when nothing changed.
n_meta=0
meta_body="$(mktemp)"
meta_status="$(github_meta_fetch "$meta_body" "$AGENT_RUN_DIR/github-meta.etag")"
if [ "$meta_status" = ok ]; then
  while IFS= read -r cidr; do
    [ -n "$cidr" ] || continue
    if non_public_v4 "$cidr"; then
      log "WARNING — dropping non-public range $cidr from api.github.com/meta"
      continue
    fi
    echo "$cidr" >> "$addr_file"
    n_meta=$((n_meta + 1))
  done < <(github_meta_ranges "$meta_body")
else
  log "WARNING — could not fetch api.github.com/meta; relying on the shipped range snapshot and resolved addresses ($meta_status)"
fi
rm -f "$meta_body"
sort -u -o "$addr_file" "$addr_file"

# --- Apply phase: lock down, then permit the gathered set --------------------
for chain in INPUT OUTPUT FORWARD; do "$IPT" -P "$chain" ACCEPT; done
"$IPT" -F

"$IPT" -A OUTPUT -o lo -j ACCEPT
"$IPT" -A INPUT -i lo -j ACCEPT
"$IPT" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
"$IPT" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# DNS to whatever resolver the runtime configured.
if [ -r "$AGENT_RESOLV_CONF" ]; then
  while read -r ns; do
    [ -n "$ns" ] || continue
    "$IPT" -A OUTPUT -p udp --dport 53 -d "$ns" -j ACCEPT
    "$IPT" -A OUTPUT -p tcp --dport 53 -d "$ns" -j ACCEPT
  done < <(awk '/^nameserver/ {print $2}' "$AGENT_RESOLV_CONF" | grep -F '.' || true)
fi

count=0
while IFS= read -r ip; do
  [ -n "$ip" ] || continue
  "$IPT" -A OUTPUT -d "$ip" -j ACCEPT
  count=$((count + 1))
done < "$addr_file"

"$IPT" -P OUTPUT DROP
"$IPT" -P INPUT DROP
"$IPT" -P FORWARD DROP

# IPv6: no allowlisted endpoint needs it and an open v6 path is a silent bypass
# (link-local reaches the host bridge even with no default route), so lock it
# down whenever ip6tables works. Missing ip6tables is fatal only when a v6
# default route makes the bypass real.
has_v6_route=0
if ip -6 route show default 2>/dev/null | grep -q .; then has_v6_route=1; fi
if [ -n "$IP6T" ]; then
  "$IP6T" -F
  "$IP6T" -A OUTPUT -o lo -j ACCEPT
  "$IP6T" -A INPUT -i lo -j ACCEPT
  "$IP6T" -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  "$IP6T" -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
  "$IP6T" -P OUTPUT DROP
  "$IP6T" -P INPUT DROP
  "$IP6T" -P FORWARD DROP
  if [ "$has_v6_route" = 1 ] && curl -6 -fsS --connect-timeout 4 --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
    fatal "example.com is reachable over IPv6; default-DROP is NOT in effect"
  fi
elif [ "$has_v6_route" = 1 ]; then
  fatal "IPv6 default route present but ip6tables is unusable"
else
  log "no IPv6 route; skipping ip6tables"
fi

# --- Canaries ----------------------------------------------------------------
# Negative: a non-allowlisted host must be unreachable, else refuse to run.
if curl -fsS --connect-timeout 4 --max-time 5 -o /dev/null https://example.com 2>/dev/null; then
  fatal "example.com is reachable; default-DROP is NOT in effect"
fi

# Positive: an allowlisted host should be reachable; warn rather than abort on
# a transient blip (a real failure surfaces in the agent's own run). No -f: an
# HTTP error such as a rate-limit 403 still proves the connection went through.
ok=0
for _ in 1 2 3; do
  if curl -sS --connect-timeout 4 --max-time 8 -o /dev/null https://api.github.com/ 2>/dev/null; then ok=1; break; fi
  sleep 1
done
[ "$ok" = 1 ] || log "WARNING — api.github.com unreachable after 3 tries; allowlist may be too tight or resolved addresses rotated"

# Hand the effective allowlist and the loaded set to agent-firewall-refresh.
# Written last, so their presence means "these rules are in force".
cp "$domains_file" "$AGENT_RUN_DIR/firewall-domains"
cp "$addr_file" "$AGENT_RUN_DIR/firewall-seen"
echo "$IPT" > "$AGENT_RUN_DIR/firewall-iptables"

verbose "allowlist: $(tr '\n' ' ' < "$domains_file")"
log "sources — $n_resolved resolved, $n_static from allow-ranges.d, $n_meta from api.github.com/meta ($meta_status)"
log "default-DROP active — $count v4 targets + loopback/DNS/established permitted; example.com blocked"

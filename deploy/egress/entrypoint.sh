#!/bin/sh
# The egress container's start, as root: route the agent's traffic into mitmproxy, fetch the GeoIP table,
# make the CA the agent will trust, then run mitmdump as the user egress with no capabilities left.
#
# The agent's container sits on the internal network doorman-egress with this container as its default
# route and DNS server. Here, on the interface that holds $EGRESS_AGENT_IP:
#   - DNS (udp and tcp 53) goes to mitmproxy's DNS mode on 8053,
#   - every other TCP connection that isn't to this container goes to the transparent proxy on 8080,
#   - nothing is forwarded (FORWARD DROP, also for IPv6): UDP other than DNS, QUIC (HTTP/3) and ICMP to the
#     internet are dropped, so clients fall back to TCP, which the proxy sees;
#   - of the traffic to this container itself only what was redirected above is accepted (a direct
#     connection to 8080 would make mitmproxy connect to itself).
set -eu

AGENT_IP="${EGRESS_AGENT_IP:-172.29.0.2}"   # this container's address on the agent's network
DATA=/data
CA_OUT=/ca/egress-ca.pem

log() { echo "egress: $*" >&2; }

iface=$(ip -o -4 addr show | awk -v ip="$AGENT_IP" '{split($4, a, "/"); if (a[1] == ip) print $2}' | head -n 1)
if [ -z "$iface" ]; then
  log "no interface holds $AGENT_IP: is this container on the doorman-egress network with that address?"
  exit 1
fi
log "agent network on $iface ($AGENT_IP)"

# appended (once), never flushed: Docker's own rules for its embedded DNS (127.0.0.11) live in these tables too
add() { table=$1; shift; iptables -t "$table" -C "$@" 2>/dev/null || iptables -t "$table" -A "$@"; }
add nat PREROUTING -i "$iface" -p udp --dport 53 -j REDIRECT --to-ports 8053
add nat PREROUTING -i "$iface" -p tcp --dport 53 -j REDIRECT --to-ports 8053
add nat PREROUTING -i "$iface" -p tcp ! -d "$AGENT_IP" -j REDIRECT --to-ports 8080
add filter INPUT -i "$iface" -p tcp --dport 8080 -m conntrack --ctstate DNAT -j ACCEPT
add filter INPUT -i "$iface" -p tcp --dport 8053 -m conntrack --ctstate DNAT -j ACCEPT
add filter INPUT -i "$iface" -p udp --dport 8053 -m conntrack --ctstate DNAT -j ACCEPT
add filter INPUT -i "$iface" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
add filter INPUT -i "$iface" -p icmp -j ACCEPT
add filter INPUT -i "$iface" -j DROP
iptables -P FORWARD DROP
ip6tables -P FORWARD DROP 2>/dev/null || log "ip6tables unavailable; the agent's network has no IPv6 anyway"

mkdir -p "$DATA/mitmproxy" "$DATA/geoip"
chown -R egress:egress "$DATA"

# The decoy keys' folder (the agent-config volume; the agent has it read-only in its home): the addon writes
# the file there as the user egress. Only the folder itself is changed: chown/chmod on a path open nothing,
# whereas anything that opens the file (or lists the folder) trips the observer's wire.
# Root here has CHOWN but not FOWNER, so it can change the mode only while it owns the folder: taken back
# (from the last start), mode set, then handed to egress.
if [ -d "${EGRESS_DECOY_DIR:-/decoys}" ]; then
  chown 0:0 "${EGRESS_DECOY_DIR:-/decoys}"
  chmod 755 "${EGRESS_DECOY_DIR:-/decoys}"
  chown egress:egress "${EGRESS_DECOY_DIR:-/decoys}"
else
  log "no ${EGRESS_DECOY_DIR:-/decoys} (the agent-config volume): no decoy keys for the agent"
fi

# DB-IP's free country table (CC BY 4.0), once a month; the addon looks again every day. EGRESS_GEOIP=0: none.
if [ "${EGRESS_GEOIP:-1}" != "0" ]; then
  month=$(date -u +%Y-%m)
  file="$DATA/geoip/dbip-country-lite-$month.csv.gz"
  if [ ! -s "$file" ]; then
    if setpriv --reuid egress --regid egress --init-groups -- \
        curl -fsS --max-time 60 -o "$file.part" "https://download.db-ip.com/free/dbip-country-lite-$month.csv.gz"; then
      mv "$file.part" "$file"
      log "GeoIP table $month downloaded"
    else
      rm -f "$file.part"
      log "GeoIP download failed; keeping the previous table (if any)"
    fi
  fi
fi

# mitmproxy's CA, made now (not on the first connection) so the agent can trust it before it starts.
# Only the certificate leaves this container's volume; the key stays in $DATA/mitmproxy.
setpriv --reuid egress --regid egress --init-groups -- \
  python -c "from mitmproxy.certs import CertStore; CertStore.from_store('$DATA/mitmproxy', 'mitmproxy', 2048)"
if [ -d /ca ]; then
  cp "$DATA/mitmproxy/mitmproxy-ca-cert.pem" "$CA_OUT.tmp"
  chmod 644 "$CA_OUT.tmp"
  mv "$CA_OUT.tmp" "$CA_OUT"
fi

# root's capabilities end here: a uid change clears them, and no-new-privileges keeps them from coming back.
# connection_strategy=lazy: nothing is connected upstream before the addon decided (the addon enforces it
# too); rawtcp=false: mitmproxy sets up no raw TCP relay on its own, only the addon does (and scans it).
exec setpriv --reuid egress --regid egress --init-groups -- \
  mitmdump --mode transparent@8080 --mode dns@8053 \
    --set confdir="$DATA/mitmproxy" --set block_global=false --set stream_large_bodies=16m \
    --set connection_strategy=lazy --set rawtcp=false \
    --set flow_detail=0 --set termlog_verbosity="${EGRESS_LOG_LEVEL:-warn}" \
    -s /app/addon.py

#!/bin/sh
# Checks the agent's container from the inside, once the stack is up:
#   docker compose exec agent sh /egress/selftest.sh     (COMPOSE_FILE with compose.egress.yaml in deploy/.env)
# One PASS or FAIL line per check; exits 1 if anything failed. Needs curl in the agent image (python3 for the
# UDP check, which is skipped without it). A `docker compose exec` shell has the container's capabilities,
# NET_ADMIN included; the agent itself (what Docker's init started, and what that starts) must not, so those
# checks look at the agent's process.
GATEWAY="${EGRESS_GATEWAY:-172.29.0.2}"
DOORMAN="${DOORMAN_URL:-http://doorman:8710}"
failed=0

pass() { echo "PASS  $*"; }
fail() { echo "FAIL  $*"; failed=1; }

if ! command -v curl >/dev/null 2>&1; then
  echo "FAIL  curl isn't installed in the agent image; install it to run this test"
  exit 1
fi

# 1. the route
if ip route show default 2>/dev/null | grep -q "via $GATEWAY "; then
  pass "default route via the proxy ($GATEWAY)"
else
  fail "default route is not via $GATEWAY: $(ip route show default 2>/dev/null)"
fi

# 2. the agent runs without NET_ADMIN (bit 12: the route) and NET_RAW (bit 13: sniffing, ARP spoofing on its
#    network), not even in its bounding set, so nothing it starts gets them back; and without KILL (bit 5),
#    SETUID (bit 7) and SETGID (bit 6), so it can't stop the observer. With `init: true` (compose.egress.yaml)
#    PID 1 is Docker's init, which only starts the agent and reaps; the agent is every process it is the parent
#    of (orphans of the agent's included). `docker compose exec` shells have no parent in here.
agents=1
if [ "$(cat /proc/1/comm 2>/dev/null)" = "docker-init" ]; then
  agents=""
  for stat in /proc/[0-9]*/stat; do
    [ "$(sed 's/.*) //' "$stat" 2>/dev/null | cut -d' ' -f2)" = 1 ] || continue
    pid=${stat#/proc/}; agents="$agents ${pid%/stat}"
  done
  [ -n "$agents" ] || fail "no agent process under Docker's init"
fi
for pid in $agents; do
  bnd=$(awk '/^CapBnd/ {print $2}' "/proc/$pid/status" 2>/dev/null)
  eff=$(awk '/^CapEff/ {print $2}' "/proc/$pid/status" 2>/dev/null)
  cmd=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-60)
  [ -n "$bnd" ] || continue  # gone since the list was made
  for cap in "NET_ADMIN 0x1000" "NET_RAW 0x2000" "KILL 0x20" "SETUID 0x80" "SETGID 0x40"; do
    name=${cap% *}; bit=${cap#* }
    if [ $((0x$bnd & bit)) -eq 0 ] && [ $((0x$eff & bit)) -eq 0 ]; then
      pass "the agent (pid $pid: $cmd) has no $name"
    else
      fail "pid $pid ($cmd) still has $name (CapBnd $bnd, CapEff $eff): is agent-entrypoint.sh the entrypoint?"
    fi
  done
done
# ... and as AGENT_USER. Root only when AGENT_USER is empty on purpose (Hermes with apt, on a Docker of its own):
# a root agent could change the programs agent-entrypoint.sh runs as root at the next start, and so get past
# the proxy then; the network watch can't hold it back the way it holds back any other user.
uid=$(awk '/^Uid/ {print ($2 == 0 || $3 == 0) ? 0 : $3}' /proc/1/status)  # real or effective root: root
if [ -n "$uid" ] && [ "$uid" != "0" ]; then
  pass "the agent (PID 1) runs as uid $uid, not root"
elif [ -n "${AGENT_USER+set}" ] && [ -z "$AGENT_USER" ]; then
  pass "the agent (PID 1) runs as root, as AGENT_USER=\"\" chooses: it could undo the route at its next start"
else
  fail "the agent (PID 1) runs as root, but AGENT_USER is '${AGENT_USER:-unset}': is agent-entrypoint.sh the entrypoint?"
fi

# 3. Doorman is reachable directly, not through the proxy
if curl -sS --max-time 5 -o /dev/null "$DOORMAN/health"; then
  pass "Doorman reachable at $DOORMAN"
else
  fail "Doorman not reachable at $DOORMAN"
fi

# 4. an ordinary HTTPS fetch works through the proxy (its CA is trusted) and isn't marked as blocked
headers=$(curl -sS --max-time 20 -D - -o /dev/null https://example.com/ 2>&1)
if echo "$headers" | head -n 1 | grep -q " 200" && ! echo "$headers" | grep -qi "^x-doorman-egress"; then
  pass "https://example.com/ fetched (200)"
else
  fail "https://example.com/ didn't come back 200: $(echo "$headers" | head -n 1)"
fi

# 5. an upload to a webhook service is blocked by the proxy's rules
headers=$(curl -sS --max-time 20 -X POST -d "selftest=1" -D - -o /dev/null https://webhook.site/doorman-selftest 2>&1)
if echo "$headers" | head -n 1 | grep -q " 403" && echo "$headers" | grep -qi "^x-doorman-egress: blocked"; then
  pass "POST to webhook.site blocked (403, X-Doorman-Egress)"
else
  fail "POST to webhook.site wasn't blocked: $(echo "$headers" | head -n 1)"
fi

# 6. a non-web connection to a bare IP no lookup led to is cut (scanme.nmap.org's SSH would greet us)
banner=$(curl -sS --max-time 5 telnet://45.33.32.156:22 < /dev/null 2>/dev/null | head -c 20)
case "$banner" in
  SSH-*) fail "a bare-IP SSH connection got through: $banner" ;;
  *) pass "bare-IP connection to port 22 cut" ;;
esac

# 7. a name that looks like data hidden in DNS isn't resolved
if getent hosts "$(printf '%060d' 0 | tr 0 a).doorman-selftest.example.com" >/dev/null 2>&1; then
  fail "a 60-character DNS label was resolved"
else
  pass "DNS tunnel-like name refused"
fi

# 8. UDP doesn't get out (no QUIC, no DNS to other resolvers on other ports): OpenDNS answers DNS on 443/udp
if command -v python3 >/dev/null 2>&1; then
  if python3 - <<'EOF'
import socket, sys
query = bytes.fromhex("123401000001000000000000076578616d706c6503636f6d0000010001")  # example.com A
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(4)
try:
    s.sendto(query, ("208.67.222.222", 443))
    s.recvfrom(512)
except OSError:
    sys.exit(0)  # nothing came back: blocked
sys.exit(1)
EOF
  then pass "UDP to 208.67.222.222:443 gets no answer"
  else fail "UDP to 208.67.222.222:443 was answered: UDP leaves the container"
  fi
else
  echo "SKIP  UDP check (no python3)"
fi

# 9. the host isn't reachable over the agent's network: its address on that bridge is on-link, so the proxy
#    never sees such a connection (the host INPUT rule in deploy/egress/README.md, "Setting it up")
HOST_GW="${EGRESS_HOST_GATEWAY:-172.29.0.1}"
banner=$(curl -sS --max-time 3 "telnet://$HOST_GW:22" < /dev/null 2>/dev/null | head -c 20)
case "$banner" in
  SSH-*) fail "the host's SSH answers at $HOST_GW:22: add the INPUT rule for the agent's bridge" ;;
  *) pass "the host's port 22 isn't reachable at $HOST_GW" ;;
esac
if curl -sS --max-time 3 -o /dev/null "http://$HOST_GW:8711/" 2>/dev/null; then
  fail "something answers at $HOST_GW:8711 (the owner app's port): add the INPUT rule for the agent's bridge"
else
  pass "nothing answers at $HOST_GW:8711"
fi

# 10. no IPv6 in the agent's container (the proxy only sees IPv4)
if [ "$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo 1)" = "1" ]; then
  pass "IPv6 is off"
else
  fail "IPv6 is on in the agent's container (sysctls in compose.egress.yaml)"
fi

# 11. ~/.config/secrets/api-keys.env is in place and its folder read-only. Looked at with test -e and stat
#     only: opening or reading the file, or listing the folder, stops the agent (deploy/egress/README.md).
#     AGENT_HOME: the agent's home if it isn't AGENT_USER's (compose.egress.yaml passes it from .env).
home="${AGENT_HOME:-}"
if [ -z "$home" ] && [ -n "${AGENT_USER:-}" ]; then
  home=$(getent passwd "${AGENT_USER%%:*}" 2>/dev/null | cut -d: -f6)
fi
keys="${home:-/opt/data}/.config/secrets/api-keys.env"
if [ -e "$keys" ]; then
  pass "$keys is in place ($(stat -c '%a, owner %u' "$keys" 2>/dev/null))"
else
  fail "no $keys: is the agent-config volume mounted there, and are the keys switched on in the app?"
fi
probe="$(dirname "$keys")/.selftest-$$"
if touch "$probe" 2>/dev/null; then
  rm -f "$probe"
  fail "$(dirname "$keys") is writable: mount the agent-config volume read-only (:ro)"
else
  pass "$(dirname "$keys") is read-only"
fi

exit "$failed"

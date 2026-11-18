#!/bin/sh
# Wraps the agent's own command (the compose file mounts this as the agent container's entrypoint):
#   1. default route and DNS through the egress proxy ($EGRESS_GATEWAY),
#   2. the proxy's CA added to the system's trust store and named for the usual tools,
#   3. the image's own start-up work, as root, when AGENT_BOOTSTRAP names it (Hermes: its stage2 hook),
#   4. the agent's command started without NET_ADMIN and NET_RAW (and SETUID, SETGID, SETPCAP): dropped from
#      the bounding set, so neither the agent nor anything it runs can take the route back or sniff and
#      spoof on its network.
# Run as root (the route needs it). POSIX sh: agent images rarely have bash. Fails closed: if a step doesn't
# work the agent doesn't start, and without the route its container has no way out anyway.
set -eu

GATEWAY="${EGRESS_GATEWAY:-172.29.0.2}"
CA=/ca/egress-ca.pem
BUNDLE=/etc/ssl/certs/ca-certificates.crt

fail() { echo "agent-entrypoint: $*" >&2; exit 1; }

[ "$#" -gt 0 ] || fail "no command given: set the agent's command in its compose file (command:, see compose.hermes.yaml)"
[ "$(id -u)" = "0" ] || fail "must start as root to set the route (user: \"0:0\" in compose.egress.yaml)"
# Unset is a mistake in the agent's compose file, not a choice for root: that has to be said with AGENT_USER=""
[ -n "${AGENT_USER+set}" ] || fail "AGENT_USER isn't set: the image's own user (name or uid:gid), or empty for root"
command -v ip >/dev/null 2>&1 || fail "the agent image needs iproute2 (the ip command)"
command -v setpriv >/dev/null 2>&1 || fail "the agent image needs setpriv (util-linux) to drop NET_ADMIN"

ip route replace default via "$GATEWAY" || fail "can't route through $GATEWAY"
# Every lookup straight to the proxy, from the agent's own address. Docker's embedded DNS (127.0.0.11) doesn't
# forward for containers that are only on internal networks; Doorman's name comes from extra_hosts.
printf 'nameserver %s\noptions ndots:0\n' "$GATEWAY" > /etc/resolv.conf

i=0
while [ ! -s "$CA" ] && [ "$i" -lt 60 ]; do sleep 1; i=$((i + 1)); done
[ -s "$CA" ] || fail "no proxy CA at $CA after 60 s: is the egress container running?"
if command -v update-ca-certificates >/dev/null 2>&1 && [ -d /usr/local/share/ca-certificates ]; then
  cp "$CA" /usr/local/share/ca-certificates/doorman-egress.crt
  update-ca-certificates >/dev/null 2>&1 || fail "update-ca-certificates failed"
else
  mkdir -p "$(dirname "$BUNDLE")"
  marker=$(sed -n 2p "$CA")
  grep -qF "$marker" "$BUNDLE" 2>/dev/null || cat "$CA" >> "$BUNDLE"
fi
[ -s "$BUNDLE" ] || fail "no CA bundle at $BUNDLE"
export SSL_CERT_FILE="$BUNDLE" REQUESTS_CA_BUNDLE="$BUNDLE" CURL_CA_BUNDLE="$BUNDLE" \
  NODE_EXTRA_CA_CERTS="$BUNDLE" GIT_SSL_CAINFO="$BUNDLE"

# The image's own start-up work (AGENT_BOOTSTRAP, a shell command; compose.hermes.yaml: Hermes's stage2 hook,
# which the image runs the same way under any init that isn't its own): as root, after the route and the CA,
# without NET_ADMIN, NET_RAW and SETPCAP, and with no folder of the agent's home on PATH, since the agent can
# write there and this runs as root. If it fails, the agent doesn't start.
if [ -n "${AGENT_BOOTSTRAP:-}" ]; then
  agent_home=""
  case "${AGENT_USER:-}" in ""|*:*) ;; *) agent_home=$(getent passwd "$AGENT_USER" | cut -d: -f6) ;; esac
  outside_home() {
    for h in "$agent_home" "${AGENT_HOME:-}"; do
      [ -n "$h" ] || continue
      case "$1" in "$h"|"$h"/*) return 1 ;; esac
    done
  }
  boot_path=""
  old_ifs=$IFS; IFS=:; set -f
  for dir in $PATH; do
    case "$dir" in /*) outside_home "$dir" && boot_path="${boot_path:+$boot_path:}$dir" ;; esac
  done
  set +f; IFS=$old_ifs
  boot_drop="-net_admin,-net_raw,-setpcap"
  PATH="$boot_path" setpriv --bounding-set="$boot_drop" --inh-caps="$boot_drop" --ambient-caps="$boot_drop" \
    -- /bin/sh -c "$AGENT_BOOTSTRAP" || fail "the image's start-up work failed: $AGENT_BOOTSTRAP"
fi

# The folder the agent starts in (AGENT_WORKDIR; Hermes: its workspace in its volume). An image's own is often
# where it was built (Hermes: /opt/hermes, its program folder), which an update replaces, so a file saved
# under a bare name, by the agent or a command it runs, would be lost.
if [ -n "${AGENT_WORKDIR:-}" ]; then
  if [ ! -d "$AGENT_WORKDIR" ]; then
    mkdir -p "$AGENT_WORKDIR" || fail "can't make $AGENT_WORKDIR"
    [ -z "${AGENT_USER:-}" ] || chown "$AGENT_USER" "$AGENT_WORKDIR"
  fi
  cd "$AGENT_WORKDIR" || fail "can't enter $AGENT_WORKDIR"
fi

# Gone from the bounding set (so from everything the agent starts, root or not):
#   NET_ADMIN  the route, iptables;
#   NET_RAW    raw sockets: ARP spoofing on the agent's network, forged packets;
#   SETUID, SETGID  becoming another user, e.g. the observer's, to signal it (the agent has no KILL either);
#   SETPCAP    needed for exactly this step.
# setpriv changes the user (AGENT_USER) with the capabilities it still has in effect, then execs.
# AGENT_USER (a name, or uid:gid): run the agent as that user, as the image would without this wrapper;
# empty: stay root (without the capabilities above), with AGENT_HOME as its home. Only on a rootless Docker
# of the agent's own: a root agent can change the image's programs that this script runs as root
# with NET_ADMIN at the next start, and so take the route back then; the network watch holds back any other user.
# AGENT_KEEP_SETID=1: SETUID and SETGID stay in the bounding set, for a user that needs
# setuid helpers (rootless Docker's newuidmap); that user still has no capability in effect. Never for root.
drop="-net_admin,-net_raw,-setpcap,-setuid,-setgid"
if [ "${AGENT_KEEP_SETID:-}" = 1 ]; then
  [ -n "${AGENT_USER:-}" ] || fail "AGENT_KEEP_SETID is for a user that isn't root"
  drop="-net_admin,-net_raw,-setpcap"
fi
caps="--bounding-set=$drop --inh-caps=$drop --ambient-caps=$drop"
case "${AGENT_USER:-}" in
  "")
    [ -z "${AGENT_HOME:-}" ] || export HOME="$AGENT_HOME"
    exec setpriv $caps -- "$@" ;;
  *:*) exec setpriv $caps --reuid "${AGENT_USER%%:*}" --regid "${AGENT_USER#*:}" --clear-groups -- "$@" ;;
  *)
    home=$(getent passwd "$AGENT_USER" | cut -d: -f6)
    [ -n "$home" ] || fail "no user $AGENT_USER in the agent image"
    # Docker makes the missing folders above a mount point as root (~/.config for ~/.config/secrets): the
    # agent's user gets ~/.config back, as it would have it without the mount
    if [ -d "$home/.config" ] && [ "$(stat -c %u "$home/.config" 2>/dev/null)" = "0" ]; then
      chown "$AGENT_USER:$(id -g "$AGENT_USER")" "$home/.config"
    fi
    export HOME="$home"
    exec setpriv $caps --reuid "$AGENT_USER" --regid "$(id -g "$AGENT_USER")" --init-groups -- "$@" ;;
esac

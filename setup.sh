#!/usr/bin/env bash
# Sets up a first Doorman. It asks how Doorman should run, where you will open the owner app and how you
# sign in, then writes the config, starts Doorman and tells you where to go. Run it again to change the
# answers: it keeps your data and your vault key.
#
#   ./setup.sh              ask and set up
#   ./setup.sh --dir DIR    Python install: keep doorman.yaml and the data in DIR, not in this folder
#
# The same steps by hand are in docs/running.md.
set -euo pipefail

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
dir=$repo
while [ $# -gt 0 ]; do
  case $1 in
    --dir) dir=${2:?--dir needs a folder}; shift 2 ;;
    -h|--help) sed -n '2,9p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option $1; see ./setup.sh --help" >&2; exit 2 ;;
  esac
done

say() { printf '%s\n' "$*"; }
stop() { say "$*" >&2; exit 1; }

# ask "Question" [default]: one line from the terminal (or from a pipe, for scripted runs)
ask() {
  local reply=""
  if [ -n "${2:-}" ]; then printf '%s [%s]: ' "$1" "$2" >&2; else printf '%s: ' "$1" >&2; fi
  read -r reply || true
  say "${reply:-${2:-}}"
}

# choose "Question" default "first" "second" ...: the number of the answer
choose() {
  local question=$1 default=$2 n=1 reply
  shift 2
  say "" >&2; say "$question" >&2
  for option in "$@"; do say "  $n) $option" >&2; n=$((n + 1)); done
  while :; do
    reply=$(ask "Choose" "$default")
    case $reply in ''|*[!0-9]*) ;; *) if [ "$reply" -ge 1 ] && [ "$reply" -le $# ]; then say "$reply"; return; fi ;; esac
    say "A number from 1 to $#, please." >&2
  done
}

# set_key FILE KEY VALUE: one top-level `key: value` line of doorman.yaml
set_key() {
  if grep -q "^$2:" "$1"; then sed -i "s|^$2:.*|$2: $3|" "$1"; else printf '%s: %s\n' "$2" "$3" >> "$1"; fi
}

# set_env FILE NAME VALUE: one NAME=value line of deploy/.env
set_env() {
  if grep -q "^$2=" "$1"; then sed -i "s|^$2=.*|$2=$3|" "$1"; else printf '%s=%s\n' "$2" "$3" >> "$1"; fi
}

MIN_PASSWORD=10
read_password() {
  local first second
  if [ ! -t 0 ]; then read -r first || true; say "$first"; return; fi   # piped in: one line
  while :; do
    read -rs -p "Password for the owner app (at least $MIN_PASSWORD characters): " first; say "" >&2
    if [ "${#first}" -lt "$MIN_PASSWORD" ]; then say "That is shorter than $MIN_PASSWORD characters." >&2; continue; fi
    read -rs -p "Once more: " second; say "" >&2
    if [ "$first" = "$second" ]; then say "$first"; return; fi
    say "The two don't match." >&2
  done
}

# ---------------------------------------------------------------- the questions

have_docker=no
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then have_docker=yes; fi

say "Doorman setup. Enter takes the answer in [brackets]."
if [ "$have_docker" = yes ]; then default_run=1; else default_run=2; fi
run=$(choose "How should Doorman run?" "$default_run" \
  "With Docker: its own container, every plugin sandboxed. For daily use." \
  "With Python on this machine: quickest to try, nothing sandboxed apart.")
if [ "$run" = 1 ] && [ "$have_docker" = no ]; then
  stop "Docker with the compose plugin isn't installed here. Install it, or choose Python."
fi

where=$(choose "Where will you open the owner app?" 1 \
  "Only on this machine, at http://localhost:8711" \
  "At an HTTPS address I have set up (a domain behind a reverse proxy or a tunnel)" \
  "From other devices on my network, without HTTPS")
network=""
case $where in
  1) url=http://localhost:8711 ;;
  2) while :; do
       url=$(ask "The HTTPS address, like https://doorman.example.com")
       case $url in https://?*) break ;; esac
       say "It has to start with https://" >&2
     done ;;
  3) address=$( (ip route get 1.1.1.1 2>/dev/null || true) | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}' | head -n 1)
     [ -n "$address" ] || address=$( (hostname -I 2>/dev/null || true) | awk '{print $1}')
     subnet=$( (ip -o -f inet addr show 2>/dev/null || true) | awk -v a="$address" 'index($4, a "/") == 1 {print $4}' | head -n 1)
     say "" >&2
     say "Without HTTPS a browser has no passkeys and gives no notifications: you sign in with a password and" >&2
     say "see what waits when you open the app. Others on the network can read the password and the app's traffic." >&2
     while :; do
       url=$(ask "The address you will open" "${address:+http://$address:8711}")
       case $url in http://?*) break ;; esac
       say "It has to start with http://" >&2
     done
     while :; do
       network=$(ask "Which network may open the app" "${subnet:-${address:+$address/24}}")
       case $network in *.*.*.*/*|*:*/*) break ;; esac
       say "A network like 192.168.1.0/24, please." >&2
     done ;;
esac
url=${url%/}

if [ "$where" = 3 ]; then
  method=2
else
  method=$(choose "How do you want to sign in to the app?" 1 \
    "With a passkey: your phone's or computer's own, nothing to guess or to phish" \
    "With a password")
fi
password=""
if [ "$method" = 2 ]; then
  password=$(read_password)
  [ "${#password}" -ge "$MIN_PASSWORD" ] || stop "The password needs at least $MIN_PASSWORD characters."
fi

# ---------------------------------------------------------------- write the config and start

sign_in() {   # sign_in COMMAND...: the doorman-admin that is given, on the host or in the container
  if [ "$method" = 2 ]; then
    printf '%s\n' "$password" | "$@" sign-in password
  else
    # a Doorman that had a password goes back to a passkey; either way this prints a setup code
    if "$@" sign-in | grep -q "with a password"; then "$@" sign-in passkey; else "$@" setup-code; fi
  fi
}

next_steps() {
  say ""
  say "Then:"
  if [ "$method" = 2 ]; then
    say "  1. Open $url/app/ and log in with your password."
  else
    say "  1. Open $url/app/, enter the setup code above and register your passkey."
  fi
  say "  2. Under Plugins, connect your first account or MCP server."
  say "  3. Under More > Agents > New agent key, copy the message the app shows into your agent."
}

if [ "$run" = 1 ]; then
  deploy=$repo/deploy
  config=$deploy/data/doorman.yaml
  mkdir -p "$deploy/data"
  [ -f "$config" ] || cp "$deploy/doorman.example.yaml" "$config"
  [ -f "$deploy/.env" ] || cp "$deploy/.env.example" "$deploy/.env"
  set_key "$config" public_url "$url"
  if [ "$where" = 3 ]; then
    # the compose file's own network (the host's forwarded port), this machine, and the network you named.
    # Never the agent's network (172.31.0.0/24): the agent must not reach the owner app.
    set_key "$config" owner_allow_cidrs "[172.30.0.0/24, 127.0.0.0/8, $network]"
    set_env "$deploy/.env" DOORMAN_OWNER_BIND 0.0.0.0
  else
    set_key "$config" owner_allow_cidrs "[172.30.0.0/24, 127.0.0.0/8]"
    set_env "$deploy/.env" DOORMAN_OWNER_BIND 127.0.0.1
  fi
  if ! grep -q '^DOORMAN_VAULT_KEY=.' "$deploy/.env"; then   # never replaced: it opens the vault you have
    set_env "$deploy/.env" DOORMAN_VAULT_KEY "$(openssl rand -base64 32 | tr '+/' '-_')"
    new_key=yes
  fi
  say ""
  say "Wrote $config and $deploy/.env. Building and starting Doorman:"
  cd "$deploy"
  docker compose up -d --build
  healthy=no
  for _ in $(seq 1 60); do
    if docker compose exec -T doorman python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8710/health', timeout=5)" >/dev/null 2>&1; then
      healthy=yes; break
    fi
    sleep 2
  done
  [ "$healthy" = yes ] || stop "Doorman didn't come up within two minutes. Look at: cd $deploy && docker compose logs doorman"
  say ""
  sign_in docker compose exec -T doorman doorman-admin
  next_steps
  if [ "${new_key:-no}" = yes ]; then
    say ""
    say "Keep the DOORMAN_VAULT_KEY from $deploy/.env in your password manager: it unlocks every stored"
    say "credential and is in no backup."
  fi
  say ""
  say "Doorman keeps running and comes back after a reboot. To stop it: cd $deploy && docker compose down"
  exit 0
fi

# with Python on this machine. DOORMAN_SETUP_ADMIN names a doorman-admin that is already installed (the
# tests use it); otherwise it goes into .venv in this folder.
admin=${DOORMAN_SETUP_ADMIN:-$repo/.venv/bin/doorman-admin}
if [ ! -x "$admin" ]; then
  command -v python3 >/dev/null 2>&1 || stop "python3 isn't installed here."
  python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))' || stop "Doorman needs Python 3.11 or newer; this is $(python3 -V)."
  say ""
  say "Installing Doorman into $repo/.venv (this takes a few minutes the first time):"
  python3 -m venv "$repo/.venv"
  "$repo/.venv/bin/pip" install --quiet -e "$repo[all]"
fi
mkdir -p "$dir"
cd "$dir"
dir=$(pwd)
config=$dir/doorman.yaml
export DOORMAN_CONFIG=$config   # whatever the shell had: this is the Doorman being set up
"$admin" init >/dev/null
set_key "$config" public_url "$url"
case $where in
  1) set_key "$config" owner_listen 127.0.0.1:8711      # nobody else's business on this machine's network
     set_key "$config" agent_listen 127.0.0.1:8710
     set_key "$config" owner_allow_cidrs "[127.0.0.0/8]" ;;
  2) set_key "$config" owner_listen 127.0.0.1:8711      # your proxy or tunnel on this machine passes it on;
     set_key "$config" agent_listen 127.0.0.1:8710      # for one on another machine, edit doorman.yaml
     set_key "$config" owner_allow_cidrs "[127.0.0.0/8]" ;;
  3) set_key "$config" owner_listen 0.0.0.0:8711
     set_key "$config" owner_allow_cidrs "[127.0.0.0/8, $network]" ;;
esac
say ""
say "Wrote $config; the data is in $dir/data."
sign_in "$admin"
next_steps
say ""
say "To start Doorman later: cd $dir && $admin serve"
start=$(ask "Start it now? It runs until you press Ctrl-C" "y")
case $start in y|Y|yes|Yes|"") exec "$admin" serve ;; esac

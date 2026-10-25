#!/usr/bin/env bash
# Starts ctf-watch.   Usage:  ./start.sh          (monitor the real CTF)
#                            ./start.sh --demo   (fake CTF + fake students, to see how it looks)
set -euo pipefail
cd "$(dirname "$0")"

DEMO=0
for a in "$@"; do
  case "$a" in
    --demo) DEMO=1 ;;
    -h|--help) sed -n 2,3p "$0"; exit 0 ;;
  esac
done

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 1. Docker
command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it with:  curl -fsSL https://get.docker.com | sudo sh"
if ! docker info >/dev/null 2>&1; then
  if [ "$(id -u)" -ne 0 ] && sudo -n true 2>/dev/null; then
    warn "Docker needs root on this machine - re-running with sudo"
    exec sudo -E "$0" "$@"
  fi
  die "Docker is installed but not reachable. Try:  sudo ./start.sh   (or add yourself to the docker group: sudo usermod -aG docker \$USER, then log out and in)"
fi
if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else die "Docker Compose is missing. Install the docker-compose-plugin package."; fi

# ---------------------------------------------------------------- 2. settings (.env)
if [ ! -f .env ]; then
  cp .env.example .env
  if [ "$DEMO" = "0" ]; then
    say "First run - looking for the CTF container's port..."
    mapfile -t FOUND < <(docker ps --format '{{.Names}}|{{.Ports}}' | grep -v '^ctf-watch' | grep -oE '[^|]+\|.*' | while IFS='|' read -r name ports; do
      for p in $(echo "$ports" | grep -oE '(0\.0\.0\.0|127\.0\.0\.1|\[::\]|::):[0-9]+->' | grep -oE ':[0-9]+' | tr -d ':' | sort -u); do echo "$p|$name"; done
    done | sort -u)
    PORT=""
    if [ "${#FOUND[@]}" -eq 1 ]; then
      PORT="${FOUND[0]%%|*}"
      say "Found one container with a published port: ${FOUND[0]#*|} on port $PORT"
    elif [ "${#FOUND[@]}" -gt 1 ]; then
      echo "Several containers publish ports:"
      i=1; for f in "${FOUND[@]}"; do echo "   $i) port ${f%%|*}   (container: ${f#*|})"; i=$((i+1)); done
      if [ -t 0 ]; then
        read -r -p "Which number is the CTF app? [1]: " choice; choice="${choice:-1}"
        PORT="${FOUND[$((choice-1))]%%|*}"
      else PORT="${FOUND[0]%%|*}"; fi
    else
      warn "No running container with a published port was found."
      if [ -t 0 ]; then read -r -p "Which port is the CTF app on? [3000]: " PORT; fi
      PORT="${PORT:-3000}"
    fi
    sed -i "s|^CTF_TARGET=.*|CTF_TARGET=http://127.0.0.1:$PORT|" .env
    say "Saved CTF_TARGET=http://127.0.0.1:$PORT to .env  (edit .env to change it)"
  fi
fi
set -a; . ./.env; set +a
PROXY_PORT="${PROXY_PORT:-8888}"; DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"; PROXY_BIND="${PROXY_BIND:-127.0.0.1}"

PROFILE=""
if [ "$DEMO" = "1" ]; then
  export DEMO=1 MOCK_PORT="${MOCK_PORT:-3999}"
  export CTF_TARGET="http://127.0.0.1:$MOCK_PORT"
  PROFILE="--profile demo"
  say "DEMO MODE: a fake CTF app + fake students will be started. No real CTF is touched."
else
  export DEMO=0
fi

# ---------------------------------------------------------------- 3. start
say "Building and starting (first time takes a minute)..."
# shellcheck disable=SC2086
$COMPOSE $PROFILE up -d --build --remove-orphans

say "Waiting for the dashboard..."
ok=0
for _ in $(seq 1 30); do
  if (command -v curl >/dev/null && curl -fs "http://127.0.0.1:$DASHBOARD_PORT/healthz" >/dev/null 2>&1) || \
     (command -v wget >/dev/null && wget -qO- "http://127.0.0.1:$DASHBOARD_PORT/healthz" >/dev/null 2>&1); then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { warn "Dashboard did not answer yet. Logs:"; $COMPOSE logs --tail=30 monitor; exit 1; }

# ---------------------------------------------------------------- 4. done
echo
printf '\033[1;32m  ctf-watch is running.\033[0m\n'
echo
echo "  Dashboard (this machine only):  http://127.0.0.1:$DASHBOARD_PORT"
echo "  Proxy for students:             http://$PROXY_BIND:$PROXY_PORT  ->  $CTF_TARGET"
echo "  Logs:                           $(pwd)/logs/"
if [ "${NAME_GATE:-0}" = "1" ]; then echo "  Name gate:                      ON - students are asked for their name on first visit"; fi
echo
if [ "$DEMO" = "1" ]; then
  echo "  Fake students are now playing. Open the dashboard and watch."
  echo "  Stop with:  ./stop.sh"
else
  echo "  NOW POINT ZROK AT THE PROXY (not at the CTF port):"
  echo
  echo "      zrok share public http://127.0.0.1:$PROXY_PORT"
  echo
  echo "  (If you use a reserved share:  zrok reserve public http://127.0.0.1:$PROXY_PORT   then   zrok share reserved <name>)"
  echo "  Stop the old zrok share that pointed at the CTF port first (Ctrl+C in its terminal)."
fi
echo
echo "  If the VM has no browser, from your laptop run:  ssh -L $DASHBOARD_PORT:127.0.0.1:$DASHBOARD_PORT <user>@<vm-ip>"
echo "  then open http://127.0.0.1:$DASHBOARD_PORT on the laptop."
echo

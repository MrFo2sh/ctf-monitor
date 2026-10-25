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

# Load KEY=value lines from .env without executing them (values may contain spaces).
load_env() {
  local k v
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in ''|'#'*) continue ;; esac
    k="${line%%=*}"; v="${line#*=}"
    [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
    v="${v#"${v%%[![:space:]]*}"}"; v="${v%"${v##*[![:space:]]}"}"
    if [[ "$v" == \"*\" ]]; then v="${v#\"}"; v="${v%\"}"; elif [[ "$v" == \'*\' ]]; then v="${v#\'}"; v="${v%\'}"; fi
    export "$k=$v"
  done < "$1"
}

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
    PORT="${PORT//[^0-9]/}"; PORT="${PORT:-3000}"
    sed -i "s|^CTF_TARGET=.*|CTF_TARGET=http://127.0.0.1:$PORT|" .env
    say "Saved CTF_TARGET=http://127.0.0.1:$PORT to .env  (edit .env to change it)"
  fi
fi
load_env .env
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

# ---------------------------------------------------------------- 4. zrok
ZROK_URL=""
ZROK_NOTE=""
if [ "$DEMO" = "0" ] && [ "${ZROK_AUTO:-1}" = "1" ]; then
  # zrok is set up for the normal user; if we were re-run with sudo, run zrok as that user
  ZROK_AS=()
  if [ -n "${SUDO_USER:-}" ] && [ "$(id -u)" -eq 0 ]; then ZROK_AS=(sudo -u "$SUDO_USER" -H); fi
  # zrok2 (new) is preferred over zrok (old); ZROK_BIN in .env overrides
  ZROK_BIN="${ZROK_BIN:-}"
  for cand in zrok2 zrok; do
    [ -n "$ZROK_BIN" ] && break
    ZROK_BIN="$(command -v "$cand" 2>/dev/null || true)"
    [ -z "$ZROK_BIN" ] && [ -n "${SUDO_USER:-}" ] && ZROK_BIN="$(sudo -u "$SUDO_USER" -i sh -c "command -v $cand" 2>/dev/null || true)"
  done

  if [ -z "$ZROK_BIN" ]; then
    ZROK_NOTE="zrok was not found. Start it yourself:   zrok2 share public $PROXY_PORT"
  else
    # an older share (ours, or the one that points straight at the CTF) must stop first
    if pgrep -f 'zrok2? share' >/dev/null 2>&1; then
      echo "A zrok share is already running:"
      pgrep -af 'zrok2? share' | sed 's/^/     /'
      yn="Y"
      if [ -t 0 ]; then read -r -p "Stop it and share the proxy port instead? [Y/n]: " yn; yn="${yn:-Y}"; fi
      case "$yn" in
        n|N) ZROK_NOTE="Left the old zrok share running. Students still go straight to the CTF, NOT through the monitor." ;;
        *) pkill -f 'zrok2? share' || true; sleep 2 ;;
      esac
    fi
    if [ -z "$ZROK_NOTE" ]; then
      case "$(basename "$ZROK_BIN")" in
        zrok2)
          # zrok 2:  zrok2 share public --headless <port>     fixed name:  -n public:<name>  (after: zrok2 create name <name>)
          if [ -n "${ZROK_RESERVED:-}" ]; then
            ZROK_CMD=("$ZROK_BIN" share public --headless -n "public:${ZROK_RESERVED#public:}" "$PROXY_PORT")
          else
            ZROK_CMD=("$ZROK_BIN" share public --headless "$PROXY_PORT")
          fi ;;
        *)
          # zrok 1:  zrok share public --headless http://127.0.0.1:<port>     reserved:  zrok share reserved <name>
          if [ -n "${ZROK_RESERVED:-}" ]; then
            ZROK_CMD=("$ZROK_BIN" share reserved --headless --override-endpoint "http://127.0.0.1:$PROXY_PORT" "$ZROK_RESERVED")
          else
            ZROK_CMD=("$ZROK_BIN" share public --headless "http://127.0.0.1:$PROXY_PORT")
          fi ;;
      esac
      say "Starting zrok: ${ZROK_CMD[*]}"
      : > logs/zrok.log
      nohup ${ZROK_AS[@]+"${ZROK_AS[@]}"} "${ZROK_CMD[@]}" >> logs/zrok.log 2>&1 &
      echo $! > logs/zrok.pid
      for _ in $(seq 1 25); do
        ZROK_URL="$(grep -oE 'https://[A-Za-z0-9._-]+\.[A-Za-z0-9._-]*zrok[A-Za-z0-9./_-]*' logs/zrok.log 2>/dev/null | head -1 || true)"
        [ -n "$ZROK_URL" ] && break
        if ! kill -0 "$(cat logs/zrok.pid)" 2>/dev/null; then break; fi
        sleep 1
      done
      if [ -z "$ZROK_URL" ]; then
        ZROK_NOTE="zrok started but no URL was seen yet. Check:  tail -f logs/zrok.log   (if it failed, run:  $(basename "$ZROK_BIN") share public $PROXY_PORT)"
      fi
    fi
  fi
fi

# ---------------------------------------------------------------- 5. done
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
elif [ -n "$ZROK_URL" ]; then
  printf '  \033[1;32mGIVE THIS LINK TO THE STUDENTS:\033[0m\n\n      %s\n\n' "$ZROK_URL"
  echo "  zrok is running in the background (log: logs/zrok.log). ./stop.sh stops it together with the monitor."
elif [ -n "$ZROK_NOTE" ]; then
  warn "$ZROK_NOTE"
else
  echo "  zrok auto-start is off (ZROK_AUTO=0). Point zrok at the proxy yourself:"
  echo "      zrok2 share public $PROXY_PORT        (old zrok:  zrok share public http://127.0.0.1:$PROXY_PORT)"
fi
echo
echo "  If the VM has no browser, from your laptop run:  ssh -L $DASHBOARD_PORT:127.0.0.1:$DASHBOARD_PORT <user>@<vm-ip>"
echo "  then open http://127.0.0.1:$DASHBOARD_PORT on the laptop."
echo

#!/usr/bin/env bash
# Stops ctf-watch. Logs in ./logs and the database in ./data are kept.
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else echo "Docker Compose not found"; exit 1; fi

if ! docker info >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi
if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'docker desktop'; then COMPOSE="$COMPOSE -f docker-compose.yml -f docker-compose.desktop.yml"; fi
if [ -f .env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"; case "$line" in ''|'#'*) continue ;; esac
    k="${line%%=*}"; v="${line#*=}"
    [[ "$k" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] && export "$k=$v"
  done < .env
fi

# stop the zrok share we started
if [ -f logs/zrok.pid ]; then
  PID="$(cat logs/zrok.pid)"
  if kill -0 "$PID" 2>/dev/null; then kill "$PID" 2>/dev/null || sudo kill "$PID" 2>/dev/null || true; echo "zrok share stopped."; fi
  rm -f logs/zrok.pid
fi
pkill -f "zrok2? share .*${PROXY_PORT:-8888}" 2>/dev/null || true
rm -f logs/zrok.url

$COMPOSE down --remove-orphans
echo
echo "ctf-watch stopped. Logs are still in ./logs/"
echo "The zrok share is stopped too, so students cannot reach the CTF until you run ./start.sh again"
echo "(or share the CTF port directly:  zrok share public <ctf-port>)."

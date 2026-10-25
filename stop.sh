#!/usr/bin/env bash
# Stops ctf-watch (and the demo, if it was running). Logs in ./logs are kept.
set -euo pipefail
cd "$(dirname "$0")"

if docker compose version >/dev/null 2>&1; then COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then COMPOSE="docker-compose"
else echo "Docker Compose not found"; exit 1; fi

if ! docker info >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi

$COMPOSE --profile demo down --remove-orphans
echo
echo "ctf-watch stopped. Logs are still in ./logs/"
echo "Remember: if zrok is still pointing at the proxy port, students can no longer reach the CTF."
echo "Either start ctf-watch again (./start.sh) or point zrok back at the CTF port."

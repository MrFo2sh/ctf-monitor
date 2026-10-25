#!/usr/bin/env bash
# Collects facts about the CTF setup on this VM into inspect-report.txt
# so the detection rules (config/rules.json) can be tuned for the real app.
# Safe: read-only. It never changes the CTF container.
# Secrets: environment variable VALUES are not printed (only names), except PORT/HOST/URL-like ones.
set -uo pipefail
cd "$(dirname "$0")"
OUT="inspect-report.txt"
exec > >(tee "$OUT") 2>&1

h() { echo; echo "================================================================"; echo "## $*"; echo "================================================================"; }

if ! docker info >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi

h "System"
date -u; uname -a; echo; free -m 2>/dev/null | head -2
echo; echo "Docker: $(docker --version 2>&1)"; docker compose version 2>&1 | head -1

h "Running containers"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

h "Listening ports on the VM (ss -ltnp)"
ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || echo "(ss/netstat not available)"

h "zrok"
command -v zrok >/dev/null && zrok version 2>&1 | head -3 || echo "zrok binary not in PATH for this user"
echo; echo "zrok processes (shows which URL/port zrok currently shares):"
pgrep -af zrok || echo "(no zrok process running right now)"
echo; ls -la ~/.zrok 2>/dev/null | head || true

for c in $(docker ps --format '{{.Names}}' | grep -v '^ctf-watch'); do
  h "Container: $c"
  echo "Image:           $(docker inspect -f '{{.Config.Image}}' "$c")"
  echo "Compose project: $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$c")"
  echo "Compose files:   $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.config_files"}}' "$c")"
  echo "Compose workdir: $(docker inspect -f '{{index .Config.Labels "com.docker.compose.project.working_dir"}}' "$c")"
  echo "Exposed ports:   $(docker inspect -f '{{range $p, $_ := .Config.ExposedPorts}}{{$p}} {{end}}' "$c")"
  echo "Published ports: $(docker inspect -f '{{range $p, $b := .NetworkSettings.Ports}}{{range $b}}{{.HostIp}}:{{.HostPort}}->{{$p}} {{end}}{{end}}' "$c")"
  echo "Network mode:    $(docker inspect -f '{{.HostConfig.NetworkMode}}' "$c")"
  echo "Cmd:             $(docker inspect -f '{{.Config.Cmd}}' "$c")"
  echo "Entrypoint:      $(docker inspect -f '{{.Config.Entrypoint}}' "$c")"
  echo "Workdir:         $(docker inspect -f '{{.Config.WorkingDir}}' "$c")"
  echo "Env (names only, PORT/HOST/URL values shown):"
  docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' "$c" | while IFS='=' read -r k v; do
    case "$k" in *PORT*|*HOST*|*URL*|*ENV*|*MODE*|*DEBUG*) echo "   $k=$v" ;; *) echo "   $k=<hidden>" ;; esac
  done
  echo "Mounts:"
  docker inspect -f '{{range .Mounts}}   {{.Type}} {{.Source}} -> {{.Destination}}{{println}}{{end}}' "$c"

  echo; echo "--- files in the container's working directory"
  docker exec "$c" sh -c 'ls -la 2>/dev/null | head -40' 2>/dev/null || echo "(docker exec not possible)"
  echo; echo "--- project manifests"
  docker exec "$c" sh -c 'for f in package.json requirements.txt Pipfile composer.json go.mod Gemfile pom.xml; do [ -f $f ] && { echo "# $f"; head -60 $f; }; done' 2>/dev/null
  echo; echo "--- routes / endpoints found in source (first 150)"
  docker exec "$c" sh -c 'grep -rEn --include=*.js --include=*.ts --include=*.py --include=*.php --include=*.rb --include=*.go --include=*.java \
      "(app|router|route|r|api|bp|blueprint)\.(get|post|put|delete|patch|route|all)\(|@(app|bp|router|api)\.(route|get|post|put|delete)|Route::(get|post|any)|path\(|\$_(GET|POST|REQUEST)\[|HandleFunc\(|@(Get|Post|Put|Delete)Mapping" . 2>/dev/null \
      | grep -v node_modules | grep -v vendor | head -150' 2>/dev/null
  echo; echo "--- auth / session / jwt hints in source"
  docker exec "$c" sh -c 'grep -rEil "jsonwebtoken|jwt|express-session|cookie-session|flask_login|session_start|PHPSESSID|django.contrib.sessions|passport|bcrypt" . 2>/dev/null | grep -v node_modules | grep -v vendor | head -30' 2>/dev/null
  echo; echo "--- seed / fixture / database files (who owns what)"
  docker exec "$c" sh -c 'find . -maxdepth 4 \( -iname "*seed*" -o -iname "*fixture*" -o -iname "*.sql" -o -iname "*.db" -o -iname "*.sqlite*" -o -iname "*.json" \) -not -path "*/node_modules/*" 2>/dev/null | head -30' 2>/dev/null
done

h "Docker compose files found on disk (home dir, depth 4)"
find "$HOME" /opt /srv -maxdepth 4 \( -name 'docker-compose*.y*ml' -o -name 'compose*.y*ml' -o -name Dockerfile \) 2>/dev/null | grep -v ctf-watch | head -20

h "HTTP probe of each published port (headers + cookie names)"
for p in $(docker ps --format '{{.Ports}}' | grep -oE ':[0-9]+->' | tr -d ':>-' | sort -u); do
  echo "--- http://127.0.0.1:$p/"
  curl -s -m 5 -D - -o /tmp/ctfwatch_body.$$ "http://127.0.0.1:$p/" | sed -E 's/(Set-Cookie: *[^=]+=)[^;]*/\1<hidden>/I' | head -25
  echo "body (first 15 lines):"; head -15 /tmp/ctfwatch_body.$$ 2>/dev/null; rm -f /tmp/ctfwatch_body.$$
  echo "links/forms/api paths seen in body:"
  curl -s -m 5 "http://127.0.0.1:$p/" | grep -oE '(href|action|src|fetch\(|url:)=?["'"'"']?[^"'"'"' >]+' | sort -u | head -30
  echo
done

h "Done"
echo "Report saved to $(pwd)/$OUT - send this file to whoever tunes config/rules.json."

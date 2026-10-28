# Start, stop and inspect scripts — `start.sh`, `stop.sh`, `inspect.sh`

## Purpose

Three bash scripts at the repository root wrap the Docker side of ctf-watch so an organizer never types a `docker compose` command:

| Script | Job |
|---|---|
| `start.sh` | Check Docker, create `.env` on first run, build and start the `monitor` container, wait until the dashboard answers, start (or keep) the zrok share that gives students a public link, print the generated dashboard accounts and the link. |
| `stop.sh` | Kill the zrok share we started, remove the container. Logs and the SQLite database stay on disk. |
| `inspect.sh` | Read-only survey of the VM (containers, ports, source files of the CTF app, HTTP headers) saved to `inspect-report.txt`, so `config/rules.json` can be tuned for the real CTF app. |

All three `cd` to their own directory first, so they can be run from anywhere (`/opt/ctf-watch/start.sh` works).

The scripts assume **bash** (arrays, `[[ ]]`, `$'\r'`, process substitution). They are declared with `#!/usr/bin/env bash`; running them with `sh start.sh` breaks.

## Walkthrough

### `start.sh`

#### Header, flags, helpers (lines 1–16)

```bash
# start.sh lines 1-12
#!/usr/bin/env bash
# Starts ctf-watch.   Usage:  ./start.sh
# (To try it without a real CTF: log in to the dashboard and use the Playground tab.)
set -euo pipefail
cd "$(dirname "$0")"

for a in "$@"; do
  case "$a" in
    -h|--help) sed -n 2,3p "$0"; exit 0 ;;
    --demo) echo "The --demo flag is gone: start normally, then use the Playground tab in the dashboard."; exit 1 ;;
  esac
done
```

- `set -euo pipefail`: `-e` aborts on any failing command, `-u` makes an unset variable an error, `pipefail` makes a pipeline fail if any stage fails (not only the last). Every place in this script that tolerates a failure therefore has an explicit `|| true` or an `if`.
- `cd "$(dirname "$0")"`: all later relative paths (`.env`, `logs/`, `docker-compose.yml`) are relative to the repo root.
- `-h`/`--help` prints lines 2–3 **of the script file itself** (`sed -n 2,3p "$0"`: `-n` suppresses default output, `2,3p` prints that line range). If you edit the comment header, the help text changes with it.
- `--demo` is a removed flag; it exits 1 with a pointer to the Playground tab so old instructions fail loudly instead of silently starting.

```bash
# start.sh lines 14-16
say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m!!\033[0m  %s\n' "$*"; }
die()  { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
```

Three output helpers using ANSI colours (`\033[1;36m` = bold cyan, `33` yellow, `31` red, `\033[0m` reset). `die` writes to stderr (`>&2`) and exits 1. `"$*"` joins all arguments with a space.

#### `load_env` — reading `.env` without executing it (lines 18–30)

```bash
# start.sh lines 19-30
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
```

The obvious alternative, `source .env`, would execute anything in the file (a value with spaces or `$(...)` would break or run code). This parser only ever assigns.

- `while IFS= read -r line || [ -n "$line" ]`: `IFS=` keeps leading/trailing whitespace, `-r` keeps backslashes literal. `read` returns non-zero on the final line when the file has no trailing newline, but it still fills `line`; the `|| [ -n "$line" ]` makes that last line processed too.
- `line="${line%$'\r'}"`: strips one trailing carriage return, so a `.env` edited on Windows (CRLF) still works. `$'\r'` is bash's ANSI-C quoting for the CR byte.
- `case "$line" in ''|'#'*) continue ;; esac`: skips blank lines and lines starting with `#`. An inline comment after a value (`PORT=1 # x`) is **not** stripped; the `# x` becomes part of the value.
- `k="${line%%=*}"` removes the longest suffix starting at `=`, leaving the key; `v="${line#*=}"` removes the shortest prefix up to the first `=`, leaving everything after it (so values may themselves contain `=`).
- The regex check rejects keys that are not valid identifiers (a line like `export FOO=1` or `foo bar=1` is silently skipped).
- Trim: `${v%%[![:space:]]*}` is `v` with everything from the first non-space removed, i.e. the leading whitespace; `${v#"..."}` then removes exactly that prefix. The mirror expression removes trailing whitespace.
- Surrounding double or single quotes are stripped, one pair, only if both ends match. No escape processing happens inside.
- `export "$k=$v"`: the variable enters the environment so that `docker compose` (which reads the shell environment first, then the project's `.env` file) and the rest of this script see it. Note that it **overwrites** a variable already set in the caller's environment: `PROXY_PORT=9999 ./start.sh` is overridden by the `PROXY_PORT=8888` line that `.env.example` ships with. Edit `.env` instead.
- `line` is intentionally not declared `local` (only `k v` are); it leaks into the global scope, harmlessly.

#### 1. Docker checks (lines 32–50)

```bash
# start.sh lines 33-43
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
```

- `command -v docker` checks the binary exists in `PATH` without running it.
- `docker info` fails when the daemon is down **or** when the user lacks permission on `/var/run/docker.sock`. The script handles the permission case: if we are not root (`id -u` ≠ 0) and `sudo -n true` succeeds (`-n` = non-interactive; it only succeeds when sudo needs no password, e.g. NOPASSWD or a cached timestamp), it re-executes itself as root. `exec` replaces the current process; `-E` preserves the environment; `"$0" "$@"` passes the same script and arguments. If a password would be required, `sudo -n` fails and the script dies with the manual instruction instead of hanging on a prompt.
- Compose v2 is a docker plugin (`docker compose`); v1 is a separate `docker-compose` binary. `COMPOSE` is a plain string that is later expanded **unquoted** (`$COMPOSE up ...`) so that word splitting turns it back into separate arguments. That is why the override files are appended to this same string below.

```bash
# start.sh lines 44-50
# Docker Desktop (Windows / macOS) cannot use host networking the way Linux does: use the bridge override
DESKTOP=0
if docker info --format '{{.OperatingSystem}}' 2>/dev/null | grep -qi 'docker desktop'; then
  DESKTOP=1
  COMPOSE="$COMPOSE -f docker-compose.yml -f docker-compose.desktop.yml"
  warn "Docker Desktop detected: using docker-compose.desktop.yml (bridge networking, ports on 127.0.0.1)"
fi
```

`docker info --format '{{.OperatingSystem}}'` prints the daemon's OS string; Docker Desktop reports `Docker Desktop`. `grep -qi`: `-q` quiet (exit status only), `-i` case-insensitive. On a match both compose files are passed with `-f`; the second one overrides keys of the first (see chapter 24 for what it changes and why). On a Linux VM nothing matches and the default `docker-compose.yml` alone is used. `DESKTOP` is set but not read anywhere else in the script; it exists for future use or debugging.

#### 2. Settings (lines 52–58)

```bash
# start.sh lines 53-58
if [ ! -f .env ]; then
  cp .env.example .env
  say "Created .env with defaults. The CTF app is chosen in the dashboard (CTFs tab) after start."
fi
load_env .env
PROXY_PORT="${PROXY_PORT:-8888}"; DASHBOARD_PORT="${DASHBOARD_PORT:-8080}"; PROXY_BIND="${PROXY_BIND:-127.0.0.1}"
```

First run copies the template. Then the file is parsed with `load_env`, and the three values the script itself needs get defaults in case the user deleted the lines (`${VAR:-default}` = value of `VAR`, or `default` if unset **or empty**). The same defaults are repeated in `docker-compose.yml`, so the script and the container agree even with a minimal `.env`.

#### 3. Start and health wait (lines 60–71)

```bash
# start.sh lines 61-71
say "Building and starting (first time takes a minute)..."
$COMPOSE up -d --build --remove-orphans

say "Waiting for the dashboard..."
ok=0
for _ in $(seq 1 30); do
  if (command -v curl >/dev/null && curl -fs "http://127.0.0.1:$DASHBOARD_PORT/healthz" >/dev/null 2>&1) || \
     (command -v wget >/dev/null && wget -qO- "http://127.0.0.1:$DASHBOARD_PORT/healthz" >/dev/null 2>&1); then ok=1; break; fi
  sleep 1
done
[ "$ok" = "1" ] || { warn "Dashboard did not answer yet. Logs:"; $COMPOSE logs --tail=30 monitor; exit 1; }
```

- `up -d --build --remove-orphans`: detached, rebuild the image from `proxy/` every time (cheap thanks to layer caching; guarantees code changes are picked up), and delete containers from services that no longer exist in the compose file (e.g. the simulator service of older versions).
- Health loop: up to 30 attempts one second apart. `curl -f` makes HTTP errors (4xx/5xx) a non-zero exit, `-s` is silent. If curl is missing, `wget -qO-` (`-q` quiet, `-O-` body to stdout) is tried. Each alternative is in a subshell `( ... )` so a missing binary just makes that branch false. `/healthz` is served by `proxy/src/dashboard.js` before authentication, returning `ok`.
- The check always targets `127.0.0.1`, which is correct both with host networking (the dashboard binds there by default) and on Docker Desktop (the port is published on `127.0.0.1`). If you set `DASHBOARD_BIND=0.0.0.0` it still works because `0.0.0.0` includes loopback.
- On timeout the last 30 log lines of the `monitor` service are shown and the script exits 1 — the container is left running so you can keep debugging.

#### 4. zrok (lines 73–155)

The whole block is skipped when `ZROK_AUTO=0`. Two outputs feed the summary: `ZROK_URL` (the public link, if known) and `ZROK_NOTE` (a message when there is no link).

```bash
# start.sh lines 76-86
if [ "${ZROK_AUTO:-1}" = "1" ]; then
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
```

- zrok's enable token lives in the **user's** home (`~/.zrok`). If the script re-ran itself through sudo, `SUDO_USER` holds the original login; `ZROK_AS` becomes a command prefix `sudo -u <user> -H` (`-H` sets `HOME` to that user's home so zrok finds its config). As a bash array it can be empty without producing a stray empty argument.
- Binary lookup: `ZROK_BIN` from `.env` wins (`break` on the first iteration when it is non-empty). Otherwise `zrok2` then `zrok` are searched in the current `PATH`. Under sudo, root's `PATH` usually lacks `~/.local/bin`-style installs, so a second lookup runs a **login shell** for the original user (`sudo -u <user> -i sh -c "command -v zrok2"`, `-i` = simulate login so their profile sets `PATH`).

```bash
# start.sh lines 88-98
  if [ -z "$ZROK_BIN" ]; then
    ZROK_NOTE="zrok was not found. Start it yourself:   zrok2 share public $PROXY_PORT"
  else
    # our own share from a previous ./start.sh still running? keep it (same link for the students)
    if [ -f logs/zrok.pid ] && kill -0 "$(cat logs/zrok.pid)" 2>/dev/null && pgrep -af 'zrok2? share' | grep -q "[: ]$PROXY_PORT\b"; then
      ZROK_URL="$(grep -oE '(https?://)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.zrok\.io[A-Za-z0-9./_-]*' logs/zrok.log 2>/dev/null | head -1 || true)"
      case "$ZROK_URL" in ''|http://*|https://*) ;; *) ZROK_URL="https://$ZROK_URL" ;; esac
      [ -n "$ZROK_URL" ] && echo "$ZROK_URL" > logs/zrok.url
      ZROK_NOTE="${ZROK_URL:+keep}"
      [ -z "$ZROK_URL" ] && ZROK_NOTE="The zrok share from the previous start is still running (see logs/zrok.log for the link)."
      say "zrok share already running for port $PROXY_PORT - keeping it"
```

**Keep-existing-share logic.** Re-running `./start.sh` (after a code change, say) must not give students a new link. Three conditions must all hold:

1. `logs/zrok.pid` exists (written by a previous run of this script);
2. `kill -0 <pid>` succeeds — signal 0 sends nothing but tests that the process exists and we may signal it;
3. `pgrep -af 'zrok2? share'` (`-a` print the full command line, `-f` match the pattern against the full command line, regex `zrok2?` = `zrok` or `zrok2`) lists the running share processes, and `grep -q "[: ]$PROXY_PORT\b"` requires our port to appear preceded by a colon or a space and followed by a word boundary. zrok 2 is started with ` 8888` at the end, zrok 1 with `:8888`; the boundary prevents `8888` from matching `18888`.

If so, the URL is recovered from the previous `logs/zrok.log` with `grep -oE` (`-o` print only the matching part, `-E` extended regex). The regex accepts an optional scheme, a dotted hostname, `.zrok.io`, and an optional path. `head -1` keeps the first hit; `|| true` absorbs grep's exit 1 when nothing matches (remember `pipefail`). A scheme-less match (what zrok 2 prints) is prefixed with `https://`. The link is written to `logs/zrok.url`, which the dashboard's CTFs tab reads (`studentLink()` in `proxy/src/server.js`).

`ZROK_NOTE="${ZROK_URL:+keep}"` uses the `:+` expansion: it yields `keep` when `ZROK_URL` is non-empty, else the empty string. `keep` is a sentinel checked at line 110. Note this branch, unlike line 136 below, does not filter out `api.` hostnames; in practice the first `*.zrok.io` string in the log is the share address.

```bash
# start.sh lines 99-109
    # an older share (ours, or the one that points straight at the CTF) must stop first
    elif pgrep -f 'zrok2? share' >/dev/null 2>&1; then
      echo "A zrok share is already running:"
      pgrep -af 'zrok2? share' | sed 's/^/     /'
      yn="Y"
      if [ -t 0 ]; then read -r -p "Stop it and share the proxy port instead? [Y/n]: " yn; yn="${yn:-Y}"; fi
      case "$yn" in
        n|N) ZROK_NOTE="Left the old zrok share running. Students still go straight to the CTF, NOT through the monitor." ;;
        *) pkill -f 'zrok2? share' || true; sleep 2 ;;
      esac
    fi
```

Some other share is running (typically the organizer's old one pointing straight at the CTF port, which would bypass the monitor). The processes are listed indented by five spaces (`sed 's/^/     /'` inserts at the start of each line). `[ -t 0 ]` is true only when stdin is a terminal; then the user is asked, default `Y`. Non-interactively (cron, CI, `./start.sh < /dev/null`) the default applies and the old share is killed with `pkill -f` (same full-command-line matching). `sleep 2` gives zrok time to release its session before a new one is opened. Answering `n` sets a note, which also prevents starting a new share (next block).

```bash
# start.sh lines 110-128
    if [ "$ZROK_NOTE" = "keep" ]; then
      ZROK_NOTE=""
    elif [ -z "$ZROK_NOTE" ]; then
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
```

Three states reach here: `keep` (existing share kept → clear the note, nothing to start), empty note (no share, or we killed one → start), or a message (zrok missing, user said `n` → start nothing, show the message later).

**zrok2 vs zrok.** The two generations have different CLIs, chosen by the binary's basename:

- zrok 2: `zrok2 share public --headless <port>` takes a bare port. A fixed name is passed as `-n public:<name>`; `${ZROK_RESERVED#public:}` strips a `public:` prefix if the user already typed one, so the prefix is never doubled. The name must have been created once with `zrok2 create name <name>`.
- zrok 1: `zrok share public --headless http://127.0.0.1:<port>` takes a full URL. A reserved share is started with `share reserved <name>`, and `--override-endpoint` points it at the proxy regardless of what endpoint it was reserved with.

`--headless` prints to stdout instead of drawing a TUI — required because the output is parsed. The command is kept as an array so arguments with spaces survive.

```bash
# start.sh lines 129-144
      say "Starting zrok: ${ZROK_CMD[*]}"
      : > logs/zrok.log
      nohup ${ZROK_AS[@]+"${ZROK_AS[@]}"} "${ZROK_CMD[@]}" >> logs/zrok.log 2>&1 &
      echo $! > logs/zrok.pid
      for _ in $(seq 1 45); do
        # zrok2 logs e.g. "...endpoints:\n rvajwqvbc62o.shares.zrok.io" (no scheme); zrok 1 prints a full https:// URL
        # only a *.zrok.io share address counts (the log also contains zrok's own API URLs, e.g. *.netfoundry.io)
        ZROK_URL="$(grep -oE '(https?://)?[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.zrok\.io[A-Za-z0-9./_-]*' logs/zrok.log 2>/dev/null | grep -vE '^(https?://)?api\.' | head -1 || true)"
        if [ -n "$ZROK_URL" ]; then
          case "$ZROK_URL" in http://*|https://*) ;; *) ZROK_URL="https://$ZROK_URL" ;; esac
          break
        fi
        if ! kill -0 "$(cat logs/zrok.pid)" 2>/dev/null; then break; fi
        sleep 1
      done
      [ -n "$ZROK_URL" ] && echo "$ZROK_URL" > logs/zrok.url   # shown on the dashboard (CTFs tab)
```

- `: > logs/zrok.log` truncates the log (`:` is the no-op builtin; the redirection does the work).
- `nohup ... &` starts zrok in the background immune to the terminal hang-up signal, so it survives the organizer logging out of SSH. stdout and stderr are appended to the log.
- `${ZROK_AS[@]+"${ZROK_AS[@]}"}` is the portable way to expand a possibly-empty array under `set -u`: older bash (4.3 and below) treats an empty array as unset and would abort on `"${ZROK_AS[@]}"`. The `+` form expands to nothing when the array is empty.
- `$!` is the PID of the last background job. When `ZROK_AS` is used, that PID belongs to `sudo`, not zrok; `kill` on sudo still works because sudo forwards the signal to its child.
- **URL parsing.** For up to 45 s the log is grepped. The second `grep -vE '^(https?://)?api\.'` drops zrok's API host (`api.<something>.zrok.io` appears in the log before the share address). Found → prefix `https://` if needed (zrok 2 prints a bare hostname under an `endpoints:` line) → `break`. If zrok has already died (`kill -0` fails) there is no point waiting; `break` early.
- The link is saved to `logs/zrok.url` for the dashboard.

```bash
# start.sh lines 145-152
      if [ -z "$ZROK_URL" ]; then
        if kill -0 "$(cat logs/zrok.pid)" 2>/dev/null; then
          ZROK_NOTE="zrok is running but printed no link yet. Last lines of logs/zrok.log:"
        else
          ZROK_NOTE="zrok exited. Last lines of logs/zrok.log:"
        fi
        ZROK_NOTE="$ZROK_NOTE"$'\n'"$(tail -n 15 logs/zrok.log | sed 's/^/     | /')"$'\n'"  Try it by hand to see the link:  $(basename "$ZROK_BIN") share public $PROXY_PORT"
      fi
```

No link after 45 s: distinguish "still running" (slow network, maybe will work) from "exited" (wrong token, name not created, port in use). Either way the last 15 log lines are embedded in the note, each prefixed with `     | `, plus a copy-pasteable manual command. The note is a multi-line string (`$'\n'` inserts newlines) printed by `warn` in the summary.

#### 5. Summary (lines 157–191)

```bash
# start.sh lines 161-168
# dashboard accounts (regenerated on every start; also in logs/credentials.txt)
CREDS="$($COMPOSE logs --no-log-prefix --tail=200 monitor 2>/dev/null | sed -n '/==== DASHBOARD LOGIN ====/,/=====================/p' | grep -E '^\s+(admin|user)\s' || true)"
if [ -n "$CREDS" ]; then
  printf '  \033[1;33mDashboard accounts (new on every start):\033[0m\n'
  echo "$CREDS" | sed 's/^/  /'
  echo "  (saved in logs/credentials.txt - give user_N accounts to co-organizers, keep admin for yourself)"
  echo
fi
```

**Credentials extraction.** `proxy/src/server.js` (`printCredentials`) logs a block on every start:

```
==================== DASHBOARD LOGIN ====================
  admin  admin_k3x     password: ...
  user   user_1        password: ...
=========================================================
```

- `logs --no-log-prefix --tail=200 monitor`: raw lines without the `ctf-watch |` prefix, last 200 lines of the `monitor` service.
- `sed -n '/A/,/B/p'` prints every line from one matching `A` to the next matching `B` inclusive. `A` is the header; `B` is 21 consecutive `=`. The header's runs are only 20 `=` long, so it does not match `B` itself; the 57-`=` footer does. If the container restarted several times within those 200 lines, every block is printed; the last one is current, and `logs/credentials.txt` (written with mode 0600 by the server) always holds only the current accounts.
- `grep -E '^\s+(admin|user)\s'` keeps the account lines (leading spaces, role, space). `|| true` because grep exits 1 on no match (e.g. the container crashed before printing).

```bash
# start.sh lines 169-177
echo "  Dashboard:                      http://${DASHBOARD_BIND:-127.0.0.1}:$DASHBOARD_PORT   (login required)"
if [ -n "${CTF_TARGET:-}" ]; then
  echo "  Proxy for students:             http://$PROXY_BIND:$PROXY_PORT  ->  $CTF_TARGET"
else
  printf '  Proxy for students:             http://%s:%s  ->  \033[1;33mnot connected yet: log in, open the CTFs tab, pick the CTF app\033[0m\n' "$PROXY_BIND" "$PROXY_PORT"
fi
echo "  Logs:                           $(pwd)/logs/"
```

The addresses are composed from the `.env` values. `CTF_TARGET` is optional; empty means the target is chosen in the dashboard, so the line says so. The printed proxy line uses the host-side `PROXY_BIND`; on Docker Desktop the override forces the container-side bind to `0.0.0.0` but the published port is still `127.0.0.1`, so the printed address is still right.

```bash
# start.sh lines 179-187
if [ -n "$ZROK_URL" ]; then
  printf '  \033[1;32mGIVE THIS LINK TO THE STUDENTS:\033[0m\n\n      %s\n\n' "$ZROK_URL"
  echo "  zrok is running in the background (log: logs/zrok.log). ./stop.sh stops it together with the monitor."
elif [ -n "$ZROK_NOTE" ]; then
  warn "$ZROK_NOTE"
else
  echo "  zrok auto-start is off (ZROK_AUTO=0). Point zrok at the proxy yourself:"
  echo "      zrok2 share public $PROXY_PORT        (old zrok:  zrok share public http://127.0.0.1:$PROXY_PORT)"
fi
```

Exactly one of three: the link, a problem note, or the "auto-start off" instructions (reached only when `ZROK_AUTO=0`, because every other path sets either `ZROK_URL` or `ZROK_NOTE`). Lines 189–190 end with the SSH port-forward recipe for a headless VM.

### `stop.sh`

```bash
# stop.sh lines 3-18
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
```

Same compose detection and Desktop override as `start.sh` — the override **must** match what was used for `up`, otherwise `down` would look for a differently-configured project and might not find the network to remove. Differences from `start.sh`:

- The sudo re-exec has no `sudo -n` probe, so it may prompt for a password interactively (acceptable for a stop).
- The `.env` parser is the reduced version: no whitespace trimming, no quote stripping. Only `PROXY_PORT` is consumed here, so that is harmless unless you quote that value.

```bash
# stop.sh lines 20-29
# stop the zrok share we started
if [ -f logs/zrok.pid ]; then
  PID="$(cat logs/zrok.pid)"
  if kill -0 "$PID" 2>/dev/null; then kill "$PID" 2>/dev/null || sudo kill "$PID" 2>/dev/null || true; echo "zrok share stopped."; fi
  rm -f logs/zrok.pid
fi
pkill -f "zrok2? share .*${PROXY_PORT:-8888}" 2>/dev/null || true
rm -f logs/zrok.url

$COMPOSE down --remove-orphans
```

- The PID from `logs/zrok.pid` is killed if alive. `sudo kill` is the fallback for the case where `start.sh` ran as root (so the pid belongs to root's `sudo` wrapper) but `stop.sh` runs as the normal user.
- `pkill -f "zrok2? share .*8888"` is a safety net: any zrok share whose command line mentions the proxy port after `share ` is killed, even one started by hand. The pattern `.*8888` has no boundary, so `18888` would match too; ports that are substrings of each other are unlikely in practice.
- `logs/zrok.url` is removed so the dashboard no longer shows a dead link.
- `down --remove-orphans` removes the container (and on Desktop the `ctfnet` network). The bind-mounted `logs/`, `data/`, `config/` are host directories and are untouched; the built image stays cached.

### `inspect.sh`

```bash
# inspect.sh lines 6-13
set -uo pipefail
cd "$(dirname "$0")"
OUT="inspect-report.txt"
exec > >(tee "$OUT") 2>&1

h() { echo; echo "================================================================"; echo "## $*"; echo "================================================================"; }

if ! docker info >/dev/null 2>&1 && [ "$(id -u)" -ne 0 ]; then exec sudo -E "$0" "$@"; fi
```

- Deliberately **no `-e`**: this is a survey, and a failing probe (no `ss`, no `docker exec`) must not stop the report.
- `exec > >(tee "$OUT") 2>&1` redirects the script's own stdout and stderr, for the rest of its life, into a process substitution running `tee`, which writes to the file and to the terminal at once. `inspect-report.txt` is listed in `.gitignore` because it contains hostnames and header values.
- `h` prints a banner. `## title` lines make the report readable as Markdown.
- The sudo re-exec comes **after** the `tee` redirect. The re-executed copy sets up its own `tee` whose stdout is the first `tee`'s pipe, so two `tee` processes write the same file. It works because nothing has been written yet and both copies write identical bytes at the same offsets, but if you modify this script, move line 13 above line 9.

```bash
# inspect.sh lines 15-30
h "System"
date -u; uname -a; echo; free -m 2>/dev/null | head -2
echo; echo "Docker: $(docker --version 2>&1)"; docker compose version 2>&1 | head -1

h "Running containers"
docker ps --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}'

h "Listening ports on the VM (ss -ltnp)"
ss -ltnp 2>/dev/null || netstat -ltnp 2>/dev/null || echo "(ss/netstat not available)"

h "zrok"
for z in zrok2 zrok; do command -v "$z" >/dev/null 2>&1 && { echo "$z: $(command -v "$z")"; "$z" version 2>&1 | head -3; }; done
command -v zrok2 >/dev/null 2>&1 || command -v zrok >/dev/null 2>&1 || echo "zrok2 / zrok binary not in PATH for this user"
echo; echo "zrok processes (shows which URL/port zrok currently shares):"
pgrep -af 'zrok2? ' || echo "(no zrok process running right now)"
echo; ls -la ~/.zrok ~/.zrok2 2>/dev/null | head || true
```

- `free -m | head -2`: memory in MiB, header plus the `Mem:` line (Linux only; silently absent elsewhere).
- `docker ps --format 'table ...'` prints a header row and the chosen Go-template columns.
- `ss -ltnp`: `-l` listening sockets only, `-t` TCP, `-n` numeric (no DNS/service lookups), `-p` owning process (needs root to show other users' processes, hence the sudo re-exec). `netstat` with the same letters is the legacy fallback.
- zrok section: path and version of each binary present; `pgrep -af 'zrok2? '` lists every zrok process with its full command line, which reveals which port is currently shared; the config directories are listed because their presence shows whether zrok was enabled for this user.

```bash
# inspect.sh lines 32-47
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
```

Every container except our own (`grep -v '^ctf-watch'` drops names starting with `ctf-watch`) is described with `docker inspect -f` Go templates:

- `{{index .Config.Labels "key"}}` reads a map entry whose key contains dots (plain `.Config.Labels.com.docker...` would not parse). The compose labels tell you where the CTF's compose file lives.
- `{{range $p, $_ := .Config.ExposedPorts}}` iterates a map; the keys are `port/proto` strings, the values are empty structs (hence `$_`).
- Published ports: `.NetworkSettings.Ports` maps `port/proto` to a list of `{HostIp, HostPort}` bindings; two nested `range`s print `HostIp:HostPort->port/proto`.
- Env: the template prints one `KEY=VALUE` per line; `while IFS='=' read -r k v` splits each at the **first** `=` (everything after it lands in `v`, the last variable). Values are printed only for names containing `PORT`, `HOST`, `URL`, `ENV`, `MODE` or `DEBUG`; others become `<hidden>`, so database passwords and flags never land in the report.

```bash
# inspect.sh lines 51-62
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
```

Each `docker exec "$c" sh -c '...'` runs a shell **inside** the CTF container in its working directory. Everything is read-only (`ls`, `head`, `grep`, `find`). Distroless images without `sh` make `docker exec` fail; the first one reports `(docker exec not possible)`, the others are silenced.

- Routes grep: `-r` recursive, `-E` extended regex, `-n` line numbers, `--include=*.ext` restricts file types. The alternation covers Express/Koa (`app.get(`), Flask (`@app.route`, `@bp.get`), Laravel (`Route::get`), Django (`path(`), raw PHP (`$_GET[`), Go (`HandleFunc(`) and Spring (`@GetMapping`). The whole `sh -c` body is single-quoted, so `\$_` reaches grep as `\$_`, which in ERE means a literal `$`. `grep -v node_modules | grep -v vendor` removes dependency noise, `head -150` caps the size.
- Auth hints: `-i` case-insensitive, `-l` print only file names.
- Seeds: `find -maxdepth 4` with the `-iname` alternatives grouped in escaped parentheses, excluding `node_modules`. These files tell you which user owns which object, which is what `config/ownership.json` needs.

```bash
# inspect.sh lines 65-76
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
```

- Port list: `docker ps --format '{{.Ports}}'` prints strings like `0.0.0.0:5000->5000/tcp`; `grep -oE ':[0-9]+->'` extracts `:5000->`; `tr -d ':>-'` deletes those three characters leaving `5000`; `sort -u` deduplicates.
- First curl: `-s` silent, `-m 5` five-second maximum, `-D -` dump response headers to stdout, `-o /tmp/ctfwatch_body.$$` write the body to a temp file named with the script's PID (`$$`). The `sed -E` keeps the cookie **name** but replaces its value with `<hidden>` (`\1` is the captured `Set-Cookie: name=` part; the trailing `I` flag is GNU sed's case-insensitive match). Cookie names are exactly what `identity.sessionCookies` in `rules.json` needs.
- Second curl fetches the body again and pulls out anything that looks like `href=`, `action=`, `src=`, `fetch(` or `url:` followed by a path. The odd `["'"'"']?` is the shell idiom for "a double or single quote": the single-quoted string is closed, `"'"` supplies a literal single quote, and the single-quoted string resumes.

Line 79 ends with the path of the report.

## Interactions

| Script | Reads | Writes | Processes / network |
|---|---|---|---|
| `start.sh` | `.env` (creates from `.env.example`), `docker-compose*.yml`, `logs/zrok.pid`, `logs/zrok.log`, container log of `monitor`; env: `ZROK_AUTO`, `ZROK_BIN`, `ZROK_RESERVED`, `PROXY_PORT`, `PROXY_BIND`, `DASHBOARD_PORT`, `DASHBOARD_BIND`, `CTF_TARGET`, `SUDO_USER` | `.env` (first run only), `logs/zrok.log`, `logs/zrok.pid`, `logs/zrok.url` | `docker compose up`, HTTP GET `127.0.0.1:$DASHBOARD_PORT/healthz`, `pgrep`/`pkill` of `zrok* share`, background `zrok2`/`zrok` process, possibly `sudo` re-exec |
| `stop.sh` | `.env`, `docker-compose*.yml`, `logs/zrok.pid` | removes `logs/zrok.pid`, `logs/zrok.url` | `kill`/`pkill` zrok, `docker compose down --remove-orphans` |
| `inspect.sh` | `$HOME`, `/opt`, `/srv` (find), every non-`ctf-watch` container (inspect + exec), HTTP GET on each published port | `inspect-report.txt`, temp `/tmp/ctfwatch_body.<pid>` (deleted) | `docker ps/inspect/exec`, `ss`/`netstat`, `curl`, `pgrep` |

Container-side counterparts: `proxy/src/server.js` writes the credentials block and `logs/credentials.txt`, and reads `logs/zrok.url` / `logs/zrok.log` for the CTFs tab; `proxy/src/dashboard.js` serves `/healthz`.

## Changing it safely

1. **Change the health-wait timeout** (slow VM, big first build): the `seq 1 30` at line 66 is the number of one-second attempts. The compose `healthcheck` in `docker-compose.yml` is independent of this loop.
2. **Support a third zrok CLI flavour** (or a different tunnel tool): add a `case` arm at lines 113–128 producing `ZROK_CMD`, and make sure its output contains a `*.zrok.io` host or adapt the regex at lines 93 and 136 (keep both in sync). The keep-existing check at line 92 relies on the process command line containing `share` and the port.
3. **Add a new `.env` setting**: add it to `.env.example` with a comment, to `docker-compose.yml` `environment:` with a `${VAR:-default}`, and read it in `proxy/src/server.js`. `load_env` exports every valid `KEY=value` automatically; nothing to change in the script unless the script itself uses the value.
4. **Run without zrok** (students on the LAN): set `ZROK_AUTO=0` and `PROXY_BIND=0.0.0.0` in `.env`; no code change needed.

Verify after any edit:

```bash
bash -n start.sh stop.sh inspect.sh          # syntax only, runs nothing
shellcheck start.sh                           # if installed: catches quoting/`set -u` mistakes
docker compose config --quiet                 # the compose files still parse
docker compose -f docker-compose.yml -f docker-compose.desktop.yml config --quiet
./start.sh && ./stop.sh                       # full round trip on a machine with Docker
```

## Exercises

1. **Trace `load_env`.** Create a scratch file with `A= "x y" `, `B=1=2`, `# C=3`, `bad key=4` and a CRLF line ending, then run `bash -c 'source <(sed -n "19,30p" start.sh); load_env scratch.env; declare -p A B; declare -p C 2>&1'`. Expect `A="x y"`, `B="1=2"`, and `C` undefined.
2. **Watch the keep-existing logic.** Start once, note the link, run `./start.sh` again without stopping. The second run must print `zrok share already running for port 8888 - keeping it` and the same link. Verify with `cat logs/zrok.url` and `pgrep -af 'zrok2? share'`.
3. **Simulate a dead dashboard.** In a scratch copy of the script, change `/healthz` to `/healthz-nope` on lines 67–68 (the dashboard answers 404 there, and `curl -f` treats that as failure). Run the copy: after 30 seconds it must print `Dashboard did not answer yet. Logs:` followed by up to 30 log lines and exit 1 (`echo $?`). The container is still running (`docker ps`); run `./stop.sh` and delete the copy.

## Quick reference

| Command / variable | Meaning |
|---|---|
| `./start.sh` | build + start + zrok + print accounts and link |
| `./start.sh -h` | print the two comment lines of the header |
| `./stop.sh` | stop zrok share and container; data kept |
| `./inspect.sh` | write `inspect-report.txt` |
| `ZROK_AUTO=1\|0` | start zrok automatically or not |
| `ZROK_BIN=/path` | explicit zrok binary |
| `ZROK_RESERVED=name` | fixed share name (zrok2 `create name`, zrok1 reserved share) |
| `logs/zrok.pid` | PID of the background share (or of its `sudo` wrapper) |
| `logs/zrok.log` | zrok's output; parsed for the link |
| `logs/zrok.url` | the link; read by the dashboard CTFs tab; removed by `stop.sh` |
| `logs/credentials.txt` | current dashboard accounts (mode 0600, written by the server) |
| `docker compose logs --tail=200 monitor` | where the credentials block is extracted from |
| `pgrep -af 'zrok2? share'` | list running shares with full command line |

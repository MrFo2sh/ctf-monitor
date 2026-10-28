# Docker packaging — `docker-compose.yml`, `docker-compose.desktop.yml`, `proxy/Dockerfile`, `.env.example`, `.gitignore`, `.gitattributes`

## Purpose

ctf-watch runs as one container, service `monitor`, built from `proxy/`. These files decide how that container is built, how it is wired to the VM's network, what settings reach the Node process as environment variables, and which host directories it shares. Two compose files exist because the networking that is right on the Linux VM (host networking) does not reach the browser on Docker Desktop; `start.sh` picks the override automatically (chapter 23).

`.env.example` is the documented list of settings; `.gitignore` and `.gitattributes` keep secrets and runtime files out of git and keep the shell scripts runnable when the repo is cloned on Windows.

## Walkthrough

### `docker-compose.yml`

```yaml
# docker-compose.yml lines 1-13
name: ctf-watch

# The monitor shares the VM's network (network_mode: host) so that:
#  - the proxy can reach the CTF container on 127.0.0.1:<port>
#  - the dashboard is bound to 127.0.0.1 by default (not reachable from outside / zrok)
# The mock playground (fake CTF app + fake students) runs inside this same container, from the dashboard.

services:
  monitor:
    build: ./proxy
    image: ctf-watch-monitor
    container_name: ctf-watch
    network_mode: host
```

- `name: ctf-watch` fixes the Compose **project name**. Without it the project is named after the directory, so a clone into `ctf-monitor/` (as the README shows) would produce different container/network/image names. A fixed name also means `docker compose` finds the same project from any clone path.
- `build: ./proxy` is the build context; the Dockerfile is `proxy/Dockerfile`. `image: ctf-watch-monitor` names the resulting image (the default would be `<project>-<service>`, the same string here, but being explicit makes `docker images` predictable).
- `container_name: ctf-watch` pins the container name. Consequences: at most one instance per Docker host; `proxy/src/ports.js` skips a container named `ctf-watch` when listing candidate CTF apps (so the monitor never offers itself as a target); `inspect.sh` skips names starting with `ctf-watch`.
- `network_mode: host` puts the process in the VM's own network namespace. There is no NAT and no `ports:` section: whatever `PROXY_BIND:PROXY_PORT` the Node process binds is bound on the VM itself. **Why host networking on Linux:**
  - the CTF app publishes a port on the VM (`0.0.0.0:5000->5000/tcp`); from the host namespace it is simply `http://127.0.0.1:5000`, so no network names, container IPs or DNS are involved and the organizer can also point the proxy at a non-Docker app;
  - `proxy/src/ports.js` reads `/proc/net/tcp` and `/proc/net/tcp6`; inside a host-network container those files list the **VM's** listening sockets, which is how the CTFs tab discovers ports;
  - `proxy/src/util.js` (`macFor`) runs `ip neigh show <ip>`, the VM's ARP table, to attach a MAC address to LAN players;
  - the dashboard bound to `127.0.0.1` is unreachable from the LAN and from zrok without any firewall rule; zrok itself (running on the VM) reaches the proxy on `127.0.0.1:8888`.

```yaml
# docker-compose.yml lines 14-27
    environment:
      # optional: the CTF app is normally picked in the dashboard (CTFs tab). Set it to skip that step.
      CTF_TARGET: ${CTF_TARGET:-}
      CTF_NAME: ${CTF_NAME:-}
      PROXY_PORT: ${PROXY_PORT:-8888}
      PROXY_BIND: ${PROXY_BIND:-127.0.0.1}
      DASHBOARD_PORT: ${DASHBOARD_PORT:-8080}
      DASHBOARD_BIND: ${DASHBOARD_BIND:-127.0.0.1}
      DASHBOARD_USERS: ${DASHBOARD_USERS:-3}
      SESSION_TTL_HOURS: ${SESSION_TTL_HOURS:-12}
      LOG_LEVEL: ${LOG_LEVEL:-info}
      CONFIG_DIR: /app/config
      LOG_DIR: /app/logs
      DATA_DIR: /app/data
```

`${VAR:-default}` is Compose interpolation, evaluated on the **host** when the file is parsed. Compose looks the variable up in the shell environment first, then in the `.env` file next to the compose file. `start.sh` exports the `.env` values before calling Compose, so both sources agree. The `:-` form substitutes the default when the variable is unset **or empty**; `CTF_TARGET=` in `.env` therefore yields an empty string, which `server.js` treats as "not set".

| Variable | Read in | Effect |
|---|---|---|
| `CTF_TARGET` | `server.js` | Upstream URL. Applied only when no target has been chosen in the dashboard yet (`if (!target && CTF_TARGET)`), after `validateTarget()`; an invalid value is logged and ignored. |
| `CTF_NAME` | `server.js` → `db.openCtf()` | Name of the CTF record; empty gives `ctf-<date>`. A new name on restart opens a new record. |
| `PROXY_PORT`, `PROXY_BIND` | `server.js` | Where the student-facing proxy listens. |
| `DASHBOARD_PORT`, `DASHBOARD_BIND` | `server.js` | Where the dashboard listens. |
| `DASHBOARD_USERS` | `server.js` → `auth.generateAccounts(n)` | Number of `user_N` viewer accounts, in addition to the admin. |
| `SESSION_TTL_HOURS` | `server.js` → `Auth({ sessionTtlMs })` | Dashboard session inactivity timeout. |
| `LOG_LEVEL` | `util.js` `log()` | `info` or `debug`; anything else behaves as `info`. |
| `CONFIG_DIR`, `LOG_DIR`, `DATA_DIR` | `server.js` and modules | Fixed to the mount points below; not configurable from `.env`. |

```yaml
# docker-compose.yml lines 28-40
    volumes:
      - ./config:/app/config:ro
      - ./logs:/app/logs
      - ./data:/app/data
      # read-only, so the CTFs tab can list the other containers and their ports
      - /var/run/docker.sock:/var/run/docker.sock:ro
    restart: unless-stopped
    mem_limit: 256m
    healthcheck:
      test: ["CMD", "wget", "-qO-", "http://127.0.0.1:${DASHBOARD_PORT:-8080}/healthz"]
      interval: 15s
      timeout: 3s
      retries: 3
```

- **Volumes** are bind mounts of repo directories (`docker compose config` shows `create_host_path: true`, so Docker creates a missing directory, owned by root on Linux):
  - `./config` read-only: `rules.json` and `ownership.json`. The monitor watches and reloads them live; `:ro` guarantees the container never edits them.
  - `./logs` read-write: `events-<date>.jsonl`, `credentials.txt` (written by the server with mode 0600), and `zrok.log` / `zrok.pid` / `zrok.url` written by `start.sh` on the host and read by the server (`studentLink()`).
  - `./data` read-write: the SQLite database `ctf-watch.db` plus its `-wal` and `-shm` files (`db.js` sets `journal_mode = WAL`). Deleting the directory while the container is stopped resets all history and players.
  - **The Docker socket.** `ports.js` sends `GET /containers/json` and `GET /containers/<id>/json` through `http.request({ socketPath: '/var/run/docker.sock' })` to list other containers, their published ports and bridge IPs. If the socket is absent inside the container, `dockerContainers()` resolves to nothing and only `/proc/net/tcp` discovery remains. The `:ro` flag makes the *mount* read-only, which prevents replacing the socket file; it does **not** restrict what the daemon will do for a client connected to it. Anything with that socket is root-equivalent on the VM, so treat `ports.js` as security-sensitive code and keep it to `GET` requests.
- `restart: unless-stopped`: the container comes back after a crash and after a VM reboot, but stays down after `docker stop` / `compose down`. Because dashboard accounts are regenerated on every process start, a crash-restart invalidates the passwords you were given; `logs/credentials.txt` always has the current ones.
- `mem_limit: 256m` is a hard cgroup memory limit (Compose renders it as `268435456`). Exceeding it gets the Node process OOM-killed, after which the restart policy restarts it. The in-memory structures (last 2000 requests for the Requests tab, per-student windows) are sized with this in mind; raise the limit before raising those.
- `healthcheck`: the `CMD` form runs the command directly (no shell). `wget` is BusyBox's inside `node:24-alpine`. `-q` quiet, `-O-` body to stdout. `${DASHBOARD_PORT:-8080}` is interpolated by Compose, so the check follows `.env`. Every 15 s, 3 s timeout, three consecutive failures mark the container `unhealthy` in `docker ps`. Docker does not restart an unhealthy container on its own; the status is informational (and `start.sh` has its own wait loop on the same URL).

### `docker-compose.desktop.yml`

```yaml
# docker-compose.desktop.yml lines 8-24
networks:
  ctfnet:

services:
  monitor:
    network_mode: !reset null
    networks: [ctfnet]
    ports:
      - "127.0.0.1:${DASHBOARD_PORT:-8080}:${DASHBOARD_PORT:-8080}"
      - "127.0.0.1:${PROXY_PORT:-8888}:${PROXY_PORT:-8888}"
    environment:
      DASHBOARD_BIND: 0.0.0.0
      PROXY_BIND: 0.0.0.0
      # discovery lists containers by their network ip, and probes common ports on your machine via host.docker.internal
      DISCOVERY_MODE: bridge
    extra_hosts:
      - "host.docker.internal:host-gateway"
```

**Why a bridge network on Docker Desktop.** On Windows/macOS the Docker engine runs inside a hidden Linux VM. `network_mode: host` would bind the ports on *that VM's* loopback, where your browser cannot reach them. The portable answer is an ordinary bridge network plus explicit port publishing, which Desktop forwards to the laptop's `127.0.0.1`.

When Compose is given two `-f` files, it merges them: scalar keys in the later file win, maps (`environment`) merge key by key, and lists (`ports`, `volumes`) are appended. Line by line:

- `networks: ctfnet:` declares a user-defined bridge network (empty body = default driver). Its real name is `ctf-watch_ctfnet` (project prefix).
- `network_mode: !reset null` — **the `!reset` trick.** A plain override cannot *remove* a key; `network_mode: ""` would still be a value, and Compose rejects a service that has both `network_mode` and `networks`. `!reset` is a YAML tag Compose understands (v2.24 and later) that deletes the inherited key from the merged model. The `null` after it is a placeholder; any value is ignored. You can confirm with `docker compose -f docker-compose.yml -f docker-compose.desktop.yml config`: `network_mode` is absent and `networks: ctfnet:` is present.
- `ports:` publish the same number on both sides, so the addresses `start.sh` prints stay valid. The leading `127.0.0.1:` is the host IP of the binding: only the laptop itself can connect, nobody on the LAN. The compose rendering shows `host_ip: 127.0.0.1`, `published`, `target`.
- `DASHBOARD_BIND` / `PROXY_BIND: 0.0.0.0` overrides the `127.0.0.1` defaults from the base file. Inside a bridge container, published traffic arrives on the container's own interface IP (`172.x.y.z`), so a socket bound to the container's `127.0.0.1` would never see it. Binding to all interfaces *inside* while publishing on `127.0.0.1` *outside* gives the same exposure as on Linux.
- `DISCOVERY_MODE: bridge` switches `ports.js discover()`: `/proc/net/tcp` now shows only the container's own sockets, so instead the code lists other containers by their bridge IPs and exposed ports, and probes a fixed list of common development ports (`DESKTOP_HOST_PORTS`: 80, 3000, 5000, 8080, …) on `host.docker.internal`, i.e. on your laptop.
- `extra_hosts: host.docker.internal:host-gateway` adds an `/etc/hosts` entry pointing at the Docker host's gateway address. Desktop already provides that name, but the special value `host-gateway` also works on a Linux engine, so the override is usable there for testing.

Everything else (volumes, restart, memory limit, healthcheck) is inherited from the base file. The `./logs` mount still carries `zrok.url`, and the healthcheck still hits `127.0.0.1` inside the container, which works because the process now listens on `0.0.0.0`.

### `proxy/Dockerfile`

```dockerfile
# proxy/Dockerfile lines 1-12
FROM node:24-alpine
WORKDIR /app
ENV NODE_ENV=production
# "ip" (iproute2) is used for best-effort MAC lookup of LAN players
RUN apk add --no-cache iproute2
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund && npm cache clean --force
COPY src ./src
COPY public ./public
COPY mock ./mock
# config, logs and data are mounted by docker-compose
CMD ["node", "src/server.js"]
```

- `node:24-alpine`: `package.json` requires Node ≥ 23.4 because `db.js` uses the built-in `node:sqlite` module (no native dependency to compile, which is why an Alpine/musl image is fine). Alpine keeps the image small.
- `ENV NODE_ENV=production` is seen by npm (skips dev dependencies) and by the app at runtime.
- `apk add --no-cache iproute2` installs the `ip` command for `util.js macFor()` → `ip neigh show <ip>`. `--no-cache` avoids keeping the package index in the layer. It is only useful on Linux with host networking (the VM's neighbour table) and only for private addresses; on Desktop it simply returns nothing.
- `COPY package.json ./` **before** the source, then `npm install`: Docker caches layers in order, so dependencies are reinstalled only when `package.json` changes, not on every code edit. `--omit=dev` (no dev deps; there are none anyway), `--no-audit --no-fund` (quiet, no network calls to the advisory service). `npm cache clean --force` removes the download cache from the layer. Note that `package-lock.json` is not copied, so this is `npm install`, not `npm ci`; the result is still deterministic because the only dependency is pinned exactly (`"ws": "8.18.0"`). The lock file in the repo is slightly stale (`engines >=18`) and unused by the build.
- `COPY src`, `public`, `mock`: the server, the dashboard HTML, and the Playground scripts (`mock-ctf.js`, `simulate.js` are spawned by `playground.js` with `process.execPath`, so they must be in the image). `test/` is not copied. `config/`, `logs/`, `data/` arrive as mounts.
- `CMD` in exec (JSON) form: `node` is PID 1 and receives `SIGTERM` directly on `compose down`, so the server can flush the database. There is no `USER` instruction: the process runs as root inside the container, which is what lets it open `/var/run/docker.sock`. There is no `EXPOSE`: it would be meaningless with host networking, and the Desktop override's `ports:` does not need it.

### `.env.example`

`start.sh` copies this file to `.env` on the first run; `.env` is git-ignored. Every value is documented inline; what each one does:

```ini
# .env.example lines 8-22 (comments removed)
CTF_TARGET=
PROXY_PORT=8888
PROXY_BIND=127.0.0.1
DASHBOARD_PORT=8080
DASHBOARD_BIND=127.0.0.1
```

| Variable | Default | Used by | Meaning |
|---|---|---|---|
| `CTF_TARGET` | empty | container | Skip the CTFs tab and proxy straight to this URL (`http://` only, port required or defaulted to 80 by `validateTarget`). Only applied when no target was already chosen in the dashboard. |
| `PROXY_PORT` | `8888` | script + container | Student-facing port. zrok must point here, not at the CTF. |
| `PROXY_BIND` | `127.0.0.1` | script + container | `127.0.0.1` when zrok runs on the VM; `0.0.0.0` only if the tunnel runs elsewhere or students are on the LAN. Overridden to `0.0.0.0` inside the container on Desktop. |
| `DASHBOARD_PORT` | `8080` | script + container | Dashboard port; also the health-check target. |
| `DASHBOARD_BIND` | `127.0.0.1` | script + container | `0.0.0.0` makes the (login-protected) dashboard reachable on the LAN; never expose it via zrok. |
| `DASHBOARD_USERS` | `3` | container | Number of `user_N` accounts generated per start. |
| `SESSION_TTL_HOURS` | `12` | container | Idle timeout of dashboard sessions. |
| `CTF_NAME` | empty | container | Name of the CTF record; empty → `ctf-<date>`. |
| `ZROK_AUTO` | `1` | script only | `0` disables the automatic share. |
| `ZROK_RESERVED` | empty | script only | Fixed share name (`zrok2 create name <name>` first; or a zrok 1 reserved share). |
| `ZROK_BIN` | empty | script only | Full path to the zrok binary if not on `PATH`. |
| `LOG_LEVEL` | `info` | container | `debug` for verbose server logs. |

The three `ZROK_*` variables are never passed to the container; they only steer `start.sh`. Conversely `CONFIG_DIR`, `LOG_DIR`, `DATA_DIR` and `DISCOVERY_MODE` are set by the compose files and are not meant to be in `.env`.

### `.gitignore`

```gitignore
# .gitignore lines 1-9
# runtime logs (can get big) - never commit
logs/*
!logs/.gitkeep

# database (players, requests, alerts, accounts)
data/
# local settings
.env
inspect-report.txt
```

- `logs/*` ignores the contents but `!logs/.gitkeep` re-includes the empty marker, so the directory exists right after `git clone`. That matters because Docker bind-mounts it: if the directory did not exist, Docker would create it as root, and `start.sh` (running as a normal user) could not write `zrok.log` there.
- `data/` is ignored entirely (there is no `.gitkeep`; Docker creates it on first start). It holds the database, including hashed dashboard accounts and every recorded request.
- `.env` holds local settings (and, if someone sets it, a `CTF_TARGET` for a private VM); `inspect-report.txt` contains hostnames, headers and file listings of the CTF machine. Neither belongs in a public repo.
- Lines 11–18: `node_modules/`, npm debug logs, editor and OS files.

### `.gitattributes`

```gitattributes
# .gitattributes lines 1-7
* text=auto
*.sh text eol=lf
*.js text eol=lf
*.json text eol=lf
*.yml text eol=lf
*.md text eol=lf
Dockerfile text eol=lf
```

- `* text=auto`: git decides per file whether it is text and, if so, stores it with LF line endings in the repository.
- The explicit `eol=lf` rules force LF **in the working tree** too, overriding a Windows user's `core.autocrlf=true`. Without this, `start.sh` cloned on Windows would get CRLF endings and fail with `/usr/bin/env: 'bash\r': No such file or directory`; the JS/JSON/YAML files are covered so the Docker build context is byte-identical on every platform (better layer-cache hits, no CR characters in `rules.json`).
- `.env.example` matches no rule beyond `text=auto`, so it may be checked out with CRLF on Windows; this is why `load_env` in `start.sh` strips a trailing `\r` from every line.

## Interactions

| File | Reads | Writes / produces | Containers, networks, ports |
|---|---|---|---|
| `docker-compose.yml` | shell env and `.env` for `${VAR}`; `proxy/` build context; host dirs `config/`, `logs/`, `data/`; `/var/run/docker.sock` | image `ctf-watch-monitor`, container `ctf-watch` | host network; the process binds `PROXY_BIND:PROXY_PORT` and `DASHBOARD_BIND:DASHBOARD_PORT` on the VM |
| `docker-compose.desktop.yml` | same `.env` values | network `ctf-watch_ctfnet` | publishes `127.0.0.1:8080` and `127.0.0.1:8888` on the laptop; `host.docker.internal` resolvable inside |
| `proxy/Dockerfile` | `proxy/package.json`, `src/`, `public/`, `mock/` | image layers | — |
| `.env.example` | — | copied to `.env` by `start.sh` | — |
| `.gitignore` | — | keeps `logs/*`, `data/`, `.env`, `inspect-report.txt`, `node_modules/` out of git | — |
| `.gitattributes` | — | LF endings for scripts, code, YAML, Dockerfile | — |

## Changing it safely

1. **Add an environment variable for the server.** Add `NEW_VAR: ${NEW_VAR:-default}` under `environment:` in `docker-compose.yml`, document it in `.env.example`, read it with `env('NEW_VAR', default)` in `proxy/src/server.js`. If Desktop needs a different value, add it to the override's `environment:` map (maps merge by key).
2. **Add a dependency.** `npm install <pkg>@<exact>` in `proxy/`, commit `package.json` (pin the version; the build does not use the lock file). The `COPY package.json` layer invalidates and `npm install` reruns at the next `./start.sh`.
3. **Expose the dashboard on the LAN on Desktop.** Change the host IP in the override's `ports:` entry from `127.0.0.1:` to `0.0.0.0:` (or drop it). On Linux set `DASHBOARD_BIND=0.0.0.0` in `.env` instead; no file change.
4. **Raise the memory limit** (large event, many students): `mem_limit` in `docker-compose.yml`. Check `docker stats ctf-watch` during the Playground load test (`proxy/mock/loadtest.js`) before and after.

Verify:

```bash
docker compose config --quiet                                              # base file parses
docker compose -f docker-compose.yml -f docker-compose.desktop.yml config  # merged model: no network_mode, ports present
docker build -t ctf-watch-monitor ./proxy                                  # image builds
./start.sh && docker inspect -f '{{.State.Health.Status}}' ctf-watch       # "healthy" after ~15 s
./stop.sh
```

## Exercises

1. **See `!reset` at work.** Comment out line 13 of `docker-compose.desktop.yml` and run `docker compose -f docker-compose.yml -f docker-compose.desktop.yml config`. Compose must refuse with an error about `network_mode` and `networks` being mutually exclusive. Restore the line; the command must print a model without `network_mode`.
2. **Prove the socket mount is what feeds container discovery.** With the stack running, call `curl -s -b cookies.txt http://127.0.0.1:8080/api/targets` (log in first, see chapter 26) and note the `candidates` with `"source":"docker"`. Then temporarily remove the `docker.sock` line, `./start.sh` again, and repeat: those entries disappear while the `/proc/net/tcp` ones remain. Restore the line.
3. **Check the layer cache.** Run `./start.sh` twice while touching only `proxy/src/server.js` between runs. The second build output must show `CACHED` for the `npm install` step and rebuild only from `COPY src ./src` onward.

## Quick reference

| Item | Value |
|---|---|
| Project / container / image | `ctf-watch` / `ctf-watch` / `ctf-watch-monitor` |
| Networking, Linux | `network_mode: host` — no port publishing |
| Networking, Desktop | bridge `ctf-watch_ctfnet`, ports `127.0.0.1:8080`, `127.0.0.1:8888`, `DISCOVERY_MODE=bridge` |
| Mounts | `config/` (ro), `logs/`, `data/`, `/var/run/docker.sock` (ro) |
| Limits | `mem_limit: 256m`; healthcheck `wget /healthz` every 15 s, 3 retries |
| Restart policy | `unless-stopped` (accounts regenerate on each start) |
| Base image | `node:24-alpine` + `iproute2`; runs `node src/server.js` as root |
| Compose merge | `docker compose -f docker-compose.yml -f docker-compose.desktop.yml …` |
| Render merged config | `docker compose -f … -f … config` |
| Git hygiene | `.env`, `data/`, `logs/*`, `inspect-report.txt` ignored; `*.sh` forced to LF |

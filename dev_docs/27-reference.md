# Reference cards

## Environment variables (read in `proxy/src/server.js`, set by `docker-compose*.yml` from `.env`)

| Variable | Default | Meaning |
|---|---|---|
| `CTF_TARGET` | empty | optional preset upstream `http://host:port`; otherwise picked in the dashboard and remembered in the database |
| `CTF_NAME` | empty → `ctf-<date>` | name of the CTF record opened at boot (an open record with another name is closed first) |
| `PROXY_PORT` / `PROXY_BIND` | `8888` / `127.0.0.1` | where students (via zrok) reach the proxy |
| `TRUSTED_PROXIES` | `127.0.0.1,::1,::ffff:127.0.0.1` | peers whose `X-Forwarded-For` is believed; `*` = everyone (Docker Desktop rehearsal override sets this) |
| `DASHBOARD_PORT` / `DASHBOARD_BIND` | `8080` / `127.0.0.1` | the dashboard; never shared through zrok |
| `DASHBOARD_USERS` | `3` | number of `user_N` viewer accounts generated at boot |
| `SESSION_TTL_HOURS` | `12` | idle lifetime of a dashboard session |
| `CREDENTIALS_FILE` | `1` | `0` = do not write `logs/credentials.txt` (accounts on stdout only) |
| `LOG_LEVEL` | `info` | `debug` prints identity/ownership learning |
| `NAME_GATE_COOKIE` / `NAME_GATE_TITLE` | `ctfw_name` / `Welcome to the CTF` | cookie name; default title (the Gate tab overrides it) |
| `CONFIG_DIR`, `LOG_DIR`, `DATA_DIR`, `DB_FILE` | `/app/config`, `/app/logs`, `/app/data`, `<DATA_DIR>/ctf-watch.db` | paths inside the container |
| `DISCOVERY_MODE` | `host` | `bridge` on Docker Desktop (set by the override file) |
| `DOCKER_SOCK` | `/var/run/docker.sock` | Docker API socket for container discovery |

## Persisted keys in the `kv` table (JSON values)

| key | module | content |
|---|---|---|
| `proxy_target` | server.js | current upstream URL or null |
| `decoy` | decoy.js | `{ target, students: { name: { since, by, reason } } }` |
| `gate_config` | server.js / namegate.js | the Gate tab configuration |
| `gate_profiles` | server.js | raw name → answers to the extra gate fields |
| `gate_queue` | approvals.js | raw name → `{ name, profile, ip, ua, firstSeen, status, decidedAt, by }` |
| `admin_state` | admin.js | `{ blocked, aliases, revoked }` |
| `dashboard_blocked_ips` | auth.js | ip → `{ reason, ts }` |

## WebSocket messages (`dashboard.js` → `app.html`)

| type | when | payload |
|---|---|---|
| `snapshot` | on connect, after a reset/rename/replay start | `{ events[≤500], alerts[≤150], stats }` |
| `event` | every proxied request | the event object (see `server.js` `onEvent`) |
| `alert` | when `store.alertFor` or `store.emitAlert` produces one | `{ ts, level, type, student, ip, msg, ack, … }` |
| `stats` | every second while a client is connected | `{ stats, replay, target, mock: { app, sim }, gate, queue: counts }` |
| `queue` | every arrival / decision | `{ counts, items }` |
| `decoy` | target or list change | `{ target, students }` |

## Event flags

`idor-attempt`, `idor-success`, `enumeration`, `burst-errors`, `blocked`, `decoy`, `attack:<class>` where class ∈ `sqli nosqli xss ssti lfi cmdi shell xxe ssrf redirect deser scanner`.

## Alert levels (`store.js` `ALERT_LEVEL`)

critical: `idor-success`, `admin-login-conflict`, shell attacks · high: `idor-attempt`, most injection classes · medium: `enumeration`, xss, nosqli, scanner · low: `burst-errors`, `blocked`, redirect · info: `new-student`, `queue`, `decoy`, target switches.

## Query language (`query.js`)

Fields `ts student raw ip method path endpoint id status size latency severity flag attack owner ua source ctf player`; operators `= != > >= < <= ~ !~ in`; logic `AND OR NOT ( )`; times `"-10m" "-2h" "-1d"` or ISO. Scoped to the active (or replayed) CTF unless `ctf` is mentioned.

## Commands

| What | Command |
|---|---|
| unit tests | `cd proxy && npm test` |
| syntax check a file | `node --check proxy/src/<file>.js` · `bash -n start.sh` |
| validate compose | `docker compose -f docker-compose.yml -f docker-compose.desktop.yml config --quiet` |
| run the monitor without Docker (dev) | `cd proxy && npm install && CTF_TARGET=http://127.0.0.1:3999 node src/server.js` |
| run the mock app by hand | `PORT=3999 node proxy/mock/mock-ctf.js` |
| run fake students by hand | `TARGET=http://127.0.0.1:8888 node proxy/mock/simulate.js` |
| load test (never the real CTF) | `node proxy/mock/loadtest.js --seconds 10 --concurrency 50` |
| container logs | `docker compose logs -f monitor` |
| database shell | `sqlite3 data/ctf-watch.db` |

# CTF Watch

A small live SOC dashboard for web CTFs. It sits between zrok and the CTF app, watches every
request, and shows who is doing what: IDOR attempts and successes, enumeration, brute force,
web exploitation attempts (SQL injection, XSS, template injection, path traversal, shells,
scanners...), per student, as it happens.

```
students  →  zrok  →  CTF Watch (proxy)  →  CTF app container
                            ↓
                   dashboard (login required)
```

Nothing in the CTF is changed. The CTF keeps working exactly as before.

---

## 1. Before you start

On the Ubuntu VM where the CTF container runs you need:

- **Docker** with the Compose plugin (`docker --version`). Missing? `curl -fsSL https://get.docker.com | sudo sh`
- **zrok2** (or zrok), already working.
- **git**.

## 2. Start it

```bash
git clone <this repo url>
cd ctf-monitor
./start.sh
```

The script builds and starts the monitor, starts the zrok share pointing at the proxy, and prints:

```
  ctf-watch is running.

  Dashboard accounts (new on every start):
    admin  admin_k3x     password: ...
    user   user_1        password: ...
    user   user_2        password: ...

  Dashboard:   http://127.0.0.1:8080   (login required)

  GIVE THIS LINK TO THE STUDENTS:
      https://xxxxxxxx.shares.zrok.io
```

If it says it cannot talk to Docker: `sudo ./start.sh`.

The dashboard comes up **before** any CTF is attached. Until you pick one, students opening the
link see "The CTF is not open yet".

### Pick the CTF app (CTFs tab)

Log in as admin; you land on the **CTFs** tab. The "CTF app behind the proxy" card shows the
**student link** (the zrok address, with a copy button) and lists every
listening port on the VM and every Docker container with its published ports or bridge IP, and
shows what each one answers (HTTP status, page title, server header). Press **▶ Use** on the
right one. Switching is immediate for the students, and you are asked whether to start a new CTF
record for it. You can switch between challenges at any time the same way, type an address by
hand, or **⏏ Disconnect** to close the game. The choice is remembered across restarts. To skip
the step entirely, set `CTF_TARGET=http://127.0.0.1:<port>` in `.env`.

### Docker Desktop (Windows / macOS laptop)

`start.sh` detects Docker Desktop and adds `docker-compose.desktop.yml` automatically: the
containers get their own bridge network and the dashboard and proxy are published on
`127.0.0.1` of your machine. The CTFs tab then lists other containers by name and anything
answering on the usual development ports of your machine (`host.docker.internal`). Everything else
is identical. This is handy to try the demo on a laptop; the event itself runs on the Linux VM.

## 3. Log in to the dashboard

Open http://127.0.0.1:8080 on the VM, or from your laptop:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<vm-ip>      # then open http://127.0.0.1:8080
```

Accounts are **generated fresh every time the monitor starts** and printed by `start.sh` (also
saved in `logs/credentials.txt`, readable only by you). Keep `admin_xxx` for yourself; give the
`user_N` accounts to co-organizers. Users can watch everything and acknowledge alerts; only the
admin can block, rename, import, replay or open a new CTF. `DASHBOARD_USERS` in `.env` sets how
many user accounts are made.

**One session per account.** If someone logs in to an account that is already in use somewhere
else, the login is refused, a **critical alert** is raised naming the IP (and the CTF player
behind it, when known), and that IP is blocked, both from the dashboard and from the CTF. The
admin can unblock it on the CTFs tab.

The dashboard is bound to `127.0.0.1` by default. Because it has a login you may set
`DASHBOARD_BIND=0.0.0.0` in `.env` to reach it over your LAN. Never share it through zrok.

## 4. Stop it

```bash
./stop.sh
```

This also stops the zrok share. Everything recorded stays in `data/` and `logs/`.

## 5. Try it first (demo mode)

```bash
./start.sh --demo
```

A fake CTF and nine fake students play: honest ones, an enumerator, a data thief, a noisy one,
an anonymous scanner and one throwing injection payloads. Stop with `./stop.sh`.

---

## The dashboard

Five tabs. Every tab has a ↗ button that opens it in its own browser tab.

### Live

One row per student; every request is a dot, newest on the left (squares are POST/PUT). Hover a
dot for details.

| Color | Meaning |
|---|---|
| Blue (faint) | Normal request |
| Yellow | 401 / 403 / 404 |
| Grey | Server error (5xx) |
| Purple | Enumeration or a burst of errors |
| Orange, pulsing | IDOR attempt, or a web attack payload |
| Red, glowing | 🚨 Successful IDOR |

Under each name: the IDs they are walking through (`orders: 1041 → 1042 → 1043`) or the attack
class just seen. The right column has the searchable student list (green dot = active in the last
two minutes), the selected student's card with IP addresses and actions, the alert feed, live
stats (req/s, status codes, top endpoints, attack classes) and the leaderboard. The selected
student's card also lists every user agent they used with counts and, when there are any, the
attack classes seen from them with counts. The bottom panel
is the request log with its own search; ⤢ makes it taller, ↗ opens it in a new tab.

### Alerts

Every alert with a **criticality level**:

| Level | What |
|---|---|
| critical | successful IDOR, dashboard login conflict, reverse / web shell attempt |
| high | IDOR attempt, SQL / command / template injection, path traversal, SSRF, XXE, deserialization |
| medium | enumeration, XSS, NoSQL injection, scanner user agent |
| low | bursts of errors, blocked requests, open-redirect probes |
| info | new student seen |

Filter by level (click the chips), text, or unacknowledged only. ✓ acknowledges one alert,
"Acknowledge all" clears the badge in the tab bar.

### Students

The table of everyone seen, searchable by name, IP or app username. Click a row (or ↗) for the
**detail view**: profile, every IP address used, every **user agent** with request counts, the
**web exploitation attempts** grouped by class with samples (classes with zero attempts are not
shown), the player's history across past CTFs, and all of their requests.

### Query

Search the recorded requests with a small query language:

```
student = "alice" AND status >= 400
flag = "idor-success"
attack ~ "sqli" OR attack ~ "xss"
(path ~ "/api/orders" OR endpoint = "orders") AND NOT student = "alice"
status in (401, 403) AND ts > "-15m"
ua ~ "curl" AND size > 500
```

Fields: `ts student raw ip method path endpoint id status size latency severity flag attack owner ua source ctf player`.
Operators: `= != > >= < <= ~ (contains) !~ in`, logic `AND OR NOT ( )`, times like `"-10m"`,
`"-2h"`, `"-1d"` or an ISO date. While a CTF is running, queries only see that CTF unless you pick
another one in the drop-down or write `ctf = <id>`. Results can be downloaded as CSV.

### CTFs

Every event ever recorded, with ⬇ export (a JSON file with requests, alerts and player identities).
Admin only: ■ Stop CTF (closes the record, disconnects the students, clears the live view; picking
a CTF app again opens a new record), ＋ New CTF (closes the current one and opens the next),
⬆ import an export file, ▶ replay any past or imported CTF into the Live tab at 1x to max speed,
to review a past event or rehearse with a realistic feed. While a replay runs, the Alerts tab, the
student detail pages and the Query tab read from the replayed CTF. Also here: blocked players,
blocked dashboard IPs, rename requests.

## Organizer actions

Select a student (Live tab list, or click their name on a row):

- ⛔ **Block**: every request from that student (and their IP, unless several students share it)
  gets an "Access blocked" page from the proxy. ✅ Unblock reverses it.
- 🔁 **Ask to rename** (needs the name gate): their browser shows the name page again with "The
  organizer asks you to enter your real name"; other requests get a short refusal until they do.
  History moves to the new name.
- ✎ **Rename**: rename the row yourself.

All of this is remembered in the database.

## Identifying students

In this order: a JWT in a cookie or `Authorization` header; a session cookie learned when the app
login succeeds; the IP zrok reports. Anonymous rows (`ip:1.2.3.4`, `sess-ab12cd34`) are merged into
the student's row as soon as they are identified.

**Name gate** (`NAME_GATE=1` in `.env`): the first time a student opens the CTF in a browser they
are asked for their name. The name is kept in a signed cookie and used for their row. Requests
without the cookie from the same IP (curl, scripts) are matched to that name, unless two students
share the IP. Only browser page loads are ever asked; tools are never blocked.

**Players across CTFs.** Each student is linked to a player record by name, app username, IP and,
when they are on the same LAN as the VM, MAC address. The next CTF recognises them: the student
detail view shows their history.

## Changing the detection rules

One file: **`config/rules.json`**, commented inside, reloaded live. Cookie and JWT names, login
and "who am I" URLs, the endpoints with object IDs, ownership rules, thresholds, masking, ignored
paths. `./inspect.sh` writes `inspect-report.txt` with everything needed to tune it for the real
CTF app (containers, ports, routes, cookie names); send it to whoever maintains the rules.

## Files and data

```
start.sh / stop.sh / inspect.sh
docker-compose.yml          monitor (+ demo app and fake students)
config/rules.json           detection rules
data/ctf-watch.db           SQLite database: CTFs, players, requests, alerts, accounts (not in git)
logs/events-<date>.jsonl    one JSON line per request
logs/credentials.txt        this start's dashboard accounts (mode 600)
proxy/                      Node.js source (one dependency: ws); `npm test` runs the unit tests
demo/                       fake CTF, simulator, load test
```

## Performance and limits

The monitor is one Node.js process. Requests are proxied as streams, detection is a fixed number
of regular expressions per request, the live state lives in bounded in-memory ring buffers, and
database writes are batched in transactions (SQLite in WAL mode). Measured on a laptop with the
demo stack and 50 concurrent clients: about 10,000 requests per second through the proxy, median
4 ms and 99th percentile 13 ms of total latency, no errors, the monitor at about 100 MB while
being hammered (40 to 60 MB in normal use) and 22 MB of database per 100,000 requests. Measure
your own VM with:

```bash
node demo/loadtest.js --seconds 10 --concurrency 50     # against ./start.sh --demo only
```

No Redis and no load balancer are used, on purpose: for one CTF of up to a few hundred students
a single process is faster than anything distributed, and there is nothing to keep in sync. If a
future event needs more, the proxy and the dashboard are separate servers already and the
database is a single file, so the next step is simply running the proxy on more cores behind the
same database.

## Security notes

- Dashboard: login with scrypt-hashed passwords, one session per account, HttpOnly + SameSite
  cookies, CSRF header on every write, rate-limited logins, IP blocking, strict security headers.
- Query language is compiled to parameterised SQL with a field whitelist. No raw SQL is accepted.
- Passwords, tokens and secrets in CTF traffic are masked before storage and display.
- The CTF container is never modified. Memory cap: 256 MB (`docker-compose.yml`).

## Troubleshooting

| Problem | What to do |
|---|---|
| `Docker is installed but not reachable` | `sudo ./start.sh` |
| Lost the dashboard password | `cat logs/credentials.txt`, or restart (`./start.sh`) for new accounts |
| Locked out after a login conflict | from the VM (localhost is never blocked): CTFs tab → blocked dashboard IPs → unblock |
| Students get `502 Bad Gateway` | the proxy cannot reach the CTF app: check `CTF_TARGET` in `.env` |
| Everyone shows as `ip:...` | the app's login URL or cookie name differs: run `./inspect.sh`, adjust `config/rules.json` |
| See what the monitor is doing | `docker compose logs -f monitor` |

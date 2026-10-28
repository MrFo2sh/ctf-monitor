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
container gets its own bridge network and the dashboard and proxy are published on
`127.0.0.1` of your machine. The CTFs tab then lists other containers by name and anything
answering on the usual development ports of your machine (`host.docker.internal`). Everything else
is identical. This is handy to try the Playground on a laptop; the event itself runs on the Linux VM.

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

## 5. Try it first (Playground tab)

Start normally, log in as admin and open the **Playground** tab. "▶ Start everything" launches a
fake CTF app inside the monitor, points the proxy at it in a fresh CTF record named `playground`,
and starts nine fake students: honest ones, an enumerator, a data thief, a noisy one, an
anonymous scanner and one throwing injection payloads. Watch the Live tab fill up, then
"■ Stop everything". The tab also lets you run the pieces separately: start or stop the mock app
on a port of your choice, point the proxy at it, and start the fake students with your own mix
of personas, pace, number of rounds, looping, or a different destination. A "MOCK TRAFFIC" badge
shows in the header while fake students are playing.

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
is the request log with its own search; ⤢ makes it taller, ↗ opens the **Requests** tab in a new
window.

### Requests

The full live request log on the whole screen (the last 2000 requests, with search, a student
filter, pause and clear). Click a request: the right column shows everything about it (student,
IP, method, full path, endpoint and object id, owner, status, size, latency, flags, the attack
payloads found and where, the user agent, the masked request body) and the student's card with
the same actions as on the Live tab.

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

The query box behaves like a SIEM search bar: syntax highlighting, live linting (the faulty part
is underlined and the message says what was expected), and autocompletion that follows what you
are typing: field names with a description, the operators valid for that field, then values taken
from the data (students, endpoints, flags, attack classes, methods, status codes, time shortcuts),
then `AND` / `OR`. Arrow keys to pick, Tab or Enter to accept, Esc to close, Ctrl+Space to reopen,
Ctrl+Enter to run. Recent queries are kept per browser.

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

## The decoy

In the CTFs tab, "🪤 Decoy app behind the proxy" takes a second address (any scanned port, the
Playground's mock app, or a typed one). Students you put on the decoy list are routed to that app
instead of the real CTF, transparently: same link, same cookies, nothing to notice. Send a student
there from their card (Live or Requests tab), from the list on the CTFs card, or straight from the
Queue with "to decoy" instead of Approve. Their requests carry a `decoy` flag (queryable with
`flag = "decoy"`), their row shows 🪤, and "Back to real CTF" undoes it. Removing the decoy app
sends everyone back.

## Organizer actions

Select a student (Live tab list, or click their name on a row):

- ⛔ **Block**: every request from that student (and their IP, unless several students share it)
  gets an "Access blocked" page from the proxy. ✅ Unblock reverses it.
- 🔁 **Ask to rename** (needs the gate on): their browser shows the gate form again with "The
  organizer asks you to enter your real name"; other requests get a short refusal until they do.
  History moves to the new name.
- ✎ **Rename**: rename the row yourself.

All of this is remembered in the database.

## Identifying students

In this order: a JWT in a cookie or `Authorization` header; a session cookie learned when the app
login succeeds; the IP zrok reports. Anonymous rows (`ip:1.2.3.4`, `sess-ab12cd34`) are merged into
the student's row as soon as they are identified.

**The gate** (Gate tab, on by default): the first time a student opens the CTF in a browser they
get a form. The username field is always there and becomes their identity; you can add any other
fields (student id, email, team as a choice list, and so on) with a label, a type and a required
flag, change the title and intro text, and see a live preview. Answers are kept per student and
shown on their card and detail page; an id or email also helps recognise the same person in a
future CTF. A password-type field is never stored. The name goes into a signed cookie and is used
for their row.

Two switches, both on by default:

- **Strict**: nothing reaches the CTF without the form. A browser gets the form; curl, scripts
  and crawlers get a refusal that names the required fields ("You must set your Your name,
  Student ID first"). Tools must send the browser's cookie. Switched off, only browser page loads
  are asked and tools pass through (requests from the same IP are then matched to the name).
- **Queue**: after the form, the student sees a waiting page and the **Queue** tab shows them with
  their answers, IP and user agent. Tick students and "Approve selected" / "Block selected", or
  approve and block one by one. The student's page continues by itself the instant they are
  approved (the waiting page keeps an event stream open to the proxy). Blocking from the queue
  also blocks them at the proxy. A yellow counter on the tab shows how many are waiting, and the
  tab updates live as students arrive.

The gate can be switched off in the tab, in which case students are identified by the app's login
or their IP.

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
docker-compose.yml          the monitor (docker-compose.desktop.yml: Docker Desktop override)
config/rules.json           detection rules
data/ctf-watch.db           SQLite database: CTFs, players, requests, alerts, accounts (not in git)
logs/events-<date>.jsonl    one JSON line per request
logs/credentials.txt        this start's dashboard accounts (mode 600)
proxy/src                   Node.js source (one dependency: ws); `npm test` runs the unit tests
proxy/mock                  the Playground's fake CTF app, fake students, and the load test
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
node proxy/mock/loadtest.js --seconds 10 --concurrency 50     # with the Playground mock app behind the proxy, never the real CTF
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

## Documentation

- [`docs/`](docs/README.md): the operator course for the SOC team and organizers who use the
  dashboard: setting up the day, admitting students, reading the live view, triage, investigating,
  actions, queries, replay, cheat sheet.
- [`dev_docs/`](dev_docs/README.md): the developer course: the architecture map and one chapter per
  source file, walking through the code with exercises.
- [`ISSUES.md`](ISSUES.md): known issues to address, with where they are and the intended fix.

## Troubleshooting

| Problem | What to do |
|---|---|
| `Docker is installed but not reachable` | `sudo ./start.sh` |
| Lost the dashboard password | `cat logs/credentials.txt`, or restart (`./start.sh`) for new accounts |
| Locked out after a login conflict | from the VM (localhost is never blocked): CTFs tab → blocked dashboard IPs → unblock |
| Students get `502 Bad Gateway` | the proxy cannot reach the CTF app: check `CTF_TARGET` in `.env` |
| Everyone shows as `ip:...` | the app's login URL or cookie name differs: run `./inspect.sh`, adjust `config/rules.json` |
| See what the monitor is doing | `docker compose logs -f monitor` |

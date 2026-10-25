# CTF Watch

A small live dashboard that shows what the students are doing in the CTF, as it happens.
It sits between zrok and the CTF app, watches every request, and highlights IDOR attempts.

```
students  →  zrok  →  CTF Watch (proxy)  →  CTF app container
                            ↓
                   dashboard (only on this VM)
```

Nothing in the CTF is changed. The CTF keeps working exactly as before.

---

## 1. Before you start

You need, on the Ubuntu VM where the CTF container runs:

- **Docker** (with the Compose plugin). Check with `docker --version`.
  If it is missing: `curl -fsSL https://get.docker.com | sudo sh`
- **zrok**, already working (you are already using it for the CTF).
- **git** to download this project.

## 2. Start it

```bash
git clone <this repo url>
cd ctf-watch
./start.sh
```

The first time, the script looks at your running containers, finds the port of the CTF
app and asks you to confirm it. Then it builds and starts the monitor. When it is ready it prints
something like:

```
  ctf-watch is running.

  Dashboard (this machine only):  http://127.0.0.1:8080
  Proxy for students:             http://127.0.0.1:8888  ->  http://127.0.0.1:5000

  GIVE THIS LINK TO THE STUDENTS:

      https://abcd1234.share.zrok.io
```

If the script says it cannot talk to Docker, run it with `sudo ./start.sh`.

## 3. zrok

You do not need to run zrok yourself. `start.sh` finds `zrok2` (or the older `zrok`), starts
the share for you pointing at the proxy port, and prints the link to give to the students. It runs
in the background and `./stop.sh` stops it. The command it runs is simply:

```bash
zrok2 share public --headless 8888
```

If a zrok share is already running when you start (for example the old one that pointed straight
at the CTF), the script shows it and asks whether to stop it. Say yes: students must go through
the proxy, otherwise the dashboard sees nothing.

Two settings in `.env`, if you need them:

- `ZROK_RESERVED=<name>` to keep the same link every time. With zrok2, create the name once with
  `zrok2 create name <name>`; the script then shares as `public:<name>`.
- `ZROK_AUTO=0` if you prefer to run zrok yourself. Then run:
  ```bash
  zrok2 share public 8888
  ```

Students will not notice any difference. Everything they do is the same as before.

## 4. Open the dashboard

On the VM, open a browser at **http://127.0.0.1:8080**.

The dashboard is only reachable from the VM itself. It is **never** visible through zrok, and
students cannot reach it.

If the VM has no desktop or browser, open a tunnel from your own laptop and view it there:

```bash
ssh -L 8080:127.0.0.1:8080 <user>@<vm-ip>
```

then open http://127.0.0.1:8080 on the laptop.

## 5. Stop it

```bash
./stop.sh
```

This also stops the zrok share, so students cannot reach the CTF until you run `./start.sh` again
(or share the CTF port directly with `zrok2 share public <ctf-port>`).

## 6. Try it first (demo mode)

To see the dashboard working before the real event, with a fake CTF and fake students:

```bash
./start.sh --demo
```

Open http://127.0.0.1:8080 and watch. The fake students include honest players, one who
enumerates IDs, one who steals another user's data, and one who makes a lot of noise. Stop with
`./stop.sh`. Demo mode does not touch the real CTF.

---

## What you see on the dashboard

**One row per student.** Every request appears as a dot on the student's row, newest on the
left. Squares are POST/PUT requests, circles are GET. Hover a dot for the details.

| Color | Meaning |
|---|---|
| Blue (faint) | Normal request, everything fine |
| Yellow | The app said no: 401 / 403 / 404 |
| Grey | The app crashed on that request (5xx) |
| Purple | **Enumeration**: the student is trying many different IDs quickly, or is spamming errors |
| Orange, pulsing | **IDOR attempt**: the student asked for an object that is not theirs |
| Red, glowing | 🚨 **Successful IDOR**: they asked for something that is not theirs AND the app gave it to them |

Under each student's name you see the IDs they are walking through, for example
`orders: 1041 → 1042 → 1043`, so you can literally watch them enumerate.

**Alert feed** (top right): the important moments, newest first.

- 🚨 successful IDOR (red)
- ⚠️ IDOR attempt (orange)
- 🔁 enumeration (purple)
- 💥 burst of errors / brute force (yellow)

**Live stats**: requests per second, how many answers were OK / redirect / client error /
server error, and the busiest endpoints.

**Leaderboard**: who got the first successful IDOR, who pulled off the most, who enumerated the
most IDs, who produced the most failed requests.

**Controls** (top right): filter to one student, change the row order, and ⏸ Pause.
While paused nothing moves; press ▶ Resume and everything that happened in between is added.

**Recent requests** (bottom): a plain table of the latest requests. Click its title to collapse.

Passwords, tokens and other secrets are replaced with `***` everywhere: in the dashboard and in the
log files. You see *who* did *what*, never their credentials.

## Log files

Every request is appended to `logs/events-<date>.jsonl` (one JSON line per request). You can keep
these after the event. They are not committed to git.

## How students are identified

In this order:

1. A JWT in a cookie or `Authorization` header (the username inside it).
2. A session cookie. When a student logs in, the monitor remembers
   "this session cookie belongs to *alice*". Before that, the session shows as `sess-xxxx`.
3. If neither exists, the IP address zrok reports (`ip:1.2.3.4`).

## Optional: ask students for their name

If the app's usernames are not helpful (random handles, or everyone shares one test account),
turn on the **name gate**. Edit `.env`:

```
NAME_GATE=1
```

and apply it without touching the zrok link:

```bash
sudo docker compose up -d monitor
```

The first time a student opens the CTF link in a browser they see a
small page: "Before you start, tell us who you are." After typing a name they land on the CTF as
normal and never see the page again (the name is kept in a cookie for 30 days). On the dashboard
that name is used for the student's row, with the app username shown next to it.

Only normal browser page loads are asked. Scripts, `curl`, Burp and the app's own API calls are
never blocked, so the CTF keeps working for all tools. A student who clears cookies is simply asked
again.

That also means a student can get around the page: by staying on a CTF page that was open before
you enabled it (no new page load), or by using `curl` or a script without the browser cookie.
If you want everyone named, no exceptions, add to `.env`:

```
NAME_GATE_STRICT=1
```

and apply with `sudo docker compose up -d monitor`. Now every request without a name cookie is
refused with a short message telling the student to open the CTF in the browser and enter a name.
Burp still works (it sends the browser's cookies). `curl` and scripts must send the `ctfw_name`
cookie copied from the browser's developer tools.

## Changing the detection rules

Everything lives in one file: **`config/rules.json`**. It is commented inside. You can change:

- cookie / JWT names, the login URL, the "who am I" URL
- the endpoints that contain object IDs and where the ID is (path, query string, body)
- how ownership is decided, or a fixed list in `config/ownership.json`
- the thresholds: how many IDs count as enumeration, how many errors count as a burst
- which field names are masked
- which paths are ignored (static files)

Save the file and the monitor picks it up within a second. No restart needed.

To tune these rules for the real CTF app, run the read-only helper on the VM and send the
result to whoever maintains this project:

```bash
./inspect.sh          # writes inspect-report.txt
```

It lists containers, ports, the current zrok process, routes found in the app source, cookie
names and seed files. It never changes anything.

## Troubleshooting

| Problem | What to do |
|---|---|
| `Docker is not installed` | `curl -fsSL https://get.docker.com \| sudo sh`, then log out and in |
| `Docker is installed but not reachable` | `sudo ./start.sh` |
| Dashboard page is empty | Is zrok pointing at the proxy port (8888)? See step 3 |
| Students get `502 Bad Gateway` | The proxy cannot reach the CTF app. Check the port in `.env` (`CTF_TARGET=...`), then `./start.sh` again |
| Port 8888 or 8080 is already used | Edit `.env`, change `PROXY_PORT` / `DASHBOARD_PORT`, run `./start.sh` again, point zrok at the new proxy port |
| Everyone shows as `ip:127.0.0.1` | Students are not logging in through a recognised login URL, or the cookie name is different. Run `./inspect.sh` and adjust `config/rules.json` |
| See what the monitor is doing | `docker compose logs -f monitor` |

## Security notes

- The dashboard and its WebSocket are bound to `127.0.0.1` inside the VM's network namespace.
  They are not published on any other address and are not part of the zrok share.
- The proxy itself also listens on `127.0.0.1` by default, which is enough when zrok runs on
  the same VM. Set `PROXY_BIND=0.0.0.0` in `.env` only if zrok runs on another machine.
- The CTF container, its image and its code are never modified.
- Memory: the whole thing uses roughly 40 to 80 MB. There is a hard limit of 200 MB in
  `docker-compose.yml`.

## What is inside

```
start.sh / stop.sh      start and stop everything
inspect.sh              read-only report about the CTF setup, for tuning the rules
docker-compose.yml      the monitor (+ the demo app and fake students, demo profile)
config/rules.json       detection rules - the file to edit
config/ownership.json   optional fixed "who owns which ID" map
proxy/                  the Node.js proxy, detector and dashboard (one dependency: ws)
demo/                   fake CTF app and the fake-student simulator
logs/                   JSONL request logs
```

Open source, MIT licensed. Dependencies: Node.js, the `ws` WebSocket library, the `node:20-alpine`
Docker image.

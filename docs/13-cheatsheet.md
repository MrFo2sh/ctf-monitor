# 13. Cheat sheet

**Start / stop (on the VM)**
`./start.sh` prints accounts + student link · `./stop.sh` stops everything · accounts also in `logs/credentials.txt`

**Dashboard** http://127.0.0.1:8080 on the VM · from a laptop `ssh -L 8080:127.0.0.1:8080 user@vm`

**First login**: CTFs tab → ▶ Use on the challenge → copy the 🔗 student link → Gate tab, check the form → Queue tab, approve students as they arrive

**Colors**: blue ok · yellow 4xx · grey 5xx · purple enumeration / bursts · orange IDOR attempt or attack · red glowing 🚨 successful IDOR

**Alert levels**: critical (success, login conflict, shell) · high (attempt, injections) · medium (enumeration, xss, scanner) · low (bursts, blocked) · info (bookkeeping)

**Student actions** (select on Live, or click a request on Requests): 📄 Details · ⛔ Block / ✅ Unblock · 🔁 Ask to rename · ✎ Rename · 🪤 Send to decoy / ↩ Back

**Queue**: tick → Approve selected / Block selected · per row Approve, to decoy, Block, back to queue

**Gate switches**: enabled · strict (no tools without the form) · queue (wait for approval)

**Query starters**
`flag = "idor-success"` · `student = "X" AND ts > "-10m"` · `owner = "alice" AND NOT student = "alice"` · `attack ~ "sqli"` · `ua ~ "curl"` · `status >= 500`

**Lifecycle** (CTFs tab): ▶ Use switches the app · ■ Stop CTF disconnects everyone · ＋ New CTF starts a fresh record · ⬇ export · ▶ replay · ⬆ import

**Badges**: red number on Alerts = open alerts · yellow number on Queue = waiting · "off" on Gate · MOCK TRAFFIC / REPLAY in the header = not real traffic

**Never**: share the dashboard through zrok · run fake students against the real challenge · restart the monitor mid-event without a reason (accounts change)

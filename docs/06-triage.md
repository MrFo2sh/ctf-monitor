# 6. Triage: alerts and what to do

The Alerts tab lists every alert with a level. Click the level chips to filter, tick
"unacknowledged only" to see what is still open, ✓ to acknowledge one, "Acknowledge all" to clear
the badge. Acknowledging changes nothing for the student; it is your own bookkeeping.

| Level | Alert | What it means | What to do |
|---|---|---|---|
| **critical** | successful IDOR | a student got another student's data from the app | in a CTF this is the goal: note who was first (leaderboard), check it was earned (lesson 7); in a training lab where this is forbidden, act (lesson 8) |
| **critical** | dashboard login conflict | someone tried to log in to a dashboard account that is already in use; the IP is now blocked from the dashboard and from the CTF | find out who: the alert names the CTF player behind that IP when known; change nothing else until you know whether it is a colleague's mistake or a student who found a password |
| **critical** | web attack: shell | a payload typical of a reverse shell or web shell upload | look at the request (Requests tab); if your challenge does not include that, it is out of scope: talk to the student or block |
| **high** | IDOR attempt | they asked for something not theirs and the app refused | expected in an IDOR CTF; no action unless the rules say so |
| **high** | web attack: injection, traversal, SSRF, XXE… | an attack payload against the app | depends on scope; look at the sample in the alert text |
| **medium** | enumeration | many different ids in a short window | normal recon; worth watching if it turns into successes |
| **medium** | web attack: XSS, NoSQL, scanner | lighter payloads or a scanning tool's user agent | scanning the challenge with sqlmap or nikto is usually out of scope: a word is often enough |
| **low** | burst of errors | lots of 401/403/404 in seconds | noise, or brute force; watch the student's row |
| **low** | blocked request | a blocked student is still trying | nothing; the proxy already answered |
| **info** | new student, queue, decoy, target switch | bookkeeping | nothing |

Rules of thumb:

- Triage by student, not by alert. One student produces many alerts; open their card and detail
  page once and decide once.
- A successful IDOR right after an enumeration is the classic pattern and the interesting one.
- A successful IDOR by someone who never enumerated and never attempted before is either very good
  or has help: look at the request and the time.
- Many alerts from one IP under several names is worth a look at the Queue (same IP, several
  entries) and the student cards (IP lists).
- Ignore your own traffic: your test visit from the setup day shows up like everyone else.

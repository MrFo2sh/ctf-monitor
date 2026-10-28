# 3. The dashboard, tab by tab

The header shows, left to right: a green dot (connected), the tabs, live counters (requests per
second, total requests, students, open alerts), the current CTF name, the address students reach
(`→ host:port` in green, or "no CTF" in yellow), and your account with Logout. Every tab has a ↗
button that opens it alone in a new browser tab, useful on a second screen.

| Tab | What it is for | Lesson |
|---|---|---|
| **Live** | one row per student with their requests animating in, the ID sequences they walk through, attack badges; the right column has the student list, the selected student's card and actions, the alert feed, live stats and the leaderboard; the bottom panel is the recent request log | 5 |
| **Requests** | the full live request log on the whole screen; click a request for its content and the student's card | 7 |
| **Alerts** | every alert with its level, filters, acknowledge | 6 |
| **Students** | the table of everyone seen; click one for the detail page (requests, user agents, attack classes, IPs, history across events) | 7 |
| **Query** | search the recorded requests with a small language, export the results | 9 |
| **CTFs** | the student link, which app is behind the proxy, the decoy, the list of events with export / replay / import, blocked lists, your session | 10, 11 |
| **Queue** | students waiting for approval, approve or block them | 4 |
| **Gate** | design the form students fill, switches for strict mode and queue, live preview | 4 |
| **Playground** | a fake challenge and fake students for rehearsal | 12 |

Badges on the tabs: a red number on **Alerts** is the count of unacknowledged alerts, a yellow
number on **Queue** is how many students are waiting, a yellow "off" on **Gate** means the gate is
switched off, a purple dot on **Playground** means fake traffic is running. In the header, a
"MOCK TRAFFIC" badge appears while fake students play and a "REPLAY" badge while a past event is
being replayed; both mean what you see is not the real event.

Roles: **admin** can do everything. **user** sees everything and can acknowledge alerts but cannot
block, rename, approve, change the gate, switch the app or import.

The page keeps itself up to date over a live connection. If the monitor is restarted, the page
reloads itself and you log in again.

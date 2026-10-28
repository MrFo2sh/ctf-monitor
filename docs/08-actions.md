# 8. Actions: block, rename, decoy, dashboard intruders

All actions are admin-only and take effect immediately. They are on the selected student's card
(Live tab and Requests tab) and some in the Queue and CTFs tabs.

## ⛔ Block / ✅ Unblock

Every request from the student gets an "Access blocked" page from the proxy; the CTF app never
sees them again. Their IP is blocked too, unless several students share it. The row dims and shows
BLOCKED; their further attempts show as `blocked` requests. Unblock reverses it. The CTFs tab lists
everyone blocked.

Use it for: someone attacking out of scope after a warning, a hostile unknown, a duplicate account.

## ✎ Rename

Changes the name on the dashboard only. History, alerts and the leaderboard follow the new name.
Use it to fix a typo or to replace a handle with a real name you know.

## 🔁 Ask to rename

Rejects the name the student typed on the gate: their browser shows the form again with a message
from the organizer, and their other requests are refused until they answer. The rejected name
cannot be reused. When they answer, their history moves to the new name. Lesson 4 has the details.

## 🪤 Send to decoy / ↩ Back to real CTF

Routes the student to the decoy app instead of the real challenge. Same link, same cookies,
nothing for them to notice; what they see is whatever the decoy app shows. Their requests carry a
`decoy` flag and their row shows 🪤.

Setting it up (CTFs tab, "Decoy app behind the proxy"): pick an address from the scan, type one,
or use the Playground's mock app, and press 🪤 decoy. The card lists who is on the decoy and lets
you remove them; "No decoy" sends everyone back. In the Queue, "to decoy" approves a student
straight onto it.

Use it for: a student you want to keep busy without feeding them the real flags, an automated
scanner you want to study without risk to the challenge, or simply for fun with the person who
brute-forces the login for the fifth time. Do not tell them.

## Dashboard intruders

If a student finds a dashboard password, they cannot use it while the owner is logged in: the
second login is refused, a critical alert says which IP tried and which CTF player sits behind it,
and that IP is blocked from both the dashboard and the CTF. To lift it: CTFs tab, "Blocked", the
"Dashboard IPs" list, unblock. If an organizer was logged out and the intruder got in first, the
owner's own login is the one refused: restart the monitor to regenerate every account.

## Everyone at once

- **Stop CTF** (CTFs tab) disconnects everyone: students see "The CTF is not open yet". Lesson 10.
- Switching the gate off lets everyone in without the form; switching strict off lets tools through.

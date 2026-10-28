# 10. Switching challenges, stopping, new CTF

Everything here is on the CTFs tab and is admin-only.

## One event, one record

A "CTF record" is one event's worth of requests, alerts and students. The header shows its name.
Everything the tabs show belongs to the current record; past records stay in the database for
search, export and replay.

## Switching to another challenge

"CTF app behind the proxy" → ▶ Use on another address. The switch is immediate for the students:
same link, now a different app. If requests were already recorded you are asked whether to start a
new record for the new challenge (recommended when it is a different game; decline when it is the
same challenge restarted or moved).

## ■ Stop CTF

Closes the record, disconnects the students (they see "The CTF is not open yet") and clears the
live view. The data stays. Use it at the end of the event, or as an emergency stop. Picking an
app again opens a new record automatically.

## ＋ New CTF

Closes the current record and opens the next one under the name you give, without touching the
app behind the proxy. Use it between two rounds of the same challenge, so each round has its own
leaderboard and alerts.

## What persists across records and restarts

- Students' gate answers, the queue decisions, blocks, renames, the decoy list, the gate design,
  which app is behind the proxy.
- Players: the same person at the next event is recognised by name, id, email, app username or IP,
  and their history shows on the detail page.
- The dashboard accounts do **not** persist across a restart of the monitor: they are regenerated
  and printed again.

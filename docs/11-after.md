# 11. After the event: export, replay, review

## Export

CTFs tab, the Events list, ⬇ export .json on the event. One file with every request, every alert
and the player identities. Keep it with the event's records; it is also what Import takes.

## Review on the dashboard

The record is still there: the Alerts tab, the Students tab and the Query tab can be pointed at it
(the Query tab's drop-down, or `ctf = <number>`). The leaderboard and the live view, however, only
show the current record; to see the event move again, replay it.

## Replay

CTFs tab, Events, ▶ replay with a speed (1x is real time, 10x fits an hour into six minutes, max
races through). The Live tab plays the event back as if it were happening: rows appear, dots
animate, alerts fire. While a replayed event is loaded, the Alerts tab, the student pages and the
Query tab read that event too, so you can click through it exactly as you would have on the day.
A REPLAY badge in the header says what you are looking at. Nothing is written during a replay.
Stop CTF or New CTF ends it and returns to live.

Replay is also the way to **train a new team member**: import an export from a past event, replay
it at 5x, and let them triage.

## Import

CTFs tab, ⬆ Import an export file. The event appears in the list marked "imported" and can be
replayed or searched. Imports never touch the current event.

## Suggested debrief

1. Replay at high speed with the team, pausing on each critical alert.
2. Query `flag = "idor-success"` for the order of first bloods, `attack ~ ""` for out-of-scope
   behaviour worth a word with the student.
3. From the Students tab, open the top three rows of the leaderboard and read their sequences.
4. Export, and archive the file with the student list.

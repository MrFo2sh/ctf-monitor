# 5. Reading the live view

## Rows

One row per student. Each request is a dot that appears on the left and pushes the older ones
right; squares are POST/PUT (they sent data), circles are GET. Hover a dot for the request.

| Color | Meaning |
|---|---|
| faint blue | normal request, fine |
| yellow | the app refused: 401, 403 or 404 |
| grey | the app broke: 5xx |
| purple | enumeration (many ids quickly) or a burst of errors |
| orange, pulsing | IDOR attempt, or an attack payload |
| red, glowing, row flashes | 🚨 successful IDOR |

Under the name: `23 req · 5 attempts · 1 🚨` (counts become `1.2k` past a thousand). Under the
dots: the ID sequence on the endpoint they are working, for example `orders: 1041 → 1042 → 1043`
with "enumerating (12 ids)" and "not theirs (bob)" tags, and on the right one badge per attack class
seen from that student with its count: `sqli 3 · xss 1`.

Row order: **activity** (most recent first), **threat** (successes, then attempts), or **name**.
⏸ Pause freezes the view; ▶ Resume adds everything that happened meanwhile.

## The right column

- **Students**: the searchable list of everyone, with a green dot for anyone active in the last two
  minutes. Click a name to select; the rows, alerts and log filter to that student.
- **Selected student**: the card. Identity (how they were identified, app username, user id,
  player number), first and last seen, counts, their gate answers (🪪), queue state, routing
  (🪤 if on the decoy), every IP they used with counts, every user agent with counts, and attack
  classes with counts (only the ones with hits). The action buttons are explained in lesson 8.
- **Alert feed**: the latest alerts with their level, newest first.
- **Live stats**: requests per second over the last minute, the split of status codes, the busiest
  endpoints, the attack classes seen overall.
- **Leaderboard**: first successful IDOR, most successful IDORs, most ids enumerated, most failed
  requests, most attack attempts.

## The request log (bottom)

The latest requests as a table with its own search (path, id, status, flag, student). Click the
title to collapse, ⤢ to make it taller, ↗ to open the full log as the Requests tab.

## How "theirs" and "not theirs" is decided

The tool needs to know who owns object #1043 to call a request an IDOR. Three sources, in order:

1. a fixed list the technical owner gave it (`config/ownership.json`), if any;
2. the student's own user id: `/api/users/1004` requested by the student whose id is 1004 is theirs;
3. learning: the first student who quietly reads an object (not while enumerating) is taken as its
   owner. Anyone else reading it afterwards is an attempt; if the app answers with data, a success.

So the first minutes of an event, while students browse their own things, teach the tool who owns
what. A student who starts enumerating at second one may be credited with objects that are not
theirs; the detail page and the query tab let you check, and the technical owner can fix the rules.

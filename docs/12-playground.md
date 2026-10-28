# 12. Rehearsing with the Playground

The Playground tab gives you a fake challenge and fake students, so the team can see the dashboard
move before a real event. Nothing in it is started unless you press a button, and it ends with the
monitor.

- **▶ Start everything**: starts the mock app, points the proxy at it in a fresh record named
  `playground`, and starts the fake students. Go to the Live tab and watch for a minute.
- **■ Stop everything** ends the fake traffic and the mock app. The proxy still points at the
  stopped mock until you pick the real challenge again on the CTFs tab.
- The two cards let you run the pieces separately and tune the students: how many honest players,
  which attackers (carol enumerates ids, dave steals a specific profile, eve produces 404 bursts,
  frank scans without logging in, mallory throws injection payloads), the pace, the number of
  rounds, looping.

What to practise:

1. Select a student from the list and read their card.
2. Find carol's first successful IDOR in the Alerts tab and acknowledge it.
3. Open mallory's detail page and read the attack classes.
4. Block eve, unblock her.
5. Run `flag = "idor-success"` in the Query tab.

Two cautions. The fake students do not fill the gate form, so with **strict** on they are refused:
switch strict off for the rehearsal, or they will all show as refused requests. And never start the
fake students while the proxy points at the real challenge during an event; they would play against
it.

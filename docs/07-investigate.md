# 7. Investigating one student

Three places, from quick to deep.

## The card (Live tab)

Select the student. The card answers: how were they identified, which app account do they use,
which IPs and browsers, how many requests and failures, how many IDOR attempts and successes, which
attack classes and how many times, what they answered on the gate, are they waiting, approved,
blocked, or on the decoy.

## The detail page (📄 Details ↗, or the Students tab)

A full page for the student:

- **Profile** with the same identity facts and the gate answers.
- **IP addresses** with counts and first/last time.
- **User agents** with counts: a browser plus `python-requests` or `curl` tells you they scripted;
  `sqlmap` or `nikto` tells you they scanned.
- **Known player across CTFs**: if the same person was seen at a previous event (same name, id,
  email, app username or IP), their history there.
- **Web exploitation attempts**, grouped by class, each with the request, where the payload was
  (URL, body, user agent) and the matched sample. Classes with zero hits are not shown.
- **All requests**, newest first, up to 5000: time, IP, method, path, object id, status, size,
  latency, flags.

## The Requests tab

The full live log of everyone. Filter by the student's name in the search box, click a request and
the right column shows everything about it: the full path, the endpoint and object id, who owns that
object and whether it was theirs, status, size, latency, the flags, every attack payload found and
where, the user agent, the ID sequence, and the request body with secrets masked. Below that, the
student's card with the same actions as on Live.

## Questions this answers

- *Did they earn the flag?* Look at the sequence of requests before the success: enumeration then a
  hit is legitimate play; a direct hit on an object id that is not guessable may mean a shared answer.
- *Are two "students" the same person?* Same IP, same browser, alternating activity, same gate
  answers. The Queue tab also shows several entries from one IP.
- *Is a script running?* Dozens of requests per second from one row, a non-browser user agent,
  perfectly regular timing in the log.
- *What did they actually send?* The request body on the Requests tab, with passwords and tokens
  already replaced by `***`.

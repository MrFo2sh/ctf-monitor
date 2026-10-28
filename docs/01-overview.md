# 1. What it is and how it sees the students

## The one idea

Students never talk to the CTF app directly. They talk to CTF Watch, which forwards everything to
the app and back without changing it, and keeps a copy of what happened:

```
student  →  zrok link  →  CTF Watch  →  the CTF app
                              ↓
                         the dashboard (only you)
```

Because every request passes through it, CTF Watch knows **who** asked for **what**, **when**, and
**what the app answered**. The dashboard is a live reading of that stream, plus a memory of it in a
database for searching and for reviewing afterwards.

The CTF app itself is never modified. If CTF Watch is stopped, the students lose the link until it
is started again or zrok is pointed back at the app.

## What it watches for

| Behaviour | What the tool calls it | Example |
|---|---|---|
| asking for an object that belongs to someone else | **IDOR attempt** | alice requests order #1043, which is bob's |
| the same, and the app hands it over | **successful IDOR** 🚨 | the request above returns 200 with the order |
| trying many different ids quickly | **enumeration** | `/api/orders/1041`, `1042`, `1043`, `1044`… |
| many errors in a short time | **burst of errors** | thirty 404s in twenty seconds |
| known attack payloads in a request | **web attack**, by class | a `' OR 1=1` in a parameter, a `<script>` tag, `../../etc/passwd`, a scanner's user agent |
| a dashboard login into an account that is already in use | **login conflict** | someone found an organizer's password |

How it knows an object "belongs to someone else" is explained in lesson 5. In short: it learns from
the app's own behaviour (who read what first, whose user id it is) and from rules the technical
owner tuned for this CTF.

## How it knows who a student is

In order of preference:

1. **The gate.** The first time a student opens the link in a browser they fill a short form (at
   least a name, plus whatever fields you added: student id, email, team…). That name follows every
   request they make afterwards, stored in a signed cookie that cannot be forged.
2. **The app's login.** When the CTF app has accounts, CTF Watch notices the login and remembers
   "this session is alice". You see the app username next to the gate name.
3. **The IP address.** For requests that carry no cookie at all, the IP that zrok reports. If a
   browser from that IP already gave a name, the request is attributed to that name.

The gate can also hold students in a **queue** until you approve them, and refuse anything that
did not go through the form. That is lesson 4.

## What students see

- With the gate on: the form on first visit, then the CTF. With the queue on: a waiting page
  between the two that lets them in by itself the moment you approve.
- When blocked: an "Access blocked" page.
- When no challenge is attached yet, or after Stop CTF: "The CTF is not open yet".
- Nothing else. They cannot reach the dashboard; it lives on the server's own loopback address and
  needs a login.

## What you are responsible for

- Keeping the dashboard login private. The accounts are printed when the monitor starts and change
  on every start.
- Deciding what to do with what you see. The tool flags; you judge. Lesson 6 gives the playbook.
- Not giving the students a reason to suspect the decoy, if you use it.

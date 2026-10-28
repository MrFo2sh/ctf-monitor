# 4. Admitting students: gate and queue

## The gate form (Gate tab)

Every student's first browser visit lands on a form. You design it:

- **Fields.** `username` is always first and is the student's identity; keep its label friendly
  ("Your name"). Add what you need to recognise people: a student id (type *number*), an email
  (type *email*), a team (type *choice* with the options), a free text. Mark each required or not.
  Answers show on the student's card and detail page. An id or email also lets the tool recognise
  the same person at your next event.
- **Texts.** Title, intro, button label, and the waiting page's title and text (`{name}` is
  replaced by the student's name).
- **Live preview** on the right shows exactly what students get. Save when happy; students see the
  new form on their next page load.

Three switches:

| Switch | On (default) | Off |
|---|---|---|
| **gate enabled** | the form is required | nobody is asked; students are identified by the app's login or their IP |
| **strict** | nothing reaches the CTF without the form: curl, scripts and crawlers get a refusal naming the required fields ("You must set your Your name, Student ID first") | tools pass without the form; only browser page loads are asked |
| **queue** | after the form, students wait until you approve them | the form alone lets them in |

With strict on, a student who wants to use Burp or a script must do it from a browser session that
filled the form, or copy the browser's cookie into the tool. Tell them that in the briefing.

## The queue (Queue tab)

When the queue is on, each student who submits the form appears here with their answers, their IP,
their browser, and how long they have waited. The tab updates live and its badge counts the
waiting students.

- Tick students and press **Approve selected**, or approve one by one. The student's waiting page
  continues by itself the instant you click; they do not need to refresh.
- **Block** refuses the student: they get "Access blocked", and they are blocked at the proxy too.
- **to decoy** approves them straight onto the decoy app (lesson 8).
- **back to queue** undoes a decision.
- Chips at the top filter pending, approved, blocked, or all; the search box looks in names,
  answers and IPs.

Typical opening: compare the pending list with your student list, approve the known names in one
go, look at the odd ones (a name you do not know, a browser from a server, two entries from the
same IP), and decide.

## "Ask to rename"

If someone typed a joke name, select them (Live tab) and press **🔁 Ask to rename**. Their next
page load shows the form again with "The organizer asks you to enter your real name", their other
requests are refused until they do, and the rejected name cannot be reused. When they re-enter, their
history moves to the new name. If you would rather just fix it yourself, use **✎ Rename**.

## What a student sees, in order

1. The form.
2. With the queue on: "Almost there. Thanks Sara! The organizer will let you in shortly." with a
   spinner. The page waits for your decision.
3. The challenge. Nothing from CTF Watch is visible from then on.

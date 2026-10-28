# 2. Setting up the event day

Do this the day before, not the morning of.

## Checklist

1. **Start the monitor** on the VM that runs the CTF container:
   ```
   cd ctf-monitor && ./start.sh
   ```
   It prints the dashboard accounts (keep `admin_xxx` for yourself, hand `user_N` to colleagues) and
   the student link from zrok. The accounts are also in `logs/credentials.txt`.
2. **Open the dashboard.** On the VM: http://127.0.0.1:8080. From your laptop:
   `ssh -L 8080:127.0.0.1:8080 <user>@<vm>` then the same address.
3. **Attach the challenge.** You land on the CTFs tab. The card "CTF app behind the proxy" lists
   every port on the VM and every container with what it answers. Press ▶ Use on the challenge.
   Until you do, students see "The CTF is not open yet".
4. **Check the student link** on the same card (🔗 with a copy button). Open it yourself in a
   private browser window: you should get the gate form, then the challenge. Your own visit shows up
   on the Live tab; that is the proof the pipe works. Afterwards remove yourself from the queue or
   just leave it; you know who you are.
5. **Design the gate** (Gate tab): which fields to ask, the texts, strict mode and queue on or off.
   See lesson 4. Save, and look at the live preview.
6. **Decide the decoy** if you plan to use one: a second instance of the challenge or any other
   app, picked on the CTFs tab. See lesson 8.
7. **Give colleagues their accounts** and this course. One session per account: two people cannot
   share a login, and the second one gets blocked and reported.
8. **Rehearse** with the Playground (lesson 12) if the team has never seen the dashboard move.

## What to have ready during the event

- The admin login, on paper or in a password manager.
- The list of expected students, to compare with the queue.
- A rule for the team: who approves the queue, who triages, who talks to students.

## Things that must not happen

- Do not share the dashboard address through zrok or any tunnel other than SSH. It holds the
  students' data and the controls.
- Do not run the Playground's fake students against the real challenge during the event.
- Know where the passwords live: `logs/credentials.txt` on the VM (readable by your user only,
  switch it off with `CREDENTIALS_FILE=0` in `.env`) and the container's own log until the next
  start. Anyone with a shell on the VM can read both; keep the VM to yourself.
- Do not restart the monitor casually during the event: accounts are regenerated and everyone is
  logged out. Data is kept, the link is kept, but logins change.

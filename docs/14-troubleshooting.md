# 14. Troubleshooting

| You see | Likely cause | What to do |
|---|---|---|
| Students report "The CTF is not open yet" | no app behind the proxy, or Stop CTF was pressed | CTFs tab → ▶ Use on the challenge |
| Students report "502 Bad Gateway" | the proxy points at an app that is down or at the wrong port | CTFs tab → ↻ Scan ports, pick the one that answers "HTTP 200" with the challenge's title |
| Students stuck on "Almost there" | they are waiting in the queue | Queue tab → approve; or switch the queue off in the Gate tab |
| A student says curl / their script is refused | strict mode | expected; they must send the browser's cookie, or you switch strict off |
| A student says "ask to rename" but they already typed their real name | you asked, they re-entered the same name | the rejected name cannot be reused: ✎ Rename them yourself, or tell them to add a surname |
| Nobody appears on the Live tab | students are not going through the proxy | check the student link on the CTFs tab is the one you distributed, and that zrok is running (`logs/zrok.log`) |
| Everyone appears as `ip:…` | the gate is off and the app's login is not recognised | turn the gate on, or have the technical owner tune `config/rules.json` |
| "This account is already logged in from another place" | someone else holds that account's session, or you logged in from two networks | use another account, or wait for the session to expire; if it is an intruder, see lesson 8 |
| You cannot log in at all and the admin password is lost | | `cat logs/credentials.txt` on the VM, or restart the monitor for new accounts |
| The dashboard page is blank or old after an update | the page kept an old version | reload the browser tab |
| The Alerts badge never clears | alerts not acknowledged | Alerts tab → Acknowledge all |
| The live preview on the Gate tab is empty | a browser blocked the preview frame | open "Preview the page" in a new tab instead |
| Queue tab says "The queue is switched off" | the queue switch is off in the Gate tab | turn it on if you want approvals |
| A fake student named carol/mallory appears | the Playground is running | Playground tab → ■ Stop everything |

For anything about the monitor itself (container logs, rules, ports), the technical owner has
`docker compose logs -f monitor` on the VM and the developer course in `dev_docs/`.

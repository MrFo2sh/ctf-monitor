# Known issues to address

Verified against the code; each entry says where it is, when it bites, and a sensible fix.
Items are ordered by how much they matter during a real event.

## 1. Forwarded headers are trusted blindly (identity spoofing) — FIXED

- **Where**: `proxy/src/util.js` `clientIp()`, used by identity resolution, ip matching, blocking, the queue and the player mapping; `proxy/src/proxy.js` when forwarding.
- **What**: the first value of `X-Forwarded-For` (then `X-Real-IP`) was taken as the client's address from any peer. A student who could reach the proxy port directly could send `X-Forwarded-For: 1.2.3.4` and appear as another IP.
- **Fix applied**: `TRUSTED_PROXIES` (default `127.0.0.1,::1,::ffff:127.0.0.1`, the tunnel on the VM; `*` trusts everyone). `clientIp` believes the headers only when the socket peer is in the list, otherwise the socket address is the identity. When forwarding, a trusted peer's chain is appended to, an untrusted client's `X-Forwarded-For` / `X-Real-IP` are dropped and replaced by its real address (HTTP and WebSocket paths). The Docker Desktop rehearsal override sets `*` because the Playground's fake students fake their addresses on purpose. Test: `core.test.js` "clientIp believes forwarded headers only from trusted proxies". Golden replay unchanged (its peer is `127.0.0.1`).

## 2. Shared IPs can merge two people into one player record

- **Where**: `proxy/src/db.js` `playerFor()` / `upsertIdentity`; `proxy/src/server.js` `playerIdFor()`.
- **What**: an `ip` identity is looked up like a name or email. Two students behind one NAT (classroom Wi-Fi) can resolve to the same player, and an identity is never moved once attached to a player.
- **Fix**: give identity kinds a weight (gate id/email > app username > name > ip) and only create or attach by ip when no stronger identity is present; never *match* on ip alone when the name differs.

## 3. A failed database flush loses the batch — FIXED

- **Where**: `proxy/src/db.js` `flush()`.
- **What**: on an exception the transaction was rolled back and the batch dropped. A disk-full or a locked database lost up to 200 ms of requests.
- **Fix applied**: the batch is put back in front of the queue and retried with a growing delay (2 s × failures, max 30 s); the retry buffer is capped at 5000 rows (older rows beyond it are dropped and counted in `droppedRows`); `onFlushError` raises a critical `db-error` alert on the first failure and every tenth. Test: `db.test.js` "a failed flush keeps the batch and retries".

## 4. Import inserts the CTF row outside its transaction — FIXED

- **Where**: `proxy/src/db.js` `importCtf()`.
- **What**: the `ctfs` row was inserted before `BEGIN`; if the requests insert failed, an empty "(imported)" record was left behind.
- **Fix applied**: the `ctfs` insert is inside the transaction; a failing import rolls back completely. Test: `db.test.js` "a failed import leaves no half-imported CTF behind".

## 5. Rename does not rewrite everything — FIXED

- **Where**: `proxy/src/store.js` `renameStudent()`, `proxy/src/detect.js` `renameStudent()`.
- **What**: alert messages were rewritten by substring replacement (a name that is a substring of another word got corrupted); the `requests` table was updated for the active CTF only and the `alerts` table not at all; in the detector, renaming onto a name that already had state dropped the old state instead of merging.
- **Fix applied**: `Store.renameInText` replaces whole words only; for the active CTF the database `requests.student`, `requests.owner`, `alerts.student` and the alert messages are updated; the detector merges enumeration windows, error windows, id sequences and the seen-id set when the target already exists. Tests: `store.test.js` (3) and the detector merge test. Golden replay unchanged.

## 6. Scanner class is broad — FIXED

- **Where**: `proxy/src/attacks.js`, class `scanner`.
- **What**: `curl/`, `wget/`, `python-requests/` and `go-http-client` were flagged as scanners (medium). In a CTF where scripting is allowed this was noise.
- **Fix applied**: two classes. `scanner` (sqlmap, nikto, nuclei, gobuster, ffuf, nmap, burp, zap, hydra…) stays medium. New `tool` (curl, wget, python-requests, urllib, Go http client, HTTPie, axios, node-fetch, okhttp) is level `info`: the request keeps the `attack:tool` flag so it is queryable and counted on the card, but an info-level tag never raises the request's severity (`pipeline.js`). The golden fixture was re-baselined: the only differences are the three `curl/` exchanges (scanner → tool, severity warn → ok) and their alert level (medium → info). Test: `attacks.test.js` "plain scripting tools are tagged tool at info level".

## 7. Query scope is disabled by the word "ctf" anywhere — FIXED

- **Where**: `proxy/src/query.js` `compile()`.
- **What**: the automatic "current CTF only" scope was dropped when the raw query text matched `\bctf\b`, including inside a string value such as `path ~ "/ctf/flag"`.
- **Fix applied**: `mentionsCtf(ast)` walks the parsed tree and only a condition on the `ctf` field disables the scope. Test: `query.test.js` "the word ctf inside a value does not disable the scope".

## 8. Attack samples are not masked — FIXED

- **Where**: `proxy/src/pipeline.js` (caller of `attacks.classify()`), `proxy/src/mask.js`.
- **What**: the 120-character sample around a match was taken from the decoded request; a payload inside a password field would have appeared unmasked in alerts and detail pages.
- **Fix applied**: the body is passed through the new `maskBodyText()` (values of sensitive fields replaced by `***`, structure kept, JSON and form bodies), the URL through `maskUrl()`, and every sample through `maskText()`. The golden replay shows no change in classification. Test: `core.test.js` "maskBodyText hides secret values…".

## 9. Secrets in `logs/credentials.txt` and in the container log — ADDRESSED

- **Where**: `proxy/src/server.js` `printCredentials()`.
- **What**: plaintext dashboard passwords are written to a file (mode 600) and to stdout, which Docker keeps in its log for the container's lifetime.
- **Applied**: `CREDENTIALS_FILE=0` disables the file (and removes a stale one); the default stays `1` because `start.sh` and non-technical operators rely on it. The `docker logs` exposure is documented in `.env.example` and the operator course; it ends when the container is recreated (`./start.sh` does that on every run). Not changed: stdout printing, which `start.sh` needs.

## 10. No HTTPS on the dashboard

- **Where**: `proxy/src/dashboard.js`.
- **What**: the session cookie travels in clear text. Safe over the SSH tunnel or loopback; not safe with `DASHBOARD_BIND=0.0.0.0` on a shared network.
- **Fix**: support a TLS cert pair via environment variables, or document a reverse proxy in front.

## Smaller notes

- `gate.unrevoke()` / `gate.isRevoked()` are unused; the form handler deletes from `revoked` directly (`namegate.js`).
- `OPS_BY_TYPE.time` omits `in` although the compiler supports it; the autocomplete therefore never offers it (`query.js`).
- `macFor()` caches a `null` result forever, so a device that joins the LAN later is never resolved (`util.js`).
- `maskObject` stops masking below six levels of nesting (`mask.js`).
- `thresholds` in `rules.json` use `||` defaults, so `0` cannot be configured (`config.js`).
- `admin.js` has no dedicated unit test; `store.js` and `replay.js` are only covered by running the stack.

# Known issues to address

Verified against the code; each entry says where it is, when it bites, and a sensible fix.
Items are ordered by how much they matter during a real event.

## 1. Forwarded headers are trusted blindly (identity spoofing)

- **Where**: `proxy/src/util.js` `clientIp()`, used by identity resolution, ip matching, blocking, the queue and the player mapping.
- **What**: the first value of `X-Forwarded-For` (then `X-Real-IP`) is taken as the client's address. A student who can reach the proxy port directly, instead of through the tunnel, can send `X-Forwarded-For: 1.2.3.4` and appear as another IP: inherit an ip-matched name, dodge an IP block, or pollute another student's IP list.
- **Why it is acceptable today**: in the intended deployment zrok terminates the connection and sets the header itself, and the proxy binds to `127.0.0.1`, so nobody but the tunnel can talk to it.
- **When it bites**: `PROXY_BIND=0.0.0.0` on a reachable network, or any deployment where students are on the same host or LAN as the proxy.
- **Fix**: add a `TRUSTED_PROXIES` setting (list of addresses, default `127.0.0.1`). In `clientIp`, honour the forwarded headers only when `req.socket.remoteAddress` is in that list; otherwise use the socket address and drop the headers before forwarding. Also stop appending to a client-supplied `X-Forwarded-For` in `proxy.js` when the peer is untrusted. Add a unit test in `core.test.js`.

## 2. Shared IPs can merge two people into one player record

- **Where**: `proxy/src/db.js` `playerFor()` / `upsertIdentity`; `proxy/src/server.js` `playerIdFor()`.
- **What**: an `ip` identity is looked up like a name or email. Two students behind one NAT (classroom Wi-Fi) can resolve to the same player, and an identity is never moved once attached to a player.
- **Fix**: give identity kinds a weight (gate id/email > app username > name > ip) and only create or attach by ip when no stronger identity is present; never *match* on ip alone when the name differs.

## 3. A failed database flush loses the batch

- **Where**: `proxy/src/db.js` `flush()`.
- **What**: on an exception the transaction is rolled back and the batch is dropped (logged). A disk-full or a locked database loses up to 200 ms of requests.
- **Fix**: keep the batch on failure and retry on the next flush, with a cap; raise a critical alert when retries fail.

## 4. Import inserts the CTF row outside its transaction — FIXED

- **Where**: `proxy/src/db.js` `importCtf()`.
- **What**: the `ctfs` row was inserted before `BEGIN`; if the requests insert failed, an empty "(imported)" record was left behind.
- **Fix applied**: the `ctfs` insert is inside the transaction; a failing import rolls back completely. Test: `db.test.js` "a failed import leaves no half-imported CTF behind".

## 5. Rename does not rewrite everything

- **Where**: `proxy/src/store.js` `renameStudent()`, `proxy/src/detect.js` `renameStudent()`.
- **What**: alert messages are rewritten by substring replacement (a name that is a substring of another word is corrupted); the `requests` table is updated for the active CTF only, the `alerts` table not at all; in the detector, renaming onto a name that already has state drops the old state instead of merging.
- **Fix**: rewrite messages by token, update `alerts.student` and all CTFs of the active record, and merge detector windows.

## 6. Scanner class is broad

- **Where**: `proxy/src/attacks.js`, class `scanner`.
- **What**: `curl/`, `wget/`, `python-requests/` and `go-http-client` are flagged as scanners (medium). In a CTF where scripting is allowed this is noise.
- **Fix**: split into `scanner` (sqlmap, nikto, nuclei…) and `tool` (curl, requests…) with level `info`, or make the list configurable in `rules.json`.

## 7. Query scope is disabled by the word "ctf" anywhere — FIXED

- **Where**: `proxy/src/query.js` `compile()`.
- **What**: the automatic "current CTF only" scope was dropped when the raw query text matched `\bctf\b`, including inside a string value such as `path ~ "/ctf/flag"`.
- **Fix applied**: `mentionsCtf(ast)` walks the parsed tree and only a condition on the `ctf` field disables the scope. Test: `query.test.js` "the word ctf inside a value does not disable the scope".

## 8. Attack samples are not masked — FIXED

- **Where**: `proxy/src/pipeline.js` (caller of `attacks.classify()`), `proxy/src/mask.js`.
- **What**: the 120-character sample around a match was taken from the decoded request; a payload inside a password field would have appeared unmasked in alerts and detail pages.
- **Fix applied**: the body is passed through the new `maskBodyText()` (values of sensitive fields replaced by `***`, structure kept, JSON and form bodies), the URL through `maskUrl()`, and every sample through `maskText()`. The golden replay shows no change in classification. Test: `core.test.js` "maskBodyText hides secret values…".

## 9. Secrets in `logs/credentials.txt` and in the container log

- **Where**: `proxy/src/server.js` `printCredentials()`.
- **What**: plaintext dashboard passwords are written to a file (mode 600) and to stdout, which Docker keeps in its log for the container's lifetime.
- **Fix**: print once to stdout and skip the file by default (`CREDENTIALS_FILE=0`), or rotate the Docker log; document `docker logs` exposure.

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

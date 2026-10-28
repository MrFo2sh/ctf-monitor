> **Added after this chapter was written:** `test/golden.test.js` replays 230 recorded proxy exchanges (`test/fixtures/golden-raw.jsonl`) through `src/pipeline.js` and compares every event's flags, severity, owner, identity and masked path with `golden-expected.json`. It is the regression net for any change to identity, detection, attacks, masking or alerting. See [28-pipeline.md](28-pipeline.md) for how to re-record it.

# Tests — `proxy/test/*.test.js`, `proxy/package.json`

## Purpose

The unit tests cover the pure logic of the monitor: masking, identity resolution, IDOR/enumeration/burst detection, attack classification, the query language compiler, the SQLite layer, dashboard authentication, the student gate and admission queue, the decoy router, and port discovery. They run with Node's built-in test runner, need no extra package, and finish in about a second. What they do not cover — the HTTP proxy path, WebSocket pushes, the dashboard UI — was exercised during development end to end by starting the stack and calling the API with curl (last section).

## Walkthrough

### `proxy/package.json` — how the runner is invoked

```json
// proxy/package.json lines 1-17
{
  "name": "ctf-watch",
  "version": "1.0.0",
  "description": "Logging reverse proxy + live IDOR dashboard for web CTFs",
  "license": "MIT",
  "private": true,
  "type": "commonjs",
  "main": "src/server.js",
  "scripts": {
    "start": "node src/server.js",
    "test": "node --test --test-reporter=spec \"test/**/*.test.js\""
  },
  "engines": { "node": ">=23.4" },
  "dependencies": {
    "ws": "8.18.0"
  }
}
```

- `"private": true` prevents an accidental `npm publish`. `"type": "commonjs"` makes `require` the module system everywhere (all files use `'use strict'` + `require`).
- `npm test` runs `node --test`: Node's own runner (`node:test`). `--test-reporter=spec` prints the human-readable `✔ name (ms)` format with a summary block. The glob `"test/**/*.test.js"` is quoted so the shell does not expand it; Node expands it itself (supported since Node 21) and runs each matching file **as a separate process**, so files cannot share state and a crash in one does not stop the others.
- `engines.node >= 23.4`: `src/db.js` uses `require('node:sqlite')`, which is built into Node (experimental; the runner prints `ExperimentalWarning: SQLite is an experimental feature` once per process). `package-lock.json` still says `>=18`; it is not used by the Docker build (chapter 24) and is simply stale.
- The only runtime dependency is `ws` (WebSocket server for the live dashboard). The tests do not need it installed, but `npm install` in `proxy/` is required once for the server itself.

Useful invocations (run from `proxy/`):

```bash
npm test                                             # everything, spec reporter
node --test test/query.test.js                       # one file
node --test --test-name-pattern='relative time' test/query.test.js   # one test by name (regex)
node --test --watch "test/**/*.test.js"              # rerun on change
node --test --test-reporter=tap "test/**/*.test.js"  # machine-readable output
```

Current state: 45 tests, all passing, about 1.2 s. The `[info] queue: ...` and `[info] decoy: ...` lines interleaved with the results are the modules' own `log()` output (they write to stdout); they are not test failures.

Common conventions in every file:

```js
// e.g. proxy/test/attacks.test.js lines 1-4
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { classify, worstLevel } = require('../src/attacks');
```

`node:assert/strict` makes `assert.equal` behave like `===` and `deepEqual` like `deepStrictEqual`, so `'1'` is not equal to `1`. Modules are required directly from `../src`; nothing is mocked. Database-backed tests construct `new Db(':memory:')`, an in-memory SQLite that disappears with the process.

### `attacks.test.js` — attack classification (`src/attacks.js`)

`classes(r)` (line 6) maps `classify(r)` to the list of class names. `r` is a minimal request description: `url`, optional `bodyText`, `ua`, `referer`.

| Test (line) | What it checks |
|---|---|
| normal traffic is not flagged (8) | A plain order read and a search with a JSON body produce `[]`. Guards against false positives on ordinary query strings. |
| classic injection probes are classified (13) | One payload per class: `sqli` (quote-OR and UNION), `xss`, `ssti` (`{{7*7}}`), `lfi` (`../../etc/passwd`), `cmdi` (`;cat`), `nosqli` (`{"$ne":null}` in the body), `ssrf` (`169.254.169.254`). These are the same payloads the simulator's attacker sends. |
| a Referer pointing at the site itself … (24) | A `Referer` of `localhost:8888` or `127.0.0.1:8888`, even with `?next=http://evil.io`, is not `ssrf`/redirect — a regression test from commit `9b15389`. A real payload inside the referer (`' OR 1=1--`) is still `sqli`. |
| double URL encoding is decoded before matching (31) | `%252e%252e%252f` (encoded `%2e%2e%2f`) is decoded twice and recognised as `lfi`. |
| scanner user agents are flagged from the UA header (35) | `sqlmap/…` gives a first hit with `cls: 'scanner'` and `where: 'user-agent'`. |
| one hit per class, with a short sample and a worst level (41) | Two SQL payloads (URL and body) collapse into one `sqli` hit; `sample` is at most 120 characters; `worstLevel` of the hits is `'high'` and of `[]` is `'info'`. |

### `auth.test.js` — dashboard accounts and sessions (`src/auth.js`)

`setup()` (lines 7–13) builds an in-memory `Db`, an `Auth` with a 60 s session TTL and an `onConflict` callback that records conflicts, and generates `2` user accounts (so `creds` has three entries: admin first).

| Test (line) | What it checks |
|---|---|
| password hashing round-trips … (15) | `hashPassword` produces a `scrypt$…` string; `verifyPassword` accepts the right password, rejects a different case and rejects garbage input without throwing. |
| accounts are generated … (23) | `admin_` + 3 lowercase alphanumerics with role `admin`, then `user_1`, `user_2`; passwords ≥ 12 chars and distinct. Matches the banner `start.sh` parses. |
| login succeeds … (33) | `login(user, pass, ip)` returns `{ ok, token }`; `sessionFromToken` resolves the account and role; `logout` invalidates the token. |
| wrong password is refused and rate limited (44) | Eight wrong attempts from one IP give 401; the ninth attempt — even with the right password — gives 429. |
| single session per account … (50) | Second login of `user_1` from another IP → 409, one conflict reported with `username`, `ip`, `activeIp`; the second IP is blocked (`isIpBlocked`) so even the admin login from it gets 403; `unblockIp` lifts it. This is the "one session per account" rule from the README. |
| re-login from the same IP replaces the session … (65) | Same IP, same account: no conflict; the old token is dead, the new one works. |
| localhost is never blocked (74) | `blockIp('127.0.0.1')` returns `false` and the address stays unblocked — protects the organizer's own SSH-tunnelled access. |

### `core.test.js` — masking, identity, detection (`src/mask.js`, `src/identity.js`, `src/detect.js`, `src/util.js`)

Lines 26–44 define `cfg`, a hand-built version of what `src/config.js` compiles from `rules.json`: identity rules, two compiled endpoints (`orders` with `owner: 'auto'`, `profile` with `owner: 'same-as-user'`), an `ownershipMap` saying order 9 belongs to carol, and low thresholds (3 distinct ids / 3 errors) so the tests stay short. `req()` (line 45) fabricates a Node request with headers and a remote address.

| Test (line) | What it checks |
|---|---|
| masking hides secrets … (12) | `maskObject` replaces values whose key **contains** a masked word (`apiToken` → `***`), recursively; `maskUrl` masks query parameters; `maskText` replaces anything that looks like a JWT with `<jwt:***>`. |
| jwt and body parsing helpers (18) | `decodeJwt` reads the payload of `Bearer a.b.c` and returns `null` for non-JWTs; `parseBody` handles form-encoded and JSON. |
| identity: jwt, then session learned at login, then ip fallback (47) | Order of precedence: a `token` cookie with a JWT gives `neo`; no credentials gives `ip:<remote>`; `X-Forwarded-For` wins over the socket address (first entry); an unknown `session` cookie gives an anonymous `sess-…` name. Then `learn()` is fed a successful `POST /login` with body `{username: 'alice'}` and response `{id: 1001}` and must return `{ name: 'alice', id: '1001' }`; afterwards the same cookie resolves to alice/1001. |
| detector: ownership map, learning, idor attempt vs success, enumeration and bursts (62) | The core scenario: alice reads order 1041 quietly → no flags, learned as hers. bob reads it with 200 → `['idor-attempt','idor-success']`, severity `critical`. bob gets 403 on order 9 (mapped to carol) → attempt only, owner carol. Profile rule: bob reading `/api/users/1002` (his own id) is clean, `1001` is an attempt+success. Three distinct order ids in the window → `enumeration` with a `seq` of ≥ 3 ids. Three error responses in the window → `burst-errors`. |
| detector: renaming a student carries state and learned ownership (94) | An `ip:1.1.1.1` student learns ownership of order 5; after `renameStudent('ip:1.1.1.1', 'Gohary')` the same read by `Gohary` is clean and the owner is reported as `Gohary`. Covers the dashboard "rename" action. |

### `db.test.js` — persistence (`src/db.js`, `src/query.js`)

`ev(over)` (lines 7–10) is a complete request event with overrides.

| Test (line) | What it checks |
|---|---|
| requests are batched, flushed and queryable … (12) | Three `addRequest` calls, then a compiled query `student = "bob" AND flag = "idor-success"` run through `runSql` returns exactly the one matching row with `flags` and `attacks` deserialized from JSON. The empty query returns all three. Note that `runSql` sees the rows without an explicit `flush()`, so reads force a flush of the write batch. |
| player mapping links identities across CTFs (27) | `playerFor([{kind:'name'},{kind:'ip'}])` creates a player; after `endCtf` and a new `openCtf`, the same IP with a different display name resolves to the **same** player id; a different IP and name does not. `playerHistory` lists all three identity values and the one CTF with requests. |
| alerts, ack and student detail aggregation (47) | `alerts()` filters by `ctfId`, `level`, `ack`; `ackAlerts([id])` flips one; `studentDetail('bob', ctfId)` aggregates user agents, distinct IPs, attack classes with counts, and the request list. |
| export / import round trip … (67) | `exportCtf` produces `{ format: 'ctf-watch/1', requests, … }`; `importCtf` of a JSON-cloned dump creates a new CTF with the same requests and alerts (`listCtfs` has two); a non-export object throws `/not a ctf-watch export/`. |

### `decoy.test.js` — routing selected students to a second app (`src/decoy.js`)

One test (line 7): with no target, `targetFor('alice')` is `null`; after `setTarget(url)` still `null` until `add('alice', 'admin_x')`; `rename` moves the entry; a **new** `Decoy` on the same `Db` sees the same list and target (persistence) including who added it (`by`); `setTarget(null)` disables routing for everyone; `remove` returns `true` for a known name and `false` otherwise.

### `gate.test.js` — the student form (`src/namegate.js`)

| Test (line) | What it checks |
|---|---|
| normalizeConfig always keeps a locked, required username field first (6) | Whatever the admin configures, the `username` field is first, `locked`, `required`; custom keys are lower-cased and stripped of non-alphanumerics (`Student-ID` → `studentid`); an empty or `null` config yields the default title and a lone username field; an unknown field `type` becomes `text`. |
| validate: username cleaning, required fields, number / email / choice checks, password never stored (25) | `gateWith(fields)` (lines 18–23) builds a gate with `secretFile: null` (signing key kept in memory). Validation errors for a too-short name, missing required field, non-number, bad email, choice not in `options`. A valid submission trims and strips tags from the name (`' Gohary<b> '` → `Goharyb`), returns the profile with the password field replaced by `***`, and echoes `values` with the password blanked (for re-rendering the form). |
| page renders the configured fields and the signed cookie round-trips (45) | `page(next, error, values)` HTML contains the inputs, the previous value and the error. `sign(name)` + cookie `ctfw_name=<name>.<sig>` resolves via `nameFrom(req)`; a forged signature yields `null`. |
| disabled gate never intercepts; enabled gate intercepts only browser navigations (55) | With `strict: false` and `queue: false`, a browser navigation (`Accept: text/html`, `Sec-Fetch-Dest: document`) with no cookie gets the form (200, `<form`), an API-style request passes through (`handle` returns `false`); with `enabled: false` nothing is intercepted. `mkRes()` is a tiny fake response object recording `code` and `body`. |

### `ports.test.js` — target discovery (`src/ports.js`)

| Test (line) | What it checks |
|---|---|
| parses LISTEN sockets out of /proc/net/tcp … (7) | Real-looking `/proc/net/tcp` text: hex `0100007F:1F90` → `127.0.0.1:8080`, state `0A` = LISTEN kept, state `01` (ESTABLISHED) dropped. IPv6 lines: all-zero address → `::`, IPv4-mapped `…FFFF00000100007F` → `127.0.0.1`. |
| validateTarget normalises and rejects bad input (20) | Trailing slash removed, missing port defaults to 80, a bare number is rejected (`/look like/`), `https` rejected (`/only http/`), port 70000 rejected (`/bad port/`). |
| probeHttp reports status, server and title … (28) | The only test that opens a real socket: a throwaway `http.createServer` on port 0 (OS-assigned); `probeHttp` returns `ok`, `status`, the `Server` header and the `<title>`; after `srv.close()` the same port probes as `ok: false`. |

### `query.test.js` — the dashboard query language (`src/query.js`)

`NOW` is fixed so relative times are deterministic.

| Test (line) | What it checks |
|---|---|
| simple comparison compiles to parameterised SQL (8) | `student = "alice" AND status >= 400` → `WHERE (student = ? AND status >= ?) AND ctf_id = ?` with params `['alice', 400, 7]`: values are never interpolated into SQL. |
| OR / NOT / parentheses respect precedence (14) | `~` becomes `LIKE ? ESCAPE '\'` with `%…%`; `flag = "x"` becomes `flags LIKE '%"x"%'` (flags are stored as a JSON array string). |
| relative time values (20) | `"-10m"` and `'-1d'` are turned into absolute millisecond timestamps relative to `now`. |
| IN lists and numeric coercion (27) | `method in ("POST","PUT")` → `IN (?, ?)`; `status < "500"` coerces the string to the number 500 because `status` is a numeric column. |
| mentioning ctf disables the automatic ctf scope (33) | A query that names `ctf` is not additionally restricted to the active CTF. |
| empty query returns everything in the active ctf (38) | `''` → `WHERE ctf_id = ?`. |
| LIKE wildcards in user input are escaped (43) | `%` and `_` typed by the user are escaped so they match literally. |
| validate() reports the position of the problem for the editor (48) | `validate()` returns `{ ok: true }` or `{ ok: false, pos, len, error }` with the character offset and length of the offending token (unknown field at 0/6, `~` on a numeric field at 7, missing `AND/OR` at 18, unterminated string at 10, missing value at 9). The dashboard's editor underlines that range. |
| unknown fields, bad operators and injection attempts are rejected (65) | `password` is not a field; `;` DROP TABLE text, dangling `=`, a non-relative time word, and `>` on `flag` all throw `QueryError`. |

### `queue.test.js` — strict gate and admission queue (`src/approvals.js`, `src/namegate.js`)

Helpers (lines 8–19): `mkRes()` also records headers and whether `end()` was called (for the event stream test); `nav(cookie)` and `api(cookie)` fabricate a browser navigation and an API call from `10.0.0.5`; `setup(over)` wires an `Approvals` store into a `NameGate` whose config has a required numeric `sid` field, and returns `cookieFor(name)` producing a correctly signed cookie plus `setCfg` to change the config live.

| Test (line) | What it checks |
|---|---|
| approvals: enqueue, decide, persist, counts (21) | `enqueue` twice → counts `{pending: 2}`; `approve([...])` returns only the names that existed and records `by`; `block`; re-`enqueue` of an approved student keeps the decision but updates the profile; a new `Approvals` on the same `Db` still knows `Sara` is blocked; `reset` returns her to pending. |
| strict gate: no cookie -> browser gets the form, tools get 428 … (41) | Default config is strict: a navigation gets the form; an API call without the cookie gets **428 Precondition Required** with a message naming the required fields (`Your name, Student ID`). |
| non-strict gate: tools without a cookie pass through (49) | `strict: false` lets API calls through unchanged. |
| queue: after the form the student waits, approval lets them in, block shuts them out (54) | With a valid cookie but no queue record the first request enqueues the student and shows the "Almost there" waiting page (API calls get 428 "waiting for the organizer"); after `approve` both pass (`handle` returns `false`); after `block` the "Access blocked" page is served. |
| queue off: the form alone is enough (73) | `queue: false`: a valid cookie passes immediately. |
| waiting page event stream: open streams get the decision pushed instantly (78) | `GET /__ctfwatch/wait` with `Accept: text/event-stream` answers with `Content-Type: text/event-stream`, writes a `"status":"pending"` event and keeps the response open (`ended === false`); calling `approvals.approve` pushes `"status":"approved"` and ends it. `GET /__ctfwatch/status` is the polling fallback and returns the same status as JSON. |

### How to add a test

1. Create `proxy/test/<module>.test.js`; the glob picks it up automatically.
2. Start with the four conventional lines (`'use strict'`, `node:test`, `node:assert/strict`, the `require('../src/<module>')`).
3. One `test('what it proves', () => { ... })` per behaviour; use `async () =>` when awaiting (see `ports.test.js`). For anything that needs a database, `new Db(':memory:')`. For HTTP, listen on port `0` and close the server at the end so the process can exit.
4. For gate/queue code, build fake `req`/`res` objects like `mkRes()`/`nav()` instead of starting the server.
5. Run `node --test test/<module>.test.js` until green, then `npm test` for the whole suite.

Keep tests independent of wall-clock time (pass `now`, as `query.test.js` does) and of the real `config/rules.json` (build a `cfg` object, as `core.test.js` does), otherwise tuning the rules for a real CTF would break the suite.

### End-to-end checks used during development

The integration path (proxy → target, dashboard API, WebSocket) was verified by running the real stack and talking to it with curl. The dashboard API requires a session cookie and, for `POST`, the header `X-Requested-With: ctf-watch` (CSRF guard, `CSRF_HEADER` in `src/dashboard.js`).

```bash
./start.sh                                   # prints admin_xxx and its password
D=http://127.0.0.1:8080
curl -s $D/healthz                            # -> ok
# log in: body is JSON, the session cookie ctfw_sid is stored in the jar
curl -s -c jar.txt -H 'Content-Type: application/json' \
     -d '{"username":"admin_xxx","password":"..."}' $D/api/login
curl -s -b jar.txt $D/api/me                  # who am I, active ctf, current target
curl -s -b jar.txt $D/api/targets             # candidates discovered on the VM + the zrok link
# start the playground (mock app + simulator) exactly as the tab does
curl -s -b jar.txt -H 'X-Requested-With: ctf-watch' -H 'Content-Type: application/json' \
     -d '{}' $D/api/playground/quick
sleep 20
curl -s -b jar.txt $D/api/state | head -c 600 # live snapshot: students, recent requests
curl -s -b jar.txt $D/api/alerts              # idor-success alerts from dave/carol
curl -s -b jar.txt -H 'X-Requested-With: ctf-watch' -H 'Content-Type: application/json' \
     -d '{"q":"flag = \"idor-success\""}' $D/api/query
curl -s -b jar.txt -H 'X-Requested-With: ctf-watch' -d '{}' $D/api/playground/stop-all
./stop.sh
```

And the student side, through the proxy, with the Playground mock attached:

```bash
P=http://127.0.0.1:8888
curl -s -i $P/                                            # gate form (200) or the CTF's page
curl -s -i -H 'Accept: application/json' $P/api/me        # 428 when the gate is strict and no cookie
curl -s -c s.txt -H 'Accept: application/json' -d '{"username":"alice","password":"password"}' \
     -H 'Content-Type: application/json' -H 'X-Forwarded-For: 10.1.1.1' $P/login
curl -s -b s.txt -H 'X-Forwarded-For: 10.1.1.1' $P/api/users/1002   # appears as an idor on the Live tab
```

Watching `docker compose logs -f monitor` alongside shows the request lines and the detector output. `proxy/mock/loadtest.js` (chapter 25) is the performance half of the same approach.

## Interactions

| File | Requires from `src/` | External resources |
|---|---|---|
| `attacks.test.js` | `attacks` | none |
| `auth.test.js` | `db`, `auth` | in-memory SQLite |
| `core.test.js` | `mask`, `identity`, `detect`, `util` | none |
| `db.test.js` | `db`, `query` | in-memory SQLite |
| `decoy.test.js` | `db`, `decoy` | in-memory SQLite |
| `gate.test.js` | `namegate` | none (`secretFile: null`) |
| `ports.test.js` | `ports` | one ephemeral TCP port on 127.0.0.1 |
| `query.test.js` | `query` | none |
| `queue.test.js` | `db`, `approvals`, `namegate` | in-memory SQLite |
| `package.json` | — | Node ≥ 23.4 (`node:sqlite`, test glob); `ws` for the server |

No test reads `config/`, `logs/`, `data/` or environment variables, so the suite runs identically on the VM, on a laptop and in the container (`docker compose exec ctf-watch node --test` would work, but `test/` is not copied into the image).

## Changing it safely

1. **A new detection rule or attack class**: add a positive case to `attacks.test.js` line 13's list **and** a negative case to "normal traffic is not flagged", because false positives on real traffic are the more expensive bug.
2. **A new query field**: add it to the field table in `src/query.js` and extend `query.test.js` with a compile test (expected `where` and `params`) plus a `validate()` case if its operators are restricted.
3. **A change to the credentials format** (`auth.generateAccounts`): update the regex in `auth.test.js` line 26 **and** the `sed`/`grep` in `start.sh` line 162, which parses the printed banner.
4. **A schema change in `db.js`**: the in-memory tests create the schema from scratch, so they will not catch a missing migration for an existing `data/ctf-watch.db`; test an upgrade manually by starting the stack on a copy of an old database.

Verify:

```bash
cd proxy && npm test                       # all 45 must pass
node --test --test-name-pattern='idor' "test/**/*.test.js"   # only the IDOR-related tests
bash -n ../start.sh                        # if start.sh was touched too
```

## Exercises

1. **Break a detector on purpose.** In `core.test.js` change `distinctIds: 3` to `4` in `cfg` and run `node --test test/core.test.js`. The enumeration assertion at line 86 must fail (only three ids were requested). Revert.
2. **Add a query test.** Write a test asserting that `compile('ua ~ "sqlmap"', { now: NOW })` produces a `LIKE` on the `ua` column with `'%sqlmap%'`. Run the single file; then run `npm test` to confirm the count is 46.
3. **Prove the CSRF guard.** With the stack running and a logged-in cookie jar, send `curl -s -b jar.txt -d '{}' http://127.0.0.1:8080/api/playground/stop-all` without the `X-Requested-With` header. Expect `{"error":"missing X-Requested-With header"}` with status 403; add the header and expect `{"ok":true,...}`.

## Quick reference

| Command / item | Meaning |
|---|---|
| `cd proxy && npm test` | run all tests (spec reporter) |
| `node --test test/<file>.test.js` | one file |
| `node --test --test-name-pattern=<regex> …` | filter by test name |
| `node --test --watch "test/**/*.test.js"` | rerun on change |
| `new Db(':memory:')` | throwaway database for a test |
| `secretFile: null` | gate without a persisted signing key |
| 45 tests / 9 files | current suite size |
| `/healthz`, `/api/login`, `/api/me`, `/api/targets`, `/api/state`, `/api/alerts`, `/api/query`, `/api/playground/*` | dashboard endpoints used in curl checks |
| `X-Requested-With: ctf-watch` | required header on every dashboard `POST /api/*` |
| `ctfw_sid` | dashboard session cookie name |

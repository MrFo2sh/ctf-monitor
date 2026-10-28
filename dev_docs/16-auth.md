# Auth — `proxy/src/auth.js`

## Purpose

`auth.js` is the authentication layer of the organizer dashboard (not of the CTF itself). It generates a fresh set of accounts on every start (one admin plus N users), stores scrypt password hashes in SQLite, issues one session per account, and protects the login endpoint with a per-IP rate limit and a persistent IP block list. Its special feature is the *login conflict*: if an account is already in use from another IP and someone logs in with the correct password from elsewhere, the newcomer is refused, their IP is blocked, and `server.js` is told so it can raise a critical alert (a student who stole organizer credentials).

## Where it sits

| Who calls it | How |
|---|---|
| `proxy/src/server.js` (lines 91-111) | `new Auth(db, { sessionTtlMs, onConflict })`, then `auth.generateAccounts(DASHBOARD_USERS)` and prints the result. |
| `proxy/src/dashboard.js` | `auth.isIpBlocked(ip)`, `auth.login(...)`, `auth.cookieFor(...)`, `auth.sessionFromRequest(req)`, `auth.logout(token)`, `auth.clearCookie()`, `auth.unblockIp(ip)`, `auth.blockedIps` (read for the Admin tab). |

| What it requires / calls | Why |
|---|---|
| `crypto` (Node core) | `randomBytes`, `scryptSync`, `timingSafeEqual`, `createHash`. |
| `./util` → `log` | Logging. |
| `Db` instance (`db.js`) | `replaceAccounts`, `account`, `accountById`, `activeSession`, `createSession`, `session`, `deleteSession`, `get`/`set` (kv). |

## Data it owns

| Name | Lines | Shape / meaning |
|---|---|---|
| `SESSION_COOKIE` | 8 | `'ctfw_sid'`, the cookie name. Exported. |
| `ALPHABET` | 9 | 32 characters, no look-alikes (no `l`, `o`, `0`, `1`). Used for usernames' suffix and passwords. |
| stored hash string | 21 | `scrypt$<salt base64>$<key base64>`; salt 16 bytes, key 32 bytes, scrypt `N=16384, r=8, p=1`. |
| `this.ttl` | 43 | Session lifetime in ms (sliding: refreshed on every use). Default 12 h. |
| `this.onConflict` | 44 | Callback `({ username, role, ip, activeIp, blocked })` invoked on a login conflict. |
| `this.blockedIps` | 45 | `Map<ip, { reason, ts }>`, persisted in kv key `dashboard_blocked_ips`. |
| `this.attempts` | 46 | `Map<ip, number[]>`: timestamps of failed logins per IP, memory only. |
| `this.maxAttempts`, `this.attemptWindowMs` | 47-48 | 8 failures within 10 minutes → 429. |
| `this.credentials` | 49, 62 | `[{ username, role, password }]` in plaintext; only exists so `server.js` can print them once. |
| `login()` result | 94 | `{ ok: true, token, account: { id, username, role } }` or `{ error, status }` with status 401/403/409/429. |
| session rows (in `db.js`) | — | `sessions(token_hash, account_id, ip, created_at, last_seen)`. Only the SHA-256 of the token is stored. |

## Walkthrough

### Token and password primitives (lines 11-34)

```js
// lines 11-16
function randomToken(len) {
  const bytes = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[bytes[i] % ALPHABET.length];
  return s;
}
```

- One random byte per output character, reduced modulo 32. Because 256 is a multiple of 32 the distribution is uniform (no modulo bias). A 14-character password has 32^14 ≈ 2^70 possibilities.

```js
// lines 18-33
function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64')}$${key.toString('base64')}`;
}
function verifyPassword(password, stored) {
  try {
    const [, saltB64, keyB64] = String(stored).split('$');
    const salt = Buffer.from(saltB64, 'base64');
    const want = Buffer.from(keyB64, 'base64');
    const got = crypto.scryptSync(password, salt, want.length, { N: 16384, r: 8, p: 1 });
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  } catch {
    return false;
  }
}
```

- scrypt with `N=16384` costs about 16 MB and a few tens of milliseconds per call: cheap enough for a login, expensive enough to make offline cracking of the database pointless (the passwords are random anyway).
- The stored string is self-describing (`scrypt$` prefix). `verifyPassword` derives a key of `want.length` bytes so a future change of key length would still verify old hashes.
- `timingSafeEqual` throws if lengths differ, hence the explicit length check first and the `try/catch` that also covers garbage input (`verifyPassword('x', 'garbage')` → `false`, tested).
- `scryptSync` blocks the event loop. With the 8-attempts rate limit per IP that is acceptable; it is the reason the limit exists.

```js
// line 34
const tokenHash = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');
```

- Session tokens are stored hashed. Someone who reads `ctf-watch.db` cannot reuse a live session; the token only exists in the cookie.

### Constructor (lines 41-50)

```js
// lines 41-50
constructor(db, opts = {}) {
  this.db = db;
  this.ttl = opts.sessionTtlMs || 12 * 3600 * 1000;
  this.onConflict = opts.onConflict || (() => {});
  this.blockedIps = new Map(db.get('dashboard_blocked_ips', {}) ? Object.entries(db.get('dashboard_blocked_ips', {})) : []);
  this.attempts = new Map(); // ip -> [ts]
  this.maxAttempts = opts.maxAttempts || 8;
  this.attemptWindowMs = 10 * 60 * 1000;
  this.credentials = []; // plaintext, only kept to print once at startup
}
```

- The block list is loaded from the kv table, so a blocked IP stays blocked across restarts. Line 45 calls `db.get` twice and the ternary is always true (the fallback `{}` is truthy); it is equivalent to `new Map(Object.entries(db.get('dashboard_blocked_ips', {})))`.
- `maxAttempts` is configurable through opts (the test suite does not use it); the window is fixed at 10 minutes.
- Failed attempts are not persisted: a restart clears them.

### `generateAccounts` (lines 53-64)

```js
// lines 53-64
generateAccounts(users) {
  const list = [];
  const mk = (username, role) => {
    const password = randomToken(14);
    list.push({ username, role, password, passHash: hashPassword(password) });
  };
  mk(`admin_${randomToken(3)}`, 'admin');
  for (let i = 1; i <= Math.max(0, Math.min(Number(users) || 0, 200)); i++) mk(`user_${i}`, 'user');
  this.db.replaceAccounts(list);
  this.credentials = list.map(({ username, role, password }) => ({ username, role, password }));
  return this.credentials;
}
```

- Called once per process start. `db.replaceAccounts` deletes **all sessions and accounts** first, so every restart logs everybody out and prints new passwords. There is no way to set a fixed password; this is by design (credentials are printed to the console and to `logs/credentials.txt`, see `server.js`).
- The admin username has a random 3-character suffix so a student cannot guess it; users are `user_1` … `user_N`. `N` is clamped to 0..200 and non-numeric input becomes 0 (admin only).
- Each `hashPassword` call runs scrypt; with 200 users startup takes a few seconds.

### IP block list (lines 66-79)

```js
// lines 69-75
blockIp(ip, reason) {
  if (!ip || /^(127\.|::1$|::ffff:127\.)/.test(ip)) return false; // never lock ourselves out of localhost
  this.blockedIps.set(ip, { reason, ts: Date.now() });
  this.db.set('dashboard_blocked_ips', Object.fromEntries(this.blockedIps));
  log('info', `auth: blocked dashboard access from ${ip} (${reason})`);
  return true;
}
```

- Loopback in IPv4, IPv6 and IPv4-mapped form is never blocked: the organizer usually opens the dashboard on the VM itself, and a conflict triggered from localhost (e.g. two browsers on the same machine with different IP representations) must not lock them out. The return value tells `login()` whether a block actually happened, which is forwarded to `onConflict` as `blocked`.
- `unblockIp` (76-79) just deletes and re-persists. The dashboard also removes the matching proxy-level block (`admin.state.blocked['ip:…']`) when the organizer unblocks from the Admin tab; that lives in `dashboard.js`, not here.
- The block applies to the **dashboard** only (`dashboard.js` checks `isIpBlocked` on every request and on WebSocket upgrade). Blocking at the CTF proxy level is `admin.js`'s job; `server.js`'s `onConflict` bridges the two.

### Rate limiting (lines 81-91)

```js
// lines 81-91
tooManyAttempts(ip) {
  const now = Date.now();
  const arr = (this.attempts.get(ip) || []).filter((t) => now - t < this.attemptWindowMs);
  this.attempts.set(ip, arr);
  return arr.length >= this.maxAttempts;
}
noteAttempt(ip) {
  const arr = this.attempts.get(ip) || [];
  arr.push(Date.now());
  this.attempts.set(ip, arr);
}
```

- A sliding window: timestamps older than 10 minutes are dropped on every check, so after 8 failures the IP is locked out until the oldest failure ages out.
- Only **wrong-password** attempts are counted (see `login`); a correct login clears the IP's entry. Entries for IPs that never come back are never pruned (bounded in practice by the number of distinct attacking IPs; negligible).

### `login` (lines 97-117)

```js
// lines 97-117
login(username, password, ip) {
  if (this.isIpBlocked(ip)) return { error: 'blocked', status: 403 };
  if (this.tooManyAttempts(ip)) return { error: 'too many attempts, try later', status: 429 };
  const acc = this.db.account(String(username || '').trim());
  if (!acc || !verifyPassword(String(password || ''), acc.pass_hash)) {
    this.noteAttempt(ip);
    return { error: 'wrong username or password', status: 401 };
  }
  const active = this.db.activeSession(acc.id, this.ttl);
  if (active && active.ip !== ip) {
    // someone else is already logged in as this account: alert + block the newcomer
    const blocked = this.blockIp(ip, `tried to log in as ${acc.username} while that account was in use from ${active.ip}`);
    this.onConflict({ username: acc.username, role: acc.role, ip, activeIp: active.ip, blocked });
    return { error: 'this account is already logged in from another place; the organizer has been alerted', status: 409 };
  }
  const token = crypto.randomBytes(32).toString('hex');
  this.db.createSession(tokenHash(token), acc.id, ip);
  this.attempts.delete(ip);
  log('info', `auth: ${acc.username} logged in from ${ip}`);
  return { ok: true, token, account: { id: acc.id, username: acc.username, role: acc.role } };
}
```

Step by step:

1. Blocked IP → 403 before anything else (cheap, no scrypt).
2. Rate limit → 429.
3. Account lookup by trimmed username; wrong user or wrong password produce the same 401 message (no username enumeration) and count as one attempt. Note an unknown username still costs no scrypt call (`!acc` short-circuits).
4. Conflict check — **after** the password was verified. So a conflict means somebody *knows the password*; that is why it is treated as a critical event. `db.activeSession` returns the newest session whose `last_seen` is within `ttl`. If it belongs to a different IP: block the newcomer's IP (unless loopback), call `onConflict`, answer 409. The existing session is untouched.
5. Same IP (or no live session): a new 32-byte token (64 hex chars; the cookie regex depends on that length). `db.createSession` first deletes every session of that account — this is the "single session per account" rule: a re-login from the same IP invalidates the previous tab's cookie (tested by `re-login from the same IP replaces the session instead of conflicting`).
6. Clearing `attempts` on success means a legitimate user who mistyped a few times is forgiven.

Gotcha: `ip` comes from `util.clientIp(req)`, which honours `X-Forwarded-For`. The dashboard is meant to be bound to localhost or a LAN, never behind zrok; if it were exposed behind a proxy that does not strip that header, a client could pick its own "IP" and defeat both the block list and the conflict check.

### Logout and session lookup (lines 119-133)

```js
// lines 124-133
sessionFromToken(token) {
  if (!token) return null;
  const s = this.db.session(tokenHash(token), this.ttl);
  if (!s) return null;
  return this.db.accountById(s.account_id);
}
sessionFromRequest(req) {
  const m = /(?:^|;\s*)ctfw_sid=([a-f0-9]{64})/.exec(req.headers.cookie || '');
  return this.sessionFromToken(m ? m[1] : null);
}
```

- `db.session` only returns rows whose `last_seen` is within `ttl` **and** bumps `last_seen`, so the TTL is sliding: a dashboard tab that keeps polling never expires; an idle one expires after `SESSION_TTL_HOURS`.
- The result is the account `{ id, username, role }` (no hash), which `dashboard.js` uses as the "user" for role checks and for `/api/me`.
- The cookie regex is strict: exactly 64 lowercase hex characters, anchored at the start of the header or after `; `. Anything else is treated as "not logged in".
- `logout(token)` (119-121) deletes the session row by hash; a missing token is a no-op.

### Cookies (lines 135-140)

```js
// lines 135-140
cookieFor(token, secure) {
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(this.ttl / 1000)}${secure ? '; Secure' : ''}`;
}
clearCookie() {
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
}
```

- `HttpOnly`: page scripts cannot read the token. `SameSite=Strict`: the browser never sends it on cross-site requests, which (together with the `X-Requested-With` check in `dashboard.js`) is the CSRF defence. `Max-Age` matches the TTL so the browser drops the cookie at the same time the server would.
- `secure` is decided by the caller (`dashboard.js` sets it when `X-Forwarded-Proto: https` is present, i.e. behind a TLS terminator). On plain `http://127.0.0.1:8080` the flag must be absent or the browser would refuse the cookie.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` | `new Auth(db, { sessionTtlMs, onConflict })`; `generateAccounts(n)` → plaintext credentials list. |
| in | `dashboard.js` | `login(username, password, ip)`, `logout(token)`, `sessionFromRequest(req)`, `isIpBlocked(ip)`, `unblockIp(ip)`, `cookieFor(token, secure)`, `clearCookie()`, direct read of `blockedIps`. |
| out | `db.js` | Accounts table (`replaceAccounts`, `account`, `accountById`), sessions table (`activeSession`, `createSession`, `session`, `deleteSession`), kv key `dashboard_blocked_ips`. |
| out | `server.js` via `onConflict` | `{ username, role, ip, activeIp, blocked }` → critical alert `admin-login-conflict` + proxy-level IP block. |
| out | `util.js` | `log` lines for login, block. |

## Changing it safely

| Likely change | Where |
|---|---|
| Fixed / configurable admin password | `generateAccounts` (53-64): replace `randomToken(14)` for the admin with an env value. Keep `hashPassword`; never store plaintext. Remember `replaceAccounts` wipes sessions on every start regardless. |
| Different lockout policy | `maxAttempts` / `attemptWindowMs` (47-48). The test `wrong password is refused and rate limited` hard-codes 8 failures → 429. |
| Allow several simultaneous sessions per account | `login` lines 105-111 (drop the conflict branch) **and** `db.createSession` (which deletes previous sessions). Tests `single session per account…` and `re-login from the same IP…` encode the current rule. |
| Longer session or non-sliding expiry | `ttl` is passed from `server.js` (`SESSION_TTL_HOURS`); sliding behaviour lives in `db.session` (the `UPDATE last_seen`). |

Tests in `proxy/test/auth.test.js` (`npm test` inside `proxy/`):

- `password hashing round-trips and rejects wrong passwords`
- `accounts are generated: one admin_xxx plus N users with random passwords`
- `login succeeds with the right password and yields a usable session`
- `wrong password is refused and rate limited`
- `single session per account: a second login from another IP is refused, reported and that IP blocked`
- `re-login from the same IP replaces the session instead of conflicting`
- `localhost is never blocked`

Not unit-tested: cookie formatting (`cookieFor`, `clearCookie`), `sessionFromRequest`'s cookie regex, persistence of the block list across restarts, and the HTTP wiring in `dashboard.js`. Those are only exercised by running the stack and logging in through a browser.

## Exercises

1. **Run the auth tests only.**
   `cd proxy && node --test test/auth.test.js`
   All seven pass. Then change `maxAttempts` to 3 at line 47 and watch `wrong password is refused and rate limited` fail; revert.

2. **Trigger a login conflict by hand.** Start the stack, log in as `user_1` from a browser, then from another machine on the LAN (or with a spoofed header if the dashboard is reached through a proxy) run:
   `curl -i -H 'Content-Type: application/json' -d '{"username":"user_1","password":"<pw>"}' http://<dashboard-host>:8080/api/login`
   Expect `409` and, in the Alerts view, a critical `admin-login-conflict` alert; the second IP now gets `403 blocked` on every dashboard URL. Unblock it from the Admin tab.

3. **Verify the token is hashed at rest.** After logging in, open `data/ctf-watch.db` with `sqlite3 data/ctf-watch.db 'select token_hash, ip from sessions'` and compare with the `ctfw_sid` cookie in your browser: they differ (SHA-256 of the cookie value equals `token_hash`).

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Auth` | `new Auth(db, { sessionTtlMs?, onConflict?, maxAttempts? })` | Dashboard authentication service. |
| `Auth#generateAccounts` | `(users: number) → [{ username, role, password }]` | Replaces all accounts (and sessions) with fresh random ones; returns plaintext once. |
| `Auth#login` | `(username, password, ip) → { ok, token, account } \| { error, status }` | Full login decision incl. block, rate limit, conflict. |
| `Auth#logout` | `(token) → void` | Deletes the session. |
| `Auth#sessionFromToken` | `(token) → { id, username, role } \| null` | Validates and refreshes a session. |
| `Auth#sessionFromRequest` | `(req) → account \| null` | Same, reading the `ctfw_sid` cookie. |
| `Auth#isIpBlocked` / `blockIp` / `unblockIp` | `(ip) → bool` / `(ip, reason) → bool` / `(ip) → void` | Persistent dashboard IP block list. |
| `Auth#cookieFor` / `clearCookie` | `(token, secure) → string` / `() → string` | `Set-Cookie` header values. |
| `hashPassword` | `(password) → 'scrypt$salt$key'` | scrypt hash with random salt. |
| `verifyPassword` | `(password, stored) → bool` | Constant-time verification; `false` on malformed input. |
| `randomToken` | `(len) → string` | Random string over the 32-char look-alike-free alphabet. |
| `SESSION_COOKIE` | `'ctfw_sid'` | Cookie name. |

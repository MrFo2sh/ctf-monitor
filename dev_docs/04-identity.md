# Identity — `proxy/src/identity.js`

## Purpose

Every request that passes through the proxy has to be attributed to one student so that the dashboard can show "who did what". The CTF app itself knows nothing about ctf-watch, so this module reconstructs the identity from what it can observe: a JWT the app issued, a session cookie whose owner was learned by watching a login or a "whoami" response, the name the student typed on the gate form, or, as a last resort, the client IP. It also owns the small learning loop that turns an anonymous `sess-xxxx` row into a named one once a login succeeds.

## Where it sits

- **Required by** `proxy/src/server.js` (line 7) and the test `proxy/test/core.test.js`.
- **Constructed once** in `server.js` line 80: `new IdentityResolver(getConfig, gate)`, where `getConfig` returns the parsed `config/rules.json` and `gate` is the `NameGate` instance (chapter 05).
- **Called by `server.js`** in three places:
  - `preRequest()` (line 172): `identity.resolve(req)` to decide whether the student is blocked before anything is proxied.
  - `onEvent()` (lines 193-195): `resolve` → `learn` → `resolve` again after the upstream response finished, so the login request itself can be attributed to the name it just revealed.
  - `getTargetFor()` (line 262): `identity.resolve(req)` to decide whether the request should go to the decoy app (chapter 07).
- **Requires** `./util` for `firstOf`, `shortHash`, `parseCookies`, `parseSetCookies`, `decodeJwt`, `clientIp`, `log`.
- **Calls into the gate** (optional): `gate.nameFrom(req)`, `gate.rememberIp(ip, name)`, `gate.nameForIp(ip)`.
- **Hook it exposes:** `onSessionNamed(anonLabel, name)`. Set in `server.js` line 139 to `mergeLane(label, name)`, which renames the `sess-xxxx` row in the store and detector into the real student row.

## Data it owns

### `IdentityResolver` instance fields

| Field | Type | Meaning |
|---|---|---|
| `getConfig` | `() => config` | Returns the current parsed rules. Only the `identity` sub-object plus `compiledLogin` / `compiledWhoami` (regexes built by `config.js`) are read. |
| `gate` | `NameGate \| null` | Optional. When present, the gate name takes precedence for the display name. |
| `sessions` | `Map<string, { name, id }>` | Session cookie value → learned student. Bounded to 5000 entries (oldest insertion dropped). In memory only; lost on restart. |
| `onSessionNamed` | `(anonLabel, name) => void \| null` | Fired when a session that previously had no name (or a different name) gets one. `anonLabel` is the `sess-<hash>` label the row was shown under. |

### Identity object returned by `resolve()` / `resolveApp()`

| Field | Meaning |
|---|---|
| `name` | Display name used as the student row key: the gate name, a JWT claim, a learned login name, `user#<id>`, `sess-<8 hex>` or `ip:<ip>`. |
| `id` | The app-side user id (string from `firstOf`) or `null`. Used by the IDOR detector to know which objects are "mine". |
| `source` | One of `'jwt'`, `'session'`, `'ip'`, `'name'`, `'ip-match'`. `server.js` later adds `'login'` for the request that revealed a name. |
| `ip` | `clientIp(req)`: first `X-Forwarded-For` entry, else `X-Real-IP`, else socket address, else `'unknown'`. |
| `sessionKey` | The raw session cookie value when a configured session cookie was present, else `null`. Needed by `learn()` to know which key to remember. |
| `appName` | Only set when the gate produced the name: the name the *app* knew (JWT/session), or `null` when the app identity was just an IP. `server.js` uses it as the `username` identity for cross-CTF player matching. |

### Return value of `learn()`

`{ name, id }` when a login or whoami response revealed who the session belongs to, else `null`.

### Config keys read (from `config/rules.json` → `identity`)

| Key | Default in code | Meaning |
|---|---|---|
| `jwt.cookies` | `[]` | Cookie names that may hold a JWT. |
| `jwt.headers` | `[]` | Header names (lower-case) that may hold a JWT, e.g. `authorization`. |
| `jwt.nameClaims` | `['username','sub']` | Claim paths tried for the display name (dot paths allowed). |
| `jwt.idClaims` | `['id','sub']` | Claim paths tried for the user id. |
| `sessionCookies` | `[]` | Cookie names that identify an app session. |
| `login.methods` | `['POST']` | Methods that count as a login. |
| `login.userFields` | `['username']` | Request body fields holding the username. |
| `login.responseNameFields` | `[]` | Response body fields holding the username. |
| `login.responseIdFields` | `['id']` | Response body fields holding the user id. |
| `whoami.nameFields` | `['username']` | Response fields for the name on a whoami endpoint. |
| `whoami.idFields` | `['id']` | Response fields for the id on a whoami endpoint. |
| `compiledLogin`, `compiledWhoami` | `null` | RegExp built by `config.js` from `login.pathPattern` / `whoami.pathPattern`; `null` disables that learning path. |

## Walkthrough

### Header and imports

```js
// lines 1-5
'use strict';
// Works out which student a request belongs to.
// Order: JWT (cookie or Authorization header) -> session cookie (learned at login) -> X-Forwarded-For / IP.

const { firstOf, shortHash, parseCookies, parseSetCookies, decodeJwt, clientIp, log } = require('./util');
```

All helpers come from `util.js`:

- `firstOf(obj, paths)` returns the first non-empty scalar found at any of the dot-paths, as a **string** (`'1001'`, never the number `1001`). That is why `core.test.js` expects `id: '1001'`.
- `shortHash(s)` is the first 8 hex chars of SHA-1; used so a session cookie value never appears in the UI or logs.
- `parseCookies(header)` splits a `Cookie:` header into `{ name: value }` (no decoding).
- `parseSetCookies(arr)` takes the array Node gives for `set-cookie` and returns `[{ name, value }]` from the part before the first `;`.
- `decodeJwt(token)` strips an optional `Bearer ` prefix, base64-decodes the middle segment and returns the payload object or `null`. **No signature check** — this is attribution, not authentication.
- `clientIp(req)` prefers `X-Forwarded-For` (first hop) so that it works behind the zrok tunnel.

### Constructor

```js
// lines 7-13
class IdentityResolver {
  constructor(getConfig, gate) {
    this.getConfig = getConfig;
    this.gate = gate || null; // optional NameGate
    this.sessions = new Map(); // session cookie value -> { name, id }
    this.onSessionNamed = null; // (anonLabel, name) => void: a "sess-xxxx" row got identified -> merge it
  }
```

`gate` is optional so that the resolver can be tested without a gate (`core.test.js` builds `new IdentityResolver(() => cfg)`). `sessions` is keyed by the *raw cookie value*, so two students with the same app username but different sessions are two entries; conversely a student who logs out and in again gets a new entry.

### `resolve(req)` — the public entry point

```js
// lines 15-31
  resolve(req) {
    const base = this.resolveApp(req);
    // 0. Name typed by the student on the name-gate page (if enabled) wins for the display name;
    //    the app identity still supplies the user ID when it has one.
    if (this.gate) {
      const appName = base.source === 'ip' ? null : base.name;
      const name = this.gate.nameFrom(req);
      if (name) {
        this.gate.rememberIp(base.ip, name);
        return { ...base, name, source: 'name', appName };
      }
      // no cookie (curl, scripts, Burp without cookies): same machine as a browser that gave a name?
      const ipName = this.gate.nameForIp(base.ip);
      if (ipName) return { ...base, name: ipName, source: 'ip-match', appName };
    }
    return base;
  }
```

- Line 16 always computes the app identity first; the gate only overrides `name` and `source`, never `id` or `sessionKey`. So a student who typed "Gohary" on the gate and is logged in as app user 1001 is shown as `Gohary` with `id: '1001'`.
- Line 20: `appName` keeps the app-side name for the player-matching logic in `server.js` (`playerIdFor`). An `ip:…` label is not a name, so it becomes `null`.
- Line 21: `gate.nameFrom(req)` verifies the HMAC-signed gate cookie and returns the raw name or `null`. Note that this is called even when the gate is **disabled** — the gate's `nameFrom` does not look at `enabled`. A student who filled the form last week is still attributed by name after the organizer turns the gate off.
- Line 23: `rememberIp` is a side effect inside a resolver. It records "this IP has been seen with this name" so that the next branch can work. It is called on every request, which is cheap (a `Map` lookup and a `Set.has`).
- Lines 27-28: the `ip-match` branch. If the request has no gate cookie (curl, Burp, a script) but the same IP was seen with exactly **one** gate name, that name is used with `source: 'ip-match'`. `nameForIp` returns `null` as soon as two names share an IP (NAT, shared lab machine), so this never mis-attributes between two students who both filled the form. The gate's `strict` mode (chapter 05) decides whether such a cookie-less request is even allowed through; attribution here is independent of that.
- Line 30: no gate, or no match: the app identity stands.

Edge case: `resolve` is called up to three times per request (`preRequest`, twice in `onEvent`) and in `getTargetFor`. It must stay side-effect-light; `rememberIp` is idempotent after the first call.

### `resolveApp(req)` — JWT → session → IP

```js
// lines 33-49
  resolveApp(req) {
    const cfg = this.getConfig().identity || {};
    const cookies = parseCookies(req.headers.cookie);
    const ip = clientIp(req);

    // 1. JWT
    const jwtCfg = cfg.jwt || {};
    const candidates = [];
    for (const c of jwtCfg.cookies || []) if (cookies[c]) candidates.push(cookies[c]);
    for (const h of jwtCfg.headers || []) if (req.headers[h]) candidates.push(String(req.headers[h]));
    for (const tok of candidates) {
      const payload = decodeJwt(tok);
      if (!payload) continue;
      const name = firstOf(payload, jwtCfg.nameClaims || ['username', 'sub']);
      const id = firstOf(payload, jwtCfg.idClaims || ['id', 'sub']);
      if (name || id) return { name: name || `user#${id}`, id, source: 'jwt', ip, sessionKey: null };
    }
```

- Line 34: `|| {}` everywhere means a rules file without an `identity` section still works; every path then falls through to IP.
- Lines 41-42: cookies are checked before headers, in configured order. Header names must be lower-case in the config because Node lower-cases incoming header names.
- Line 45: anything that is not three dot-separated segments with a JSON middle is skipped, so an opaque cookie called `token` does not break attribution.
- Line 48: a JWT with an id but no name claim is shown as `user#<id>`. A JWT with neither is ignored (falls through to the session cookie). `sessionKey` is `null`: JWT identities are never "learned", they carry their own name.

```js
// lines 51-67
    // 2. Session cookie
    const sessionNames = cfg.sessionCookies || [];
    let sessionKey = null;
    for (const c of sessionNames) {
      if (cookies[c]) {
        sessionKey = cookies[c];
        break;
      }
    }
    if (sessionKey) {
      const learned = this.sessions.get(sessionKey);
      if (learned) return { name: learned.name, id: learned.id, source: 'session', ip, sessionKey };
      return { name: `sess-${shortHash(sessionKey)}`, id: null, source: 'session', ip, sessionKey };
    }

    // 3. IP / forwarded header
    return { name: `ip:${ip}`, id: null, source: 'ip', ip, sessionKey: null };
  }
```

- Lines 54-59: the first configured cookie name present wins. Order in `sessionCookies` matters when an app sets more than one (e.g. both `session` and `PHPSESSID`).
- Line 63: an unknown session is shown as `sess-<8 hex>`. The label is deterministic for the cookie value, so the row is stable across requests until `learn()` names it, at which point `onSessionNamed` fires and `server.js` merges the row.
- Line 67: the `ip:` label is the fallback. `server.js` treats `source === 'ip'` rows as "not a player yet" (`playerIdFor` returns `null`).

### `learn(...)` — turning a login or whoami response into a session → name mapping

```js
// lines 70-80
  // Called after a response finished. Learns "session cookie -> student" from logins and whoami endpoints.
  // Returns the learned { name, id } (so the login request itself can be attributed), or null.
  learn({ req, identity, reqBody, status, resHeaders, resBody, pathOnly }) {
    const full = this.getConfig();
    const cfg = full.identity || {};
    if (status < 200 || status >= 400) return null;

    const setCookies = parseSetCookies(resHeaders['set-cookie']);
    const sessionNames = cfg.sessionCookies || [];
    const newSessionKeys = setCookies.filter((c) => sessionNames.includes(c.name)).map((c) => c.value);
    const keys = new Set([...newSessionKeys, ...(identity.sessionKey ? [identity.sessionKey] : [])]);
```

- `identity` is the result of `resolve(req)` *before* the response was known (`pre` in `server.js` line 193). Only its `sessionKey` is used.
- Line 75: only 2xx/3xx responses teach anything. A 401 on `/login` must not bind the attempted username to the session (that would let a student frame someone by typing their name into a failing login).
- Lines 77-80: `keys` is the set of session values to bind: a session cookie the app just **set** in this response (typical: the login response rotates the session), plus the one the request **sent** (typical: the app keeps the pre-login session id). Both are remembered, so attribution works whichever strategy the app uses. The header is read as `resHeaders['set-cookie']`, which Node provides as an array.

```js
// lines 82-94
    // login
    const loginCfg = cfg.login || {};
    const loginMethods = (loginCfg.methods || ['POST']).map((m) => m.toUpperCase());
    if (full.compiledLogin && full.compiledLogin.test(pathOnly) && loginMethods.includes(req.method.toUpperCase())) {
      const name = firstOf(reqBody || {}, loginCfg.userFields || ['username']) || firstOf(resBody || {}, loginCfg.responseNameFields || []);
      const id = firstOf(resBody || {}, loginCfg.responseIdFields || ['id']);
      if (name) {
        for (const k of keys) this.remember(k, name, id);
        if (!keys.size) log('debug', `login by ${name} but no session cookie seen (JWT app?)`);
        return { name, id };
      }
      return null;
    }
```

- Line 85: `compiledLogin` is a RegExp compiled once by `config.js` from `identity.login.pathPattern`; `null` when the pattern is absent, which disables login learning entirely.
- Line 86: the name is taken from the **request** body first (the student typed it), falling back to the response. `reqBody` is whatever `parseBody` produced: JSON, form-urlencoded, or the simple fields of a multipart body.
- Line 87: the id can only come from the response (the app assigns it).
- Line 90: a JWT-only app sets no session cookie; the login is still returned so `server.js` can attribute that one request (`source: 'login'`), but nothing is remembered. Logged at `debug` level only.
- Line 93: a matching login path with no recognisable username yields `null` and does **not** fall through to the whoami block (the `if` returns in all branches).

```js
// lines 96-107
    // whoami
    const who = cfg.whoami || {};
    if (full.compiledWhoami && full.compiledWhoami.test(pathOnly) && resBody && typeof resBody === 'object') {
      const name = firstOf(resBody, who.nameFields || ['username']);
      const id = firstOf(resBody, who.idFields || ['id']);
      if (name || id) {
        for (const k of keys) this.remember(k, name, id);
        return { name: name || `user#${id}`, id };
      }
    }
    return null;
  }
```

- Whoami endpoints are not method-restricted. The response must have parsed to an object (an HTML profile page teaches nothing).
- Unlike login, an id alone is enough here: the display name becomes `user#<id>` and `remember` fills a name later if one is seen.

### `remember(sessionKey, name, id)`

```js
// lines 109-124
  remember(sessionKey, name, id) {
    const prev = this.sessions.get(sessionKey) || {};
    const entry = { name: name || prev.name || (id ? `user#${id}` : null), id: id || prev.id || null };
    if (!entry.name) return;
    const changed = prev.name !== entry.name || prev.id !== entry.id;
    this.sessions.set(sessionKey, entry);
    if (changed) {
      log('info', `identity learned: session ${shortHash(sessionKey)} -> ${entry.name}${entry.id ? ` (id ${entry.id})` : ''}`);
      if (this.onSessionNamed && prev.name !== entry.name) this.onSessionNamed(`sess-${shortHash(sessionKey)}`, entry.name);
    }
    // keep the map bounded
    if (this.sessions.size > 5000) {
      const first = this.sessions.keys().next().value;
      this.sessions.delete(first);
    }
  }
```

- Line 111: merging rule. A new name or id overrides; a missing one keeps the previous value; a missing name with a known id becomes `user#<id>`. This lets a whoami that only returns `{ id }` and a later login that only has a username build up one complete entry.
- Line 112: nothing is stored without a name, so `sessions.get()` never returns a nameless entry (which `resolveApp` line 62 relies on).
- Line 117: `onSessionNamed` fires only when the **name** changed, with the old anonymous label `sess-<hash>`. `server.js`'s `mergeLane` checks whether such a row exists in the store before renaming, so firing it for a session that was already named is harmless but is avoided anyway. Note the hook is called synchronously inside the request's `onEvent`; it must not throw.
- Lines 120-123: a `Map` iterates in insertion order, so deleting `keys().next().value` drops the oldest session. The bound is a memory guard, not an LRU: a re-learned session is not moved to the end.

### Export

```js
// line 127
module.exports = { IdentityResolver };
```

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` (`preRequest`, `onEvent`, `getTargetFor`) | `req` object; returns the identity object described above |
| in | `server.js` (`onEvent`) | `learn({ req, identity, reqBody, status, resHeaders, resBody, pathOnly })`; returns `{ name, id }` or `null` |
| out | `namegate.js` | `gate.nameFrom(req)` (signed cookie → raw name), `gate.rememberIp(ip, name)`, `gate.nameForIp(ip)` |
| out | `util.js` | cookie / JWT / body helpers, `clientIp`, `log` |
| out (hook) | `server.js` `mergeLane` via `identity.onSessionNamed` | `(anonLabel 'sess-xxxx', newName)` when a session gets a name |
| in (config) | `config.js` / `config/rules.json` | `identity.*`, `compiledLogin`, `compiledWhoami` |

## Changing it safely

| Likely change | Where |
|---|---|
| Support a new way the app identifies users (e.g. a custom `X-User` header) | Add a step inside `resolveApp()` between the JWT block (line 38) and the session block (line 51). Return the same object shape with a new `source` value, then check `server.js` `playerIdFor` (line 153) so the new source is treated as an app name. |
| Learn identities from another endpoint type (e.g. a registration response) | Copy the whoami block (lines 96-105); add a compiled regex in `config.js` next to `compiledWhoami` (line 39). |
| Change the precedence of gate name vs app name | `resolve()` lines 19-29 only. Keep `id` coming from `base`, or the IDOR detector loses "my own objects". |
| Persist learned sessions across restarts | `remember()` writes to `this.sessions`; add a `db.set('identity_sessions', …)` there and load in the constructor. Keep the 5000 bound. |

Tests: `proxy/test/core.test.js` → `identity: jwt, then session learned at login, then ip fallback` covers JWT cookie, IP fallback, `X-Forwarded-For`, the `sess-` label, `learn()` on a login and the subsequent `resolve()` with `id: '1001'`. The gate branches (`name`, `ip-match`) have no dedicated unit test; they are exercised indirectly through `gate.test.js` (`nameFrom` round-trip) and manually via the proxy.

## Exercises

1. **Add a whoami test.** In `proxy/test/core.test.js`, after the login assertion, call `id.learn({ req: req({ cookie: 'session=zzz' }), identity: id.resolve(req({ cookie: 'session=zzz' })), reqBody: null, status: 200, resHeaders: {}, resBody: { id: 7, username: 'trinity' }, pathOnly: '/api/me' })` and assert `id.resolve(req({ cookie: 'session=zzz' })).name === 'trinity'`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node --test test/core.test.js`
2. **Watch the ip-match branch.** Start the stack, open the CTF link in a browser and fill the gate form, then from the same machine run `curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8888/` (no cookie). With `strict: false` in the Gate tab the request passes and the dashboard attributes it to your gate name with source `ip-match`. With `strict: true` it is refused with HTTP 428.
   Verify: the printed status code is `200` vs `428`, and the Students table shows the row.
3. **Prove the failed-login guard.** Write a one-off script: `const { IdentityResolver } = require('./src/identity'); const r = new IdentityResolver(() => ({ identity: { sessionCookies: ['session'] }, compiledLogin: /^\/login$/ })); console.log(r.learn({ req: { method: 'POST', headers: {} }, identity: { sessionKey: 'abc' }, reqBody: { username: 'victim' }, status: 401, resHeaders: {}, resBody: null, pathOnly: '/login' }));`
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node -e "<script>"` prints `null` and `r.sessions.size` stays `0`.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `IdentityResolver` | `new IdentityResolver(getConfig, gate?)` | Attribution engine; one instance per process. |
| `.resolve(req)` | `(req) => { name, id, source, ip, sessionKey, appName? }` | Gate name → ip-match → JWT → session → IP. |
| `.resolveApp(req)` | `(req) => { name, id, source, ip, sessionKey }` | Same without the gate layer (`jwt` / `session` / `ip` only). |
| `.learn({...})` | `({ req, identity, reqBody, status, resHeaders, resBody, pathOnly }) => { name, id } \| null` | Binds session cookies to a student on successful login / whoami responses. |
| `.remember(key, name, id)` | `(sessionKey, name, id) => void` | Merge-and-store one session entry; fires `onSessionNamed` when the name changes. |
| `.onSessionNamed` | `(anonLabel, name) => void \| null` | Hook; set by `server.js` to merge the anonymous row. |
| `.sessions` | `Map<string, { name, id }>` | Learned sessions, max 5000. |

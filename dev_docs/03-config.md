# config — `proxy/src/config.js`, `config/rules.json`, `config/ownership.json`

## Purpose

All detection behaviour — how a student is identified, which URLs are IDOR targets, who owns which object, when a burst of IDs counts as enumeration, what gets masked, what gets ignored — lives in one JSON file, `config/rules.json`, with an optional companion `config/ownership.json`. `config.js` loads those files, turns the regex strings into `RegExp` objects, fills in defaults, and re-loads them automatically whenever a file in the config directory changes, so an instructor can tune rules during a live CTF without restarting the proxy.

## Where it sits

`config.js` requires `fs`, `path` and `log` from `./util`. It is instantiated exactly once, in `proxy/src/server.js` line 41 (`const config = new Config()`), and every consumer receives a *getter* (`getConfig = () => config.get()`) rather than the object, so they always read the latest compiled config: `IdentityResolver` and `Detector` are built with it (`server.js` lines 80-81), `server.js` itself reads `cfg.successMinBytes`, `cfg.maskFields` and `compiledIgnore`, and the dashboard serves the untouched JSON at `GET /api/config` through `getRawConfig: () => config.raw` (`server.js` line 329, `dashboard.js` line 157). Nothing currently calls `config.onChange`. Tests do **not** go through `config.js`: `core.test.js` hand-builds a compiled config object (lines 26-44) in the shape `compile()` produces.

## Data it owns

### The compiled config object (`config.get()`)

A deep copy of `rules.json` with these fields added or normalised. Everything else from the JSON (`identity.*`, `_help`, ...) is still present on the same object and read directly by `identity.js`.

| Field | Type | Meaning / default |
|---|---|---|
| `compiledEndpoints` | `Array<Endpoint>` (below) | IDOR rules from `endpoints.list` with a valid name + pattern, in file order. Rules whose regex fails to compile are dropped with an error log. |
| `compiledLogin` | `RegExp \| null` | `identity.login.pathPattern`, flag `i`; `null` if absent or invalid. |
| `compiledWhoami` | `RegExp \| null` | `identity.whoami.pathPattern`, flag `i`; `null` if absent or invalid. |
| `compiledIgnore` | `RegExp[]` | `ignore.pathPatterns`, each with flag `i`; invalid ones dropped; `[]` if absent. |
| `maskFields` | `string[]` lower-cased | `masking.fields`; default `['password','token','secret']` only when the key is missing. |
| `enumeration.distinctIds` | number | default `5` |
| `enumeration.windowSeconds` | number | default `30` |
| `bruteForce.errors` | number | default `15` |
| `bruteForce.windowSeconds` | number | default `20` |
| `bruteForce.statuses` | `Set<number>` | default `{401, 403, 404}` (the shipped `rules.json` adds `429`) |
| `successMinBytes` | number | `thresholds.successMinBytes.value`, default `2` |
| `learnFromFirstSuccess` | boolean | `true` unless `ownership.learnFromFirstSuccess` is literally `false` |
| `ownershipMap` | `{ [endpointName \| '*']: { [objectId: string]: ownerName: string } }` | parsed `ownership.json`; `{}` when the file is missing or unreadable |

### `Endpoint` (one element of `compiledEndpoints`)

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Rule name, also the key used in `ownershipMap` and shown on the dashboard as `endpoint`. |
| `methods` | `string[]` upper-case | HTTP methods the rule applies to; **empty array = any method**. |
| `re` | `RegExp` (flag `i`) | Tested against the request path *without* query string (`pathOnly`). |
| `idFrom` | `'path' \| 'query:<p>' \| 'body:<f>'` | Where the object id comes from; default `'path'`. |
| `idParam` | `string \| null` | The `<p>` / `<f>` part of `idFrom`, `null` for `'path'`. |
| `owner` | string | Ownership policy word; default `'auto'`. Not validated (see walkthrough). |

### `Config` instance

| Field | Type | Meaning |
|---|---|---|
| `current` | compiled config or `null` | Latest successfully compiled config. Replaced wholesale, never mutated. |
| `raw` | parsed JSON | The untouched `rules.json` content of the last successful load (served to the dashboard). Undefined until the first success. |
| `listeners` | `Array<(cfg) => void>` | Callbacks run after every successful load. |

## Walkthrough

### Header and `CONFIG_DIR`

```js
// lines 1-6
'use strict';
const fs = require('fs');
const path = require('path');
const { log } = require('./util');

const CONFIG_DIR = process.env.CONFIG_DIR || path.join(__dirname, '..', '..', 'config');
```

Line 6 decides where the JSON lives: the `CONFIG_DIR` environment variable if set, otherwise `<repo>/config` (two directories up from `proxy/src`). This value is exported so other code can print or reuse it. `rules.json` is always looked up inside this directory with that fixed name; the ownership file name is configurable but is also joined onto this directory (`path.join` does not treat an absolute second argument specially, so give a relative name).

### `safeRegex(pattern, label)`

```js
// lines 8-15
function safeRegex(pattern, label) {
  try {
    return new RegExp(pattern, 'i');
  } catch (err) {
    log('error', `rules.json: bad pattern for ${label}: ${err.message}`);
    return null;
  }
}
```

Every pattern in `rules.json` passes through here. Two facts to remember: (1) **all patterns are case-insensitive** (`'i'`), so `^/api/users/` also matches `/API/Users/`; there is no `u` or `g` flag; (2) a syntax error does not abort loading — it is logged with a label (`endpoint "orders"`, `identity.login`, `ignore`) and the caller gets `null`, which it then filters out. A typo therefore silently disables one rule rather than the whole file; watch the startup log.

### `compile(raw)` — endpoints

```js
// lines 17-35
function compile(raw) {
  const cfg = JSON.parse(JSON.stringify(raw)); // deep copy
  const endpoints = (cfg.endpoints && cfg.endpoints.list) || [];
  cfg.compiledEndpoints = endpoints
    .filter((e) => e && e.pattern && e.name)
    .map((e) => {
      const re = safeRegex(e.pattern, `endpoint "${e.name}"`);
      if (!re) return null;
      const idFrom = e.idFrom || 'path';
      return {
        name: e.name,
        methods: (e.methods || []).map((m) => m.toUpperCase()),
        re,
        idFrom,
        idParam: idFrom.startsWith('query:') ? idFrom.slice(6) : idFrom.startsWith('body:') ? idFrom.slice(5) : null,
        owner: e.owner || 'auto',
      };
    })
    .filter(Boolean);
```

- Line 18: a JSON round-trip deep copy, so the compiled fields are added to a copy and `this.raw` (what the dashboard shows) stays exactly what was on disk.
- Line 21: a rule needs both `name` and `pattern`; an entry missing either is dropped **without any log message**. `_help` strings inside `list` would also just be filtered out, but the shipped file keeps help at the `endpoints` level.
- Line 24: an invalid regex becomes `null` and is removed by the final `.filter(Boolean)` (line 35).
- Line 28: methods are upper-cased so the file may say `get`; an absent or empty `methods` means "match every method" (`detect.js` line 37: `if (ep.methods.length && !ep.methods.includes(method)) continue`).
- Line 31: `idParam` is derived by slicing off the `query:` (6 chars) or `body:` (5 chars) prefix. For `'path'`, or any unrecognised string, it is `null`. `detect.js` then uses `m.groups.id` for `'path'`, `new URL(url).searchParams.get(idParam)` for `query:`, and `reqBody[idParam]` for `body:`. Two gotchas follow directly: a `'path'` rule whose pattern has no `(?<id>...)` group yields `undefined` and the rule **never matches anything** (silently); an unknown `idFrom` word is kept verbatim and falls through every branch in `detect.js`, so it never matches either.
- Line 32: `owner` defaults to `'auto'` and is **not validated**. The five meaningful words are `auto`, `same-as-user`, `map`, `learn`, `none` (explained under `rules.json` below). Reading `detect.js` `ownerOf`, any other word is treated like `map` in effect: the ownership map is consulted, nothing is learned.
- Order is preserved; `detect.js` iterates the array and stops at the first match, so put specific rules before catch-alls.

### `compile(raw)` — identity, masking, thresholds

```js
// lines 37-56
  const id = cfg.identity || {};
  cfg.compiledLogin = id.login && id.login.pathPattern ? safeRegex(id.login.pathPattern, 'identity.login') : null;
  cfg.compiledWhoami = id.whoami && id.whoami.pathPattern ? safeRegex(id.whoami.pathPattern, 'identity.whoami') : null;
  cfg.compiledIgnore = ((cfg.ignore && cfg.ignore.pathPatterns) || []).map((p) => safeRegex(p, 'ignore')).filter(Boolean);
  cfg.maskFields = ((cfg.masking && cfg.masking.fields) || ['password', 'token', 'secret']).map((f) => String(f).toLowerCase());

  const th = cfg.thresholds || {};
  cfg.enumeration = {
    distinctIds: (th.enumeration && th.enumeration.distinctIds) || 5,
    windowSeconds: (th.enumeration && th.enumeration.windowSeconds) || 30,
  };
  cfg.bruteForce = {
    errors: (th.bruteForce && th.bruteForce.errors) || 15,
    windowSeconds: (th.bruteForce && th.bruteForce.windowSeconds) || 20,
    statuses: new Set((th.bruteForce && th.bruteForce.statuses) || [401, 403, 404]),
  };
  cfg.successMinBytes = (th.successMinBytes && th.successMinBytes.value) || 2;
  cfg.learnFromFirstSuccess = !(cfg.ownership && cfg.ownership.learnFromFirstSuccess === false);
  return cfg;
}
```

- Lines 38-39: only the two `pathPattern` strings are compiled. The rest of `identity` (cookie names, claim lists, `login.methods`, `userFields`, ...) is left as plain data; `identity.js` reads it straight from `cfg.identity` with its own fallbacks (e.g. `loginCfg.methods || ['POST']`).
- Line 40: the ignore list compiles to an array of regexes; `server.js` `shouldIgnore(pathOnly)` runs `.some(re => re.test(pathOnly))`.
- Line 41: mask words are lower-cased here because `mask.isSensitive` lower-cases names but not the field list. The default applies only when `masking.fields` is **absent**; an explicit empty array `[]` is truthy, so it is kept and masking is effectively off.
- Lines 44-53: every threshold uses `||`, so `0` is impossible — writing `"distinctIds": 0` silently gives you the default `5`. `statuses` becomes a `Set` because `detect.js` does `cfg.bruteForce.statuses.has(ev.status)` on every response. The default `[401, 403, 404]` differs from the shipped file, which also lists `429`.
- Line 54: `learnFromFirstSuccess` is `true` for anything except an explicit JSON `false` (a string `"false"` would still be `true`).

### `loadOwnership(cfg)`

```js
// lines 58-74
function loadOwnership(cfg) {
  const file = (cfg.ownership && cfg.ownership.file) || 'ownership.json';
  const p = path.join(CONFIG_DIR, file);
  const map = {};
  if (!fs.existsSync(p)) return map;
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    for (const [endpoint, ids] of Object.entries(raw)) {
      if (endpoint.startsWith('_') || !ids || typeof ids !== 'object') continue;
      map[endpoint] = {};
      for (const [oid, owner] of Object.entries(ids)) map[endpoint][String(oid)] = String(owner);
    }
  } catch (err) {
    log('error', `ownership.json could not be read: ${err.message}`);
  }
  return map;
}
```

- Line 59-60: file name from `rules.json` `ownership.file`, default `ownership.json`, resolved inside `CONFIG_DIR`.
- Line 62: a missing file is normal (the map is optional) and returns `{}` with no log line.
- Line 66: top-level keys starting with `_` (the `_help` text) are skipped, as is any key whose value is not an object. Keys are endpoint rule names or `*`.
- Line 68: both object ids and owner names are coerced to strings so lookups by `objectId` (always a string in `detect.js`) work even if someone wrote a number. JSON keys are strings anyway; the `String()` on the owner side matters if a value were written as a number.
- Lines 70-72: a parse error is logged and the function returns whatever was built before the throw — which, since `JSON.parse` fails before the loop, is `{}`. The main config still loads.

### `class Config` — constructor and `reload()`

```js
// lines 76-97
class Config {
  constructor() {
    this.listeners = [];
    this.current = null;
    this.reload();
    this.watch();
  }
  reload() {
    const p = path.join(CONFIG_DIR, 'rules.json');
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      const cfg = compile(raw);
      cfg.ownershipMap = loadOwnership(cfg);
      this.current = cfg;
      this.raw = raw;
      log('info', `config loaded from ${p} (${cfg.compiledEndpoints.length} endpoint rules)`);
      for (const l of this.listeners) l(cfg);
    } catch (err) {
      log('error', `could not load ${p}: ${err.message}${this.current ? ' - keeping previous config' : ''}`);
      if (!this.current) throw err;
    }
  }
```

- Lines 80-81: the constructor loads synchronously and then starts the watcher, so by the time `new Config()` returns, `get()` is usable. `raw` is not initialised in the constructor; it exists only after the first successful load.
- Line 86-88: read → parse → compile → attach the ownership map. Only after all of that succeeds are `current` and `raw` swapped (lines 89-90). A consumer that grabbed `cfg = getConfig()` at the start of a request keeps a consistent snapshot even if a reload happens mid-request, because the old object is never mutated.
- Line 91: the info line is your confirmation that a hot reload took effect; the count tells you whether a rule was dropped by `safeRegex` or the name/pattern filter.
- Line 92: listeners fire on every successful load, including the first one (nobody can have registered yet at that point, so in practice only on reloads). No module registers a listener today.
- Lines 93-96: two different failure modes. **First load** (`this.current` is still `null`): the error is logged and re-thrown, so `new Config()` throws and `server.js` crashes at startup — a broken `rules.json` cannot start the proxy. **Later reload**: the error is logged with "keeping previous config" and the old config stays active; `raw` also stays at the old version, so the dashboard keeps showing the last good file. Note that a regex syntax error is *not* a load failure (it is handled inside `safeRegex`); only unreadable files and invalid JSON reach this `catch`.

### `watch()`, `onChange()`, `get()`

```js
// lines 98-117
  watch() {
    let timer = null;
    try {
      fs.watch(CONFIG_DIR, { persistent: false }, () => {
        clearTimeout(timer);
        timer = setTimeout(() => this.reload(), 300);
      });
    } catch (err) {
      log('info', `config hot-reload unavailable (${err.message})`);
    }
  }
  onChange(fn) {
    this.listeners.push(fn);
  }
  get() {
    return this.current;
  }
}

module.exports = { Config, CONFIG_DIR };
```

- Line 101: the watcher is on the **directory**, not on `rules.json`. This is deliberate: many editors save by writing a temp file and renaming it, which would break a per-file watcher; and it means a change to `ownership.json` (or any file in the folder) also triggers a reload, which re-reads the ownership map too. The callback ignores which file changed.
- Lines 102-103: a 300 ms debounce collapses the multiple events one save produces (and an editor's temp file + rename) into a single `reload()`. Any error inside that reload is handled by `reload()` itself, so the watcher never dies.
- `persistent: false` means the watcher does not keep the Node event loop alive — a one-off script that does `new Config()` and nothing else exits normally (that is why the exercise one-liners below terminate).
- Lines 105-107: if `fs.watch` throws (unsupported filesystem, permissions) the proxy still runs; it just needs a restart after editing rules. Known platform caveat: `fs.watch` may not deliver events on some network or virtualised filesystems.
- `onChange` is a simple subscriber list; `get` returns the current compiled object. Both are trivial on purpose — all consumers call `getConfig()` per request rather than caching.

---

## `config/rules.json` — field by field

The file is plain JSON, so every regex backslash is doubled (`\\d`). Every key named `_help` is ignored by the loader (never read by `compile()`); it exists purely as in-file documentation and is shown verbatim on the dashboard's config view.

### Top-level `_help` (lines 2-7)

Four sentences summarising the rules below; no effect on behaviour.

### `identity` (lines 9-32)

```jsonc
// lines 11-17
"jwt": {
  "cookies": ["token", "jwt", "auth", "access_token", "authToken"],
  "headers": ["authorization"],
  "nameClaims": ["username", "user", "name", "email", "login", "preferred_username", "user.username", "user.name"],
  "idClaims": ["id", "userId", "user_id", "uid", "sub", "user.id"]
},
"sessionCookies": ["session", "connect.sid", "PHPSESSID", "sessionid", "sid", "JSESSIONID", "laravel_session", "ctf_session"],
```

Read by `identity.js` `resolveApp` (lines 39-63), which tries three strategies in order:

| Key | Used how |
|---|---|
| `jwt.cookies` | Cookie names (exact, case-sensitive — `parseCookies` keeps case) whose value is tried as a JWT, in this order. |
| `jwt.headers` | Request header names tried as JWTs. **Must be lower-case** because Node lower-cases incoming header names and the lookup is `req.headers[h]`. A `Bearer ` prefix is stripped by `decodeJwt`. |
| `jwt.nameClaims` | Dotted paths into the JWT payload, first non-empty scalar wins (`util.firstOf`), becomes the student name. Default in code if absent: `['username','sub']`. |
| `jwt.idClaims` | Same, for the student's own user id (used by the `same-as-user` / `auto` ownership rules). Default `['id','sub']`. If a name is missing but an id exists the student is shown as `user#<id>`. |
| `sessionCookies` | Cookie names, first present wins; the value is the session key. Until a login is observed the student is labelled `sess-<shortHash>`. |

```jsonc
// lines 18-31
"login": {
  "methods": ["POST"],
  "pathPattern": "^/(api/)?(auth/)?(login|signin|session)s?$",
  "userFields": ["username", "email", "user", "login", "name"],
  "responseIdFields": ["id", "userId", "user_id", "user.id"],
  "responseNameFields": ["username", "user.username", "name", "email"]
},
"whoami": {
  "pathPattern": "^/(api/)?(me|profile|whoami|user/me|users/me)$",
  "idFields": ["id", "userId", "user_id", "user.id"],
  "nameFields": ["username", "user.username", "name", "email"]
}
```

`login` is read by `identity.learn` (lines 83-96). When a request matches `compiledLogin` **and** its method is in `methods` (default `POST`), the monitor remembers "this session cookie belongs to this username": the name is `firstOf(reqBody, userFields)` falling back to `firstOf(resBody, responseNameFields)`; the id is `firstOf(resBody, responseIdFields)`. The password field is never read. `pathPattern` piece by piece: `^/` root; `(api/)?` optional `api/` prefix; `(auth/)?` optional `auth/`; `(login|signin|session)` one of three words; `s?` optional plural; `$` nothing after (query strings are not part of `pathOnly`). With the `i` flag, `/API/Auth/Login` matches too.

`whoami` (lines 97-100 of `identity.js`) covers endpoints that return the current user: when `compiledWhoami` matches and the response body is an object, name and id are learned from it using `nameFields` / `idFields`. The pattern lists the usual `me`-style paths, anchored both ends.

### `endpoints` (lines 34-51)

The `_help` block (lines 35-43) documents the per-rule keys; the loader reads `list` only.

| Rule key | Meaning |
|---|---|
| `name` | Required. Label for the dashboard, key in `ownership.json`, and key of the detector's per-endpoint ID windows. |
| `methods` | Optional array; omitted = every method. |
| `pattern` | Required. Regex tested against the path without query string. For `idFrom: "path"` it must contain a named group `(?<id>...)`. |
| `idFrom` | `"path"` (default), `"query:<param>"` (read from the URL query), `"body:<field>"` (read from the parsed request body, top-level key only). |
| `owner` | Ownership policy, see below. Default `"auto"`. |

Ownership policies (as implemented in `detect.js` `ownerOf` and the learning block, lines 61-80 and 163-170):

- `auto` — the `ownership.json` map first; then "the object id equals the student's own user id" (basis `self`); then whatever was learned earlier; and, if still unknown and the request was a quiet (non-enumerating) 2xx with data, the student **learns** ownership (when `learnFromFirstSuccess` is on).
- `same-as-user` — the map is ignored; the object id must equal the student's id. Nothing is learned from success (the `self` basis is recorded when it matches).
- `map` — only `ownership.json`; never learns.
- `learn` — the map is ignored; first quiet success owns it.
- `none` — only enumeration / sequence tracking; ownership is never computed, so no `idor-*` flags.

The five shipped rules (lines 45-49):

```jsonc
// lines 45-49
{ "name": "user profile", "pattern": "^/api/users/(?<id>[^/?]+)", "owner": "auto" },
{ "name": "orders",       "pattern": "^/api/orders/(?<id>[^/?]+)", "owner": "auto" },
{ "name": "invoice",      "pattern": "^/api/invoices?$", "idFrom": "query:id", "owner": "auto" },
{ "name": "messages",     "pattern": "^/api/messages/(?<id>[^/?]+)", "owner": "auto" },
{ "name": "generic numeric id", "pattern": "^/(?!static|assets|public)[^?]*/(?<id>\\d{2,})(/|$)", "owner": "learn" }
```

1. **user profile** — `^/api/users/` literal prefix, then `(?<id>[^/?]+)`: one or more characters that are neither `/` nor `?`, captured as `id`. Not anchored at the end, so `/api/users/5/orders` also matches with id `5`. Ids may be non-numeric (`alice`, UUIDs). `owner: auto` means a student reading `/api/users/<their own id>` is recognised via the `self` basis.
2. **orders** — identical shape for `/api/orders/<id>`.
3. **invoice** — `^/api/invoices?$`: `invoice` with an optional `s`, and `$` so the path must end there (the query string is not part of the tested path). The id comes from `?id=...` (`idFrom: "query:id"`); a request without `id` does not match this rule and falls through to the next.
4. **messages** — same shape as orders.
5. **generic numeric id** — the catch-all, last on purpose. `^/` root; `(?!static|assets|public)` negative lookahead: the path must not start with those three words (static assets often have numeric names); `[^?]*` any run of non-`?` characters, **greedy and allowed to contain slashes**; `/` a slash; `(?<id>\d{2,})` two or more digits; `(/|$)` followed by a slash or the end. Because `[^?]*` is greedy the engine prefers the *last* qualifying numeric segment: `/a/12/b/34` captures `34`. Single-digit ids never match. `owner: learn` because for unknown apps there is no way to know an owner except by observing the first quiet read.

Because the first matching rule wins, a URL like `/api/orders/42` is reported as `orders`, never as `generic numeric id`.

### `ownership` (lines 53-57)

| Key | Meaning |
|---|---|
| `file` | File name of the ownership map inside `CONFIG_DIR`. Default `ownership.json`. |
| `learnFromFirstSuccess` | `true` (default): rules `auto` and `learn` may learn an owner from a quiet successful read. Set to literally `false` to trust only the map and `same-as-user`. |

### `thresholds` (lines 59-63)

| Key | Meaning (from `detect.js`) | Shipped | Code default |
|---|---|---|---|
| `enumeration.distinctIds` | Number of *different* object ids on the same endpoint, by the same student, inside the window, that raises the `enumeration` flag (and un-learns ownership gained during the burst). | 5 | 5 |
| `enumeration.windowSeconds` | Sliding window length for the above. | 30 | 30 |
| `bruteForce.errors` | Number of responses with a status in `statuses`, by the same student, inside the window, that raises `burst-errors`. | 15 | 15 |
| `bruteForce.windowSeconds` | Window for the above. | 20 | 20 |
| `bruteForce.statuses` | Which status codes count as errors. | 401, 403, 404, 429 | 401, 403, 404 |
| `successMinBytes.value` | A 2xx needs at least this many response-body bytes to count as "contains data" (so an `idor-attempt` becomes `idor-success`). `server.js` additionally treats a JSON body whose only keys are `error`/`message`/`status`-like as no data. | 2 | 2 |

Remember the `||` defaults: none of these can be set to `0`.

### `masking` (lines 65-68)

`fields` is the word list for `mask.js`. A field or query-parameter *name* that **contains** any of these (case-insensitive) is replaced by `***` in stored bodies and paths. The shipped list — `password, passwd, pass, pwd, token, secret, otp, csrf, authorization, apikey, api_key, credit, card, cvv` — is intentionally stem-based; be aware that `pass` also hits `passenger`/`bypass`, and `card` hits `cardinal`/`discard`. Values are never inspected (a JWT in a field called `jwt` is not masked by this list; `maskText` only runs on the path).

### `ignore` (lines 70-73)

```jsonc
// line 72
"pathPatterns": ["\\.(css|js|map|png|jpe?g|gif|svg|ico|webp|woff2?|ttf)$", "^/favicon", "^/health$"]
```

Requests whose path matches any pattern are proxied but **not logged, not shown, not used for identity learning**. Pattern 1: a literal dot (`\\.` in JSON, `\.` in regex), one of the listed extensions (`jpe?g` = jpg/jpeg, `woff2?` = woff/woff2), `$` end of path. Pattern 2: anything starting with `/favicon`. Pattern 3: exactly `/health`. All case-insensitive. Do not add your login or API paths here, or identity learning and detection stop for them.

---

## `config/ownership.json` — format

```jsonc
// lines 1-4
{
  "_help": "Optional. Who owns which object ID. Keys are endpoint names from rules.json, or '*' for every endpoint. Leave empty to let the monitor learn.",
  "*": {}
}
```

| Key | Value | Meaning |
|---|---|---|
| `_help` (any key starting with `_`) | string | Ignored by `loadOwnership`. |
| `"<endpoint name>"` | `{ "<objectId>": "<student name>", ... }` | Fixed owners for one rule. The key must equal the rule's `name` in `rules.json` exactly (case-sensitive, e.g. `"user profile"`). |
| `"*"` | same object shape | Fallback owners for every endpoint; consulted only when the endpoint-specific entry has no match (`detect.js` line 62: `map[ep.name][objectId] || map['*'][objectId]`). |

Object ids are JSON keys, hence strings; `detect.js` always compares string ids, so `"9"` matches `/api/orders/9` (the test `detector: ownership map, learning, idor attempt vs success, enumeration and bursts` uses `{ orders: { 9: 'carol' } }`). The owner value must equal the student name as the detector sees it (`ev.student.name`, which `server.js` builds after applying dashboard aliases via `withAlias`). The shipped file is effectively empty (`"*": {}`), which means "learn everything". Edits to this file are picked up live because the directory watcher triggers `reload()`, which calls `loadOwnership` again. The map is honoured by `auto` and `map` rules and ignored by `learn`, `same-as-user` and `none`.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in ← | `config/rules.json` | read + `JSON.parse` on construction and on every directory change event (300 ms debounce) |
| in ← | `config/ownership.json` (or `ownership.file`) | read inside every `reload()`; parsed into `cfg.ownershipMap` |
| in ← | `process.env.CONFIG_DIR` | overrides the config directory (default `<repo>/config`) |
| in ← | `fs.watch(CONFIG_DIR)` | change events → debounced `reload()` |
| out → | `proxy/src/util.js` | `log('info' \| 'error', ...)` for loads, bad patterns, unreadable files |
| out → | `proxy/src/server.js` | `new Config()` once; `config.get()` per request (`successMinBytes`, `maskFields`, `compiledIgnore`); `config.raw` for the dashboard `/api/config` |
| out → | `proxy/src/identity.js` | via `getConfig()`: `identity.*` raw sections, `compiledLogin`, `compiledWhoami` |
| out → | `proxy/src/detect.js` | via `getConfig()`: `compiledEndpoints`, `ownershipMap`, `enumeration`, `bruteForce`, `learnFromFirstSuccess` |
| out → | `proxy/src/dashboard.js` | `getRawConfig()` → `GET /api/config` returns the untouched JSON |
| tests | `proxy/test/core.test.js` | no direct test of `config.js`; the compiled *shape* is hand-written on lines 26-44 and consumed by the identity and detector tests |

## Changing it safely

1. **Adding a new per-rule option** (e.g. `idFrom: "header:<name>"`): extend the object built on lines 26-33 (and the `idParam` derivation on line 31), then teach `detect.js` `matchEndpoint` to read it. Update the hand-built `compiledEndpoints` in `core.test.js` lines 35-38 only if the new field is mandatory. There is no unit test for `compile()` itself; the detector tests (`detector: ownership map, learning, idor attempt vs success, enumeration and bursts`, `detector: renaming a student carries state and learned ownership`) are the contract for the `Endpoint` shape.
2. **Adding a new threshold or top-level section**: add a line next to lines 44-54 with a `||` default (or a `??` default if `0` must be allowed), document it with a `_help` entry in `rules.json`, and add the field to the test config object in `core.test.js` (lines 26-44) so the consumers' tests keep passing.
3. **Changing how ownership is loaded** (e.g. several files, or validation of owner names): `loadOwnership` lines 58-74. The map shape is asserted indirectly by the `/api/orders/9` → `carol` case in the detector test.
4. **Changing regex flags or validation** (e.g. dropping case-insensitivity, or making a bad pattern fatal): `safeRegex` lines 8-15. The identity test uses hand-compiled regexes without the `i` flag, so it will not notice — verify with the exercise below.

Always run `cd proxy && npm test` and additionally start the proxy once and read the `config loaded from ... (N endpoint rules)` line to confirm no rule was silently dropped.

## Exercises

1. **See the compiled shape.** Load the real config and print each endpoint rule as the detector sees it.
   ```
   cd proxy && node -e "const {Config}=require('./src/config');const g=new Config().get();console.log(g.compiledEndpoints.map(e=>[e.name,e.idFrom,e.idParam,e.owner]));console.log(g.bruteForce.statuses, g.maskFields.length, g.compiledIgnore.length)"
   ```
   Expected: five rows, the third being `[ 'invoice', 'query:id', 'id', 'auto' ]`, followed by `Set(4) { 401, 403, 404, 429 } 14 3`. The process exits by itself because the watcher is non-persistent.

2. **A bad pattern is dropped, not fatal.** Copy the config folder somewhere temporary, break the `orders` pattern by hand (for example remove the closing `)` so it reads `"^/api/orders/(?<id>[^/?]+"`), and load it through `CONFIG_DIR`.
   ```
   cp -r config /tmp/cfgtest      # PowerShell: Copy-Item -Recurse config $env:TEMP\cfgtest
   # edit /tmp/cfgtest/rules.json as described
   cd proxy && CONFIG_DIR=/tmp/cfgtest node -e "const {Config}=require('./src/config');console.log(new Config().get().compiledEndpoints.map(e=>e.name))"
   # PowerShell: $env:CONFIG_DIR="$env:TEMP\cfgtest"; node -e "..."
   ```
   Expected: an `[error] rules.json: bad pattern for endpoint "orders": ...` line, then `config loaded ... (4 endpoint rules)` and a list without `orders`. Now also delete a comma to make the JSON invalid and rerun: the process throws `SyntaxError` at `new Config()` because there is no previous config to keep.

3. **Hot reload.** Keep a `Config` alive, then save `config/rules.json` (even without changes) from another terminal.
   ```
   cd proxy && node -e "const {Config}=require('./src/config');const c=new Config();c.onChange(g=>console.log('reloaded,',g.compiledEndpoints.length,'rules'));setInterval(()=>{},1e9)"
   ```
   Expected: after each save, within about 300 ms, a second `config loaded from ...` line followed by `reloaded, 5 rules`. Touching `config/ownership.json` triggers the same, because the watcher is on the directory. Stop with Ctrl+C.

## Quick reference

| Export | Signature | One line |
|---|---|---|
| `Config` | `new Config()` | Loads `rules.json` + `ownership.json` from `CONFIG_DIR` synchronously (throws if the first load fails) and watches the directory for changes. |
| `Config#get` | `get() → compiledConfig` | The current compiled config (see "Data it owns"); call per request, never cache across requests. |
| `Config#reload` | `reload() → void` | Re-read and recompile; keeps the previous config on failure after the first load; notifies listeners on success. |
| `Config#onChange` | `onChange(fn: (cfg) => void) → void` | Register a callback for successful reloads. |
| `Config#watch` | `watch() → void` | (called by the constructor) non-persistent `fs.watch` on the directory with a 300 ms debounce. |
| `Config#raw` | property | Untouched parsed `rules.json` of the last successful load; served at `/api/config`. |
| `CONFIG_DIR` | `string` | `process.env.CONFIG_DIR` or `<repo>/config`. |
| (internal) `compile` | `compile(raw) → compiledConfig` | Deep-copies the JSON and adds the compiled fields and defaults. |
| (internal) `safeRegex` | `safeRegex(pattern, label) → RegExp \| null` | `new RegExp(pattern, 'i')`, logging and returning `null` on a syntax error. |
| (internal) `loadOwnership` | `loadOwnership(cfg) → map` | Reads the ownership file into `{ endpoint: { id: owner } }`, skipping `_` keys. |

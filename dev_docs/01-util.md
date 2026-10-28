# util — `proxy/src/util.js`

## Purpose

`util.js` is the toolbox every other proxy module reaches for: dotted-path lookup into parsed JSON, cookie / `Set-Cookie` / JWT / request-body parsing, client-IP extraction, a timestamped logger and a best-effort MAC-address lookup. It exists so that identity resolution (`identity.js`), the request pipeline (`server.js`) and the name gate (`namegate.js`) do not each re-implement the same fragile parsing. Every function is pure except `macFor`, which keeps a small cache and shells out to `ip neigh`.

## Where it sits

`util.js` is the bottom of the dependency graph: it requires only Node built-ins (`crypto` at load time, `child_process` lazily inside `macFor`) and **must never require another project module**, because `config.js` requires `util.js` for `log` and a cycle would break startup. Every file in `proxy/src` imports `log` from here. The parsing helpers are consumed by `identity.js` (`firstOf`, `shortHash`, `parseCookies`, `parseSetCookies`, `decodeJwt`, `clientIp`), `server.js` (`parseBody`, `clientIp`, `macFor`), `namegate.js` (`parseCookies`, `clientIp`) and `dashboard.js` (`clientIp`). `get` and `nowIso` are exported but, as of this code, only used inside `util.js` itself.

## Data it owns

The module holds one piece of state, `macCache`. The rest of the table describes the shapes the helpers return, since callers depend on them.

| Structure | Shape | Meaning of each field |
|---|---|---|
| `macCache` (module-level `Map`) | `Map<string, string \| null>` | key = IPv4 address as text; value = lower-case MAC `aa:bb:cc:dd:ee:ff`, or `null` when the neighbour table had no entry. Never evicted for the life of the process. |
| `parseCookies()` result | `{ [name: string]: string }` | one key per `name=value` pair of the `Cookie` request header; value is the raw (not URL-decoded) text after the first `=`. |
| `parseSetCookies()` result | `Array<{ name: string, value: string }>` | one entry per `Set-Cookie` response header; only the `name=value` part, attributes (`Path`, `HttpOnly`, ...) are dropped. |
| `decodeJwt()` result | `object \| null` | the decoded JWT *payload* (second segment) as a JS value, or `null` if the input is not shaped like a JWT. Signature is **not** verified. |
| `parseBody()` result | `object \| array \| null` | JSON value, flat `{field: value}` object for form bodies, or `null` when empty / unparseable. |
| log line | `[<ISO time>] [<level>] <args...>` | written with `console.error` for `error`, `console.log` otherwise. |

## Walkthrough

### Module header

```js
// lines 1-2
'use strict';
const crypto = require('crypto');
```

Strict mode for the whole file. `crypto` is only used by `shortHash`. Nothing else is loaded at require time, which keeps `util.js` cheap and dependency-free.

### `get(obj, path)` — dotted-path lookup

```js
// lines 4-13
function get(obj, path) {
  if (!obj || typeof obj !== 'object') return undefined;
  const parts = path.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[p];
  }
  return cur;
}
```

- Line 5: anything that is not an object (including `null`, strings, numbers) yields `undefined` immediately. Arrays are objects, so `get(arr, '0.id')` works.
- Line 6: the path is split on literal dots. There is no escaping, so a key that itself contains a dot cannot be addressed. Bracket syntax (`a[0]`) is not supported; use `a.0`.
- Line 9: before each step the current value must be a non-null object, otherwise the walk stops with `undefined` (this is what makes `user.id` safe when `user` is missing). `cur == null` (loose) covers both `null` and `undefined`.
- Line 10: plain property read; prototype properties would be visible (e.g. `get({}, 'constructor')` returns a function). Callers only pass JSON-derived objects and config-chosen paths, so this is not a practical problem, but keep it in mind if you ever feed user-controlled *paths* in.
- The function is exported but nothing outside this file imports it; its real job is to serve `firstOf`.

### `firstOf(obj, paths)` — first usable scalar

```js
// lines 15-21
function firstOf(obj, paths) {
  for (const p of paths) {
    const v = get(obj, p);
    if (v !== undefined && v !== null && v !== '' && typeof v !== 'object') return String(v);
  }
  return null;
}
```

This is the workhorse behind every "which field holds the username / user id" question in `identity.js`. The `paths` array comes straight from `rules.json` (`nameClaims`, `idClaims`, `userFields`, `responseIdFields`, ...), so **order in the config is priority order**.

- Line 18: a value is accepted only if it is not `undefined`, not `null`, not the empty string and not an object (so nested objects and arrays are skipped, never stringified to `[object Object]`). Note that `0` and `false` **are** accepted and become `'0'` / `'false'` — a user id of `0` is therefore preserved.
- The result is always a string (`String(v)`) so that ids compare consistently later (`detect.js` compares `String(student.id) === objectId`).
- Returns `null`, not `undefined`, when nothing matched; callers test with `||`.

### `shortHash(s)` — 8-hex-char label

```js
// lines 23-25
function shortHash(s) {
  return crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 8);
}
```

SHA-1 of the stringified input, first 8 hex characters (32 bits). Used by `identity.js` to turn an opaque session-cookie value into a stable, non-secret display name `sess-1a2b3c4d`, and in log lines. This is a *label*, not a security primitive: collisions are possible (birthday bound around 65k sessions) and SHA-1 is fine for that. `String(s)` means Buffers and numbers are accepted; `undefined` hashes as the text `"undefined"`.

### `parseCookies(header)` — request `Cookie` header

```js
// lines 27-38
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}
```

- Line 29: missing header returns an empty object, so callers can index it without guarding.
- Line 30: the header is split on `;`. Per RFC 6265 pairs are separated by `; ` but the code trims each side, so sloppy clients work too.
- Lines 31-32: split on the **first** `=` only, so a value that itself contains `=` (base64, `x=y`) is kept intact: `b=x=y` becomes `{ b: 'x=y' }`. A part with no `=` at all (e.g. a bare flag) is skipped.
- Line 35: an empty name (`=d`) is dropped. Duplicate names: the last one wins. Values are **not** URL-decoded and surrounding quotes are not stripped; `identity.js` uses the raw text as the session key, which is exactly what you want (it must match byte-for-byte what the app set).

### `parseSetCookies(arr)` — response `Set-Cookie` headers

```js
// lines 40-49
function parseSetCookies(arr) {
  const out = [];
  for (const sc of arr || []) {
    const first = String(sc).split(';')[0];
    const i = first.indexOf('=');
    if (i < 0) continue;
    out.push({ name: first.slice(0, i).trim(), value: first.slice(i + 1).trim() });
  }
  return out;
}
```

- Node always exposes `set-cookie` as an **array** of strings (one per header), which is what this expects; `arr || []` tolerates the header being absent. If you ever pass a single string instead, `for...of` would iterate its characters — always pass the array.
- Line 43: only the text before the first `;` is kept, i.e. `name=value`; cookie attributes such as `Path`, `Expires`, `HttpOnly` are discarded because the monitor only needs to know *which session value was issued*.
- Unlike `parseCookies` this returns an array, not an object, because the same cookie name can legitimately be set twice in one response (e.g. clear then set) and order matters to `identity.learn`.

### `decodeJwt(token)` — read a JWT payload without verifying it

```js
// lines 51-63
function decodeJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const t = token.replace(/^Bearer\s+/i, '').trim();
  const parts = t.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const payload = JSON.parse(json);
    return payload && typeof payload === 'object' ? payload : null;
  } catch {
    return null;
  }
}
```

- Line 53: strips an optional `Bearer ` prefix. Regex: `^` start, `Bearer` literal, `\s+` one or more whitespace, flag `i` so `bearer` / `BEARER` work. This lets the same function handle both the `Authorization` header and a cookie value.
- Line 55: a JWT is `header.payload.signature`; anything without exactly three dot-separated parts is rejected (`'not a jwt'` → `null`, a two-part token → `null`).
- Line 57: the payload is base64url. Node's `'base64'` decoder does not understand the url alphabet, so `-` → `+` and `_` → `/` first. Missing `=` padding is tolerated by Node, so none is added. Invalid characters are silently ignored by the decoder, which usually produces garbage that then fails `JSON.parse` and lands in the `catch`.
- Line 59: only an object is returned. Note `typeof [] === 'object'`, so a JSON **array** payload (`[1,2]`) is returned as-is; `firstOf` later skips it harmlessly because it only reads named paths.
- **The signature is never checked.** That is intentional: the monitor only wants to read the claims the app put there, and it has no key. Do not reuse this for anything that grants access.
- The first segment (header, with `alg`) is ignored entirely.

### `parseBody(contentType, buf)` — turn a raw body into an object

```js
// lines 65-89
function parseBody(contentType, buf) {
  if (!buf || !buf.length) return null;
  const ct = String(contentType || '').toLowerCase();
  const text = buf.toString('utf8');
  try {
    if (ct.includes('json') || (!ct && /^\s*[{[]/.test(text))) return JSON.parse(text);
    if (ct.includes('x-www-form-urlencoded')) {
      const o = {};
      for (const [k, v] of new URLSearchParams(text)) o[k] = v;
      return o;
    }
    if (ct.includes('multipart/form-data')) {
      // light-touch: pick out simple text fields only
      const o = {};
      const re = /name="([^"]+)"\r?\n\r?\n([^\r\n]*)/g;
      let m;
      while ((m = re.exec(text))) o[m[1]] = m[2];
      return o;
    }
    if (/^\s*[{[]/.test(text)) return JSON.parse(text);
  } catch {
    /* not parseable */
  }
  return null;
}
```

- Line 66: an empty or missing buffer is `null`, which callers treat as "no body".
- Line 67-68: the content type is lower-cased for substring tests (`application/json; charset=utf-8`, `application/problem+json`, `text/json` all contain `json`). The whole buffer is decoded as UTF-8 once; binary bodies become mojibake but that is harmless because none of the branches will match them. `server.js` already caps the captured buffer, so there is no size limit here.
- Line 70: JSON if the type says so, **or** if there is no content type at all and the text starts (after optional whitespace) with `{` or `[`. Regex `^\s*[{[]`: start, any whitespace, then one of `{` `[`.
- Lines 71-75: form bodies go through `URLSearchParams`, which decodes `%xx` and `+`-as-space. Repeated keys collapse to the last value (`a=1&a=2` → `{a:'2'}`), which is enough for login forms.
- Lines 76-83: multipart is parsed with a deliberately tiny regex rather than a real parser. Piece by piece: `name="` literal, `([^"]+)` captures the field name up to the closing quote, `"` closing quote, `\r?\n` end of the `Content-Disposition` line, `\r?\n` the blank line that separates part headers from the part body, `([^\r\n]*)` captures the **first line** of the value only. File parts look like `name="f"; filename="a.txt"` — after the closing quote comes `;` not a newline — so the regex does not match them and files are skipped by construction. Multi-line text values are truncated to their first line. The `g` flag plus the `while (re.exec)` loop walks all matches.
- Line 84: a last chance for bodies with an unhelpful type (`text/plain` carrying JSON): if it looks like JSON, try it. Combined with line 70 this means JSON is attempted whenever the text starts with `{`/`[`, regardless of type.
- Lines 85-87: any throw (bad JSON, odd encoding) is swallowed and the function returns `null`. Nothing is logged, on purpose — this runs on every request.

### `clientIp(req)` — who is on the other end

```js
// lines 91-97
function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  const xr = req.headers['x-real-ip'];
  if (xr) return String(xr).trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}
```

- Node lower-cases incoming header names, hence `'x-forwarded-for'`.
- Line 93: `X-Forwarded-For` is a comma list `client, proxy1, proxy2`; the **first** entry is the original client. Required because students usually reach the proxy through a tunnel (zrok) that sets this header.
- Line 95: `X-Real-IP` as a fallback (nginx style).
- Line 96: otherwise the TCP peer address. For IPv4 clients on a dual-stack socket this looks like `::ffff:10.0.0.5`. `'unknown'` is returned only when there is no socket at all (tests pass bare objects).
- **Gotcha:** the headers are trusted blindly. A student who talks to the proxy directly can send `X-Forwarded-For: 1.2.3.4` and appear as someone else. In the intended deployment the tunnel overwrites the header, which is why this is acceptable.

### `nowIso()` and `log(level, ...args)`

```js
// lines 99-108
function nowIso() {
  return new Date().toISOString();
}

function log(level, ...args) {
  const want = (process.env.LOG_LEVEL || 'info').toLowerCase();
  if (level === 'debug' && want !== 'debug') return;
  const fn = level === 'error' ? console.error : console.log;
  fn(`[${nowIso()}] [${level}]`, ...args);
}
```

- `nowIso` is a one-liner so that every log line uses the same UTC format; it is exported but no other module uses it.
- Line 104: `LOG_LEVEL` is read from the environment **on every call**, so there is no startup snapshot; `process.env.LOG_LEVEL = 'debug'` at runtime takes effect immediately.
- Line 105: the only filtering rule is "hide `debug` unless `LOG_LEVEL=debug`". Any other level string (`info`, `warn`, `error`, or a typo) always prints. There is no level hierarchy.
- Line 106: `error` goes to stderr, everything else to stdout. Extra arguments are passed through to `console.*`, so objects are pretty-printed by Node, not JSON-stringified.

### `macFor(ip)` — neighbour-table MAC lookup

```js
// lines 110-128
// Best-effort MAC address lookup for a LAN ip (only possible when the player is on the same network segment
// as this machine, i.e. not through zrok). Uses the host's neighbour table; returns null when unknown.
const macCache = new Map();
function macFor(ip) {
  if (process.platform !== 'linux' || !/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(ip)) return Promise.resolve(null);
  if (macCache.has(ip)) return Promise.resolve(macCache.get(ip));
  return new Promise((resolve) => {
    try {
      require('child_process').execFile('ip', ['neigh', 'show', ip], { timeout: 1500 }, (err, out) => {
        const m = !err && /lladdr\s+([0-9a-f:]{17})/i.exec(String(out));
        const mac = m ? m[1].toLowerCase() : null;
        macCache.set(ip, mac);
        resolve(mac);
      });
    } catch {
      resolve(null);
    }
  });
}
```

- Line 114: two cheap bail-outs. Only Linux has the `ip` tool in the expected form, and only RFC 1918 private IPv4 ranges can be on the same L2 segment. The regex, piece by piece: `^` start; `10\.` the 10/8 block; `192\.168\.` the 192.168/16 block; `172\.(1[6-9]|2\d|3[01])\.` the 172.16/12 block, i.e. second octet 16-19, 20-29 or 30-31. IPv6, loopback, public and `::ffff:`-prefixed addresses all return a resolved `null` promise without touching the cache.
- Line 115: cache hit returns immediately. Because `null` is cached too (line 121), an IP that had no neighbour entry the first time stays `null` for the lifetime of the process even if the device shows up later. Restart the proxy to retry.
- Line 118: runs `ip neigh show <ip>` with `execFile` (no shell, so the IP cannot inject anything) and a 1.5 s timeout. `child_process` is required lazily so non-Linux hosts never load it.
- Line 119: the output looks like `10.0.0.5 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE`. The regex grabs `lladdr`, whitespace, then exactly 17 characters of hex and colons (6 pairs + 5 colons). `!err &&` short-circuits to `false` on any failure, so `m` is falsy and `mac` becomes `null`.
- Line 124: the `try/catch` guards against a synchronous throw from `execFile` (e.g. an invalid option); a missing `ip` binary surfaces as `err` in the callback instead. Either way the promise **never rejects** — `server.js` still adds a `.catch(() => {})` for safety.
- Line 130 exports everything; note `macFor` is only used by `server.js` to record a `mac` identity row.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in ← | `proxy/src/identity.js` | `req.headers.cookie` / `set-cookie` arrays, JWT strings, parsed bodies and claim-path arrays from `rules.json` → `firstOf`, `shortHash`, `parseCookies`, `parseSetCookies`, `decodeJwt`, `clientIp` |
| in ← | `proxy/src/server.js` | raw request/response buffers + `content-type` → `parseBody`; `req` → `clientIp`; IP string → `macFor` (promise of MAC or `null`) |
| in ← | `proxy/src/namegate.js` | `req` → `parseCookies` (gate cookie), `clientIp` |
| in ← | `proxy/src/dashboard.js` | `req` → `clientIp` (dashboard login / rate limiting) |
| in ← | every `proxy/src/*.js` incl. `config.js` | `log(level, ...args)` |
| out → | `process.env.LOG_LEVEL` | read on each `log` call |
| out → | `child_process` (`ip neigh show`) | Linux only, private IPv4 only, 1.5 s timeout |
| out → | `crypto` | SHA-1 for `shortHash` |
| tests | `proxy/test/core.test.js` | imports `decodeJwt`, `parseBody` directly; exercises the rest through `IdentityResolver` |

## Changing it safely

1. **Supporting another body encoding** (e.g. `application/xml`, or real multipart with multi-line values): add a branch inside the `try` in `parseBody` (lines 69-85) *before* the generic JSON fallback on line 84. Keep returning `null` on failure; `server.js` and `identity.js` treat `null` as "no body". Covered by `jwt and body parsing helpers` (`core.test.js`), which checks the JSON and form branches — add a case there.
2. **Changing which proxy headers are trusted for the client IP** (e.g. `CF-Connecting-IP`, or taking the *last* XFF hop): edit `clientIp` (lines 91-97) only. The test `identity: jwt, then session learned at login, then ip fallback` asserts that the first `x-forwarded-for` entry wins (`ip:9.9.9.9`) and that the socket address is used otherwise (`ip:1.2.3.4`), so it will fail if you change the precedence — update it deliberately.
3. **Accepting JWTs from other places / rejecting array payloads**: `decodeJwt` lines 53 and 59. `jwt and body parsing helpers` checks the `Bearer` prefix and the `'not a jwt'` → `null` case; the identity test relies on a cookie-carried JWT decoding.
4. **MAC lookup on other platforms** (macOS `arp -n`, Windows `arp -a`): `macFor` lines 114-119. Nothing tests it; verify by hand on the target OS, keep the "never rejects" contract and remember the cache stores `null`.

Run everything with `cd proxy && npm test`.

## Exercises

1. **Cookie parsing quirks.** Predict, then check, how a value containing `=`, a bare flag and an empty name are handled.
   ```
   cd proxy && node -e "const u=require('./src/util');console.log(JSON.stringify(u.parseCookies('a=1; b=x=y;  c ; =d')))"
   ```
   Expected: `{"a":"1","b":"x=y"}`.

2. **`decodeJwt` accepts array payloads.** Confirm it, then change line 59 so that arrays return `null` (`!Array.isArray(payload)`), re-run the one-liner and the suite.
   ```
   cd proxy && node -e "const u=require('./src/util');const p=Buffer.from('[1,2]').toString('base64url');console.log(u.decodeJwt('Bearer h.'+p+'.s'), u.decodeJwt('h.'+p), u.decodeJwt(42))"
   cd proxy && npm test
   ```
   Before the change the first value prints `[ 1, 2 ]`; the other two are `null`. All tests must still pass after your change.

3. **Log level filter.** Show that only `debug` is filtered and that the filter is read per call.
   ```
   cd proxy && node -e "const {log}=require('./src/util');log('debug','hidden');log('info','shown');process.env.LOG_LEVEL='debug';log('debug','now visible')"
   ```
   Expected: two lines (`[info] shown`, `[debug] now visible`); the first `debug` call prints nothing.

## Quick reference

| Export | Signature | One line |
|---|---|---|
| `get` | `get(obj, path: string) → any \| undefined` | Walk a dotted path (`user.id`) into a JSON-like object; `undefined` if any step is missing. |
| `firstOf` | `firstOf(obj, paths: string[]) → string \| null` | First path whose value is a non-empty scalar, returned as a string. |
| `shortHash` | `shortHash(s) → string` | First 8 hex chars of SHA-1; used for `sess-xxxxxxxx` labels. |
| `parseCookies` | `parseCookies(header?: string) → {[name]: string}` | Parse a `Cookie` request header; raw values, last duplicate wins. |
| `parseSetCookies` | `parseSetCookies(arr?: string[]) → {name, value}[]` | Extract `name=value` from each `Set-Cookie` header, attributes dropped. |
| `decodeJwt` | `decodeJwt(token: string) → object \| null` | Decode (not verify) the payload of a JWT, optional `Bearer ` prefix. |
| `parseBody` | `parseBody(contentType, buf: Buffer) → object \| array \| null` | JSON / form-urlencoded / simple multipart text fields; `null` otherwise. |
| `clientIp` | `clientIp(req) → string` | `X-Forwarded-For` first hop, else `X-Real-IP`, else socket address, else `'unknown'`. |
| `macFor` | `macFor(ip: string) → Promise<string \| null>` | Linux + private IPv4 only: MAC from `ip neigh show`, cached forever, never rejects. |
| `nowIso` | `nowIso() → string` | Current time as ISO-8601 UTC. |
| `log` | `log(level: string, ...args)` | Timestamped console line; `debug` hidden unless `LOG_LEVEL=debug`; `error` → stderr. |

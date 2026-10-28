# mask — `proxy/src/mask.js`

## Purpose

The proxy records every student request, including login bodies and query strings. `mask.js` makes sure that what is stored and shown on the dashboard never contains the actual passwords, tokens or card numbers: anything whose **name** contains a configured word becomes `***`, and raw JWTs or long hex blobs embedded in free text are replaced by placeholders. It is the only place where secrets are scrubbed, so `server.js` runs every event through it before `store.add`.

## Where it sits

`mask.js` has no dependencies at all. It is required only by `proxy/src/server.js` (`maskObject`, `maskUrl`, `maskText`) and by the test suite (`proxy/test/core.test.js`). The list of sensitive words comes from `config.js`, which lower-cases `masking.fields` from `rules.json` into `cfg.maskFields`; `server.js` passes that array in on every call. `isSensitive` and `MASK` are exported for completeness but no other module uses them.

## Data it owns

The module has no mutable state. It owns one constant and relies on one input shape:

| Item | Shape | Meaning |
|---|---|---|
| `MASK` | `'***'` (string constant) | The replacement written in place of every sensitive value. Searching the database for `***` finds all masked fields. |
| `fields` (parameter) | `string[]`, **already lower-cased** | Words to look for *inside* key / parameter names. Supplied by `config.js` (`cfg.maskFields`); default `['password','token','secret']`, in `config/rules.json` a longer list. A capitalised entry would never match because names are lower-cased before comparison and fields are not. |
| `maskObject()` result | new object/array of the same shape | Sensitive keys → `'***'`; nested objects recursed up to depth 6; non-sensitive strings truncated to 200 chars + `'...'`. |
| `maskUrl()` result | string | Same path, query parameters with sensitive names set to `***`. |
| `maskText()` result | string | Input with `<jwt:***>` / `<hex:***>` substituted. |

## Walkthrough

### Header and constant

```js
// lines 1-4
'use strict';
// Hides secrets. Anything whose NAME contains one of the configured words becomes "***".

const MASK = '***';
```

The comment states the contract precisely: masking is driven by **names**, never by inspecting values. A password stored under a key called `p` would not be masked; a harmless field called `passenger` would be (because `pass` is in the configured list). `MASK` is a single constant so that consumers (and database searches) can rely on the exact text.

### `isSensitive(name, fields)`

```js
// lines 6-9
function isSensitive(name, fields) {
  const n = String(name).toLowerCase();
  return fields.some((f) => n.includes(f));
}
```

- Line 7: the name is coerced to a string (array indices, numeric keys) and lower-cased, so `Password`, `PASSWD`, `apiToken` all match.
- Line 8: a **substring** test, not equality or word match: `token` matches `apiToken`, `access_token`, `tokenizer`. This is deliberate (CTF apps use unpredictable names) and is the reason the default list in `rules.json` is written with short stems. It is also why `fields` must already be lower-case: `'Password'.includes('Password')` would be tested against the lower-cased `n` and never match. `config.js` guarantees this; the test file passes lower-case literals.
- `fields.some` returns `false` for an empty list, i.e. an empty `masking.fields` array disables masking entirely (see the config chapter).

### `maskObject(obj, fields, depth = 0)`

```js
// lines 11-21
function maskObject(obj, fields, depth = 0) {
  if (obj == null || typeof obj !== 'object' || depth > 6) return obj;
  if (Array.isArray(obj)) return obj.map((v) => maskObject(v, fields, depth + 1));
  const out = {};
  for (const [k, v] of Object.entries(obj)) {
    if (isSensitive(k, fields)) out[k] = MASK;
    else if (v && typeof v === 'object') out[k] = maskObject(v, fields, depth + 1);
    else out[k] = typeof v === 'string' && v.length > 200 ? v.slice(0, 200) + '...' : v;
  }
  return out;
}
```

- Line 12: scalars, `null`, `undefined` and anything deeper than 6 levels are returned **as they are**. The depth cap protects against pathological or cyclic input (a cycle would otherwise recurse forever), but it has a consequence worth knowing: a secret nested 8 objects deep is *not* masked (verified: `{n:{n:{n:{n:{n:{n:{n:{n:{password:'top'}}}}}}}}}` comes back untouched). Bodies produced by `util.parseBody` are flat or shallow JSON in practice.
- Line 13: arrays are mapped element by element and count as one level of depth. Array *indices* are never treated as names, so `['secret']` as a value is not masked (values are not inspected).
- Line 14: a fresh object is always built; the input is never mutated. `server.js` relies on this because the same `reqBody` object is also handed, unmasked, to `identity.learn` and `detector.analyze` (they need the real username / ids).
- Line 16: a sensitive key wins before the value is looked at — a sensitive key holding an object (`{ password: { hash: ... } }`) is replaced entirely by `'***'`, not recursed.
- Line 17: non-sensitive objects and arrays recurse. `v &&` guards `null` (typeof `null` is `'object'`).
- Line 18: non-sensitive strings longer than 200 characters are cut to 200 and suffixed with `'...'`. This is a size guard for the store / websocket, not a security feature. Numbers, booleans and short strings pass through unchanged. Note this truncation only happens *inside* objects: a top-level string passed directly to `maskObject` is returned whole by line 12.
- Only own enumerable keys are visited (`Object.entries`). Non-plain objects such as `Buffer` or `Date` would be flattened oddly (a `Date` becomes `{}`), but `parseBody` only ever yields plain JSON values.

### `maskUrl(url, fields)`

```js
// lines 23-36
function maskUrl(url, fields) {
  const q = url.indexOf('?');
  if (q < 0) return url;
  const path = url.slice(0, q);
  const params = new URLSearchParams(url.slice(q + 1));
  let changed = false;
  for (const k of [...params.keys()]) {
    if (isSensitive(k, fields)) {
      params.set(k, MASK);
      changed = true;
    }
  }
  return changed ? `${path}?${params.toString()}` : url;
}
```

- Lines 24-25: no `?` means no query string, return the input untouched. Only the query is examined; **path segments are never masked here** (a token embedded in the path is handled by `maskText`, which `server.js` applies afterwards).
- Line 27: everything after the first `?` is parsed with `URLSearchParams`. A `#fragment` is not separated out, so it would be parsed as part of the last parameter value — browsers never send fragments to servers, so this does not occur in practice.
- Line 29: `[...params.keys()]` snapshots the key list before mutating. Duplicate keys appear once per occurrence in the iterator, and `params.set` collapses duplicates to a single entry, so `password=a&password=b` becomes one `password=***`.
- Line 35: the URL is **re-serialised only when something was masked**. This matters: `URLSearchParams.toString()` normalises encoding (`%20` becomes `+`, reserved characters are re-encoded), so a masked URL may differ cosmetically from what the student sent (`/a?x=1%202&password=p` → `/a?x=1+2&password=***`), while an unmasked one is returned byte-for-byte. Keep this in mind when comparing stored paths against raw logs.

### `maskText(text)`

```js
// lines 38-44
// Mask raw JWT-looking strings and long hex blobs inside free text.
function maskText(text) {
  if (!text) return text;
  return String(text)
    .replace(/eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, '<jwt:***>')
    .replace(/\b[A-Fa-f0-9]{32,}\b/g, '<hex:***>');
}
```

- Line 40: falsy input (`''`, `null`, `undefined`) is returned unchanged rather than stringified, so `maskText(null)` is `null`, not `'null'`.
- Line 42, JWT regex piece by piece: `eyJ` is the base64 encoding of `{"`, the first three characters of every JSON JWT header; `[A-Za-z0-9_-]{10,}` ten or more base64url characters (the header); `\.` a literal dot; the same class again for the payload; `\.`; and again for the signature. The 10-character minimum avoids false positives on short dotted strings; the `g` flag replaces every occurrence. The whole token, all three parts, becomes `<jwt:***>`. Note: `eyJ` is **not** anchored by a word boundary, so a token glued to text (`t=eyJ...`) is still found — exactly the test case in `core.test.js`.
- Line 43, hex regex: `\b` word boundary, `[A-Fa-f0-9]{32,}` thirty-two or more hex digits, `\b`. 32 is the length of an MD5 digest, so MD5, SHA-1 (40), SHA-256 (64) and typical API keys are all caught. Gotchas: a UUID (`8-4-4-4-12` with dashes) is *not* matched because no single run reaches 32; conversely a run of 32+ **decimal** digits matches too (digits are hex digits), so an unusually long numeric id would be masked. Word boundaries mean `abc0123...` as part of a longer alphanumeric word is not matched.
- Order: JWT first, then hex. A JWT contains no 32-hex runs after replacement, so order does not change results, but it would if the placeholders overlapped.
- `server.js` applies it as `maskText(maskUrl(x.url, cfg.maskFields))` to the request path only. It is **not** applied to body values; a body field named e.g. `jwt` is only masked if its *name* contains a configured word (`jwt` is not in the default list in `rules.json`, `token` is).

### Exports

```js
// line 46
module.exports = { maskObject, maskUrl, maskText, isSensitive, MASK };
```

`server.js` uses the first three; `isSensitive` and `MASK` are exported so other code (or tests) can reuse the same rule rather than copying it.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in ← | `proxy/src/server.js` (line 223) | request URL string + `cfg.maskFields` → `maskUrl` then `maskText`; result stored as `ev.path` |
| in ← | `proxy/src/server.js` (line 228) | parsed non-GET request body + `cfg.maskFields` → `maskObject`; result stored as `ev.body` (copy; the original body is still used unmasked by identity/detect) |
| in ← | `proxy/src/config.js` (indirectly) | `cfg.maskFields`: lower-cased `masking.fields` from `config/rules.json`, default `['password','token','secret']` |
| out → | `proxy/src/store.js`, `db.js`, dashboard websocket | only ever see the masked `ev.path` / `ev.body` |
| tests | `proxy/test/core.test.js` | `masking hides secrets by field name, in URLs and in free text` |

## Changing it safely

1. **Masking by value instead of (or as well as) name** — e.g. anything that *looks like* a card number: add a check in `maskObject` line 18 for string values and reuse the same rule in `maskUrl` (line 30 only looks at keys today). Extend `masking hides secrets by field name, in URLs and in free text` with a case whose key is innocent and whose value must be masked.
2. **Deeper or shallower recursion / longer string cap**: the literals `6` (line 12) and `200` (line 18). Nothing tests the limits; add an assertion if you change them, and remember the depth cap exists to stop runaway recursion.
3. **Different placeholder** (`***`): change `MASK` only; the test asserts the literal `'***'` and the dashboard search / users may rely on it. `maskText` uses its own `<jwt:***>` / `<hex:***>` literals on lines 42-43.
4. **Adding another free-text pattern** (e.g. AWS keys `AKIA[0-9A-Z]{16}`): chain another `.replace` in `maskText`. Keep patterns anchored enough to avoid eating normal words; the existing test checks that `t=` before a JWT survives.

Run `cd proxy && npm test`; the relevant test is `masking hides secrets by field name, in URLs and in free text` in `proxy/test/core.test.js`.

## Exercises

1. **Depth cap.** Prove that a secret buried deeper than 6 levels is returned unmasked, then decide whether that is acceptable for your CTF app.
   ```
   cd proxy && node -e "const m=require('./src/mask');let o={password:'top'};for(let i=0;i<8;i++)o={n:o};console.log(JSON.stringify(m.maskObject(o,['password'])))"
   ```
   Expected: the output still contains `"password":"top"`. Change `depth > 6` to `depth > 10` and the same command prints `"password":"***"`.

2. **URL re-encoding side effect.** Observe that an unmasked URL is returned verbatim while a masked one is re-serialised.
   ```
   cd proxy && node -e "const m=require('./src/mask');console.log(m.maskUrl('/a?x=1%202&password=p',['password']), '|', m.maskUrl('/a?x=1%202',['password']), '|', m.maskUrl('/a?Password=p&PASSWD=q',['password','passwd']))"
   ```
   Expected: `/a?x=1+2&password=*** | /a?x=1%202 | /a?Password=***&PASSWD=***`.

3. **Hex rule boundaries.** Check which of an MD5, a SHA-1 and a 6-char hex string are masked.
   ```
   cd proxy && node -e "const m=require('./src/mask');console.log(m.maskText('id=0123456789abcdef0123456789abcdef sha=' + 'f'.repeat(40) + ' short=abcdef'))"
   ```
   Expected: `id=<hex:***> sha=<hex:***> short=abcdef`.

## Quick reference

| Export | Signature | One line |
|---|---|---|
| `maskObject` | `maskObject(obj, fields: string[], depth = 0) → same shape` | Deep copy where keys containing a field word become `***`; strings > 200 chars truncated; stops at depth 6. |
| `maskUrl` | `maskUrl(url: string, fields: string[]) → string` | Replace the value of query parameters whose name contains a field word; path untouched. |
| `maskText` | `maskText(text) → string` | Replace JWT-shaped tokens with `<jwt:***>` and 32+ hex-digit runs with `<hex:***>`. |
| `isSensitive` | `isSensitive(name, fields: string[]) → boolean` | Case-insensitive substring test of a key name against the (lower-case) field list. |
| `MASK` | `'***'` | The replacement text. |

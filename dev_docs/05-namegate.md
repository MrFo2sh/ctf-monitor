# Name gate — `proxy/src/namegate.js`

## Purpose

Most CTF apps let players in anonymously or with throw-away usernames, which makes the dashboard useless for an instructor who needs to know *which student* is attacking. The gate is a small form the proxy shows on the first browser visit: at least a username, optionally more fields configured in the dashboard's Gate tab (student id, team, …). The answer is stored in an HMAC-signed cookie, so every later request carries the name and the identity resolver (chapter 04) can use it. The same module implements strict mode (refuse tools that have no cookie), the admission queue hand-off (show a waiting page until the organizer approves), the "ask to rename" flow, and an IP → name memory for cookie-less tools on the same machine.

## Where it sits

- **Required by** `server.js` (line 13), `admin.js` (for `NameGate.clean`), `dashboard.js` (for `TYPES`, `GATE_PATH`, `normalizeConfig`), and the tests `gate.test.js` and `queue.test.js`.
- **Constructed once** in `server.js` lines 49-61 with `secretFile` (`data/.name-gate-secret`), `cookie` (env `NAME_GATE_COOKIE`, default `ctfw_name`), `getConfig` (returns the saved Gate-tab config), `approvals` (chapter 06), `onProfile` and `onEnqueue`.
- **Called by:**
  - `proxy.js` `handle()` line 51: `gate.handle(req, res)` is the **first** thing done for every proxied request; `true` means the gate answered and the proxy stops.
  - `identity.js`: `nameFrom(req)`, `rememberIp(ip, name)`, `nameForIp(ip)`.
  - `admin.js`: `revoke(raw)`, `enabled`, `ipNames`, static `clean()`; sets `onRename`.
  - `server.js`: `gate.ipNames.clear()` in `resetLive()` (line 306); sets `onIpNamed` (line 138).
  - `dashboard.js`: `gate.config`, `gate.enabled`, `gate.page(...)` for the preview (temporarily swapping `gate.getConfig`, lines 278-281).
- **Requires** `fs`, `path`, `crypto`, and `./util` (`parseCookies`, `clientIp`, `log`).
- **Hooks it exposes and who sets them:**

| Hook | Signature | Set by | Fired when |
|---|---|---|---|
| `onProfile` | `(rawName, profile)` | `server.js` constructor option | A form submission with at least one extra answer; `server.js` saves it to `gate_profiles` and attaches it to the live student row. |
| `onEnqueue` | `(rawName, { ip })` | `server.js` constructor option | A student enters the queue for the first time; `server.js` emits a `queue` alert. |
| `onRename` | `(oldRawName, newName)` | `admin.js` constructor (line 16) | A revoked student submits a different name. |
| `onIpNamed` | `(ip, name)` | `server.js` line 138 | An IP is associated with its first gate name; `server.js` merges the `ip:<ip>` row into the named one. |

## Data it owns

### Module constants

| Constant | Value | Meaning |
|---|---|---|
| `GATE_PATH` | `/__ctfwatch/name` | Form POST target. |
| `STATUS_PATH` | `/__ctfwatch/status` | JSON poll used by the waiting page as a fallback. |
| `STREAM_PATH` | `/__ctfwatch/wait` | Server-sent events stream held open by the waiting page. |
| `MAX_AGE` | 2 592 000 s (30 days) | Cookie lifetime. |
| `TYPES` | `['text','number','email','password','select']` | Allowed field types. |
| `DEFAULT_CONFIG` | see lines 16-26 | Fallback for every config key. |

### Normalised gate config (what `normalizeConfig` returns and `this.config` yields)

| Key | Type / limit | Meaning |
|---|---|---|
| `enabled` | boolean (default true) | Gate off → `handle()` returns `false` for everything except the three `/__ctfwatch/*` endpoints. |
| `strict` | boolean (default true) | With no cookie, non-navigation requests are refused with 428 instead of passed through. |
| `queue` | boolean (default true) | After the form, wait for organizer approval. |
| `title`, `intro`, `button` | strings ≤ 80 / 400 / 30 | Form texts. `intro` may be empty (`??` keeps `''`). |
| `waitTitle`, `waitText` | strings ≤ 80 / 400 | Waiting page texts; `{name}` in `waitText` is replaced by the student's name. |
| `fields` | array ≤ 12 | First is always `username`. Each: `{ key, label, type, required, placeholder, options?, locked }`. |

Field properties: `key` is lower-case `[a-z0-9_]`, ≤ 24 chars, unique, never `next`; `label` ≤ 60; `placeholder` ≤ 60; `options` only for `select`, ≤ 50 entries, split on newline or comma; `locked` is `true` only for `username`.

### Instance fields

| Field | Type | Meaning |
|---|---|---|
| `cookie` | string | Cookie name (default `ctfw_name`). |
| `getConfig` | `() => rawConfig` | Re-read on every access of `this.config`; so a Gate-tab save applies immediately. |
| `onProfile`, `onEnqueue`, `onRename`, `onIpNamed` | functions or null | Hooks (table above). |
| `approvals` | `Approvals \| null` | The queue. `null` disables queue behaviour regardless of `cfg.queue`. |
| `secret` | hex string (64 chars) | HMAC key for the cookie; from `secretFile` or random. |
| `ipNames` | `Map<ip, { names: Set<string>, last: string }>` | Which gate names were seen from an IP. ≤ 5000 entries. Cleared on "New CTF". |
| `revoked` | `Map<rawName, ts>` | Names the organizer rejected ("ask to rename"). Re-seeded by `admin.load()`. |
| `waiters` | `Map<rawName, Set<res>>` | Open event-stream responses of waiting pages. |
| `heartbeat` | interval | Every 15 s writes `: ping` to every open stream so proxies/tunnels do not close them. `unref()`'d so it does not keep the process alive. |

### Cookie format

`<cookie name>=encodeURIComponent("<rawName>.<sig>")`, where `sig = base64url(HMAC-SHA256(secret, rawName))` truncated to 24 chars. `Path=/; Max-Age=2592000; SameSite=Lax`. Not `HttpOnly` (the waiting page's `fetch` needs no access to it, but tools copying it from DevTools is the intended workflow); not `Secure` (the proxy is plain HTTP behind the zrok tunnel).

## Walkthrough

### Imports and constants

```js
// lines 7-14
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseCookies, clientIp, log } = require('./util');

const GATE_PATH = '/__ctfwatch/name';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const TYPES = ['text', 'number', 'email', 'password', 'select'];
```

The `/__ctfwatch/` prefix is chosen so it cannot clash with a real CTF route. Everything under it is answered by the gate and never reaches the upstream.

```js
// lines 16-28
const DEFAULT_CONFIG = {
  enabled: true,
  strict: true, // nothing reaches the CTF without the form: curl / scripts / crawlers are refused too
  queue: true, // after the form, students wait until the organizer approves them (Queue tab)
  title: 'Welcome to the CTF',
  intro: 'Before you start, tell us who you are. Use the name your instructor knows you by.',
  button: 'Start',
  waitTitle: 'Almost there',
  waitText: 'Thanks {name}! The organizer will let you in shortly. This page continues by itself once you are approved.',
  fields: [{ key: 'username', label: 'Your name', type: 'text', required: true, placeholder: 'Your name', locked: true }],
};
const STATUS_PATH = '/__ctfwatch/status';
const STREAM_PATH = '/__ctfwatch/wait'; // server-sent events: the waiting page learns about the decision instantly
```

All three switches default to **on**. `server.js` line 46 seeds the very first config from `NAME_GATE_TITLE` only; everything else comes from these defaults until the organizer saves the Gate tab.

### `cleanKey` and `normalizeConfig`

```js
// lines 30-44
function cleanKey(k) {
  return String(k || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24);
}

// Validates a config coming from the dashboard; always returns a usable config.
function normalizeConfig(raw) {
  const cfg = { ...DEFAULT_CONFIG, ...(raw && typeof raw === 'object' ? raw : {}) };
  cfg.enabled = cfg.enabled !== false;
  cfg.strict = cfg.strict !== false;
  cfg.queue = cfg.queue !== false;
  cfg.title = String(cfg.title || DEFAULT_CONFIG.title).slice(0, 80);
  cfg.intro = String(cfg.intro ?? DEFAULT_CONFIG.intro).slice(0, 400);
  cfg.button = String(cfg.button || DEFAULT_CONFIG.button).slice(0, 30);
  cfg.waitTitle = String(cfg.waitTitle || DEFAULT_CONFIG.waitTitle).slice(0, 80);
  cfg.waitText = String(cfg.waitText || DEFAULT_CONFIG.waitText).slice(0, 400);
```

- `cleanKey` turns `'Student-ID'` into `'studentid'` (gate.test.js asserts this). Keys become form `name=` attributes and profile object keys, so they are kept to a safe charset.
- Line 36: `normalizeConfig(null)` and non-objects yield the defaults (tested).
- Lines 37-39: the booleans are "true unless explicitly `false`", so a missing key (older saved config) keeps the safe default of on.
- Line 41: `intro` uses `??` not `||`: an organizer may blank the intro, and the empty string must survive. The other texts fall back on empty.

```js
// lines 45-67
  const seen = new Set();
  const fields = [];
  for (const f of Array.isArray(cfg.fields) ? cfg.fields : []) {
    const key = cleanKey(f && f.key);
    if (!key || seen.has(key) || key === 'next') continue;
    seen.add(key);
    fields.push({
      key,
      label: String((f && f.label) || key).slice(0, 60),
      type: TYPES.includes(f && f.type) ? f.type : 'text',
      required: key === 'username' ? true : !!(f && f.required),
      placeholder: String((f && f.placeholder) || '').slice(0, 60),
      options: f && f.type === 'select' ? String(f.options || '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean).slice(0, 50) : undefined,
      locked: key === 'username',
    });
  }
  // username is always first, text, required and locked
  const u = fields.find((f) => f.key === 'username');
  const username = { ...DEFAULT_CONFIG.fields[0], ...(u || {}), type: 'text', required: true, locked: true, options: undefined };
  if (!u || !u.label || u.label === 'username') username.label = DEFAULT_CONFIG.fields[0].label;
  cfg.fields = [username, ...fields.filter((f) => f.key !== 'username')].slice(0, 12);
  return cfg;
}
```

- Line 49: `next` is reserved because the form has a hidden `next` input (the URL to return to); a field with that key would collide with it in `URLSearchParams`.
- Line 54: an unknown type silently becomes `text` (tested with `type: 'weird'`).
- Line 57: `options` is authored as one string in the dashboard (`'red, blue'` or one per line) and stored as an array. Non-select fields get `undefined`, which `JSON.stringify` drops.
- Lines 62-65: the username field cannot be removed, retyped, made optional or given options; only its label and placeholder are editable. A label that is empty or literally `username` is replaced by `Your name`. The cap of 12 fields includes username.

### Constructor

```js
// lines 74-91
  constructor({ secretFile, cookie, getConfig, onProfile, approvals, onEnqueue }) {
    this.cookie = cookie || 'ctfw_name';
    this.getConfig = getConfig || (() => DEFAULT_CONFIG);
    this.onProfile = onProfile || null;
    this.approvals = approvals || null;
    this.onEnqueue = onEnqueue || null;
    this.secret = this.loadSecret(secretFile);
    this.ipNames = new Map(); // ip -> { names:Set, last }
    this.revoked = new Map(); // rawName -> ts   ("ask to rename")
    this.onRename = null; // (oldRawName, newName) => void
    this.onIpNamed = null; // (ip, name) => void
    this.waiters = new Map(); // rawName -> Set(res) of open event streams (waiting pages)
    if (this.approvals) this.approvals.onChange((names) => this.notifyWaiters(names));
    this.heartbeat = setInterval(() => {
      for (const set of this.waiters.values()) for (const res of set) res.write(': ping\n\n');
    }, 15000);
    if (this.heartbeat.unref) this.heartbeat.unref();
  }
```

- Line 86: the gate subscribes to queue changes so a decision is pushed to the student's open waiting page within the same tick as the organizer's click.
- Lines 87-90: an SSE comment line (`: ping`) is ignored by `EventSource` but keeps the TCP connection alive through zrok and browser idle timeouts. `unref()` lets tests (and `process.exit`) finish without clearing the interval. `res.write` on a closed response can throw in theory; in practice `req.on('close')` removes the entry first (line 269).

### `notifyWaiters` and `statusOf`

```js
// lines 93-113
  // push the new status to every open waiting page of these students
  notifyWaiters(names) {
    for (const n of names || []) {
      const set = this.waiters.get(n);
      if (!set) continue;
      const status = this.approvals ? this.approvals.status(n) || 'none' : 'approved';
      for (const res of set) {
        try {
          res.write(`data: ${JSON.stringify({ status })}\n\n`);
          if (status !== 'pending') res.end();
        } catch {}
      }
      if (status !== 'pending') this.waiters.delete(n);
    }
  }
  statusOf(name) {
    const cfg = this.config;
    if (!name) return 'none';
    if (!cfg.queue || !this.approvals) return 'approved';
    return this.approvals.status(name) || 'pending';
  }
```

- `notifyWaiters` only touches the names it is given (the `changed` list from `Approvals.decide` / `remove`). A status of `null` (record removed) is sent as `'none'`; anything other than `pending` closes the stream, and the page's script reloads on any non-pending status.
- `statusOf` is the page-facing view: no cookie → `none`; queue off → `approved`; otherwise the queue's answer, with "never seen" shown as `pending` (the next navigation will enqueue them).

### `config`, `enabled`, `loadSecret`, `sign`

```js
// lines 115-139
  get config() {
    return normalizeConfig(this.getConfig());
  }
  get enabled() {
    return this.config.enabled;
  }

  loadSecret(file) {
    try {
      if (file && fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
      const s = crypto.randomBytes(32).toString('hex');
      if (file) {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, s, { mode: 0o600 });
      }
      return s;
    } catch (err) {
      log('error', `gate: could not persist secret (${err.message}) - using a temporary one`);
      return crypto.randomBytes(32).toString('hex');
    }
  }

  sign(name) {
    return crypto.createHmac('sha256', this.secret).update(name).digest('base64url').slice(0, 24);
  }
```

- `config` re-normalises on every access. `handle()` reads it once per request into `cfg`; the getter is cheap but not free, so avoid calling `this.config` in loops.
- The secret lives in `data/.name-gate-secret` (mode 600). Losing it (e.g. deleting `data/`) invalidates every student cookie; they get the form again. Tests pass `secretFile: null` to get a random in-memory secret.
- `sign` truncates the 43-char base64url digest to 24 chars (144 bits), plenty for an HMAC tag, and keeps the cookie short.

### `nameFrom(req)` — verify the cookie

```js
// lines 141-157
  nameFrom(req) {
    const raw = parseCookies(req.headers.cookie)[this.cookie];
    if (!raw) return null;
    let v;
    try {
      v = decodeURIComponent(raw);
    } catch {
      return null;
    }
    const i = v.lastIndexOf('.');
    if (i <= 0) return null;
    const name = v.slice(0, i);
    const sig = v.slice(i + 1);
    const want = this.sign(name);
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    return name;
  }
```

- `lastIndexOf('.')` because the name itself may contain dots (`clean` allows them); the signature never does (base64url alphabet).
- `timingSafeEqual` throws on different lengths, hence the explicit length check first. `gate.test.js` checks that `Gohary.forged` yields `null`.
- The returned name is exactly what was signed, i.e. the output of `NameGate.clean` at submission time. It is **not** re-cleaned here, so a change to `clean()`'s rules does not retroactively reject old cookies.

### `clean(name)` — the shared sanitiser

```js
// lines 159-165
  static clean(name) {
    const n = String(name || '')
      .replace(/[^\p{L}\p{N} _.\-@]/gu, '')
      .trim()
      .slice(0, 32);
    return n.length >= 2 ? n : null;
  }
```

Keeps Unicode letters and digits (so Arabic or accented names work), space, `_`, `.`, `-`, `@`; removes everything else (tags, quotes, slashes). `' Gohary<b> '` → `Goharyb` (tested). Used by `validate()` and by `admin.rename`.

### IP memory: `rememberIp` / `nameForIp`

```js
// lines 167-186
  rememberIp(ip, name) {
    if (!ip || !name) return;
    let e = this.ipNames.get(ip);
    if (!e) {
      e = { names: new Set(), last: name };
      this.ipNames.set(ip, e);
      if (this.ipNames.size > 5000) this.ipNames.delete(this.ipNames.keys().next().value);
    }
    if (!e.names.has(name)) {
      e.names.add(name);
      if (e.names.size === 2) log('info', `gate: ip ${ip} is shared by ${[...e.names].join(', ')} - no longer matching that ip to a name`);
      if (e.names.size === 1 && this.onIpNamed) this.onIpNamed(ip, name);
    }
    e.last = name;
  }
  nameForIp(ip) {
    const e = ip && this.ipNames.get(ip);
    if (!e || e.names.size !== 1) return null;
    return e.last;
  }
```

- Called by `identity.resolve` on every request that carries a valid cookie, and by the form POST handler. The `Set` grows only when a *new* name appears for the IP, so it is cheap on the hot path.
- `onIpNamed` fires exactly once per IP: on its first name. `server.js` uses it to merge the anonymous `ip:<ip>` row (requests made before the form, or by tools) into the named row.
- `nameForIp` returns a name only while the IP is **unambiguous**. The moment a second student submits from the same IP the mapping is disabled for that IP (logged once). `e.last` is still tracked but unused once the set has two names.
- `admin.block` reads `ipNames.get(ip).names.size > 1` to avoid blocking a shared IP. `server.js` `resetLive()` clears the map on "New CTF".

### Revocation ("ask to rename")

```js
// lines 188-196
  revoke(rawName) {
    if (rawName) this.revoked.set(rawName, Date.now());
  }
  unrevoke(rawName) {
    this.revoked.delete(rawName);
  }
  isRevoked(rawName) {
    return this.revoked.has(rawName);
  }
```

Memory-only; `admin.js` persists the same set under `admin_state.revoked` and calls `revoke` for each on load. `unrevoke` and `isRevoked` are not called anywhere in the codebase today (the POST handler deletes from `this.revoked` directly on line 307).

### `isNavigation(req)` — "is this a browser page load?"

```js
// lines 198-206
  isNavigation(req) {
    if (req.method !== 'GET') return false;
    const accept = String(req.headers.accept || '');
    if (!accept.includes('text/html')) return false;
    const dest = req.headers['sec-fetch-dest'];
    if (dest && dest !== 'document') return false;
    if (req.headers['x-requested-with']) return false;
    return true;
  }
```

This is the heuristic that decides who sees HTML pages (form, waiting, blocked) versus a plain-text/JSON 428. A real top-level navigation is a GET accepting `text/html` with `Sec-Fetch-Dest: document` (modern browsers) and no `X-Requested-With`. `fetch()`/XHR calls, images, scripts and curl fail at least one of these. The waiting page's own poll sends `X-Requested-With: ctf-watch-wait` precisely so it is treated as an API call. Older clients without `Sec-Fetch-Dest` still pass if they accept HTML.

### `validate(form)`

```js
// lines 208-233
  // Validate submitted answers against the configured fields -> { name, profile } or { error, values }
  validate(form) {
    const cfg = this.config;
    const values = {};
    const profile = {};
    let name = null;
    for (const f of cfg.fields) {
      let v = String(form.get(f.key) ?? '').trim();
      values[f.key] = f.type === 'password' ? '' : v;
      if (f.key === 'username') {
        name = NameGate.clean(v);
        if (!name) return { error: `${f.label}: 2-32 letters or numbers please.`, values };
        continue;
      }
      if (!v) {
        if (f.required) return { error: `${f.label} is required.`, values };
        continue;
      }
      if (f.type === 'number' && !/^\d{1,20}$/.test(v)) return { error: `${f.label} must be a number.`, values };
      if (f.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return { error: `${f.label} must be an email address.`, values };
      if (f.type === 'select' && f.options && !f.options.includes(v)) return { error: `${f.label}: pick one of the options.`, values };
      // never keep secrets: a password-type answer is only recorded as "given"
      profile[f.key] = f.type === 'password' ? '***' : v.slice(0, 120);
    }
    return { name, profile, values };
  }
```

- `form` is a `URLSearchParams`. Fields are validated in configured order, and the first failure returns; `values` holds what was typed so far so the re-rendered form can keep the inputs filled (password answers are blanked, line 216).
- `username` is always first (normalisation guarantees it), so a bad name is reported before anything else.
- Optional empty fields are skipped and do not appear in `profile`.
- `number` means digits only (no sign, no decimals, max 20), suitable for ids. `email` is a loose shape check. `select` must match one of the configured options exactly.
- Password-type answers reach the profile only as `'***'` and `values` as `''`: the proxy never stores a student's secret. Everything else is capped at 120 chars.
- Returns `{ name, profile, values }` on success; `error` is `undefined` (gate.test.js checks `ok.error === undefined`).

### `refuse` and `requiredLabels`

```js
// lines 235-244
  // "You must set your Your name, Student ID first" for tools hitting the proxy without the form
  refuse(req, res, status, text) {
    const wantsJson = String(req.headers.accept || '').includes('json');
    res.writeHead(status, { 'Content-Type': wantsJson ? 'application/json' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(wantsJson ? JSON.stringify({ error: text }) : text + '\n');
    return true;
  }
  requiredLabels() {
    return this.config.fields.filter((f) => f.required).map((f) => f.label).join(', ');
  }
```

Used for every non-navigation refusal. The status is always 428 (Precondition Required) from the callers, chosen because it is unlikely to be produced by the CTF app and signals "do something first". JSON clients get `{ "error": "..." }`. `requiredLabels` produces the list in the message ("Your name, Student ID"), tested in `queue.test.js`.

### `handle(req, res)` — the per-request entry point

#### Decision order

For every proxied request, `handle` checks the following in this exact order; the first match wins. "Answered" means it wrote the response and returned `true`; `proxy.js` then stops. "Pass" means it returned `false` and the request continues to `preRequest` (block check) and the upstream.

1. **`GET /__ctfwatch/status`** (any method actually): answered with JSON `{ status }` from `statusOf(nameFrom(req))`. Works even when the gate is disabled.
2. **`/__ctfwatch/wait`** (any method): answered with an SSE stream. Sends the current status immediately; if the student has a valid cookie and is `pending`, the response is kept open and registered in `waiters`; otherwise it is ended at once.
3. **`/__ctfwatch/name`**: non-POST → `405` empty. POST → body read (max 64 chunks / 8 KiB), validated; on error the form is re-rendered (200) with the message; if the name is currently revoked the form is re-rendered with "That name was not accepted"; else `302` to `next` with the signed cookie, followed by side effects (IP memory, `onProfile`, enqueue, `onEnqueue`, rename detection / `onRename`). Always answered (returns `true` synchronously while the body is still being read).
4. **Gate disabled** (`cfg.enabled === false`): pass.
5. **No valid cookie**: navigation → the form (200) with `next` set to the requested URL; otherwise if `strict` → `428` "You must set your <required labels> first…"; if not strict → pass.
6. **Cookie name is revoked**: navigation → the form (200) with the "organizer asks you to enter your real name" message; otherwise `428`.
7. **Queue on and `approvals` present**: status `null` (never seen) → enqueue now, `onEnqueue`, treat as `pending`. `blocked` → blocked page (200 HTML, even for non-navigation requests). Not `approved` (i.e. `pending`) → navigation gets the waiting page (200), others `428` "waiting for the organizer's approval". `approved` → fall through.
8. **Pass**: cookie valid, not revoked, approved (or queue off).

Note that the block list in `admin.js` is checked *after* the gate (`proxy.js` line 52): a student blocked from the queue sees the gate's "Access blocked" page via step 7; a student blocked from the Students table but never queued sees the near-identical page produced by `server.js` `preRequest`.

#### Status and stream endpoints

```js
// lines 247-275
  handle(req, res) {
    const cfg = this.config;
    const pathOnly = (req.url || '/').split('?')[0];

    // polled by the waiting page (fallback): { status: pending | approved | blocked | none }
    if (pathOnly === STATUS_PATH) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ status: this.statusOf(this.nameFrom(req)) }));
      return true;
    }
    // event stream held open by the waiting page: the decision arrives the moment it is made
    if (pathOnly === STREAM_PATH) {
      const name = this.nameFrom(req);
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      res.write(`data: ${JSON.stringify({ status: this.statusOf(name) })}\n\n`);
      if (name && this.statusOf(name) === 'pending') {
        let set = this.waiters.get(name);
        if (!set) {
          set = new Set();
          this.waiters.set(name, set);
        }
        set.add(res);
        req.on('close', () => {
          set.delete(res);
          if (!set.size) this.waiters.delete(name);
        });
      } else res.end();
      return true;
    }
```

- `X-Accel-Buffering: no` tells nginx-style proxies not to buffer the stream. The first `data:` line goes out immediately so the page knows the stream works.
- A student may have several tabs open; each is one `res` in the `Set`. `req.on('close')` cleans up when the tab closes, so the heartbeat never writes to a dead socket.
- These two endpoints run before the `enabled` check, so a waiting page keeps working if the organizer disables the gate mid-wait (it will see `approved` and reload into the CTF).

#### Form POST

```js
// lines 277-299
    if (pathOnly === GATE_PATH) {
      if (req.method !== 'POST') {
        res.writeHead(405).end();
        return true;
      }
      const chunks = [];
      req.on('data', (c) => chunks.length < 64 && chunks.push(c));
      req.on('end', () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8').slice(0, 8192));
        let next = form.get('next') || '/';
        if (!next.startsWith('/') || next.startsWith('//')) next = '/';
        const v = this.validate(form);
        const html = (msg, values) => {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end(this.page(next, msg, values));
        };
        if (v.error) return html(v.error, v.values);
        if (this.revoked.has(v.name)) return html('That name was not accepted by the organizer. Please enter your real name.', v.values);
        const prev = this.nameFrom(req);
        const value = encodeURIComponent(`${v.name}.${this.sign(v.name)}`);
        res.writeHead(302, { Location: next, 'Set-Cookie': `${this.cookie}=${value}; Path=/; Max-Age=${MAX_AGE}; SameSite=Lax`, 'Cache-Control': 'no-store' });
        res.end();
        this.rememberIp(clientIp(req), v.name);
```

- Lines 283-285: body size is bounded twice (chunk count, then 8 KiB of text) so a hostile client cannot make the proxy buffer a large upload here. Excess bytes are ignored, not rejected.
- Line 287: open-redirect guard. `next` must be a same-origin absolute path; `//evil.com` is a protocol-relative URL and is rejected.
- Line 294: a revoked name cannot be re-submitted as-is; the student must type something different. The form is re-rendered with the typed values.
- Line 295: `prev` is the name from the *previous* cookie, read before the new one is set; it drives the rename detection below.
- Line 297: `302` with the cookie, then the browser re-requests `next`, which now passes step 5. The response is finished **before** the side effects run so the student is not delayed by DB writes.

```js
// lines 300-313
        if (this.onProfile && Object.keys(v.profile).length) this.onProfile(v.name, v.profile);
        if (cfg.queue && this.approvals) {
          const before = this.approvals.status(v.name);
          this.approvals.enqueue(v.name, { profile: v.profile, ip: clientIp(req), ua: String(req.headers['user-agent'] || '').slice(0, 160) });
          if (!before && this.onEnqueue) this.onEnqueue(v.name, { ip: clientIp(req) });
        }
        if (prev && prev !== v.name && this.revoked.has(prev)) {
          this.revoked.delete(prev);
          log('info', `gate: "${prev}" renamed themselves to "${v.name}"`);
          if (this.onRename) this.onRename(prev, v.name);
        } else log('info', `gate: student "${v.name}" (ip ${clientIp(req)})${Object.keys(v.profile).length ? ' ' + JSON.stringify(v.profile) : ''}`);
      });
      return true;
    }
```

- Line 300: `onProfile` is skipped when there are no extra fields, so `gate_profiles` only contains students with real answers.
- Lines 301-305: `enqueue` keeps an existing decision (chapter 06); `onEnqueue` (the dashboard alert) fires only for a brand-new queue record, detected by `before === null`. An approved student who resubmits the form is not re-alerted and stays approved.
- Lines 306-310: rename detection. Only a student whose **old** name was revoked and who typed a **different** name counts as a rename; the revoke is lifted and `onRename` (→ `admin.onGateRename`) moves their rows. A non-revoked student who changes their name simply appears as a second student. Note `cfg` here is the config captured at the top of `handle`, before the body was read; a Gate-tab save in between is not seen by this submission.
- `return true` on line 312 happens while the body is still streaming; `proxy.js` must not touch `req` after that, and it does not.

#### Gate logic for ordinary requests

```js
// lines 315-334
    if (!cfg.enabled) return false;
    const current = this.nameFrom(req);
    const nav = this.isNavigation(req);
    const html = (body) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(body);
      return true;
    };

    // no form filled yet
    if (!current) {
      if (nav) return html(this.page(req.url || '/'));
      if (cfg.strict) return this.refuse(req, res, 428, `You must set your ${this.requiredLabels()} first: open the CTF link in your browser and fill the form, then retry (tools must send the same cookie as the browser).`);
      return false;
    }
    // organizer rejected the name
    if (this.revoked.has(current)) {
      if (nav) return html(this.page(req.url || '/', 'The organizer asks you to enter your real name before continuing.'));
      return this.refuse(req, res, 428, 'ctf-watch: the organizer asks you to re-enter your name. Open the CTF in your browser, then retry.');
    }
```

- All gate pages are served with **200**, not 4xx, so browsers render them normally and do not show error UI; `Cache-Control: no-store` prevents the form from being cached in place of the real page.
- Line 326: `req.url` (with query string) is passed as `next`, so the student lands on the deep link they clicked after submitting.
- Line 327: strict mode. The message deliberately explains the workaround (copy the browser cookie into the tool); the intent is attribution, not to stop tools.
- Line 328: non-strict pass-through. Attribution of that request then relies on `identity.resolve`'s `ip-match` branch (chapter 04).
- Lines 331-334: the revoked branch uses `this.revoked`, the in-memory map, which `admin.load()` seeds from the DB on start.

```js
// lines 335-351
    // admission queue
    if (cfg.queue && this.approvals) {
      let st = this.approvals.status(current);
      if (!st) {
        // cookie from before the queue was switched on: put them in the queue now
        this.approvals.enqueue(current, { ip: clientIp(req), ua: String(req.headers['user-agent'] || '').slice(0, 160) });
        if (this.onEnqueue) this.onEnqueue(current, { ip: clientIp(req) });
        st = 'pending';
      }
      if (st === 'blocked') return html(this.blockedPage());
      if (st !== 'approved') {
        if (nav) return html(this.waitPage(current));
        return this.refuse(req, res, 428, `ctf-watch: ${current}, you are waiting for the organizer's approval. Keep the CTF page open in your browser.`);
      }
    }
    return false;
  }
```

- Lines 338-343: lazy enqueue. Covers cookies issued while `queue` was off, cookies that survived a `queue/remove`, and a fresh DB with old cookies. Without profile data (the form was not submitted now). `queue.test.js` (`queue: after the form the student waits…`) starts from exactly this state.
- Line 344: a blocked student gets the HTML page on every request type, including API calls; a JSON client sees HTML with status 200. (The `admin.js` block path returns 403 JSON for non-HTML clients; the two differ.)
- Lines 345-348: `pending` and any unknown status are treated as "wait".
- Line 350: the pass-through for approved students (or `queue` off / no `approvals`).

### Page rendering: `waitPage`, `blockedPage`, `page`

```js
// lines 353-360
  waitPage(name) {
    const cfg = this.config;
    const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(cfg.waitTitle)}</title>
<style>...</style></head><body>
<div class="b"><h1>${esc(cfg.waitTitle)}</h1><p>${esc(cfg.waitText).replace(/\{name\}/g, `<span class="n">${esc(name)}</span>`)}</p><div class="s"></div></div>
```

(Lines 357-359 are the inline CSS, elided here.) Every organizer- or student-supplied string goes through `esc`, including the name inside the `{name}` replacement — the replacement happens *after* escaping the template, so the name cannot inject HTML.

```js
// lines 361-367
<script>(function(){
  var done=false; function go(){ if(!done){ done=true; location.reload(); } }
  // realtime: event stream from the proxy; the decision arrives the moment the organizer clicks
  try { var es=new EventSource("${STREAM_PATH}"); es.onmessage=function(e){ try{ var j=JSON.parse(e.data); if(j.status!=="pending") go(); }catch(x){} }; es.onerror=function(){ /* fallback below keeps working */ }; } catch(x){}
  // fallback: slow poll in case the stream cannot stay open through the tunnel
  setInterval(function(){ fetch("${STATUS_PATH}",{credentials:"same-origin",headers:{"X-Requested-With":"ctf-watch-wait"}}).then(function(r){return r.json()}).then(function(j){ if(j.status!=="pending") go(); }).catch(function(){}); },10000);
})();</script>
```

- Two channels, one action: any status other than `pending` reloads the page once (`done` guards double reload if both channels fire). After reload, step 7 of the decision order serves the CTF (approved), the blocked page, or a new waiting page (`none` → re-enqueued as pending).
- The poll runs every 10 s regardless of whether the stream works, so a stuck tunnel costs at most 10 s. `credentials: "same-origin"` sends the gate cookie; the custom header makes `isNavigation` false, which does not matter for `/__ctfwatch/status` but is a habit worth keeping for any future gate-aware endpoint.

```js
// lines 370-372
  blockedPage() {
    return '<!doctype html>...<h1 style="color:#d03b3b">Access blocked</h1><p>The organizer has not admitted you to this CTF.<br>Talk to the organizer if you think this is a mistake.</p>...';
  }
```

Static; no student input. Text differs slightly from `server.js`'s block page ("has not admitted" vs "has blocked") so you can tell which path produced it.

```js
// lines 374-383
  page(next, error, values = {}) {
    const cfg = this.config;
    const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const field = (f, i) => {
      const common = `name="${esc(f.key)}" id="f-${esc(f.key)}" ${f.required ? 'required' : ''} ${i === 0 ? 'autofocus' : ''} autocomplete="off"`;
      let input;
      if (f.type === 'select') input = `<select ${common}><option value="">choose…</option>${(f.options || []).map((o) => `<option ${values[f.key] === o ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
      else input = `<input ${common} type="${f.type === 'number' ? 'text' : f.type}" ${f.type === 'number' ? 'inputmode="numeric" pattern="[0-9]*"' : ''} maxlength="${f.key === 'username' ? 32 : 120}" placeholder="${esc(f.placeholder || f.label)}" value="${esc(values[f.key] || '')}">`;
      return `<label for="f-${esc(f.key)}">${esc(f.label)}${f.required ? '' : ' <span class="opt">(optional)</span>'}</label>${input}`;
    };
```

- `number` fields are rendered as `type="text"` with `inputmode="numeric"` and a digits-only `pattern`: a native `type="number"` would accept `1e5` and `-3`, which server-side validation rejects anyway, and shows spinners. `maxlength` mirrors the server limits (32 / 120).
- `autocomplete="off"` because shared lab machines would otherwise suggest the previous student's name. The first field (username) gets `autofocus`.
- `values` re-fills the form after a validation error; options are compared by exact string.

```js
// lines 384-403
    return `<!doctype html>...
<form method="post" action="${GATE_PATH}">
  <h1>${esc(cfg.title)}</h1>
  ${cfg.intro ? `<p>${esc(cfg.intro)}</p>` : ''}
  ${cfg.fields.map(field).join('')}
  <input type="hidden" name="next" value="${esc(next)}">
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <button type="submit">${esc(cfg.button)}</button>
</form></body></html>`;
  }
```

The form is plain HTML (no JavaScript, no external assets) so it works through any tunnel and under any CSP. `dashboard.js` reuses this method for the Gate-tab preview and neuters the submit with a string replace on `<form method="post"`; renaming that attribute order would silently break the preview.

### Export

```js
// line 407
module.exports = { NameGate, GATE_PATH, STATUS_PATH, STREAM_PATH, DEFAULT_CONFIG, normalizeConfig, TYPES };
```

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `proxy.js` `handle` line 51 | `handle(req, res)` first for every request; `true` = answered |
| in | `identity.js` | `nameFrom(req)` → raw name or null; `rememberIp(ip, name)`; `nameForIp(ip)` |
| in | `admin.js` | `revoke(raw)` (ask to rename / reload), `enabled` (guard), `ipNames` (shared-IP check), `NameGate.clean` (organizer rename); sets `onRename` |
| in | `dashboard.js` | `config` (GET `/api/gate`, queue tab), `enabled` (stats), `page('/', error)` with a temporarily swapped `getConfig` (preview); `normalizeConfig`, `TYPES`, `GATE_PATH` |
| in | `server.js` | constructor options (`secretFile`, `cookie`, `getConfig`, `approvals`, `onProfile`, `onEnqueue`); sets `onIpNamed`; `ipNames.clear()` on New CTF; `setGateConfig` runs `normalizeConfig` before saving `gate_config` |
| out | `approvals.js` | `status(raw)`, `enqueue(raw, { profile, ip, ua })`, `onChange(names => notifyWaiters(names))` |
| out (hooks) | `server.js` | `onProfile(raw, profile)` → `gate_profiles` + live row; `onEnqueue(raw, { ip })` → `queue` alert; `onIpNamed(ip, name)` → `mergeLane('ip:<ip>', name)` |
| out (hook) | `admin.js` | `onRename(oldRaw, newName)` → `onGateRename` |
| out | `util.js`, `fs`, `crypto` | cookies / client IP / logging; secret file; HMAC |
| out (HTTP) | the student's browser | form page, waiting page (SSE on `/__ctfwatch/wait`, poll on `/__ctfwatch/status`), blocked page, `Set-Cookie` on `/__ctfwatch/name` |

## Changing it safely

| Likely change | Where |
|---|---|
| Add a field type (e.g. `tel`, `checkbox`) | `TYPES` (line 14); a validation rule in `validate()` (lines 226-228); rendering in `page()`'s `field` (lines 377-383). The dashboard reads `TYPES` from `/api/gate`, so its dropdown updates by itself. |
| Change what counts as a navigation (e.g. also gate `POST` page loads) | `isNavigation()` (lines 198-206) only. Keep the waiting page's poll excluded (`X-Requested-With`). Re-run `gate.test.js` and `queue.test.js`, which build requests with explicit headers. |
| Change the cookie (name, lifetime, `HttpOnly`) | `MAX_AGE` (line 13), the `Set-Cookie` string (line 297), and `nameFrom` if the format changes. Changing the format or the secret logs every student out of the gate. Do not add `HttpOnly` without checking the "copy the cookie into your tool" workflow in the README. |
| Persist `revoked` or `ipNames` | `revoked` already round-trips via `admin_state.revoked`; keep both in sync (`revoke()` + `admin.state.revoked`). `ipNames` is intentionally volatile (cleared on New CTF); if persisted, also persist the shared-IP flag or `admin.block` may block a NAT. |
| Add a new `/__ctfwatch/*` endpoint | Add it before the `enabled` check (line 315) if it must work with the gate off; it is reachable without authentication by anyone with the student link, so it must leak nothing beyond the caller's own status. |

Tests:

- `proxy/test/gate.test.js`
  - `normalizeConfig always keeps a locked, required username field first` — normalisation, key cleaning, unknown type, `null` input.
  - `validate: username cleaning, required fields, number / email / choice checks, password never stored` — every branch of `validate()`.
  - `page renders the configured fields and the signed cookie round-trips` — `page()`, `sign()`, `nameFrom()` incl. a forged signature.
  - `disabled gate never intercepts; enabled gate intercepts only browser navigations` — steps 4 and 5 of the decision order with `strict: false, queue: false`.
- `proxy/test/queue.test.js`
  - `strict gate: no cookie -> browser gets the form, tools get 428 naming the required fields` — step 5 strict branch and `requiredLabels()`.
  - `non-strict gate: tools without a cookie pass through` — step 5 pass branch.
  - `queue: after the form the student waits, approval lets them in, block shuts them out` — step 7: lazy enqueue, waiting page, 428 for tools, approved pass-through, blocked page.
  - `queue off: the form alone is enough` — step 8 with `queue: false`.
  - `waiting page event stream: open streams get the decision pushed instantly` — steps 1-2, `waiters`, `notifyWaiters` closing the stream, the status poll.
- Not covered by tests: the form POST handler (step 3) including `next` sanitising, `onProfile`, `onEnqueue`, rename detection and `onRename`; `rememberIp` / `nameForIp` / `onIpNamed`; the revoked branch (step 6); `loadSecret` with a real file.

## Exercises

1. **Test the form POST.** Add a test to `queue.test.js` that builds a request `{ method: 'POST', url: '/__ctfwatch/name', headers: { 'user-agent': 'x' }, socket: { remoteAddress: '10.0.0.5' }, on(ev, fn) { if (ev === 'data') fn(Buffer.from('username=Gohary&sid=42&next=//evil.com')); if (ev === 'end') fn(); } }`, calls `g.handle(req, r)` and asserts `r.code === 302`, `r.headers.Location === '/'`, that `r.headers['Set-Cookie']` starts with `ctfw_name=`, and `approvals.status('Gohary') === 'pending'`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node --test test/queue.test.js`
2. **Watch strict mode from the shell.** With the stack running and the gate on: `curl -s -i http://127.0.0.1:8888/ | head -1` → `HTTP/1.1 428 Precondition Required`. Then copy the `ctfw_name` cookie from your browser's DevTools and run `curl -s -o /dev/null -w "%{http_code}\n" -b "ctfw_name=<value>" http://127.0.0.1:8888/`.
   Verify: the second command prints `200` if you are approved, `428` if you are still in the queue (and the body names you).
3. **Rename round-trip.** In the dashboard, use "ask to rename" on your own student row, then reload the CTF tab: you get the form with the organizer's message. Submit the **same** name → the form comes back with "That name was not accepted". Submit a different name → you are redirected and the Students table shows one row under the new name.
   Verify: `curl -s -b "<dashboard cookie>" http://127.0.0.1:8080/api/admin` shows an empty `renamePending` array afterwards.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `NameGate` | `new NameGate({ secretFile?, cookie?, getConfig?, onProfile?, approvals?, onEnqueue? })` | The gate; one instance per process. |
| `.handle(req, res)` | `(req, res) => boolean` | Per-request entry; `true` if answered. |
| `.nameFrom(req)` | `(req) => string \| null` | Verified raw name from the cookie. |
| `.sign(name)` | `(string) => string` | 24-char HMAC tag. |
| `NameGate.clean(name)` | `static (any) => string \| null` | Sanitise to 2-32 allowed chars. |
| `.validate(form)` | `(URLSearchParams) => { name, profile, values } \| { error, values }` | Check submitted answers against the config. |
| `.rememberIp(ip, name)` / `.nameForIp(ip)` | `(ip, name) => void` / `(ip) => string \| null` | IP → unambiguous gate name memory. |
| `.revoke(raw)` / `.unrevoke(raw)` / `.isRevoked(raw)` | `(string) => …` | "Ask to rename" set. |
| `.isNavigation(req)` | `(req) => boolean` | Browser page-load heuristic. |
| `.statusOf(name)` | `(raw \| null) => 'none' \| 'approved' \| 'pending' \| 'blocked'` | Page-facing queue status. |
| `.notifyWaiters(names)` | `(string[]) => void` | Push status to open streams; wired to `approvals.onChange`. |
| `.page(next, error?, values?)` | `(string, string?, object?) => html` | The form. |
| `.waitPage(name)` / `.blockedPage()` | `(string) => html` / `() => html` | Waiting and blocked pages. |
| `.refuse(req, res, status, text)` | `(…) => true` | Plain-text or JSON refusal. |
| `.requiredLabels()` | `() => string` | "Your name, Student ID". |
| `.config` / `.enabled` | getters | Normalised config / its `enabled` flag. |
| `normalizeConfig(raw)` | `(any) => config` | Validate and complete a Gate-tab config. |
| `GATE_PATH`, `STATUS_PATH`, `STREAM_PATH` | strings | `/__ctfwatch/name`, `/__ctfwatch/status`, `/__ctfwatch/wait`. |
| `DEFAULT_CONFIG`, `TYPES` | object, string[] | Defaults and allowed field types. |

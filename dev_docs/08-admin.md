# Admin — `proxy/src/admin.js`

## Purpose

Organizers act on students from the dashboard: block someone (by name and, when safe, by IP), unblock them, rename a row ("ip:10.0.0.7" → "Sara"), or ask a student to re-enter their name at the gate because the one they typed is not acceptable. This module holds those decisions, persists them in the DB key `admin_state`, and propagates renames into the live store, the IDOR detector and the decoy list so that a student's history follows the new name. It is also the bridge between the organizer's naming (aliases) and the raw names the gate cookie carries.

## Where it sits

- **Required by** `server.js` (line 12). No unit test file targets it directly.
- **Constructed once** in `server.js` line 83: `new Admin({ db, store, detector, gate })`, after the gate and store exist.
- **Callers:**
  - `server.js` `preRequest()` line 174: `admin.isBlocked(who.name, ip)` → 403 page before proxying.
  - `server.js` `withAlias()` line 126 and many other places: `admin.alias(rawName)` to turn a raw gate name into the display name.
  - `server.js` lines 86-88: `store.isBlocked`, `store.renamePending` (`admin.isRenamePending`), `store.queueStatus` (`admin.rawNameFor`).
  - `server.js` `queueDecide()` lines 63-73: `admin.block(display, ip)` / `admin.unblock(display)` when the queue decision changes.
  - `server.js` `auth.onConflict` lines 104-107: writes `admin.state.blocked['ip:<ip>']` directly and calls `admin.save()`.
  - `dashboard.js` lines 188-199: `list()`, `block`, `unblock`, `rename`, `requireRename`, and `/api/admin/unblock-ip` which deletes `state.blocked['ip:…']` directly.
- **Requires** `./util` (`log`) and `./namegate` (only the static `NameGate.clean`). Uses `db.get/set`, `store.students` / `store.renameStudent`, `detector.renameStudent`, and on the gate: `onRename` (sets it), `revoke`, `enabled`, `ipNames`.
- **Hooks:**
  - **Sets** `gate.onRename = (oldRaw, newName) => this.onGateRename(oldRaw, newName)` in the constructor (line 16): the gate reports a student who renamed themselves after a revoke.
  - **Exposes** `onRenamed(from, to)`: `server.js` line 276 sets it to `decoy.rename(from, to)`. Only `rename()` (organizer rename) fires it.

## Data it owns

### `state` (persisted as `admin_state`)

| Field | Type | Meaning |
|---|---|---|
| `blocked` | `{ [displayName]: { ip, ts, reason? } }` | Blocked students. Key is the display name. `ip` is the IP to block as well, or `null` when unknown/shared/loopback. `server.js` adds synthetic keys `ip:<ip>` with a `reason` for dashboard login conflicts. |
| `aliases` | `{ [rawName]: displayName }` | Organizer renames. `rawName` is what the gate cookie (or the app) produced; the value is what the dashboard shows. |
| `revoked` | `{ [rawName]: ts }` | Names the organizer asked to be re-entered ("ask to rename"). Mirrors `gate.revoked` so it survives restarts. |

### Other instance fields

| Field | Meaning |
|---|---|
| `db`, `store`, `detector`, `gate` | Collaborators. `gate` may be `null` in principle (guards everywhere), though `server.js` always passes one. |
| `onRenamed` | Optional hook `(from, to) => void`; not initialised in the constructor (undefined until set). |

## Walkthrough

### Imports and constructor

```js
// lines 1-17
'use strict';
// Organizer actions from the dashboard: block / unblock / rename / ask-to-rename a student.
// State lives in the database (kv table) so it survives a restart.

const { log } = require('./util');
const { NameGate } = require('./namegate');

class Admin {
  constructor({ db, store, detector, gate }) {
    this.db = db;
    this.store = store;
    this.detector = detector;
    this.gate = gate;
    this.state = { blocked: {}, aliases: {}, revoked: {} };
    this.load();
    if (this.gate) this.gate.onRename = (oldRaw, newName) => this.onGateRename(oldRaw, newName);
  }
```

`NameGate` is imported only for `NameGate.clean` (the shared name sanitiser), so organizer-given names obey the same character rules as student-typed ones. Line 16 wires the gate → admin direction: `namegate.js` line 309 calls `this.onRename(prev, v.name)` when a revoked student submits a different name.

### `load()` and `save()`

```js
// lines 19-32
  load() {
    const raw = this.db.get('admin_state', null);
    if (raw && typeof raw === 'object') {
      this.state.blocked = raw.blocked || {};
      this.state.aliases = raw.aliases || {};
      this.state.revoked = raw.revoked || {};
      if (this.gate) for (const r of Object.keys(this.state.revoked)) this.gate.revoke(r);
      const n = Object.keys(this.state.blocked).length;
      if (n) log('info', `admin: ${n} blocked student(s) loaded`);
    }
  }
  save() {
    this.db.set('admin_state', this.state);
  }
```

- Line 25: the gate keeps its own in-memory `revoked` map (chapter 05); it is re-seeded from the persisted state on start so an "ask to rename" survives a restart.
- `save()` writes the whole `state` object. Other modules call `admin.save()` after poking `admin.state.blocked` directly (`server.js` line 106, `dashboard.js` line 199) — the state object is intentionally public.

### Aliases and blocked lookups

```js
// lines 34-45
  alias(rawName) {
    return this.state.aliases[rawName] || rawName;
  }
  blockedIps() {
    const s = new Set();
    for (const b of Object.values(this.state.blocked)) if (b && b.ip) s.add(b.ip);
    return s;
  }
  isBlocked(name, ip) {
    if (this.state.blocked[name]) return true;
    return !!(ip && this.blockedIps().has(ip));
  }
```

- `alias` is total: an unknown raw name maps to itself. It is called on every request path (`withAlias`), so it must stay a plain object lookup.
- `blockedIps()` rebuilds a `Set` on every call. `isBlocked` is called once per request in `preRequest`; with a handful of blocked students this is negligible, but it is the first thing to cache if the blocked list ever grows large.
- `isBlocked(name, ip)` is true if the **display** name is blocked, or if the request's IP matches the IP recorded with *any* block (including the `ip:<ip>` entries from dashboard login conflicts). The `ip &&` guard means `'unknown'` is never matched because no block ever stores `'unknown'` (see `block()`).

### `block(name, ipOverride)` and `unblock(name)`

```js
// lines 47-62
  block(name, ipOverride) {
    if (!name) throw new Error('student name required');
    const s = this.store.students.get(name);
    let ip = ipOverride || (s ? s.ip : null);
    if (ip && this.gate && this.gate.ipNames.get(ip) && this.gate.ipNames.get(ip).names.size > 1) ip = null; // shared ip
    if (ip && /^(127\.|::1|unknown)/.test(ip)) ip = null;
    this.state.blocked[name] = { ip, ts: Date.now() };
    this.save();
    log('info', `admin: blocked ${name}${ip ? ` (ip ${ip})` : ''}`);
    return { name, ip };
  }
  unblock(name) {
    delete this.state.blocked[name];
    this.save();
    log('info', `admin: unblocked ${name}`);
  }
```

- Line 50: the IP comes from the explicit override (`queueDecide` passes the IP recorded in the queue item) or from the live store row's last IP. A student never seen live (e.g. blocked from the queue before any request reached the CTF) still gets their queue IP.
- Line 51: **shared-IP guard.** `gate.ipNames` (chapter 05) knows how many gate names were seen from this IP. If more than one, blocking the IP would block classmates behind the same NAT, so only the name is blocked. The check uses only gate knowledge; two app sessions from one IP without the gate are not detected.
- Line 52: never block loopback or `unknown` (that would block the organizer's own tests and every request without a resolvable IP).
- Blocking is keyed by display name; `isBlocked` is called with `who.name` after `withAlias`, so the two agree.
- `unblock` only removes the name entry; it does not know about the `ip:<ip>` conflict entries (those have their own endpoint).

### `rawNameFor(displayName)`

```js
// lines 64-68
  rawNameFor(displayName) {
    for (const [raw, al] of Object.entries(this.state.aliases)) if (al === displayName) return raw;
    const s = this.store.students.get(displayName);
    return (s && s.rawName) || displayName;
  }
```

The reverse of `alias`: first an explicit alias, then the `rawName` the store recorded on the student row (set from the event's `rawName`, which `withAlias` fills), else the name itself. Needed wherever the gate or queue (raw-keyed) must be addressed from a display name: `requireRename`, `isRenamePending`, `store.queueStatus`. If two raw names were aliased to the same display name, the first one in insertion order wins.

### `rename(from, to)` — organizer rename

```js
// lines 70-84
  rename(from, to) {
    const clean = NameGate.clean(to);
    if (!clean) throw new Error('new name must be 2-32 letters, digits, space, _ . -');
    if (!from || from === clean) return clean;
    let found = false;
    for (const [raw, al] of Object.entries(this.state.aliases)) if (al === from) { this.state.aliases[raw] = clean; found = true; }
    if (!found) this.state.aliases[from] = clean;
    if (this.state.blocked[from]) { this.state.blocked[clean] = this.state.blocked[from]; delete this.state.blocked[from]; }
    this.save();
    this.store.renameStudent(from, clean);
    this.detector.renameStudent(from, clean);
    if (this.onRenamed) this.onRenamed(from, clean);
    log('info', `admin: renamed ${from} -> ${clean}`);
    return clean;
  }
```

- Line 71: `NameGate.clean` keeps letters/digits (any script), space, `_`, `.`, `-`, `@`; trims; cuts at 32; requires at least 2 characters. The error text (line 72) lists the ASCII subset; `@` is also allowed.
- Line 73: renaming to the same name is a no-op that still returns the cleaned value.
- Lines 75-76: if `from` is itself already a display name produced by an alias (A → B, now B → C), the existing alias is rewritten to point at C (`A → C`) rather than chaining, so `alias()` stays a single lookup. Otherwise a new alias `from → clean` is created; `from` may be an `ip:…` label, a `sess-…` label, an app username or a raw gate name.
- Line 77: a block follows the name.
- Lines 79-81: live state follows the name: the store merges the rows (counters, IPs, events, alert texts), the detector moves per-student state and learned ownership, and the `onRenamed` hook moves the decoy entry. The DB history is **not** rewritten; past events keep the old `student` value but share the `playerId` where player matching applied.
- From now on, every new request from the raw identity is displayed as `clean` because `withAlias` runs `admin.alias` on every resolved identity.

### `requireRename` / `isRenamePending` / `onGateRename`

```js
// lines 86-106
  requireRename(displayName) {
    if (!this.gate || !this.gate.enabled) throw new Error('the gate is switched off (Gate tab) - turn it on to ask students for their name');
    const raw = this.rawNameFor(displayName);
    this.gate.revoke(raw);
    this.state.revoked[raw] = Date.now();
    this.save();
    log('info', `admin: asked ${displayName} to rename`);
    return { name: displayName };
  }
  isRenamePending(displayName) {
    return !!this.state.revoked[this.rawNameFor(displayName)];
  }
  onGateRename(oldRaw, newName) {
    const oldDisplay = this.alias(oldRaw);
    delete this.state.aliases[oldRaw];
    delete this.state.revoked[oldRaw];
    if (this.state.blocked[oldDisplay]) { this.state.blocked[newName] = this.state.blocked[oldDisplay]; delete this.state.blocked[oldDisplay]; }
    this.save();
    this.store.renameStudent(oldDisplay, newName);
    this.detector.renameStudent(oldDisplay, newName);
  }
```

- `requireRename`: the revoke only has an effect through the gate (`namegate.js` lines 331-334 show the form again; line 294 refuses re-submitting the same name), so it is rejected when the gate is off. The raw name is revoked both in the gate's memory and in persisted state. The student's existing rows are untouched; they continue to be displayed under the old name until the student submits a new one.
- `isRenamePending` feeds the "rename pending" badge in the Students table (`store.renamePending`).
- `onGateRename` runs when the gate accepts a **different** name from a revoked student (namegate.js lines 306-309). It drops any alias and the revoke for the old raw name (the new raw name is the new display name; no alias needed), moves a block, and merges the live rows under the new name. It does **not** call `onRenamed`, so the decoy entry (keyed by the old display name) is not moved; and it does not re-check `NameGate.clean` because the gate already validated the new name.
- Note the asymmetry with `rename()`: the organizer rename creates an alias; the gate rename deletes one. After a gate rename the student's cookie carries the new raw name, so no mapping is required.

### `list()` and export

```js
// lines 108-117
  list() {
    return {
      blocked: Object.entries(this.state.blocked).map(([name, b]) => ({ name, ip: b.ip, ts: b.ts })),
      aliases: this.state.aliases,
      renamePending: Object.keys(this.state.revoked).map((raw) => this.alias(raw)),
    };
  }
}

module.exports = { Admin };
```

`blocked` drops the `reason` field of conflict entries (the dashboard adds `dashboardBlockedIps` from `auth` separately). `renamePending` is translated to display names for the UI.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` `preRequest` | `isBlocked(displayName, ip)` → boolean, decides the 403 |
| in | `server.js` `withAlias`, `mergeLane`, `queueDecide`, `onProfile`, `onEnqueue` | `alias(raw)`, `rawNameFor(display)`, `block(display, ip)`, `unblock(display)`, `state.blocked[...]` direct reads/writes, `save()` |
| in | `dashboard.js` `/api/admin/*` | `list()`, `block(student)`, `unblock(student)`, `rename(student, newName)`, `requireRename(student)`, direct `state.blocked` deletion + `save()` |
| out | `store.js` | `store.students.get(name)` (ip, rawName), `store.renameStudent(from, to)` |
| out | `detect.js` | `detector.renameStudent(from, to)` |
| out | `namegate.js` | `NameGate.clean`, `gate.revoke(raw)`, `gate.enabled`, `gate.ipNames` (shared-IP check); sets `gate.onRename` |
| out (hook) | `server.js` → `decoy.rename` via `onRenamed` | `(from, to)` on organizer renames only |
| out | `db.js` | `db.get('admin_state')`, `db.set('admin_state', state)` |

## Changing it safely

| Likely change | Where |
|---|---|
| Block with an expiry ("block for 10 minutes") | Store `until` in the `blocked` entry (line 53) and check it in `isBlocked` (line 43) and `blockedIps` (line 39). |
| Keep the decoy entry when a student self-renames | Add `if (this.onRenamed) this.onRenamed(oldDisplay, newName);` at the end of `onGateRename` (after line 105). |
| Record who performed an action | `block`, `rename`, `requireRename` receive no actor today; add a `by` parameter, pass `user.username` from `dashboard.js` lines 195-198, and store it next to `ts`. |
| Cache `blockedIps()` | Maintain a `Set` updated in `block`, `unblock`, `load`, and wherever `state.blocked` is mutated directly (`server.js` line 105, `dashboard.js` line 199) — those direct writes are the trap. |

Tests: there is no `admin.test.js`. Related coverage: `proxy/test/gate.test.js` indirectly checks `NameGate.clean` through `validate: username cleaning, …` (`' Gohary<b> '` → `Goharyb`); `proxy/test/queue.test.js` covers the `Approvals` side of `queueDecide` but not `admin.block`; `proxy/test/core.test.js` → `detector: renaming a student carries state and learned ownership` covers `detector.renameStudent`, which `rename` relies on. Behaviour of `rename`, `isBlocked` and `requireRename` is only verified manually or by writing a new test with `new Db(':memory:')`, a `Store`, a `Detector` and a `NameGate`.

## Exercises

1. **Write the first admin test.** Create `proxy/test/admin.test.js` that builds `new Admin({ db: new Db(':memory:'), store: new Store({ logDir: os.tmpdir(), db }), detector: new Detector(() => ({ compiledEndpoints: [] })), gate: null })`, calls `rename('ip:1.2.3.4', 'Sara')`, and asserts `alias('ip:1.2.3.4') === 'Sara'` and `rawNameFor('Sara') === 'ip:1.2.3.4'`. Also assert `rename('x', '!')` throws.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node --test test/admin.test.js`
2. **Shared-IP guard.** In the same test, pass a real `NameGate` as `gate`, call `gate.rememberIp('10.0.0.9', 'A')` and `gate.rememberIp('10.0.0.9', 'B')`, then `admin.block('A', '10.0.0.9')`.
   Verify: the returned object has `ip: null` and `admin.isBlocked('C', '10.0.0.9')` is `false`.
3. **Persistence round-trip.** Block `Sara` with IP `10.0.0.7`, construct a second `Admin` on the same `db` and check `isBlocked('nobody', '10.0.0.7')`.
   Verify: prints `true` with `node -e` using the same construction as exercise 1.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Admin` | `new Admin({ db, store, detector, gate })` | Loads `admin_state`, re-seeds gate revokes, wires `gate.onRename`. |
| `.load()` / `.save()` | `() => void` | Read / write `admin_state`. |
| `.alias(raw)` | `(rawName) => displayName` | Organizer rename lookup; identity when none. |
| `.rawNameFor(display)` | `(displayName) => rawName` | Reverse lookup via aliases, then the store row, else itself. |
| `.blockedIps()` | `() => Set<string>` | IPs attached to any block. |
| `.isBlocked(name, ip)` | `(displayName, ip) => boolean` | Blocked by name or by IP. |
| `.block(name, ipOverride?)` | `(displayName, ip?) => { name, ip }` | Block; IP dropped when shared, loopback or unknown. |
| `.unblock(name)` | `(displayName) => void` | Remove the name block. |
| `.rename(from, to)` | `(displayName, newName) => cleanName` | Alias + move block + rename in store, detector and decoy; throws on a bad name. |
| `.requireRename(name)` | `(displayName) => { name }` | Revoke the raw name at the gate; throws if the gate is off. |
| `.isRenamePending(name)` | `(displayName) => boolean` | Revoke outstanding. |
| `.onGateRename(oldRaw, newName)` | internal hook target | Clean up alias/revoke, move block, rename live rows. |
| `.onRenamed` | `(from, to) => void \| undefined` | Hook fired by `rename()`. |
| `.list()` | `() => { blocked: [{ name, ip, ts }], aliases, renamePending: string[] }` | Dashboard view. |
| `.state` | `{ blocked, aliases, revoked }` | Public, persisted. |

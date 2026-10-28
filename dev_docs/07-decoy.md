# Decoy — `proxy/src/decoy.js`

## Purpose

Sometimes an organizer wants to take a student off the real challenge without telling them: a suspected cheater, someone sharing flags, or simply a student to observe on a sandbox copy. The decoy is a second app (another port) behind the same proxy. Students on the decoy list are transparently routed there: same link, same cookies, no visible change. This module is only the list and the decision ("which upstream for this name?"); the actual routing happens in `proxy.js` through the `getTargetFor` callback.

## Where it sits

- **Required by** `server.js` (line 15) and the test `proxy/test/decoy.test.js`.
- **Constructed once** in `server.js` line 259: `new Decoy({ db })`.
- **Callers:**
  - `server.js` `getTargetFor(req)` (lines 260-264): resolves the identity, applies the alias, then calls `decoy.targetFor(who.name)`. `proxy.js` `currentUpstream()` (line 38) calls `getTargetFor(req)` for every request and every WebSocket upgrade; a non-null result replaces the real target.
  - `server.js` `decoySet(name, on, by)` (lines 265-274): `add` / `remove` plus a dashboard alert.
  - `server.js` line 275: `store.isDecoy = (name) => decoy.has(name)` so the Students table can show a decoy badge; `onEvent` line 224-225 adds a `decoy` flag to every event of a decoyed student.
  - `server.js` line 276: `admin.onRenamed = (from, to) => decoy.rename(from, to)` so a renamed student stays on the decoy.
  - `dashboard.js`: `list()` (GET `/api/decoy`), `setTarget(url)` (POST `/api/decoy`), `decoySet` for `/api/decoy/add` and `/api/decoy/remove`, `onChange` (line 416) to broadcast the list, and `decoySet(admin.alias(n), true, …)` when a queue approval carries `decoy: true`.
- **Requires** `./util` (`log`) and a `Db` with `get` / `set`.
- **Hook it exposes:** `onChange(fn)`, `fn()` with no arguments, after every `save()`.

## Data it owns

| Field | Type | Meaning |
|---|---|---|
| `db` | `Db` | Persistence under key `decoy`. |
| `target` | string \| null | Base URL of the decoy app, e.g. `http://127.0.0.1:4000`. `null` means "no decoy app picked"; then nobody is routed, whatever the list says. |
| `students` | `Map<displayName, { since, by, reason }>` | Who is on the decoy. Keyed by the **display** name (alias applied), unlike the approvals queue which uses raw names. |
| `students.get(name).since` | number (ms) | When they were added. |
| `students.get(name).by` | string \| null | Dashboard username that added them. |
| `students.get(name).reason` | string \| null | Free text; the dashboard currently never passes one (`decoySet` calls `add(name, by)`), so it is always `null` in practice. |
| `listeners` | `Set<fn>` | Change subscribers. |

Stored JSON shape: `{ target: string | null, students: { [name]: { since, by, reason } } }`.

## Walkthrough

### Header and constructor

```js
// lines 1-14
'use strict';
// The decoy: a second app behind the proxy. Students on the decoy list are routed to it instead of
// the real CTF, transparently (same link, same cookies). Persisted in the database (kv "decoy").

const { log } = require('./util');

class Decoy {
  constructor({ db }) {
    this.db = db;
    const saved = db.get('decoy', null) || {};
    this.target = saved.target || null; // http://host:port or null
    this.students = new Map(Object.entries(saved.students || {})); // display name -> { since, by, reason }
    this.listeners = new Set();
  }
```

- Line 10: `db.get` with fallback `null`, then `|| {}` covers both "key absent" and "stored null". Each sub-field has its own default so a partial record (e.g. an older DB without `students`) loads cleanly.
- Line 12: `new Map(Object.entries(obj))` is the inverse of `Object.fromEntries(map)` used in `save()`.
- The target is stored here, independent of the real proxy target (`proxy_target` key, managed by `server.js` `setTarget`). Both are validated by `ports.validateTarget` before they get here (`dashboard.js` line 294).

### `onChange` and `save`

```js
// lines 15-25
  onChange(fn) {
    this.listeners.add(fn);
  }
  save() {
    this.db.set('decoy', { target: this.target, students: Object.fromEntries(this.students) });
    for (const l of this.listeners) {
      try {
        l();
      } catch {}
    }
  }
```

Same pattern as `approvals.js`: whole-object rewrite, then synchronous, exception-safe fan-out. Listeners get no arguments; the dashboard re-sends the full `list()`.

### `setTarget(url)`

```js
// lines 26-30
  setTarget(url) {
    this.target = url || null;
    this.save();
    log('info', `decoy target: ${this.target || '(none)'}`);
  }
```

Setting the target to `null` switches the decoy off for everyone but **keeps the list**. `decoy.test.js` checks exactly this: after `setTarget(null)`, `targetFor('Alice K')` is `null`, yet the student can still be removed. Validation of the URL is the caller's job (`dashboard.js` runs `validateTarget`); the module trusts what it gets.

### Membership and the routing decision

```js
// lines 31-37
  has(name) {
    return this.students.has(name);
  }
  // the upstream this student should get, or null for the real CTF
  targetFor(name) {
    return this.target && name && this.students.has(name) ? this.target : null;
  }
```

- `has` is the badge check (list membership, regardless of target).
- `targetFor` is the routing check: all three of a configured target, a non-empty name and list membership are needed. The `name &&` guard means an identity of `''`/`null` can never be routed, even if someone managed to add an empty key.
- Because the key is the display name, routing follows whatever `identity.resolve` + `admin.alias` produce. A student recognised only by `ip:1.2.3.4` can be put on the decoy under that label; a student on `ip-match` is routed under the matched gate name. `getTargetFor` in `server.js` (line 261) short-circuits when there is no target or the list is empty, so the identity resolver is not even run in the common case.

### `add`, `remove`, `rename`

```js
// lines 38-59
  add(name, by, reason) {
    if (!name) throw new Error('student name required');
    this.students.set(name, { since: Date.now(), by: by || null, reason: reason || null });
    this.save();
    log('info', `decoy: ${name} -> decoy${by ? ` (by ${by})` : ''}`);
  }
  remove(name) {
    const had = this.students.delete(name);
    if (had) {
      this.save();
      log('info', `decoy: ${name} -> back to the real CTF`);
    }
    return had;
  }
  rename(from, to) {
    if (this.students.has(from)) {
      const v = this.students.get(from);
      this.students.delete(from);
      this.students.set(to, v);
      this.save();
    }
  }
```

- `add` on an existing name **overwrites** `since` and `by` (a re-add resets the clock). The thrown error for an empty name surfaces as a 400 from the dashboard (`dashboard.js` catches and returns `err.message`). Note that `server.js` `decoySet` throws its own error *before* `add` if no target is set ("pick a decoy app first"), so you cannot build a list ahead of picking the app via the UI.
- `remove` returns a boolean and only saves/logs when something was actually removed; `server.js` emits the "back on the real CTF" alert regardless.
- `rename` keeps the record (including `since` and `by`) under the new key. If `to` already exists on the list it is overwritten by `from`'s record. It is wired to `admin.onRenamed` (organizer renames) only; a student renaming themselves through the gate goes through `admin.onGateRename`, which does **not** call `onRenamed`, so a self-renamed student drops off the decoy under their new name. See chapter 08.

### `list()` and export

```js
// lines 60-65
  list() {
    return { target: this.target, students: [...this.students.entries()].map(([name, v]) => ({ name, ...v })) };
  }
}

module.exports = { Decoy };
```

Returns the JSON shape the Decoy tab renders: the target plus an array with the name folded into each record. Insertion order is preserved (the order students were added).

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` `getTargetFor` → `proxy.js` `currentUpstream` | `targetFor(displayName)` → upstream URL or `null` for every request and upgrade |
| in | `server.js` `decoySet` | `add(name, by)`, `remove(name)` |
| in | `server.js` line 275 | `has(name)` via `store.isDecoy` for the badge and the `decoy` event flag |
| in (hook) | `server.js` line 276 via `admin.onRenamed` | `rename(from, to)` |
| in | `dashboard.js` | `list()`, `setTarget(url)`, `onChange(() => broadcast)` |
| out | `db.js` | `db.get('decoy')` at start, `db.set('decoy', …)` on change |
| out | `util.js` | `log` |

## Changing it safely

| Likely change | Where |
|---|---|
| Several decoy apps (per-student target) | Store the URL inside each student record in `add()` (line 40), make `targetFor()` return `this.students.get(name).target || this.target`. `proxy.js` already caches parsed URLs per string, so no change there. |
| Route by IP as well as by name | `targetFor` only receives a name. Change `server.js` `getTargetFor` to pass `clientIp(req)` too and add an `ips` map here. |
| Make a self-rename at the gate keep the decoy | In `admin.js` `onGateRename` (line 98), call `this.onRenamed(oldDisplay, newName)` after the store/detector renames; nothing changes in this file. |
| Use the `reason` field | Pass a third argument from `server.js` `decoySet` (line 268) and read `body.reason` in `dashboard.js` line 299. |

Tests: `proxy/test/decoy.test.js` → `decoy: target, list membership, routing decision, rename, persistence` covers `targetFor` with and without a target, `add`, `rename`, reload from the same `Db`, `list().students[0].by`, `setTarget(null)` and `remove` return values. The routing integration (`currentUpstream` picking the decoy URL) has no automated test.

## Exercises

1. **Check the empty-name guard.** In a `node -e` script create `new Decoy({ db: new Db(':memory:') })` and call `add('')`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node -e "const {Db}=require('./src/db');const {Decoy}=require('./src/decoy');try{new Decoy({db:new Db(':memory:')}).add('')}catch(e){console.log(e.message)}"` prints `student name required`.
2. **See the routing live.** Start the stack with a real CTF target, start a second trivial server on port 4000 (`node -e "require('http').createServer((q,s)=>s.end('DECOY')).listen(4000)"`), set it as decoy target in the dashboard (POST `/api/decoy` with `{ "url": "http://127.0.0.1:4000" }`), add your gate name via `/api/decoy/add`, then reload the CTF link in the browser.
   Verify: the browser shows `DECOY`; `curl -s http://127.0.0.1:8080/api/decoy` (with your dashboard session cookie) lists you under `students`.
3. **Rename overwrite.** Extend `decoy.test.js`: add `alice` and `bob`, `rename('alice', 'bob')`, assert `list().students.length === 1` and that its `by` is alice's.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node --test test/decoy.test.js`

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Decoy` | `new Decoy({ db })` | Loads target and list from `db` key `decoy`. |
| `.onChange(fn)` | `(fn: () => void) => void` | Subscribe to every save. |
| `.save()` | `() => void` | Persist and notify listeners. |
| `.setTarget(url)` | `(string \| null) => void` | Set or clear the decoy app URL; list is kept. |
| `.has(name)` | `(displayName) => boolean` | On the list (ignores target). |
| `.targetFor(name)` | `(displayName) => string \| null` | Decoy URL if target set and name listed, else `null`. |
| `.add(name, by?, reason?)` | `(displayName, by?, reason?) => void` | Add/overwrite; throws on empty name. |
| `.remove(name)` | `(displayName) => boolean` | Remove; `true` if it was listed. |
| `.rename(from, to)` | `(string, string) => void` | Move the record to a new key. |
| `.list()` | `() => { target, students: [{ name, since, by, reason }] }` | Dashboard view. |

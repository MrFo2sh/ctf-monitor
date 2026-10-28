# Approvals — `proxy/src/approvals.js`

## Purpose

When the gate's queue mode is on, a student who filled the form is not let into the CTF until an organizer clicks "approve" in the Queue tab. This module is the store for that admission queue: one record per raw gate name with a status of `pending`, `approved` or `blocked`, persisted in the SQLite key/value table so decisions survive a restart. It knows nothing about HTTP; `namegate.js` asks it for a status and `server.js` / `dashboard.js` change statuses.

## Where it sits

- **Required by** `server.js` (line 14) and the test `proxy/test/queue.test.js`.
- **Constructed once** in `server.js` line 48: `new Approvals({ db })`, before the `NameGate`, which receives it as `approvals`.
- **Callers:**
  - `namegate.js`: `status(name)`, `enqueue(name, info)`, and subscribes with `onChange(fn)` to push decisions to open waiting pages.
  - `server.js` `queueDecide()` (lines 63-73): `approve` / `block` / `reset`, then `get(raw)` to find the IP for a proxy-level block.
  - `server.js` line 88: `approvals.status(admin.rawNameFor(name))` to show the queue status in the Students table.
  - `dashboard.js`: `counts()`, `list()`, `remove(names)` for the Queue tab, and `onChange` (line 415) to broadcast the queue over WebSocket.
- **Requires** `./util` (`log`) and a `Db` instance with `get(k, fallback)` / `set(k, v)`.
- **Hook it exposes:** `onChange(fn)` where `fn(changedNames: string[])` is called after every `save()`.

## Data it owns

### Instance fields

| Field | Type | Meaning |
|---|---|---|
| `db` | `Db` | Persistence. Key `gate_queue` holds the whole queue as one JSON object. |
| `items` | `Map<rawName, item>` | The queue, keyed by the **raw** name typed on the form (not the alias the organizer may have given). |
| `listeners` | `Set<fn>` | Change subscribers. |

### Queue item

| Field | Type | Meaning |
|---|---|---|
| `name` | string | Raw gate name (same as the map key). |
| `profile` | object | Extra gate answers (`{ sid: '42', team: 'blue' }`); password-type answers are stored as `'***'` by the gate's validator. Merged on re-submit. |
| `ip` | string \| null | Client IP at the last submission. Used by `queueDecide` to also block the IP. |
| `ua` | string \| null | User-Agent, truncated to 160 chars by the caller. |
| `firstSeen` | number (ms) | When the record was created. Sort key within a status group. |
| `status` | `'pending' \| 'approved' \| 'blocked'` | The decision. |
| `decidedAt` | number \| null | When the last non-pending decision was made; `null` while pending. |
| `by` | string \| null | Dashboard username that decided; `null` while pending. |

### Module constant

`STATUSES = ['pending', 'approved', 'blocked']` — the only accepted statuses, and also the display order of `list()`.

## Walkthrough

### Imports and constants

```js
// lines 1-7
'use strict';
// The admission queue: students who filled the gate form wait here until the organizer approves them.
// Persisted in the database (kv "gate_queue"), keyed by the raw name typed on the form.

const { log } = require('./util');

const STATUSES = ['pending', 'approved', 'blocked'];
```

The queue is keyed by the raw name because that is what the signed gate cookie carries. Organizer renames (aliases, chapter 08) are applied on top by `admin.alias(raw)` whenever a queue name is shown or compared with a store row.

### Constructor and persistence

```js
// lines 9-26
class Approvals {
  constructor({ db }) {
    this.db = db;
    this.items = new Map(); // rawName -> { name, profile, ip, ua, firstSeen, status, decidedAt, by }
    for (const [k, v] of Object.entries(db.get('gate_queue', {}) || {})) this.items.set(k, v);
    this.listeners = new Set();
  }
  onChange(fn) {
    this.listeners.add(fn);
  }
  save(changedNames) {
    this.db.set('gate_queue', Object.fromEntries(this.items));
    for (const l of this.listeners) {
      try {
        l(changedNames || []);
      } catch {}
    }
  }
```

- Line 13: `db.get` parses the stored JSON, returning the fallback `{}` when the key is missing or unparsable; the `|| {}` guards a stored `null`. Items are loaded as plain objects straight into the map, so the shape in the DB is the shape in memory.
- Line 20: the whole map is rewritten on every change. The queue is small (one entry per student), so this is simpler and safer than per-row updates.
- Lines 21-25: listeners are called synchronously after the write, with the list of names whose status changed. A throwing listener never breaks a decision. `enqueue` calls `save()` with no argument, so listeners get `[]`; the gate's `notifyWaiters` then iterates nothing (a newly enqueued student has no open stream yet anyway), while the dashboard listener ignores its argument and re-broadcasts the full list.

### `enqueue(name, info)`

```js
// lines 28-42
  // Called when a student submits the form (or shows up with a cookie we have not seen). Keeps an existing decision.
  enqueue(name, info = {}) {
    let it = this.items.get(name);
    if (!it) {
      it = { name, profile: info.profile || {}, ip: info.ip || null, ua: info.ua || null, firstSeen: Date.now(), status: 'pending', decidedAt: null, by: null };
      this.items.set(name, it);
      log('info', `queue: ${name} is waiting for approval${it.ip ? ` (ip ${it.ip})` : ''}`);
    } else {
      if (info.profile && Object.keys(info.profile).length) it.profile = { ...it.profile, ...info.profile };
      if (info.ip) it.ip = info.ip;
      if (info.ua) it.ua = info.ua;
    }
    this.save();
    return it;
  }
```

- The function is idempotent with respect to **status**: a student who resubmits the form (or who is enqueued again by the gate because their cookie predates the queue) keeps `approved` / `blocked`. That is why `queue.test.js` asserts `status('Gohary') === 'approved'` after a second `enqueue`.
- Profile answers are merged, not replaced, so a later submission with fewer fields does not erase earlier answers. IP and UA are refreshed (the student may have moved network).
- `save()` runs even when nothing changed; cheap and keeps the code branch-free.
- Returns the item so a caller could inspect it; the gate ignores the return value.

### Reading

```js
// lines 44-50
  status(name) {
    const it = this.items.get(name);
    return it ? it.status : null; // null = never seen
  }
  get(name) {
    return this.items.get(name) || null;
  }
```

`status()` returning `null` (never seen) versus `'pending'` matters: the gate uses `null` to detect a cookie from before the queue was switched on and enqueues the student on the spot (namegate.js lines 338-343); `server.js` line 88 shows `null` as "no queue entry" in the Students table.

### `decide(names, status, by)` and its wrappers

```js
// lines 52-77
  decide(names, status, by) {
    if (!STATUSES.includes(status)) throw new Error('bad status');
    const changed = [];
    for (const n of [].concat(names || [])) {
      const it = this.items.get(n);
      if (!it) continue;
      it.status = status;
      it.decidedAt = status === 'pending' ? null : Date.now();
      it.by = status === 'pending' ? null : by || null;
      changed.push(n);
    }
    if (changed.length) {
      this.save(changed);
      log('info', `queue: ${status} -> ${changed.join(', ')}${by ? ` (by ${by})` : ''}`);
    }
    return changed;
  }
  approve(names, by) {
    return this.decide(names, 'approved', by);
  }
  block(names, by) {
    return this.decide(names, 'blocked', by);
  }
  reset(names) {
    return this.decide(names, 'pending');
  }
```

- Line 55: `[].concat(x)` accepts a single string or an array, so `approve('Gohary')` and `approve(['Gohary', 'Sara'])` both work.
- Line 57: unknown names are skipped silently and are not in the returned list. `queue.test.js` checks `approve(['Gohary', 'nobody'])` returns `['Gohary']`. `server.js` `queueDecide` relies on this to only block/unblock students that really changed.
- Lines 59-60: `reset` clears the audit fields; any other status stamps them. A name that is already in the requested status is still counted as "changed" (the timestamp refreshes) and listeners fire, which is harmless.
- Line 64: `save(changed)` passes exactly the names whose status changed; the gate's `notifyWaiters(changed)` uses them to push the new status to the right waiting pages.
- `reset` deliberately takes no `by` argument.

### `remove(names)`

```js
// lines 78-82
  remove(names) {
    const gone = [].concat(names || []).filter((x) => this.items.delete(x));
    if (gone.length) this.save(gone);
    return gone.length;
  }
```

`Map.delete` returns `true` only when the key existed, so `filter` doubles as the "which were removed" computation. After a removal, `status(name)` is `null` again; a student with a still-valid cookie will be re-enqueued as `pending` on their next browser navigation. Listeners receive the removed names; `notifyWaiters` then computes `status || 'none'` and closes those streams, so the waiting page reloads and gets the waiting page again with a fresh `pending` record.

### `list()` and `counts()`

```js
// lines 84-91
  list() {
    return [...this.items.values()].sort((a, b) => (a.status === b.status ? a.firstSeen - b.firstSeen : STATUSES.indexOf(a.status) - STATUSES.indexOf(b.status)));
  }
  counts() {
    const c = { pending: 0, approved: 0, blocked: 0 };
    for (const it of this.items.values()) c[it.status] = (c[it.status] || 0) + 1;
    return c;
  }
```

- `list()` sorts pending first (so the organizer sees the work to do), then approved, then blocked; inside a group oldest first. It returns the live item objects, not copies; the dashboard serialises them immediately, so this is fine, but a caller must not mutate them.
- `counts()` always has the three keys, so the UI can render zeros. The `|| 0` guards an item with an unexpected status loaded from an older DB.

### Export

```js
// line 94
module.exports = { Approvals, STATUSES };
```

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `namegate.js` | `status(rawName)`, `enqueue(rawName, { profile, ip, ua })`, `onChange(names => notifyWaiters(names))` |
| in | `server.js` `queueDecide` | `approve / block / reset (names, by)` → returns changed raw names; `get(raw).ip` for the proxy-level block |
| in | `server.js` line 88 | `status(raw)` for `store.queueStatus` |
| in | `dashboard.js` | `counts()`, `list()`, `remove(names)`, `onChange(() => broadcast(...))` |
| out | `db.js` | `db.get('gate_queue', {})` at start, `db.set('gate_queue', obj)` on every change |
| out | `util.js` | `log` |

## Changing it safely

| Likely change | Where |
|---|---|
| Add a new status (e.g. `'later'`) | Add it to `STATUSES` (line 7), add a wrapper next to `approve/block/reset`, initialise it in `counts()` (line 88), and teach `namegate.js` `handle()` (lines 344-348) and `server.js` `queueDecide` what it means at the proxy. |
| Store more per-student info (e.g. the gate `next` URL) | Extend the item literal in `enqueue()` (line 32) and the refresh branch (lines 36-38). Old DB rows simply lack the field; read it with a default. |
| Auto-approve some students | Call `enqueue` then `approve` from the gate, or set `status: 'approved'` in the literal under a condition. Remember `queueDecide` is not involved then, so no alert and no IP block. |
| Per-row DB writes instead of one blob | Replace `save()`; keep the listener call and the `changedNames` contract. |

Tests: `proxy/test/queue.test.js` → `approvals: enqueue, decide, persist, counts` covers enqueue, `approve` with an unknown name, `by`, `block`, re-enqueue keeping the decision while merging the profile, reload from the same `Db`, and `reset`. The gate-side consumers are covered by `queue: after the form the student waits, approval lets them in, block shuts them out` and `waiting page event stream: open streams get the decision pushed instantly` in the same file.

## Exercises

1. **Sort order.** Add to `queue.test.js`: enqueue `A`, `B`, `C`; `block('A')`; `approve('B')`; assert `a.list().map(x => x.name)` equals `['C', 'B', 'A']`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node --test test/queue.test.js`
2. **Remove then re-enqueue.** In a `node -e` script using `new Db(':memory:')`, enqueue `X`, `approve('X')`, `remove('X')`, enqueue `X` again and print `status('X')`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy && node -e "const {Db}=require('./src/db');const {Approvals}=require('./src/approvals');const a=new Approvals({db:new Db(':memory:')});a.enqueue('X');a.approve('X');a.remove('X');a.enqueue('X');console.log(a.status('X'))"` prints `pending`.
3. **Listener payload.** Register `a.onChange(n => console.log('changed', n))` before calling `enqueue('Y')` and then `approve('Y')`.
   Verify: the same `node -e` pattern prints `changed []` for the enqueue and `changed [ 'Y' ]` for the approval.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Approvals` | `new Approvals({ db })` | Loads `gate_queue` from the DB. |
| `.onChange(fn)` | `(fn: (changedNames: string[]) => void) => void` | Subscribe to every save. |
| `.save(changedNames?)` | `(string[]?) => void` | Persist and notify. |
| `.enqueue(name, info?)` | `(rawName, { profile?, ip?, ua? }) => item` | Create as `pending` or refresh answers; never changes status. |
| `.status(name)` | `(rawName) => 'pending' \| 'approved' \| 'blocked' \| null` | `null` = never seen. |
| `.get(name)` | `(rawName) => item \| null` | Full record. |
| `.decide(names, status, by?)` | `(string \| string[], status, by?) => string[]` | Generic decision; throws on a bad status; returns names that existed. |
| `.approve(names, by?)` / `.block(names, by?)` / `.reset(names)` | same | Wrappers around `decide`. |
| `.remove(names)` | `(string \| string[]) => number` | Delete records; returns how many. |
| `.list()` | `() => item[]` | Pending, approved, blocked; oldest first within a group. |
| `.counts()` | `() => { pending, approved, blocked }` | Totals. |
| `STATUSES` | `string[]` | `['pending', 'approved', 'blocked']`. |

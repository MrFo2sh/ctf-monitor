# Detector — `proxy/src/detect.js`

## Purpose

`detect.js` is the IDOR detection engine. For every proxied request it decides whether the request hits one of the IDOR endpoints declared in `config/rules.json`, extracts the object ID, works out who owns that object (from `config/ownership.json`, from the student's own user ID, or from what it learned earlier), and raises the flags `idor-attempt`, `idor-success`, `enumeration` and `burst-errors`. It also keeps a short ID sequence per student per endpoint so the dashboard can show `1041 -> 1042 -> 1043`.

The web-attack classifier (SQLi, XSS, ...) is **not** here; that is `attacks.js` (chapter 10). The two verdicts are merged in `server.js`.

## Where it sits

| | |
|---|---|
| Required by | `proxy/src/server.js` (creates one `Detector`, calls `analyze()` on every event, `renameStudent()` when a lane is merged, and clears `students` / `learned` directly in `resetLive()`); `proxy/src/admin.js` (calls `renameStudent()` from `rename()` and `onGateRename()`) |
| Requires | `./util` for `log()` only |
| Input it reads | the compiled config returned by `getConfig()` (see `config.js` `compile()`): `compiledEndpoints`, `ownershipMap`, `enumeration`, `bruteForce`, `learnFromFirstSuccess` |

The detector never touches the store, the DB or the network. It is a pure in-memory state machine, which is why it is easy to unit test (`proxy/test/core.test.js`).

## Data it owns

### `Detector` instance fields

| Field | Type | Meaning |
|---|---|---|
| `getConfig` | `() => cfg` | Called on **every** `analyze()` / `matchEndpoint()` / `ownerOf()` so a hot-reloaded `rules.json` takes effect immediately. |
| `students` | `Map<name, state>` | Per-student sliding-window state, keyed by the display name (after aliasing). Cleared by `server.js resetLive()`. |
| `learned` | `Map<endpointName, Map<objectId, ownerName>>` | Ownership learned at runtime ("alice read order 1041 quietly, so 1041 is alice's"). Cleared by `resetLive()`. |

### Per-student `state` (created lazily by `state(name)`, line 19)

| Field | Type | Meaning |
|---|---|---|
| `byEndpoint` | `Map<endpointName, Array<{id, ts}>>` | The enumeration sliding window: every ID request on that endpoint within the last `enumeration.windowSeconds`. Older entries are shifted off on each request. |
| `errors` | `Array<ts>` | Timestamps of responses whose status is in `bruteForce.statuses`, within the last `bruteForce.windowSeconds`. |
| `seq` | `Map<endpointName, Array<objectId>>` | The last `SEQ_KEEP` (15) distinct-in-a-row IDs, for display and for the `sequential` heuristic. Never time-trimmed. |
| `idsSeen` | `Set<"endpoint:id">` | Every (endpoint, id) pair this student ever requested. Its size is reported as `idsSeenTotal` and becomes `distinctIds` on the student row / leaderboard. |

### Compiled endpoint rule (produced by `config.js`, consumed here)

| Field | Meaning |
|---|---|
| `name` | Rule name, e.g. `orders`. Becomes `ev.endpoint`. |
| `methods` | Upper-case list; empty means any method. |
| `re` | `RegExp` built from `pattern` with the `i` flag. Must contain `(?<id>...)` when `idFrom` is `path`. |
| `idFrom` | `'path'` (default), `'query:<param>'` or `'body:<field>'`. |
| `idParam` | The `<param>` / `<field>` part, or `null`. |
| `owner` | `'auto'` (default), `'same-as-user'`, `'map'`, `'learn'`, `'none'`. |

### Result of `analyze()`

| Field | Meaning |
|---|---|
| `endpoint`, `objectId` | Matched rule name and ID as a string, or `null`. |
| `owner` | Name of the owner if known, else `null`. |
| `ownerBasis` | `'map'`, `'self'`, `'learned'` or `null` — where the owner came from. |
| `mine` | `true` (student's own object), `false` (someone else's), `null` (unknown). Only `false` produces IDOR flags. |
| `seq` | Copy of the display sequence for this endpoint, or `null`. |
| `distinctIds` | Distinct IDs in the current enumeration window (windowed, not lifetime). |
| `sequential` | `true` when the last three IDs are consecutive integers. |
| `flags` | Subset of `['enumeration', 'idor-attempt', 'idor-success', 'burst-errors']`, in that insertion order. |
| `severity` | `'critical' > 'high' > 'warn' > 'notice' > 'ok'`. |
| `idsSeenTotal` | Lifetime distinct (endpoint, id) count for this student. |

## Walkthrough

### Header and constants

```js
// lines 1-7
'use strict';
// Detection engine: matches requests against the IDOR endpoints in rules.json,
// works out who owns the object, and flags attempts / successes / enumeration / error bursts.

const { log } = require('./util');

const SEQ_KEEP = 15; // IDs to remember per student per endpoint (for the "1041 -> 1042 -> 1043" display)
```

`SEQ_KEEP` bounds only the *display* sequence. The enumeration window is bounded by time, not count, so a student hammering one endpoint can grow the `byEndpoint` entries to as many requests as fit in `windowSeconds` (default 30 s; at 1000 rps that is 30 000 small objects, which is fine).

### Constructor and lazy state

```js
// lines 9-23
class Detector {
  constructor(getConfig) {
    this.getConfig = getConfig;
    this.students = new Map(); // name -> state
    this.learned = new Map(); // endpoint name -> Map(objectId -> owner name)
  }

  state(name) {
    let st = this.students.get(name);
    if (!st) {
      st = { byEndpoint: new Map(), errors: [], seq: new Map(), idsSeen: new Set() };
      this.students.set(name, st);
    }
    return st;
  }
```

- `getConfig` is a function, not a config object, on purpose: `Config` in `config.js` watches the config directory and swaps `current`; reading it through a function means the detector always sees the latest compiled rules without a restart.
- `state()` creates the record on first sight. There is no eviction: anonymous `ip:*` lanes and `sess-*` lanes accumulate until `resetLive()` (New CTF / Stop CTF) clears the map.

### `renameStudent` — moving state when a lane is merged

```js
// lines 25-32
  renameStudent(oldName, newName) {
    const st = this.students.get(oldName);
    if (st) {
      this.students.delete(oldName);
      if (!this.students.has(newName)) this.students.set(newName, st);
    }
    for (const m of this.learned.values()) for (const [id, owner] of m) if (owner === oldName) m.set(id, newName);
  }
```

Called when an anonymous lane (`ip:1.2.3.4`, `sess-abcd`) gets a real name (gate form, login) or when the organizer renames someone. Two things happen:

1. The sliding-window state moves under the new name. **Gotcha:** if the new name already has state, the old state is simply dropped, not merged. The windows restart from whatever the target already had. `store.js` by contrast merges counters on rename; the detector does not because merging two time windows is not meaningful.
2. Every learned ownership that pointed at the old name is re-attributed, so "ip:1.1.1.1 owns order 5" becomes "Gohary owns order 5". The test `detector: renaming a student carries state and learned ownership` checks exactly this.

### `matchEndpoint` — which rule, which ID

```js
// lines 34-53
  matchEndpoint(method, pathOnly, url, reqBody) {
    const cfg = this.getConfig();
    for (const ep of cfg.compiledEndpoints) {
      if (ep.methods.length && !ep.methods.includes(method)) continue;
      const m = ep.re.exec(pathOnly);
      if (!m) continue;
      let id = null;
      if (ep.idFrom === 'path') id = m.groups && m.groups.id;
      else if (ep.idFrom.startsWith('query:')) {
        try {
          id = new URL(url, 'http://x').searchParams.get(ep.idParam);
        } catch {
          id = null;
        }
      } else if (ep.idFrom.startsWith('body:')) id = reqBody && reqBody[ep.idParam];
      if (id === null || id === undefined || id === '') continue;
      return { endpoint: ep, objectId: String(id) };
    }
    return null;
  }
```

- Rules are tried **top to bottom, first match wins** — the order in `rules.json` matters. The shipped file puts the specific rules first and the catch-all `generic numeric id` last.
- `methods` is already upper-cased by `config.js`; `method` comes from `req.method` which Node upper-cases, so no normalisation is needed here.
- The regex runs against `pathOnly` (the URL with the query string removed by `server.js`), so a pattern like `^/api/orders/(?<id>[^/?]+)` cannot accidentally capture `?page=2`.
- `query:` extraction parses the full `url` with a dummy base `http://x` because `req.url` is path-only (`/api/invoice?id=7`) and the WHATWG `URL` constructor needs an absolute URL. `searchParams.get` already percent-decodes. The `try/catch` covers malformed URLs — `id` stays `null`.
- `body:` reads a top-level field of the parsed body (`util.parseBody` returns an object for JSON, form-urlencoded and simple multipart). Nested paths are not supported.
- **Gotcha:** a rule whose regex matches but yields no ID does `continue`, not `return null`. A later, broader rule can therefore still match the same path. Example: `invoice` matches `/api/invoice` but with no `?id=`, the loop moves on to `generic numeric id`.
- `String(id)` makes `1041` and `"1041"` the same key everywhere (ownership map keys are strings too, see `config.loadOwnership`).

### `ownerOf` — the three ownership outcomes

```js
// lines 55-81
  ownerOf(ep, objectId, student) {
    const cfg = this.getConfig();
    const unknown = { owner: null, mine: null, basis: null };
    const rule = ep.owner;
    if (rule === 'none') return unknown;

    const map = cfg.ownershipMap || {};
    const mapped = (map[ep.name] && map[ep.name][objectId]) || (map['*'] && map['*'][objectId]) || null;
    if (mapped && rule !== 'learn' && rule !== 'same-as-user') {
      return { owner: mapped, mine: mapped === student.name, basis: 'map' };
    }
    if (rule === 'map') return unknown;

    if (rule === 'same-as-user') {
      if (student.id == null) return unknown;
      const mine = String(student.id) === objectId;
      return { owner: mine ? student.name : null, mine, basis: 'self' };
    }

    // auto / learn: positive self-evidence first, then what we learned
    if (rule === 'auto' && student.id != null && String(student.id) === objectId) {
      return { owner: student.name, mine: true, basis: 'self' };
    }
    const learnedOwner = this.learned.get(ep.name) && this.learned.get(ep.name).get(objectId);
    if (learnedOwner) return { owner: learnedOwner, mine: learnedOwner === student.name, basis: 'learned' };
    return unknown;
  }
```

The return value is always a triple `{owner, mine, basis}`. What each `owner` rule consults, in order:

| rule | ownership.json | student's own user id | learned map |
|---|---|---|---|
| `none` | – | – | – (IDs are still tracked for enumeration) |
| `map` | yes | – | – |
| `same-as-user` | **ignored** | yes | – |
| `auto` (default) | yes | yes | yes |
| `learn` | **ignored** | – | yes |

Details worth knowing:

- `ownershipMap` has an endpoint-specific section and a `'*'` wildcard section (`config/ownership.json` → `loadOwnership`). The endpoint section wins.
- `mapped === student.name` compares against the **display** name (after `admin.alias`), so the names in `ownership.json` must be the names you see on the dashboard, not the raw gate names.
- `same-as-user` can only say "mine" or "not mine". When it is not mine, `owner` is `null` — the detector does not know whose profile it is, only that it is not this student's. The alert text will therefore lack the "(belongs to X)" part.
- `student.id` comes from the identity resolver (JWT `sub`/`id` claim, login response, whoami) and may be a number or a string; `String()` normalises it. With no known ID, `same-as-user` returns `unknown` and never flags anything, which is the safe default.
- `basis: 'self'` with `mine: true` under `auto` is later used by `analyze()` to seed the learned map (lines 168-170).

### `learnOwner` and `unlearnBurst`

```js
// lines 83-100
  learnOwner(epName, objectId, owner) {
    let m = this.learned.get(epName);
    if (!m) {
      m = new Map();
      this.learned.set(epName, m);
    }
    if (!m.has(objectId)) {
      m.set(objectId, owner);
      log('debug', `ownership learned: ${epName} #${objectId} -> ${owner}`);
    }
  }

  // A student that turned out to be enumerating should not keep ownership it "learned" during that burst.
  unlearnBurst(epName, student, entries) {
    const m = this.learned.get(epName);
    if (!m) return;
    for (const e of entries) if (m.get(e.id) === student) m.delete(e.id);
  }
```

- **First writer wins.** Once an ID has an owner it is never overwritten by `learnOwner`. If the first reader was wrong (e.g. the attacker got there before the real owner), the only fixes are `unlearnBurst`, a rename, or `resetLive()`.
- `unlearnBurst` is the safety valve: when a student crosses the enumeration threshold, every ID *in the current window* that was learned as theirs is forgotten. IDs they read before the window started stay learned. The loop deletes only entries where the owner is this student, so it never damages ownership learned from other students.
- The `debug` log line is only printed with `LOG_LEVEL=debug` (see `util.log`).

### `analyze` — part 1: endpoint match, enumeration window, sequence

```js
// lines 106-135
  analyze(ev) {
    const cfg = this.getConfig();
    const st = this.state(ev.student.name);
    const now = ev.ts || Date.now();
    const flags = [];
    const out = { endpoint: null, objectId: null, owner: null, ownerBasis: null, mine: null, seq: null, distinctIds: 0, sequential: false };

    const match = this.matchEndpoint(ev.method, ev.pathOnly, ev.url, ev.reqBody);
    if (match) {
      const { endpoint: ep, objectId } = match;
      out.endpoint = ep.name;
      out.objectId = objectId;
      st.idsSeen.add(`${ep.name}:${objectId}`);

      // sliding window of IDs on this endpoint
      let entries = st.byEndpoint.get(ep.name);
      if (!entries) {
        entries = [];
        st.byEndpoint.set(ep.name, entries);
      }
      entries.push({ id: objectId, ts: now });
      const cutoff = now - cfg.enumeration.windowSeconds * 1000;
      while (entries.length && entries[0].ts < cutoff) entries.shift();
      const distinct = new Set(entries.map((e) => e.id)).size;
      out.distinctIds = distinct;
      const enumerating = distinct >= cfg.enumeration.distinctIds;
      if (enumerating) {
        flags.push('enumeration');
        this.unlearnBurst(ep.name, ev.student.name, entries);
      }
```

- `ev.ts` is the proxy's timestamp of the request; tests pass synthetic values. Falling back to `Date.now()` keeps the method usable without one.
- `idsSeen` is updated before anything else, so even a request that is later ignored for ownership still counts toward the student's lifetime "distinct IDs" figure.
- The window is an array in arrival order. The new entry is pushed first, then expired entries are shifted from the front while the oldest is older than `cutoff`. The loop stops at the first entry that is still inside the window — this is correct only if timestamps are non-decreasing, which holds for live traffic. **Gotcha:** feeding an out-of-order *older* timestamp (possible in tests) appends an entry that will not be expired until everything before it has gone.
- `distinct` counts **different IDs**, not requests: refreshing `/api/orders/1041` 500 times never triggers enumeration.
- The threshold is `>=`, i.e. with `distinctIds: 5` the fifth different ID within the window flags. Every subsequent request in the same window is also flagged `enumeration` (the store rate-limits the resulting *alerts*; see chapter 11, `alertFor`).

```js
// lines 137-149
      // sequence display (skip immediate repeats)
      let seq = st.seq.get(ep.name);
      if (!seq) {
        seq = [];
        st.seq.set(ep.name, seq);
      }
      if (seq[seq.length - 1] !== objectId) seq.push(objectId);
      while (seq.length > SEQ_KEEP) seq.shift();
      out.seq = seq.slice();
      if (seq.length >= 3) {
        const a = seq.slice(-3).map(Number);
        if (a.every((n) => Number.isFinite(n)) && Math.abs(a[2] - a[1]) === 1 && Math.abs(a[1] - a[0]) === 1) out.sequential = true;
      }
```

- The sequence drops only *immediate* repeats (`1041, 1041, 1042` → `1041, 1042`), so `1041, 1042, 1041` keeps all three.
- `out.seq` is a **copy** (`slice()`), because the same array keeps mutating and the event object is stored in ring buffers and serialised to JSON later.
- `sequential` means the last three IDs are integers and each step is ±1. `Math.abs` makes both `5,6,7` and `7,6,5` sequential, and also `5,6,5`. Non-numeric IDs (UUIDs) make `Number()` return `NaN`, and `Number.isFinite(NaN)` is `false`, so UUID endpoints never report `sequential`.

### `analyze` — part 2: ownership, IDOR flags, learning

```js
// lines 151-171
      // ownership
      const own = this.ownerOf(ep, objectId, ev.student);
      out.owner = own.owner;
      out.ownerBasis = own.basis;
      out.mine = own.mine;
      const success = ev.status >= 200 && ev.status < 300 && ev.hasData;
      if (own.mine === false) {
        flags.push('idor-attempt');
        if (success) flags.push('idor-success');
      }

      // learn ownership from a quiet, successful read (or from "this is my own user id")
      if (success && own.mine === null && !enumerating && cfg.learnFromFirstSuccess && (ep.owner === 'auto' || ep.owner === 'learn')) {
        this.learnOwner(ep.name, objectId, ev.student.name);
        out.owner = ev.student.name;
        out.ownerBasis = 'learned';
        out.mine = true;
      } else if (own.mine === true && own.basis === 'self') {
        this.learnOwner(ep.name, objectId, ev.student.name);
      }
    }
```

- `success` requires a 2xx **and** `hasData`. `hasData` is computed in `server.js` (lines 200-204): at least `successMinBytes` of body, and not a body consisting only of keys like `error`/`message`/`status`. This stops `{"error":"forbidden"}` with HTTP 200 from counting as a successful read.
- `idor-attempt` is raised the moment `mine === false`, whatever the status. A 403 on someone else's order is still an attempt (test: "bob gets a 403 on carol's mapped order: attempt only"). `idor-success` is always accompanied by `idor-attempt`.
- Learning conditions, all required: successful read; owner currently unknown (`mine === null`, so mapped/self/learned objects are never re-learned); the student is **not** enumerating right now (a scanner that reads 50 orders must not be recorded as their owner); `learnFromFirstSuccess` is not switched off in `rules.json`; the rule is `auto` or `learn`. When learning happens the *current* event is reported as `mine: true, basis: 'learned'`, so the first quiet read is never flagged.
- The `else if` branch records positive self-evidence (`same-as-user` or `auto` matching the student's own user ID) into `learned`. For `auto` endpoints that lets *other* students be flagged later when they read that ID. For `same-as-user` endpoints `ownerOf` never consults `learned`, so there the entry only matters for `renameStudent` and debugging.

### `analyze` — part 3: error bursts and severity

```js
// lines 173-188
    // error bursts (brute force / noisy scanning)
    if (cfg.bruteForce.statuses.has(ev.status)) {
      st.errors.push(now);
      const cutoff = now - cfg.bruteForce.windowSeconds * 1000;
      while (st.errors.length && st.errors[0] < cutoff) st.errors.shift();
      if (st.errors.length >= cfg.bruteForce.errors) flags.push('burst-errors');
    }

    let severity = 'ok';
    if (flags.includes('idor-success')) severity = 'critical';
    else if (flags.includes('idor-attempt')) severity = 'high';
    else if (flags.includes('enumeration') || flags.includes('burst-errors')) severity = 'warn';
    else if (ev.status >= 400) severity = 'notice';

    return { ...out, flags, severity, idsSeenTotal: st.idsSeen.size };
  }
}
```

- The burst window runs **outside** the `if (match)` block: any URL counts, not only IDOR endpoints. `statuses` is a `Set` built by `config.js` (default `401, 403, 404`; the shipped `rules.json` adds `429`).
- The `errors` array is only trimmed when another error arrives. It is not a memory concern (it holds numbers), but it means `st.errors.length` is stale between errors; nothing reads it except this block.
- Severity is a strict ladder; `notice` is for plain 4xx/5xx with no detection flag. `server.js` may later bump severity because of web-attack hits (chapter 10).
- `idsSeenTotal` is appended last; the store copies it into `student.distinctIds`.

### Export

```js
// line 191
module.exports = { Detector };
```

## Worked example

Config as in `core.test.js` (`enumeration: {distinctIds: 3, windowSeconds: 30}`, `bruteForce: {errors: 3, windowSeconds: 20}`, `orders` rule `owner: auto`, `profile` rule `owner: same-as-user`, `ownershipMap: {orders: {9: 'carol'}}`). alice has user id `1001`, bob has `1002`. `t0` is any epoch in ms. The table values were produced by running the real code.

### The three ownership outcomes

| # | request | status | `owner` | `basis` | `mine` | flags | why |
|---|---|---|---|---|---|---|---|
| 1 | alice `GET /api/orders/1041` | 200 | `alice` | `learned` | `true` | `[]` | `auto`: no map entry, 1041 ≠ her id, nothing learned → `mine === null`; the read is successful and quiet, so it is **learned** and reported as hers. |
| 2 | bob `GET /api/orders/1041` | 200 | `alice` | `learned` | `false` | `idor-attempt, idor-success` | learned map says alice → `mine === false`; 200 with data → success. Severity `critical`. |
| 3 | bob `GET /api/orders/9` | 403 | `carol` | `map` | `false` | `idor-attempt` | `ownership.json` wins under `auto`; 403 → attempt only. Severity `high`. |
| 4 | bob `GET /api/users/1002` | 200 | `bob` | `self` | `true` | `[]` | `same-as-user`: 1002 equals bob's id. Also recorded into `learned.profile`. |
| 5 | bob `GET /api/users/1001` | 200 | `null` | `self` | `false` | `idor-attempt, idor-success` | `same-as-user` only knows it is **not** his; owner stays unknown. |

### The enumeration window (endpoint `orders`, bob, threshold 3 distinct in 30 s)

| time | request | window entries (ids) | distinct | flags |
|---|---|---|---|---|
| t0+1.0 s | `/orders/1041` | `1041` | 1 | (idor flags as above) |
| t0+2.0 s | `/orders/9` | `1041, 9` | 2 | idor-attempt |
| t0+4.0 s | `/orders/1043` 404 | `1041, 9, 1043` | 3 | **enumeration** (3 ≥ 3). `unlearnBurst` runs but bob learned nothing, so nothing is removed. `seq` = `1041 -> 9 -> 1043`. |
| t0+4.5 s | `/orders/1044` 404 | `1041, 9, 1043, 1044` | 4 | enumeration, and `burst-errors` because that is bob's 3rd 403/404 inside 20 s (the 403 on #9 at t0+2 s, then the two 404s). |
| t0+45 s | `/orders/1045` 404 | `1045` (everything older than t0+15 s expired) | 1 | `[]`, severity `notice`. `seq` is still `1041 -> 9 -> 1043 -> 1044 -> 1045` and `sequential` is now `true` (1043, 1044, 1045). The error window also expired, so no burst. |

Observe that `distinctIds` in the result (windowed) dropped back to 1 while `idsSeenTotal` stayed 5: the leaderboard uses the lifetime figure, the enumeration flag uses the window.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` `onEvent()` (line 208) | `analyze({student: who, method, pathOnly, url, status, size, hasData, reqBody, ts})`; the returned verdict is copied field by field into the event sent to `store.add()`. |
| in | `server.js` `mergeLane()` (line 134), `admin.js` `rename()` / `onGateRename()` | `renameStudent(oldName, newName)` |
| in | `server.js` `resetLive()` (lines 303-304) | Direct `detector.students.clear()` and `detector.learned.clear()` — there is no `reset()` method. |
| in | `config.js` via `getConfig()` | `compiledEndpoints`, `ownershipMap`, `enumeration`, `bruteForce`, `learnFromFirstSuccess`. |
| out | `util.js` | `log('debug', ...)` when ownership is learned. |
| out (indirect) | `store.js` | The flags and `owner` drive `alertFor()` messages and student counters; `idsSeenTotal` → `student.distinctIds`; `seq` → `student.seq[endpoint]`. |

## Changing it safely

| Likely change | Where | Notes |
|---|---|---|
| New way to extract the ID (e.g. header, nested body path) | `matchEndpoint` lines 40-48, and `config.js compile()` which sets `idFrom`/`idParam` | Keep the `continue` on empty ID so later rules still get a chance. |
| New ownership rule (e.g. `'group'`) | `ownerOf` lines 55-81 and the `else if` learning branch at 163-170 | Decide explicitly which of map / self / learned it consults; update the `_help` block in `config/rules.json`. |
| Different enumeration semantics (per-request count, per-path instead of per-rule) | lines 120-135 | `distinct` is a `Set` over the window; `unlearnBurst` relies on the same `entries` array. |
| Severity ladder / new flag | lines 181-185, and `store.js` `ALERT_LEVEL` + `alertFor()` so the new flag produces an alert; `query.js` `FIELDS.flag.help` for the editor hint | Flags are stored as a JSON array in `requests.flags`, so old recordings keep working. |

Tests (`proxy/test/core.test.js`):

- `detector: ownership map, learning, idor attempt vs success, enumeration and bursts` — covers map/self/learned, attempt vs success, the window threshold, `seq`, and bursts.
- `detector: renaming a student carries state and learned ownership` — covers `renameStudent`.

Run them from `D:\SIEMs\ctf-watch\proxy` with `node --test test/core.test.js` (or `npm test` for everything).

## Exercises

1. **Watch the window expire.** Write a 10-line script that creates a `Detector` with `enumeration: {distinctIds: 3, windowSeconds: 5}` (copy `cfg` from `core.test.js`), sends four different IDs at `ts = 0, 1000, 2000, 7000` and prints `flags` and `distinctIds` for each. Expect `enumeration` on the third call and `distinctIds: 2` on the fourth (only `2000` and `7000` survive).
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node your-script.js`
2. **Make `same-as-user` honour `ownership.json`.** Change `ownerOf` so that a mapped owner wins for `same-as-user` too (remove `&& rule !== 'same-as-user'` on line 63), then add a map entry `profile: {1001: 'alice'}` to the test config and assert that bob reading `/api/users/1001` now reports `owner: 'alice'`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node --test test/core.test.js` (the existing assertions must still pass).
3. **Prove the first-writer rule.** Call `learnOwner('orders', '1', 'alice')` then `learnOwner('orders', '1', 'bob')` and print `d.learned.get('orders').get('1')`. Expect `alice`. Then call `unlearnBurst('orders', 'alice', [{id: '1'}])` and print again — expect `undefined`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node -e "const {Detector}=require('./src/detect');const d=new Detector(()=>({}));d.learnOwner('orders','1','alice');d.learnOwner('orders','1','bob');console.log(d.learned.get('orders').get('1'));d.unlearnBurst('orders','alice',[{id:'1'}]);console.log(d.learned.get('orders').get('1'))"`

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Detector` | `new Detector(getConfig: () => cfg)` | Stateful IDOR / enumeration / burst detector. |
| `Detector#analyze` | `(ev: {student:{name,id,source}, method, pathOnly, url, status, size, hasData, reqBody, ts}) => {endpoint, objectId, owner, ownerBasis, mine, seq, distinctIds, sequential, flags, severity, idsSeenTotal}` | Main entry point, one call per proxied request. |
| `Detector#matchEndpoint` | `(method, pathOnly, url, reqBody) => {endpoint, objectId} \| null` | First matching rule in config order with a non-empty ID. |
| `Detector#ownerOf` | `(ep, objectId, student) => {owner, mine, basis}` | Applies the rule's `owner` policy. |
| `Detector#learnOwner` | `(epName, objectId, owner) => void` | Records ownership if not already known. |
| `Detector#unlearnBurst` | `(epName, student, entries) => void` | Forgets ownership learned by `student` for the IDs in `entries`. |
| `Detector#renameStudent` | `(oldName, newName) => void` | Moves state and re-attributes learned ownership. |
| `Detector#state` | `(name) => state` | Lazily creates the per-student record. |
| `Detector#students`, `#learned` | `Map` | Cleared directly by `server.js resetLive()`. |

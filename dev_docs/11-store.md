# Store — `proxy/src/store.js`

## Purpose

`store.js` holds the live state that the dashboard shows: the last 1500 events, the last 400 alerts, one row per student with counters, per-endpoint and per-status totals, a 120-second requests-per-second ring, and the leaderboard. It is the single point where a finished event enters the system: `add()` updates every counter, decides whether the event deserves an alert, appends the event to the daily JSONL log, hands it to the database, and notifies the WebSocket broadcaster. Everything here is in memory and lost on restart; durability is `db.js` (chapter 12).

## Where it sits

| | |
|---|---|
| Required by | `server.js` (creates it, calls `add()` from `onEvent()`, `emitAlert()` for login conflicts / queue / decoy / target changes, `renameStudent()` from `mergeLane()`, `reset()` from `resetLive()`, `studentsByIp()`, reads `store.students` directly; sets the four hooks `isBlocked`, `renamePending`, `queueStatus`, `isDecoy`); `dashboard.js` (`snapshot()`, `stats()`, `onEvent()`, `onReset()`, reads `store.alerts` / `store.students` / `store.replayCtfId`); `admin.js` (`renameStudent()`, reads `store.students`); `replay.js` (`reset()`, `add()`, sets `replayCtfId`) |
| Requires | `fs`, `path` (JSONL log), `./util` (`log`), and a `Db` instance passed in (`addRequest`, `addAlert`, raw `db.db.prepare` for rename) |

## Data it owns

### Module constants

| Name | Value | Meaning |
|---|---|---|
| `MAX_EVENTS` | 1500 | Ring size of `events`. |
| `MAX_ALERTS` | 400 | Ring size of `alerts`. |
| `RPS_WINDOW` | 120 | Seconds of per-second request counts kept. |
| `LEVELS` | `['info','low','medium','high','critical']` | Alert level order (index = rank). Exported. |
| `ALERT_LEVEL` | map type → level | Default level per alert type (lines 14-27). `web-attack` is overridden by the worst attack class. Exported. |

### `Store` instance fields

| Field | Type | Meaning |
|---|---|---|
| `logDir` | string \| null | Folder for `events-YYYY-MM-DD.jsonl`; `null` disables the log. |
| `db` | `Db` \| null | Write-through target. `null` in tests. |
| `listeners` | `Set<fn(ev, alert)>` | Called after every `add()` (with the event and the alert or `null`) and every `emitAlert()` (with `null` and the alert). |
| `resetListeners` | `Set<fn()>` | Called by `reset()` and at the end of `renameStudent()`; the dashboard answers with a full snapshot. |
| `isBlocked`, `renamePending`, `queueStatus`, `isDecoy` | `(name) => ...` | Hooks injected by `server.js`; defaults return `false` / `null`. Only read in `stats()` to decorate student rows. |
| `stream`, `streamDate` | WriteStream, `'YYYY-MM-DD'` | The open JSONL file and its day. |
| `replayCtfId` | number \| null | Set by `Replay.start()`; read by the dashboard's `scopeCtf()`. Cleared by `reset()`. |
| `startedAt` | ms | When the live view was last reset (uptime on the dashboard). |
| `events` | `Array<ev>` | Ring of the last `MAX_EVENTS` events, oldest first. |
| `alerts` | `Array<alert>` | Ring of the last `MAX_ALERTS` alerts. |
| `students` | `Map<name, studentRow>` | One row per display name. |
| `total` | number | Events since reset. |
| `byStatus` | `{[status]: count}` | |
| `byEndpoint` | `Map<key, count>` | Key is the IDOR rule name when matched, else the templated path (`/api/orders/:id`). |
| `attackTotals` | `{[cls]: count}` | |
| `rps` | `number[120]` | Per-second counts, index 119 is the second `rpsHead`. |
| `rpsHead` | epoch seconds | The second that the last slot represents. |
| `seq` | number | Monotonic event counter; `ev.n`. |
| `firstIdorSuccess` | `{student, ts, endpoint, objectId}` \| null | Leaderboard "first blood". |

### Student row (created in `student()`, lines 77-81)

| Field | Meaning |
|---|---|
| `name` | Display name (map key). |
| `rawName` | Name before organizer aliasing; updated on each event. |
| `id` | App user ID once known (first non-empty `ev.studentId`). |
| `source` | How the student was identified (`name`, `ip-match`, `session`, `jwt`, `login`, `ip`, `replay`). Overwritten by any non-`ip` source. |
| `ip` | IP at first sight (used by `admin.block`). |
| `playerId` | Cross-CTF player number from `db.playerFor`. |
| `firstSeen`, `lastSeen` | Timestamps. |
| `requests`, `failed`, `flagged`, `idorAttempts`, `idorSuccess`, `enumeration`, `bursts` | Counters. `failed` = status ≥ 400; `flagged` = any flag. |
| `distinctIds` | Lifetime distinct (endpoint, id) pairs — copied from `ev.idsSeenTotal`. |
| `firstIdorSuccessTs` | First successful IDOR by this student. |
| `seq` | `{[endpoint]: [ids]}` — latest ID sequence per endpoint for the "1041 -> 1042" display. |
| `ips` | `{[ip]: {n, first, last}}`, at most 25 IPs. |
| `appNames` | Up to 10 app usernames seen under this display name; `appName` is the latest. |
| `attacks` | `{[cls]: count}`. |
| `uas` | `{[ua]: count}`, at most 30 distinct UAs. |
| `profile` | Extra gate-form answers (set from `ev.profile` or directly by `server.js`). |

### Alert shape

| Field | Meaning |
|---|---|
| `n` | `ev.n` of the triggering event; `0` for `emitAlert()` alerts. |
| `ts`, `level`, `type`, `student`, `ip`, `msg` | Core fields; `level` is one of `LEVELS`. |
| `endpoint`, `objectId`, `owner`, `status` | Only on event-derived alerts. |
| `data` | Free-form object, only from `emitAlert()` (e.g. login-conflict details). |
| `ack` | `0`/`1`. Note: in-memory alerts have no DB `id`; the dashboard's ack-by-id only updates the DB, and `all: true` updates both. |
| `replay` | `true` when produced during a replay (not persisted). |

## Walkthrough

### Constants and `pathTemplate`

```js
// lines 8-31
const MAX_EVENTS = 1500;
const MAX_ALERTS = 400;
const RPS_WINDOW = 120;
const LEVELS = ['info', 'low', 'medium', 'high', 'critical'];

// alert type -> criticality
const ALERT_LEVEL = {
  'idor-success': 'critical',
  'admin-login-conflict': 'critical',
  'idor-attempt': 'high',
  enumeration: 'medium',
  'burst-errors': 'low',
  blocked: 'low',
  'web-attack': 'high', // overridden by the worst attack class level
  'new-student': 'info',
  queue: 'info',
  decoy: 'info',
  renamed: 'info',
  info: 'info',
};

function pathTemplate(p) {
  return p.replace(/\/\d+(?=\/|$)/g, '/:id').replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, '/:uuid');
}
```

- `ALERT_LEVEL` is the default; `emitAlert()` accepts an explicit `level`, and `alertFor()` computes one for `web-attack`. The alert levels (`info..critical`) are a different scale from event `severity` (`ok..critical`).
- `pathTemplate` collapses numeric and UUID path segments so `topEndpoints` groups `/api/users/17/orders/9` and `/api/users/18/orders/3` as `/api/users/:id/orders/:id`. A segment must be *all* digits (`/v2` stays), and the UUID form is `8 hex, dash, ≥27 more hex/dashes`. Query strings are stripped by the caller.

### Constructor and `reset()`

```js
// lines 34-64
  constructor({ logDir, db }) {
    this.logDir = logDir;
    this.db = db || null;
    this.listeners = new Set();
    this.resetListeners = new Set();
    this.isBlocked = () => false;
    this.renamePending = () => false;
    this.queueStatus = () => null; // set by server.js: pending | approved | blocked | null
    this.isDecoy = () => false; // set by server.js: routed to the decoy app?
    this.stream = null;
    this.streamDate = null;
    if (logDir) fs.mkdirSync(logDir, { recursive: true });
    this.reset();
  }

  reset() {
    this.replayCtfId = null; // set by Replay.start(): the live view shows that CTF, history views follow it
    this.startedAt = Date.now();
    this.events = [];
    this.alerts = [];
    this.students = new Map();
    this.total = 0;
    this.byStatus = {};
    this.byEndpoint = new Map();
    this.attackTotals = {};
    this.rps = new Array(RPS_WINDOW).fill(0);
    this.rpsHead = Math.floor(Date.now() / 1000);
    this.seq = 0;
    this.firstIdorSuccess = null;
    for (const l of this.resetListeners) l();
  }
```

- The four hooks are plain properties so `server.js` can assign closures over objects that are created *after* the store (`admin`, `approvals`, `decoy`). The store never knows about those modules.
- `reset()` is what "New CTF", "Stop CTF" and `Replay.start()` call. It does not touch the JSONL stream, the DB, or the listeners. `seq` restarts at 0, so `ev.n` is unique only within one live session; the dashboard uses it to order/dedupe events within a snapshot.
- `rpsHead` is initialised to the current second so `tick()` has a frame of reference.

### Listener registration

```js
// lines 66-72
  onEvent(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  onReset(fn) {
    this.resetListeners.add(fn);
  }
```

`onEvent` returns an unsubscribe function; `onReset` does not (nothing unsubscribes today).

### `student()` and `noteIp()`

```js
// lines 74-95
  student(ev) {
    let s = this.students.get(ev.student);
    if (!s) {
      s = {
        name: ev.student, rawName: ev.rawName || ev.student, id: ev.studentId || null, source: ev.source, ip: ev.ip, playerId: ev.playerId || null,
        firstSeen: ev.ts, lastSeen: ev.ts, requests: 0, failed: 0, flagged: 0, idorAttempts: 0, idorSuccess: 0, enumeration: 0, bursts: 0,
        distinctIds: 0, firstIdorSuccessTs: null, seq: {}, ips: {}, appNames: [], attacks: {}, uas: {},
      };
      this.students.set(ev.student, s);
      this.emitAlert({ ts: ev.ts, type: 'new-student', student: ev.student, ip: ev.ip, replay: !!ev.replay, msg: `${ev.student} appeared (${ev.source}${ev.ip ? `, ip ${ev.ip}` : ''})` });
    }
    return s;
  }

  static noteIp(s, ip, ts) {
    if (!ip) return;
    const e = s.ips[ip];
    if (e) {
      e.n++;
      e.last = ts;
    } else if (Object.keys(s.ips).length < 25) s.ips[ip] = { n: 1, last: ts, first: ts };
  }
```

- First sight of a name emits a `new-student` info alert through `emitAlert()`, which means the listeners are called (and the DB written) **before** the event itself is processed. The `replay` flag is propagated so replayed "appearances" are not persisted.
- `noteIp` caps the per-student IP table at 25 entries; later new IPs are counted nowhere (the student detail view uses the DB for the full list).

### `add()` — counters and student updates

```js
// lines 97-118
  add(ev) {
    ev.n = ++this.seq;
    ev.attacks = ev.attacks || [];
    this.total++;
    this.byStatus[ev.status] = (this.byStatus[ev.status] || 0) + 1;
    const key = ev.endpoint ? `${ev.endpoint}` : pathTemplate(String(ev.path).split('?')[0]);
    this.byEndpoint.set(key, (this.byEndpoint.get(key) || 0) + 1);
    this.tick(ev.ts, 1);

    const s = this.student(ev);
    s.lastSeen = ev.ts;
    s.requests++;
    if (ev.studentId && !s.id) s.id = ev.studentId;
    if (ev.rawName) s.rawName = ev.rawName;
    if (ev.playerId) s.playerId = ev.playerId;
    if (ev.source !== 'ip') s.source = ev.source;
    if (ev.appName) {
      s.appName = ev.appName;
      if (!s.appNames.includes(ev.appName) && s.appNames.length < 10) s.appNames.push(ev.appName);
    }
    if (ev.profile) s.profile = ev.profile;
    Store.noteIp(s, ev.ip, ev.ts);
```

- `add()` **mutates** the event (`n`, `attacks` default). The same object is later pushed to `events`, to `db.pending`, and serialised — they all share it.
- `ev.flags` must be an array; `server.js` and `replay.js` guarantee that. `ev.attacks` is defaulted here because older callers may omit it.
- `byEndpoint` groups by rule name when the detector matched, else by templated path. Both kinds share one map, so `orders` (rule) and `/api/orders/:id` (unmatched because e.g. the method filter excluded it) can both appear in Top endpoints.
- `s.id` is set once and never overwritten; `s.source` is upgraded by anything stronger than `ip`; `rawName`, `playerId`, `appName`, `profile` follow the latest event.

```js
// lines 119-141
    if (ev.ua) {
      if (s.uas[ev.ua] !== undefined) s.uas[ev.ua]++;
      else if (Object.keys(s.uas).length < 30) s.uas[ev.ua] = 1;
    }
    if (ev.status >= 400) s.failed++;
    if (ev.flags.length) s.flagged++;
    if (ev.flags.includes('idor-attempt')) s.idorAttempts++;
    if (ev.flags.includes('idor-success')) {
      s.idorSuccess++;
      if (!s.firstIdorSuccessTs) s.firstIdorSuccessTs = ev.ts;
      if (!this.firstIdorSuccess) this.firstIdorSuccess = { student: s.name, ts: ev.ts, endpoint: ev.endpoint, objectId: ev.objectId };
    }
    if (ev.flags.includes('enumeration')) s.enumeration++;
    if (ev.flags.includes('burst-errors')) s.bursts++;
    if (ev.idsSeenTotal) s.distinctIds = ev.idsSeenTotal;
    if (ev.seq) s.seq[ev.endpoint] = ev.seq;
    for (const a of ev.attacks) {
      s.attacks[a.cls] = (s.attacks[a.cls] || 0) + 1;
      this.attackTotals[a.cls] = (this.attackTotals[a.cls] || 0) + 1;
    }

    this.events.push(ev);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);
```

- `flagged` counts events with any flag, including `attack:*`, `decoy` and `blocked` (those are added by `server.js`).
- `distinctIds` is *replaced* by the detector's lifetime count, not incremented — the detector is the source of truth. During replay it is never set (stays 0).
- The counters updated here (`s.attacks[cls]`, `s.bursts`, `s.enumeration`) are read a few lines later by `alertFor()` to rate-limit alerts, so order matters: counters first, alert decision second.
- The ring is trimmed with one `splice` per event when full; `events` stays oldest-first.

### `add()` — alert, log, DB, listeners

```js
// lines 143-155
    const alert = this.alertFor(ev, s);
    if (alert) this.pushAlert(alert);

    this.writeLog(ev);
    if (this.db && !ev.replay) this.db.addRequest(ev);
    for (const l of this.listeners) {
      try {
        l(ev, alert);
      } catch (err) {
        log('error', `listener failed: ${err.message}`);
      }
    }
  }
```

- Replayed events skip the DB (they already exist in the replayed CTF). The JSONL log skips them inside `writeLog()`.
- Listener errors are caught per listener, so a broken WebSocket broadcaster cannot break request processing.

### `emitAlert()` and `pushAlert()`

```js
// lines 157-173
  // Alerts raised by other parts of the system (login conflicts, admin actions...)
  emitAlert(a) {
    const alert = { n: 0, ts: a.ts || Date.now(), level: a.level || ALERT_LEVEL[a.type] || 'info', type: a.type, student: a.student || null, ip: a.ip || null, msg: a.msg, data: a.data || null, ack: 0, replay: !!a.replay };
    this.pushAlert(alert);
    for (const l of this.listeners) {
      try {
        l(null, alert);
      } catch {}
    }
    return alert;
  }

  pushAlert(alert) {
    this.alerts.push(alert);
    if (this.alerts.length > MAX_ALERTS) this.alerts.splice(0, this.alerts.length - MAX_ALERTS);
    if (this.db && !alert.replay) this.db.addAlert(alert); // replayed alerts already exist in the replayed CTF
  }
```

- `emitAlert()` is the entry point for alerts that are not tied to an event: `new-student` (here), `admin-login-conflict`, `queue`, `decoy`, `info` (proxy target changes) from `server.js`. Listeners get `(null, alert)` — the dashboard broadcaster checks `if (ev)` / `if (alert)` separately.
- Level precedence: explicit `a.level`, else the table, else `info`. An unknown `type` with no level becomes `info`, which is also "not counted as unacked" in `stats()`.
- `pushAlert()` is shared by both paths and is the only place that writes alerts to the DB.

### `alertFor()` — when an event becomes an alert

```js
// lines 175-203
  alertFor(ev, s) {
    if (ev.flags.includes('blocked')) return null;
    let type = null;
    let msg = null;
    let level = null;
    if (ev.flags.includes('idor-success')) {
      type = 'idor-success';
      msg = `${ev.student} READ ${ev.endpoint} #${ev.objectId}${ev.owner ? ` (belongs to ${ev.owner})` : ''} - HTTP ${ev.status}, ${ev.size} bytes`;
    } else if (ev.flags.includes('idor-attempt')) {
      type = 'idor-attempt';
      msg = `${ev.student} tried ${ev.endpoint} #${ev.objectId}${ev.owner ? ` (belongs to ${ev.owner})` : ''} - HTTP ${ev.status}`;
    } else if (ev.attacks.length) {
      // one alert per student per attack class per 10 hits
      const fresh = ev.attacks.filter((a) => s.attacks[a.cls] === 1 || s.attacks[a.cls] % 10 === 0);
      if (!fresh.length) return null;
      type = 'web-attack';
      level = fresh.reduce((w, a) => (LEVELS.indexOf(a.level) > LEVELS.indexOf(w) ? a.level : w), 'low');
      msg = `${ev.student}: ${fresh.map((a) => `${a.label} (${a.where}: ${a.sample})`).join('; ')} - ${ev.method} ${ev.path}`;
    } else if (ev.flags.includes('burst-errors') && (s.bursts === 1 || s.bursts % 25 === 0)) {
      type = 'burst-errors';
      msg = `${ev.student} is producing a burst of ${ev.status} errors (${ev.method} ${ev.path})`;
    } else if (ev.flags.includes('enumeration')) {
      if (ev.distinctIds % 10 !== 0 && s.enumeration !== 1) return null;
      type = 'enumeration';
      msg = `${ev.student} is enumerating ${ev.endpoint}: ${ev.distinctIds} different IDs (${(ev.seq || []).slice(-4).join(' -> ')})`;
    }
    if (!type) return null;
    return { n: ev.n, ts: ev.ts, level: level || ALERT_LEVEL[type], type, student: ev.student, ip: ev.ip, endpoint: ev.endpoint, objectId: ev.objectId, owner: ev.owner, status: ev.status, msg, ack: 0, replay: !!ev.replay };
  }
```

One alert at most per event, chosen by this precedence:

1. `blocked` → never (the 403 page served by `preRequest` is noise).
2. `idor-success` → every time, `critical`.
3. `idor-attempt` → every time, `high`.
4. web attack → only when some class on this event is at hit 1, 10, 20, ... for this student (`s.attacks` was just incremented). Level = worst level among those *fresh* classes, starting from `low`. The message lists each fresh class with its sample.
5. `burst-errors` → at the student's 1st, 25th, 50th ... burst-flagged event.
6. `enumeration` → at the student's first enumeration-flagged event, then whenever the *windowed* `distinctIds` is a multiple of 10. The message shows the last four IDs of `seq`.

Because of the `else if` chain an event that carries both an attack hit and an enumeration flag produces only the attack alert (or nothing, if the attack class is not "fresh"). `ev.owner` may be `null` (e.g. `same-as-user` miss), in which case the "(belongs to ...)" part is omitted.

### `renameStudent()` — rename or merge

```js
// lines 205-215
  renameStudent(oldName, newName) {
    if (!oldName || !newName || oldName === newName) return;
    for (const ev of this.events) if (ev.student === oldName) ev.student = newName;
    for (const a of this.alerts) {
      if (a.student === oldName) a.student = newName;
      a.msg = a.msg.split(oldName).join(newName);
    }
    const s = this.students.get(oldName);
    if (s) {
      this.students.delete(oldName);
      const t = this.students.get(newName);
      if (t) {
```

- Events in the ring are patched in place. Because `db.pending` holds the *same objects* (`add()` passes `ev` by reference and the pending batch is at most 500 events, well inside the 1500 ring), rows not yet flushed get the new name too.
- Alert messages are rewritten with a plain text replace of every occurrence. **Gotcha:** `split(oldName).join(newName)` is substring-based; renaming `ali` to `alice` also rewrites "alias" or "alice" inside other messages. Anonymous names (`ip:1.2.3.4`, `sess-ab12cd34`) are distinctive enough in practice.

```js
// lines 216-242
        for (const k of ['requests', 'failed', 'flagged', 'idorAttempts', 'idorSuccess', 'enumeration', 'bursts']) t[k] += s[k];
        t.distinctIds = Math.max(t.distinctIds, s.distinctIds);
        t.firstSeen = Math.min(t.firstSeen, s.firstSeen);
        t.lastSeen = Math.max(t.lastSeen, s.lastSeen);
        if (s.firstIdorSuccessTs && (!t.firstIdorSuccessTs || s.firstIdorSuccessTs < t.firstIdorSuccessTs)) t.firstIdorSuccessTs = s.firstIdorSuccessTs;
        Object.assign(t.seq, s.seq);
        for (const [ip, e] of Object.entries(s.ips)) {
          if (t.ips[ip]) {
            t.ips[ip].n += e.n;
            t.ips[ip].last = Math.max(t.ips[ip].last, e.last);
          } else t.ips[ip] = e;
        }
        for (const [ua, n] of Object.entries(s.uas)) t.uas[ua] = (t.uas[ua] || 0) + n;
        for (const [c, n] of Object.entries(s.attacks)) t.attacks[c] = (t.attacks[c] || 0) + n;
        for (const a of s.appNames) if (!t.appNames.includes(a)) t.appNames.push(a);
        t.playerId = t.playerId || s.playerId;
        t.profile = t.profile || s.profile;
      } else {
        s.name = newName;
        this.students.set(newName, s);
      }
    }
    if (this.firstIdorSuccess && this.firstIdorSuccess.student === oldName) this.firstIdorSuccess.student = newName;
    if (this.db) this.db.db.prepare('UPDATE requests SET student = ? WHERE ctf_id = ? AND student = ?').run(newName, this.db.ctfId, oldName);
    for (const l of this.resetListeners) l();
  }
```

- Two cases: the target row already exists (an `ip:` lane turned out to be an existing student) → **merge** counters, take the earliest first-seen, the latest last-seen, the earliest IDOR success, union the IP/UA/attack/appName tables (the caps of 25/30/10 are not enforced during a merge); otherwise → **move** the row under the new name.
- `t.seq` is overwritten per endpoint by the source's sequence (`Object.assign`), i.e. the merged-in lane's sequence wins for endpoints both had.
- The DB rename is a direct SQL update on the **active** CTF's rows (not the replayed one), and it bypasses the batch. Alerts in the DB are **not** renamed; only the in-memory copies are.
- Finally the reset listeners fire, so the dashboard gets a full snapshot instead of trying to patch names client-side.

### `studentsByIp()` and `tick()`

```js
// lines 244-260
  studentsByIp(ip) {
    return [...this.students.values()].filter((s) => s.ips[ip]).map((s) => s.name);
  }

  tick(ts, inc) {
    const sec = Math.floor(ts / 1000);
    if (sec > this.rpsHead) {
      const gap = Math.min(sec - this.rpsHead, RPS_WINDOW);
      for (let i = 0; i < gap; i++) {
        this.rps.shift();
        this.rps.push(0);
      }
      this.rpsHead = sec;
    }
    const idx = RPS_WINDOW - 1 - (this.rpsHead - sec);
    if (idx >= 0 && idx < RPS_WINDOW) this.rps[idx] += inc;
  }
```

- `studentsByIp` is used by `server.js` to name suspects in a dashboard login conflict.
- `tick(ts, inc)` keeps a 120-slot ring where the last slot is the second `rpsHead`. When a newer second arrives, the ring slides forward by the gap (capped at 120, so a long idle period costs at most 120 shifts). Then `inc` is added to the slot for `ts`'s second. A timestamp older than the window gives a negative `idx` and is silently dropped — this is why events with synthetic old timestamps (tests) do not show up in `rps`, and why replay uses wall time.
- `shift()`/`push()` on a 120-element array per new second is cheap.

### `stats()`

```js
// lines 262-279
  stats() {
    this.tick(Date.now(), 0);
    const last60 = this.rps.slice(-60);
    const last10 = this.rps.slice(-11, -1);
    const topEndpoints = [...this.byEndpoint.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count }));
    const classes = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
    for (const [code, n] of Object.entries(this.byStatus)) {
      const c = `${String(code)[0]}xx`;
      if (classes[c] !== undefined) classes[c] += n;
    }
    const students = [...this.students.values()].map((s) => ({ ...s, blocked: this.isBlocked(s.name), renamePending: this.renamePending(s.name), queue: this.queueStatus(s.name), decoy: this.isDecoy(s.name) }));
    const byLevel = {};
    for (const l of LEVELS) byLevel[l] = 0;
    let unacked = 0;
    for (const a of this.alerts) {
      byLevel[a.level] = (byLevel[a.level] || 0) + 1;
      if (!a.ack && a.level !== 'info') unacked++;
    }
```

- `tick(now, 0)` slides the ring forward without counting, so idle seconds show as zeros.
- `rps` on the dashboard is the last 60 slots; `rpsNow` (below) is the average of the 10 **completed** seconds — `slice(-11, -1)` excludes the current, partial second so the number does not flicker low.
- `topEndpoints`: the eight busiest keys.
- `statusClasses`: 1xx is ignored (not in `classes`).
- Student rows are shallow-copied and decorated with the four hooks. This is the only place the hooks are used; they are called once per student per `stats()` call (every second per connected dashboard, plus every `/api/students` hit), so they must be cheap. `queueStatus` goes through `admin.rawNameFor()` which scans the alias table — fine for classroom sizes.
- `unacked` ignores `info` alerts and uses only the in-memory ring, so it caps at 400.

```js
// lines 280-296
    const lb = {
      firstIdorSuccess: this.firstIdorSuccess,
      mostIds: students.filter((s) => s.distinctIds > 0).sort((a, b) => b.distinctIds - a.distinctIds).slice(0, 5).map((s) => ({ student: s.name, value: s.distinctIds })),
      mostFailed: students.filter((s) => s.failed > 0).sort((a, b) => b.failed - a.failed).slice(0, 5).map((s) => ({ student: s.name, value: s.failed })),
      mostIdor: students.filter((s) => s.idorSuccess > 0).sort((a, b) => b.idorSuccess - a.idorSuccess || a.firstIdorSuccessTs - b.firstIdorSuccessTs).slice(0, 5).map((s) => ({ student: s.name, value: s.idorSuccess })),
      mostAttacks: students.map((s) => ({ student: s.name, value: Object.values(s.attacks).reduce((a, b) => a + b, 0) })).filter((x) => x.value > 0).sort((a, b) => b.value - a.value).slice(0, 5),
    };
    return {
      startedAt: this.startedAt, uptimeSec: Math.round((Date.now() - this.startedAt) / 1000), total: this.total,
      rps: last60, rpsNow: last10.reduce((a, b) => a + b, 0) / 10, statusClasses: classes, byStatus: this.byStatus, topEndpoints,
      attackTotals: this.attackTotals, students, leaderboard: lb, alertsTotal: this.alerts.length, alertsUnacked: unacked, alertsByLevel: byLevel,
    };
  }

  snapshot() {
    return { events: this.events.slice(-500), alerts: this.alerts.slice(-150), stats: this.stats() };
  }
```

- Leaderboard: top 5 per category; `mostIdor` ties are broken by who succeeded first.
- `snapshot()` is what a newly connected dashboard receives (and what `onReset` broadcasts): the last 500 events, last 150 alerts and the stats. The full 1500/400 rings are only reachable through `/api/state` (same `snapshot()`, so also 500/150) — the rings are larger than the snapshot simply so `renameStudent` can patch more history.

### `writeLog()` — daily JSONL

```js
// lines 298-311
  writeLog(ev) {
    if (!this.logDir || ev.replay) return;
    const day = new Date(ev.ts).toISOString().slice(0, 10);
    if (!this.stream || this.streamDate !== day) {
      if (this.stream) this.stream.end();
      const file = path.join(this.logDir, `events-${day}.jsonl`);
      this.stream = fs.createWriteStream(file, { flags: 'a' });
      this.stream.on('error', (err) => log('error', `log write failed: ${err.message}`));
      this.streamDate = day;
      log('info', `logging to ${file}`);
    }
    const { req, ...rest } = ev;
    this.stream.write(JSON.stringify(rest) + '\n');
  }
```

- One file per **UTC** day, opened in append mode, rotated when the event's date changes. Back-pressure is ignored (`write()` return value unused) — acceptable for a line-per-request log on local disk.
- `req` is stripped defensively (the event built by `server.js` does not carry it, but the raw proxy event does).
- The stream is never explicitly closed on shutdown; the OS flushes it when the process exits.

### Export

```js
// line 314
module.exports = { Store, LEVELS, ALERT_LEVEL };
```

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` `onEvent()` line 230 | `add(ev)` with the fully built event (identity + detector + attacks + masking). |
| in | `server.js` lines 60, 95, 251, 269, 272 | `emitAlert({type, level, student, ip, msg, data})` for queue arrivals, login conflicts, target changes, decoy routing. |
| in | `server.js` lines 86-88, 275 | Hook assignment: `isBlocked`, `renamePending`, `queueStatus`, `isDecoy`. |
| in | `server.js` `mergeLane()`, `admin.js` `rename()` / `onGateRename()` | `renameStudent(old, new)`. |
| in | `server.js` `resetLive()`, `replay.js` `start()` | `reset()`; replay then sets `replayCtfId`. |
| in | `server.js` line 57, `admin.js` | Direct reads/writes of `store.students` (profile update, block IP lookup, raw name lookup). |
| in | `dashboard.js` | `snapshot()`, `stats()`, `onEvent(fn)`, `onReset(fn)`, `store.alerts` (ack), `store.students`, `store.replayCtfId`, `isBlocked`/`renamePending` for the detail view. |
| out | `db.js` | `addRequest(ev)`, `addAlert(alert)`, and a raw `db.db.prepare('UPDATE requests ...')` in `renameStudent`. |
| out | filesystem | `logs/events-YYYY-MM-DD.jsonl`. |
| out | `util.js` | `log()`. |

## Changing it safely

| Likely change | Where | Notes |
|---|---|---|
| New alert type (e.g. for a new detector flag) | `ALERT_LEVEL` (lines 14-27) and a new `else if` in `alertFor()` (lines 175-203) with its own rate-limit rule | Also decide the precedence position in the chain. |
| New per-student counter / field | `student()` initialiser (lines 77-81), the update in `add()` (lines 106-138), and the merge branch of `renameStudent()` (lines 216-233) | Three places; forgetting the merge branch silently loses data on lane merges. |
| Bigger/smaller rings or snapshot | `MAX_EVENTS`, `MAX_ALERTS`, `snapshot()` slices | The dashboard's client-side buffers assume ≤ 500 events per snapshot. |
| Different leaderboard | `stats()` lines 280-286 | All derived from the student rows; no new state needed. |
| Log format / rotation | `writeLog()` | Keep one JSON object per line; `inspect.sh` and external tools read it. |

Tests: no file in `proxy/test` imports `store.js` directly. It is exercised indirectly only through the modules it feeds (`db.test.js` for the DB side). If you change `alertFor()` or `renameStudent()`, write a test with `new Store({ logDir: null, db: null })` and hand-built events (see the exercises).

## Exercises

1. **Alert rate limiting.** Create `new Store({logDir: null, db: null})`, then call `add()` 21 times with the same student and `attacks: [{cls:'sqli', level:'high', label:'SQL injection', where:'url', sample:'x'}]` (all other fields as in the `ev` helper of `db.test.js`, plus `flags: []`). Print `store.alerts.map(a => a.type)`. Expect `new-student`, then `web-attack` at hit 1, 10 and 20 — four alerts in total.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node your-script.js`
2. **Merge on rename.** Add two events for `ip:1.1.1.1` (one with `status: 404`) and one for `alice`, then `renameStudent('ip:1.1.1.1', 'alice')`. Print `store.stats().students` — one row named `alice` with `requests: 3`, `failed: 1`, and `ips` containing the IP. Also print `store.alerts.map(a => a.msg)` to see the "appeared" messages rewritten.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node your-script.js`
3. **Path templating.** Confirm `topEndpoints` groups numeric IDs: add events with paths `/api/users/1/orders/5` and `/api/users/2/orders/9?x=1` (no `endpoint`), then read `store.stats().topEndpoints`. Expect one entry `/api/users/:id/orders/:id` with `count: 2`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node -e "const {Store}=require('./src/store');const s=new Store({logDir:null,db:null});const b={ts:Date.now(),student:'a',source:'ip',ip:'1',method:'GET',status:200,size:1,flags:[],attacks:[],severity:'ok'};s.add({...b,path:'/api/users/1/orders/5'});s.add({...b,path:'/api/users/2/orders/9?x=1'});console.log(s.stats().topEndpoints)"`

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Store` | `new Store({logDir, db})` | Live in-memory state + JSONL log + DB write-through. |
| `Store#add` | `(ev) => void` | Ingest one finished request event; updates counters, may alert, logs, persists, notifies. |
| `Store#emitAlert` | `({ts?, type, level?, student?, ip?, msg, data?, replay?}) => alert` | Raise an alert not tied to an event. |
| `Store#pushAlert` | `(alert) => void` | Ring insert + DB write (internal, used by both paths). |
| `Store#alertFor` | `(ev, studentRow) => alert \| null` | Alert decision and rate limiting for an event. |
| `Store#renameStudent` | `(oldName, newName) => void` | Rename or merge a student row, patch history, update DB rows, fire reset listeners. |
| `Store#reset` | `() => void` | Clear the live view (also clears `replayCtfId`). |
| `Store#onEvent` | `(fn(ev\|null, alert\|null)) => unsubscribe` | Subscribe to events/alerts. |
| `Store#onReset` | `(fn()) => void` | Subscribe to resets. |
| `Store#stats` | `() => {startedAt, uptimeSec, total, rps, rpsNow, statusClasses, byStatus, topEndpoints, attackTotals, students, leaderboard, alertsTotal, alertsByLevel, alertsUnacked}` | Dashboard numbers. |
| `Store#snapshot` | `() => {events, alerts, stats}` | Last 500 events + 150 alerts + stats. |
| `Store#studentsByIp` | `(ip) => string[]` | Names of students seen from that IP. |
| `Store#tick` | `(ts, inc) => void` | Advance / increment the rps ring. |
| `Store.noteIp` | `(studentRow, ip, ts) => void` | Static helper for the per-student IP table. |
| `Store#isBlocked`, `#renamePending`, `#queueStatus`, `#isDecoy` | `(name) => bool \| string \| null` | Hooks injected by `server.js`; used in `stats()`. |
| `LEVELS` | `string[]` | Alert level order. |
| `ALERT_LEVEL` | `{[type]: level}` | Default alert level per type. |

## Update: issue 5 fixed

`renameStudent()` now rewrites alert text with `Store.renameInText()` (whole-word replacement: letters, digits and `_ . - / : @` next to the name mean it is part of a bigger token, so `bobby`, `bob.smith` and `/bob/x` are left alone), and for the active CTF it also updates the database: `requests.student`, `requests.owner`, `alerts.student` and the alert messages. Covered by `test/store.test.js`.

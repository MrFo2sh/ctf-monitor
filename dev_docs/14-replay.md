# Replay — `proxy/src/replay.js`

## Purpose

`replay.js` plays a recorded CTF (the `requests` rows of one `ctfs` record, live or imported) back into the live `Store` at a chosen speed, so the organizer can review a past event on the same Live/Students/Alerts screens as if it were happening now. It does not re-run detection: the flags, severity and attack hits come from the recording. While a replay is loaded, `store.replayCtfId` makes the history views (alerts, student detail, query) read that CTF instead of the active one.

## Where it sits

| | |
|---|---|
| Required by | `server.js` (creates `new Replay({db, store})`; calls `replay.stop()` from `newCtf()` and `stopCtf()`); `dashboard.js` (`GET /api/replay` → `status()`, `POST /api/replay` → `start()`, `POST /api/replay/stop` → `stop()`; `status()` is also included in every 1-second `stats` WebSocket broadcast and in `/api/me`) |
| Requires | `./util` (`log`); a `Db` (`requestsOf()`); a `Store` (`reset()`, `add()`, `replayCtfId`) |

## Data it owns

| Field | Type | Meaning |
|---|---|---|
| `db` | `Db` | Source of rows: `db.requestsOf(ctfId)` (chapter 12). |
| `store` | `Store` | Destination of events (chapter 11). |
| `timer` | `Timeout \| null` | The pending `setTimeout` for the next batch. `null` when idle or finished; `!!timer` is the `running` flag. |
| `state` | `{ctfId, speed, total, done, startedAt} \| null` | Progress of the last started replay. Stays set after the replay finished, until another `start()`. Never cleared by `stop()`. |

`status()` output:

| Field | Meaning |
|---|---|
| `running` | A timer is pending (rows remain). |
| `loaded` | `store.replayCtfId` — the CTF the live view currently shows, or `null`. Stays set after the replay finished until the store is reset. |
| `ctfId`, `speed`, `total`, `done`, `startedAt` | Copied from `state` when there is one. `done` is the number of rows emitted so far. |

## Walkthrough

### Constructor and `status()`

```js
// lines 7-20
class Replay {
  constructor({ db, store }) {
    this.db = db;
    this.store = store;
    this.timer = null;
    this.state = null; // { ctfId, speed, total, done, startedAt }
  }

  // loaded = the live view currently shows this replayed CTF (stays set after the replay finished,
  // until Stop / New CTF / another replay clears the live view)
  status() {
    const loaded = this.store.replayCtfId || null;
    return this.state ? { ...this.state, running: !!this.timer, loaded } : { running: false, loaded };
  }
```

Two distinct notions:

- **running** — rows are still being emitted (a timer exists).
- **loaded** — the live view is showing a replayed CTF. This is read from the store, not from `state`, because the store is the thing that can be reset from elsewhere (`server.js resetLive()`); after `store.reset()` `loaded` becomes `null` even though `state` still remembers the last replay.

### `start()` — preparation

```js
// lines 22-32
  start(ctfId, speed = 10) {
    this.stop();
    const rows = this.db.requestsOf(ctfId);
    if (!rows.length) throw new Error('that CTF has no requests');
    const sp = Math.max(0.1, Math.min(Number(speed) || 10, 1000));
    this.state = { ctfId, speed: sp, total: rows.length, done: 0, startedAt: Date.now() };
    this.store.reset();
    this.store.replayCtfId = ctfId;
    const base = rows[0].ts;
    const now = Date.now();
    let i = 0;
```

- `stop()` first, so starting a second replay cancels the first.
- `db.requestsOf(ctfId)` flushes pending writes and returns **all** rows ordered by `ts, id`, already run through `parseRow` (so `flags`, `attacks`, `body` are parsed JSON). The whole CTF is held in memory for the duration; a 200k-request CTF is a few hundred MB, which is acceptable for an organizer's laptop but worth knowing.
- The error for an empty CTF surfaces as HTTP 400 from the dashboard.
- Speed is clamped to `[0.1, 1000]`; a non-numeric speed (`Number('fast')` is `NaN`, falsy) falls back to 10×. 1× is the original pace.
- `store.reset()` clears the live view (events, alerts, students, rps, `replayCtfId`) and fires the reset listeners, which makes the dashboard push a fresh empty snapshot. Then `replayCtfId` is set — order matters because `reset()` sets it to `null`.
- `base` is the timestamp of the first recorded row; `now` is the wall-clock origin. Row *k* is due at `now + (rows[k].ts - base) / sp`.

### `start()` — the `step` loop

```js
// lines 33-64
    const step = () => {
      const wallNow = Date.now();
      // emit every row whose (scaled) time has come
      while (i < rows.length && now + (rows[i].ts - base) / sp <= wallNow) {
        const r = rows[i++];
        this.store.add({
          ts: wallNow,
          time: new Date(wallNow).toISOString(),
          student: r.student,
          rawName: r.raw_name,
          studentId: null,
          source: r.source || 'replay',
          ip: r.ip,
          method: r.method,
          path: r.path,
          endpoint: r.endpoint,
          objectId: r.object_id,
          status: r.status,
          size: r.size,
          latencyMs: r.latency,
          flags: Array.isArray(r.flags) ? r.flags : [],
          attacks: Array.isArray(r.attacks) ? r.attacks : [],
          severity: r.severity || 'ok',
          owner: r.owner,
          mine: r.flags && r.flags.includes('idor-attempt') ? false : null,
          seq: null,
          ua: r.ua,
          body: r.body || undefined,
          replay: true,
        });
        this.state.done = i;
      }
```

- The `while` emits every row that is due, in one synchronous burst. There is no cap, so at 1000× a 10-minute recording is emitted in about 0.6 s of wall time, in chunks sized by how much "recorded time" elapsed since the previous tick. The store's `add()` is cheap (no DB, no file), so this is fine.
- The event is rebuilt from DB column names (`raw_name`, `object_id`, `latency`) into the store's event shape (`rawName`, `objectId`, `latencyMs`). Keep this mapping in sync with `db.js` `insertReq` and `store.js` `add()`.
- `ts` is **the current wall time**, not the recorded time. The live view therefore shows the replay as if it happens now (and the rps chart works, because `store.tick()` ignores timestamps older than its 120 s window). The original timestamps are still available through the history views, which read the DB.
- `studentId: null` and `seq: null`: the identity resolver and detector are not involved, so there is no user ID and no ID sequence. Consequences in the store: `s.id` stays `null`, `s.seq` stays empty, and `s.distinctIds` stays 0 because `idsSeenTotal` is absent. The leaderboard's "most IDs" panel is empty during a replay.
- `mine` is reconstructed from the flags only for the attempt case; it is informational (the store does not read it).
- `flags`/`attacks` are guarded with `Array.isArray` because `parseRow` leaves the column as a string if the JSON was malformed.
- `replay: true` is the switch that makes `store.add()` skip the JSONL log and `db.addRequest()`, and makes `pushAlert()` skip `db.addAlert()`. Without it a replay would duplicate every request into the *active* CTF.
- `state.done = i` after each row, so `status()` can report progress.

```js
// lines 65-76
      if (i >= rows.length) {
        log('info', `replay of CTF #${ctfId} finished (${rows.length} requests)`);
        this.timer = null;
        return;
      }
      const wait = Math.max(20, Math.min(1000, now + (rows[i].ts - base) / sp - Date.now()));
      this.timer = setTimeout(step, wait);
    };
    log('info', `replaying CTF #${ctfId}: ${rows.length} requests at ${sp}x`);
    step();
    return this.status();
  }
```

- On completion the timer is cleared (`running` becomes `false`) but `state` and `store.replayCtfId` stay, so the dashboard keeps showing the replayed CTF with `loaded` set.
- The next wake-up is the scaled time until the next row, clamped to 20 ms (don't spin) and 1000 ms (keep `done` updating and respond to `stop()` quickly even in long silent gaps of the recording).
- `step()` is called synchronously once so rows at `base` (offset 0) are emitted immediately, and the dashboard's `POST /api/replay` response already contains `done ≥ 1`.
- The timer is **not** `unref()`'d; a running replay keeps the process alive, which is irrelevant for the server (it listens anyway) but matters if you ever script it.

### `stop()`

```js
// lines 78-82
  stop() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
```

Stops emitting; does **not** touch `state`, `store.replayCtfId` or the store contents. The live view keeps what was replayed so far. Clearing the view is the job of `server.js resetLive()` (New CTF / Stop CTF) or of the next `start()`.

### The `replayCtfId` scope, end to end

1. `Replay.start()` sets `store.replayCtfId = ctfId` after `store.reset()`.
2. `dashboard.js` line 49: `scopeCtf(explicit) = explicit ? Number(explicit) : store.replayCtfId || db.ctfId || undefined`. Used by `/api/alerts` (line 163), `/api/students/<name>` detail (line 183), `/api/query/values` (line 224) and `/api/query` (line 236). So while a replay is loaded, those read the replayed CTF's rows, matching what the live view shows.
3. Live traffic that arrives during a replay is still recorded into the **active** CTF (`db.ctfId`), because `store.add()` only skips the DB for `replay: true` events. It also appears mixed into the live view. Replaying while students are playing is therefore confusing but not destructive.
4. `store.reset()` (from `resetLive()`, i.e. New CTF or Stop CTF) sets `replayCtfId = null`, returning the scope to `db.ctfId`.
5. `store.renameStudent()` writes `UPDATE requests ... WHERE ctf_id = this.db.ctfId` — the **active** CTF, not `replayCtfId`. Renaming a student while a replay is loaded updates the in-memory rows but not the replayed CTF's DB rows.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `dashboard.js` lines 360-374 | `status()`, `start(Number(body.ctf), body.speed)` (admin only), `stop()`. |
| in | `dashboard.js` line 417, 134 | `status()` in the 1 s `stats` broadcast and in `/api/me`. |
| in | `server.js` `newCtf()` / `stopCtf()` | `stop()` before the store is reset. |
| out | `db.js` | `requestsOf(ctfId)` — flush + full ordered read. |
| out | `store.js` | `reset()`, `replayCtfId = ctfId`, `add(ev)` with `replay: true`. |
| out | `util.js` | `log('info', ...)` on start and finish. |

## Changing it safely

| Likely change | Where | Notes |
|---|---|---|
| Keep original timestamps in the live view | lines 39-40 (`ts`, `time`) | The rps chart (`store.tick`) would then show nothing for old recordings (timestamps outside its 120 s window are dropped); the JSONL log is unaffected because replayed events are never written to it. |
| Re-run detection during replay (fresh flags from current rules) | Replace the hand-built event with a call into the same pipeline `server.js onEvent()` uses | Needs a `Detector` and identity data that is not in the DB; non-trivial. |
| Pause / seek | Add a `paused` flag checked in `step()`, or recompute `now`/`base` for seeking | `state.done` and `i` are the cursor. |
| Bound the burst size | Add a row cap to the `while` on line 36 and reschedule with `wait = 0` | Only matters for very large recordings at 1000×. |
| Add a column to the recording | `db.js` schema + `insertReq` + `importCtf`, then the mapping on lines 38-62 here, then `store.js add()` | Three places must agree. |

Tests: none of the files in `proxy/test` import `replay.js`. The pieces it relies on are covered by `db.test.js` (`export / import round trip creates an imported CTF with the same requests` exercises `requestsOf`). Write a test with `new Db(':memory:')`, a `Store({logDir: null, db: null})` and a `Replay` at `speed: 1000` if you change the timing logic.

## Exercises

1. **Replay an in-memory CTF.** Script: create `Db(':memory:')`, `openCtf('r')`, add three requests with `ts` 0, 1000, 2000 ms apart via `db.addRequest`, `db.flush()`, then `new Replay({db, store: new Store({logDir: null, db: null})}).start(ctf.id, 1000)`. Print `replay.status()` immediately and again after 50 ms. Expect `done: 1` then `done: 3, running: false, loaded: <ctf.id>`.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node your-script.js`
2. **Confirm replayed events never reach the DB.** In the same script, pass the `db` to the store (`new Store({logDir: null, db})`), replay, then run `db.requestsOf(ctf.id).length` — it must still be 3, and `db.alerts({ctfId: ctf.id}).length` must be 0 even though the store produced `new-student` alerts.
   Verify: `cd D:\SIEMs\ctf-watch\proxy; node your-script.js`
3. **Watch the scope switch from the dashboard.** Start the server, import or record a CTF, press Replay in the CTFs tab, then open the Query tab and run an empty query: the rows come from the replayed CTF. Press New CTF: the same query now returns rows of the new, empty CTF.
   Verify: `curl -s -H "Cookie: <session cookie>" http://127.0.0.1:8080/api/replay` shows `loaded` set during the replay and `null` after New CTF.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Replay` | `new Replay({db, store})` | Replays a recorded CTF into the live store. |
| `Replay#start` | `(ctfId, speed = 10) => status` | Resets the live view, sets `store.replayCtfId`, emits rows on a scaled timeline. Throws if the CTF has no requests. Speed clamped to 0.1-1000. |
| `Replay#stop` | `() => void` | Cancels the timer; leaves the live view and `replayCtfId` as they are. |
| `Replay#status` | `() => {running, loaded, ctfId?, speed?, total?, done?, startedAt?}` | Progress and whether the live view is showing a replay. |

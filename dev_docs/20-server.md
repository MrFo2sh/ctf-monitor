# Server — `proxy/src/server.js`

## Purpose

`server.js` is the entry point (`node src/server.js`). It reads the environment, builds every object in the right order, and wires them together with small closures: the proxy's raw exchanges go through identity resolution, IDOR detection and attack classification into the store; the dashboard gets callbacks for everything that changes global state (target, decoy, gate config, queue decisions, CTF lifecycle). It also owns the three pieces of logic that belong to no other module: the player mapping cache, the per-request block check (`preRequest`) and the CTF lifecycle (`newCtf`, `stopCtf`, `shutdown`).

## Where it sits

| Who calls it | How |
|---|---|
| `npm start` / Docker `CMD ["node", "src/server.js"]` | Runs top to bottom once; there are no exports. |

| What it requires | For |
|---|---|
| `./config` → `Config` | `rules.json` (hot-reloaded). |
| `./identity` → `IdentityResolver` | Who sent a request. |
| `./detect` → `Detector` | IDOR / enumeration / burst verdicts. |
| `./store` → `Store` | Live ring buffers, JSONL log, db write-through, listeners. |
| `./db` → `Db` | SQLite. |
| `./auth` → `Auth` | Dashboard accounts. |
| `./admin` → `Admin` | Block / rename / require-rename state. |
| `./namegate` → `NameGate`, `normalizeConfig` | The name form at first visit. |
| `./approvals` → `Approvals` | Admission queue. |
| `./decoy` → `Decoy` | Decoy routing list. |
| `./replay` → `Replay` | Replaying a past CTF. |
| `./playground` → `Playground` | Mock app + simulator children. |
| `./attacks` → `classify`, `worstLevel` | Web-attack classification. |
| `./proxy` → `createProxy` | The student-facing proxy. |
| `./ports` → `discover`, `validateTarget` | Target discovery/validation. |
| `./dashboard` → `createDashboard` | The organizer UI server. |
| `./mask` → `maskObject`, `maskUrl`, `maskText` | Secret masking before storage. |
| `./util` → `parseBody`, `clientIp`, `macFor`, `log` | Helpers. |

## Data it owns

### Environment variables (lines 25-38, plus the ones read by required modules)

`env(k, d)` treats an **empty string as unset** (so `CTF_TARGET=` in `.env` means "none"). `flag()` (line 26) is defined but unused.

| Variable | Default | Used for |
|---|---|---|
| `CTF_TARGET` | `''` | Initial proxy target, only when no target is saved in the db (see line 237). |
| `PROXY_PORT` | `8888` | Proxy listen port; also excluded from discovery and used in `studentLink` hint. |
| `PROXY_BIND` | `127.0.0.1` | Proxy bind address (`0.0.0.0` when zrok runs elsewhere / Docker Desktop). |
| `DASHBOARD_PORT` | `8080` | Dashboard port. |
| `DASHBOARD_BIND` | `127.0.0.1` | Dashboard bind address; never expose through zrok. |
| `DASHBOARD_USERS` | `3` | Number of `user_N` accounts (0-200). |
| `SESSION_TTL_HOURS` | `12` | Dashboard session lifetime. |
| `LOG_DIR` | `<repo>/logs` | JSONL event logs, `credentials.txt`, `zrok.url` / `zrok.log`. |
| `DATA_DIR` | `<repo>/data` | Gate secret file; default db location. |
| `DB_FILE` | `<DATA_DIR>/ctf-watch.db` | SQLite file. |
| `CTF_NAME` | `''` | Name for the CTF record opened at start (a different name than the active record closes it and opens a new one). |
| `NAME_GATE_TITLE` | `Welcome to the CTF` | Gate title, only when no gate config is saved yet. |
| `NAME_GATE_COOKIE` | `ctfw_name` | Gate cookie name. |
| `LOG_LEVEL` (util.js) | `info` | `debug` shows discovery and identity details. |
| `CONFIG_DIR` (config.js) | `<repo>/config` | Where `rules.json` / `ownership.json` live. |
| `DISCOVERY_MODE`, `DOCKER_SOCK` (ports.js) | `host`, `/var/run/docker.sock` | See chapter 17. |

### Module-level state

| Name | Lines | Meaning |
|---|---|---|
| `config`, `getConfig` | 41-42 | Compiled `rules.json`; `getConfig()` always returns the latest reload. |
| `db`, `ctf` | 43-44 | SQLite handle; the CTF record active at start. |
| `gateConfig` | 46 | `let`: the normalised gate config, persisted in kv `gate_config`. |
| `profiles` | 47 | `{ rawName: { field: value, _at } }`, extra gate answers, kv `gate_profiles`. |
| `approvals`, `gate`, `identity`, `detector`, `store`, `admin`, `replay`, `playground`, `auth`, `decoy` | 48-85, 91, 259 | The core objects. |
| `playerCache` | 142 | `Map<studentRow, { id, ips: Set }>`: player id per live student row. Cleared by `resetLive`. |
| `target` | 236 | `let`: current proxy target URL or null; persisted in kv `proxy_target`. |
| exchange → event | 221-229 | The event object stored by `store.add`; fields listed in the pipeline section. |

## Walkthrough

### Construction order (lines 41-111) and why

```js
// lines 41-48
const config = new Config();
const getConfig = () => config.get();
const db = new Db(DB_FILE);
const ctf = db.openCtf(CTF_NAME || undefined);
let gateConfig = normalizeConfig(db.get('gate_config', null) || { title: env('NAME_GATE_TITLE', 'Welcome to the CTF') });
const profiles = db.get('gate_profiles', {});
const approvals = new Approvals({ db });
```

1. **Config first**: `new Config()` throws if `rules.json` cannot be read, so a misconfigured deployment fails immediately instead of after the servers are listening.
2. **Db second**: everything else loads persisted state from it. `openCtf` reuses the active (not ended) record, or opens one named `CTF_NAME` or `ctf-YYYY-MM-DD`.
3. **Gate config and profiles** come from the db (the env title is only a first-run default). `approvals` needs only the db.

```js
// lines 49-61
const gate = new NameGate({
  secretFile: path.join(DATA_DIR, '.name-gate-secret'),
  cookie: env('NAME_GATE_COOKIE', 'ctfw_name'),
  getConfig: () => gateConfig,
  approvals,
  onProfile: (name, profile) => {
    profiles[name] = { ...(profiles[name] || {}), ...profile, _at: Date.now() };
    db.set('gate_profiles', profiles);
    const s = store.students.get(admin.alias(name));
    if (s) s.profile = profiles[name];
  },
  onEnqueue: (name, info) => store.emitAlert({ type: 'queue', level: 'info', student: admin.alias(name), ip: info.ip, msg: `${name} filled the gate form and is waiting for approval (Queue tab)` }),
});
```

4. **Gate** before identity, because `IdentityResolver` consults the gate for the typed name. Its callbacks reference `store` and `admin`, which are declared *later* with `const`. That is safe only because the callbacks run at request time, long after line 83; calling one during construction would hit the temporal dead zone. `getConfig: () => gateConfig` is a closure over the `let`, so `setGateConfig` takes effect without touching the gate object.

```js
// lines 63-79
function queueDecide(names, status, by) {
  const changed = approvals[status === 'approved' ? 'approve' : status === 'blocked' ? 'block' : 'reset'](names, by);
  for (const raw of changed) {
    const display = admin.alias(raw);
    if (status === 'blocked') {
      const it = approvals.get(raw);
      admin.block(display, it && it.ip);
    } else if (admin.state.blocked[display]) admin.unblock(display);
  }
  return changed;
}
function setGateConfig(raw) {
  gateConfig = normalizeConfig(raw);
  db.set('gate_config', gateConfig);
  ...
  return gateConfig;
}
```

- `queueDecide` is the bridge between the admission queue (keyed by raw typed name) and the organizer block list (keyed by display alias): blocking in the queue also blocks at the proxy, using the IP recorded at form submission; approving or resetting lifts a block that the queue had set. These are function declarations, so they are hoisted and may be referenced before this line.

```js
// lines 80-88
const identity = new IdentityResolver(getConfig, gate);
const detector = new Detector(getConfig);
const store = new Store({ logDir: LOG_DIR, db });
const admin = new Admin({ db, store, detector, gate });
const replay = new Replay({ db, store });
const playground = new Playground({ proxyPort: PROXY_PORT });
store.isBlocked = (name) => !!admin.state.blocked[name];
store.renamePending = (name) => admin.isRenamePending(name);
store.queueStatus = (name) => (gateConfig.queue ? approvals.status(admin.rawNameFor(name)) : null);
```

5. **identity, detector** depend only on config (+gate). **store** needs the db (write-through). **admin** needs store and detector (its `rename` rewrites both) and the gate (it installs `gate.onRename` in its constructor). **replay** needs db and store. **playground** only needs the proxy port.
6. Three store hooks are injected so `store.stats()` can decorate each student row with `blocked`, `renamePending` and `queue` without the store knowing about admin/approvals.

```js
// lines 91-111
const auth = new Auth(db, {
  sessionTtlMs: SESSION_TTL_HOURS * 3600 * 1000,
  onConflict: (c) => {
    const suspects = store.studentsByIp(c.ip);
    store.emitAlert({ type: 'admin-login-conflict', level: 'critical', ip: c.ip, student: suspects[0] || null,
      msg: `Someone at ${c.ip} tried to log in to the dashboard as ${c.username} while that account is in use from ${c.activeIp}.` + ..., data: { username: c.username, ip: c.ip, activeIp: c.activeIp, suspects } });
    if (c.blocked) {
      admin.state.blocked[`ip:${c.ip}`] = { ip: c.ip, ts: Date.now(), reason: 'dashboard login conflict' };
      admin.save();
    }
  },
});
const credentials = auth.generateAccounts(DASHBOARD_USERS);
printCredentials(credentials);
```

7. **auth** after store and admin: a login conflict becomes a critical alert that names the CTF players seen from that IP (`store.studentsByIp`), and — if `auth.blockIp` actually blocked (not loopback) — also a proxy-level block entry keyed `ip:<ip>` so the same machine is cut off from the CTF. `admin.isBlocked(name, ip)` matches on the `ip` field of any entry, which is why this synthetic entry works.
8. `generateAccounts` runs synchronously here (scrypt per account), then the credentials are printed.

### `printCredentials` (lines 113-122)

```js
// lines 113-122
function printCredentials(list) {
  const lines = ['', '==================== DASHBOARD LOGIN ====================', ...list.map((c) => `  ${c.role.padEnd(5)}  ${c.username.padEnd(12)}  password: ${c.password}`), '=========================================================', ''];
  console.log(lines.join('\n'));
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.writeFileSync(path.join(LOG_DIR, 'credentials.txt'), lines.join('\n'), { mode: 0o600 });
  } catch (err) {
    log('error', `could not write credentials file: ${err.message}`);
  }
}
```

- Printed to stdout (visible in `docker compose logs`) and written to `logs/credentials.txt` with mode 600 so `start.sh` can show them again later. Because accounts are regenerated on every start, the file is always current. On Windows the mode is ignored.

### `withAlias` and `mergeLane` (lines 125-139)

```js
// lines 125-139
const withAlias = (who) => {
  const name = admin.alias(who.name);
  return name === who.name ? who : { ...who, name, rawName: who.name };
};

function mergeLane(anonLabel, rawName) {
  const target = admin.alias(rawName);
  if (!anonLabel || anonLabel === target || !store.students.has(anonLabel)) return;
  store.renameStudent(anonLabel, target);
  detector.renameStudent(anonLabel, target);
  playerCache.delete(anonLabel);
  log('info', `merged row ${anonLabel} into ${target}`);
}
gate.onIpNamed = (ip, name) => mergeLane(`ip:${ip}`, name);
identity.onSessionNamed = (label, name) => mergeLane(label, name);
```

- `withAlias` applies the organizer's rename (`admin.state.aliases`) to an identity: the display `name` becomes the alias and the original is kept as `rawName`. When no alias exists the same object is returned (no copy).
- `mergeLane` handles the moment an **anonymous row** becomes identified: a student who first appeared as `ip:1.2.3.4` (no cookie) or `sess-ab12cd34` (session cookie before login) and then filled the gate form / logged in. The old row's events, alerts, detector state and db rows are folded into the named row (`store.renameStudent` and `detector.renameStudent` do the merging). The guard `store.students.has(anonLabel)` skips the common case where the anonymous row never produced an event. The player cache entry is dropped so the merged row gets a player id computed from its real identities.
- Both triggers are callbacks: the gate fires `onIpNamed` the first time an IP is associated with exactly one name; the identity resolver fires `onSessionNamed` when a session cookie is learned at login.

### Player mapping cache: `playerIdFor` (lines 141-168)

```js
// lines 143-155
function playerIdFor(who, ip, ts) {
  const key = who.name;
  const cached = playerCache.get(key);
  const identities = [];
  if (who.source === 'name' || who.source === 'ip-match') {
    identities.push({ kind: 'name', value: who.rawName || who.name });
    const prof = profiles[who.rawName || who.name] || {};
    for (const [k, v] of Object.entries(prof)) if (!k.startsWith('_') && v && v !== '***' && /^(id|.*_id|.*id|email|mail|phone|student.*|roll.*)$/i.test(k)) identities.push({ kind: `gate:${k}`, value: String(v).toLowerCase() });
  }
  const appName = who.appName || (who.source === 'session' || who.source === 'jwt' || who.source === 'login' ? who.name : null);
  if (appName && !/^sess-/.test(appName)) identities.push({ kind: 'username', value: appName });
  if (ip && who.source !== 'ip') identities.push({ kind: 'ip', value: ip });
```

A *player* is a person across CTFs; a *student row* is a name within one CTF. The identities are listed **in order of trust** because `db.playerFor` takes the first one that already exists:

1. `name` — the gate name (raw, before aliasing), only when the gate supplied it (`source` `name` or `ip-match`).
2. `gate:<field>` — extra gate answers that look like identifiers: keys matching id / `*_id` / `*id` / email / mail / phone / `student*` / `roll*`, excluding internal `_at` and masked `***` (password-type fields). Lower-cased. Gotcha: `.*id` also matches keys like `paid` or `valid`.
3. `username` — the app account name (`appName` when the gate name is the display name, or the identity itself for session/jwt/login sources), never a `sess-` placeholder.
4. `ip` — unless the row *is* the IP (anonymous), where it would be circular.

```js
// lines 156-167
if (cached) {
  if (ip && !cached.ips.has(ip) && who.source !== 'ip') {
    cached.ips.add(ip);
    db.stmts.upsertIdentity.run(cached.id, 'ip', ip, db.ctfId, ts, ts);
  }
  return cached.id;
}
if (!identities.length) return null; // anonymous ip-only rows are not players yet
const id = db.playerFor(identities, who.name, ts);
playerCache.set(key, { id, ips: new Set(ip ? [ip] : []) });
if (ip) macFor(ip).then((mac) => mac && db.stmts.upsertIdentity.run(id, 'mac', mac, db.ctfId, ts, ts)).catch(() => {});
return id;
```

- The db lookup happens once per student row; afterwards only *new* IPs for that row are written. This keeps the per-request cost at a `Map` lookup.
- `null` for ip-only rows: they get a player id later, after `mergeLane` renames them (the cache entry is deleted there).
- MAC lookup (`util.macFor`: `ip neigh show`, Linux + private ranges only) is fire-and-forget; errors are swallowed.

### `preRequest`: blocked students (lines 171-184)

```js
// lines 171-184
function preRequest(req, res) {
  const who = withAlias(identity.resolve(req));
  const ip = clientIp(req);
  if (!admin.isBlocked(who.name, ip)) return false;
  const wantsHtml = String(req.headers.accept || '').includes('text/html');
  const body = wantsHtml ? '<!doctype html>…Access blocked…' : JSON.stringify({ error: 'blocked by the CTF organizer' });
  res.writeHead(403, { 'Content-Type': wantsHtml ? 'text/html; charset=utf-8' : 'application/json', 'Cache-Control': 'no-store' });
  res.end(body);
  req.resume();
  onEvent({ ts: Date.now(), req, method: req.method, url: req.url || '/', pathOnly: (req.url || '/').split('?')[0], status: 403, size: Buffer.byteLength(body), latencyMs: 0, reqLen: 0, reqBuf: Buffer.alloc(0), resHeaders: {}, resBuf: Buffer.alloc(0), error: 'blocked' });
  return true;
}
```

- Called by `proxy.js` for every request after the gate. A student is blocked by display name **or** by IP (`admin.isBlocked` checks both, including the synthetic `ip:` entries from login conflicts).
- Browsers get an HTML page, tools get JSON. `req.resume()` drains the body.
- The refusal is reported through `onEvent` with `error: 'blocked'`, so blocked attempts still appear in the Requests view (flag `blocked`, severity `notice`) without triggering detection or alerts (`store.alertFor` returns null for the `blocked` flag).

### The `onEvent` pipeline (lines 186-231)

From the raw proxy exchange `x` (`{ ts, req, method, url, pathOnly, status, size, latencyMs, reqLen, reqBuf, resHeaders, resBuf, error }`, see chapter 15) to the stored event:

1. **Config snapshot and flags** (187-188): `cfg = getConfig()` once, so a hot reload mid-request cannot mix two rule sets. `blockedReq = x.error === 'blocked'` marks the 403s from `preRequest`.
2. **Body parsing** (189-190): `parseBody(contentType, buf)` → object for JSON / urlencoded / simple multipart, else `null`. Adds nothing to the event yet; feeds steps 4, 6 and 8.
3. **Client IP** (191): `ip = clientIp(req)` (first `X-Forwarded-For` hop, then `X-Real-IP`, then socket).
4. **Identity, pass 1** (193): `pre = identity.resolve(req)` → `{ name, id, source, ip, sessionKey, appName? }` based on gate cookie / JWT / session cookie / IP.
5. **Learning** (194): unless blocked, `identity.learn({...})` inspects login and whoami exchanges (per `rules.json`) and returns `{ name, id }` when it learned who owns the session cookie, else `null`.
6. **Identity, pass 2 and patching** (195-198): resolve again so a cookie learned in step 5 is already applied, then: if a login was learned and the row is still anonymous (`source === 'ip'` or a `sess-` name) → attribute this request to the learned name with `source: 'login'`; if the gate supplied the name → keep it as display name but fill `id` and `appName` from the login. Finally `withAlias` → adds `rawName` when the organizer renamed the student. Fields produced: `student`, `rawName`, `studentId`, `source`, `appName`.
7. **`hasData`** (200-204): `size >= cfg.successMinBytes` (default 2) **and** the JSON body is not just an envelope of `error/err/message/msg/success/status` keys. Tells the detector whether a 200 really returned an object (IDOR *success*) or a polite error.
8. **Verdict** (206-208): `detector.analyze({ student, method, pathOnly, url, status, size, hasData, reqBody, ts })` → `{ endpoint, objectId, owner, ownerBasis, mine, seq, sequential, distinctIds, idsSeenTotal, flags, severity }`. Blocked requests get a fixed verdict with `flags: ['blocked']`, `severity: 'notice'`.
9. **Attack classification** (211): `classify({ url, bodyText (first 8 KiB of reqBuf), ua, referer })` → `[{ cls, level, label, where, sample }]`; empty for blocked requests.
10. **Flags and severity merge** (212-219): `flags = verdict.flags + 'attack:<cls>'…`; severity is raised by the worst attack level (`critical` → critical, `high` → high, otherwise at least `warn`) unless the verdict was already `critical`.
11. **Event assembly** (221-229), the stored shape:

| Field | From |
|---|---|
| `ts`, `time` | `x.ts`, ISO string of it |
| `student`, `rawName`, `studentId`, `source`, `appName` | step 6 |
| `profile` | `profiles[rawName]` (gate answers) or undefined |
| `playerId` | `playerIdFor(who, ip, ts)` (cache + db) |
| `ip` | step 3 |
| `method` | `x.method` |
| `path` | `maskText(maskUrl(x.url, cfg.maskFields))`: sensitive query params → `***`, JWT-looking and long-hex substrings → `<jwt:***>` / `<hex:***>` |
| `endpoint`, `objectId`, `owner`, `ownerBasis`, `mine`, `seq`, `sequential`, `distinctIds`, `idsSeenTotal` | verdict |
| `status`, `size`, `latencyMs` | `x` |
| `flags` | step 10, plus `'decoy'` when the student is on the decoy list |
| `attacks`, `severity` | steps 9-10 |
| `decoy` | `true` or undefined |
| `ua` | User-Agent, first 160 chars |
| `body` | `maskObject(reqBody, cfg.maskFields)` for non-GET requests with a parsed body (password-like keys → `***`, strings cut at 200 chars), else undefined |
| `error` | `x.error` or undefined |

12. **Store** (230): `store.add(ev)` assigns `n`, updates the student row and stats, derives an alert if warranted, appends to `logs/events-<day>.jsonl` (without `req`), queues the db insert (batched every 200 ms), and notifies listeners — the dashboard broadcasts `event` and `alert`.

Note `x.req` stays attached to `ev` (store listeners and the JSONL writer strip it); it is needed nowhere after this point but costs nothing.

`shouldIgnore` (233) tells the proxy which paths to skip entirely: the `ignore.pathPatterns` regexes from `rules.json`, compiled by `config.js`.

### Target, decoy and student link (lines 236-298)

```js
// lines 236-255
let target = db.get('proxy_target', null);
if (!target && CTF_TARGET) {
  try { target = validateTarget(CTF_TARGET); } catch (err) { log('error', `CTF_TARGET ignored: ${err.message}`); }
}
function setTarget(url, { label } = {}) {
  const clean = url ? validateTarget(url) : null;
  const prev = target;
  target = clean;
  db.set('proxy_target', clean);
  if (clean !== prev) {
    log('info', `proxy target: ${prev || '(none)'} -> ${clean || '(none)'}${label ? ` (${label})` : ''}`);
    store.emitAlert({ type: 'info', level: 'info', msg: clean ? `Proxy now points at ${clean}${label ? ` (${label})` : ''}` : 'Proxy disconnected from the CTF app' });
  }
  return target;
}
```

- The saved target (kv `proxy_target`) **wins over `CTF_TARGET`**: once the organizer picked a target in the dashboard, changing `.env` has no effect until the target is cleared (Stop CTF saves `null`, after which `CTF_TARGET` applies again on the next start). An invalid `CTF_TARGET` is logged and ignored, not fatal.
- `setTarget` validates, persists (also `null`), and logs + emits an info alert only on actual change. `getTarget` (255) is the closure the proxy and dashboard read.
- `discoverTargets` (256) excludes the monitor's own ports.

```js
// lines 259-276
const decoy = new Decoy({ db });
const getTargetFor = (req) => {
  if (!decoy.target || !decoy.students.size) return null;
  const who = withAlias(identity.resolve(req));
  return decoy.targetFor(who.name);
};
function decoySet(name, on, by) {
  if (on) {
    if (!decoy.target) throw new Error('pick a decoy app first (CTFs tab)');
    decoy.add(name, by);
    store.emitAlert({ type: 'decoy', level: 'info', student: name, msg: `${name} is now routed to the decoy app (${decoy.target})${by ? ` by ${by}` : ''}` });
  } else {
    decoy.remove(name);
    store.emitAlert({ type: 'decoy', level: 'info', student: name, msg: `${name} is back on the real CTF` });
  }
}
store.isDecoy = (name) => decoy.has(name);
admin.onRenamed = (from, to) => decoy.rename(from, to); // a renamed student stays on the decoy
```

- `getTargetFor` is called by the proxy for **every** request; the first line makes it free when the decoy is unused. Otherwise it resolves the identity (a third `identity.resolve` per request, after `preRequest` and before `onEvent`'s two) and asks the decoy list by display name. The student keeps the same link and cookies; only the upstream changes.
- `decoySet` is the dashboard's entry point; refusing to add without a decoy target avoids a list that does nothing.

`studentLink()` (279-298) finds the public zrok URL for the CTFs tab: first `logs/zrok.url` (written by `start.sh`), else the last 64 KiB of `logs/zrok.log` searched for a `*.zrok.io` host; otherwise a hint with the manual command. Any filesystem error yields the hint.

### Lifecycle (lines 301-326)

```js
// lines 301-326
function resetLive() {
  store.reset();
  detector.students.clear();
  detector.learned.clear();
  playerCache.clear();
  gate.ipNames.clear();
}
function newCtf(name) {
  replay.stop();
  db.endCtf(db.ctfId);
  const c = db.openCtf(name || undefined);
  resetLive();
  log('info', `switched to CTF #${c.id} "${c.name}"`);
  return c;
}
function stopCtf() {
  replay.stop();
  const ended = db.activeCtf();
  setTarget(null, { label: 'CTF stopped' });
  db.endCtf(db.ctfId);
  resetLive();
  if (ended) log('info', `CTF #${ended.id} "${ended.name}" stopped`);
  return ended;
}
```

- `resetLive` wipes everything that is per-CTF and in memory: the store (which fires `onReset` → the dashboard pushes a fresh `snapshot`), detector per-student state and learned ownership, the player cache, and the gate's IP→name memory. Persistent things (block list, aliases, queue, decoy list, gate profiles) survive on purpose.
- `newCtf`: stop any replay, close the current record (flushes pending writes), open a new one (`undefined` name → `ctf-<date>`), reset. The target is kept, so students continue seamlessly into the new record.
- `stopCtf`: additionally disconnects the target *before* ending the record so the "Proxy disconnected" alert is stored in the record being closed. Afterwards `db.ctfId` is `null`: `db.addRequest` drops events (live view only) until a target is picked again (which opens a record automatically, see `POST /api/targets`) or "New CTF" is pressed. Returns the ended record (or `null` if none was active).

### Start-up of the servers and shutdown (lines 328-343)

```js
// lines 328-329
createProxy({ getTarget, getTargetFor, bind: PROXY_BIND, port: PROXY_PORT, shouldIgnore, onEvent, gate, preRequest });
createDashboard({ port: DASHBOARD_PORT, bind: DASHBOARD_BIND, store, admin, auth, db, replay, playground, gate, setGateConfig, approvals, queueDecide, decoy, decoySet, newCtf, stopCtf, getTarget, setTarget, discoverTargets, studentLink, proxyPort: PROXY_PORT, getRawConfig: () => config.raw });
```

- Both servers are created **last**, after every callback they receive exists. `getRawConfig` exposes the uncompiled `rules.json` for the dashboard's config view.

```js
// lines 333-343
function shutdown() {
  log('info', 'shutting down');
  try {
    playground.stopAll();
    db.close();
  } catch {}
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('uncaughtException', (err) => log('error', `uncaught: ${err.stack || err}`));
```

- `docker stop` sends `SIGTERM`: child processes are signalled and `db.close()` flushes the pending batch, then the process exits. Servers are not closed explicitly; `process.exit` drops the sockets.
- `uncaughtException` only logs: the monitor prefers to keep running during an event (a crash would cut every student off) at the cost of possibly inconsistent in-memory state. Promise rejections are not handled here; Node's default for unhandled rejections (crash since v15) still applies, which is why async code elsewhere attaches `.catch`.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | environment / `.env` via compose | The variables in the table above. |
| in | `proxy.js` → `preRequest(req, res)` | Per-request block check; returns `true` when answered. |
| in | `proxy.js` → `onEvent(x)` | Raw exchange → pipeline → `store.add`. |
| in | `proxy.js` → `getTarget()`, `getTargetFor(req)`, `shouldIgnore(path)` | Upstream selection and ignore rules. |
| in | `dashboard.js` → callbacks | `setGateConfig`, `queueDecide`, `decoySet`, `newCtf`, `stopCtf`, `setTarget`, `discoverTargets`, `studentLink`, `getRawConfig`. |
| in | `namegate.js` → `onProfile`, `onEnqueue`, `onIpNamed` | Gate answers, queue arrivals, IP↔name association. |
| in | `identity.js` → `onSessionNamed` | Session cookie identified → `mergeLane`. |
| in | `auth.js` → `onConflict` | Login conflict → critical alert + proxy IP block. |
| in | `admin.js` → `onRenamed` | Keeps the decoy list in sync with renames. |
| out | `db.js` | kv keys `gate_config`, `gate_profiles`, `proxy_target`; `openCtf/endCtf/activeCtf`; `playerFor`; `stmts.upsertIdentity`; `close`. |
| out | `store.js` | `add`, `emitAlert`, `reset`, `renameStudent`, `students`, `studentsByIp`; hooks `isBlocked`, `renamePending`, `queueStatus`, `isDecoy`. |
| out | `detector`, `identity`, `admin`, `decoy`, `replay`, `playground`, `approvals`, `gate` | Method calls listed in the walkthrough. |
| out | filesystem | `logs/credentials.txt`, reads `logs/zrok.url` / `zrok.log`. |

## Changing it safely

| Likely change | Where |
|---|---|
| New environment variable | Add an `env('NAME', default)` constant near lines 28-38 and pass it to the consumer; document it in `.env.example` and `docker-compose.yml`. Remember empty strings count as unset. |
| Add a field to stored events | Build it in the `ev` literal (221-229). Then: `db.js` schema + `insertReq` if it must be queryable, `store.js` if it affects stats/alerts, `app.html` to display it. Replayed events (`replay.js`) will not have it unless you add it there too. |
| Change how identities map to players | `playerIdFor` (143-168), especially the identity order and the gate-field regex at line 151. `db.test.js` → `player mapping links identities across CTFs` covers `db.playerFor` but not this function. |
| Change what happens on Stop / New CTF | `resetLive`, `newCtf`, `stopCtf` (301-326). Everything cleared in `resetLive` must be per-CTF; anything persistent must be left alone. |
| Add a new lifecycle hook to the dashboard | Define the function here, add it to the `createDashboard` call (329) and destructure it in `dashboard.js`. |

Tests: **`server.js` has no unit test and cannot be required without side effects** (it opens the db and listens on two ports). Its building blocks are covered: `core.test.js` (`identity: jwt, then session learned at login, then ip fallback`; `detector: ownership map, learning, idor attempt vs success, enumeration and bursts`; `detector: renaming a student carries state and learned ownership`; `masking hides secrets by field name, in URLs and in free text`; `jwt and body parsing helpers`), `attacks.test.js` (classification feeding steps 9-10), `db.test.js`, `auth.test.js`, `queue.test.js`, `gate.test.js`, `decoy.test.js`. The pipeline order, `preRequest`, `playerIdFor`, `mergeLane`, target persistence, `studentLink` and the lifecycle functions are verified only by running the stack (Playground quick start is the fastest way).

## Exercises

1. **Trace one request through the pipeline.** Start the Playground quick start, then in `logs/events-<today>.jsonl` find a line with `"source":"login"` or `"source":"session"` and map each field back to the step that produced it (student/rawName/appName → step 6, `path` masking → step 11, `playerId` → `playerIdFor`). Command: `grep -m1 '"endpoint":"orders"' logs/events-*.jsonl | python -m json.tool` (or `jq .`).

2. **Prove the saved target beats `CTF_TARGET`.** Pick a target in the CTFs tab, stop the stack, set `CTF_TARGET=http://127.0.0.1:1` in `.env`, start again: the start-up log line (`target=…`, line 331) still shows the saved one. Press Stop CTF, restart: now `CTF_TARGET` is used (and `validateTarget` accepted port 1).

3. **Watch `mergeLane` happen.** Enable the gate (Gate tab), then from a shell: `curl -s http://127.0.0.1:8888/api/me -H 'X-Forwarded-For: 10.1.1.1'` (an `ip:10.1.1.1` row appears in Students), then submit the gate form from a browser that also sends `X-Forwarded-For: 10.1.1.1` (e.g. through a local proxy) or simply use the simulator's `anonymous` persona. The monitor log prints `merged row ip:10.1.1.1 into <name>` and the Students view shows a single row.

## Quick reference

`server.js` exports nothing. Internal functions by role:

| Function | Signature | Description |
|---|---|---|
| `env` / `flag` | `(key, default) → string` / `(key) → bool` | Env reading; empty string = unset. `flag` is unused. |
| `queueDecide` | `(names: string[], status: 'approved' \| 'blocked' \| 'pending', by) → changedRawNames[]` | Queue decision + proxy-level block/unblock. |
| `setGateConfig` | `(raw) → normalizedConfig` | Persist and apply gate config. |
| `printCredentials` | `(list) → void` | Print accounts to stdout and `logs/credentials.txt`. |
| `withAlias` | `(who) → who'` | Apply organizer rename; adds `rawName`. |
| `mergeLane` | `(anonLabel, rawName) → void` | Fold an anonymous row into the named one. |
| `playerIdFor` | `(who, ip, ts) → playerId \| null` | Cross-CTF player id with per-row cache. |
| `preRequest` | `(req, res) → bool` | 403 for blocked students; records the attempt. |
| `onEvent` | `(exchange) → void` | The 12-step pipeline ending in `store.add`. |
| `shouldIgnore` | `(pathOnly) → bool` | `ignore.pathPatterns` from `rules.json`. |
| `setTarget` / `getTarget` | `(url \| null, { label? }) → url \| null` / `() → url \| null` | Proxy target, persisted in kv `proxy_target`. |
| `discoverTargets` | `() → Promise<candidate[]>` | Discovery excluding the monitor's own ports. |
| `getTargetFor` | `(req) → decoyUrl \| null` | Per-request decoy routing. |
| `decoySet` | `(name, on, by) → void` | Add/remove a student on the decoy, with alert; throws without a decoy target. |
| `studentLink` | `() → { url, source, since } \| { url: null, source: null, hint }` | Public zrok link. |
| `resetLive` / `newCtf` / `stopCtf` | `() → void` / `(name?) → ctf` / `() → ctf \| null` | CTF lifecycle. |
| `shutdown` | `() → never` | Stop children, close db, exit 0. |

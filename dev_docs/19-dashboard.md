# Dashboard — `proxy/src/dashboard.js`

## Purpose

`dashboard.js` is the HTTP server the organizer uses: it serves the login page and the single-page app, exposes the JSON API behind a session cookie, enforces the admin/user role split and a CSRF header on every state-changing call, and pushes live updates (events, alerts, stats, queue, decoy) over an authenticated WebSocket. It does not own any state: every route delegates to `store`, `db`, `admin`, `auth`, `replay`, `playground`, `gate`, `approvals`, `decoy` or callbacks from `server.js`.

## Where it sits

| Who calls it | How |
|---|---|
| `proxy/src/server.js` (line 329) | `createDashboard({ port, bind, store, admin, auth, db, replay, playground, gate, setGateConfig, approvals, queueDecide, decoy, decoySet, newCtf, stopCtf, getTarget, setTarget, discoverTargets, studentLink, proxyPort, getRawConfig })`. |
| Browser (`proxy/public/app.html`, `login.html`) | Fetches the routes below with `X-Requested-With: ctf-watch`; opens `ws://…/ws`. |

| What it requires / calls | Why |
|---|---|
| `http`, `fs`, `path` | Server, static files. |
| `ws` → `WebSocketServer` | The only npm dependency of the project. |
| `./query` → `compile`, `QueryError` | The query language for the Query tab; `query.js` is also served to the browser. |
| `./namegate` → `NameGate.clean`, `normalizeConfig`, `TYPES`, `GATE_PATH` | Name cleaning, gate preview, gate config metadata. |
| `./ports` → `validateTarget` | Target/decoy URL validation. |
| `./util` → `log`, `clientIp` | Logging; client IP for block list and login. |

## Data it owns

| Name | Lines | Shape / meaning |
|---|---|---|
| `PUBLIC_DIR` | 13 | `proxy/public`, holds `app.html` and `login.html`. |
| `PAGES` | 14 | Paths that serve the SPA: `/`, `/live`, `/alerts`, `/students`, `/query`, `/requests`, `/admin`, `/ctfs`, `/playground`, `/gate`, `/queue` (plus any `/students/…`). The path only picks the initial view; routing is client-side. |
| `CSRF_HEADER` | 15 | `'x-requested-with'`; POSTs to `/api/*` must carry the value `ctf-watch`. |
| `SECURITY_HEADERS` | 38-44 | CSP (`default-src 'self'`, inline scripts/styles allowed, `connect-src 'self' ws: wss:`, no framing), `nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`. Added to every JSON, page and redirect response (not to `/healthz`). |
| `user` (per request) | 99 | `{ id, username, role }` from `auth.sessionFromRequest`. |
| `wss` | 387 | `WebSocketServer({ noServer: true, maxPayload: 1024 })`; clients are not expected to send anything. |
| broadcast messages | 402-417 | See "WebSocket" below. |

## Walkthrough

### Body helpers (lines 17-36)

```js
// lines 17-36
function readBody(req, limit) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > limit) {
        reject(new Error('body too large'));
        req.destroy();
      } else chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
async function readJson(req, limit = 64 * 1024) {
  const buf = await readBody(req, limit);
  if (!buf.length) return {};
  return JSON.parse(buf.toString('utf8'));
}
```

- Bodies above `limit` reject **and** destroy the socket, so a 1 GB upload to `/api/query` is cut off after 64 KiB. Three limits are used: 4 KiB for login (line 88), 64 KiB default, 200 MiB for import (line 258).
- An empty body is `{}` so routes can read `body.x` without checks. Invalid JSON throws; most routes turn that into `{}` via `.catch(() => ({}))`, the admin and gate routes use `.catch(() => null)` and answer `400 bad json`.

### Response helpers and `scopeCtf` (lines 46-67)

```js
// lines 46-53
function createDashboard({ port, bind, store, admin, auth, db, replay, playground, gate, setGateConfig, approvals, queueDecide, decoy, decoySet, newCtf, stopCtf, getTarget, setTarget, discoverTargets, studentLink, proxyPort, getRawConfig }) {
  bind = bind || '127.0.0.1';
  // while the live view shows a replayed CTF, history views (alerts, student detail, query) read that CTF
  const scopeCtf = (explicit) => (explicit ? Number(explicit) : store.replayCtfId || db.ctfId || undefined);
  const json = (res, status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
    res.end(JSON.stringify(obj));
  };
```

- `scopeCtf` decides which CTF record history reads use. Priority: an explicit `?ctf=` / `body.ctf` → the CTF currently being **replayed** (`store.replayCtfId`, set by `Replay.start` and cleared by `store.reset`) → the active CTF (`db.ctfId`) → `undefined` (no CTF open, e.g. after "Stop CTF"). This is what makes the Alerts, Student and Query views follow a replay automatically.
- `page` (54-63) reads the HTML file on every request (no caching; `Cache-Control: no-store` anyway) and answers 500 with `<file> missing` if absent. `redirect` (64-67) is a 302 with the security headers.

### `handle`: pre-auth section (lines 69-96)

```js
// lines 69-81
async function handle(req, res) {
  const ip = clientIp(req);
  const url = (req.url || '/').split('?')[0];
  const qs = new URL(req.url || '/', 'http://x').searchParams;

  if (url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'text/plain' });
    return res.end('ok');
  }
  if (auth.isIpBlocked(ip)) {
    res.writeHead(403, { 'Content-Type': 'text/plain', ...SECURITY_HEADERS });
    return res.end('blocked');
  }
```

- `/healthz` is answered before the block check (the Docker healthcheck in `docker-compose.yml` uses it, and it must work even if, say, loopback were ever blocked — which `auth.blockIp` prevents anyway).
- A blocked IP gets `403 blocked` for **every** other URL, including `/login`. The only way back is the Admin tab from another IP (`POST /api/admin/unblock-ip`).
- `qs` is parsed with a dummy base so relative URLs parse.

```js
// lines 84-96
if (url === '/login' && req.method === 'GET') return page(res, 'login.html');
if (url === '/api/login' && req.method === 'POST') {
  let body;
  try {
    body = await readJson(req, 4096);
  } catch {
    return json(res, 400, { error: 'bad request' });
  }
  const r = auth.login(body.username, body.password, ip);
  if (!r.ok) return json(res, r.status, { error: r.error });
  res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': auth.cookieFor(r.token, req.headers['x-forwarded-proto'] === 'https'), ...SECURITY_HEADERS });
  return res.end(JSON.stringify({ ok: true, account: r.account }));
}
```

- Login does **not** require the CSRF header (there is no session yet; `SameSite=Strict` on the cookie plus the JSON content type is the protection). The status code comes straight from `auth.login` (401/403/409/429).
- The `Secure` cookie flag is set only when a TLS terminator in front announces `X-Forwarded-Proto: https`.

### Session, role and CSRF gate (lines 98-110)

```js
// lines 99-110
const user = auth.sessionFromRequest(req);
if (!user) {
  if (url.startsWith('/api/')) return json(res, 401, { error: 'login required' });
  return redirect(res, '/login');
}
const isAdmin = user.role === 'admin';
const adminOnly = () => {
  if (isAdmin) return false;
  json(res, 403, { error: 'admin only' });
  return true;
};
if (req.method === 'POST' && url.startsWith('/api/') && req.headers[CSRF_HEADER] !== 'ctf-watch') return json(res, 403, { error: 'missing X-Requested-With header' });
```

- Everything below this point has a logged-in `user`. API callers get 401 JSON; page requests are redirected to `/login`.
- `adminOnly()` is the idiom used by every mutating route: it writes the 403 itself and returns `true`, so the caller does `if (adminOnly()) return;`. Routes without that line are available to the `user` role too (see the table).
- CSRF: a browser cannot add a custom header in a cross-site form post or a plain navigation, so requiring `X-Requested-With: ctf-watch` on every API POST blocks CSRF even if the cookie were sent. Note the check is by method **and** prefix: a POST to a route that does not check its method (e.g. `/api/me`) still needs the header.

### Pages and `query.js` (lines 112-125)

- Any path in `PAGES` or under `/students/` serves `app.html`; the app reads `location.pathname` to open the right tab.
- `GET /query.js` serves `proxy/src/query.js` itself (the parser is shared between server and browser for live linting and autocomplete) with `Cache-Control: no-cache` overriding the `no-store` default so the browser may revalidate it.

### Route by route (lines 127-376)

The table in "Quick reference" lists every route; here are the points that are not obvious from the code:

- **`/api/me`** (134): returns the account plus `ctf` (active record), `replay.status()` and `target` so the app can render its header in one call. Any method.
- **`GET /api/targets`** (137): runs discovery (`await discoverTargets()`, about 1.5 s worst case) on every call; the CTFs tab calls it on demand. Available to the `user` role.
- **`POST /api/targets`** (139-152): validates first (`validateTarget` throws → 400) so nothing is touched on bad input. If a URL is given and either `newCtf` was requested or there is no active CTF (after "Stop CTF"), a new CTF record is opened **before** `setTarget`, so the "Proxy now points at …" info alert lands in the new record. `url: null`/missing disconnects (students get the 503 page).
- **`GET /api/alerts`** (160-167): `level`, `ack` (0/1), `ctf`, `limit` (max 5000 enforced in `db.alerts`). `db.flush()` first so alerts raised milliseconds ago are included (the db batches writes). `safeJson` (424-431) parses the stored `data` column. Returns `[]` when no CTF is in scope.
- **`POST /api/alerts/ack`** (168-176): **not** admin-only — any logged-in user can acknowledge. Marks the ids in the db and in the in-memory ring; `all: true` additionally runs a raw `UPDATE … WHERE ctf_id = db.ctfId` (active CTF only, not the replayed one).
- **`/api/students/:name`** (180-185): `decodeURIComponent` of the name; combines `db.studentDetail` (history in the scoped CTF; `|| 0` falls through to `db.ctfId` inside `db.js`) with the live row plus `blocked`/`renamePending` flags.
- **`GET /api/admin`** (188): `admin.list()` plus the dashboard IP block list from `auth.blockedIps`.
- **`POST /api/admin/*`** (189-205): one `switch`; errors thrown by `admin.*` (e.g. invalid new name) become 400. `unblock-ip` clears both the dashboard block (`auth.unblockIp`) and the proxy-level `ip:<ip>` entry that `server.js`'s `onConflict` wrote.
- **`/api/query/values`** (220-230): autocomplete. The column name is interpolated into SQL, which is safe only because it comes from the `COLS` whitelist (`qs.get('field')` is a key lookup, never used directly). Top 60 values by frequency, scoped by `scopeCtf`.
- **`POST /api/query`** (233-242): `compile()` turns the query language into parameterised SQL; `db.runSql` caps the limit at 20000. A `QueryError` carries `pos`/`len` so the editor can underline the problem; other errors are 500.
- **`/api/export`** (245-254): any method, any role; `Content-Disposition` builds a safe file name from the CTF name.
- **`POST /api/import`** (255-263): admin; body limit 200 MiB; `db.importCtf` validates the format.
- **`/api/gate/preview`** (272-285): renders the exact gate page students see. To preview an unsaved config it temporarily swaps `gate.getConfig` and restores it right after `gate.page(...)` — safe because `page()` is synchronous and Node is single-threaded, so no student request can observe the swapped getter. The response overrides two security headers (`X-Frame-Options: SAMEORIGIN`, a CSP with `frame-ancestors 'self'`) so the Gate tab's iframe may show it, and disables the form with `onsubmit="return false"`.
- **`POST /api/decoy*`** (289-306): `/api/decoy` sets/clears the decoy app URL (validated); `/add` and `/remove` accept `names: []` or a single `student` and call `decoySet` from `server.js` (which throws "pick a decoy app first" → 400 when no decoy target is set).
- **`POST /api/queue/*`** (310-330): `approve`/`block`/`reset` go through `queueDecide` (`server.js`), which also applies the proxy-level block; `approve` with `decoy: true` additionally routes each approved student (by display alias) to the decoy. `remove` deletes queue entries.
- **`POST /api/playground/*`** (334-358): `mock` and `sim` start or stop depending on `action === 'stop'`; `quick` is the one-click demo: start the mock if needed, wait 600 ms for it to bind, open a fresh CTF record named `ctfName` or `playground`, point the proxy at the mock, start the simulator. `stop-all` stops both.
- **`/api/replay`** (360-374): `replay.start(ctf, speed)` throws when the CTF has no requests → 400.
- Unmatched URLs → `404 { error: 'not found' }` (line 376).

### Server wrapper (lines 379-384)

```js
// lines 379-384
const server = http.createServer((req, res) => {
  handle(req, res).catch((err) => {
    log('error', `dashboard: ${err.stack || err}`);
    if (!res.headersSent) json(res, 500, { error: 'internal error' });
  });
});
```

- `handle` is `async`; any uncaught exception inside a route (including `readJson` limits where not caught locally) ends here as a 500 instead of crashing the process or hanging the request.

### WebSocket: upgrade auth and broadcasts (lines 386-418)

```js
// lines 387-395
const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 });
server.on('upgrade', (req, socket, head) => {
  const url = (req.url || '').split('?')[0];
  if (url !== '/ws' || auth.isIpBlocked(clientIp(req)) || !auth.sessionFromRequest(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
    return socket.destroy();
  }
  wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
});
```

- `noServer: true` so the session check runs **before** the WebSocket handshake. The browser sends the `ctfw_sid` cookie with the upgrade request (same origin), which is validated like any other request. Blocked IPs and anonymous clients get a raw 401 and a closed socket.
- `maxPayload: 1024`: any client frame above 1 KiB closes the connection; the server never acts on client messages anyway.

```js
// lines 396-418
const send = (ws, obj) => ws.readyState === ws.OPEN && ws.send(JSON.stringify(obj));
const broadcast = (obj) => {
  const data = JSON.stringify(obj);
  for (const ws of wss.clients) if (ws.readyState === ws.OPEN) ws.send(data);
};
wss.on('connection', (ws) => {
  send(ws, { type: 'snapshot', ...store.snapshot() });
  ws.on('error', () => {});
});
store.onEvent((ev, alert) => {
  if (!wss.clients.size) return;
  if (ev) {
    const { req, ...rest } = ev;
    broadcast({ type: 'event', event: rest });
  }
  if (alert) broadcast({ type: 'alert', alert });
});
store.onReset(() => wss.clients.size && broadcast({ type: 'snapshot', ...store.snapshot() }));
approvals.onChange(() => wss.clients.size && broadcast({ type: 'queue', counts: approvals.counts(), items: approvals.list() }));
decoy.onChange(() => wss.clients.size && broadcast({ type: 'decoy', ...decoy.list() }));
const statsTimer = setInterval(() => wss.clients.size && broadcast({ ... type: 'stats' ... }), 1000);
statsTimer.unref();
```

Message types and shapes (all JSON objects with a `type` field):

| `type` | When | Shape |
|---|---|---|
| `snapshot` | On connect; whenever the store resets (new CTF, stop, replay start, after a student rename). | `{ type, events: Event[] (last 500), alerts: Alert[] (last 150), stats: Stats }` — `store.snapshot()` spread. |
| `event` | Every stored request (live or replayed). | `{ type, event: Event }` where `Event` is the object `server.js` built in `onEvent` **minus `req`** (the `IncomingMessage` is stripped because it is not serialisable and would leak headers). |
| `alert` | Every new alert (from a request or `store.emitAlert`). | `{ type, alert: { n, ts, level, type, student, ip, msg, data?, endpoint?, objectId?, owner?, status?, ack, replay } }`. |
| `queue` | Any admission-queue change (arrival, decision, removal). | `{ type, counts: { pending, approved, blocked }, items: QueueItem[] }`. |
| `decoy` | Decoy target or list change. | `{ type, target: string \| null, students: [{ name, since, by, reason }] }`. |
| `stats` | Every second while at least one client is connected. | `{ type, stats: Stats, replay: ReplayStatus, target: string \| null, mock: { app: bool, sim: bool }, gate: bool (enabled), queue: counts \| null }`. |

- `store.onEvent` runs for every proxied request; the early `return` when nobody is connected avoids serialising events for no one. `ws.on('error', () => {})` prevents an unhandled error on a dropped client from crashing the process.
- The 1 s stats timer is `unref()`ed so it does not keep the process alive at shutdown; it is cheap when `wss.clients.size` is 0.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` | All collaborators and callbacks listed in "Where it sits". |
| in | browser | HTTP requests with the `ctfw_sid` cookie and `X-Requested-With: ctf-watch`; WebSocket upgrade on `/ws`. |
| out | `auth.js` | IP block check, login/logout, session lookup, cookies, `unblockIp`, `blockedIps`. |
| out | `store.js` | `snapshot()`, `stats()`, `students`, `alerts`, `isBlocked`, `renamePending`, `replayCtfId`; subscriptions `onEvent`, `onReset`. |
| out | `db.js` | `activeCtf`, `listCtfs`, `flush`, `alerts`, `ackAlerts`, `studentDetail`, `runSql`, `exportCtf`, `importCtf`, `ctfId`, raw `db.db.prepare` for ack-all and autocomplete. |
| out | `admin.js` | `list`, `block`, `unblock`, `rename`, `requireRename`, `alias`, `state.blocked`, `save`. |
| out | `replay.js` | `status`, `start`, `stop`. |
| out | `playground.js` | `status`, `startMock/stopMock`, `startSim/stopSim`, `stopAll`, `mockUrl`, `mock.running`, `sim.running`. |
| out | `namegate.js` | `gate.config`, `gate.enabled`, `gate.page`, `gate.getConfig` (swapped for preview), `NameGate.clean`, `normalizeConfig`, `TYPES`, `GATE_PATH`. |
| out | `approvals.js` | `counts`, `list`, `remove`, `onChange`. |
| out | `decoy.js` | `list`, `setTarget`, `onChange`. |
| out | `server.js` callbacks | `setGateConfig(body)`, `queueDecide(names, status, by)`, `decoySet(name, on, by)`, `newCtf(name)`, `stopCtf()`, `getTarget()`, `setTarget(url, { label })`, `discoverTargets()`, `studentLink()`, `getRawConfig()`. |
| out | `query.js` | `compile(q, { ctfId })`, `QueryError`; the file itself is served to the browser. |

## Changing it safely

| Likely change | Where |
|---|---|
| Add an API route | Insert an `if (url === '/api/…' && req.method === '…')` block in `handle` **after** line 110 (so it is behind session + CSRF) and before the 404 at line 376. Use `adminOnly()` for mutations, `readJson` for bodies, `json()` for answers. Add it to the route table below. |
| Add a new SPA tab path | `PAGES` (line 14); otherwise the path 404s on a hard reload. |
| Add a broadcast message | Subscribe near lines 405-417 and `broadcast({ type: '…', … })`; guard with `wss.clients.size`. Document the shape here and handle it in `app.html`. |
| Relax the CSP (e.g. a CDN script) | `SECURITY_HEADERS` (line 39). The preview route overrides CSP separately (line 283). |
| Make a route user-accessible / admin-only | Add or remove the `if (adminOnly()) return;` line in that route. |

Tests: **there is no unit test for `dashboard.js`.** Nothing in `proxy/test/` starts the HTTP server or the WebSocket. What is covered indirectly: `auth.test.js` (every login outcome the `/api/login` route maps to status codes), `query.test.js` (what `/api/query` compiles), `db.test.js` (`alerts, ack and student detail aggregation`, `export / import round trip…`), `queue.test.js` (`approvals: enqueue, decide, persist, counts`), `decoy.test.js`, `gate.test.js` (`page renders the configured fields…` for the preview route). Route wiring, role checks, CSRF, the WebSocket handshake and message shapes are verified only by running the stack and using the browser.

## Exercises

1. **See the three auth layers.** With the stack running:
   `curl -i http://127.0.0.1:8080/api/state` → `401 {"error":"login required"}`;
   `curl -i -b 'ctfw_sid=<token>' -X POST http://127.0.0.1:8080/api/ctfs/stop` → `403 missing X-Requested-With header`;
   repeat with `-H 'X-Requested-With: ctf-watch'` using a `user_1` session → `403 admin only`; with the admin session → `200`.

2. **Listen to the WebSocket from a script** (Node 22+ has a global `WebSocket`):
   `node -e "const ws=new WebSocket('ws://127.0.0.1:8080/ws',{headers:{cookie:'ctfw_sid=<token>'}});ws.onmessage=m=>console.log(JSON.parse(m.data).type)"`
   Expect `snapshot` first, then `stats` once per second; start the Playground simulator and watch `event`/`alert` arrive.

3. **Scope a history read to a replay.** Import or pick a past CTF, `POST /api/replay {"ctf":<id>,"speed":50}` as admin, then `GET /api/alerts` without `?ctf=`: the alerts returned belong to the replayed CTF (`scopeCtf` used `store.replayCtfId`). `POST /api/replay/stop` does not change that; `POST /api/ctfs/new` does (store reset clears `replayCtfId`).

## Quick reference — route table

Legend for "who": **any** = any logged-in account; **admin** = `adminOnly()`; **public** = no session needed. All `/api/*` POSTs (except `/api/login`) additionally require `X-Requested-With: ctf-watch`. Routes marked "any method" do not check `req.method`.

| Method | Path | Who | Input | Output |
|---|---|---|---|---|
| GET | `/healthz` | public (even blocked IPs) | — | `ok` (text) |
| GET | `/login` | public | — | `login.html` |
| POST | `/api/login` | public | JSON `{ username, password }` (≤ 4 KiB) | `200 { ok, account }` + `Set-Cookie ctfw_sid`; `400` bad JSON; `401/403/409/429` from `auth.login` |
| GET | `/`, `/live`, `/alerts`, `/students`, `/students/*`, `/query`, `/requests`, `/admin`, `/ctfs`, `/playground`, `/gate`, `/queue` | any (else 302 `/login`) | — | `app.html` |
| GET | `/query.js` | any | — | `src/query.js` source |
| POST | `/api/logout` | any | — | `{ ok: true }` + cookie cleared |
| any method | `/api/me` | any | — | `{ id, username, role, ctf, replay, target }` |
| GET | `/api/targets` | any | — | `{ current, link, proxyPort, candidates }` (runs discovery) |
| any method | `/api/link` | any | — | `{ url, source, since \| hint, proxyPort }` |
| POST | `/api/targets` | admin | `{ url?: string \| null, newCtf?: bool, ctfName?: string, label?: string }` | `{ ok, target, ctf }`; `400 { error }` |
| any method | `/api/state` | any | — | `store.snapshot()` |
| any method | `/api/stats` | any | — | `store.stats()` |
| any method | `/api/config` | any | — | raw `rules.json` object |
| GET | `/api/alerts` | any | `?level=&ack=0\|1&ctf=&limit=` | `Alert[]` (`data` parsed); `[]` when no CTF in scope |
| POST | `/api/alerts/ack` | any | `{ ids?: number[], all?: bool }` | `{ ok }` |
| any method | `/api/students` | any | — | `stats().students` |
| any method | `/api/students/:name` | any | `?ctf=` | `{ ...studentDetail, live: row \| null }` |
| GET | `/api/admin` | any | — | `{ blocked, aliases, renamePending, dashboardBlockedIps }` |
| POST | `/api/admin/block` | admin | `{ student }` | `{ ok, name, ip }` |
| POST | `/api/admin/unblock` | admin | `{ student }` | `{ ok }` |
| POST | `/api/admin/rename` | admin | `{ student, newName }` | `{ ok, name }`; `400` on bad name |
| POST | `/api/admin/require-rename` | admin | `{ student }` | `{ ok, name }`; `400` if gate off |
| POST | `/api/admin/unblock-ip` | admin | `{ ip }` | `{ ok }` |
| GET | `/api/ctfs` | any | — | `{ active, list }` |
| POST | `/api/ctfs/new` | admin | `{ name? }` | `{ ok, ctf }` |
| POST | `/api/ctfs/stop` | admin | — | `{ ok, ended: ctf \| null }` |
| any method | `/api/query/values` | any | `?field=student\|raw\|ip\|method\|endpoint\|owner\|source\|severity\|status\|ua\|id&ctf=` | `{ values: [{ v, n }] }` (≤ 60) |
| POST | `/api/query` | any | `{ q, ctf?, limit? }` | `{ ok, rows, count, sql, params }`; `400 { error, pos, len }` on `QueryError`; `500` otherwise |
| any method | `/api/export` | any | `?ctf=` (default active) | JSON attachment `ctf-<id>-<name>.json`; `400` if no such CTF |
| POST | `/api/import` | admin | export JSON (≤ 200 MiB) | `{ ok, ctf }`; `400` |
| GET | `/api/gate` | any | — | `{ config, types, path }` |
| POST | `/api/gate` | admin | gate config object | `{ ok, config }`; `400 bad json` |
| any method | `/api/gate/preview` | any | `?config=<json>&error=<text>` | HTML page (framable by the dashboard) |
| GET | `/api/decoy` | any | — | `{ target, students }` |
| POST | `/api/decoy` | admin | `{ url: string \| null }` | `{ ok, target, students }` |
| POST | `/api/decoy/add` / `/api/decoy/remove` | admin | `{ names?: string[], student?: string }` | `{ ok, target, students }`; `400` |
| GET | `/api/queue` | any | — | `{ enabled, fields, counts, items }` |
| POST | `/api/queue/approve` | admin | `{ names?: string[], name?: string, decoy?: bool }` | `{ ok, changed }` |
| POST | `/api/queue/block` / `/reset` | admin | `{ names?, name? }` | `{ ok, changed }` |
| POST | `/api/queue/remove` | admin | `{ names?, name? }` | `{ ok, removed: number }` |
| GET | `/api/playground` | any | — | `playground.status()` |
| POST | `/api/playground/mock` | admin | `{ action?: 'stop', port? }` | `{ ok, ...status }` |
| POST | `/api/playground/sim` | admin | `{ action?: 'stop', config? }` | `{ ok, ...status }` |
| POST | `/api/playground/quick` | admin | `{ port?, ctfName?, config? }` | `{ ok, ...status, target }` |
| POST | `/api/playground/stop-all` | admin | — | `{ ok, ...status }` |
| GET | `/api/replay` | any | — | `replay.status()` |
| POST | `/api/replay` | admin | `{ ctf, speed? }` | `{ ok, ...status }`; `400` |
| POST | `/api/replay/stop` | admin | — | `{ ok }` |
| WS | `/ws` | any (cookie checked on upgrade) | — | messages `snapshot`, `event`, `alert`, `queue`, `decoy`, `stats` |
| * | anything else | any | — | `404 { error: 'not found' }` |

Exported function: `createDashboard(opts) → http.Server`.

## Update: issue 10 fixed (https)

`createDashboard` takes `tls: { cert, key }` (PEM paths from `TLS_CERT` / `TLS_KEY`). When both files load, the server is `https.createServer` and the login cookie is issued with `Secure`; otherwise plain http as before, with an error logged if the files were set but unreadable. The WebSocket client already picks `wss` on an https page.

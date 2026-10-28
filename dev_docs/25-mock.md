# Playground scripts — `proxy/mock/mock-ctf.js`, `proxy/mock/simulate.js`, `proxy/mock/loadtest.js`

## Purpose

The monitor is only interesting when there is traffic to watch. These three standalone Node scripts supply it without a real CTF:

| Script | Role | Started by |
|---|---|---|
| `mock-ctf.js` | A fake "shop" CTF app with deliberate IDOR bugs. Stands in for the real challenge. | Playground tab (`playground.js startMock`, env `PORT`, `HOST=127.0.0.1`) or by hand |
| `simulate.js` | Nine fake students with distinct personas sending traffic **through the proxy**, so every detector has something to fire on. | Playground tab (`startSim`, env `TARGET`, `SIM_CONFIG`) or by hand |
| `loadtest.js` | A throughput/latency hammer for the proxy. | By hand only |

They are copied into the image (`COPY mock ./mock` in the Dockerfile) and spawned by `proxy/src/playground.js` with `spawn(process.execPath, [script], { env })`. They have no dependencies beyond Node's `http`, `crypto` and `url`.

## Walkthrough

### `proxy/mock/mock-ctf.js`

#### Seed data (lines 1–28)

```js
// proxy/mock/mock-ctf.js lines 8-28
const PORT = Number(process.env.PORT || 3999);
const HOST = process.env.HOST || '127.0.0.1';

const USERS = ['alice', 'bob', 'carol', 'dave', 'eve', 'frank', 'grace', 'heidi', 'mallory'].map((username, i) => ({
  id: 1001 + i,
  username,
  password: 'password',
  email: `${username}@example.edu`,
  secret: `FLAG{idor_profile_${1001 + i}}`,
}));
const ORDERS = {};
USERS.forEach((u, i) => {
  for (let k = 0; k < 2; k++) {
    const id = 1041 + i * 2 + k;
    ORDERS[id] = { id, owner: u.id, item: ['laptop', 'keyboard', 'monitor', 'headset'][(i + k) % 4], total: 100 + id, flag: `FLAG{idor_order_${id}}` };
  }
});
const INVOICES = {};
Object.values(ORDERS).forEach((o) => (INVOICES[o.id + 6000] = { id: o.id + 6000, order: o.id, owner: o.owner, pdf: `invoice-${o.id}.pdf` }));
const MESSAGES = {};
for (let i = 500; i < 540; i++) MESSAGES[i] = { id: i, owner: USERS[i % USERS.length].id, text: `private message #${i}` };
```

The header comment (line 2) still mentions `./start.sh --demo`; that flag is gone, the Playground tab replaced it. `PORT`/`HOST` come from the environment: `playground.js` passes the port chosen in the dashboard (default 3999) and always `127.0.0.1`.

All data is in memory and deterministic, so the simulator can compute IDs instead of discovering them:

| Collection | IDs | Owner rule |
|---|---|---|
| `USERS` | 1001–1009 in the listed order (alice=1001 … mallory=1009); password is always `password`; each has a `secret` flag | — |
| `ORDERS` | two per user: `1041 + i*2 + k` → 1041–1058 (alice 1041/1042, bob 1043/1044, …) | `owner` = user id; `item` rotates through four names; `total = 100 + id` |
| `INVOICES` | `order id + 6000` → 7041–7058 | same owner as the order |
| `MESSAGES` | 500–539 | owner = `USERS[i % 9]`, so message 500 belongs to alice, 501 to bob, … 509 to alice again |

`sessions` (line 30) maps a random session id to a user object; nothing persists across restarts.

#### Helpers (lines 32–63)

```js
// proxy/mock/mock-ctf.js lines 32-44
function send(res, status, body, headers = {}) {
  const data = typeof body === 'string' ? body : JSON.stringify(body);
  res.writeHead(status, { 'Content-Type': typeof body === 'string' ? 'text/html; charset=utf-8' : 'application/json', 'Content-Length': Buffer.byteLength(data), ...headers });
  res.end(data);
}
function cookies(req) {
  const o = {};
  for (const p of (req.headers.cookie || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0) o[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  }
  return o;
}
```

- `send`: a string body is HTML, anything else is serialized as JSON. `Content-Length` uses `Buffer.byteLength` (bytes, not characters) so the proxy sees a correct length even for non-ASCII. Extra headers (`Set-Cookie`, `Location`, a different `Content-Type`) are spread last so they override.
- `cookies`: splits the header at `;`, then each pair at the **first** `=`. The result is used only for `.session`.
- `readBody` (lines 45–61) buffers the request, parses JSON when the content type contains `json`, otherwise treats it as a URL-encoded form; any parse error resolves to `{}` rather than rejecting, so a malformed login body just fails authentication.
- `PAGE` (line 63) wraps a title and body in a minimal HTML document that references `/static/style.css` and `/static/app.js`. Those two static requests are what a browser would make, and `rules.json` `ignore.pathPatterns` drops `.css`/`.js` from the dashboard, which the simulator exercises.

#### Request handling (lines 65–119)

```js
// proxy/mock/mock-ctf.js lines 66-92
  .createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const sid = cookies(req).session;
    const user = sid && sessions.get(sid);

    if (p === '/' && req.method === 'GET') return send(res, 200, PAGE('Shop CTF (demo)', '<form method="post" action="/login">...</form>'));
    if (p === '/static/style.css') return send(res, 200, 'body{font-family:sans-serif}', { 'Content-Type': 'text/css' });
    if (p === '/static/app.js') return send(res, 200, 'console.log("demo")', { 'Content-Type': 'application/javascript' });
    if (p === '/health') return send(res, 200, { ok: true });

    if (p === '/login' && req.method === 'POST') {
      const b = await readBody(req);
      const u = USERS.find((x) => x.username === b.username && x.password === b.password);
      if (!u) return send(res, 401, { error: 'bad credentials' });
      const s = crypto.randomBytes(16).toString('hex');
      sessions.set(s, u);
      const cookie = `session=${s}; Path=/; HttpOnly`;
      if ((req.headers.accept || '').includes('text/html')) return send(res, 302, '', { Location: '/dashboard', 'Set-Cookie': cookie });
      return send(res, 200, { id: u.id, username: u.username }, { 'Set-Cookie': cookie });
    }
    if (p === '/logout') {
      if (sid) sessions.delete(sid);
      return send(res, 302, '', { Location: '/', 'Set-Cookie': 'session=; Max-Age=0; Path=/' });
    }

    if (!user) return send(res, 401, { error: 'login required' });
```

- `new URL(req.url, 'http://x')`: `req.url` is only a path; a dummy base makes the WHATWG parser accept it and gives `pathname` and `searchParams`.
- Public routes: the login page, two static files, and `/health` (the simulator polls this through the proxy to know when the stack is up; `rules.json` ignores `^/health$`).
- `/login`: credentials are compared in plain text (it is a fake app). The session id is 16 random bytes as hex; the cookie name `session` is one of the `identity.sessionCookies` in `rules.json`, and the JSON response `{ id, username }` matches `identity.login.responseIdFields` / `responseNameFields`, so the monitor learns "this cookie = alice (1001)" from the login response. A browser (`Accept: text/html`) gets a redirect instead; the simulator sends `Accept: application/json` to get the JSON.
- Everything below line 92 requires a valid session; otherwise `401 {"error":"login required"}`. This is why the anonymous persona's requests all show as 401 on the dashboard.

```js
// proxy/mock/mock-ctf.js lines 94-117
    if (p === '/dashboard') return send(res, 200, PAGE(`Hello ${user.username}`, `<a href="/api/users/${user.id}">my profile</a> · <a href="/api/orders/${Object.values(ORDERS).find((o) => o.owner === user.id).id}">my order</a>`));
    if (p === '/api/me') return send(res, 200, { id: user.id, username: user.username, email: user.email });

    let m;
    if ((m = p.match(/^\/api\/users\/(\d+)$/))) {
      // IDOR: no ownership check
      const t = USERS.find((x) => x.id === Number(m[1]));
      return t ? send(res, 200, { id: t.id, username: t.username, email: t.email, secret: t.secret }) : send(res, 404, { error: 'no such user' });
    }
    if ((m = p.match(/^\/api\/orders\/(\d+)$/))) {
      const o = ORDERS[m[1]];
      return o ? send(res, 200, o) : send(res, 404, { error: 'no such order' }); // IDOR
    }
    if (p === '/api/invoice') {
      const inv = INVOICES[url.searchParams.get('id')];
      return inv ? send(res, 200, inv) : send(res, 404, { error: 'no such invoice' }); // IDOR
    }
    if ((m = p.match(/^\/api\/messages\/(\d+)$/))) {
      const msg = MESSAGES[m[1]];
      if (!msg) return send(res, 404, { error: 'no such message' });
      if (msg.owner !== user.id && Number(m[1]) % 3 === 0) return send(res, 403, { error: 'forbidden' }); // partially fixed
      return send(res, 200, msg);
    }
    send(res, 404, { error: 'not found' });
```

The deliberate bugs, and what each one exercises in the monitor:

| Route | Bug | What the dashboard should show |
|---|---|---|
| `GET /api/users/:id` | Any logged-in user can read any profile **including the `secret` flag**. | `rules.json` endpoint "user profile" with `owner: auto`: reading a profile whose id ≠ your own user id is an `idor-attempt`; a 200 with data is `idor-success`. |
| `GET /api/orders/:id` | No ownership check. | Endpoint "orders": ownership is learned from the first quiet success (alice reads 1041 → hers); later readers trigger attempt/success. |
| `GET /api/invoice?id=` | ID from the query string, no check. | Endpoint "invoice" with `idFrom: query:id`, same logic. |
| `GET /api/messages/:id` | "Partially fixed": a foreign message is refused with 403 **only when its id is divisible by 3**; others leak. | A mix of 200 and 403 for the same endpoint, i.e. attempts that sometimes succeed, plus 404 noise from non-existent ids. |

Details worth knowing: `/api/me` returns `{ id, username, email }` which matches the `whoami` rule in `rules.json` (another way the monitor learns a student's own id). The `\d+` in the regexes means a path like `/api/users/1001'%20OR%20'1'='1` does not match any route and falls through to the final 404 — the attacker persona's SQL-injection probes therefore come back as 404 from the app, but are still classified by the proxy from the URL. `listen(PORT, HOST)` on line 119 logs the address.

### `proxy/mock/simulate.js`

#### Configuration (lines 1–20)

```js
// proxy/mock/simulate.js lines 10-20
const TARGET = new URL(process.env.TARGET || 'http://127.0.0.1:8888');
let CFG = { honest: 4, enumerator: true, sniper: true, noisy: true, anonymous: true, attacker: true, loop: process.argv.includes('--loop'), pace: 1, rounds: 0 };
try {
  CFG = { ...CFG, ...JSON.parse(process.env.SIM_CONFIG || '{}') };
} catch {}
const PACE = Math.max(0.1, Number(CFG.pace) || 1);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms * PACE));
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
let stopping = false;
process.on('SIGTERM', () => { stopping = true; console.log('[sim] stopping'); setTimeout(() => process.exit(0), 300); });
process.on('SIGINT', () => process.exit(0));
```

- `TARGET` defaults to the proxy's default address; traffic must go through the proxy, not to the mock directly, or nothing is recorded.
- **`SIM_CONFIG`** is a JSON object merged over the defaults. Keys: `honest` (0–4, how many of the honest names to run), five persona booleans, `loop`, `pace`, `rounds`. Invalid JSON is ignored silently (defaults apply). `playground.js startSim()` clamps the values before passing them (`honest` 0–4, `pace` 0.1–10, `rounds` 0–1000) and builds the JSON itself, so the dashboard form cannot send unexpected keys.
- `PACE` multiplies every `sleep`; `0.5` halves all delays (twice as fast), `2` doubles them. The floor of 0.1 prevents a zero-delay busy loop.
- `rnd(a, b)` is an inclusive integer in `[a, b]`.
- `SIGTERM` (what `playground.js stop()` sends) sets `stopping`, which makes every further `req()` return immediately with `status: 0`, and exits 300 ms later so in-flight requests can finish. `SIGINT` (Ctrl-C when run by hand) exits at once.

#### The `Student` class (lines 22–88)

```js
// proxy/mock/simulate.js lines 29-46
  req(method, path, body, headers = {}) {
    if (stopping) return Promise.resolve({ status: 0, json: null });
    return new Promise((resolve) => {
      const data = body ? JSON.stringify(body) : null;
      const r = http.request(
        {
          host: TARGET.hostname,
          port: TARGET.port || 80,
          method,
          path,
          headers: {
            'User-Agent': `sim/${this.name}`,
            'X-Forwarded-For': this.ip,
            Accept: 'application/json',
            ...(this.cookie ? { Cookie: this.cookie } : {}),
            ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
            ...headers,
          },
        },
```

A `Student` has a `name`, a fake `ip`, a cookie jar (`cookie`) and, after login, its user `id`.

- Every request carries `User-Agent: sim/<name>` (visible on the student card) and **`X-Forwarded-For: <fake ip>`**. All simulated students really connect from localhost; the monitor's identity resolver prefers the first `X-Forwarded-For` address, which is how nine "different machines" appear on one laptop. The same header is how zrok conveys the real client IP in production.
- `Accept: application/json` makes the mock's `/login` answer with JSON (not a redirect), so `login()` can read `json.id`.
- Caller-supplied `headers` are spread last, so the attacker can override the User-Agent.
- Lines 48–62: the response body is collected, `Set-Cookie` headers are stored as `name=value` pairs (attributes after `;` dropped) for the next request, the body is parsed as JSON if possible, and the promise resolves with `{ status, json }`. A connection error resolves with `status: 0` — the simulator never rejects, so one failed request cannot abort a persona.

```js
// proxy/mock/simulate.js lines 67-87
  async login() {
    const r = await this.req('POST', '/login', { username: this.name, password: 'password' });
    if (r.json && r.json.id) this.id = r.json.id;
    return r;
  }
  async browseOwn(times = 3) {
    if (!this.id) return;
    await this.req('GET', '/api/me');
    for (let i = 0; i < times; i++) {
      await this.req('GET', `/api/users/${this.id}`);
      await sleep(rnd(300, 900));
      await this.req('GET', `/api/orders/${this.order(0)}`);
      await sleep(rnd(300, 900));
      await this.req('GET', `/api/orders/${this.order(1)}`);
      await this.req('GET', '/static/app.js');
      await sleep(rnd(500, 1500));
    }
  }
  order(k) {
    return 1041 + (this.id - 1001) * 2 + k;
  }
```

`order(k)` is the mock's order-id formula inverted, so a student knows its own two order ids without listing anything. `browseOwn` is the "legitimate activity" building block: whoami, own profile, own orders, one static file, with human-looking pauses. Its first quiet reads are what teach the detector who owns which order (`learnFromFirstSuccess`).

#### Personas (lines 90–169)

| Function | Name / IP (in `round`) | Behaviour | Detector it targets |
|---|---|---|---|
| `honest` | alice, bob, grace, heidi / `10.0.n.1`–`.4`, staggered by 3 s each | login, `browseOwn(4)`, own invoice (`order(0)+6000`), one message `500 + ((id-1001) % 8) + 8` (508–515), `browseOwn(2)` | Baseline. Establishes ownership of orders/invoices. Note the message read is not necessarily their own (message owner is `USERS[i % 9]`), so a mild attempt can appear. |
| `enumerator` | carol / `.3` | login, `browseOwn(1)`, **wait 8 s** so the honest students own their orders first, then `GET /api/orders/1040..1062` every 250–500 ms (1040 and 1059–1062 are 404), then invoices 7040–7050 | `enumeration` (5 distinct ids in 30 s by default), many `idor-attempt` + `idor-success`, some 404 noise. |
| `sniper` | dave / `.4` | login, browse, wait 12 s, then exactly alice's profile `1001`, alice's order `1041`, bob's profile `1002` | A quiet, targeted `idor-success` without enumeration — the case a rate-based detector would miss. |
| `noisy` | eve / `.5` | login, wait 5 s, 30 random message ids 900–9999 (404), then messages 500–529 (200 or 403 per the `% 3` rule) | `burst-errors` (15 error statuses in 20 s by default) and the partially-fixed endpoint. |
| `attacker` | mallory / `.9` | login, wait 6 s, seven injection probes with `User-Agent: sqlmap/1.8#stable`, then a NoSQL-style login body `{ username: { $ne: null }, ... }`, then `browseOwn(1)` | Attack classes: `sqli`, `xss`, `ssti`, `lfi`, `cmdi`, `ssrf`, `nosqli`, `scanner` (see `proxy/src/attacks.js` and its tests). |
| `anonymous` | frank / `.6` | never logs in; after 3 s, `GET /api/users/1..8` (all 401), then two `admin`/`admin`, `admin`/`123456` logins (401) | A student identified only by IP (`ip:10.0.n.6`), plus brute-force-looking 401s. |

```js
// proxy/mock/simulate.js lines 140-158
async function attacker(s) {
  await s.login();
  await sleep(6000);
  const probes = [
    ['GET', "/api/users/1001'%20OR%20'1'='1"],
    ['GET', '/api/orders/1041%20UNION%20SELECT%20username,password%20FROM%20users'],
    ['GET', '/dashboard?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E'],
    ['GET', '/api/invoice?id=../../../../etc/passwd'],
    ['GET', '/render?tpl={{7*7}}'],
    ['GET', '/api/ping?host=127.0.0.1;id'],
    ['GET', '/fetch?url=http://169.254.169.254/latest/meta-data/'],
  ];
  for (const [m, p] of probes) {
    await s.req(m, p, null, { 'User-Agent': 'sqlmap/1.8#stable (https://sqlmap.org)' });
    await sleep(rnd(400, 900));
  }
  await s.req('POST', '/login', { username: { $ne: null }, password: { $ne: null } });
  await s.browseOwn(1);
}
```

The probes are URL-encoded where a browser would encode them (`%20`, `%3C`), because Node's `http.request` rejects raw spaces in the path. The mock answers 404 to most of them; the classification happens in the proxy, on the request, regardless of the response.

#### Rounds and the main loop (lines 171–202)

```js
// proxy/mock/simulate.js lines 173-200
async function round(n) {
  console.log(`[sim] round ${n} -> ${TARGET.origin}`);
  const S = (name, i) => new Student(name, `10.0.${n % 250}.${i}`);
  const jobs = [];
  HONEST.slice(0, CFG.honest).forEach((name, i) => jobs.push((async () => { await sleep(i * 3000); await honest(S(name, i + 1)); })()));
  if (CFG.enumerator) jobs.push(enumerator(S('carol', 3)));
  if (CFG.sniper) jobs.push(sniper(S('dave', 4)));
  if (CFG.noisy) jobs.push(noisy(S('eve', 5)));
  if (CFG.anonymous) jobs.push(anonymous(S('frank', 6)));
  if (CFG.attacker) jobs.push(attacker(S('mallory', 9)));
  await Promise.all(jobs);
  console.log(`[sim] round ${n} done`);
}

(async () => {
  console.log(`[sim] config ${JSON.stringify(CFG)}`);
  for (let i = 0; i < 60 && !stopping; i++) {
    const r = await new Student('probe', '10.0.0.250').req('GET', '/health');
    if (r.status) break;
    if (i === 0) console.log('[sim] waiting for the proxy to answer...');
    await sleep(1000);
  }
  let n = 1;
  do {
    await round(n++);
    if (CFG.rounds && n > CFG.rounds) break;
    if (CFG.loop && !stopping) await sleep(10000);
  } while (CFG.loop && !stopping);
```

- Each round creates fresh `Student` objects (new sessions) with IPs in `10.0.<round % 250>.<i>`, so a looping simulation produces a new "class" of IPs every round while the names stay the same. The third octet wraps at 250 to stay a valid octet. Note that two pairs share an IP within a round (grace and carol are both `.3`, heidi and dave both `.4`); they stay distinct on the dashboard because logged-in students are identified by session, not IP.
- Honest students start 3 s apart (`i * 3000`) so their first reads are spread out; the other personas start at once but each sleeps before misbehaving, which is what makes the honest ownership learning come first.
- Startup waits up to 60 s for `/health` **through the proxy**. Any HTTP status counts (`r.status` truthy), including a 502 if the proxy is up but the target is not; only a connection failure (`status 0`) keeps waiting.
- The loop: `rounds` > 0 caps the number of rounds; `loop` repeats with a 10 s pause; `rounds: 0` with `loop: true` runs until stopped (the Playground default, `DEFAULT_SIM` in `playground.js`). With both off, exactly one round runs. The console lines (`[sim] ...`) are captured by `playground.js` and shown in the dashboard.

### `proxy/mock/loadtest.js`

```js
// proxy/mock/loadtest.js lines 8-17
const arg = (name, d) => { const i = process.argv.indexOf('--' + name); return i > 0 ? process.argv[i + 1] : d; };
const TARGET = new URL(arg('target', 'http://127.0.0.1:8888'));
const SECONDS = Number(arg('seconds', 10));
const CONC = Number(arg('concurrency', 50));
const PATHS = ['/api/users/1001', '/api/orders/1041', '/api/orders/999999', '/api/invoice?id=7041', '/api/messages/503', "/api/users/1?id=1'%20OR%201=1", '/'];

const agent = new http.Agent({ keepAlive: true, maxSockets: CONC });
let done = 0, errors = 0, bytes = 0;
const lat = [];
const stopAt = Date.now() + SECONDS * 1000;
```

- A three-line argument parser: `--target`, `--seconds`, `--concurrency` each followed by a value.
- `PATHS` mixes successful-looking reads, a non-existent order, an invoice, a message and one SQL-injection-looking query so the proxy exercises its parsing, masking, detection and attack classification paths under load, not only pass-through.
- A keep-alive agent with `maxSockets = CONC` keeps exactly one persistent connection per worker, which is the realistic shape of load behind zrok.

```js
// proxy/mock/loadtest.js lines 19-34
function one(i) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const path = PATHS[(i + done) % PATHS.length];
    const req = http.request({ host: TARGET.hostname, port: TARGET.port || 80, path, agent, headers: { 'X-Forwarded-For': `10.9.${i % 250}.${(i * 7) % 250}`, Cookie: `session=load${i % 40}` } }, (res) => {
      res.on('data', (c) => (bytes += c.length));
      res.on('end', () => { lat.push(Number(process.hrtime.bigint() - t0) / 1e6); done++; resolve(); });
    });
    req.on('error', () => { errors++; resolve(); });
    req.end();
  });
}

async function worker(i) {
  while (Date.now() < stopAt) await one(i);
}
```

- Each worker `i` has its own fake IP and one of 40 fake session cookies (`session=load0..load39`). The mock does not know those sessions, so `/api/*` answers 401 and `/` answers 200; the point is to measure the proxy, not the app. On the monitor those 40 cookies become 40 `sess-…` students.
- Latency is measured with `process.hrtime.bigint()` (nanoseconds) and stored in milliseconds. Path rotation uses `(i + done)`, and `done` changes concurrently, so the sequence is not strictly deterministic — fine for a load test.
- Workers run `one()` back to back until the deadline; `Promise.all` over `CONC` workers (line 39) is the whole run.
- Lines 40–45 print requests, errors, req/s, KB/s, latency percentiles (`lat` sorted ascending, `p(q)` picks index `floor(length * q)`), the maximum, and the client's own RSS so you can tell whether the *generator* was the bottleneck.

The header comment is important: never run this against the real CTF during the event; it should hit the Playground's mock app behind the proxy.

## Interactions

| Script | Reads (env / args) | Network | Writes |
|---|---|---|---|
| `mock-ctf.js` | `PORT` (3999), `HOST` (127.0.0.1) | listens on `HOST:PORT`; the proxy connects to it | stdout line on listen |
| `simulate.js` | `TARGET` (`http://127.0.0.1:8888`), `SIM_CONFIG` JSON, `--loop` argv | HTTP to the proxy; headers `X-Forwarded-For`, `User-Agent: sim/<name>`, `Cookie` | `[sim] …` progress lines on stdout (shown in the Playground tab) |
| `loadtest.js` | `--target`, `--seconds`, `--concurrency` | up to `concurrency` keep-alive connections to the proxy | results on stdout |
| `playground.js` (caller) | dashboard form | spawns the first two with `process.execPath`, sends `SIGTERM` to stop | — |

Related config: `config/rules.json` endpoint patterns (`^/api/users/`, `^/api/orders/`, `^/api/invoices?$` with `query:id`, `^/api/messages/`), `identity.sessionCookies` includes `session`, `ignore.pathPatterns` drops `/static/*.js|css` and `/health`.

## Changing it safely

1. **Add a route with a new bug to the mock** (e.g. `PUT /api/orders/:id` with no check): add a branch after line 106 following the regex pattern; add a matching endpoint to `config/rules.json` (`methods: ["PUT"]`) or the monitor will only track it under "generic numeric id". Add a persona step in `simulate.js` that exercises it.
2. **Add a persona**: write an `async function name(s)`, add a `CFG` boolean default on line 11, push it in `round()` with a distinct name from `USERS` and a distinct IP octet, and add the key to `DEFAULT_SIM` and the boolean list in `playground.js startSim()` (otherwise the dashboard never sends it and the clamp loop drops it).
3. **Change timing**: the waits at lines 102, 117, 128, 142, 162 are what order the personas; shortening `enumerator`'s 8 s below the honest students' browse time makes carol own some orders first and changes who is flagged.
4. **Change the seed layout** (more users, different id ranges): keep `order(k)` in `simulate.js` and the hard-coded ids in `sniper`, `enumerator` and `loadtest.js` in sync with the formulas on lines 11–28 of the mock.

Verify:

```bash
node --check proxy/mock/mock-ctf.js proxy/mock/simulate.js proxy/mock/loadtest.js   # syntax
PORT=3999 node proxy/mock/mock-ctf.js &                                               # run the mock alone
curl -s -c c.txt -H 'Accept: application/json' -d 'username=alice&password=password' http://127.0.0.1:3999/login
curl -s -b c.txt http://127.0.0.1:3999/api/users/1002                                 # bob's secret leaks -> IDOR works
TARGET=http://127.0.0.1:3999 SIM_CONFIG='{"honest":1,"rounds":1,"enumerator":false,"sniper":false,"noisy":false,"anonymous":false,"attacker":false}' node proxy/mock/simulate.js
cd proxy && npm test                                                                  # detector/attack tests still pass
```

## Exercises

1. **Map the `% 3` rule.** Log in as alice (1001) to a bare mock on port 3999 and request messages 501, 502, 503 with curl. Expect 200, 200 (not hers but id not divisible by 3), 403 (502's owner is carol? check: `502 % 9 = 7` → heidi; 503 → `503 % 3 === 0` and owner `USERS[503 % 9 = 8]` = mallory → 403). Confirm 504 (owner alice) returns 200 even though `504 % 3 === 0`.
2. **Run one sniper round through the proxy.** With the Playground mock started and the proxy pointed at it, run `TARGET=http://127.0.0.1:8888 SIM_CONFIG='{"honest":1,"sniper":true,"enumerator":false,"noisy":false,"anonymous":false,"attacker":false,"rounds":1}' node proxy/mock/simulate.js`. On the Live tab, alice must appear clean and dave must get an `idor-success` on `/api/users/1001` about 12 s after start.
3. **Measure the proxy.** `node proxy/mock/loadtest.js --seconds 5 --concurrency 20` against the proxy with the mock behind it, then `docker stats ctf-watch --no-stream`. Note req/s and container memory; compare with the `mem_limit` from chapter 24.

## Quick reference

| Item | Value |
|---|---|
| Mock users | alice 1001 … mallory 1009, password `password` |
| Orders / invoices / messages | 1041–1058 / 7041–7058 / 500–539 |
| IDOR routes | `/api/users/:id`, `/api/orders/:id`, `/api/invoice?id=`, `/api/messages/:id` (403 when foreign and id % 3 == 0) |
| Login | `POST /login` → JSON `{id, username}` + `session` cookie (302 for browsers) |
| Run mock by hand | `PORT=3999 HOST=127.0.0.1 node proxy/mock/mock-ctf.js` |
| Run simulator by hand | `TARGET=http://127.0.0.1:8888 SIM_CONFIG='{"honest":4,"loop":true}' node proxy/mock/simulate.js` |
| `SIM_CONFIG` keys | `honest` 0–4, `enumerator`, `sniper`, `noisy`, `anonymous`, `attacker`, `loop`, `pace` (0.5 = faster), `rounds` (0 = unlimited with loop) |
| Persona names / IPs | alice .1, bob .2, grace .3, heidi .4, carol .3, dave .4, eve .5, frank .6, mallory .9 in `10.0.<round%250>.x` |
| Load test | `node proxy/mock/loadtest.js [--target URL] [--seconds 10] [--concurrency 50]` |

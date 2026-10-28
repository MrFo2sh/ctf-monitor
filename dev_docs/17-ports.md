# Ports — `proxy/src/ports.js`

## Purpose

`ports.js` finds candidate CTF apps for the CTFs tab so the organizer can pick the proxy target from a list instead of typing a URL. It combines two sources: TCP sockets in LISTEN state read from `/proc/net/tcp` and `/proc/net/tcp6` (works because the monitor container shares the host network), and containers listed through the Docker socket (published ports, host-network containers, bridge IPs). Every candidate is probed with a real HTTP GET so the list can say which ones speak HTTP and show their `<title>`. It also owns `validateTarget`, the single place where a target URL is validated and normalised.

## Where it sits

| Who calls it | How |
|---|---|
| `proxy/src/server.js` (line 256) | `discoverTargets = () => discover({ excludePorts: [PROXY_PORT, DASHBOARD_PORT] })`, passed to the dashboard. |
| `proxy/src/server.js` (lines 239, 245) | `validateTarget(CTF_TARGET)` at start, `validateTarget(url)` in `setTarget`. |
| `proxy/src/dashboard.js` (lines 143, 294) | `validateTarget` for `POST /api/targets` and `POST /api/decoy`. |
| `proxy/test/ports.test.js` | `parseProcNetTcp`, `probeHttp`, `validateTarget`. |

| What it requires / calls | Why |
|---|---|
| `fs` | Read `/proc/net/tcp*`, check the Docker socket exists. |
| `http` | Docker API over the unix socket; HTTP probes. |
| `./util` → `log` | One debug line per discovery. |
| env `DOCKER_SOCK` (default `/var/run/docker.sock`), `DISCOVERY_MODE` (default `host`) | Where the Docker socket is; host vs bridge strategy. |

## Data it owns

| Name | Lines | Shape / meaning |
|---|---|---|
| `DOCKER_SOCK` | 10 | Path of the Docker unix socket; `docker-compose.yml` mounts it read-only into the container. |
| `DESKTOP_HOST_PORTS` | 124 | 18 common development ports probed on `host.docker.internal` in bridge mode, and on a container's IPs when its image declares no ports. |
| listening entry | 27, 36 | `{ addr, port }` where `addr` is `a.b.c.d`, `'0.0.0.0'`, `'::'`, `'[v6]'` (unrecognised IPv6) or the raw hex. |
| container entry (`dockerContainers`) | 94 | `{ name, image, state, published: [{ hostIp, hostPort, containerPort }], exposed: number[], ips: string[], hostNet: bool, guessed: bool }`. |
| probe result (`probeHttp`) | 110, 117 | `{ ok: true, status, server, title, location, contentType }` or `{ ok: false, error }`. |
| candidate (`discover`) | 136-137, 160 | `{ url, host, port, source, container, image, probe, bindAddr?, containerPort? }`. `source` ∈ `host`, `docker`, `docker-bridge`, `docker-guess`, `desktop-host`. |

## Walkthrough

### `hexAddr`: decoding one `/proc/net/tcp` address (lines 12-28)

```js
// lines 12-28
function hexAddr(h) {
  // /proc/net/tcp: "0100007F:1F90" -> 127.0.0.1:8080 ; tcp6: 32 hex chars
  const [a, p] = h.split(':');
  const port = parseInt(p, 16);
  let addr;
  if (a.length === 8) {
    const b = Buffer.from(a, 'hex');
    addr = `${b[3]}.${b[2]}.${b[1]}.${b[0]}`;
  } else if (a.length === 32) {
    const b = Buffer.from(a, 'hex');
    // the kernel prints four little-endian 32-bit words: ::ffff:a.b.c.d shows up as 00000000 00000000 FFFF0000 dcba(hex)
    if (b.subarray(0, 8).every((x) => x === 0) && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) addr = `${b[15]}.${b[14]}.${b[13]}.${b[12]}`;
    else if (b.every((x) => x === 0)) addr = '::';
    else addr = '[v6]';
  } else addr = a;
  return { addr, port };
}
```

The kernel prints addresses as hex in **host byte order**, which on x86/ARM is little-endian. Byte by byte:

- IPv4 (`8` hex chars = 4 bytes): `0100007F` → bytes `01 00 00 7F`. The dotted address is read backwards: `b[3].b[2].b[1].b[0]` = `127.0.0.1`. The port after the colon is big-endian hex (`1F90` = 8080), so `parseInt(p, 16)` is enough.
- IPv6 (`32` hex chars = 16 bytes): the kernel prints four 32-bit words, each little-endian. An IPv4-mapped address `::ffff:127.0.0.1` is `0000:0000:0000:0000:0000:ffff:7f00:0001` in network order; after per-word byte swapping it prints as `00000000 00000000 FFFF0000 0100007F`. The code checks bytes 0-7 are zero, bytes 8-9 are `ff ff` and bytes 10-11 are `00 00`, then reads the last word backwards `b[15].b[14].b[13].b[12]` = `127.0.0.1`. The `ports.test.js` row `0000000000000000FFFF00000100007F:0050` exercises exactly this.
- All zero → `'::'` (wildcard; the dual-stack bind most Node/Python servers use). Any other IPv6 → `'[v6]'`: not resolvable to something the proxy can dial (the proxy only talks `http://host:port` with IPv4-style hosts), so it is kept only as a port hint.
- Any other length → the raw string, so an unexpected format never throws.

### `parseProcNetTcp` and `listeningPorts` (lines 30-54)

```js
// lines 30-39
function parseProcNetTcp(text) {
  const out = [];
  for (const line of String(text).split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4 || cols[3] !== '0A') continue; // 0A = LISTEN
    const { addr, port } = hexAddr(cols[1]);
    if (port > 0) out.push({ addr, port });
  }
  return out;
}
```

- `.slice(1)` skips the header line. Columns after trimming: `sl`, `local_address`, `rem_address`, `st`, … so `cols[1]` is the local socket and `cols[3]` the state. `0A` is `TCP_LISTEN`; established connections (`01`) and others are ignored, which is why the test's third row (state `01`) is absent from the result.
- Pure function of the text: this is what the unit test feeds.

```js
// lines 41-54
function listeningPorts() {
  const seen = new Map();
  for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
    try {
      for (const e of parseProcNetTcp(fs.readFileSync(f, 'utf8'))) {
        const cur = seen.get(e.port);
        if (!cur || e.addr === '0.0.0.0' || e.addr === '::') seen.set(e.port, e);
      }
    } catch {
      /* not linux or not readable */
    }
  }
  return [...seen.values()];
}
```

- One entry per port. If the same port appears twice (e.g. bound on `127.0.0.1` and on `::`), the wildcard binding wins so the UI can say "listens on all interfaces" via `bindAddr`.
- On Windows/macOS or inside a container without `/proc` access the reads throw and the function returns `[]`; discovery then relies on Docker only.
- Important: `/proc/net/tcp` shows the **network namespace of the process**. In `docker-compose.yml` the monitor runs with `network_mode: host`, so this is the VM's socket table. In Docker Desktop (bridge) it would only show the monitor's own two ports, which is why `bridge` mode exists.

### Docker API client (lines 56-74)

```js
// lines 56-74
function dockerApi(path) {
  return new Promise((resolve) => {
    if (!fs.existsSync(DOCKER_SOCK)) return resolve(null);
    const req = http.request({ socketPath: DOCKER_SOCK, path, method: 'GET', timeout: 2000 }, (res) => {
      const c = [];
      res.on('data', (d) => c.push(d));
      res.on('end', () => {
        try {
          resolve(res.statusCode === 200 ? JSON.parse(Buffer.concat(c).toString()) : null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}
```

- The Docker Engine API speaks plain HTTP over a unix socket; Node's `socketPath` option does exactly that, no client library needed. No API version prefix is used, so the daemon serves its default (current) version.
- Every failure mode (no socket mounted, permission denied, timeout → `destroy` → `'error'`, non-200, invalid JSON) resolves to `null`. The promise never rejects; callers only need to check for `null`. The 2-second timeout keeps the CTFs tab responsive when the daemon is slow.

### `dockerContainers` (lines 76-97)

```js
// lines 80-94
for (const c of list) {
  const name = (c.Names && c.Names[0] ? c.Names[0] : c.Id.slice(0, 12)).replace(/^\//, '');
  const published = (c.Ports || []).filter((p) => p.PublicPort && p.Type === 'tcp').map((p) => ({ hostIp: p.IP || '0.0.0.0', hostPort: p.PublicPort, containerPort: p.PrivatePort }));
  let exposed = [...new Set((c.Ports || []).filter((p) => p.Type === 'tcp').map((p) => p.PrivatePort))];
  const ips = Object.values((c.NetworkSettings && c.NetworkSettings.Networks) || {}).map((n) => n.IPAddress).filter(Boolean);
  const hostNet = c.HostConfig && c.HostConfig.NetworkMode === 'host';
  let guessed = false;
  if (!exposed.length && !name.startsWith('ctf-watch')) {
    // no port metadata in the list: ask for the image's EXPOSE list
    const insp = await dockerApi(`/containers/${c.Id}/json`);
    const ex = insp && insp.Config && insp.Config.ExposedPorts ? Object.keys(insp.Config.ExposedPorts) : [];
    exposed = ex.filter((k) => k.endsWith('/tcp')).map((k) => Number(k.split('/')[0])).filter(Boolean);
    if (!exposed.length) guessed = true; // caller probes common ports instead
  }
  out.push({ name, image: c.Image, state: c.State, published, exposed, ips, hostNet, guessed });
}
```

- `/containers/json` lists only **running** containers (no `all=1`), which is what we want.
- Docker names come with a leading `/`; it is stripped. Containers without a name fall back to the short ID.
- `Ports` entries with a `PublicPort` are `-p` mappings (reachable on the host at `hostIp:hostPort`); entries without are merely `EXPOSE`d. `PrivatePort` is the port inside the container. Only TCP matters; UDP is dropped.
- `ips` collects the container's address on every network it is attached to (`docker network` bridges), used when nothing is published.
- A container in `network_mode: host` has empty `Ports` in the list output. For those (and for any container with no port metadata) the code inspects the container to get the image's `EXPOSE` list. The monitor's own containers (`ctf-watch…`) are skipped to save a round trip. If even the image declares nothing, `guessed = true` and the caller will try `DESKTOP_HOST_PORTS`.
- The inspections run sequentially (`await` inside the loop); with many port-less containers discovery gets slower, bounded by 2 s per call.

### `probeHttp` (lines 99-120)

```js
// lines 99-120
function probeHttp(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.request({ host, port, path: '/', method: 'GET', timeout: timeoutMs, headers: { 'User-Agent': 'ctf-watch-probe', Accept: 'text/html' } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => {
        if (body.length < 4096) body += d;
        else res.destroy();
      });
      const finish = () => {
        const t = /<title[^>]*>([^<]{0,80})/i.exec(body);
        resolve({ ok: true, status: res.statusCode, server: String(res.headers.server || '').slice(0, 40), title: t ? t[1].trim() : '', location: res.headers.location || '', contentType: String(res.headers['content-type'] || '').split(';')[0] });
      };
      res.on('end', finish);
      res.on('close', finish);
      res.on('error', finish);
    });
    req.on('timeout', () => req.destroy());
    req.on('error', (e) => resolve({ ok: false, error: e.code || e.message }));
    req.end();
  });
}
```

- A real `GET /` with a recognisable `User-Agent` (so the probe is identifiable in the CTF app's own logs). Any HTTP answer — including 401, 404, 302 — counts as `ok: true`; the point is "does it speak HTTP", not "is it healthy".
- The body is read only until 4 KiB then the response is destroyed; that is enough to find `<title>` (first 80 chars) and keeps the probe cheap against big pages. `finish` is bound to `end`, `close` and `error` so it always resolves; a promise resolves only once, so the extra calls are harmless.
- Non-HTTP listeners (SSH, databases) typically produce `HPE_INVALID_CONSTANT` parse errors or a timeout → `ok: false` with the error code, which the UI shows greyed.
- `location` is captured so a `302` to `/login` is visible as a hint.

### `discover` (lines 124-166)

```js
// lines 130-138
async function discover({ excludePorts = [], mode = process.env.DISCOVERY_MODE || 'host' } = {}) {
  const ex = new Set(excludePorts.map(Number));
  const byUrl = new Map();
  const add = (host, port, extra) => {
    const url = `http://${host}:${port}`;
    if (ex.has(Number(port)) && (host === '127.0.0.1' || host === 'host.docker.internal')) return;
    const cur = byUrl.get(url) || { url, host, port: Number(port), source: 'host', container: null, image: null };
    byUrl.set(url, { ...cur, ...extra });
  };
  const containers = await dockerContainers();
```

- `mode` defaults from `DISCOVERY_MODE` **at call time** (default parameter), so the env var is read on every discovery. `docker-compose.desktop.yml` sets `bridge`.
- `excludePorts` are the monitor's own proxy and dashboard ports. They are excluded only on the local hosts; a *container* that happens to use port 8080 on its bridge IP is still listed.
- `byUrl` merges information from several sources for the same `host:port` (e.g. `/proc` says it listens, Docker says which container owns it): later `add` calls spread their `extra` over the earlier entry.

```js
// lines 140-158
if (mode === 'bridge') {
  for (const c of containers) {
    if (c.name === 'ctf-watch' || c.name === 'ctf-watch-simulator') continue;
    const ports = c.guessed ? DESKTOP_HOST_PORTS : c.exposed;
    for (const ip of c.ips) for (const p of ports) add(ip, p, { source: c.guessed ? 'docker-guess' : 'docker', container: c.name, image: c.image });
  }
  for (const p of DESKTOP_HOST_PORTS) add('host.docker.internal', p, { source: 'desktop-host' });
} else {
  for (const e of listeningPorts()) add('127.0.0.1', e.port, { bindAddr: e.addr });
  for (const c of containers) {
    if (c.name === 'ctf-watch' || c.name === 'ctf-watch-simulator') continue;
    if (c.hostNet) {
      for (const p of c.exposed) add('127.0.0.1', p, { source: 'docker', container: c.name, image: c.image });
      continue;
    }
    for (const p of c.published) add('127.0.0.1', p.hostPort, { source: 'docker', container: c.name, image: c.image, containerPort: p.containerPort });
    if (!c.published.length) for (const ip of c.ips) for (const p of c.exposed) add(ip, p, { source: 'docker-bridge', container: c.name, image: c.image });
  }
}
```

**Bridge mode** (Docker Desktop on Windows/macOS): the monitor cannot see the host's sockets, so (a) every other container is reachable by its network IP on its exposed ports (or, with no metadata, the common ports, tagged `docker-guess`), and (b) an app running directly on the developer's machine is reachable at `host.docker.internal` (`extra_hosts: host-gateway` in the desktop compose file) on the common ports, tagged `desktop-host`.

**Host mode** (the Ubuntu VM, default): (a) every LISTEN socket on the VM is a candidate at `127.0.0.1:port` with `bindAddr` showing how it is bound; (b) containers in host network mode are reachable on `127.0.0.1` at their exposed ports; (c) published ports are reachable at `127.0.0.1:hostPort` (the `containerPort` is kept for display); (d) a container with nothing published is reachable only on its bridge IP — the monitor can dial that because it shares the host network, which includes the `docker0` bridge.

The monitor's own container and the (legacy) simulator container are always skipped; the playground now runs the simulator as a child process instead, see `playground.js`.

```js
// lines 159-165
let list = [...byUrl.values()].slice(0, 80);
await Promise.all(list.map(async (c) => (c.probe = await probeHttp(c.host, c.port))));
// the guessed desktop-host ports are only worth showing when something answers there
list = list.filter((c) => (c.source !== 'desktop-host' && c.source !== 'docker-guess') || c.probe.ok);
list.sort((a, b) => Number(b.probe.ok) - Number(a.probe.ok) || (a.source === 'docker' ? -1 : 0) - (b.source === 'docker' ? -1 : 0) || a.port - b.port);
log('debug', `discover: ${list.length} candidates, ${list.filter((c) => c.probe.ok).length} speak http`);
return list;
```

- At most 80 candidates are probed, **in parallel** (`Promise.all`), so a discovery takes about one probe timeout (1.5 s) in the worst case rather than 80 × 1.5 s. On a busy VM with more than 80 listeners the extras are silently dropped (insertion order: `/proc` first, then Docker).
- Guessed sources are kept only if something answered; real sources (`host`, `docker`, `docker-bridge`) are listed even when the probe failed, so the organizer can see "there is a listener on 5432 but it is not HTTP".
- Sort: HTTP speakers first, then Docker-published ones, then by port number.

### `validateTarget` (lines 168-183)

```js
// lines 168-183
function validateTarget(input) {
  const s = String(input || '').trim();
  const pm = /:(\d+)\/?$/.exec(s);
  if (pm && (Number(pm[1]) < 1 || Number(pm[1]) > 65535)) throw new Error('bad port');
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error('target must look like http://127.0.0.1:5000');
  }
  if (u.protocol !== 'http:') throw new Error('only http:// targets are supported (the proxy talks plain http to the app)');
  if (!u.hostname) throw new Error('target needs a host');
  const port = Number(u.port) || 80;
  if (port < 1 || port > 65535) throw new Error('bad port');
  return `http://${u.hostname}:${port}`;
}
```

- The regex pre-check exists because `new URL('http://127.0.0.1:70000')` throws a generic "Invalid URL"; checking the port first gives the user the precise message `bad port` (tested).
- Only `http:` is accepted: the proxy dials the app with plain `http.request`; TLS termination is zrok's job on the public side.
- The result is **normalised**: path, query and trailing slash are dropped and the port is made explicit (`http://172.17.0.3` → `http://172.17.0.3:80`). Because every target goes through here, `proxy.js` can safely `new URL(url)` and cache by string, and `decoy.targetFor` comparisons work on identical strings.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` | `discover({ excludePorts })`; `validateTarget(url)`. |
| in | `dashboard.js` | `validateTarget(url)` for the target and decoy routes. |
| out | kernel `/proc/net/tcp`, `/proc/net/tcp6` | Read-only text. |
| out | Docker Engine API via `DOCKER_SOCK` | `GET /containers/json`, `GET /containers/{id}/json`. |
| out | network | `GET /` probes to each candidate with `User-Agent: ctf-watch-probe`. |
| out | `util.js` | One `debug` log line per discovery. |

## Changing it safely

| Likely change | Where |
|---|---|
| Add a common port to guess in bridge mode | `DESKTOP_HOST_PORTS` (line 124). Each extra port is one more probe per container and on `host.docker.internal`. |
| Show IPv6-only listeners properly | `hexAddr` (line 25 `'[v6]'`) and `add()` would need bracketed hosts; `validateTarget` and `proxy.js` would also have to accept `[::1]`. |
| Probe a different path or accept HTTPS apps | `probeHttp` (path at line 101); HTTPS would need `https.request` here and in `proxy.js`, and dropping the `http:` check in `validateTarget`. |
| Different exclusion rule (e.g. also hide port 22) | `add()` (line 135) or filter after probing (line 162). |

Tests in `proxy/test/ports.test.js`:

- `parses LISTEN sockets out of /proc/net/tcp (ipv4 and mapped ipv6)` — covers `parseProcNetTcp` and `hexAddr` for IPv4, wildcard IPv6 and IPv4-mapped IPv6.
- `validateTarget normalises and rejects bad input` — the five rules above.
- `probeHttp reports status, server and title of an http server, and failure for a closed port` — real local server.

Not unit-tested: `listeningPorts` (needs Linux `/proc`), `dockerApi`/`dockerContainers` (need a Docker socket), and `discover`'s merging, filtering and sorting. Those are only verified by opening the CTFs tab on the VM (host mode) and on Docker Desktop (bridge mode).

## Exercises

1. **Decode an address by hand, then check.** `0100007F:1F90` → which address and port? Verify:
   `cd proxy && node -e "const {parseProcNetTcp}=require('./src/ports');console.log(parseProcNetTcp('hdr\n 0: 0100007F:1F90 00000000:0000 0A'))"`
   Expect `[ { addr: '127.0.0.1', port: 8080 } ]`.

2. **Run discovery from the shell inside the container** (host mode) and look at `source` and `probe.ok`:
   `docker exec ctf-watch node -e "require('./src/ports').discover({excludePorts:[8888,8080]}).then(l=>console.log(l.map(c=>[c.url,c.source,c.probe.ok,c.probe.title])))"`
   Start the Playground mock app first and confirm `http://127.0.0.1:3999` appears with `probe.ok === true`.

3. **Make `validateTarget` reject something new.** Add a rule that refuses port 22, run `node --test test/ports.test.js` (still green, the existing cases do not use 22), add an assertion `assert.throws(() => validateTarget('http://x:22'), /bad port/)` to `validateTarget normalises and rejects bad input`, and run again. Revert afterwards.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `discover` | `async ({ excludePorts?: number[], mode?: 'host' \| 'bridge' }) → candidate[]` | Full discovery: `/proc` + Docker, probed, filtered, sorted. |
| `listeningPorts` | `() → [{ addr, port }]` | LISTEN sockets from `/proc/net/tcp` and `tcp6`, one per port, wildcard bind preferred. |
| `parseProcNetTcp` | `(text) → [{ addr, port }]` | Pure parser for one `/proc/net/tcp*` file. |
| `dockerContainers` | `async () → container[]` | Running containers with their ports, IPs and network mode; `[]` without a socket. |
| `probeHttp` | `(host, port, timeoutMs = 1500) → Promise<probe>` | `GET /`; never rejects. |
| `validateTarget` | `(input) → 'http://host:port'` | Throws `Error` with a user-facing message on invalid input. |

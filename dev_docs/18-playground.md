# Playground — `proxy/src/playground.js`

## Purpose

`playground.js` lets the organizer test the whole monitor without a real CTF. From the dashboard's Playground tab it starts two child processes of the monitor: `proxy/mock/mock-ctf.js` (a tiny fake CTF app with deliberate IDOR bugs) and `proxy/mock/simulate.js` (fake students that send traffic *through the proxy*). It keeps a small log ring per process and reports their status. Nothing in this module runs unless an admin starts it from the dashboard.

## Where it sits

| Who calls it | How |
|---|---|
| `proxy/src/server.js` (line 85) | `new Playground({ proxyPort: PROXY_PORT })`; `playground.stopAll()` on shutdown. |
| `proxy/src/dashboard.js` (lines 333-358, 417) | `status()`, `startMock`, `stopMock`, `startSim`, `stopSim`, `stopAll`, `mockUrl()`, `mock.running()`, `sim.running()`. |

| What it requires / calls | Why |
|---|---|
| `child_process.spawn` | Run the two scripts with the same Node binary as the monitor. |
| `path` | Locate `proxy/mock/`. |
| `./util` → `log` | Start/exit log lines. |
| `proxy/mock/mock-ctf.js` | Reads env `PORT`, `HOST`. |
| `proxy/mock/simulate.js` | Reads env `TARGET`, `SIM_CONFIG` (JSON). |

## Data it owns

| Name | Lines | Shape / meaning |
|---|---|---|
| `MOCK_DIR` | 9 | `proxy/mock` (resolved from `__dirname`). |
| `MAX_LOG` | 10 | 60 lines kept per process; `status()` returns the last 25. |
| `Proc` fields | 13-19 | `name` (for logs), `child` (`ChildProcess` or null), `startedAt` (ms), `lines` (string[] with `HH:MM:SS` prefix), `lastExit` (`{ code, signal, at }` or null), `config` (whatever the caller passed, echoed in status). |
| `Proc#status()` | 56 | `{ running, pid, startedAt, lastExit, config, log: string[] }`. |
| `DEFAULT_SIM` | 60 | `{ honest: 4, enumerator: true, sniper: true, noisy: true, anonymous: true, attacker: true, loop: true, pace: 1, rounds: 0 }` — the simulator's personas and pacing. Exported. |
| `Playground` fields | 63-67 | `proxyPort`, `mock` (Proc), `sim` (Proc), `mockPort` (default 3999). |
| `Playground#status()` | 107 | `{ mock: { …Proc status, port, url }, sim: Proc status, defaults: DEFAULT_SIM, proxyPort }`. |

## Walkthrough

### `Proc`: one managed child process (lines 12-58)

```js
// lines 21-23
running() {
  return !!this.child && this.child.exitCode === null && !this.child.killed;
}
```

- `exitCode === null` means the process has not exited. `killed` becomes `true` as soon as `kill()` successfully *sent* a signal, before the process actually exits. So `running()` turns false immediately after `stop()`, even though the OS process may survive up to 2 s more. This is what makes "Stop" feel instant in the UI, but it also means a `start()` right after `stop()` is accepted while the old process is still terminating (a second mock app on the same port would then fail to bind — its error shows up in the new process's log lines).

```js
// lines 24-45
start(script, env, config) {
  if (this.running()) throw new Error(`${this.name} is already running`);
  this.lines = [];
  this.lastExit = null;
  this.config = config || null;
  this.child = spawn(process.execPath, [script], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
  this.startedAt = Date.now();
  const onLine = (chunk) => {
    for (const l of String(chunk).split('\n')) {
      if (!l.trim()) continue;
      this.lines.push(`${new Date().toLocaleTimeString([], { hour12: false })} ${l.trim()}`);
      if (this.lines.length > MAX_LOG) this.lines.shift();
    }
  };
  this.child.stdout.on('data', onLine);
  this.child.stderr.on('data', onLine);
  this.child.on('exit', (code, signal) => {
    this.lastExit = { code, signal, at: Date.now() };
    log('info', `playground: ${this.name} exited (${signal || code})`);
  });
  log('info', `playground: ${this.name} started (pid ${this.child.pid})`);
}
```

- `process.execPath` is the running Node binary, so the children use exactly the same runtime as the monitor (inside the Docker image: `/usr/local/bin/node`).
- The child inherits the monitor's environment plus the overrides. That is how `PORT`/`HOST`/`TARGET`/`SIM_CONFIG` reach the scripts, and also why the child sees `LOG_LEVEL` etc.
- `stdio: ['ignore', 'pipe', 'pipe']`: stdin closed, stdout and stderr captured. Both streams feed the same ring of 60 timestamped lines; chunks are split on newlines and blank lines dropped. A chunk boundary in the middle of a line produces two log entries (cosmetic).
- There is no `'error'` listener on the child. If `spawn` itself fails asynchronously (e.g. the script file is missing — Node reports `ENOENT` through `'error'`), Node would raise an unhandled `'error'` event. In practice the scripts ship with the image, so this is accepted.
- `startedAt`, `lastExit` and `config` are only bookkeeping for the status panel.

```js
// lines 46-54
stop() {
  if (!this.running()) return false;
  this.child.kill('SIGTERM');
  const c = this.child;
  setTimeout(() => {
    if (c.exitCode === null) c.kill('SIGKILL');
  }, 2000).unref();
  return true;
}
```

- Polite first: `SIGTERM` lets `simulate.js` print `[sim] stopping` and finish its in-flight request (it exits itself 300 ms later). If the process is still alive after 2 s, `SIGKILL`. The timer is `unref()`ed so it never keeps the monitor alive during shutdown. `c` is captured so a `start()` in between does not kill the new child.
- On Windows `kill('SIGTERM')` terminates immediately (no graceful phase); irrelevant in the Docker deployment.

```js
// lines 55-57
status() {
  return { running: this.running(), pid: this.running() ? this.child.pid : null, startedAt: this.startedAt, lastExit: this.lastExit, config: this.config, log: this.lines.slice(-25) };
}
```

### `Playground` (lines 60-109)

```js
// lines 70-83
startMock({ port } = {}) {
  const p = Number(port) || 3999;
  if (p < 1024 || p > 65535) throw new Error('port must be between 1024 and 65535');
  this.mockPort = p;
  this.mock.start(path.join(MOCK_DIR, 'mock-ctf.js'), { PORT: String(p), HOST: '127.0.0.1' }, { port: p });
  return this.status();
}
stopMock() {
  this.mock.stop();
  return this.status();
}
mockUrl() {
  return `http://127.0.0.1:${this.mockPort}`;
}
```

- Unprivileged ports only. The mock app always binds `127.0.0.1`, so it is reachable only through the proxy (or locally), never directly from the network.
- `mockPort` is remembered so `mockUrl()` (used by the "quick start" route in `dashboard.js` to point the proxy at the mock) matches what was started. The error from `Proc.start` ("already running") propagates to the dashboard as a 400.

```js
// lines 85-95
startSim(cfg = {}) {
  const c = { ...DEFAULT_SIM };
  for (const k of Object.keys(DEFAULT_SIM)) if (cfg[k] !== undefined) c[k] = cfg[k];
  c.honest = Math.max(0, Math.min(4, Number(c.honest) || 0));
  c.pace = Math.max(0.1, Math.min(10, Number(c.pace) || 1));
  c.rounds = Math.max(0, Math.min(1000, Number(c.rounds) || 0));
  for (const k of ['enumerator', 'sniper', 'noisy', 'anonymous', 'attacker', 'loop']) c[k] = !!c[k];
  const target = cfg.target ? String(cfg.target) : `http://127.0.0.1:${this.proxyPort}`;
  this.sim.start(path.join(MOCK_DIR, 'simulate.js'), { TARGET: target, SIM_CONFIG: JSON.stringify(c) }, { ...c, target });
  return this.status();
}
```

- Only keys that exist in `DEFAULT_SIM` are accepted from the request body (unknown keys are ignored, so the JSON passed to the child is always well-formed). Numbers are clamped: at most 4 honest students (the script has four named personas), pace between 0.1× and 10× (`pace` multiplies every sleep in the simulator: 0.5 = twice as fast), at most 1000 rounds (0 = unlimited when `loop` is on). The persona switches are coerced to booleans.
- The default **target is the proxy**, not the mock app: the whole point is that simulated traffic passes through `proxy.js` and shows up on the dashboard with identities, IDOR detection and attack classification. A `cfg.target` override is allowed (string, not validated) for aiming the simulator elsewhere.
- The simulator fakes distinct student IPs by setting `X-Forwarded-For` per persona; see the gotcha in chapter 15 about `clientIp` trusting the first hop.

```js
// lines 101-108
stopAll() {
  this.sim.stop();
  this.mock.stop();
}
status() {
  return { mock: { ...this.mock.status(), port: this.mockPort, url: this.mockUrl() }, sim: this.sim.status(), defaults: DEFAULT_SIM, proxyPort: this.proxyPort };
}
```

- The simulator is stopped before the app so its last requests fail quickly rather than hang. `server.js` calls `stopAll()` on `SIGTERM`/`SIGINT`, so children do not outlive the monitor; a hard crash of the monitor (no signal) can leave them running until the container stops.
- `status()` is what `GET /api/playground` returns and what the `stats` WebSocket message summarises as `mock: { app, sim }`.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` | `new Playground({ proxyPort })`, `stopAll()` at shutdown. |
| in | `dashboard.js` | `startMock({ port })`, `stopMock()`, `startSim(cfg)`, `stopSim()`, `stopAll()`, `status()`, `mockUrl()`, `mock.running()`, `sim.running()`. |
| out | child process `mock/mock-ctf.js` | env `PORT`, `HOST=127.0.0.1`; stdout/stderr captured. |
| out | child process `mock/simulate.js` | env `TARGET` (default the proxy URL), `SIM_CONFIG` (JSON of the clamped config); `SIGTERM` then `SIGKILL`. |
| out (indirect) | `proxy.js` | The simulator's HTTP traffic enters the proxy like any student's. |
| out | `util.js` | `log` on start/exit. |

## Changing it safely

| Likely change | Where |
|---|---|
| New simulator option (e.g. a new persona) | Add the key to `DEFAULT_SIM` (line 60) with its default, add clamping/coercion in `startSim` (88-91), and read it in `mock/simulate.js` from `SIM_CONFIG`. The dashboard shows `defaults` from `status()`, so the UI form needs a matching control. |
| Longer log history in the panel | `MAX_LOG` (line 10) and the `slice(-25)` at line 56. Each line is one string in memory per process. |
| Let the mock app listen on another interface | The `HOST` env at line 74 (`mock-ctf.js` reads `HOST`). Keep in mind the proxy dials `mockUrl()` on `127.0.0.1`. |
| Run a third helper process | Add another `Proc` instance in the constructor, a `startX`/`stopX` pair, include it in `stopAll()` and `status()`, then add the route in `dashboard.js`. |

Tests: **none.** No file in `proxy/test/` touches `playground.js`, `mock-ctf.js` or `simulate.js`. It is verified only by running the stack and using the Playground tab (or the `curl` calls below).

## Exercises

1. **Start the mock app from the API and read its log ring.** Log in as admin in a browser, copy the `ctfw_sid` cookie, then:
   `curl -s -b 'ctfw_sid=<token>' -H 'X-Requested-With: ctf-watch' -H 'Content-Type: application/json' -d '{"port":3999}' http://127.0.0.1:8080/api/playground/mock`
   The JSON shows `mock.running: true` and a `log` array with the app's "listening" line. Running the same command again returns 400 `mock CTF app is already running`.

2. **Observe the stop sequence.** Start the simulator (`POST /api/playground/sim` with `{}`), then stop it (`{"action":"stop"}`) and immediately `GET /api/playground`: `sim.running` is already `false` while `sim.lastExit` is still `null`; a second later `lastExit` is `{ code: 0, signal: null }` (the simulator exits by itself after `[sim] stopping`).

3. **Run the simulator by hand against the proxy** (no dashboard involved) to see what the child receives:
   `cd proxy && TARGET=http://127.0.0.1:8888 SIM_CONFIG='{"honest":1,"loop":false,"rounds":1,"attacker":false}' node mock/simulate.js`
   Compare the keys you passed with what `startSim` would have produced for the same request body (`defaults` filled in, numbers clamped).

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `Playground` | `new Playground({ proxyPort })` | Manager for the two child processes. |
| `Playground#startMock` | `({ port? }) → status` | Starts `mock-ctf.js` on `127.0.0.1:port` (default 3999, 1024-65535). Throws if running. |
| `Playground#stopMock` | `() → status` | `SIGTERM`, `SIGKILL` after 2 s. |
| `Playground#mockUrl` | `() → 'http://127.0.0.1:<mockPort>'` | URL the proxy should target. |
| `Playground#startSim` | `(cfg?) → status` | Starts `simulate.js` with clamped config; target defaults to the proxy. Throws if running. |
| `Playground#stopSim` | `() → status` | Stops the simulator. |
| `Playground#stopAll` | `() → void` | Stops both (simulator first). |
| `Playground#status` | `() → { mock, sim, defaults, proxyPort }` | Full status for the Playground tab. |
| `DEFAULT_SIM` | object | Default simulator configuration. |

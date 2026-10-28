# Proxy — `proxy/src/proxy.js`

## Purpose

`proxy.js` is the transparent reverse proxy that students actually talk to. It forwards every HTTP request unchanged to the CTF app (headers, cookies, redirects, status codes, request and response bodies, WebSocket upgrades), captures a bounded copy of the request and response bodies for inspection, and reports every finished exchange to a single `onEvent()` callback supplied by `server.js`. It contains no detection logic of its own: it only moves bytes and describes what it moved.

## Where it sits

| Who calls it | How |
|---|---|
| `proxy/src/server.js` (line 328) | `createProxy({ getTarget, getTargetFor, bind, port, shouldIgnore, onEvent, gate, preRequest })` once at startup. |

| What it requires / calls | Why |
|---|---|
| `http`, `net`, `zlib` (Node core) | Listening server, upstream requests, raw TCP tunnel for upgrades, body decompression. |
| `./util` → `log` | Logging only. |
| `gate.handle(req, res)` (a `NameGate`, see `namegate.js`) | Optional: lets the name-gate answer the request (the "enter your name" page, its status/stream endpoints). |
| `preRequest(req, res)` (from `server.js`) | Lets `server.js` refuse blocked students with a 403 before anything is forwarded. |
| `getTargetFor(req)` / `getTarget()` (from `server.js`) | Per-request upstream (the decoy) or the global upstream (the real CTF). |
| `shouldIgnore(pathOnly)` (from `server.js`) | Paths matching `ignore.pathPatterns` in `rules.json` are proxied but not captured or reported. |
| `onEvent(exchange)` (from `server.js`) | The one output of this module: one call per finished exchange. |

## Data it owns

| Name | Lines | Shape / meaning |
|---|---|---|
| `MAX_CAPTURE` | 10 | `65536` bytes. Upper bound on how much of the request body and of the response body is kept in memory for inspection. The full bodies are always streamed through; only the *copy* is truncated. |
| `HOP_BY_HOP` | 11 | `Set` of lower-cased header names that must not be copied from the upstream response to the client (`transfer-encoding`, `connection`, `keep-alive`, `proxy-connection`, `upgrade`, `te`, `trailer`). Node generates its own framing headers for the client connection. |
| `NO_TARGET_PAGE` | 27 | Static HTML shown with status 503 when no CTF app is selected. |
| `agent` | 34 | `http.Agent({ keepAlive: true, maxSockets: 512 })`, shared by all upstream requests so TCP connections to the CTF app are reused. |
| `parsed` | 35 | `Map<url, { url, host, port }>`: cache of parsed upstream URLs, capped at 50 entries (FIFO eviction). |
| exchange object passed to `onEvent` | 102-116, 188-202 | See table below. |

The exchange object (the only thing that crosses to `server.js`):

| Field | Meaning |
|---|---|
| `ts` | `Date.now()` when the request arrived at the proxy. |
| `req` | The original `http.IncomingMessage` (headers, socket, cookies). `server.js` needs it for identity resolution and the client IP. It is **not** serialisable; downstream code strips it before JSON. |
| `method`, `url`, `pathOnly` | Request method, full URL path with query string, path without query string. For WebSocket tunnels `method` is the literal string `'UPGRADE'`. |
| `status` | Upstream status code; `502` when the upstream failed; `101` for tunnels. |
| `size` | Total response body bytes actually streamed to the client (not capped). |
| `latencyMs` | Time from request arrival to upstream response end, one decimal. |
| `reqLen` | Total request body bytes (not capped). |
| `reqBuf` | `Buffer` with the first `MAX_CAPTURE` bytes of the request body (raw, not decompressed). |
| `resHeaders` | Upstream response headers as Node's lower-cased object (`set-cookie` is an array). `{}` on upstream error. |
| `resBuf` | `Buffer` with the first `MAX_CAPTURE` bytes of the response body, **decompressed** if `content-encoding` was gzip/deflate/br. |
| `error` | `null`, or a message string (`'upstream timeout'`, socket error text). |

## Walkthrough

### Constants and body decoding (lines 10-27)

```js
// lines 13-25
function decodeBody(encoding, buf) {
  if (!buf || !buf.length) return buf;
  const enc = String(encoding || '').toLowerCase();
  const opts = { finishFlush: zlib.constants.Z_SYNC_FLUSH };
  try {
    if (enc.includes('gzip')) return zlib.gunzipSync(buf, opts);
    if (enc.includes('deflate')) return zlib.inflateSync(buf, opts);
    if (enc.includes('br')) return zlib.brotliDecompressSync(buf, { finishFlush: zlib.constants.BROTLI_OPERATION_FLUSH });
  } catch {
    return Buffer.alloc(0);
  }
  return buf;
}
```

- The captured response copy is at most 64 KiB, so for a bigger compressed body the copy is a *truncated* gzip stream. A normal `gunzipSync` throws "unexpected end of file" on that. `finishFlush: Z_SYNC_FLUSH` (and `BROTLI_OPERATION_FLUSH` for brotli) tells zlib to return whatever it could decode instead of insisting on a complete stream. This is what makes partial inspection possible.
- Any decoding error returns an empty buffer rather than the still-compressed bytes, so downstream parsers never try to `JSON.parse` gzip garbage.
- `enc.includes(...)` is deliberately loose: `Content-Encoding: gzip, identity` or odd casing still work. Unknown encodings return the buffer unchanged.
- Note the request body copy (`reqBuf`) is **not** decoded; students' uploads are assumed uncompressed.

### `createProxy` and `currentUpstream` (lines 33-48)

```js
// lines 33-48
function createProxy({ getTarget, getTargetFor, bind, port, shouldIgnore, onEvent, gate, preRequest }) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 512 });
  const parsed = new Map(); // url -> { url, host, port }
  function currentUpstream(req) {
    const url = (getTargetFor && req ? getTargetFor(req) : null) || getTarget();
    if (!url) return null;
    let u = parsed.get(url);
    if (!u) {
      const p = new URL(url);
      u = { url, host: p.hostname, port: Number(p.port) || 80 };
      parsed.set(url, u);
      if (parsed.size > 50) parsed.delete(parsed.keys().next().value);
    }
    return u;
  }
```

- The upstream is resolved **per request**, not once. `getTargetFor(req)` is the decoy hook (`server.js` line 260): it returns a different base URL for students on the decoy list, or `null`. `|| getTarget()` falls back to the real CTF, which can itself change at runtime from the CTFs tab. Nothing in the proxy needs restarting when the target changes.
- The URL is parsed once per distinct value and cached. The map is capped at 50 entries; `parsed.keys().next().value` is the oldest insertion, so eviction is FIFO. The cap only matters if the organizer switches targets dozens of times.
- `Number(p.port) || 80`: `new URL('http://host')` has an empty `port`, so port 80 is the default. Targets always pass through `validateTarget` in `ports.js` first, so the protocol is always `http:`.
- The keep-alive agent with `maxSockets: 512` means up to 512 concurrent connections per upstream host:port. Idle sockets are reused, which matters under simulator/fuzzing load.

### `handle`: gate, block, no target (lines 50-59)

```js
// lines 50-59
function handle(req, res) {
  if (gate && gate.handle(req, res)) return; // optional "enter your name" page
  if (preRequest && preRequest(req, res)) return; // blocked students are answered here
  const up = currentUpstream(req);
  if (!up) {
    res.writeHead(503, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'Retry-After': '10' });
    res.end(NO_TARGET_PAGE);
    req.resume();
    return;
  }
```

Order matters:

1. The gate runs first and returns `true` when it answered the request itself (served the form, handled the form POST, the queue status/stream endpoints, or refused a tool with 428). Those requests never reach the CTF app and are never reported to `onEvent`.
2. `preRequest` (in `server.js`) answers blocked students with a 403 and records the attempt itself.
3. Only then is the upstream looked up. With no target the student gets the "not open yet" page. `Retry-After: 10` is a hint for well-behaved clients; `Cache-Control: no-store` prevents the browser from caching the 503 and showing it after the organizer connects the app. `req.resume()` drains any request body so the socket is not left half-read (otherwise keep-alive connections could stall).

### Request header copying and `X-Forwarded-For` (lines 60-78)

```js
// lines 67-78
const headers = {};
for (let i = 0; i < req.rawHeaders.length; i += 2) {
  const k = req.rawHeaders[i];
  const lk = k.toLowerCase();
  if (lk === 'proxy-connection') continue;
  if (headers[k] !== undefined) headers[k] = [].concat(headers[k], req.rawHeaders[i + 1]);
  else headers[k] = req.rawHeaders[i + 1];
}
const remote = req.socket.remoteAddress || '';
const xffKey = Object.keys(headers).find((k) => k.toLowerCase() === 'x-forwarded-for');
if (xffKey) headers[xffKey] = `${[].concat(headers[xffKey]).join(', ')}, ${remote}`;
else headers['X-Forwarded-For'] = remote;
```

- `req.rawHeaders` is used instead of `req.headers` so the original header **casing** and **duplicates** are preserved exactly as the student's tool sent them (some CTF apps or WAF-style challenges care). `req.headers` would have lower-cased and joined them.
- Duplicated headers become arrays; Node's `http.request` sends an array as repeated header lines.
- Only `proxy-connection` is dropped on the request side. `Connection`, `Transfer-Encoding` etc. from the client are passed to `http.request`, which handles framing itself. Because the body is streamed with `req.pipe(upstream)` and the client's `Content-Length`/`Transfer-Encoding` is forwarded, the upstream sees the same framing the client used.
- `X-Forwarded-For`: if the client already sent one (zrok does, and the simulator sets it on purpose to fake many student IPs), the proxy's view of the peer is **appended**; otherwise it is created. Gotcha: `util.clientIp()` (used everywhere for identity) takes the **first** entry, i.e. it trusts whatever the client claimed. That is intentional for the zrok deployment (zrok puts the real student IP first) and for the simulator, but it means a student on a direct LAN connection can spoof their IP by sending the header.
- `startNs` (line 62) uses `process.hrtime.bigint()` for latency; `ts` (line 63) is wall-clock for the event.
- `ignored` (line 65) is computed once from the path without query string.

### Request body capture (lines 80-92)

```js
// lines 80-92
const reqChunks = [];
let reqCap = 0;
let reqLen = 0;
if (!ignored) {
  req.on('data', (c) => {
    reqLen += c.length;
    if (reqCap < MAX_CAPTURE) {
      const slice = c.subarray(0, MAX_CAPTURE - reqCap);
      reqChunks.push(slice);
      reqCap += slice.length;
    }
  });
}
```

- A `data` listener is attached *in addition to* the later `req.pipe(upstream)`. Both consume the same stream; the listener just observes the chunks as they fly past.
- `reqLen` counts everything; `reqCap` counts only what was kept. `subarray` is a zero-copy view; `Buffer.concat` at line 112 copies once at the end.
- For ignored paths no listener is attached, so an ignored upload costs nothing extra.

### `finish`: building the event (lines 94-120)

```js
// lines 95-116
const finish = (status, resHeaders, resBuf, resLen, error) => {
  if (finished || ignored) return;
  finished = true;
  const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
  let decoded = Buffer.alloc(0);
  if (resBuf && resBuf.length) decoded = decodeBody(resHeaders['content-encoding'], resBuf);
  try {
    onEvent({
      ts, req, method: req.method, url: req.url || '/', pathOnly, status, size: resLen,
      latencyMs: Math.round(latencyMs * 10) / 10, reqLen, reqBuf: Buffer.concat(reqChunks),
      resHeaders: resHeaders || {}, resBuf: decoded, error: error || null,
    });
  } catch (err) {
    log('error', `event handler failed: ${err.stack || err}`);
  }
};
```

- `finish` can be reached from several places (response end, response error, upstream error). The `finished` flag makes the **first** caller win; later ones are no-ops. Ignored paths never report.
- `onEvent` is wrapped in `try/catch`: a bug in detection must not crash the proxy or leave the student's response hanging (by this point the response is already streaming independently).
- `resHeaders` here is Node's parsed `ures.headers` (lower-cased). Header lookups downstream (`content-type`, `set-cookie`) rely on that.

### The upstream request and response relay (lines 122-153)

```js
// lines 122-133
const upstream = http.request(
  { host: upstreamHost, port: upstreamPort, method: req.method, path: req.url, headers, agent, timeout: 120000 },
  (ures) => {
    const outHeaders = {};
    for (let i = 0; i < ures.rawHeaders.length; i += 2) {
      const k = ures.rawHeaders[i];
      if (HOP_BY_HOP.has(k.toLowerCase())) continue;
      const v = ures.rawHeaders[i + 1];
      if (outHeaders[k] !== undefined) outHeaders[k] = [].concat(outHeaders[k], v);
      else outHeaders[k] = v;
    }
    res.writeHead(ures.statusCode, ures.statusMessage, outHeaders);
```

- `path: req.url` forwards the path **and** query string untouched. No `Host` rewriting happens either: the student's `Host` header (the zrok hostname) reaches the CTF app, which is what a transparent proxy should do. Apps that validate `Host` must accept the public hostname.
- `timeout: 120000` is a socket *inactivity* timeout (2 minutes). Node only emits `'timeout'`; the handler at line 155 turns it into an error.
- On the way back, hop-by-hop headers are stripped and everything else is copied with original casing and duplicates. This is what keeps **multiple `Set-Cookie` lines** intact (an array value is written as repeated headers).
- `res.writeHead(status, statusMessage, headers)`: the status text is also relayed.

```js
// lines 135-151
const resChunks = [];
let resCap = 0;
let resLen = 0;
ures.on('data', (c) => {
  resLen += c.length;
  if (!ignored && resCap < MAX_CAPTURE) {
    const slice = c.subarray(0, MAX_CAPTURE - resCap);
    resChunks.push(slice);
    resCap += slice.length;
  }
});
ures.on('end', () => finish(ures.statusCode, ures.headers, Buffer.concat(resChunks), resLen));
ures.on('error', (err) => {
  finish(ures.statusCode, ures.headers, Buffer.concat(resChunks), resLen, err.message);
  res.destroy();
});
ures.pipe(res);
```

- Same capture pattern as the request side. `size` reported to `onEvent` is `resLen`, the full streamed length, so the dashboard shows the true response size even when only 64 KiB was kept.
- `ures.pipe(res)` streams the body; the client starts receiving bytes before the upstream finishes, so a 100 MB download does not sit in memory.
- A mid-body upstream error (`'error'` on `ures`) records the event with whatever was captured plus the error text, then destroys the client socket so the client sees a truncated response rather than a hung connection.

### Error paths and lifetime wiring (lines 155-168)

```js
// lines 155-168
upstream.on('timeout', () => upstream.destroy(new Error('upstream timeout')));
upstream.on('error', (err) => {
  log('error', `upstream error for ${req.method} ${req.url}: ${err.message}`);
  if (!res.headersSent) {
    res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('502 Bad Gateway - the CTF app did not answer. (ctf-watch proxy)');
  } else res.destroy();
  finish(502, {}, Buffer.alloc(0), 0, err.message);
});
req.on('error', () => upstream.destroy());
res.on('close', () => {
  if (!finished) upstream.destroy();
});
req.pipe(upstream);
```

- Timeout becomes an error with a readable message, which flows into the generic error handler below.
- Upstream errors (connection refused because the app is down, reset, timeout): if nothing was sent yet the student gets a plain-text 502 (the README troubleshooting table refers to this text); if headers were already sent the only option is to cut the connection. In both cases a `502` event is recorded with `error` set. Gotcha: when the error happens after headers were sent, the student actually saw the upstream's real status, but the recorded event says 502. The `finished` flag means the event is recorded only once even if `ures` also emits `'error'`.
- `req.on('error')`: the client's request stream broke (reset while uploading) — abort the upstream request.
- `res.on('close')` while `!finished`: the client went away before the exchange completed (closed the tab, `curl` killed). The upstream request is destroyed so the CTF app is not kept busy on behalf of nobody. If that destroy surfaces as an `'error'` on `upstream`, the error handler above records a 502 event (`headersSent` decides whether it writes a 502 body or just destroys).
- `req.pipe(upstream)` is last: nothing is written to the upstream until all handlers are installed.

### WebSocket / upgrade tunnel (lines 171-211)

```js
// lines 172-186
function tunnel(req, socket, head) {
  const ts = Date.now();
  const target = currentUpstream(req);
  if (!target) {
    socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }
  const up = net.connect(target.port, target.host, () => {
    let raw = `${req.method} ${req.url} HTTP/${req.httpVersion}\r\n`;
    for (let i = 0; i < req.rawHeaders.length; i += 2) raw += `${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}\r\n`;
    raw += `X-Forwarded-For: ${req.socket.remoteAddress || ''}\r\n\r\n`;
    up.write(raw);
    if (head && head.length) up.write(head);
    up.pipe(socket);
    socket.pipe(up);
```

- Node hands `'upgrade'` requests to a separate handler with the raw socket. The proxy does not parse the WebSocket protocol at all: it re-serialises the original request line and headers byte-for-byte onto a plain TCP connection to the app and then pipes both directions. Everything the app answers (101 or a rejection) goes straight back.
- `head` is any bytes the client sent after the headers before Node handed over the socket (rare, but must be forwarded or the first frame is lost).
- `X-Forwarded-For` is **appended as a new line** here, not merged. If the client already sent one, the app receives two `X-Forwarded-For` headers.
- Gotchas compared to `handle`: the gate, `preRequest` (blocked students) and `shouldIgnore` are **not** applied to upgrades, and the decoy decision (`getTargetFor`) is. A blocked student can still open a WebSocket to the app.

```js
// lines 187-210
    try {
      onEvent({ ts, req, method: 'UPGRADE', url: req.url || '/', pathOnly: (req.url || '/').split('?')[0], status: 101, size: 0,
        latencyMs: Date.now() - ts, reqLen: 0, reqBuf: Buffer.alloc(0), resHeaders: {}, resBuf: Buffer.alloc(0), error: null });
    } catch (err) {
      log('error', `event handler failed: ${err.message}`);
    }
  });
  up.on('error', () => socket.destroy());
  socket.on('error', () => up.destroy());
  socket.on('close', () => up.destroy());
  up.on('close', () => socket.destroy());
}
```

- One event is recorded per tunnel, at connect time, with `status: 101` **assumed** (the app's real answer is never inspected). `latencyMs` is the TCP connect time, not a response time. Frames exchanged later are invisible to the monitor.
- The four error/close handlers tie the two sockets' lifetimes together: whichever side dies takes the other with it, so no half-open tunnel leaks.

### Server creation (lines 213-223)

```js
// lines 213-223
const server = http.createServer(handle);
server.on('upgrade', tunnel);
server.on('clientError', (err, socket) => {
  if (socket.writable) socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});
server.keepAliveTimeout = 65000;
server.listen(port, bind, () => {
  log('info', `proxy listening on http://${bind}:${port} -> ${getTarget() || '(no CTF selected yet)'}`);
});
return server;
```

- `clientError` fires for unparsable requests (fuzzers sending garbage). Without this handler Node would just close the socket; writing a 400 is friendlier and avoids noisy stack traces.
- `keepAliveTimeout = 65000`: idle client connections are kept 65 s. This is deliberately longer than the 60 s many tunnels/load balancers (zrok included) use, so the proxy is never the side that closes an idle connection first (which produces spurious 502s at the tunnel).
- The returned server is not used by `server.js`; it is returned for completeness/tests.

## Interactions

| direction | module/file | what crosses the boundary |
|---|---|---|
| in | `server.js` → `createProxy(opts)` | `getTarget()` (string URL or null), `getTargetFor(req)` (decoy URL or null), `bind`, `port`, `shouldIgnore(pathOnly)` (bool), `onEvent(exchange)`, `gate` (NameGate), `preRequest(req, res)` (bool). |
| in | `namegate.js` → `gate.handle(req, res)` | Returns `true` when the gate consumed the request. |
| out | `server.js` → `onEvent(exchange)` | The exchange object described in "Data it owns"; the `req` field carries the live `IncomingMessage`. |
| out | network → CTF app | Forwarded HTTP request (plus `X-Forwarded-For`), raw TCP tunnel for upgrades. |
| out | network → student | Relayed response; 503 no-target page; 502 text on upstream failure; 400 on malformed request. |
| out | `util.js` → `log` | Info line at listen, error lines for upstream failures and `onEvent` exceptions. |

## Changing it safely

| Likely change | Where |
|---|---|
| Keep more (or less) of the bodies for inspection | `MAX_CAPTURE` (line 10). Memory per in-flight request is up to 2 × `MAX_CAPTURE`. The detector reads request bodies and `classify()` only looks at the first 8 KiB anyway. |
| Strip or add a request header before forwarding (e.g. remove `Accept-Encoding` so the app sends plain text) | The header copy loop at lines 68-74 (add another `if (lk === ...) continue;`). Removing `Accept-Encoding` would make `decodeBody` unnecessary but increases upstream bandwidth. |
| Apply the gate / block list to WebSockets too | `tunnel()` (line 172): call `preRequest`-like logic before `net.connect`. Note the upgrade handler only has a raw socket, not a `res`, so the 403 would have to be written by hand like the 503 at line 176. |
| Change the no-target page or the 502 text | `NO_TARGET_PAGE` (line 27), line 160. The README's troubleshooting table quotes the 502 text. |
| Change upstream timeouts or connection pooling | `timeout: 120000` (line 123), `agent` (line 34), `keepAliveTimeout` (line 218). |

Tests: **there is no unit test for `proxy.js`.** Nothing in `proxy/test/` starts the proxy. Behaviour is only verified by running the stack (Playground tab: mock app + simulator, or `curl` through the proxy as in the exercises). Pieces that feed it are covered elsewhere: `ports.test.js` → `validateTarget normalises and rejects bad input` guarantees the URL shape `currentUpstream` parses; `core.test.js` covers what `onEvent` does with the exchange.

## Exercises

1. **See the 503 page.** Start the monitor with no target (CTFs tab → disconnect, or a fresh database), then:
   `curl -i http://127.0.0.1:8888/anything`
   Expect `HTTP/1.1 503`, `Retry-After: 10` and the "not open yet" HTML.

2. **Watch the capture limit.** With the Playground mock app running as target, send a 100 KB body and check the Requests view / `logs/events-*.jsonl`:
   `head -c 100000 /dev/zero | tr '\0' 'a' | curl -s -X POST --data-binary @- -H 'Content-Type: text/plain' http://127.0.0.1:8888/api/login -o /dev/null -w '%{http_code}\n'`
   The stored event has no parsed `body` (not JSON), but `reqLen` in the proxy was 100000 while only 65536 bytes were captured. Add a temporary `log('debug', reqLen, reqCap)` in `finish` to see both numbers, then remove it.

3. **Prove headers are relayed verbatim.** Point the target at a tiny server that echoes headers, e.g. `node -e "require('http').createServer((q,s)=>s.end(JSON.stringify(q.headers))).listen(3999,'127.0.0.1')"`, select `http://127.0.0.1:3999` in the CTFs tab and run
   `curl -s -H 'X-Weird-Case: 1' -H 'X-Forwarded-For: 10.9.9.9' http://127.0.0.1:8888/`
   The echoed JSON shows `x-forwarded-for: "10.9.9.9, 127.0.0.1"` (appended) and your custom header.

## Quick reference

| Export | Signature | Description |
|---|---|---|
| `createProxy` | `createProxy({ getTarget, getTargetFor, bind, port, shouldIgnore, onEvent, gate, preRequest }) → http.Server` | Starts the listening reverse proxy; every finished exchange is passed to `onEvent`. |

Internal (not exported): `decodeBody(encoding, buf)` → decompressed `Buffer` (tolerates truncation); `currentUpstream(req)` → `{ url, host, port } | null`; `handle(req, res)`; `tunnel(req, socket, head)`.

## Update: issue 1 fixed (forwarded headers)

When the peer is trusted (`util.isTrustedPeer`), the proxy appends its address to the incoming `X-Forwarded-For` as before. When the peer is an untrusted direct client, the incoming `X-Forwarded-For` and `X-Real-IP` are deleted and `X-Forwarded-For` is set to the real socket address, so the CTF app never sees a forged chain either. The WebSocket tunnel does the same.

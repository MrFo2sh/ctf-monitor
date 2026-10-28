'use strict';
// Transparent logging reverse proxy. Forwards everything to the CTF app unchanged
// (headers, cookies, redirects, status codes, WebSockets) and reports each exchange to onEvent().

const http = require('http');
const net = require('net');
const zlib = require('zlib');
const { log } = require('./util');

const MAX_CAPTURE = 64 * 1024; // bytes of request / response body we keep for inspection
const HOP_BY_HOP = new Set(['transfer-encoding', 'connection', 'keep-alive', 'proxy-connection', 'upgrade', 'te', 'trailer']);

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

const NO_TARGET_PAGE = '<!doctype html><html><head><meta charset="utf-8"><title>CTF not ready</title></head><body style="font-family:system-ui;background:#0b0f14;color:#e6edf3;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="color:#fab219">The CTF is not open yet</h1><p>The organizer has not connected a challenge to this link. Please try again in a moment.</p></div></body></html>';

/**
 * createProxy({ getTarget, bind, port, ... })
 * getTarget() returns the current upstream base URL (http://host:port) or null when no CTF is selected.
 */
function createProxy({ getTarget, getTargetFor, bind, port, shouldIgnore, onEvent, gate, preRequest }) {
  const agent = new http.Agent({ keepAlive: true, maxSockets: 512 });
  const parsed = new Map(); // url -> { url, host, port }
  // getTargetFor(req) may route this particular request elsewhere (the decoy); otherwise the real CTF
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
    const upstreamHost = up.host;
    const upstreamPort = up.port;
    const startNs = process.hrtime.bigint();
    const ts = Date.now();
    const pathOnly = (req.url || '/').split('?')[0];
    const ignored = shouldIgnore ? shouldIgnore(pathOnly) : false;

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

    let finished = false;
    const finish = (status, resHeaders, resBuf, resLen, error) => {
      if (finished || ignored) return;
      finished = true;
      const latencyMs = Number(process.hrtime.bigint() - startNs) / 1e6;
      let decoded = Buffer.alloc(0);
      if (resBuf && resBuf.length) decoded = decodeBody(resHeaders['content-encoding'], resBuf);
      try {
        onEvent({
          ts,
          req,
          method: req.method,
          url: req.url || '/',
          pathOnly,
          status,
          size: resLen,
          latencyMs: Math.round(latencyMs * 10) / 10,
          reqLen,
          reqBuf: Buffer.concat(reqChunks),
          resHeaders: resHeaders || {},
          resBuf: decoded,
          error: error || null,
        });
      } catch (err) {
        log('error', `event handler failed: ${err.stack || err}`);
      }
    };

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
      }
    );

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
  }

  // WebSocket / HTTP upgrade: raw TCP tunnel to the app
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
      try {
        onEvent({
          ts,
          req,
          method: 'UPGRADE',
          url: req.url || '/',
          pathOnly: (req.url || '/').split('?')[0],
          status: 101,
          size: 0,
          latencyMs: Date.now() - ts,
          reqLen: 0,
          reqBuf: Buffer.alloc(0),
          resHeaders: {},
          resBuf: Buffer.alloc(0),
          error: null,
        });
      } catch (err) {
        log('error', `event handler failed: ${err.message}`);
      }
    });
    up.on('error', () => socket.destroy());
    socket.on('error', () => up.destroy());
    socket.on('close', () => up.destroy());
    up.on('close', () => socket.destroy());
  }

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
}

module.exports = { createProxy };

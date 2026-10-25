'use strict';
// Dashboard server: static pages + JSON API + WebSocket feed + organizer actions. Bound to 127.0.0.1 ONLY.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { log } = require('./util');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

function readJson(req, limit = 16 * 1024) {
  return new Promise((resolve) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n <= limit) chunks.push(c);
    });
    req.on('end', () => {
      try {
        resolve(JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'));
      } catch {
        resolve(null);
      }
    });
    req.on('error', () => resolve(null));
  });
}

function createDashboard({ port, store, admin, getRawConfig }) {
  const bind = '127.0.0.1'; // deliberately not configurable

  const json = (res, status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(obj));
  };
  const page = (res, file) => {
    fs.readFile(path.join(PUBLIC_DIR, file), (err, data) => {
      if (err) {
        res.writeHead(500);
        return res.end(`${file} missing`);
      }
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(data);
    });
  };

  const server = http.createServer(async (req, res) => {
    const url = (req.url || '/').split('?')[0];
    if (url === '/' || url === '/index.html') return page(res, 'index.html');
    if (url === '/requests' || url === '/requests.html') return page(res, 'requests.html');
    if (url === '/api/state') return json(res, 200, store.snapshot());
    if (url === '/api/stats') return json(res, 200, store.stats());
    if (url === '/api/config') return json(res, 200, getRawConfig());
    if (url === '/api/admin' && req.method === 'GET') return json(res, 200, admin.list());
    if (url.startsWith('/api/admin/') && req.method === 'POST') {
      const body = await readJson(req);
      if (!body || typeof body.student !== 'string') return json(res, 400, { error: 'student required' });
      try {
        if (url === '/api/admin/block') return json(res, 200, { ok: true, ...admin.block(body.student) });
        if (url === '/api/admin/unblock') {
          admin.unblock(body.student);
          return json(res, 200, { ok: true });
        }
        if (url === '/api/admin/rename') return json(res, 200, { ok: true, name: admin.rename(body.student, String(body.newName || '')) });
        if (url === '/api/admin/require-rename') return json(res, 200, { ok: true, ...admin.requireRename(body.student) });
      } catch (err) {
        return json(res, 400, { error: err.message });
      }
      return json(res, 404, { error: 'unknown action' });
    }
    if (url === '/healthz') {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      return res.end('ok');
    }
    res.writeHead(404, { 'Content-Type': 'text/plain' });
    res.end('not found');
  });

  const wss = new WebSocketServer({ server, path: '/ws', maxPayload: 1024 });

  const send = (ws, obj) => {
    if (ws.readyState === ws.OPEN) ws.send(JSON.stringify(obj));
  };
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
    const { req, ...rest } = ev;
    broadcast({ type: 'event', event: rest });
    if (alert) broadcast({ type: 'alert', alert });
  });
  store.onReset(() => {
    if (wss.clients.size) broadcast({ type: 'snapshot', ...store.snapshot() });
  });

  const statsTimer = setInterval(() => {
    if (wss.clients.size) broadcast({ type: 'stats', stats: store.stats() });
  }, 1000);
  statsTimer.unref();

  server.listen(port, bind, () => {
    log('info', `dashboard on http://${bind}:${port}  (local only)`);
  });
  return server;
}

module.exports = { createDashboard };

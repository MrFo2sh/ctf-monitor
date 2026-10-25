'use strict';
// Dashboard server: static page + JSON API + WebSocket feed. Bound to 127.0.0.1 ONLY.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { log } = require('./util');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');

function createDashboard({ port, store, getRawConfig }) {
  const bind = '127.0.0.1'; // deliberately not configurable

  const server = http.createServer((req, res) => {
    const url = (req.url || '/').split('?')[0];
    if (url === '/' || url === '/index.html') {
      fs.readFile(path.join(PUBLIC_DIR, 'index.html'), (err, data) => {
        if (err) {
          res.writeHead(500);
          return res.end('index.html missing');
        }
        res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
        res.end(data);
      });
      return;
    }
    if (url === '/api/state') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify(store.snapshot()));
    }
    if (url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify(store.stats()));
    }
    if (url === '/api/config') {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      return res.end(JSON.stringify(getRawConfig()));
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

'use strict';
// Dashboard server: login, pages, JSON API, authenticated WebSocket feed, organizer actions, query, export/import/replay.

const http = require('http');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');
const { compile, QueryError } = require('./query');
const { NameGate } = require('./namegate');
const { log, clientIp } = require('./util');

const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const PAGES = new Set(['/', '/live', '/alerts', '/students', '/query', '/requests', '/admin', '/ctfs']);
const CSRF_HEADER = 'x-requested-with';

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

const SECURITY_HEADERS = {
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cache-Control': 'no-store',
};

function createDashboard({ port, bind, store, admin, auth, db, replay, newCtf, getRawConfig }) {
  bind = bind || '127.0.0.1';
  const json = (res, status, obj) => {
    res.writeHead(status, { 'Content-Type': 'application/json', ...SECURITY_HEADERS });
    res.end(JSON.stringify(obj));
  };
  const page = (res, file, status = 200) => {
    fs.readFile(path.join(PUBLIC_DIR, file), (err, data) => {
      if (err) {
        res.writeHead(500, SECURITY_HEADERS);
        return res.end(`${file} missing`);
      }
      res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8', ...SECURITY_HEADERS });
      res.end(data);
    });
  };
  const redirect = (res, to) => {
    res.writeHead(302, { Location: to, ...SECURITY_HEADERS });
    res.end();
  };

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

    // ---- public: login
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

    // ---- everything else needs a session
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

    // ---- pages (one SPA, the path picks the initial view)
    if (PAGES.has(url) || url.startsWith('/students/')) return page(res, 'app.html');

    // ---- session
    if (url === '/api/logout' && req.method === 'POST') {
      const m = /(?:^|;\s*)ctfw_sid=([a-f0-9]{64})/.exec(req.headers.cookie || '');
      auth.logout(m ? m[1] : null);
      res.writeHead(200, { 'Content-Type': 'application/json', 'Set-Cookie': auth.clearCookie(), ...SECURITY_HEADERS });
      return res.end('{"ok":true}');
    }
    if (url === '/api/me') return json(res, 200, { ...user, ctf: db.activeCtf(), replay: replay.status() });

    // ---- live state
    if (url === '/api/state') return json(res, 200, store.snapshot());
    if (url === '/api/stats') return json(res, 200, store.stats());
    if (url === '/api/config') return json(res, 200, getRawConfig());

    // ---- alerts
    if (url === '/api/alerts' && req.method === 'GET') {
      const level = qs.get('level') || undefined;
      const ack = qs.has('ack') ? Number(qs.get('ack')) : undefined;
      const ctfId = qs.get('ctf') ? Number(qs.get('ctf')) : undefined;
      db.flush();
      return json(res, 200, db.alerts({ ctfId, level, ack, limit: qs.get('limit') || 500 }).map((a) => ({ ...a, data: safeJson(a.data) })));
    }
    if (url === '/api/alerts/ack' && req.method === 'POST') {
      const body = await readJson(req).catch(() => ({}));
      const ids = Array.isArray(body.ids) ? body.ids : [];
      db.flush();
      db.ackAlerts(ids);
      for (const a of store.alerts) if (ids.includes(a.id) || (body.all && !a.ack)) a.ack = 1;
      if (body.all) db.db.prepare('UPDATE alerts SET ack = 1 WHERE ctf_id = ?').run(db.ctfId);
      return json(res, 200, { ok: true });
    }

    // ---- students
    if (url === '/api/students') return json(res, 200, store.stats().students);
    if (url.startsWith('/api/students/')) {
      const name = decodeURIComponent(url.slice('/api/students/'.length));
      const live = store.students.get(name) || null;
      const detail = db.studentDetail(name, qs.get('ctf') ? Number(qs.get('ctf')) : undefined);
      return json(res, 200, { ...detail, live: live ? { ...live, blocked: store.isBlocked(name), renamePending: store.renamePending(name) } : null });
    }

    // ---- organizer actions
    if (url === '/api/admin' && req.method === 'GET') return json(res, 200, { ...admin.list(), dashboardBlockedIps: [...auth.blockedIps.entries()].map(([ip, b]) => ({ ip, ...b })) });
    if (url.startsWith('/api/admin/') && req.method === 'POST') {
      if (adminOnly()) return;
      const body = await readJson(req).catch(() => null);
      if (!body) return json(res, 400, { error: 'bad json' });
      try {
        switch (url) {
          case '/api/admin/block': return json(res, 200, { ok: true, ...admin.block(String(body.student || '')) });
          case '/api/admin/unblock': admin.unblock(String(body.student || '')); return json(res, 200, { ok: true });
          case '/api/admin/rename': return json(res, 200, { ok: true, name: admin.rename(String(body.student || ''), String(body.newName || '')) });
          case '/api/admin/require-rename': return json(res, 200, { ok: true, ...admin.requireRename(String(body.student || '')) });
          case '/api/admin/unblock-ip': auth.unblockIp(String(body.ip || '')); delete admin.state.blocked[`ip:${body.ip}`]; admin.save(); return json(res, 200, { ok: true });
          default: return json(res, 404, { error: 'unknown action' });
        }
      } catch (err) {
        return json(res, 400, { error: err.message });
      }
    }

    // ---- ctfs
    if (url === '/api/ctfs' && req.method === 'GET') return json(res, 200, { active: db.activeCtf(), list: db.listCtfs() });
    if (url === '/api/ctfs/new' && req.method === 'POST') {
      if (adminOnly()) return;
      const body = await readJson(req).catch(() => ({}));
      return json(res, 200, { ok: true, ctf: newCtf(NameGate.clean(body.name) || undefined) });
    }

    // ---- query
    if (url === '/api/query' && req.method === 'POST') {
      const body = await readJson(req).catch(() => ({}));
      try {
        const q = compile(String(body.q || ''), { ctfId: body.ctf ? Number(body.ctf) : db.ctfId });
        const rows = db.runSql(q.sql, q.params, body.limit || 1000);
        return json(res, 200, { ok: true, rows, count: rows.length, sql: q.sql, params: q.params });
      } catch (err) {
        return json(res, err instanceof QueryError ? 400 : 500, { error: err.message });
      }
    }

    // ---- export / import / replay
    if (url === '/api/export') {
      try {
        const id = Number(qs.get('ctf')) || db.ctfId;
        const dump = db.exportCtf(id);
        res.writeHead(200, { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="ctf-${id}-${dump.ctf.name.replace(/[^a-z0-9_-]+/gi, '_')}.json"`, ...SECURITY_HEADERS });
        return res.end(JSON.stringify(dump));
      } catch (err) {
        return json(res, 400, { error: err.message });
      }
    }
    if (url === '/api/import' && req.method === 'POST') {
      if (adminOnly()) return;
      try {
        const data = await readJson(req, 200 * 1024 * 1024);
        return json(res, 200, { ok: true, ctf: db.importCtf(data) });
      } catch (err) {
        return json(res, 400, { error: err.message });
      }
    }
    if (url === '/api/replay' && req.method === 'GET') return json(res, 200, replay.status());
    if (url === '/api/replay' && req.method === 'POST') {
      if (adminOnly()) return;
      const body = await readJson(req).catch(() => ({}));
      try {
        return json(res, 200, { ok: true, ...replay.start(Number(body.ctf), body.speed) });
      } catch (err) {
        return json(res, 400, { error: err.message });
      }
    }
    if (url === '/api/replay/stop' && req.method === 'POST') {
      if (adminOnly()) return;
      replay.stop();
      return json(res, 200, { ok: true });
    }

    json(res, 404, { error: 'not found' });
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch((err) => {
      log('error', `dashboard: ${err.stack || err}`);
      if (!res.headersSent) json(res, 500, { error: 'internal error' });
    });
  });

  // ---- websocket (session checked on upgrade)
  const wss = new WebSocketServer({ noServer: true, maxPayload: 1024 });
  server.on('upgrade', (req, socket, head) => {
    const url = (req.url || '').split('?')[0];
    if (url !== '/ws' || auth.isIpBlocked(clientIp(req)) || !auth.sessionFromRequest(req)) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      return socket.destroy();
    }
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  });
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
  const statsTimer = setInterval(() => wss.clients.size && broadcast({ type: 'stats', stats: store.stats(), replay: replay.status() }), 1000);
  statsTimer.unref();

  server.listen(port, bind, () => log('info', `dashboard on http://${bind}:${port}${bind === '127.0.0.1' ? '  (local only)' : ''}`));
  return server;
}

function safeJson(s) {
  if (typeof s !== 'string') return s;
  try {
    return JSON.parse(s);
  } catch {
    return s;
  }
}

module.exports = { createDashboard };

'use strict';
// A tiny FAKE CTF app with deliberate IDOR bugs. Only used by `./start.sh --demo`.
// It stands in for the real challenge so the dashboard can be tested without touching the real one.

const http = require('http');
const crypto = require('crypto');

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

const sessions = new Map(); // sid -> user

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
function readBody(req) {
  return new Promise((resolve) => {
    const c = [];
    req.on('data', (d) => c.push(d));
    req.on('end', () => {
      const t = Buffer.concat(c).toString();
      try {
        if ((req.headers['content-type'] || '').includes('json')) return resolve(JSON.parse(t));
        const o = {};
        for (const [k, v] of new URLSearchParams(t)) o[k] = v;
        resolve(o);
      } catch {
        resolve({});
      }
    });
  });
}

const PAGE = (title, body) => `<!doctype html><html><head><title>${title}</title><link rel="stylesheet" href="/static/style.css"></head><body><h1>${title}</h1>${body}<script src="/static/app.js"></script></body></html>`;

http
  .createServer(async (req, res) => {
    const url = new URL(req.url, 'http://x');
    const p = url.pathname;
    const sid = cookies(req).session;
    const user = sid && sessions.get(sid);

    if (p === '/' && req.method === 'GET') return send(res, 200, PAGE('Shop CTF (demo)', '<form method="post" action="/login"><input name="username" placeholder="username"><input name="password" type="password"><button>login</button></form>'));
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
  })
  .listen(PORT, HOST, () => console.log(`mock CTF app on http://${HOST}:${PORT}`));

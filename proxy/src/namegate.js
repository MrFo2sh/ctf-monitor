'use strict';
// Optional "what's your name?" page (NAME_GATE=1).
// The first time a BROWSER opens the CTF through the proxy, it gets a small page asking for a name.
// The name is stored in a signed cookie and used as the student's identity on the dashboard.
// API calls, curl, scripts and anything that is not a normal page navigation are never blocked.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseCookies, log } = require('./util');

const GATE_PATH = '/__ctfwatch/name';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days

class NameGate {
  constructor({ secretFile, cookie, title, strict }) {
    this.cookie = cookie || 'ctfw_name';
    this.title = title || 'Welcome to the CTF';
    this.strict = !!strict; // strict: block EVERY request without a valid name cookie (not just page loads)
    this.secret = this.loadSecret(secretFile);
  }

  loadSecret(file) {
    try {
      if (file && fs.existsSync(file)) return fs.readFileSync(file, 'utf8').trim();
      const s = crypto.randomBytes(32).toString('hex');
      if (file) {
        fs.mkdirSync(path.dirname(file), { recursive: true });
        fs.writeFileSync(file, s, { mode: 0o600 });
      }
      return s;
    } catch (err) {
      log('error', `name gate: could not persist secret (${err.message}) - using a temporary one`);
      return crypto.randomBytes(32).toString('hex');
    }
  }

  sign(name) {
    return crypto.createHmac('sha256', this.secret).update(name).digest('base64url').slice(0, 24);
  }

  // Returns the student's name if the request carries a valid gate cookie, else null.
  nameFrom(req) {
    const raw = parseCookies(req.headers.cookie)[this.cookie];
    if (!raw) return null;
    let v;
    try {
      v = decodeURIComponent(raw);
    } catch {
      return null;
    }
    const i = v.lastIndexOf('.');
    if (i <= 0) return null;
    const name = v.slice(0, i);
    const sig = v.slice(i + 1);
    const want = this.sign(name);
    if (sig.length !== want.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(want))) return null;
    return name;
  }

  static clean(name) {
    const n = String(name || '')
      .replace(/[^\p{L}\p{N} _.\-]/gu, '')
      .trim()
      .slice(0, 32);
    return n.length >= 2 ? n : null;
  }

  isNavigation(req) {
    if (req.method !== 'GET') return false;
    const accept = String(req.headers.accept || '');
    if (!accept.includes('text/html')) return false;
    const dest = req.headers['sec-fetch-dest'];
    if (dest && dest !== 'document') return false;
    if (req.headers['x-requested-with']) return false;
    return true;
  }

  /**
   * Called for every proxied request. Returns true if the gate handled (answered) the request.
   */
  handle(req, res) {
    const pathOnly = (req.url || '/').split('?')[0];

    if (pathOnly === GATE_PATH) {
      if (req.method !== 'POST') {
        res.writeHead(405).end();
        return true;
      }
      const chunks = [];
      req.on('data', (c) => chunks.length < 64 && chunks.push(c));
      req.on('end', () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8').slice(0, 4096));
        const name = NameGate.clean(form.get('name'));
        let next = form.get('next') || '/';
        if (!next.startsWith('/') || next.startsWith('//')) next = '/';
        if (!name) {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
          return res.end(this.page(next, 'Please enter a name (2-32 letters or numbers).'));
        }
        const value = encodeURIComponent(`${name}.${this.sign(name)}`);
        res.writeHead(302, {
          Location: next,
          'Set-Cookie': `${this.cookie}=${value}; Path=/; Max-Age=${MAX_AGE}; SameSite=Lax`,
          'Cache-Control': 'no-store',
        });
        res.end();
        log('info', `name gate: new student "${name}"`);
      });
      return true;
    }

    if (this.nameFrom(req)) return false;

    if (this.isNavigation(req)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(this.page(req.url || '/'));
      return true;
    }
    if (!this.strict) return false;

    // strict mode: API calls, form posts, scripts... without the name cookie are refused by the proxy
    const msg = 'ctf-watch: open the CTF in your browser and enter your name first (then retry; tools must send the ctfw_name cookie)';
    const wantsJson = String(req.headers.accept || '').includes('json') || String(req.headers['content-type'] || '').includes('json');
    res.writeHead(428, { 'Content-Type': wantsJson ? 'application/json' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(wantsJson ? JSON.stringify({ error: msg }) : msg + '\n');
    return true;
  }

  page(next, error) {
    const esc = (s) => String(s).replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(this.title)}</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0f14;color:#e6edf3;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  form{background:#111820;border:1px solid #1f2a36;border-radius:10px;padding:32px 28px;width:min(92vw,380px);box-shadow:0 20px 60px rgba(0,0,0,.5)}
  h1{font-size:20px;margin:0 0 6px}p{margin:0 0 18px;color:#8b98a5;font-size:14px}
  input{width:100%;box-sizing:border-box;padding:12px 14px;font-size:16px;border-radius:6px;border:1px solid #2a3847;background:#0b0f14;color:#e6edf3}
  input:focus{outline:none;border-color:#3987e5}
  button{margin-top:14px;width:100%;padding:12px;font-size:16px;font-weight:600;border:0;border-radius:6px;background:#3987e5;color:#fff;cursor:pointer}
  .err{color:#fab219;font-size:13px;margin:8px 0 0}
</style></head><body>
<form method="post" action="${GATE_PATH}">
  <h1>${esc(this.title)}</h1>
  <p>Before you start, tell us who you are. Use the name your instructor knows you by.</p>
  <input name="name" maxlength="32" placeholder="Your name" autofocus required autocomplete="off">
  <input type="hidden" name="next" value="${esc(next)}">
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <button type="submit">Start</button>
</form></body></html>`;
  }
}

module.exports = { NameGate, GATE_PATH };

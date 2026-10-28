'use strict';
// The gate: a form the student fills in the first time they open the CTF in a browser.
// Which fields are asked is configured in the dashboard (Gate tab). "username" is always there and is
// the student's identity; the other answers are kept as the student's profile.
// Only normal browser page loads are gated; API calls, curl, scripts and tools are never blocked.

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { parseCookies, clientIp, log } = require('./util');

const GATE_PATH = '/__ctfwatch/name';
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days
const TYPES = ['text', 'number', 'email', 'password', 'select'];

const DEFAULT_CONFIG = {
  enabled: true,
  strict: true, // nothing reaches the CTF without the form: curl / scripts / crawlers are refused too
  queue: true, // after the form, students wait until the organizer approves them (Queue tab)
  title: 'Welcome to the CTF',
  intro: 'Before you start, tell us who you are. Use the name your instructor knows you by.',
  button: 'Start',
  waitTitle: 'Almost there',
  waitText: 'Thanks {name}! The organizer will let you in shortly. This page continues by itself once you are approved.',
  fields: [{ key: 'username', label: 'Your name', type: 'text', required: true, placeholder: 'Your name', locked: true }],
};
const STATUS_PATH = '/__ctfwatch/status';
const STREAM_PATH = '/__ctfwatch/wait'; // server-sent events: the waiting page learns about the decision instantly

function cleanKey(k) {
  return String(k || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 24);
}

// Validates a config coming from the dashboard; always returns a usable config.
function normalizeConfig(raw) {
  const cfg = { ...DEFAULT_CONFIG, ...(raw && typeof raw === 'object' ? raw : {}) };
  cfg.enabled = cfg.enabled !== false;
  cfg.strict = cfg.strict !== false;
  cfg.queue = cfg.queue !== false;
  cfg.title = String(cfg.title || DEFAULT_CONFIG.title).slice(0, 80);
  cfg.intro = String(cfg.intro ?? DEFAULT_CONFIG.intro).slice(0, 400);
  cfg.button = String(cfg.button || DEFAULT_CONFIG.button).slice(0, 30);
  cfg.waitTitle = String(cfg.waitTitle || DEFAULT_CONFIG.waitTitle).slice(0, 80);
  cfg.waitText = String(cfg.waitText || DEFAULT_CONFIG.waitText).slice(0, 400);
  const seen = new Set();
  const fields = [];
  for (const f of Array.isArray(cfg.fields) ? cfg.fields : []) {
    const key = cleanKey(f && f.key);
    if (!key || seen.has(key) || key === 'next') continue;
    seen.add(key);
    fields.push({
      key,
      label: String((f && f.label) || key).slice(0, 60),
      type: TYPES.includes(f && f.type) ? f.type : 'text',
      required: key === 'username' ? true : !!(f && f.required),
      placeholder: String((f && f.placeholder) || '').slice(0, 60),
      options: f && f.type === 'select' ? String(f.options || '').split(/[\n,]/).map((s) => s.trim()).filter(Boolean).slice(0, 50) : undefined,
      locked: key === 'username',
    });
  }
  // username is always first, text, required and locked
  const u = fields.find((f) => f.key === 'username');
  const username = { ...DEFAULT_CONFIG.fields[0], ...(u || {}), type: 'text', required: true, locked: true, options: undefined };
  if (!u || !u.label || u.label === 'username') username.label = DEFAULT_CONFIG.fields[0].label;
  cfg.fields = [username, ...fields.filter((f) => f.key !== 'username')].slice(0, 12);
  return cfg;
}

class NameGate {
  /**
   * @param opts { secretFile, cookie, getConfig: () => config, onProfile: (name, profile) => void,
   *               approvals: Approvals (the admission queue), onEnqueue: (name, info) => void }
   */
  constructor({ secretFile, cookie, getConfig, onProfile, approvals, onEnqueue }) {
    this.cookie = cookie || 'ctfw_name';
    this.getConfig = getConfig || (() => DEFAULT_CONFIG);
    this.onProfile = onProfile || null;
    this.approvals = approvals || null;
    this.onEnqueue = onEnqueue || null;
    this.secret = this.loadSecret(secretFile);
    this.ipNames = new Map(); // ip -> { names:Set, last }
    this.revoked = new Map(); // rawName -> ts   ("ask to rename")
    this.onRename = null; // (oldRawName, newName) => void
    this.onIpNamed = null; // (ip, name) => void
    this.waiters = new Map(); // rawName -> Set(res) of open event streams (waiting pages)
    if (this.approvals) this.approvals.onChange((names) => this.notifyWaiters(names));
    this.heartbeat = setInterval(() => {
      for (const set of this.waiters.values()) for (const res of set) res.write(': ping\n\n');
    }, 15000);
    if (this.heartbeat.unref) this.heartbeat.unref();
  }

  // push the new status to every open waiting page of these students
  notifyWaiters(names) {
    for (const n of names || []) {
      const set = this.waiters.get(n);
      if (!set) continue;
      const status = this.approvals ? this.approvals.status(n) || 'none' : 'approved';
      for (const res of set) {
        try {
          res.write(`data: ${JSON.stringify({ status })}\n\n`);
          if (status !== 'pending') res.end();
        } catch {}
      }
      if (status !== 'pending') this.waiters.delete(n);
    }
  }
  statusOf(name) {
    const cfg = this.config;
    if (!name) return 'none';
    if (!cfg.queue || !this.approvals) return 'approved';
    return this.approvals.status(name) || 'pending';
  }

  get config() {
    return normalizeConfig(this.getConfig());
  }
  get enabled() {
    return this.config.enabled;
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
      log('error', `gate: could not persist secret (${err.message}) - using a temporary one`);
      return crypto.randomBytes(32).toString('hex');
    }
  }

  sign(name) {
    return crypto.createHmac('sha256', this.secret).update(name).digest('base64url').slice(0, 24);
  }

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
      .replace(/[^\p{L}\p{N} _.\-@]/gu, '')
      .trim()
      .slice(0, 32);
    return n.length >= 2 ? n : null;
  }

  rememberIp(ip, name) {
    if (!ip || !name) return;
    let e = this.ipNames.get(ip);
    if (!e) {
      e = { names: new Set(), last: name };
      this.ipNames.set(ip, e);
      if (this.ipNames.size > 5000) this.ipNames.delete(this.ipNames.keys().next().value);
    }
    if (!e.names.has(name)) {
      e.names.add(name);
      if (e.names.size === 2) log('info', `gate: ip ${ip} is shared by ${[...e.names].join(', ')} - no longer matching that ip to a name`);
      if (e.names.size === 1 && this.onIpNamed) this.onIpNamed(ip, name);
    }
    e.last = name;
  }
  nameForIp(ip) {
    const e = ip && this.ipNames.get(ip);
    if (!e || e.names.size !== 1) return null;
    return e.last;
  }

  revoke(rawName) {
    if (rawName) this.revoked.set(rawName, Date.now());
  }
  unrevoke(rawName) {
    this.revoked.delete(rawName);
  }
  isRevoked(rawName) {
    return this.revoked.has(rawName);
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

  // Validate submitted answers against the configured fields -> { name, profile } or { error, values }
  validate(form) {
    const cfg = this.config;
    const values = {};
    const profile = {};
    let name = null;
    for (const f of cfg.fields) {
      let v = String(form.get(f.key) ?? '').trim();
      values[f.key] = f.type === 'password' ? '' : v;
      if (f.key === 'username') {
        name = NameGate.clean(v);
        if (!name) return { error: `${f.label}: 2-32 letters or numbers please.`, values };
        continue;
      }
      if (!v) {
        if (f.required) return { error: `${f.label} is required.`, values };
        continue;
      }
      if (f.type === 'number' && !/^\d{1,20}$/.test(v)) return { error: `${f.label} must be a number.`, values };
      if (f.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return { error: `${f.label} must be an email address.`, values };
      if (f.type === 'select' && f.options && !f.options.includes(v)) return { error: `${f.label}: pick one of the options.`, values };
      // never keep secrets: a password-type answer is only recorded as "given"
      profile[f.key] = f.type === 'password' ? '***' : v.slice(0, 120);
    }
    return { name, profile, values };
  }

  // "You must set your Your name, Student ID first" for tools hitting the proxy without the form
  refuse(req, res, status, text) {
    const wantsJson = String(req.headers.accept || '').includes('json');
    res.writeHead(status, { 'Content-Type': wantsJson ? 'application/json' : 'text/plain; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(wantsJson ? JSON.stringify({ error: text }) : text + '\n');
    return true;
  }
  requiredLabels() {
    return this.config.fields.filter((f) => f.required).map((f) => f.label).join(', ');
  }

  /** Called for every proxied request. Returns true if the gate answered it. */
  handle(req, res) {
    const cfg = this.config;
    const pathOnly = (req.url || '/').split('?')[0];

    // polled by the waiting page (fallback): { status: pending | approved | blocked | none }
    if (pathOnly === STATUS_PATH) {
      res.writeHead(200, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      res.end(JSON.stringify({ status: this.statusOf(this.nameFrom(req)) }));
      return true;
    }
    // event stream held open by the waiting page: the decision arrives the moment it is made
    if (pathOnly === STREAM_PATH) {
      const name = this.nameFrom(req);
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', Connection: 'keep-alive', 'X-Accel-Buffering': 'no' });
      res.write(`data: ${JSON.stringify({ status: this.statusOf(name) })}\n\n`);
      if (name && this.statusOf(name) === 'pending') {
        let set = this.waiters.get(name);
        if (!set) {
          set = new Set();
          this.waiters.set(name, set);
        }
        set.add(res);
        req.on('close', () => {
          set.delete(res);
          if (!set.size) this.waiters.delete(name);
        });
      } else res.end();
      return true;
    }

    if (pathOnly === GATE_PATH) {
      if (req.method !== 'POST') {
        res.writeHead(405).end();
        return true;
      }
      const chunks = [];
      req.on('data', (c) => chunks.length < 64 && chunks.push(c));
      req.on('end', () => {
        const form = new URLSearchParams(Buffer.concat(chunks).toString('utf8').slice(0, 8192));
        let next = form.get('next') || '/';
        if (!next.startsWith('/') || next.startsWith('//')) next = '/';
        const v = this.validate(form);
        const html = (msg, values) => {
          res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
          res.end(this.page(next, msg, values));
        };
        if (v.error) return html(v.error, v.values);
        if (this.revoked.has(v.name)) return html('That name was not accepted by the organizer. Please enter your real name.', v.values);
        const prev = this.nameFrom(req);
        const value = encodeURIComponent(`${v.name}.${this.sign(v.name)}`);
        res.writeHead(302, { Location: next, 'Set-Cookie': `${this.cookie}=${value}; Path=/; Max-Age=${MAX_AGE}; SameSite=Lax`, 'Cache-Control': 'no-store' });
        res.end();
        this.rememberIp(clientIp(req), v.name);
        if (this.onProfile && Object.keys(v.profile).length) this.onProfile(v.name, v.profile);
        if (cfg.queue && this.approvals) {
          const before = this.approvals.status(v.name);
          this.approvals.enqueue(v.name, { profile: v.profile, ip: clientIp(req), ua: String(req.headers['user-agent'] || '').slice(0, 160) });
          if (!before && this.onEnqueue) this.onEnqueue(v.name, { ip: clientIp(req) });
        }
        if (prev && prev !== v.name && this.revoked.has(prev)) {
          this.revoked.delete(prev);
          log('info', `gate: "${prev}" renamed themselves to "${v.name}"`);
          if (this.onRename) this.onRename(prev, v.name);
        } else log('info', `gate: student "${v.name}" (ip ${clientIp(req)})${Object.keys(v.profile).length ? ' ' + JSON.stringify(v.profile) : ''}`);
      });
      return true;
    }

    if (!cfg.enabled) return false;
    const current = this.nameFrom(req);
    const nav = this.isNavigation(req);
    const html = (body) => {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
      res.end(body);
      return true;
    };

    // no form filled yet
    if (!current) {
      if (nav) return html(this.page(req.url || '/'));
      if (cfg.strict) return this.refuse(req, res, 428, `You must set your ${this.requiredLabels()} first: open the CTF link in your browser and fill the form, then retry (tools must send the same cookie as the browser).`);
      return false;
    }
    // organizer rejected the name
    if (this.revoked.has(current)) {
      if (nav) return html(this.page(req.url || '/', 'The organizer asks you to enter your real name before continuing.'));
      return this.refuse(req, res, 428, 'ctf-watch: the organizer asks you to re-enter your name. Open the CTF in your browser, then retry.');
    }
    // admission queue
    if (cfg.queue && this.approvals) {
      let st = this.approvals.status(current);
      if (!st) {
        // cookie from before the queue was switched on: put them in the queue now
        this.approvals.enqueue(current, { ip: clientIp(req), ua: String(req.headers['user-agent'] || '').slice(0, 160) });
        if (this.onEnqueue) this.onEnqueue(current, { ip: clientIp(req) });
        st = 'pending';
      }
      if (st === 'blocked') return html(this.blockedPage());
      if (st !== 'approved') {
        if (nav) return html(this.waitPage(current));
        return this.refuse(req, res, 428, `ctf-watch: ${current}, you are waiting for the organizer's approval. Keep the CTF page open in your browser.`);
      }
    }
    return false;
  }

  waitPage(name) {
    const cfg = this.config;
    const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${esc(cfg.waitTitle)}</title>
<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0f14;color:#e6edf3;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.b{background:#111820;border:1px solid #1f2a36;border-radius:10px;padding:32px 28px;width:min(92vw,420px);text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.5)}h1{font-size:20px;margin:0 0 8px}p{color:#8b98a5;font-size:14px;margin:0 0 18px}
.s{width:28px;height:28px;border:3px solid #2a3847;border-top-color:#3987e5;border-radius:50%;margin:0 auto;animation:r 1s linear infinite}@keyframes r{to{transform:rotate(360deg)}}.n{color:#fab219}</style></head><body>
<div class="b"><h1>${esc(cfg.waitTitle)}</h1><p>${esc(cfg.waitText).replace(/\{name\}/g, `<span class="n">${esc(name)}</span>`)}</p><div class="s"></div></div>
<script>(function(){
  var done=false; function go(){ if(!done){ done=true; location.reload(); } }
  // realtime: event stream from the proxy; the decision arrives the moment the organizer clicks
  try { var es=new EventSource("${STREAM_PATH}"); es.onmessage=function(e){ try{ var j=JSON.parse(e.data); if(j.status!=="pending") go(); }catch(x){} }; es.onerror=function(){ /* fallback below keeps working */ }; } catch(x){}
  // fallback: slow poll in case the stream cannot stay open through the tunnel
  setInterval(function(){ fetch("${STATUS_PATH}",{credentials:"same-origin",headers:{"X-Requested-With":"ctf-watch-wait"}}).then(function(r){return r.json()}).then(function(j){ if(j.status!=="pending") go(); }).catch(function(){}); },10000);
})();</script>
</body></html>`;
  }
  blockedPage() {
    return '<!doctype html><html><body style="font-family:system-ui;background:#0b0f14;color:#e6edf3;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="color:#d03b3b">Access blocked</h1><p>The organizer has not admitted you to this CTF.<br>Talk to the organizer if you think this is a mistake.</p></div></body></html>';
  }

  page(next, error, values = {}) {
    const cfg = this.config;
    const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]));
    const field = (f, i) => {
      const common = `name="${esc(f.key)}" id="f-${esc(f.key)}" ${f.required ? 'required' : ''} ${i === 0 ? 'autofocus' : ''} autocomplete="off"`;
      let input;
      if (f.type === 'select') input = `<select ${common}><option value="">choose…</option>${(f.options || []).map((o) => `<option ${values[f.key] === o ? 'selected' : ''}>${esc(o)}</option>`).join('')}</select>`;
      else input = `<input ${common} type="${f.type === 'number' ? 'text' : f.type}" ${f.type === 'number' ? 'inputmode="numeric" pattern="[0-9]*"' : ''} maxlength="${f.key === 'username' ? 32 : 120}" placeholder="${esc(f.placeholder || f.label)}" value="${esc(values[f.key] || '')}">`;
      return `<label for="f-${esc(f.key)}">${esc(f.label)}${f.required ? '' : ' <span class="opt">(optional)</span>'}</label>${input}`;
    };
    return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(cfg.title)}</title>
<style>
  body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#0b0f14;color:#e6edf3;font:16px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
  form{background:#111820;border:1px solid #1f2a36;border-radius:10px;padding:32px 28px;width:min(92vw,400px);box-shadow:0 20px 60px rgba(0,0,0,.5)}
  h1{font-size:20px;margin:0 0 6px}p{margin:0 0 18px;color:#8b98a5;font-size:14px}
  label{display:block;font-size:13px;color:#8b98a5;margin:12px 0 4px}label .opt{color:#5b6774;font-size:12px}
  input,select{width:100%;box-sizing:border-box;padding:12px 14px;font-size:16px;border-radius:6px;border:1px solid #2a3847;background:#0b0f14;color:#e6edf3}
  input:focus,select:focus{outline:none;border-color:#3987e5}
  button{margin-top:18px;width:100%;padding:12px;font-size:16px;font-weight:600;border:0;border-radius:6px;background:#3987e5;color:#fff;cursor:pointer}
  .err{color:#fab219;font-size:13px;margin:10px 0 0}
</style></head><body>
<form method="post" action="${GATE_PATH}">
  <h1>${esc(cfg.title)}</h1>
  ${cfg.intro ? `<p>${esc(cfg.intro)}</p>` : ''}
  ${cfg.fields.map(field).join('')}
  <input type="hidden" name="next" value="${esc(next)}">
  ${error ? `<div class="err">${esc(error)}</div>` : ''}
  <button type="submit">${esc(cfg.button)}</button>
</form></body></html>`;
  }
}

module.exports = { NameGate, GATE_PATH, STATUS_PATH, STREAM_PATH, DEFAULT_CONFIG, normalizeConfig, TYPES };

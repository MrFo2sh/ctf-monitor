'use strict';
// Entry point. Wires: proxy -> identity -> detection (IDOR + web attacks) -> store -> db / dashboard / JSONL.

const fs = require('fs');
const path = require('path');
const { Config } = require('./config');
const { IdentityResolver } = require('./identity');
const { Detector } = require('./detect');
const { Store } = require('./store');
const { Db } = require('./db');
const { Auth } = require('./auth');
const { Admin } = require('./admin');
const { NameGate, normalizeConfig } = require('./namegate');
const { Approvals } = require('./approvals');
const { Replay } = require('./replay');
const { Playground } = require('./playground');
const { classify, worstLevel } = require('./attacks');
const { createProxy } = require('./proxy');
const { discover, validateTarget } = require('./ports');
const { createDashboard } = require('./dashboard');
const { maskObject, maskUrl, maskText } = require('./mask');
const { parseBody, clientIp, macFor, log } = require('./util');

const env = (k, d) => (process.env[k] === undefined || process.env[k] === '' ? d : process.env[k]);
const flag = (k) => /^(1|true|yes)$/i.test(String(env(k, '')));

const CTF_TARGET = env('CTF_TARGET', ''); // optional: the dashboard (CTFs tab) picks the target at runtime
const PROXY_PORT = Number(env('PROXY_PORT', 8888));
const PROXY_BIND = env('PROXY_BIND', '127.0.0.1');
const DASHBOARD_PORT = Number(env('DASHBOARD_PORT', 8080));
const DASHBOARD_BIND = env('DASHBOARD_BIND', '127.0.0.1');
const DASHBOARD_USERS = Number(env('DASHBOARD_USERS', 3));
const SESSION_TTL_HOURS = Number(env('SESSION_TTL_HOURS', 12));
const LOG_DIR = env('LOG_DIR', path.join(__dirname, '..', '..', 'logs'));
const DATA_DIR = env('DATA_DIR', path.join(__dirname, '..', '..', 'data'));
const DB_FILE = env('DB_FILE', path.join(DATA_DIR, 'ctf-watch.db'));
const CTF_NAME = env('CTF_NAME', '');

// ---------------------------------------------------------------- core objects
const config = new Config();
const getConfig = () => config.get();
const db = new Db(DB_FILE);
const ctf = db.openCtf(CTF_NAME || undefined);
// The gate (the form students fill on their first browser visit) is configured in the dashboard, Gate tab.
let gateConfig = normalizeConfig(db.get('gate_config', null) || { title: env('NAME_GATE_TITLE', 'Welcome to the CTF') });
const profiles = db.get('gate_profiles', {}); // raw student name -> answers to the extra gate fields
const approvals = new Approvals({ db }); // the admission queue (Queue tab)
const gate = new NameGate({
  secretFile: path.join(DATA_DIR, '.name-gate-secret'),
  cookie: env('NAME_GATE_COOKIE', 'ctfw_name'),
  getConfig: () => gateConfig,
  approvals,
  onProfile: (name, profile) => {
    profiles[name] = { ...(profiles[name] || {}), ...profile, _at: Date.now() };
    db.set('gate_profiles', profiles);
    const s = store.students.get(admin.alias(name));
    if (s) s.profile = profiles[name];
  },
  onEnqueue: (name, info) => store.emitAlert({ type: 'queue', level: 'info', student: admin.alias(name), ip: info.ip, msg: `${name} filled the gate form and is waiting for approval (Queue tab)` }),
});
// decisions from the Queue tab: block also blocks at the proxy level (name + ip)
function queueDecide(names, status, by) {
  const changed = approvals[status === 'approved' ? 'approve' : status === 'blocked' ? 'block' : 'reset'](names, by);
  for (const raw of changed) {
    const display = admin.alias(raw);
    if (status === 'blocked') {
      const it = approvals.get(raw);
      admin.block(display, it && it.ip);
    } else if (admin.state.blocked[display]) admin.unblock(display);
  }
  return changed;
}
function setGateConfig(raw) {
  gateConfig = normalizeConfig(raw);
  db.set('gate_config', gateConfig);
  log('info', `gate config saved: ${gateConfig.enabled ? 'on' : 'off'}, fields: ${gateConfig.fields.map((f) => f.key).join(', ')}`);
  return gateConfig;
}
const identity = new IdentityResolver(getConfig, gate);
const detector = new Detector(getConfig);
const store = new Store({ logDir: LOG_DIR, db });
const admin = new Admin({ db, store, detector, gate });
const replay = new Replay({ db, store });
const playground = new Playground({ proxyPort: PROXY_PORT });
store.isBlocked = (name) => !!admin.state.blocked[name];
store.renamePending = (name) => admin.isRenamePending(name);
store.queueStatus = (name) => (gateConfig.queue ? approvals.status(admin.rawNameFor(name)) : null);

// ---------------------------------------------------------------- dashboard accounts
const auth = new Auth(db, {
  sessionTtlMs: SESSION_TTL_HOURS * 3600 * 1000,
  onConflict: (c) => {
    const suspects = store.studentsByIp(c.ip);
    store.emitAlert({
      type: 'admin-login-conflict',
      level: 'critical',
      ip: c.ip,
      student: suspects[0] || null,
      msg: `Someone at ${c.ip} tried to log in to the dashboard as ${c.username} while that account is in use from ${c.activeIp}.` +
        (suspects.length ? ` That IP belongs to CTF player ${suspects.join(' / ')}.` : ' No CTF player matches that IP.') + (c.blocked ? ' The IP is now blocked.' : ''),
      data: { username: c.username, ip: c.ip, activeIp: c.activeIp, suspects },
    });
    if (c.blocked) {
      admin.state.blocked[`ip:${c.ip}`] = { ip: c.ip, ts: Date.now(), reason: 'dashboard login conflict' };
      admin.save();
    }
  },
});
const credentials = auth.generateAccounts(DASHBOARD_USERS);
printCredentials(credentials);

function printCredentials(list) {
  const lines = ['', '==================== DASHBOARD LOGIN ====================', ...list.map((c) => `  ${c.role.padEnd(5)}  ${c.username.padEnd(12)}  password: ${c.password}`), '=========================================================', ''];
  console.log(lines.join('\n'));
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    fs.writeFileSync(path.join(LOG_DIR, 'credentials.txt'), lines.join('\n'), { mode: 0o600 });
  } catch (err) {
    log('error', `could not write credentials file: ${err.message}`);
  }
}

// ---------------------------------------------------------------- helpers
const withAlias = (who) => {
  const name = admin.alias(who.name);
  return name === who.name ? who : { ...who, name, rawName: who.name };
};

function mergeLane(anonLabel, rawName) {
  const target = admin.alias(rawName);
  if (!anonLabel || anonLabel === target || !store.students.has(anonLabel)) return;
  store.renameStudent(anonLabel, target);
  detector.renameStudent(anonLabel, target);
  playerCache.delete(anonLabel);
  log('info', `merged row ${anonLabel} into ${target}`);
}
gate.onIpNamed = (ip, name) => mergeLane(`ip:${ip}`, name);
identity.onSessionNamed = (label, name) => mergeLane(label, name);

// player mapping across CTFs (name / app username / ip / mac). Cached per student row.
const playerCache = new Map(); // student -> { id, ips:Set }
function playerIdFor(who, ip, ts) {
  const key = who.name;
  const cached = playerCache.get(key);
  const identities = [];
  if (who.source === 'name' || who.source === 'ip-match') {
    identities.push({ kind: 'name', value: who.rawName || who.name });
    // extra gate answers (id, email...) are strong identities across CTFs
    const prof = profiles[who.rawName || who.name] || {};
    for (const [k, v] of Object.entries(prof)) if (!k.startsWith('_') && v && v !== '***' && /^(id|.*_id|.*id|email|mail|phone|student.*|roll.*)$/i.test(k)) identities.push({ kind: `gate:${k}`, value: String(v).toLowerCase() });
  }
  const appName = who.appName || (who.source === 'session' || who.source === 'jwt' || who.source === 'login' ? who.name : null);
  if (appName && !/^sess-/.test(appName)) identities.push({ kind: 'username', value: appName });
  if (ip && who.source !== 'ip') identities.push({ kind: 'ip', value: ip });
  if (cached) {
    if (ip && !cached.ips.has(ip) && who.source !== 'ip') {
      cached.ips.add(ip);
      db.stmts.upsertIdentity.run(cached.id, 'ip', ip, db.ctfId, ts, ts);
    }
    return cached.id;
  }
  if (!identities.length) return null; // anonymous ip-only rows are not players yet
  const id = db.playerFor(identities, who.name, ts);
  playerCache.set(key, { id, ips: new Set(ip ? [ip] : []) });
  if (ip) macFor(ip).then((mac) => mac && db.stmts.upsertIdentity.run(id, 'mac', mac, db.ctfId, ts, ts)).catch(() => {});
  return id;
}

// ---------------------------------------------------------------- request pipeline
function preRequest(req, res) {
  const who = withAlias(identity.resolve(req));
  const ip = clientIp(req);
  if (!admin.isBlocked(who.name, ip)) return false;
  const wantsHtml = String(req.headers.accept || '').includes('text/html');
  const body = wantsHtml
    ? '<!doctype html><html><body style="font-family:system-ui;background:#0b0f14;color:#e6edf3;display:flex;align-items:center;justify-content:center;height:100vh;margin:0"><div style="text-align:center"><h1 style="color:#d03b3b">Access blocked</h1><p>The organizer has blocked your access to this CTF.<br>Talk to the organizer if you think this is a mistake.</p></div></body></html>'
    : JSON.stringify({ error: 'blocked by the CTF organizer' });
  res.writeHead(403, { 'Content-Type': wantsHtml ? 'text/html; charset=utf-8' : 'application/json', 'Cache-Control': 'no-store' });
  res.end(body);
  req.resume();
  onEvent({ ts: Date.now(), req, method: req.method, url: req.url || '/', pathOnly: (req.url || '/').split('?')[0], status: 403, size: Buffer.byteLength(body), latencyMs: 0, reqLen: 0, reqBuf: Buffer.alloc(0), resHeaders: {}, resBuf: Buffer.alloc(0), error: 'blocked' });
  return true;
}

function onEvent(x) {
  const cfg = getConfig();
  const blockedReq = x.error === 'blocked';
  const reqBody = parseBody(x.req.headers['content-type'], x.reqBuf);
  const resBody = parseBody(x.resHeaders['content-type'], x.resBuf);
  const ip = clientIp(x.req);

  const pre = identity.resolve(x.req);
  const learned = blockedReq ? null : identity.learn({ req: x.req, identity: pre, reqBody, status: x.status, resHeaders: x.resHeaders, resBody, pathOnly: x.pathOnly });
  let who = identity.resolve(x.req);
  if (learned && (who.source === 'ip' || who.name.startsWith('sess-'))) who = { ...who, name: learned.name, id: learned.id || who.id, source: 'login' };
  if (learned && (who.source === 'name' || who.source === 'ip-match')) who = { ...who, id: who.id || learned.id || null, appName: who.appName || learned.name };
  who = withAlias(who);

  let hasData = x.size >= cfg.successMinBytes;
  if (hasData && resBody && typeof resBody === 'object' && !Array.isArray(resBody)) {
    const keys = Object.keys(resBody);
    if (keys.length && keys.every((k) => /^(error|err|message|msg|success|status)$/i.test(k))) hasData = false;
  }

  const verdict = blockedReq
    ? { endpoint: null, objectId: null, owner: null, ownerBasis: null, mine: null, seq: null, sequential: false, distinctIds: 0, flags: ['blocked'], severity: 'notice' }
    : detector.analyze({ student: who, method: x.method, pathOnly: x.pathOnly, url: x.url, status: x.status, size: x.size, hasData, reqBody, ts: x.ts });

  // web exploitation attempts (SQLi, XSS, SSTI, LFI, shells, scanners...)
  const attacks = blockedReq ? [] : classify({ url: x.url, bodyText: x.reqBuf.length ? x.reqBuf.toString('utf8', 0, 8192) : '', ua: x.req.headers['user-agent'], referer: x.req.headers.referer });
  const flags = verdict.flags.concat(attacks.map((a) => `attack:${a.cls}`));
  let severity = verdict.severity;
  if (attacks.length && severity !== 'critical') {
    const w = worstLevel(attacks);
    if (w === 'critical') severity = 'critical';
    else if (w === 'high' && severity !== 'high') severity = 'high';
    else if (severity === 'ok' || severity === 'notice') severity = 'warn';
  }

  const ev = {
    ts: x.ts, time: new Date(x.ts).toISOString(), student: who.name, rawName: who.rawName || who.name, studentId: who.id, source: who.source,
    appName: who.appName || undefined, profile: profiles[who.rawName || who.name] || undefined, playerId: playerIdFor(who, ip, x.ts), ip, method: x.method, path: maskText(maskUrl(x.url, cfg.maskFields)),
    endpoint: verdict.endpoint, objectId: verdict.objectId, status: x.status, size: x.size, latencyMs: x.latencyMs, flags, attacks, severity,
    owner: verdict.owner, ownerBasis: verdict.ownerBasis, mine: verdict.mine, seq: verdict.seq, sequential: verdict.sequential, distinctIds: verdict.distinctIds,
    idsSeenTotal: verdict.idsSeenTotal, ua: String(x.req.headers['user-agent'] || '').slice(0, 160),
    body: x.method !== 'GET' && reqBody ? maskObject(reqBody, cfg.maskFields) : undefined, error: x.error || undefined,
  };
  store.add(ev);
}

const shouldIgnore = (pathOnly) => getConfig().compiledIgnore.some((re) => re.test(pathOnly));

// ---------------------------------------------------------------- proxy target (the CTF app), switchable at runtime
let target = db.get('proxy_target', null);
if (!target && CTF_TARGET) {
  try {
    target = validateTarget(CTF_TARGET);
  } catch (err) {
    log('error', `CTF_TARGET ignored: ${err.message}`);
  }
}
function setTarget(url, { label } = {}) {
  const clean = url ? validateTarget(url) : null;
  const prev = target;
  target = clean;
  db.set('proxy_target', clean);
  if (clean !== prev) {
    log('info', `proxy target: ${prev || '(none)'} -> ${clean || '(none)'}${label ? ` (${label})` : ''}`);
    store.emitAlert({ type: 'info', level: 'info', msg: clean ? `Proxy now points at ${clean}${label ? ` (${label})` : ''}` : 'Proxy disconnected from the CTF app' });
  }
  return target;
}
const getTarget = () => target;
const discoverTargets = () => discover({ excludePorts: [PROXY_PORT, DASHBOARD_PORT] });

// The public (zrok) link the students use. start.sh writes logs/zrok.url; otherwise parse zrok's own log.
function studentLink() {
  try {
    const f = path.join(LOG_DIR, 'zrok.url');
    if (fs.existsSync(f)) {
      const u = fs.readFileSync(f, 'utf8').trim();
      if (u) return { url: u, source: 'start.sh', since: fs.statSync(f).mtimeMs };
    }
    const lg = path.join(LOG_DIR, 'zrok.log');
    if (fs.existsSync(lg)) {
      const st = fs.statSync(lg);
      const fd = fs.openSync(lg, 'r');
      const buf = Buffer.alloc(Math.min(st.size, 64 * 1024));
      fs.readSync(fd, buf, 0, buf.length, Math.max(0, st.size - buf.length));
      fs.closeSync(fd);
      const m = /(https?:\/\/)?([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.zrok\.io[A-Za-z0-9./_-]*)/.exec(buf.toString('utf8'));
      if (m) return { url: `https://${m[2]}`, source: 'zrok.log', since: st.mtimeMs };
    }
  } catch {}
  return { url: null, source: null, hint: `no zrok share seen (start.sh starts one on the VM; by hand: zrok2 share public ${PROXY_PORT})` };
}

// ---------------------------------------------------------------- lifecycle
function resetLive() {
  store.reset();
  detector.students.clear();
  detector.learned.clear();
  playerCache.clear();
  gate.ipNames.clear();
}
function newCtf(name) {
  replay.stop();
  db.endCtf(db.ctfId);
  const c = db.openCtf(name || undefined);
  resetLive();
  log('info', `switched to CTF #${c.id} "${c.name}"`);
  return c;
}
// Stop CTF: close the record, disconnect the students, clear the live view. Nothing is recorded until
// a target is picked again (which opens a new record automatically) or "New CTF" is pressed.
function stopCtf() {
  replay.stop();
  const ended = db.activeCtf();
  setTarget(null, { label: 'CTF stopped' });
  db.endCtf(db.ctfId);
  resetLive();
  if (ended) log('info', `CTF #${ended.id} "${ended.name}" stopped`);
  return ended;
}

createProxy({ getTarget, bind: PROXY_BIND, port: PROXY_PORT, shouldIgnore, onEvent, gate, preRequest });
createDashboard({ port: DASHBOARD_PORT, bind: DASHBOARD_BIND, store, admin, auth, db, replay, playground, gate, setGateConfig, approvals, queueDecide, newCtf, stopCtf, getTarget, setTarget, discoverTargets, studentLink, proxyPort: PROXY_PORT, getRawConfig: () => config.raw });

log('info', `ctf-watch v2.1 started (gate ${gateConfig.enabled ? 'on' : 'off'}, fields: ${gateConfig.fields.map((f) => f.key).join(', ')}). ctf="${ctf.name}" target=${target || '(pick one in the dashboard, CTFs tab)'} proxy=${PROXY_BIND}:${PROXY_PORT} dashboard=${DASHBOARD_BIND}:${DASHBOARD_PORT} db=${DB_FILE}`);

function shutdown() {
  log('info', 'shutting down');
  try {
    playground.stopAll();
    db.close();
  } catch {}
  process.exit(0);
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
process.on('uncaughtException', (err) => log('error', `uncaught: ${err.stack || err}`));

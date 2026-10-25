'use strict';
// Entry point. Wires: proxy -> identity -> detector -> store -> dashboard/JSONL.

const path = require('path');
const { Config } = require('./config');
const { IdentityResolver } = require('./identity');
const { Detector } = require('./detect');
const { Store } = require('./store');
const { createProxy } = require('./proxy');
const { createDashboard } = require('./dashboard');
const { NameGate } = require('./namegate');
const { maskObject, maskUrl, maskText } = require('./mask');
const { parseBody, clientIp, log } = require('./util');

const CTF_TARGET = process.env.CTF_TARGET || 'http://127.0.0.1:3000';
const PROXY_PORT = Number(process.env.PROXY_PORT || 8888);
const PROXY_BIND = process.env.PROXY_BIND || '127.0.0.1';
const DASHBOARD_PORT = Number(process.env.DASHBOARD_PORT || 8080);
const LOG_DIR = process.env.LOG_DIR || path.join(__dirname, '..', '..', 'logs');
const DEMO = /^(1|true|yes)$/i.test(String(process.env.DEMO || ''));
const NAME_GATE = /^(1|true|yes)$/i.test(String(process.env.NAME_GATE || ''));

const config = new Config();
const getConfig = () => config.get();
const gate = NAME_GATE
  ? new NameGate({
      secretFile: path.join(LOG_DIR, '.name-gate-secret'),
      cookie: process.env.NAME_GATE_COOKIE || 'ctfw_name',
      title: process.env.NAME_GATE_TITLE || 'Welcome to the CTF',
    })
  : null;
const identity = new IdentityResolver(getConfig, gate);
const detector = new Detector(getConfig);
const store = new Store({ logDir: LOG_DIR, demo: DEMO });

function onEvent(x) {
  const cfg = getConfig();
  const reqBody = parseBody(x.req.headers['content-type'], x.reqBuf);
  const resBody = parseBody(x.resHeaders['content-type'], x.resBuf);

  // learn identity first (login / whoami), then resolve - so the login request itself shows the right name
  const pre = identity.resolve(x.req);
  const learned = identity.learn({ req: x.req, identity: pre, reqBody, status: x.status, resHeaders: x.resHeaders, resBody, pathOnly: x.pathOnly });
  let who = identity.resolve(x.req);
  // the login request itself carries no session cookie yet: attribute it to the student who just logged in
  if (learned && (who.source === 'ip' || who.name.startsWith('sess-'))) who = { ...who, name: learned.name, id: learned.id || who.id, source: 'login' };
  if (learned && (who.source === 'name' || who.source === 'ip-match') && !who.id) who = { ...who, id: learned.id || null };

  // "contains data": 2xx with a real body that is not just an error message
  let hasData = x.size >= cfg.successMinBytes;
  if (hasData && resBody && typeof resBody === 'object' && !Array.isArray(resBody)) {
    const keys = Object.keys(resBody);
    if (keys.length && keys.every((k) => /^(error|err|message|msg|success|status)$/i.test(k))) hasData = false;
  }

  const verdict = detector.analyze({
    student: who,
    method: x.method,
    pathOnly: x.pathOnly,
    url: x.url,
    status: x.status,
    size: x.size,
    hasData,
    reqBody,
    ts: x.ts,
  });

  const ev = {
    ts: x.ts,
    time: new Date(x.ts).toISOString(),
    student: who.name,
    studentId: who.id,
    source: who.source,
    appName: who.appName || undefined,
    ip: clientIp(x.req),
    method: x.method,
    path: maskText(maskUrl(x.url, cfg.maskFields)),
    endpoint: verdict.endpoint,
    objectId: verdict.objectId,
    status: x.status,
    size: x.size,
    latencyMs: x.latencyMs,
    flags: verdict.flags,
    severity: verdict.severity,
    owner: verdict.owner,
    ownerBasis: verdict.ownerBasis,
    mine: verdict.mine,
    seq: verdict.seq,
    sequential: verdict.sequential,
    distinctIds: verdict.distinctIds,
    idsSeenTotal: verdict.idsSeenTotal,
    ua: String(x.req.headers['user-agent'] || '').slice(0, 80),
    body: x.method !== 'GET' && reqBody ? maskObject(reqBody, cfg.maskFields) : undefined,
    error: x.error || undefined,
  };
  store.add(ev);
}

const shouldIgnore = (pathOnly) => getConfig().compiledIgnore.some((re) => re.test(pathOnly));

createProxy({ target: CTF_TARGET, bind: PROXY_BIND, port: PROXY_PORT, shouldIgnore, onEvent, gate });
createDashboard({ port: DASHBOARD_PORT, store, getRawConfig: () => config.raw });

log('info', `ctf-watch started${DEMO ? ' (DEMO MODE)' : ''}${NAME_GATE ? ' (name gate ON)' : ''}. target=${CTF_TARGET} proxy=${PROXY_BIND}:${PROXY_PORT} dashboard=127.0.0.1:${DASHBOARD_PORT}`);

process.on('SIGTERM', () => {
  log('info', 'shutting down');
  process.exit(0);
});
process.on('SIGINT', () => process.exit(0));
process.on('uncaughtException', (err) => log('error', `uncaught: ${err.stack || err}`));

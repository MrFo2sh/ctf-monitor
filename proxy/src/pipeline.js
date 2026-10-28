'use strict';
// The event pipeline: turns one raw proxy exchange into the event the dashboard and the database see.
// Pure with respect to its dependencies, so the golden test (test/golden.test.js) can run recorded
// exchanges through it without the HTTP proxy.
//
// x = { ts, req: { method, url, headers }, method, url, pathOnly, status, size, latencyMs, reqLen,
//       reqBuf (Buffer), resHeaders, resBuf (Buffer, already decompressed), error }
// deps = { getConfig, identity, detector, alias(name) -> displayName, profiles (raw name -> answers),
//          playerIdFor(who, ip, ts) -> id|null, isDecoy(name) -> bool }

const { classify, worstLevel } = require('./attacks');
const { maskObject, maskUrl, maskText, maskBodyText } = require('./mask');
const { parseBody, clientIp } = require('./util');

function withAlias(who, alias) {
  const name = alias(who.name);
  return name === who.name ? who : { ...who, name, rawName: who.name };
}

function buildEvent(x, deps) {
  const { getConfig, identity, detector, alias, profiles, playerIdFor, isDecoy } = deps;
  const cfg = getConfig();
  const blockedReq = x.error === 'blocked';
  const gateReq = x.error === 'gate'; // refused at the name gate: nothing reached the CTF, but the attempt counts
  const reqBody = parseBody(x.req.headers['content-type'], x.reqBuf);
  const resBody = parseBody(x.resHeaders['content-type'], x.resBuf);
  const ip = clientIp(x.req);

  // identity: learn first (a login / whoami may teach a session -> name), then resolve
  const pre = identity.resolve(x.req);
  const learned = blockedReq || gateReq ? null : identity.learn({ req: x.req, identity: pre, reqBody, status: x.status, resHeaders: x.resHeaders, resBody, pathOnly: x.pathOnly });
  let who = identity.resolve(x.req);
  if (learned && (who.source === 'ip' || who.name.startsWith('sess-'))) who = { ...who, name: learned.name, id: learned.id || who.id, source: 'login' };
  if (learned && (who.source === 'name' || who.source === 'ip-match')) who = { ...who, id: who.id || learned.id || null, appName: who.appName || learned.name };
  who = withAlias(who, alias);

  // "contains data": a 2xx with a body that is not just an error message
  let hasData = x.size >= cfg.successMinBytes;
  if (hasData && resBody && typeof resBody === 'object' && !Array.isArray(resBody)) {
    const keys = Object.keys(resBody);
    if (keys.length && keys.every((k) => /^(error|err|message|msg|success|status)$/i.test(k))) hasData = false;
  }

  const verdict = blockedReq || gateReq
    ? { endpoint: null, objectId: null, owner: null, ownerBasis: null, mine: null, seq: null, sequential: false, distinctIds: 0, flags: [blockedReq ? 'blocked' : 'gate-refused'], severity: 'notice' }
    : detector.analyze({ student: who, method: x.method, pathOnly: x.pathOnly, url: x.url, status: x.status, size: x.size, hasData, reqBody, ts: x.ts });

  // web exploitation attempts (SQLi, XSS, SSTI, LFI, shells, scanners...)
  // the classifier never sees secret values: sensitive fields are masked in the body before scanning, and
  // the samples it returns are masked again (jwt / long hex), so an alert can never quote a password
  const bodyText = x.reqBuf.length ? maskBodyText(x.reqBuf.toString('utf8', 0, 8192), cfg.maskFields) : '';
  const attacks = blockedReq ? [] : classify({ url: maskUrl(x.url, cfg.maskFields), bodyText, ua: x.req.headers['user-agent'], referer: x.req.headers.referer }).map((a) => ({ ...a, sample: maskText(a.sample) }));
  let flags = verdict.flags.concat(attacks.map((a) => `attack:${a.cls}`));
  let severity = verdict.severity;
  if (attacks.length && severity !== 'critical') {
    const w = worstLevel(attacks);
    if (w === 'critical') severity = 'critical';
    else if (w === 'high' && severity !== 'high') severity = 'high';
    else if (w !== 'info' && (severity === 'ok' || severity === 'notice')) severity = 'warn'; // an info-level tag (curl, requests…) never colours the request
  }
  const onDecoy = isDecoy(who.name);
  if (onDecoy) flags = flags.concat('decoy');

  return {
    ts: x.ts, time: new Date(x.ts).toISOString(), student: who.name, rawName: who.rawName || who.name, studentId: who.id, source: who.source,
    appName: who.appName || undefined, profile: profiles[who.rawName || who.name] || undefined, playerId: playerIdFor(who, ip, x.ts), ip, method: x.method, path: maskText(maskUrl(x.url, cfg.maskFields)),
    endpoint: verdict.endpoint, objectId: verdict.objectId, status: x.status, size: x.size, latencyMs: x.latencyMs, flags, attacks, severity,
    decoy: onDecoy || undefined,
    owner: verdict.owner, ownerBasis: verdict.ownerBasis, mine: verdict.mine, seq: verdict.seq, sequential: verdict.sequential, distinctIds: verdict.distinctIds,
    idsSeenTotal: verdict.idsSeenTotal, ua: String(x.req.headers['user-agent'] || '').slice(0, 160),
    body: x.method !== 'GET' && reqBody ? maskObject(reqBody, cfg.maskFields) : undefined, error: x.error || undefined,
  };
}

// Serialise a raw exchange for recording (RECORD_RAW) and rebuild it for replaying through buildEvent.
function rawToJson(x) {
  return {
    ts: x.ts, method: x.method, url: x.url, pathOnly: x.pathOnly, status: x.status, size: x.size, latencyMs: x.latencyMs, reqLen: x.reqLen, error: x.error || null,
    headers: x.req.headers, reqBuf: x.reqBuf.toString('base64'), resHeaders: x.resHeaders, resBuf: x.resBuf.toString('base64'), remote: (x.req.socket && x.req.socket.remoteAddress) || '127.0.0.1',
  };
}
function rawFromJson(j) {
  return {
    ts: j.ts, method: j.method, url: j.url, pathOnly: j.pathOnly, status: j.status, size: j.size, latencyMs: j.latencyMs, reqLen: j.reqLen, error: j.error || null,
    req: { method: j.method, url: j.url, headers: j.headers, socket: { remoteAddress: j.remote } },
    reqBuf: Buffer.from(j.reqBuf || '', 'base64'), resHeaders: j.resHeaders || {}, resBuf: Buffer.from(j.resBuf || '', 'base64'),
  };
}

module.exports = { buildEvent, withAlias, rawToJson, rawFromJson };

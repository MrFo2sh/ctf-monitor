'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Db } = require('../src/db');
const { Approvals } = require('../src/approvals');
const { NameGate, normalizeConfig } = require('../src/namegate');

const mkRes = () => { const r = { code: null, headers: null, body: '', ended: false, writeHead(c, h) { r.code = c; r.headers = h || {}; return r; }, write(b) { r.body += String(b); }, end(b) { r.body += String(b || ''); r.ended = true; } }; return r; };
const nav = (cookie) => ({ method: 'GET', url: '/dashboard', headers: { accept: 'text/html', 'sec-fetch-dest': 'document', 'user-agent': 'Mozilla/5.0', ...(cookie ? { cookie } : {}) }, socket: { remoteAddress: '10.0.0.5' }, on() {} });
const api = (cookie) => ({ method: 'GET', url: '/api/x', headers: { accept: 'application/json', ...(cookie ? { cookie } : {}) }, socket: { remoteAddress: '10.0.0.5' }, on() {} });

function setup(over = {}) {
  const db = new Db(':memory:');
  const approvals = new Approvals({ db });
  let cfg = normalizeConfig({ fields: [{ key: 'username' }, { key: 'sid', label: 'Student ID', type: 'number', required: true }], ...over });
  const g = new NameGate({ secretFile: null, getConfig: () => cfg, approvals });
  const cookieFor = (name) => `ctfw_name=${encodeURIComponent(name + '.' + g.sign(name))}`;
  return { db, approvals, g, cookieFor, setCfg: (o) => (cfg = normalizeConfig({ ...cfg, ...o })) };
}

test('approvals: enqueue, decide, persist, counts', () => {
  const db = new Db(':memory:');
  const a = new Approvals({ db });
  a.enqueue('Gohary', { profile: { sid: '42' }, ip: '1.2.3.4', ua: 'x' });
  a.enqueue('Sara', { ip: '1.2.3.5' });
  assert.deepEqual(a.counts(), { pending: 2, approved: 0, blocked: 0 });
  assert.deepEqual(a.approve(['Gohary', 'nobody'], 'admin_x'), ['Gohary']);
  assert.equal(a.get('Gohary').by, 'admin_x');
  a.block('Sara');
  assert.deepEqual(a.counts(), { pending: 0, approved: 1, blocked: 1 });
  // a resubmitted form keeps the decision but refreshes the answers
  a.enqueue('Gohary', { profile: { sid: '43' } });
  assert.equal(a.status('Gohary'), 'approved');
  assert.equal(a.get('Gohary').profile.sid, '43');
  const again = new Approvals({ db });
  assert.equal(again.status('Sara'), 'blocked');
  a.reset('Sara');
  assert.equal(a.status('Sara'), 'pending');
});

test('strict gate: no cookie -> browser gets the form, tools get 428 naming the required fields', () => {
  const { g } = setup();
  let r = mkRes();
  assert.equal(g.handle(nav(), r), true); assert.equal(r.code, 200); assert.ok(r.body.includes('<form'));
  r = mkRes();
  assert.equal(g.handle(api(), r), true); assert.equal(r.code, 428); assert.match(r.body, /You must set your Your name, Student ID first/);
});

test('non-strict gate: tools without a cookie pass through', () => {
  const { g } = setup({ strict: false });
  assert.equal(g.handle(api(), mkRes()), false);
});

test('queue: after the form the student waits, approval lets them in, block shuts them out', () => {
  const { g, approvals, cookieFor } = setup();
  const ck = cookieFor('Gohary');
  // first request with a cookie but no queue record: enqueued + waiting page
  let r = mkRes();
  assert.equal(g.handle(nav(ck), r), true); assert.equal(r.code, 200); assert.match(r.body, /Almost there/); assert.match(r.body, /Gohary/);
  assert.equal(approvals.status('Gohary'), 'pending');
  r = mkRes();
  assert.equal(g.handle(api(ck), r), true); assert.equal(r.code, 428); assert.match(r.body, /waiting for the organizer/);
  // approved -> passes through to the CTF
  approvals.approve(['Gohary']);
  assert.equal(g.handle(nav(ck), mkRes()), false);
  assert.equal(g.handle(api(ck), mkRes()), false);
  // blocked -> blocked page
  approvals.block(['Gohary']);
  r = mkRes();
  assert.equal(g.handle(nav(ck), r), true); assert.match(r.body, /Access blocked/);
});

test('queue off: the form alone is enough', () => {
  const { g, cookieFor } = setup({ queue: false });
  assert.equal(g.handle(nav(cookieFor('Sara')), mkRes()), false);
});

test('waiting page event stream: open streams get the decision pushed instantly', () => {
  const { g, approvals, cookieFor } = setup();
  const ck = cookieFor('Gohary');
  approvals.enqueue('Gohary', {});
  const req = { method: 'GET', url: '/__ctfwatch/wait', headers: { cookie: ck, accept: 'text/event-stream' }, socket: {}, on() {} };
  const r = mkRes();
  assert.equal(g.handle(req, r), true);
  assert.equal(r.headers['Content-Type'], 'text/event-stream');
  assert.match(r.body, /"status":"pending"/);
  assert.equal(r.ended, false);
  approvals.approve(['Gohary']);
  assert.match(r.body, /"status":"approved"/);
  assert.equal(r.ended, true);
  // status endpoint (fallback poll)
  const s = mkRes();
  g.handle({ method: 'GET', url: '/__ctfwatch/status', headers: { cookie: ck }, socket: {}, on() {} }, s);
  assert.match(s.body, /"status":"approved"/);
});

test('clear() forgets every decision and the next visit waits again', () => {
  const { db, approvals, g, cookieFor } = setup({ enabled: true, strict: false, queue: true });
  approvals.enqueue('Gohary', { ip: '1.2.3.4' });
  approvals.approve(['Gohary'], 'admin_x');
  assert.equal(g.handle(nav(cookieFor('Gohary')), mkRes()), false, 'approved: the page is proxied');
  assert.equal(approvals.clear(), 1);
  assert.deepEqual(db.get('gate_queue', null), {}, 'persisted as empty');
  const r = mkRes();
  assert.equal(g.handle(nav(cookieFor('Gohary')), r), true, 'back in the queue: the waiting page');
  assert.equal(approvals.status('Gohary'), 'pending');
  assert.equal(approvals.clear(), 1);
  assert.equal(approvals.clear(), 0, 'nothing left to clear');
});

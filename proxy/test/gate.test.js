'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { NameGate, normalizeConfig, DEFAULT_CONFIG } = require('../src/namegate');

test('normalizeConfig always keeps a locked, required username field first', () => {
  const c = normalizeConfig({ enabled: true, fields: [{ key: 'Student-ID', label: 'Student ID', type: 'number', required: true }, { key: 'username', label: 'Name' }] });
  assert.equal(c.fields[0].key, 'username');
  assert.equal(c.fields[0].locked, true);
  assert.equal(c.fields[0].required, true);
  assert.deepEqual(c.fields.map((f) => f.key), ['username', 'studentid']);
  const none = normalizeConfig({ fields: [] });
  assert.deepEqual(none.fields.map((f) => f.key), ['username']);
  assert.equal(normalizeConfig(null).title, DEFAULT_CONFIG.title);
  assert.equal(normalizeConfig({ fields: [{ key: 'x', type: 'weird' }] }).fields[1].type, 'text');
});

function gateWith(fields) {
  const cfg = normalizeConfig({ fields: [{ key: 'username' }, ...fields] });
  const profiles = [];
  const g = new NameGate({ secretFile: null, getConfig: () => cfg, onProfile: (n, p) => profiles.push([n, p]) });
  return { g, profiles };
}

test('validate: username cleaning, required fields, number / email / choice checks, password never stored', () => {
  const { g } = gateWith([
    { key: 'sid', label: 'Student ID', type: 'number', required: true },
    { key: 'email', label: 'Email', type: 'email', required: false },
    { key: 'team', label: 'Team', type: 'select', options: 'red, blue', required: true },
    { key: 'pw', label: 'Secret', type: 'password', required: false },
  ]);
  const form = (o) => new URLSearchParams(o);
  assert.match(g.validate(form({ username: 'x' })).error, /Your name/);
  assert.match(g.validate(form({ username: 'Gohary', sid: '' })).error, /Student ID is required/);
  assert.match(g.validate(form({ username: 'Gohary', sid: '12a', team: 'red' })).error, /must be a number/);
  assert.match(g.validate(form({ username: 'Gohary', sid: '42', email: 'nope', team: 'red' })).error, /email/);
  assert.match(g.validate(form({ username: 'Gohary', sid: '42', team: 'green' })).error, /pick one/);
  const ok = g.validate(form({ username: ' Gohary<b> ', sid: '42', email: 'g@x.io', team: 'blue', pw: 'hunter2' }));
  assert.equal(ok.error, undefined);
  assert.equal(ok.name, 'Goharyb');
  assert.deepEqual(ok.profile, { sid: '42', email: 'g@x.io', team: 'blue', pw: '***' });
  assert.equal(ok.values.pw, '');
});

test('page renders the configured fields and the signed cookie round-trips', () => {
  const { g } = gateWith([{ key: 'sid', label: 'Student ID', type: 'number', required: true }]);
  const html = g.page('/next', 'oops', { sid: '7' });
  assert.ok(html.includes('name="username"') && html.includes('name="sid"') && html.includes('value="7"') && html.includes('oops'));
  const sig = g.sign('Gohary');
  const req = { headers: { cookie: `ctfw_name=${encodeURIComponent('Gohary.' + sig)}` } };
  assert.equal(g.nameFrom(req), 'Gohary');
  assert.equal(g.nameFrom({ headers: { cookie: 'ctfw_name=Gohary.forged' } }), null);
});

test('disabled gate never intercepts; enabled gate intercepts only browser navigations', () => {
  const cfgOn = normalizeConfig({ enabled: true, strict: false, queue: false });
  const cfgOff = normalizeConfig({ enabled: false });
  let cfg = cfgOn;
  const g = new NameGate({ secretFile: null, getConfig: () => cfg });
  const mkRes = () => { const r = { code: null, body: '', writeHead(c) { r.code = c; return r; }, end(b) { r.body = String(b || ''); } }; return r; };
  const nav = { method: 'GET', url: '/', headers: { accept: 'text/html', 'sec-fetch-dest': 'document' }, socket: {} };
  const api = { method: 'GET', url: '/api/x', headers: { accept: 'application/json' }, socket: {} };
  let res = mkRes();
  assert.equal(g.handle(nav, res), true);
  assert.equal(res.code, 200);
  assert.ok(res.body.includes('<form'));
  assert.equal(g.handle(api, mkRes()), false);
  cfg = cfgOff;
  assert.equal(g.handle(nav, mkRes()), false);
});

test('a tool refused by the strict gate is reported through onRefused with its request', () => {
  const g = new NameGate({ secretFile: null, getConfig: () => normalizeConfig({ enabled: true, strict: true, queue: false }) });
  const seen = [];
  g.onRefused = (req, status, text) => seen.push({ ua: req.headers['user-agent'], status, text });
  const req = { method: 'GET', url: '/api/orders/1', headers: { 'user-agent': 'Wget/1.21.4', accept: '*/*' }, socket: { remoteAddress: '10.0.0.9' } };
  const r = { code: null, body: '', writeHead(c) { r.code = c; return r; }, end(b) { r.body = String(b || ''); } };
  assert.equal(g.handle(req, r), true, 'the gate answers the request');
  assert.equal(r.code, 428);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].ua, 'Wget/1.21.4');
  assert.equal(seen[0].status, 428);
  assert.match(seen[0].text, /form/);
});

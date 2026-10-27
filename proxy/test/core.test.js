'use strict';
// Tests for the v1 modules: masking, identity resolution, IDOR / enumeration / burst detection.
const test = require('node:test');
const assert = require('node:assert/strict');
const { maskObject, maskUrl, maskText } = require('../src/mask');
const { IdentityResolver } = require('../src/identity');
const { Detector } = require('../src/detect');
const { decodeJwt, parseBody } = require('../src/util');

const FIELDS = ['password', 'token', 'secret'];

test('masking hides secrets by field name, in URLs and in free text', () => {
  assert.deepEqual(maskObject({ username: 'a', password: 'p', nested: { apiToken: 'x', ok: 1 } }, FIELDS), { username: 'a', password: '***', nested: { apiToken: '***', ok: 1 } });
  assert.equal(maskUrl('/login?user=a&password=p', FIELDS), '/login?user=a&password=***');
  assert.equal(maskText('t=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abcdefghijklmnop'), 't=<jwt:***>');
});

test('jwt and body parsing helpers', () => {
  const payload = Buffer.from(JSON.stringify({ sub: '42', username: 'neo' })).toString('base64url');
  assert.deepEqual(decodeJwt(`Bearer aaa.${payload}.sig`), { sub: '42', username: 'neo' });
  assert.equal(decodeJwt('not a jwt'), null);
  assert.deepEqual(parseBody('application/x-www-form-urlencoded', Buffer.from('a=1&b=x')), { a: '1', b: 'x' });
  assert.deepEqual(parseBody('application/json', Buffer.from('{"a":1}')), { a: 1 });
});

const cfg = {
  identity: {
    jwt: { cookies: ['token'], headers: ['authorization'], nameClaims: ['username'], idClaims: ['id', 'sub'] },
    sessionCookies: ['session'],
    login: { methods: ['POST'], pathPattern: '^/login$', userFields: ['username'], responseIdFields: ['id'] },
    whoami: { pathPattern: '^/api/me$', idFields: ['id'], nameFields: ['username'] },
  },
  compiledLogin: /^\/login$/,
  compiledWhoami: /^\/api\/me$/,
  compiledEndpoints: [
    { name: 'orders', methods: [], re: /^\/api\/orders\/(?<id>\d+)/, idFrom: 'path', idParam: null, owner: 'auto' },
    { name: 'profile', methods: [], re: /^\/api\/users\/(?<id>\d+)/, idFrom: 'path', idParam: null, owner: 'same-as-user' },
  ],
  ownershipMap: { orders: { 9: 'carol' } },
  enumeration: { distinctIds: 3, windowSeconds: 30 },
  bruteForce: { errors: 3, windowSeconds: 20, statuses: new Set([401, 403, 404]) },
  successMinBytes: 2,
  learnFromFirstSuccess: true,
};
const req = (headers = {}, ip = '1.2.3.4') => ({ headers, socket: { remoteAddress: ip }, method: 'GET' });

test('identity: jwt, then session learned at login, then ip fallback', () => {
  const id = new IdentityResolver(() => cfg);
  const payload = Buffer.from(JSON.stringify({ username: 'neo', id: 7 })).toString('base64url');
  assert.deepEqual(id.resolve(req({ cookie: `token=h.${payload}.s` })).name, 'neo');
  assert.equal(id.resolve(req({})).name, 'ip:1.2.3.4');
  assert.equal(id.resolve(req({ 'x-forwarded-for': '9.9.9.9, 1.1.1.1' })).name, 'ip:9.9.9.9');
  const anon = id.resolve(req({ cookie: 'session=abc' }));
  assert.match(anon.name, /^sess-/);
  const learned = id.learn({ req: { ...req({ cookie: 'session=abc' }), method: 'POST' }, identity: anon, reqBody: { username: 'alice', password: 'x' }, status: 200, resHeaders: {}, resBody: { id: 1001 }, pathOnly: '/login' });
  assert.deepEqual(learned, { name: 'alice', id: '1001' });
  const who = id.resolve(req({ cookie: 'session=abc' }));
  assert.equal(who.name, 'alice');
  assert.equal(who.id, '1001');
});

test('detector: ownership map, learning, idor attempt vs success, enumeration and bursts', () => {
  const d = new Detector(() => cfg);
  const alice = { name: 'alice', id: '1001', source: 'session' };
  const bob = { name: 'bob', id: '1002', source: 'session' };
  const t0 = 1_000_000;
  const go = (student, path, status, ts, hasData = true) => d.analyze({ student, method: 'GET', pathOnly: path, url: path, status, size: 50, hasData, reqBody: null, ts });

  // alice quietly reads her order: learned as hers
  let r = go(alice, '/api/orders/1041', 200, t0);
  assert.deepEqual(r.flags, []);
  assert.equal(r.owner, 'alice');
  // bob reads it: attempt + success
  r = go(bob, '/api/orders/1041', 200, t0 + 1000);
  assert.deepEqual(r.flags, ['idor-attempt', 'idor-success']);
  assert.equal(r.severity, 'critical');
  // bob gets a 403 on carol's mapped order: attempt only
  r = go(bob, '/api/orders/9', 403, t0 + 2000);
  assert.deepEqual(r.flags, ['idor-attempt']);
  assert.equal(r.owner, 'carol');
  // profile rule: same-as-user, bob reading his own id is fine, alice's id is an attempt
  assert.deepEqual(go(bob, '/api/users/1002', 200, t0 + 3000).flags, []);
  assert.ok(go(bob, '/api/users/1001', 200, t0 + 3500).flags.includes('idor-success'));
  // enumeration: 3 distinct ids within the window
  r = go(bob, '/api/orders/1043', 404, t0 + 4000, false);
  assert.ok(r.flags.includes('enumeration'));
  assert.ok(r.seq.length >= 3);
  // bursts of errors
  go(bob, '/x', 404, t0 + 5000, false);
  r = go(bob, '/y', 404, t0 + 5100, false);
  assert.ok(r.flags.includes('burst-errors'));
});

test('detector: renaming a student carries state and learned ownership', () => {
  const d = new Detector(() => cfg);
  const a = { name: 'ip:1.1.1.1', id: null, source: 'ip' };
  d.analyze({ student: a, method: 'GET', pathOnly: '/api/orders/5', url: '/api/orders/5', status: 200, size: 9, hasData: true, ts: 1 });
  d.renameStudent('ip:1.1.1.1', 'Gohary');
  const r = d.analyze({ student: { name: 'Gohary', id: null, source: 'name' }, method: 'GET', pathOnly: '/api/orders/5', url: '/api/orders/5', status: 200, size: 9, hasData: true, ts: 2 });
  assert.equal(r.owner, 'Gohary');
  assert.deepEqual(r.flags, []);
});

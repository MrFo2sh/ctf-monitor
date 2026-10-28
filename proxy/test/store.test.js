'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Store } = require('../src/store');
const { Db } = require('../src/db');
const { Detector } = require('../src/detect');

const ev = (over) => ({
  ts: Date.now(), student: 'alice', rawName: 'alice', source: 'name', ip: '10.0.0.1', method: 'GET', path: '/api/orders/1041', endpoint: 'orders', objectId: '1041',
  status: 200, size: 80, latencyMs: 3, severity: 'ok', flags: [], attacks: [], owner: 'alice', ua: 'x', ...over,
});

test('renameInText replaces whole words only', () => {
  assert.equal(Store.renameInText('bob tried orders #1 (belongs to bob)', 'bob', 'Robert'), 'Robert tried orders #1 (belongs to Robert)');
  assert.equal(Store.renameInText('bobby and bob.smith and /bob/x', 'bob', 'R'), 'bobby and bob.smith and /bob/x');
  assert.equal(Store.renameInText('ip:10.0.0.1 appeared', 'ip:10.0.0.1', 'Sara'), 'Sara appeared');
  assert.equal(Store.renameInText('a.b read orders', 'a.b', 'C'), 'C read orders');
});

test('renameStudent rewrites memory and the database rows of the active CTF (issue 5)', () => {
  const db = new Db(':memory:');
  const ctf = db.openCtf('x');
  const store = new Store({ logDir: null, db });
  store.add(ev({ student: 'bob', rawName: 'bob', owner: 'bob' }));
  store.add(ev({ student: 'bob', rawName: 'bob', flags: ['idor-attempt', 'idor-success'], owner: 'alice', mine: false, objectId: '1042', path: '/api/orders/1042', severity: 'critical' }));
  store.add(ev({ student: 'bobby', rawName: 'bobby' }));
  db.flush();
  store.renameStudent('bob', 'Robert');
  assert.ok(store.students.has('Robert') && !store.students.has('bob') && store.students.has('bobby'));
  assert.ok(store.alerts.some((a) => a.student === 'Robert' && /^Robert READ/.test(a.msg)));
  const rows = db.db.prepare('SELECT student, owner FROM requests WHERE ctf_id = ? ORDER BY id').all(ctf.id);
  assert.deepEqual(rows.map((r) => r.student), ['Robert', 'Robert', 'bobby']);
  assert.equal(rows[0].owner, 'Robert', 'owner column follows');
  const alerts = db.db.prepare('SELECT student, msg FROM alerts WHERE ctf_id = ? AND type = ?').all(ctf.id, 'idor-success');
  assert.equal(alerts.length, 1);
  assert.equal(alerts[0].student, 'Robert');
  assert.match(alerts[0].msg, /^Robert READ/);
});

test('renameStudent onto an existing row merges counters', () => {
  const store = new Store({ logDir: null });
  store.add(ev({ student: 'ip:10.0.0.1', source: 'ip' }));
  store.add(ev({ student: 'ip:10.0.0.1', source: 'ip', status: 404, severity: 'notice' }));
  store.add(ev({ student: 'Sara', source: 'name', ip: '10.0.0.2' }));
  store.renameStudent('ip:10.0.0.1', 'Sara');
  const s = store.students.get('Sara');
  assert.equal(s.requests, 3);
  assert.equal(s.failed, 1);
  assert.deepEqual(Object.keys(s.ips).sort(), ['10.0.0.1', '10.0.0.2']);
});

test('detector.renameStudent merges windows when the target already has state (issue 5)', () => {
  const cfg = { compiledEndpoints: [{ name: 'orders', methods: [], re: /^\/api\/orders\/(?<id>\d+)/, idFrom: 'path', idParam: null, owner: 'none' }], ownershipMap: {}, enumeration: { distinctIds: 4, windowSeconds: 60 }, bruteForce: { errors: 100, windowSeconds: 60, statuses: new Set([404]) }, successMinBytes: 1, learnFromFirstSuccess: false };
  const d = new Detector(() => cfg);
  const go = (name, id, ts) => d.analyze({ student: { name, id: null, source: 'ip' }, method: 'GET', pathOnly: `/api/orders/${id}`, url: `/api/orders/${id}`, status: 200, size: 5, hasData: true, ts });
  go('ip:1.1.1.1', 1, 1000);
  go('ip:1.1.1.1', 2, 2000);
  go('Sara', 3, 3000);
  d.renameStudent('ip:1.1.1.1', 'Sara');
  const r = go('Sara', 4, 4000);
  assert.equal(r.distinctIds, 4, 'ids seen under both names count in one window');
  assert.ok(r.flags.includes('enumeration'));
  assert.deepEqual(r.seq, ['1', '2', '3', '4']);
  assert.equal(r.idsSeenTotal, 4);
});

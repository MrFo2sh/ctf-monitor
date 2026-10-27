'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Db } = require('../src/db');
const { compile } = require('../src/query');

const ev = (over) => ({
  ts: Date.now(), student: 'alice', rawName: 'alice', source: 'name', ip: '10.0.0.1', method: 'GET', path: '/api/orders/1041', endpoint: 'orders', objectId: '1041',
  status: 200, size: 80, latencyMs: 3.2, severity: 'ok', flags: [], attacks: [], owner: 'alice', ua: 'curl/8.0', ...over,
});

test('requests are batched, flushed and queryable through the query language', () => {
  const db = new Db(':memory:');
  const ctf = db.openCtf('unit');
  db.addRequest(ev({}));
  db.addRequest(ev({ student: 'bob', status: 403, flags: ['idor-attempt'], path: '/api/orders/1042', objectId: '1042' }));
  db.addRequest(ev({ student: 'bob', status: 200, flags: ['idor-attempt', 'idor-success'], attacks: [{ cls: 'sqli', where: 'url', sample: 'x' }] }));
  const q = compile('student = "bob" AND flag = "idor-success"', { ctfId: ctf.id });
  const rows = db.runSql(q.sql, q.params, 100);
  assert.equal(rows.length, 1);
  assert.deepEqual(rows[0].flags, ['idor-attempt', 'idor-success']);
  assert.equal(rows[0].attacks[0].cls, 'sqli');
  const all = db.runSql(compile('', { ctfId: ctf.id }).sql, [ctf.id], 100);
  assert.equal(all.length, 3);
});

test('player mapping links identities across CTFs', () => {
  const db = new Db(':memory:');
  const c1 = db.openCtf('ctf-1');
  const p1 = db.playerFor([{ kind: 'name', value: 'Gohary' }, { kind: 'ip', value: '41.1.1.1' }], 'Gohary', 1000);
  db.addRequest(ev({ ctfId: c1.id, playerId: p1, student: 'Gohary' }));
  db.flush();
  db.endCtf(c1.id);
  const c2 = db.openCtf('ctf-2');
  assert.notEqual(c1.id, c2.id);
  // same person, new display name, same ip -> same player
  const p2 = db.playerFor([{ kind: 'name', value: 'M. Gohary' }, { kind: 'ip', value: '41.1.1.1' }], 'M. Gohary', 2000);
  assert.equal(p2, p1);
  const other = db.playerFor([{ kind: 'name', value: 'Sara' }, { kind: 'ip', value: '41.1.1.2' }], 'Sara', 2000);
  assert.notEqual(other, p1);
  const h = db.playerHistory(p1);
  assert.deepEqual(h.identities.map((i) => i.value).sort(), ['41.1.1.1', 'Gohary', 'M. Gohary']);
  assert.equal(h.ctfs.length, 1);
  assert.equal(h.ctfs[0].name, 'ctf-1');
});

test('alerts, ack and student detail aggregation', () => {
  const db = new Db(':memory:');
  const ctf = db.openCtf('x');
  db.addAlert({ ts: 1, level: 'critical', type: 'idor-success', student: 'bob', msg: 'bob read 1041' });
  db.addAlert({ ts: 2, level: 'low', type: 'burst-errors', student: 'bob', msg: 'noise' });
  db.addRequest(ev({ student: 'bob', ua: 'curl/8.0', attacks: [{ cls: 'xss', where: 'url', sample: '<script>' }] }));
  db.addRequest(ev({ student: 'bob', ua: 'Mozilla/5.0', ip: '10.0.0.2' }));
  db.flush();
  assert.equal(db.alerts({ ctfId: ctf.id }).length, 2);
  assert.equal(db.alerts({ ctfId: ctf.id, level: 'critical' }).length, 1);
  db.ackAlerts([db.alerts({ ctfId: ctf.id, level: 'critical' })[0].id]);
  assert.equal(db.alerts({ ctfId: ctf.id, ack: 0 }).length, 1);
  const d = db.studentDetail('bob', ctf.id);
  assert.deepEqual(d.userAgents.map((u) => u.ua).sort(), ['Mozilla/5.0', 'curl/8.0']);
  assert.equal(d.ips.length, 2);
  assert.deepEqual(Object.keys(d.attacks), ['xss']);
  assert.equal(d.attacks.xss.count, 1);
  assert.equal(d.requests.length, 2);
});

test('export / import round trip creates an imported CTF with the same requests', () => {
  const db = new Db(':memory:');
  const ctf = db.openCtf('live');
  db.addRequest(ev({}));
  db.addRequest(ev({ student: 'bob' }));
  db.addAlert({ ts: 5, level: 'high', type: 'idor-attempt', student: 'bob', msg: 'm' });
  db.flush();
  const dump = db.exportCtf(ctf.id);
  assert.equal(dump.format, 'ctf-watch/1');
  assert.equal(dump.requests.length, 2);
  const imported = db.importCtf(JSON.parse(JSON.stringify(dump)));
  assert.equal(imported.imported, 1);
  assert.equal(db.requestsOf(imported.id).length, 2);
  assert.equal(db.alerts({ ctfId: imported.id }).length, 1);
  assert.equal(db.listCtfs().length, 2);
  assert.throws(() => db.importCtf({ nope: true }), /not a ctf-watch export/);
});

'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Db } = require('../src/db');
const { Auth, hashPassword, verifyPassword } = require('../src/auth');

function setup() {
  const db = new Db(':memory:');
  const conflicts = [];
  const auth = new Auth(db, { onConflict: (c) => conflicts.push(c), sessionTtlMs: 60000 });
  const creds = auth.generateAccounts(2);
  return { db, auth, creds, conflicts };
}

test('password hashing round-trips and rejects wrong passwords', () => {
  const h = hashPassword('s3cret');
  assert.ok(h.startsWith('scrypt$'));
  assert.ok(verifyPassword('s3cret', h));
  assert.ok(!verifyPassword('S3cret', h));
  assert.ok(!verifyPassword('s3cret', 'garbage'));
});

test('accounts are generated: one admin_xxx plus N users with random passwords', () => {
  const { creds } = setup();
  assert.equal(creds.length, 3);
  assert.match(creds[0].username, /^admin_[a-z0-9]{3}$/);
  assert.equal(creds[0].role, 'admin');
  assert.deepEqual(creds.slice(1).map((c) => c.username), ['user_1', 'user_2']);
  assert.ok(creds.every((c) => c.password.length >= 12));
  assert.notEqual(creds[0].password, creds[1].password);
});

test('login succeeds with the right password and yields a usable session', () => {
  const { auth, creds } = setup();
  const r = auth.login(creds[0].username, creds[0].password, '10.0.0.5');
  assert.ok(r.ok);
  const who = auth.sessionFromToken(r.token);
  assert.equal(who.username, creds[0].username);
  assert.equal(who.role, 'admin');
  auth.logout(r.token);
  assert.equal(auth.sessionFromToken(r.token), null);
});

test('wrong password is refused and rate limited', () => {
  const { auth, creds } = setup();
  for (let i = 0; i < 8; i++) assert.equal(auth.login(creds[0].username, 'nope', '10.0.0.9').status, 401);
  assert.equal(auth.login(creds[0].username, creds[0].password, '10.0.0.9').status, 429);
});

test('single session per account: a second login from another IP is refused, reported and that IP blocked', () => {
  const { auth, creds, conflicts } = setup();
  assert.ok(auth.login(creds[1].username, creds[1].password, '10.0.0.5').ok);
  const second = auth.login(creds[1].username, creds[1].password, '10.0.0.6');
  assert.equal(second.status, 409);
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].username, 'user_1');
  assert.equal(conflicts[0].ip, '10.0.0.6');
  assert.equal(conflicts[0].activeIp, '10.0.0.5');
  assert.ok(auth.isIpBlocked('10.0.0.6'));
  assert.equal(auth.login(creds[0].username, creds[0].password, '10.0.0.6').status, 403);
  auth.unblockIp('10.0.0.6');
  assert.ok(!auth.isIpBlocked('10.0.0.6'));
});

test('re-login from the same IP replaces the session instead of conflicting', () => {
  const { auth, creds } = setup();
  const a = auth.login(creds[0].username, creds[0].password, '10.0.0.5');
  const b = auth.login(creds[0].username, creds[0].password, '10.0.0.5');
  assert.ok(a.ok && b.ok);
  assert.equal(auth.sessionFromToken(a.token), null);
  assert.ok(auth.sessionFromToken(b.token));
});

test('localhost is never blocked', () => {
  const { auth } = setup();
  assert.equal(auth.blockIp('127.0.0.1', 'test'), false);
  assert.ok(!auth.isIpBlocked('127.0.0.1'));
});

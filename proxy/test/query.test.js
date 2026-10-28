'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { compile, parse, QueryError } = require('../src/query');

const NOW = Date.parse('2026-10-28T12:00:00Z');

test('simple comparison compiles to parameterised SQL', () => {
  const q = compile('student = "alice" AND status >= 400', { ctfId: 7, now: NOW });
  assert.equal(q.where, 'WHERE (student = ? AND status >= ?) AND ctf_id = ?');
  assert.deepEqual(q.params, ['alice', 400, 7]);
});

test('OR / NOT / parentheses respect precedence', () => {
  const q = compile('(path ~ "/api/orders" OR endpoint = "orders") AND NOT flag = "idor-success"', { now: NOW });
  assert.equal(q.where, "WHERE ((path LIKE ? ESCAPE '\\' OR endpoint = ?) AND (NOT flags LIKE ?))");
  assert.deepEqual(q.params, ['%/api/orders%', 'orders', '%"idor-success"%']);
});

test('relative time values', () => {
  const q = compile('ts > "-10m"', { now: NOW });
  assert.deepEqual(q.params, [NOW - 10 * 60000]);
  const d = compile("ts >= '-1d'", { now: NOW });
  assert.deepEqual(d.params, [NOW - 86400000]);
});

test('IN lists and numeric coercion', () => {
  const q = compile('method in ("POST", "PUT") AND status < "500"', { now: NOW });
  assert.equal(q.where, 'WHERE (method IN (?, ?) AND status < ?)');
  assert.deepEqual(q.params, ['POST', 'PUT', 500]);
});

test('mentioning ctf disables the automatic ctf scope', () => {
  const q = compile('ctf = 3 AND status = 200', { ctfId: 9, now: NOW });
  assert.deepEqual(q.params, [3, 200]);
  const q2 = compile('NOT (ctf in (1, 2))', { ctfId: 9, now: NOW });
  assert.deepEqual(q2.params, [1, 2]);
});

test('the word "ctf" inside a value does not disable the scope (issue 7)', () => {
  const q = compile('path ~ "/ctf/flag" OR student = "ctf-master"', { ctfId: 9, now: NOW });
  assert.deepEqual(q.params, ['%/ctf/flag%', 'ctf-master', 9]);
  assert.match(q.where, /ctf_id = \?$/);
});

test('empty query returns everything in the active ctf', () => {
  const q = compile('', { ctfId: 2 });
  assert.equal(q.where, 'WHERE ctf_id = ?');
});

test('LIKE wildcards in user input are escaped', () => {
  const q = compile('path ~ "100%_x"', { now: NOW });
  assert.deepEqual(q.params, ['%100\\%\\_x%']);
});

test('validate() reports the position of the problem for the editor', () => {
  const { validate } = require('../src/query');
  assert.deepEqual(validate('student = "alice"'), { ok: true });
  let v = validate('studnt = "alice"');
  assert.equal(v.ok, false); assert.equal(v.pos, 0); assert.equal(v.len, 6); assert.match(v.error, /unknown field/);
  v = validate('status ~ 200');
  assert.equal(v.pos, 7); assert.match(v.error, /cannot be used/);
  v = validate('student = "alice" status = 200');
  assert.equal(v.pos, 18); assert.match(v.error, /AND \/ OR/);
  v = validate('student = "ali');
  assert.equal(v.pos, 10); assert.match(v.error, /unterminated string/);
  v = validate('student =');
  assert.equal(v.pos, 9); assert.match(v.error, /missing value/);
  v = validate('status >');
  assert.match(v.error, /missing value/);
});

test('unknown fields, bad operators and injection attempts are rejected', () => {
  assert.throws(() => parse('password = "x"'), QueryError);
  assert.throws(() => compile('status ~ 200'), QueryError);
  assert.throws(() => parse('student = "a"; DROP TABLE requests'), QueryError);
  assert.throws(() => parse('student = '), QueryError);
  assert.throws(() => compile('ts > "yesterday"'), QueryError);
  assert.throws(() => compile('flag > "x"'), QueryError);
});

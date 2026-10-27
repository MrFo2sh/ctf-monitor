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
});

test('empty query returns everything in the active ctf', () => {
  const q = compile('', { ctfId: 2 });
  assert.equal(q.where, 'WHERE ctf_id = ?');
});

test('LIKE wildcards in user input are escaped', () => {
  const q = compile('path ~ "100%_x"', { now: NOW });
  assert.deepEqual(q.params, ['%100\\%\\_x%']);
});

test('unknown fields, bad operators and injection attempts are rejected', () => {
  assert.throws(() => parse('password = "x"'), QueryError);
  assert.throws(() => compile('status ~ 200'), QueryError);
  assert.throws(() => parse('student = "a"; DROP TABLE requests'), QueryError);
  assert.throws(() => parse('student = '), QueryError);
  assert.throws(() => compile('ts > "yesterday"'), QueryError);
  assert.throws(() => compile('flag > "x"'), QueryError);
});

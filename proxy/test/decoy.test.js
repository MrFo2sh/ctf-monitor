'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { Db } = require('../src/db');
const { Decoy } = require('../src/decoy');

test('decoy: target, list membership, routing decision, rename, persistence', () => {
  const db = new Db(':memory:');
  const d = new Decoy({ db });
  assert.equal(d.targetFor('alice'), null);
  d.setTarget('http://127.0.0.1:4000');
  assert.equal(d.targetFor('alice'), null); // not on the list
  d.add('alice', 'admin_x');
  assert.equal(d.targetFor('alice'), 'http://127.0.0.1:4000');
  assert.equal(d.targetFor('bob'), null);
  d.rename('alice', 'Alice K');
  assert.equal(d.targetFor('alice'), null);
  assert.equal(d.targetFor('Alice K'), 'http://127.0.0.1:4000');
  const again = new Decoy({ db });
  assert.equal(again.targetFor('Alice K'), 'http://127.0.0.1:4000');
  assert.equal(again.list().students[0].by, 'admin_x');
  again.setTarget(null);
  assert.equal(again.targetFor('Alice K'), null); // no decoy app: everyone gets the real CTF
  assert.ok(again.remove('Alice K'));
  assert.ok(!again.remove('nobody'));
});

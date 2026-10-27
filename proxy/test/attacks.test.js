'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { classify, worstLevel } = require('../src/attacks');

const classes = (r) => classify(r).map((h) => h.cls);

test('normal traffic is not flagged', () => {
  assert.deepEqual(classes({ url: '/api/orders/1041', ua: 'Mozilla/5.0 (X11; Linux) Firefox/130' }), []);
  assert.deepEqual(classes({ url: '/search?q=blue+shoes&page=2', bodyText: '{"username":"alice"}', ua: 'Mozilla/5.0' }), []);
});

test('classic injection probes are classified', () => {
  assert.ok(classes({ url: "/api/users?id=1'%20OR%20'1'='1" }).includes('sqli'));
  assert.ok(classes({ url: '/api/users?id=1 UNION SELECT username,password FROM users' }).includes('sqli'));
  assert.ok(classes({ url: '/profile?name=%3Cscript%3Ealert(1)%3C/script%3E' }).includes('xss'));
  assert.ok(classes({ url: '/render?tpl={{7*7}}' }).includes('ssti'));
  assert.ok(classes({ url: '/download?file=../../../../etc/passwd' }).includes('lfi'));
  assert.ok(classes({ url: '/ping?host=127.0.0.1;cat /etc/hostname' }).includes('cmdi'));
  assert.ok(classes({ bodyText: '{"username":{"$ne":null}}' }).includes('nosqli'));
  assert.ok(classes({ url: '/fetch?url=http://169.254.169.254/latest/meta-data/' }).includes('ssrf'));
});

test('double URL encoding is decoded before matching', () => {
  assert.ok(classes({ url: '/f?p=%252e%252e%252f%252e%252e%252fetc%252fpasswd' }).includes('lfi'));
});

test('scanner user agents are flagged from the UA header', () => {
  const hits = classify({ url: '/', ua: 'sqlmap/1.8#stable (https://sqlmap.org)' });
  assert.equal(hits[0].cls, 'scanner');
  assert.equal(hits[0].where, 'user-agent');
});

test('one hit per class, with a short sample and a worst level', () => {
  const hits = classify({ url: "/a?x=1' OR 1=1", bodyText: "y=' or '1'='1" });
  assert.equal(hits.filter((h) => h.cls === 'sqli').length, 1);
  assert.ok(hits[0].sample.length <= 120);
  assert.equal(worstLevel(hits), 'high');
  assert.equal(worstLevel([]), 'info');
});

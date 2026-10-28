'use strict';
// A request the gate refuses never reaches the CTF, but it is recorded: the pipeline turns it into
// a `gate-refused` request with the client's user agent, so the student card lists the tools tried.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const { Config } = require('../src/config');
const { IdentityResolver } = require('../src/identity');
const { Detector } = require('../src/detect');
const { NameGate, normalizeConfig } = require('../src/namegate');
const { buildEvent } = require('../src/pipeline');

test('a gate-refused request becomes a recorded request with its user agent and tool tag', () => {
  process.env.CONFIG_DIR = path.join(__dirname, '..', '..', 'config');
  const config = new Config();
  const gate = new NameGate({ secretFile: null, getConfig: () => normalizeConfig({ strict: true, queue: false }) });
  const identity = new IdentityResolver(() => config.get(), gate);
  const detector = new Detector(() => config.get());
  const deps = { getConfig: () => config.get(), identity, detector, alias: (n) => n, profiles: {}, playerIdFor: () => null, isDecoy: () => false };
  const req = { method: 'GET', url: '/api/orders/1', headers: { 'user-agent': 'Wget/1.21.4', accept: '*/*', host: 'localhost:8888' }, socket: { remoteAddress: '10.0.0.9' } };
  const ev = buildEvent({ ts: Date.now(), req, method: 'GET', url: '/api/orders/1', pathOnly: '/api/orders/1', status: 428, size: 0, latencyMs: 0, reqLen: 0, reqBuf: Buffer.alloc(0), resHeaders: {}, resBuf: Buffer.alloc(0), error: 'gate' }, deps);
  assert.equal(ev.status, 428);
  assert.ok(ev.flags.includes('gate-refused'), ev.flags.join(','));
  assert.ok(ev.flags.includes('attack:tool'), 'wget is tagged as a plain tool');
  assert.equal(ev.ua, 'Wget/1.21.4');
  assert.equal(ev.severity, 'notice');
  assert.equal(ev.ip, '10.0.0.9');
  assert.equal(ev.endpoint, null, 'no IDOR analysis: nothing reached the app');
});

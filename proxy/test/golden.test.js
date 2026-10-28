'use strict';
// Golden replay: recorded raw proxy exchanges (fixtures/golden-raw.jsonl) are pushed through the event
// pipeline exactly as server.js does it, and the result must match what the code produced when the
// fixture was recorded (fixtures/golden-expected.json). Any change in identity, detection, attack
// classification, masking or alerting shows up here as a diff, request by request.
//
// To re-record after an intended change:  see dev_docs/26-tests.md ("golden fixture").

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { Config } = require('../src/config');
const { IdentityResolver } = require('../src/identity');
const { Detector } = require('../src/detect');
const { Store } = require('../src/store');
const { NameGate, normalizeConfig } = require('../src/namegate');
const { buildEvent, rawFromJson } = require('../src/pipeline');

const FIX = path.join(__dirname, 'fixtures');

function runPipeline(rawLines) {
  process.env.CONFIG_DIR = path.join(__dirname, '..', '..', 'config');
  const config = new Config();
  // the fixture's gate cookies were signed with this secret (recorded together with the traffic)
  const gate = new NameGate({ secretFile: path.join(FIX, 'golden-gate-secret'), getConfig: () => normalizeConfig({ strict: false, queue: false }) });
  const identity = new IdentityResolver(() => config.get(), gate);
  const detector = new Detector(() => config.get());
  const store = new Store({ logDir: null });
  const deps = { getConfig: () => config.get(), identity, detector, alias: (n) => n, profiles: {}, playerIdFor: () => null, isDecoy: () => false };
  // the same row-merging the server does when an anonymous row gets identified
  const merge = (from, to) => { if (store.students.has(from) && from !== to) { store.renameStudent(from, to); detector.renameStudent(from, to); } };
  gate.onIpNamed = (ip, name) => merge(`ip:${ip}`, name);
  identity.onSessionNamed = (label, name) => merge(label, name);
  const events = [];
  for (const line of rawLines) {
    const ev = buildEvent(rawFromJson(JSON.parse(line)), deps);
    store.add(ev);
    events.push(ev);
  }
  return { events, alerts: store.alerts };
}

const pick = (e) => ({ student: e.student, source: e.source, endpoint: e.endpoint, object_id: e.objectId == null ? null : String(e.objectId), owner: e.owner, flags: e.flags, severity: e.severity, attacks: (e.attacks || []).map((a) => a.cls), path: e.path });

test('golden replay: recorded traffic produces the recorded flags, severities, owners and alerts', () => {
  const rawFile = path.join(FIX, 'golden-raw.jsonl');
  const expFile = path.join(FIX, 'golden-expected.json');
  assert.ok(fs.existsSync(rawFile) && fs.existsSync(expFile), 'fixtures missing');
  const raw = fs.readFileSync(rawFile, 'utf8').trim().split('\n');
  const expected = JSON.parse(fs.readFileSync(expFile, 'utf8'));
  assert.equal(raw.length, expected.count, 'fixture length');

  const { events, alerts } = runPipeline(raw);
  // the fixture's "student" is the final name after the server merged anonymous rows; compare after the same merging
  const got = events.map(pick);
  const diffs = [];
  for (let i = 0; i < expected.events.length; i++) {
    const a = expected.events[i], b = got[i];
    for (const k of Object.keys(a)) if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) diffs.push(`#${i} ${a.path}: ${k} expected ${JSON.stringify(a[k])} got ${JSON.stringify(b[k])}`);
  }
  assert.deepEqual(diffs, [], `pipeline output changed:\n${diffs.slice(0, 20).join('\n')}${diffs.length > 20 ? `\n... ${diffs.length - 20} more` : ''}`);

  // alerts: same multiset of (type, level), order-insensitive (timing of replays can reorder equal-ts alerts)
  const key = (a) => `${a.type}|${a.level}`;
  const count = (list) => list.reduce((m, a) => ((m[key(a)] = (m[key(a)] || 0) + 1), m), {});
  const expAlerts = expected.alerts.filter((a) => a.type !== 'new-student' && a.type !== 'info');
  const gotAlerts = alerts.filter((a) => a.type !== 'new-student' && a.type !== 'info');
  assert.deepEqual(count(gotAlerts), count(expAlerts), 'alert counts per type/level changed');
});

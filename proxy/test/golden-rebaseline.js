'use strict';
// Re-baselines fixtures/golden-expected.json from fixtures/golden-raw.jsonl with the CURRENT code.
// Use it only after an intended behaviour change, after reading the diff the golden test printed.
//   node test/golden-rebaseline.js            -> prints the per-event differences and writes the new file
//   node test/golden-rebaseline.js --dry      -> prints the differences only
const fs = require('fs');
const path = require('path');
const { Config } = require('../src/config');
const { IdentityResolver } = require('../src/identity');
const { Detector } = require('../src/detect');
const { Store } = require('../src/store');
const { NameGate, normalizeConfig } = require('../src/namegate');
const { buildEvent, rawFromJson } = require('../src/pipeline');

const FIX = path.join(__dirname, 'fixtures');
process.env.CONFIG_DIR = path.join(__dirname, '..', '..', 'config');
const config = new Config();
const gate = new NameGate({ secretFile: path.join(FIX, 'golden-gate-secret'), getConfig: () => normalizeConfig({ strict: false, queue: false }) });
const identity = new IdentityResolver(() => config.get(), gate);
const detector = new Detector(() => config.get());
const store = new Store({ logDir: null });
const merge = (from, to) => { if (store.students.has(from) && from !== to) { store.renameStudent(from, to); detector.renameStudent(from, to); } };
gate.onIpNamed = (ip, name) => merge(`ip:${ip}`, name);
identity.onSessionNamed = (label, name) => merge(label, name);
const deps = { getConfig: () => config.get(), identity, detector, alias: (n) => n, profiles: {}, playerIdFor: () => null, isDecoy: () => false };

const raw = fs.readFileSync(path.join(FIX, 'golden-raw.jsonl'), 'utf8').trim().split('\n');
const old = JSON.parse(fs.readFileSync(path.join(FIX, 'golden-expected.json'), 'utf8'));
const events = raw.map((line) => { const ev = buildEvent(rawFromJson(JSON.parse(line)), deps); store.add(ev); return ev; });
const pick = (e) => ({ student: e.student, source: e.source, endpoint: e.endpoint, object_id: e.objectId == null ? null : String(e.objectId), owner: e.owner, flags: e.flags, severity: e.severity, attacks: (e.attacks || []).map((a) => a.cls), path: e.path });
const next = { ctf: old.ctf, count: events.length, alerts: store.alerts.map((a) => ({ type: a.type, level: a.level, student: a.student })), events: events.map(pick) };

let changed = 0;
next.events.forEach((b, i) => { const a = old.events[i] || {}; for (const k of Object.keys(b)) if (JSON.stringify(a[k]) !== JSON.stringify(b[k])) { changed++; console.log(`#${i} ${b.path}: ${k} ${JSON.stringify(a[k])} -> ${JSON.stringify(b[k])}`); } });
const count = (l) => l.reduce((m, a) => ((m[`${a.type}|${a.level}`] = (m[`${a.type}|${a.level}`] || 0) + 1), m), {});
const ca = count(old.alerts), cb = count(next.alerts);
for (const k of new Set([...Object.keys(ca), ...Object.keys(cb)])) if (ca[k] !== cb[k]) { changed++; console.log(`alerts ${k}: ${ca[k] || 0} -> ${cb[k] || 0}`); }
console.log(`${changed} difference(s)`);
if (!process.argv.includes('--dry')) {
  fs.writeFileSync(path.join(FIX, 'golden-expected.json'), JSON.stringify(next) + '\n');
  console.log('golden-expected.json rewritten');
}

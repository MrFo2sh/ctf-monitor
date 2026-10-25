'use strict';
// Organizer actions from the (local-only) dashboard: block / unblock / rename a student.
// Persisted in logs/admin-state.json so they survive a restart.

const fs = require('fs');
const path = require('path');
const { log } = require('./util');
const { NameGate } = require('./namegate');

class Admin {
  constructor({ file, store, detector, gate }) {
    this.file = file;
    this.store = store;
    this.detector = detector;
    this.gate = gate;
    this.state = { blocked: {}, aliases: {} };
    this.load();
  }

  load() {
    try {
      if (this.file && fs.existsSync(this.file)) {
        const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        this.state.blocked = raw.blocked && typeof raw.blocked === 'object' ? raw.blocked : {};
        this.state.aliases = raw.aliases && typeof raw.aliases === 'object' ? raw.aliases : {};
        const n = Object.keys(this.state.blocked).length;
        if (n) log('info', `admin: ${n} blocked student(s) loaded`);
      }
    } catch (err) {
      log('error', `admin state could not be read: ${err.message}`);
    }
  }

  save() {
    if (!this.file) return;
    try {
      fs.mkdirSync(path.dirname(this.file), { recursive: true });
      fs.writeFileSync(this.file, JSON.stringify(this.state, null, 2));
    } catch (err) {
      log('error', `admin state could not be saved: ${err.message}`);
    }
  }

  alias(rawName) {
    return this.state.aliases[rawName] || rawName;
  }

  blockedIps() {
    const s = new Set();
    for (const b of Object.values(this.state.blocked)) if (b && b.ip) s.add(b.ip);
    return s;
  }

  isBlocked(name, ip) {
    if (this.state.blocked[name]) return true;
    return !!(ip && this.blockedIps().has(ip));
  }

  block(name) {
    if (!name) throw new Error('student name required');
    const s = this.store.students.get(name);
    let ip = s ? s.ip : null;
    // do not block an ip that several students share (classroom NAT)
    if (ip && this.gate && this.gate.ipNames.get(ip) && this.gate.ipNames.get(ip).names.size > 1) ip = null;
    if (ip && /^(127\.|::1|unknown)/.test(ip)) ip = null;
    this.state.blocked[name] = { ip, ts: Date.now() };
    this.save();
    log('info', `admin: blocked ${name}${ip ? ` (ip ${ip})` : ''}`);
    return { name, ip };
  }

  unblock(name) {
    delete this.state.blocked[name];
    this.save();
    log('info', `admin: unblocked ${name}`);
  }

  rename(from, to) {
    const clean = NameGate.clean(to);
    if (!clean) throw new Error('new name must be 2-32 letters, digits, space, _ . -');
    if (!from || from === clean) return clean;
    // the alias is keyed by the raw identity name (as the proxy sees it), so follow existing aliases back
    let found = false;
    for (const [raw, al] of Object.entries(this.state.aliases)) {
      if (al === from) {
        this.state.aliases[raw] = clean;
        found = true;
      }
    }
    if (!found) this.state.aliases[from] = clean;
    if (this.state.blocked[from]) {
      this.state.blocked[clean] = this.state.blocked[from];
      delete this.state.blocked[from];
    }
    this.save();
    this.store.renameStudent(from, clean);
    this.detector.renameStudent(from, clean);
    log('info', `admin: renamed ${from} -> ${clean}`);
    return clean;
  }

  list() {
    return {
      blocked: Object.entries(this.state.blocked).map(([name, b]) => ({ name, ip: b.ip, ts: b.ts })),
      aliases: this.state.aliases,
    };
  }
}

module.exports = { Admin };

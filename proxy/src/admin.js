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
    this.state = { blocked: {}, aliases: {}, revoked: {} };
    this.load();
    if (this.gate) this.gate.onRename = (oldRaw, newName) => this.onGateRename(oldRaw, newName);
  }

  load() {
    try {
      if (this.file && fs.existsSync(this.file)) {
        const raw = JSON.parse(fs.readFileSync(this.file, 'utf8'));
        this.state.blocked = raw.blocked && typeof raw.blocked === 'object' ? raw.blocked : {};
        this.state.aliases = raw.aliases && typeof raw.aliases === 'object' ? raw.aliases : {};
        this.state.revoked = raw.revoked && typeof raw.revoked === 'object' ? raw.revoked : {};
        if (this.gate) for (const r of Object.keys(this.state.revoked)) this.gate.revoke(r);
        const n = Object.keys(this.state.blocked).length;
        if (n) log('info', `admin: ${n} blocked student(s) loaded`);
      }
    } catch (err) {
      log('error', `admin state could not be read: ${err.message}`);
    }
  }

  // raw identity name (what the proxy sees in the cookie) behind a dashboard name
  rawNameFor(displayName) {
    for (const [raw, al] of Object.entries(this.state.aliases)) if (al === displayName) return raw;
    const s = this.store.students.get(displayName);
    return (s && s.rawName) || displayName;
  }

  // "Ask to rename": the student's current name is rejected; the name page comes back in their browser.
  requireRename(displayName) {
    if (!this.gate) throw new Error('the name gate is off (set NAME_GATE=1 in .env)');
    const raw = this.rawNameFor(displayName);
    this.gate.revoke(raw);
    this.state.revoked[raw] = Date.now();
    this.save();
    log('info', `admin: asked ${displayName} to rename`);
    return { name: displayName };
  }

  isRenamePending(displayName) {
    return !!this.state.revoked[this.rawNameFor(displayName)];
  }

  // the student entered a new name after being asked: carry their history over
  onGateRename(oldRaw, newName) {
    const oldDisplay = this.alias(oldRaw);
    delete this.state.aliases[oldRaw];
    delete this.state.revoked[oldRaw];
    if (this.state.blocked[oldDisplay]) {
      this.state.blocked[newName] = this.state.blocked[oldDisplay];
      delete this.state.blocked[oldDisplay];
    }
    this.save();
    this.store.renameStudent(oldDisplay, newName);
    this.detector.renameStudent(oldDisplay, newName);
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
      renamePending: Object.keys(this.state.revoked).map((raw) => this.alias(raw)),
    };
  }
}

module.exports = { Admin };

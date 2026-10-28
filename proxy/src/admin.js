'use strict';
// Organizer actions from the dashboard: block / unblock / rename / ask-to-rename a student.
// State lives in the database (kv table) so it survives a restart.

const { log } = require('./util');
const { NameGate } = require('./namegate');

class Admin {
  constructor({ db, store, detector, gate }) {
    this.db = db;
    this.store = store;
    this.detector = detector;
    this.gate = gate;
    this.state = { blocked: {}, aliases: {}, revoked: {} };
    this.load();
    if (this.gate) this.gate.onRename = (oldRaw, newName) => this.onGateRename(oldRaw, newName);
  }

  load() {
    const raw = this.db.get('admin_state', null);
    if (raw && typeof raw === 'object') {
      this.state.blocked = raw.blocked || {};
      this.state.aliases = raw.aliases || {};
      this.state.revoked = raw.revoked || {};
      if (this.gate) for (const r of Object.keys(this.state.revoked)) this.gate.revoke(r);
      const n = Object.keys(this.state.blocked).length;
      if (n) log('info', `admin: ${n} blocked student(s) loaded`);
    }
  }
  save() {
    this.db.set('admin_state', this.state);
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

  block(name, ipOverride) {
    if (!name) throw new Error('student name required');
    const s = this.store.students.get(name);
    let ip = ipOverride || (s ? s.ip : null);
    if (ip && this.gate && this.gate.ipNames.get(ip) && this.gate.ipNames.get(ip).names.size > 1) ip = null; // shared ip
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

  rawNameFor(displayName) {
    for (const [raw, al] of Object.entries(this.state.aliases)) if (al === displayName) return raw;
    const s = this.store.students.get(displayName);
    return (s && s.rawName) || displayName;
  }

  rename(from, to) {
    const clean = NameGate.clean(to);
    if (!clean) throw new Error('new name must be 2-32 letters, digits, space, _ . -');
    if (!from || from === clean) return clean;
    let found = false;
    for (const [raw, al] of Object.entries(this.state.aliases)) if (al === from) { this.state.aliases[raw] = clean; found = true; }
    if (!found) this.state.aliases[from] = clean;
    if (this.state.blocked[from]) { this.state.blocked[clean] = this.state.blocked[from]; delete this.state.blocked[from]; }
    this.save();
    this.store.renameStudent(from, clean);
    this.detector.renameStudent(from, clean);
    if (this.onRenamed) this.onRenamed(from, clean);
    log('info', `admin: renamed ${from} -> ${clean}`);
    return clean;
  }

  requireRename(displayName) {
    if (!this.gate || !this.gate.enabled) throw new Error('the gate is switched off (Gate tab) - turn it on to ask students for their name');
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
  onGateRename(oldRaw, newName) {
    const oldDisplay = this.alias(oldRaw);
    delete this.state.aliases[oldRaw];
    delete this.state.revoked[oldRaw];
    if (this.state.blocked[oldDisplay]) { this.state.blocked[newName] = this.state.blocked[oldDisplay]; delete this.state.blocked[oldDisplay]; }
    this.save();
    this.store.renameStudent(oldDisplay, newName);
    this.detector.renameStudent(oldDisplay, newName);
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

'use strict';
// The decoy: a second app behind the proxy. Students on the decoy list are routed to it instead of
// the real CTF, transparently (same link, same cookies). Persisted in the database (kv "decoy").

const { log } = require('./util');

class Decoy {
  constructor({ db }) {
    this.db = db;
    const saved = db.get('decoy', null) || {};
    this.target = saved.target || null; // http://host:port or null
    this.students = new Map(Object.entries(saved.students || {})); // display name -> { since, by, reason }
    this.listeners = new Set();
  }
  onChange(fn) {
    this.listeners.add(fn);
  }
  save() {
    this.db.set('decoy', { target: this.target, students: Object.fromEntries(this.students) });
    for (const l of this.listeners) {
      try {
        l();
      } catch {}
    }
  }
  setTarget(url) {
    this.target = url || null;
    this.save();
    log('info', `decoy target: ${this.target || '(none)'}`);
  }
  has(name) {
    return this.students.has(name);
  }
  // the upstream this student should get, or null for the real CTF
  targetFor(name) {
    return this.target && name && this.students.has(name) ? this.target : null;
  }
  add(name, by, reason) {
    if (!name) throw new Error('student name required');
    this.students.set(name, { since: Date.now(), by: by || null, reason: reason || null });
    this.save();
    log('info', `decoy: ${name} -> decoy${by ? ` (by ${by})` : ''}`);
  }
  remove(name) {
    const had = this.students.delete(name);
    if (had) {
      this.save();
      log('info', `decoy: ${name} -> back to the real CTF`);
    }
    return had;
  }
  rename(from, to) {
    if (this.students.has(from)) {
      const v = this.students.get(from);
      this.students.delete(from);
      this.students.set(to, v);
      this.save();
    }
  }
  list() {
    return { target: this.target, students: [...this.students.entries()].map(([name, v]) => ({ name, ...v })) };
  }
}

module.exports = { Decoy };

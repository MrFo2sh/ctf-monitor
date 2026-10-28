'use strict';
// The admission queue: students who filled the gate form wait here until the organizer approves them.
// Persisted in the database (kv "gate_queue"), keyed by the raw name typed on the form.

const { log } = require('./util');

const STATUSES = ['pending', 'approved', 'blocked'];

class Approvals {
  constructor({ db }) {
    this.db = db;
    this.items = new Map(); // rawName -> { name, profile, ip, ua, firstSeen, status, decidedAt, by }
    for (const [k, v] of Object.entries(db.get('gate_queue', {}) || {})) this.items.set(k, v);
    this.listeners = new Set();
  }
  onChange(fn) {
    this.listeners.add(fn);
  }
  save(changedNames) {
    this.db.set('gate_queue', Object.fromEntries(this.items));
    for (const l of this.listeners) {
      try {
        l(changedNames || []);
      } catch {}
    }
  }

  // Called when a student submits the form (or shows up with a cookie we have not seen). Keeps an existing decision.
  enqueue(name, info = {}) {
    let it = this.items.get(name);
    if (!it) {
      it = { name, profile: info.profile || {}, ip: info.ip || null, ua: info.ua || null, firstSeen: Date.now(), status: 'pending', decidedAt: null, by: null };
      this.items.set(name, it);
      log('info', `queue: ${name} is waiting for approval${it.ip ? ` (ip ${it.ip})` : ''}`);
    } else {
      if (info.profile && Object.keys(info.profile).length) it.profile = { ...it.profile, ...info.profile };
      if (info.ip) it.ip = info.ip;
      if (info.ua) it.ua = info.ua;
    }
    this.save();
    return it;
  }

  status(name) {
    const it = this.items.get(name);
    return it ? it.status : null; // null = never seen
  }
  get(name) {
    return this.items.get(name) || null;
  }

  decide(names, status, by) {
    if (!STATUSES.includes(status)) throw new Error('bad status');
    const changed = [];
    for (const n of [].concat(names || [])) {
      const it = this.items.get(n);
      if (!it) continue;
      it.status = status;
      it.decidedAt = status === 'pending' ? null : Date.now();
      it.by = status === 'pending' ? null : by || null;
      changed.push(n);
    }
    if (changed.length) {
      this.save(changed);
      log('info', `queue: ${status} -> ${changed.join(', ')}${by ? ` (by ${by})` : ''}`);
    }
    return changed;
  }
  approve(names, by) {
    return this.decide(names, 'approved', by);
  }
  block(names, by) {
    return this.decide(names, 'blocked', by);
  }
  reset(names) {
    return this.decide(names, 'pending');
  }
  remove(names) {
    const gone = [].concat(names || []).filter((x) => this.items.delete(x));
    if (gone.length) this.save(gone);
    return gone.length;
  }

  list() {
    return [...this.items.values()].sort((a, b) => (a.status === b.status ? a.firstSeen - b.firstSeen : STATUSES.indexOf(a.status) - STATUSES.indexOf(b.status)));
  }
  counts() {
    const c = { pending: 0, approved: 0, blocked: 0 };
    for (const it of this.items.values()) c[it.status] = (c[it.status] || 0) + 1;
    return c;
  }
}

module.exports = { Approvals, STATUSES };

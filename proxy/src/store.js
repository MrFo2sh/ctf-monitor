'use strict';
// In-memory state for the dashboard + JSONL log writer.

const fs = require('fs');
const path = require('path');
const { log } = require('./util');

const MAX_EVENTS = 1500;
const MAX_ALERTS = 300;
const RPS_WINDOW = 120; // seconds of per-second counts kept

function pathTemplate(p) {
  return p.replace(/\/\d+(?=\/|$)/g, '/:id').replace(/\/[0-9a-f]{8}-[0-9a-f-]{27,}(?=\/|$)/gi, '/:uuid');
}

class Store {
  constructor({ logDir, demo }) {
    this.logDir = logDir;
    this.demo = !!demo;
    this.startedAt = Date.now();
    this.events = [];
    this.alerts = [];
    this.students = new Map();
    this.total = 0;
    this.byStatus = {};
    this.byEndpoint = new Map();
    this.rps = new Array(RPS_WINDOW).fill(0);
    this.rpsHead = Math.floor(Date.now() / 1000);
    this.listeners = new Set();
    this.resetListeners = new Set();
    this.isBlocked = () => false; // set by server.js (admin block list)
    this.renamePending = () => false; // set by server.js (admin "ask to rename")
    this.seq = 0;
    this.stream = null;
    this.streamDate = null;
    this.firstIdorSuccess = null;
    if (logDir) fs.mkdirSync(logDir, { recursive: true });
  }

  onEvent(fn) {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }
  onReset(fn) {
    this.resetListeners.add(fn);
  }

  // Admin rename: rewrite history so the dashboard shows one lane under the new name.
  renameStudent(oldName, newName) {
    if (!oldName || !newName || oldName === newName) return;
    for (const ev of this.events) if (ev.student === oldName) ev.student = newName;
    for (const a of this.alerts) {
      if (a.student === oldName) a.student = newName;
      a.msg = a.msg.split(oldName).join(newName);
    }
    const s = this.students.get(oldName);
    if (s) {
      this.students.delete(oldName);
      const t = this.students.get(newName);
      if (t) {
        for (const k of ['requests', 'failed', 'flagged', 'idorAttempts', 'idorSuccess', 'enumeration', 'bursts']) t[k] += s[k];
        t.distinctIds = Math.max(t.distinctIds, s.distinctIds);
        t.firstSeen = Math.min(t.firstSeen, s.firstSeen);
        t.lastSeen = Math.max(t.lastSeen, s.lastSeen);
        if (s.firstIdorSuccessTs && (!t.firstIdorSuccessTs || s.firstIdorSuccessTs < t.firstIdorSuccessTs)) t.firstIdorSuccessTs = s.firstIdorSuccessTs;
        Object.assign(t.seq, s.seq);
        for (const [ip, e] of Object.entries(s.ips)) {
          if (t.ips[ip]) {
            t.ips[ip].n += e.n;
            t.ips[ip].last = Math.max(t.ips[ip].last, e.last);
          } else t.ips[ip] = e;
        }
        for (const a of s.appNames) if (!t.appNames.includes(a)) t.appNames.push(a);
      } else {
        s.name = newName;
        this.students.set(newName, s);
      }
    }
    if (this.firstIdorSuccess && this.firstIdorSuccess.student === oldName) this.firstIdorSuccess.student = newName;
    for (const l of this.resetListeners) l();
  }

  student(ev) {
    let s = this.students.get(ev.student);
    if (!s) {
      s = {
        name: ev.student,
        id: ev.studentId || null,
        source: ev.source,
        ip: ev.ip,
        firstSeen: ev.ts,
        lastSeen: ev.ts,
        requests: 0,
        failed: 0,
        flagged: 0,
        idorAttempts: 0,
        idorSuccess: 0,
        enumeration: 0,
        bursts: 0,
        distinctIds: 0,
        firstIdorSuccessTs: null,
        seq: {},
        ips: {}, // ip -> { n, last }
        appNames: [],
      };
      this.students.set(ev.student, s);
    }
    return s;
  }

  static noteIp(s, ip, ts) {
    if (!ip) return;
    const e = s.ips[ip];
    if (e) {
      e.n++;
      e.last = ts;
    } else if (Object.keys(s.ips).length < 25) s.ips[ip] = { n: 1, last: ts, first: ts };
  }

  add(ev) {
    ev.n = ++this.seq;
    this.total++;
    const st = this.byStatus;
    st[ev.status] = (st[ev.status] || 0) + 1;

    const key = ev.endpoint ? `${ev.endpoint}` : pathTemplate(ev.path.split('?')[0]);
    this.byEndpoint.set(key, (this.byEndpoint.get(key) || 0) + 1);

    this.tick(ev.ts, 1);

    const s = this.student(ev);
    s.lastSeen = ev.ts;
    s.requests++;
    if (ev.studentId && !s.id) s.id = ev.studentId;
    if (ev.rawName) s.rawName = ev.rawName;
    if (ev.source !== 'ip') s.source = ev.source;
    if (ev.appName) {
      s.appName = ev.appName;
      if (!s.appNames.includes(ev.appName) && s.appNames.length < 10) s.appNames.push(ev.appName);
    }
    Store.noteIp(s, ev.ip, ev.ts);
    if (ev.status >= 400) s.failed++;
    if (ev.flags.length) s.flagged++;
    if (ev.flags.includes('idor-attempt')) s.idorAttempts++;
    if (ev.flags.includes('idor-success')) {
      s.idorSuccess++;
      if (!s.firstIdorSuccessTs) s.firstIdorSuccessTs = ev.ts;
      if (!this.firstIdorSuccess) this.firstIdorSuccess = { student: s.name, ts: ev.ts, endpoint: ev.endpoint, objectId: ev.objectId };
    }
    if (ev.flags.includes('enumeration')) s.enumeration++;
    if (ev.flags.includes('burst-errors')) s.bursts++;
    if (ev.idsSeenTotal) s.distinctIds = ev.idsSeenTotal;
    if (ev.endpoint && ev.seq) s.seq[ev.endpoint] = ev.seq;

    this.events.push(ev);
    if (this.events.length > MAX_EVENTS) this.events.splice(0, this.events.length - MAX_EVENTS);

    const alert = this.alertFor(ev, s);
    if (alert) {
      this.alerts.push(alert);
      if (this.alerts.length > MAX_ALERTS) this.alerts.splice(0, this.alerts.length - MAX_ALERTS);
    }

    this.writeLog(ev);
    for (const l of this.listeners) {
      try {
        l(ev, alert);
      } catch (err) {
        log('error', `listener failed: ${err.message}`);
      }
    }
  }

  // Only the interesting things become alerts (and not one alert per request during a burst).
  alertFor(ev, s) {
    let type = null;
    let msg = null;
    if (ev.flags.includes('blocked')) return null;
    if (ev.flags.includes('idor-success')) {
      type = 'idor-success';
      msg = `${ev.student} READ ${ev.endpoint} #${ev.objectId}${ev.owner ? ` (belongs to ${ev.owner})` : ''} - HTTP ${ev.status}, ${ev.size} bytes`;
    } else if (ev.flags.includes('idor-attempt')) {
      type = 'idor-attempt';
      msg = `${ev.student} tried ${ev.endpoint} #${ev.objectId}${ev.owner ? ` (belongs to ${ev.owner})` : ''} - HTTP ${ev.status}`;
    } else if (ev.flags.includes('burst-errors') && (s.bursts === 1 || s.bursts % 25 === 0)) {
      type = 'burst-errors';
      msg = `${ev.student} is producing a burst of ${ev.status} errors (${ev.method} ${ev.path})`;
    } else if (ev.flags.includes('enumeration')) {
      // one alert per 10 ids to keep the feed readable
      if (ev.distinctIds % 10 !== 0 && s.enumeration !== 1) return null;
      type = 'enumeration';
      msg = `${ev.student} is enumerating ${ev.endpoint}: ${ev.distinctIds} different IDs (${ev.seq.slice(-4).join(' -> ')})`;
    }
    if (!type) return null;
    return { n: ev.n, ts: ev.ts, type, student: ev.student, endpoint: ev.endpoint, objectId: ev.objectId, owner: ev.owner, status: ev.status, msg };
  }

  tick(ts, inc) {
    const sec = Math.floor(ts / 1000);
    if (sec > this.rpsHead) {
      const gap = Math.min(sec - this.rpsHead, RPS_WINDOW);
      for (let i = 0; i < gap; i++) {
        this.rps.shift();
        this.rps.push(0);
      }
      this.rpsHead = sec;
    }
    const idx = RPS_WINDOW - 1 - (this.rpsHead - sec);
    if (idx >= 0 && idx < RPS_WINDOW) this.rps[idx] += inc;
  }

  stats() {
    this.tick(Date.now(), 0);
    const last60 = this.rps.slice(-60);
    const last10 = this.rps.slice(-11, -1);
    const topEndpoints = [...this.byEndpoint.entries()].sort((a, b) => b[1] - a[1]).slice(0, 8).map(([name, count]) => ({ name, count }));
    const classes = { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0 };
    for (const [code, n] of Object.entries(this.byStatus)) {
      const c = `${String(code)[0]}xx`;
      if (classes[c] !== undefined) classes[c] += n;
    }
    const students = [...this.students.values()].map((s) => ({ ...s, blocked: this.isBlocked(s.name), renamePending: this.renamePending(s.name) }));
    const lb = {
      firstIdorSuccess: this.firstIdorSuccess,
      mostIds: students.filter((s) => s.distinctIds > 0).sort((a, b) => b.distinctIds - a.distinctIds).slice(0, 5).map((s) => ({ student: s.name, value: s.distinctIds })),
      mostFailed: students.filter((s) => s.failed > 0).sort((a, b) => b.failed - a.failed).slice(0, 5).map((s) => ({ student: s.name, value: s.failed })),
      mostIdor: students.filter((s) => s.idorSuccess > 0).sort((a, b) => b.idorSuccess - a.idorSuccess || a.firstIdorSuccessTs - b.firstIdorSuccessTs).slice(0, 5).map((s) => ({ student: s.name, value: s.idorSuccess })),
    };
    return {
      demo: this.demo,
      uptimeSec: Math.round((Date.now() - this.startedAt) / 1000),
      total: this.total,
      rps: last60,
      rpsNow: last10.reduce((a, b) => a + b, 0) / 10,
      statusClasses: classes,
      byStatus: this.byStatus,
      topEndpoints,
      students,
      leaderboard: lb,
      alertsTotal: this.alerts.length,
    };
  }

  snapshot() {
    return { events: this.events.slice(-500), alerts: this.alerts.slice(-100), stats: this.stats() };
  }

  writeLog(ev) {
    if (!this.logDir) return;
    const day = new Date(ev.ts).toISOString().slice(0, 10);
    if (!this.stream || this.streamDate !== day) {
      if (this.stream) this.stream.end();
      const file = path.join(this.logDir, `events-${day}.jsonl`);
      this.stream = fs.createWriteStream(file, { flags: 'a' });
      this.stream.on('error', (err) => log('error', `log write failed: ${err.message}`));
      this.streamDate = day;
      log('info', `logging to ${file}`);
    }
    const { req, ...rest } = ev; // never serialise the raw request object
    this.stream.write(JSON.stringify(rest) + '\n');
  }
}

module.exports = { Store };

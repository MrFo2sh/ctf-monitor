'use strict';
// SQLite persistence (Node's built-in node:sqlite, no dependency).
// Holds CTFs, players (mapped across CTFs), requests, alerts, accounts, sessions and admin state.
// Request writes are batched in a transaction every ~200 ms so fuzzing traffic never blocks the proxy.

const path = require('path');
const fs = require('fs');
const { DatabaseSync } = require('node:sqlite');
const { log } = require('./util');

const SCHEMA = `
CREATE TABLE IF NOT EXISTS ctfs (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, started_at INTEGER NOT NULL, ended_at INTEGER, imported INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS players (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, created_at INTEGER NOT NULL, notes TEXT
);
CREATE TABLE IF NOT EXISTS identities (
  player_id INTEGER NOT NULL, kind TEXT NOT NULL, value TEXT NOT NULL, ctf_id INTEGER, first_seen INTEGER, last_seen INTEGER,
  PRIMARY KEY (kind, value)
);
CREATE INDEX IF NOT EXISTS identities_player ON identities(player_id);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY, ctf_id INTEGER NOT NULL, ts INTEGER NOT NULL, player_id INTEGER, student TEXT NOT NULL, raw_name TEXT,
  source TEXT, ip TEXT, method TEXT, path TEXT, endpoint TEXT, object_id TEXT, status INTEGER, size INTEGER, latency REAL,
  severity TEXT, flags TEXT, attacks TEXT, owner TEXT, ua TEXT, body TEXT
);
CREATE INDEX IF NOT EXISTS requests_ctf_ts ON requests(ctf_id, ts);
CREATE INDEX IF NOT EXISTS requests_ctf_student ON requests(ctf_id, student);
CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY, ctf_id INTEGER NOT NULL, ts INTEGER NOT NULL, level TEXT NOT NULL, type TEXT NOT NULL,
  student TEXT, ip TEXT, msg TEXT NOT NULL, data TEXT, ack INTEGER DEFAULT 0
);
CREATE INDEX IF NOT EXISTS alerts_ctf_ts ON alerts(ctf_id, ts);
CREATE TABLE IF NOT EXISTS accounts (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, pass_hash TEXT NOT NULL, role TEXT NOT NULL, created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY, account_id INTEGER NOT NULL, ip TEXT, created_at INTEGER NOT NULL, last_seen INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT);
`;

class Db {
  constructor(file) {
    this.file = file;
    if (file !== ':memory:') fs.mkdirSync(path.dirname(file), { recursive: true });
    this.db = new DatabaseSync(file);
    this.db.exec('PRAGMA journal_mode = WAL; PRAGMA synchronous = NORMAL; PRAGMA temp_store = MEMORY;');
    this.db.exec(SCHEMA);
    this.pending = [];
    this.pendingAlerts = [];
    this.flushTimer = null;
    this.flushFailures = 0; // consecutive failed flushes (reset on success)
    this.lastFlushError = null;
    this.droppedRows = 0; // rows given up after the retry buffer overflowed
    this.onFlushError = null; // (err, consecutiveFailures) => void, set by server.js to raise an alert
    this.stmts = {
      insertReq: this.db.prepare(`INSERT INTO requests (ctf_id, ts, player_id, student, raw_name, source, ip, method, path, endpoint, object_id, status, size, latency, severity, flags, attacks, owner, ua, body)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`),
      insertAlert: this.db.prepare('INSERT INTO alerts (ctf_id, ts, level, type, student, ip, msg, data) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'),
      findIdentity: this.db.prepare('SELECT player_id FROM identities WHERE kind = ? AND value = ?'),
      upsertIdentity: this.db.prepare(`INSERT INTO identities (player_id, kind, value, ctf_id, first_seen, last_seen) VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(kind, value) DO UPDATE SET last_seen = excluded.last_seen, ctf_id = excluded.ctf_id`),
      insertPlayer: this.db.prepare('INSERT INTO players (name, created_at) VALUES (?, ?)'),
      getKv: this.db.prepare('SELECT v FROM kv WHERE k = ?'),
      setKv: this.db.prepare('INSERT INTO kv (k, v) VALUES (?, ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v'),
    };
    this.ctfId = null;
  }

  // ---------- ctfs ----------
  activeCtf() {
    return this.db.prepare('SELECT * FROM ctfs WHERE ended_at IS NULL AND imported = 0 ORDER BY id DESC LIMIT 1').get() || null;
  }
  openCtf(name) {
    let ctf = this.activeCtf();
    if (ctf && name && ctf.name !== name) {
      this.endCtf(ctf.id);
      ctf = null;
    }
    if (!ctf) {
      const r = this.db.prepare('INSERT INTO ctfs (name, started_at) VALUES (?, ?)').run(name || `ctf-${new Date().toISOString().slice(0, 10)}`, Date.now());
      ctf = this.db.prepare('SELECT * FROM ctfs WHERE id = ?').get(r.lastInsertRowid);
      log('info', `db: new CTF #${ctf.id} "${ctf.name}"`);
    }
    this.ctfId = ctf.id;
    return ctf;
  }
  endCtf(id) {
    if (!id) return;
    this.flush();
    this.db.prepare('UPDATE ctfs SET ended_at = ? WHERE id = ? AND ended_at IS NULL').run(Date.now(), id);
    if (this.ctfId === id) this.ctfId = null; // nothing is recorded until a CTF is opened again
  }
  /**
   * Delete whole CTF records with their requests and alerts. The active CTF is never deleted
   * (it is skipped); identities keep the player but forget which CTF last saw them.
   * Returns the ids that were actually removed.
   */
  deleteCtfs(ids) {
    const want = [...new Set((ids || []).map(Number).filter((n) => Number.isInteger(n) && n > 0))];
    if (!want.length) return [];
    this.flush();
    const active = this.activeCtf();
    const marks = want.map(() => '?').join(',');
    const targets = this.db
      .prepare(`SELECT id FROM ctfs WHERE id IN (${marks})`)
      .all(...want)
      .map((r) => Number(r.id))
      .filter((id) => !active || id !== active.id);
    if (!targets.length) return [];
    const m = targets.map(() => '?').join(',');
    this.db.exec('BEGIN');
    try {
      this.db.prepare(`DELETE FROM alerts WHERE ctf_id IN (${m})`).run(...targets);
      this.db.prepare(`DELETE FROM requests WHERE ctf_id IN (${m})`).run(...targets);
      this.db.prepare(`UPDATE identities SET ctf_id = NULL WHERE ctf_id IN (${m})`).run(...targets);
      this.db.prepare(`DELETE FROM ctfs WHERE id IN (${m})`).run(...targets);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    log('info', `db: deleted CTF record(s) ${targets.join(', ')}`);
    return targets;
  }
  listCtfs() {
    return this.db
      .prepare(`SELECT c.*, (SELECT COUNT(*) FROM requests r WHERE r.ctf_id = c.id) AS requests, (SELECT COUNT(*) FROM alerts a WHERE a.ctf_id = c.id) AS alerts,
        (SELECT COUNT(DISTINCT student) FROM requests r WHERE r.ctf_id = c.id) AS students FROM ctfs c ORDER BY c.id DESC`)
      .all();
  }

  // ---------- players (mapped across CTFs by name / username / ip) ----------
  playerFor(identities, displayName, ts) {
    // identities: [{kind, value}] in order of trust (gate name, gate id/email, app username, mac, ip).
    // An ip is a weak identity: many people can share one (classroom NAT), so it is recorded for the
    // history but never used to MATCH an existing player when any stronger identity is present.
    const strong = identities.filter((i) => i.value && i.kind !== 'ip');
    const lookupBy = strong.length ? strong : identities.filter((i) => i.value);
    let playerId = null;
    for (const { kind, value } of lookupBy) {
      const row = this.stmts.findIdentity.get(kind, value);
      if (row) {
        playerId = row.player_id;
        break;
      }
    }
    if (!playerId) {
      playerId = Number(this.stmts.insertPlayer.run(displayName, ts).lastInsertRowid);
    }
    // upsert keeps an identity with its first player (ON CONFLICT only refreshes last_seen / ctf), so a shared ip
    // stays attached to whoever had it first and never moves another person's record
    for (const { kind, value } of identities) if (value) this.stmts.upsertIdentity.run(playerId, kind, value, this.ctfId, ts, ts);
    return playerId;
  }
  playerHistory(playerId) {
    const ids = this.db.prepare('SELECT kind, value, ctf_id, first_seen, last_seen FROM identities WHERE player_id = ? ORDER BY last_seen DESC').all(playerId);
    const ctfs = this.db
      .prepare(`SELECT c.id, c.name, c.started_at, COUNT(r.id) AS requests, SUM(CASE WHEN r.flags LIKE '%idor-success%' THEN 1 ELSE 0 END) AS idor
        FROM requests r JOIN ctfs c ON c.id = r.ctf_id WHERE r.player_id = ? GROUP BY c.id ORDER BY c.id DESC`)
      .all(playerId);
    return { identities: ids, ctfs };
  }

  // ---------- requests (batched) ----------
  addRequest(ev) {
    if (!(ev.ctfId || this.ctfId)) return; // no active CTF: live view only
    this.pending.push(ev);
    if (this.pending.length >= 500) this.flush();
    else if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), 200);
      if (this.flushTimer.unref) this.flushTimer.unref();
    }
  }
  addAlert(a) {
    if (!(a.ctfId || this.ctfId)) return;
    this.pendingAlerts.push(a);
    if (!this.flushTimer) {
      this.flushTimer = setTimeout(() => this.flush(), 200);
      if (this.flushTimer.unref) this.flushTimer.unref();
    }
  }
  flush() {
    clearTimeout(this.flushTimer);
    this.flushTimer = null;
    if (!this.pending.length && !this.pendingAlerts.length) return;
    const reqs = this.pending.splice(0);
    const alerts = this.pendingAlerts.splice(0);
    try {
      this.db.exec('BEGIN');
      for (const e of reqs) {
        this.stmts.insertReq.run(
          e.ctfId || this.ctfId, e.ts, e.playerId || null, e.student, e.rawName || null, e.source || null, e.ip || null, e.method, e.path,
          e.endpoint || null, e.objectId == null ? null : String(e.objectId), e.status, e.size, e.latencyMs, e.severity,
          JSON.stringify(e.flags || []), JSON.stringify(e.attacks || []), e.owner || null, e.ua || null, e.body ? JSON.stringify(e.body) : null
        );
      }
      for (const a of alerts) this.stmts.insertAlert.run(a.ctfId || this.ctfId, a.ts, a.level, a.type, a.student || null, a.ip || null, a.msg, a.data ? JSON.stringify(a.data) : null);
      this.db.exec('COMMIT');
      this.flushFailures = 0;
      this.lastFlushError = null;
    } catch (err) {
      try {
        this.db.exec('ROLLBACK');
      } catch {}
      // keep the batch and retry later instead of losing it (bounded: oldest rows are dropped past the cap)
      this.pending = reqs.concat(this.pending);
      this.pendingAlerts = alerts.concat(this.pendingAlerts);
      const CAP = 5000;
      if (this.pending.length > CAP) {
        this.droppedRows += this.pending.length - CAP;
        this.pending.splice(0, this.pending.length - CAP);
      }
      this.flushFailures++;
      this.lastFlushError = err.message;
      log('error', `db flush failed (${this.flushFailures} in a row, ${this.pending.length} rows waiting): ${err.message}`);
      if (this.onFlushError) {
        try {
          this.onFlushError(err, this.flushFailures);
        } catch {}
      }
      this.flushTimer = setTimeout(() => this.flush(), Math.min(2000 * this.flushFailures, 30000));
      if (this.flushTimer.unref) this.flushTimer.unref();
    }
  }

  // ---------- reads ----------
  alerts({ ctfId, level, ack, limit = 500 } = {}) {
    const where = ['ctf_id = ?'];
    const params = [ctfId || this.ctfId];
    if (level) {
      where.push('level = ?');
      params.push(level);
    }
    if (ack === 0 || ack === 1) {
      where.push('ack = ?');
      params.push(ack);
    }
    return this.db.prepare(`SELECT * FROM alerts WHERE ${where.join(' AND ')} ORDER BY id DESC LIMIT ?`).all(...params, Math.min(Number(limit) || 500, 5000));
  }
  ackAlerts(ids) {
    const stmt = this.db.prepare('UPDATE alerts SET ack = 1 WHERE id = ?');
    for (const id of ids) stmt.run(Number(id));
  }
  studentDetail(student, ctfId) {
    this.flush();
    const cid = ctfId || this.ctfId;
    const userAgents = this.db.prepare('SELECT ua, COUNT(*) AS n FROM requests WHERE ctf_id = ? AND student = ? GROUP BY ua ORDER BY n DESC').all(cid, student);
    const ips = this.db.prepare('SELECT ip, COUNT(*) AS n, MIN(ts) AS first, MAX(ts) AS last FROM requests WHERE ctf_id = ? AND student = ? GROUP BY ip ORDER BY n DESC').all(cid, student);
    const rows = this.db.prepare('SELECT * FROM requests WHERE ctf_id = ? AND student = ? ORDER BY id DESC LIMIT 5000').all(cid, student);
    const attacks = {};
    for (const r of rows) {
      let list = [];
      try {
        list = JSON.parse(r.attacks || '[]');
      } catch {}
      for (const a of list) {
        const k = a.cls || a;
        attacks[k] = attacks[k] || { count: 0, samples: [] };
        attacks[k].count++;
        if (attacks[k].samples.length < 25) attacks[k].samples.push({ id: r.id, ts: r.ts, method: r.method, path: r.path, status: r.status, where: a.where, sample: a.sample });
      }
    }
    const player = this.db.prepare('SELECT player_id FROM requests WHERE ctf_id = ? AND student = ? AND player_id IS NOT NULL LIMIT 1').get(cid, student);
    return { student, userAgents, ips, attacks, requests: rows.map(parseRow), player: player ? this.playerHistory(player.player_id) : null, playerId: player ? player.player_id : null };
  }
  runSql(sql, params, limit) {
    this.flush();
    return this.db.prepare(`${sql} LIMIT ${Math.min(Number(limit) || 1000, 20000)}`).all(...params).map(parseRow);
  }
  exportCtf(ctfId) {
    this.flush();
    const ctf = this.db.prepare('SELECT * FROM ctfs WHERE id = ?').get(ctfId);
    if (!ctf) throw new Error('no such CTF');
    const requests = this.db.prepare('SELECT * FROM requests WHERE ctf_id = ? ORDER BY id').all(ctfId).map(parseRow);
    const alerts = this.db.prepare('SELECT * FROM alerts WHERE ctf_id = ? ORDER BY id').all(ctfId);
    const players = this.db
      .prepare(`SELECT p.id, p.name, i.kind, i.value FROM players p JOIN identities i ON i.player_id = p.id WHERE p.id IN (SELECT DISTINCT player_id FROM requests WHERE ctf_id = ?)`)
      .all(ctfId);
    return { format: 'ctf-watch/1', exportedAt: Date.now(), ctf, requests, alerts, players };
  }
  importCtf(data) {
    if (!data || data.format !== 'ctf-watch/1' || !data.ctf || !Array.isArray(data.requests)) throw new Error('not a ctf-watch export');
    this.flush();
    let id;
    this.db.exec('BEGIN');
    try {
      // the ctf row is part of the transaction: a failed import leaves nothing behind
      const r = this.db.prepare('INSERT INTO ctfs (name, started_at, ended_at, imported) VALUES (?, ?, ?, 1)').run(`${data.ctf.name} (imported)`, data.ctf.started_at || Date.now(), data.ctf.ended_at || Date.now());
      id = Number(r.lastInsertRowid);
      for (const e of data.requests) {
        this.stmts.insertReq.run(id, e.ts, null, e.student, e.raw_name || e.rawName || null, e.source || null, e.ip || null, e.method, e.path, e.endpoint || null,
          e.object_id == null ? (e.objectId == null ? null : String(e.objectId)) : String(e.object_id), e.status, e.size, e.latency ?? e.latencyMs ?? 0, e.severity,
          JSON.stringify(e.flags || []), JSON.stringify(e.attacks || []), e.owner || null, e.ua || null, e.body ? JSON.stringify(e.body) : null);
      }
      for (const a of data.alerts || []) this.stmts.insertAlert.run(id, a.ts, a.level || 'medium', a.type, a.student || null, a.ip || null, a.msg, typeof a.data === 'string' ? a.data : a.data ? JSON.stringify(a.data) : null);
      this.db.exec('COMMIT');
    } catch (err) {
      this.db.exec('ROLLBACK');
      throw err;
    }
    return this.db.prepare('SELECT * FROM ctfs WHERE id = ?').get(id);
  }
  requestsOf(ctfId) {
    this.flush();
    return this.db.prepare('SELECT * FROM requests WHERE ctf_id = ? ORDER BY ts, id').all(ctfId).map(parseRow);
  }

  // ---------- accounts / sessions ----------
  replaceAccounts(list) {
    this.db.exec('DELETE FROM sessions; DELETE FROM accounts;');
    const stmt = this.db.prepare('INSERT INTO accounts (username, pass_hash, role, created_at) VALUES (?, ?, ?, ?)');
    for (const a of list) stmt.run(a.username, a.passHash, a.role, Date.now());
  }
  account(username) {
    return this.db.prepare('SELECT * FROM accounts WHERE username = ?').get(username) || null;
  }
  accountById(id) {
    return this.db.prepare('SELECT id, username, role FROM accounts WHERE id = ?').get(id) || null;
  }
  activeSession(accountId, ttlMs) {
    return this.db.prepare('SELECT * FROM sessions WHERE account_id = ? AND last_seen > ? ORDER BY last_seen DESC LIMIT 1').get(accountId, Date.now() - ttlMs) || null;
  }
  createSession(tokenHash, accountId, ip) {
    this.db.prepare('DELETE FROM sessions WHERE account_id = ?').run(accountId);
    this.db.prepare('INSERT INTO sessions (token_hash, account_id, ip, created_at, last_seen) VALUES (?, ?, ?, ?, ?)').run(tokenHash, accountId, ip, Date.now(), Date.now());
  }
  session(tokenHash, ttlMs) {
    const s = this.db.prepare('SELECT * FROM sessions WHERE token_hash = ? AND last_seen > ?').get(tokenHash, Date.now() - ttlMs);
    if (s) this.db.prepare('UPDATE sessions SET last_seen = ? WHERE token_hash = ?').run(Date.now(), tokenHash);
    return s || null;
  }
  deleteSession(tokenHash) {
    this.db.prepare('DELETE FROM sessions WHERE token_hash = ?').run(tokenHash);
  }

  // ---------- small key/value (admin state etc.) ----------
  get(k, fallback) {
    const r = this.stmts.getKv.get(k);
    if (!r) return fallback;
    try {
      return JSON.parse(r.v);
    } catch {
      return fallback;
    }
  }
  set(k, v) {
    this.stmts.setKv.run(k, JSON.stringify(v));
  }

  close() {
    this.flush();
    this.db.close();
  }
}

function parseRow(r) {
  const out = { ...r };
  for (const k of ['flags', 'attacks', 'body']) {
    if (typeof out[k] === 'string') {
      try {
        out[k] = JSON.parse(out[k]);
      } catch {}
    }
  }
  return out;
}

module.exports = { Db };

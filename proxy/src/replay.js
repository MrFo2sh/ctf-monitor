'use strict';
// Replays an imported (or past) CTF into the live dashboard, at the original pace or faster,
// so a recording can be reviewed as if it were happening now.

const { log } = require('./util');

class Replay {
  constructor({ db, store }) {
    this.db = db;
    this.store = store;
    this.timer = null;
    this.state = null; // { ctfId, speed, total, done, startedAt }
  }

  // loaded = the live view currently shows this replayed CTF (stays set after the replay finished,
  // until Stop / New CTF / another replay clears the live view)
  status() {
    const loaded = this.store.replayCtfId || null;
    return this.state ? { ...this.state, running: !!this.timer, loaded } : { running: false, loaded };
  }

  start(ctfId, speed = 10) {
    this.stop();
    const rows = this.db.requestsOf(ctfId);
    if (!rows.length) throw new Error('that CTF has no requests');
    const sp = Math.max(0.1, Math.min(Number(speed) || 10, 1000));
    this.state = { ctfId, speed: sp, total: rows.length, done: 0, startedAt: Date.now() };
    this.store.reset();
    this.store.replayCtfId = ctfId;
    const base = rows[0].ts;
    const now = Date.now();
    let i = 0;
    const step = () => {
      const wallNow = Date.now();
      // emit every row whose (scaled) time has come
      while (i < rows.length && now + (rows[i].ts - base) / sp <= wallNow) {
        const r = rows[i++];
        this.store.add({
          ts: wallNow,
          time: new Date(wallNow).toISOString(),
          student: r.student,
          rawName: r.raw_name,
          studentId: null,
          source: r.source || 'replay',
          ip: r.ip,
          method: r.method,
          path: r.path,
          endpoint: r.endpoint,
          objectId: r.object_id,
          status: r.status,
          size: r.size,
          latencyMs: r.latency,
          flags: Array.isArray(r.flags) ? r.flags : [],
          attacks: Array.isArray(r.attacks) ? r.attacks : [],
          severity: r.severity || 'ok',
          owner: r.owner,
          mine: r.flags && r.flags.includes('idor-attempt') ? false : null,
          seq: null,
          ua: r.ua,
          body: r.body || undefined,
          replay: true,
        });
        this.state.done = i;
      }
      if (i >= rows.length) {
        log('info', `replay of CTF #${ctfId} finished (${rows.length} requests)`);
        this.timer = null;
        return;
      }
      const wait = Math.max(20, Math.min(1000, now + (rows[i].ts - base) / sp - Date.now()));
      this.timer = setTimeout(step, wait);
    };
    log('info', `replaying CTF #${ctfId}: ${rows.length} requests at ${sp}x`);
    step();
    return this.status();
  }

  stop() {
    if (this.timer) clearTimeout(this.timer);
    this.timer = null;
  }
}

module.exports = { Replay };

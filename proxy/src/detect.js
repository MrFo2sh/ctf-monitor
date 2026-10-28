'use strict';
// Detection engine: matches requests against the IDOR endpoints in rules.json,
// works out who owns the object, and flags attempts / successes / enumeration / error bursts.

const { log } = require('./util');

const SEQ_KEEP = 15; // IDs to remember per student per endpoint (for the "1041 -> 1042 -> 1043" display)

class Detector {
  constructor(getConfig) {
    this.getConfig = getConfig;
    this.students = new Map(); // name -> state
    this.learned = new Map(); // endpoint name -> Map(objectId -> owner name)
  }

  state(name) {
    let st = this.students.get(name);
    if (!st) {
      st = { byEndpoint: new Map(), errors: [], seq: new Map(), idsSeen: new Set() };
      this.students.set(name, st);
    }
    return st;
  }

  renameStudent(oldName, newName) {
    const st = this.students.get(oldName);
    if (st) {
      this.students.delete(oldName);
      const t = this.students.get(newName);
      if (!t) this.students.set(newName, st);
      else {
        // the target already has state (two rows merged): combine the windows instead of dropping one side
        const firstTs = (s, ep) => ((s.byEndpoint.get(ep) || [])[0] || {}).ts ?? Infinity;
        for (const [ep, seq] of st.seq) {
          // chronological: the side whose window started earlier goes first
          const cur = t.seq.get(ep) || [];
          const merged = firstTs(st, ep) <= firstTs(t, ep) ? seq.concat(cur) : cur.concat(seq);
          t.seq.set(ep, merged.filter((id, i) => i === 0 || merged[i - 1] !== id).slice(-SEQ_KEEP));
        }
        for (const [ep, entries] of st.byEndpoint) {
          const cur = t.byEndpoint.get(ep) || [];
          t.byEndpoint.set(ep, cur.concat(entries).sort((a, b) => a.ts - b.ts));
        }
        t.errors = t.errors.concat(st.errors).sort((a, b) => a - b);
        for (const k of st.idsSeen) t.idsSeen.add(k);
      }
    }
    for (const m of this.learned.values()) for (const [id, owner] of m) if (owner === oldName) m.set(id, newName);
  }

  matchEndpoint(method, pathOnly, url, reqBody) {
    const cfg = this.getConfig();
    for (const ep of cfg.compiledEndpoints) {
      if (ep.methods.length && !ep.methods.includes(method)) continue;
      const m = ep.re.exec(pathOnly);
      if (!m) continue;
      let id = null;
      if (ep.idFrom === 'path') id = m.groups && m.groups.id;
      else if (ep.idFrom.startsWith('query:')) {
        try {
          id = new URL(url, 'http://x').searchParams.get(ep.idParam);
        } catch {
          id = null;
        }
      } else if (ep.idFrom.startsWith('body:')) id = reqBody && reqBody[ep.idParam];
      if (id === null || id === undefined || id === '') continue;
      return { endpoint: ep, objectId: String(id) };
    }
    return null;
  }

  ownerOf(ep, objectId, student) {
    const cfg = this.getConfig();
    const unknown = { owner: null, mine: null, basis: null };
    const rule = ep.owner;
    if (rule === 'none') return unknown;

    const map = cfg.ownershipMap || {};
    const mapped = (map[ep.name] && map[ep.name][objectId]) || (map['*'] && map['*'][objectId]) || null;
    if (mapped && rule !== 'learn' && rule !== 'same-as-user') {
      return { owner: mapped, mine: mapped === student.name, basis: 'map' };
    }
    if (rule === 'map') return unknown;

    if (rule === 'same-as-user') {
      if (student.id == null) return unknown;
      const mine = String(student.id) === objectId;
      return { owner: mine ? student.name : null, mine, basis: 'self' };
    }

    // auto / learn: positive self-evidence first, then what we learned
    if (rule === 'auto' && student.id != null && String(student.id) === objectId) {
      return { owner: student.name, mine: true, basis: 'self' };
    }
    const learnedOwner = this.learned.get(ep.name) && this.learned.get(ep.name).get(objectId);
    if (learnedOwner) return { owner: learnedOwner, mine: learnedOwner === student.name, basis: 'learned' };
    return unknown;
  }

  learnOwner(epName, objectId, owner) {
    let m = this.learned.get(epName);
    if (!m) {
      m = new Map();
      this.learned.set(epName, m);
    }
    if (!m.has(objectId)) {
      m.set(objectId, owner);
      log('debug', `ownership learned: ${epName} #${objectId} -> ${owner}`);
    }
  }

  // A student that turned out to be enumerating should not keep ownership it "learned" during that burst.
  unlearnBurst(epName, student, entries) {
    const m = this.learned.get(epName);
    if (!m) return;
    for (const e of entries) if (m.get(e.id) === student) m.delete(e.id);
  }

  /**
   * @param ev { student:{name,id,source}, method, pathOnly, url, status, size, hasData, reqBody, ts }
   * @returns { endpoint, objectId, flags, severity, owner, ownerBasis, mine, seq, distinctIds }
   */
  analyze(ev) {
    const cfg = this.getConfig();
    const st = this.state(ev.student.name);
    const now = ev.ts || Date.now();
    const flags = [];
    const out = { endpoint: null, objectId: null, owner: null, ownerBasis: null, mine: null, seq: null, distinctIds: 0, sequential: false };

    const match = this.matchEndpoint(ev.method, ev.pathOnly, ev.url, ev.reqBody);
    if (match) {
      const { endpoint: ep, objectId } = match;
      out.endpoint = ep.name;
      out.objectId = objectId;
      st.idsSeen.add(`${ep.name}:${objectId}`);

      // sliding window of IDs on this endpoint
      let entries = st.byEndpoint.get(ep.name);
      if (!entries) {
        entries = [];
        st.byEndpoint.set(ep.name, entries);
      }
      entries.push({ id: objectId, ts: now });
      const cutoff = now - cfg.enumeration.windowSeconds * 1000;
      while (entries.length && entries[0].ts < cutoff) entries.shift();
      const distinct = new Set(entries.map((e) => e.id)).size;
      out.distinctIds = distinct;
      const enumerating = distinct >= cfg.enumeration.distinctIds;
      if (enumerating) {
        flags.push('enumeration');
        this.unlearnBurst(ep.name, ev.student.name, entries);
      }

      // sequence display (skip immediate repeats)
      let seq = st.seq.get(ep.name);
      if (!seq) {
        seq = [];
        st.seq.set(ep.name, seq);
      }
      if (seq[seq.length - 1] !== objectId) seq.push(objectId);
      while (seq.length > SEQ_KEEP) seq.shift();
      out.seq = seq.slice();
      if (seq.length >= 3) {
        const a = seq.slice(-3).map(Number);
        if (a.every((n) => Number.isFinite(n)) && Math.abs(a[2] - a[1]) === 1 && Math.abs(a[1] - a[0]) === 1) out.sequential = true;
      }

      // ownership
      const own = this.ownerOf(ep, objectId, ev.student);
      out.owner = own.owner;
      out.ownerBasis = own.basis;
      out.mine = own.mine;
      const success = ev.status >= 200 && ev.status < 300 && ev.hasData;
      if (own.mine === false) {
        flags.push('idor-attempt');
        if (success) flags.push('idor-success');
      }

      // learn ownership from a quiet, successful read (or from "this is my own user id")
      if (success && own.mine === null && !enumerating && cfg.learnFromFirstSuccess && (ep.owner === 'auto' || ep.owner === 'learn')) {
        this.learnOwner(ep.name, objectId, ev.student.name);
        out.owner = ev.student.name;
        out.ownerBasis = 'learned';
        out.mine = true;
      } else if (own.mine === true && own.basis === 'self') {
        this.learnOwner(ep.name, objectId, ev.student.name);
      }
    }

    // error bursts (brute force / noisy scanning)
    if (cfg.bruteForce.statuses.has(ev.status)) {
      st.errors.push(now);
      const cutoff = now - cfg.bruteForce.windowSeconds * 1000;
      while (st.errors.length && st.errors[0] < cutoff) st.errors.shift();
      if (st.errors.length >= cfg.bruteForce.errors) flags.push('burst-errors');
    }

    let severity = 'ok';
    if (flags.includes('idor-success')) severity = 'critical';
    else if (flags.includes('idor-attempt')) severity = 'high';
    else if (flags.includes('enumeration') || flags.includes('burst-errors')) severity = 'warn';
    else if (ev.status >= 400) severity = 'notice';

    return { ...out, flags, severity, idsSeenTotal: st.idsSeen.size };
  }
}

module.exports = { Detector };

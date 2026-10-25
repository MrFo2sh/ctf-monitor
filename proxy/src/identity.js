'use strict';
// Works out which student a request belongs to.
// Order: JWT (cookie or Authorization header) -> session cookie (learned at login) -> X-Forwarded-For / IP.

const { firstOf, shortHash, parseCookies, parseSetCookies, decodeJwt, clientIp, log } = require('./util');

class IdentityResolver {
  constructor(getConfig, gate) {
    this.getConfig = getConfig;
    this.gate = gate || null; // optional NameGate
    this.sessions = new Map(); // session cookie value -> { name, id }
  }

  resolve(req) {
    const base = this.resolveApp(req);
    // 0. Name typed by the student on the name-gate page (if enabled) wins for the display name;
    //    the app identity still supplies the user ID when it has one.
    if (this.gate) {
      const appName = base.source === 'ip' ? null : base.name;
      const name = this.gate.nameFrom(req);
      if (name) {
        this.gate.rememberIp(base.ip, name);
        return { ...base, name, source: 'name', appName };
      }
      // no cookie (curl, scripts, Burp without cookies): same machine as a browser that gave a name?
      const ipName = this.gate.nameForIp(base.ip);
      if (ipName) return { ...base, name: ipName, source: 'ip-match', appName };
    }
    return base;
  }

  resolveApp(req) {
    const cfg = this.getConfig().identity || {};
    const cookies = parseCookies(req.headers.cookie);
    const ip = clientIp(req);

    // 1. JWT
    const jwtCfg = cfg.jwt || {};
    const candidates = [];
    for (const c of jwtCfg.cookies || []) if (cookies[c]) candidates.push(cookies[c]);
    for (const h of jwtCfg.headers || []) if (req.headers[h]) candidates.push(String(req.headers[h]));
    for (const tok of candidates) {
      const payload = decodeJwt(tok);
      if (!payload) continue;
      const name = firstOf(payload, jwtCfg.nameClaims || ['username', 'sub']);
      const id = firstOf(payload, jwtCfg.idClaims || ['id', 'sub']);
      if (name || id) return { name: name || `user#${id}`, id, source: 'jwt', ip, sessionKey: null };
    }

    // 2. Session cookie
    const sessionNames = cfg.sessionCookies || [];
    let sessionKey = null;
    for (const c of sessionNames) {
      if (cookies[c]) {
        sessionKey = cookies[c];
        break;
      }
    }
    if (sessionKey) {
      const learned = this.sessions.get(sessionKey);
      if (learned) return { name: learned.name, id: learned.id, source: 'session', ip, sessionKey };
      return { name: `sess-${shortHash(sessionKey)}`, id: null, source: 'session', ip, sessionKey };
    }

    // 3. IP / forwarded header
    return { name: `ip:${ip}`, id: null, source: 'ip', ip, sessionKey: null };
  }

  // Called after a response finished. Learns "session cookie -> student" from logins and whoami endpoints.
  // Returns the learned { name, id } (so the login request itself can be attributed), or null.
  learn({ req, identity, reqBody, status, resHeaders, resBody, pathOnly }) {
    const full = this.getConfig();
    const cfg = full.identity || {};
    if (status < 200 || status >= 400) return null;

    const setCookies = parseSetCookies(resHeaders['set-cookie']);
    const sessionNames = cfg.sessionCookies || [];
    const newSessionKeys = setCookies.filter((c) => sessionNames.includes(c.name)).map((c) => c.value);
    const keys = new Set([...newSessionKeys, ...(identity.sessionKey ? [identity.sessionKey] : [])]);

    // login
    const loginCfg = cfg.login || {};
    const loginMethods = (loginCfg.methods || ['POST']).map((m) => m.toUpperCase());
    if (full.compiledLogin && full.compiledLogin.test(pathOnly) && loginMethods.includes(req.method.toUpperCase())) {
      const name = firstOf(reqBody || {}, loginCfg.userFields || ['username']) || firstOf(resBody || {}, loginCfg.responseNameFields || []);
      const id = firstOf(resBody || {}, loginCfg.responseIdFields || ['id']);
      if (name) {
        for (const k of keys) this.remember(k, name, id);
        if (!keys.size) log('debug', `login by ${name} but no session cookie seen (JWT app?)`);
        return { name, id };
      }
      return null;
    }

    // whoami
    const who = cfg.whoami || {};
    if (full.compiledWhoami && full.compiledWhoami.test(pathOnly) && resBody && typeof resBody === 'object') {
      const name = firstOf(resBody, who.nameFields || ['username']);
      const id = firstOf(resBody, who.idFields || ['id']);
      if (name || id) {
        for (const k of keys) this.remember(k, name, id);
        return { name: name || `user#${id}`, id };
      }
    }
    return null;
  }

  remember(sessionKey, name, id) {
    const prev = this.sessions.get(sessionKey) || {};
    const entry = { name: name || prev.name || (id ? `user#${id}` : null), id: id || prev.id || null };
    if (!entry.name) return;
    const changed = prev.name !== entry.name || prev.id !== entry.id;
    this.sessions.set(sessionKey, entry);
    if (changed) log('info', `identity learned: session ${shortHash(sessionKey)} -> ${entry.name}${entry.id ? ` (id ${entry.id})` : ''}`);
    // keep the map bounded
    if (this.sessions.size > 5000) {
      const first = this.sessions.keys().next().value;
      this.sessions.delete(first);
    }
  }
}

module.exports = { IdentityResolver };

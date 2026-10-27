'use strict';
// Dashboard authentication: generated accounts, scrypt password hashes, single session per account,
// login rate limiting and IP blocking for the dashboard.

const crypto = require('crypto');
const { log } = require('./util');

const SESSION_COOKIE = 'ctfw_sid';
const ALPHABET = 'abcdefghijkmnpqrstuvwxyz23456789'; // no look-alike characters

function randomToken(len) {
  const bytes = crypto.randomBytes(len);
  let s = '';
  for (let i = 0; i < len; i++) s += ALPHABET[bytes[i] % ALPHABET.length];
  return s;
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const key = crypto.scryptSync(password, salt, 32, { N: 16384, r: 8, p: 1 });
  return `scrypt$${salt.toString('base64')}$${key.toString('base64')}`;
}
function verifyPassword(password, stored) {
  try {
    const [, saltB64, keyB64] = String(stored).split('$');
    const salt = Buffer.from(saltB64, 'base64');
    const want = Buffer.from(keyB64, 'base64');
    const got = crypto.scryptSync(password, salt, want.length, { N: 16384, r: 8, p: 1 });
    return got.length === want.length && crypto.timingSafeEqual(got, want);
  } catch {
    return false;
  }
}
const tokenHash = (t) => crypto.createHash('sha256').update(String(t)).digest('hex');

class Auth {
  /**
   * @param db Db instance
   * @param opts { users: number, sessionTtlMs, onConflict(info), onBlockIp(ip, reason) }
   */
  constructor(db, opts = {}) {
    this.db = db;
    this.ttl = opts.sessionTtlMs || 12 * 3600 * 1000;
    this.onConflict = opts.onConflict || (() => {});
    this.blockedIps = new Map(db.get('dashboard_blocked_ips', {}) ? Object.entries(db.get('dashboard_blocked_ips', {})) : []);
    this.attempts = new Map(); // ip -> [ts]
    this.maxAttempts = opts.maxAttempts || 8;
    this.attemptWindowMs = 10 * 60 * 1000;
    this.credentials = []; // plaintext, only kept to print once at startup
  }

  // Fresh accounts on every start: admin_<3 chars> + N users. Returns the plaintext list (print it, then forget it).
  generateAccounts(users) {
    const list = [];
    const mk = (username, role) => {
      const password = randomToken(14);
      list.push({ username, role, password, passHash: hashPassword(password) });
    };
    mk(`admin_${randomToken(3)}`, 'admin');
    for (let i = 1; i <= Math.max(0, Math.min(Number(users) || 0, 200)); i++) mk(`user_${i}`, 'user');
    this.db.replaceAccounts(list);
    this.credentials = list.map(({ username, role, password }) => ({ username, role, password }));
    return this.credentials;
  }

  isIpBlocked(ip) {
    return this.blockedIps.has(ip);
  }
  blockIp(ip, reason) {
    if (!ip || /^(127\.|::1$|::ffff:127\.)/.test(ip)) return false; // never lock ourselves out of localhost
    this.blockedIps.set(ip, { reason, ts: Date.now() });
    this.db.set('dashboard_blocked_ips', Object.fromEntries(this.blockedIps));
    log('info', `auth: blocked dashboard access from ${ip} (${reason})`);
    return true;
  }
  unblockIp(ip) {
    this.blockedIps.delete(ip);
    this.db.set('dashboard_blocked_ips', Object.fromEntries(this.blockedIps));
  }

  tooManyAttempts(ip) {
    const now = Date.now();
    const arr = (this.attempts.get(ip) || []).filter((t) => now - t < this.attemptWindowMs);
    this.attempts.set(ip, arr);
    return arr.length >= this.maxAttempts;
  }
  noteAttempt(ip) {
    const arr = this.attempts.get(ip) || [];
    arr.push(Date.now());
    this.attempts.set(ip, arr);
  }

  /**
   * login(username, password, ip) -> { ok, token, account } | { error, status }
   * Single session per account: a second login while a session is alive is refused, reported and the IP blocked.
   */
  login(username, password, ip) {
    if (this.isIpBlocked(ip)) return { error: 'blocked', status: 403 };
    if (this.tooManyAttempts(ip)) return { error: 'too many attempts, try later', status: 429 };
    const acc = this.db.account(String(username || '').trim());
    if (!acc || !verifyPassword(String(password || ''), acc.pass_hash)) {
      this.noteAttempt(ip);
      return { error: 'wrong username or password', status: 401 };
    }
    const active = this.db.activeSession(acc.id, this.ttl);
    if (active && active.ip !== ip) {
      // someone else is already logged in as this account: alert + block the newcomer
      const blocked = this.blockIp(ip, `tried to log in as ${acc.username} while that account was in use from ${active.ip}`);
      this.onConflict({ username: acc.username, role: acc.role, ip, activeIp: active.ip, blocked });
      return { error: 'this account is already logged in from another place; the organizer has been alerted', status: 409 };
    }
    const token = crypto.randomBytes(32).toString('hex');
    this.db.createSession(tokenHash(token), acc.id, ip);
    this.attempts.delete(ip);
    log('info', `auth: ${acc.username} logged in from ${ip}`);
    return { ok: true, token, account: { id: acc.id, username: acc.username, role: acc.role } };
  }

  logout(token) {
    if (token) this.db.deleteSession(tokenHash(token));
  }

  // -> { id, username, role } or null
  sessionFromToken(token) {
    if (!token) return null;
    const s = this.db.session(tokenHash(token), this.ttl);
    if (!s) return null;
    return this.db.accountById(s.account_id);
  }
  sessionFromRequest(req) {
    const m = /(?:^|;\s*)ctfw_sid=([a-f0-9]{64})/.exec(req.headers.cookie || '');
    return this.sessionFromToken(m ? m[1] : null);
  }

  cookieFor(token, secure) {
    return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${Math.floor(this.ttl / 1000)}${secure ? '; Secure' : ''}`;
  }
  clearCookie() {
    return `${SESSION_COOKIE}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0`;
  }
}

module.exports = { Auth, hashPassword, verifyPassword, randomToken, SESSION_COOKIE };

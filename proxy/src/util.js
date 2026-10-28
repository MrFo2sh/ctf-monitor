'use strict';
const crypto = require('crypto');

function get(obj, path) {
  if (!obj || typeof obj !== 'object') return undefined;
  const parts = path.split('.');
  let cur = obj;
  for (const p of parts) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = cur[p];
  }
  return cur;
}

function firstOf(obj, paths) {
  for (const p of paths) {
    const v = get(obj, p);
    if (v !== undefined && v !== null && v !== '' && typeof v !== 'object') return String(v);
  }
  return null;
}

function shortHash(s) {
  return crypto.createHash('sha1').update(String(s)).digest('hex').slice(0, 8);
}

function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of String(header).split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) out[k] = v;
  }
  return out;
}

function parseSetCookies(arr) {
  const out = [];
  for (const sc of arr || []) {
    const first = String(sc).split(';')[0];
    const i = first.indexOf('=');
    if (i < 0) continue;
    out.push({ name: first.slice(0, i).trim(), value: first.slice(i + 1).trim() });
  }
  return out;
}

function decodeJwt(token) {
  if (!token || typeof token !== 'string') return null;
  const t = token.replace(/^Bearer\s+/i, '').trim();
  const parts = t.split('.');
  if (parts.length !== 3) return null;
  try {
    const json = Buffer.from(parts[1].replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8');
    const payload = JSON.parse(json);
    return payload && typeof payload === 'object' ? payload : null;
  } catch {
    return null;
  }
}

function parseBody(contentType, buf) {
  if (!buf || !buf.length) return null;
  const ct = String(contentType || '').toLowerCase();
  const text = buf.toString('utf8');
  try {
    if (ct.includes('json') || (!ct && /^\s*[{[]/.test(text))) return JSON.parse(text);
    if (ct.includes('x-www-form-urlencoded')) {
      const o = {};
      for (const [k, v] of new URLSearchParams(text)) o[k] = v;
      return o;
    }
    if (ct.includes('multipart/form-data')) {
      // light-touch: pick out simple text fields only
      const o = {};
      const re = /name="([^"]+)"\r?\n\r?\n([^\r\n]*)/g;
      let m;
      while ((m = re.exec(text))) o[m[1]] = m[2];
      return o;
    }
    if (/^\s*[{[]/.test(text)) return JSON.parse(text);
  } catch {
    /* not parseable */
  }
  return null;
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  const xr = req.headers['x-real-ip'];
  if (xr) return String(xr).trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

function nowIso() {
  return new Date().toISOString();
}

function log(level, ...args) {
  const want = (process.env.LOG_LEVEL || 'info').toLowerCase();
  if (level === 'debug' && want !== 'debug') return;
  const fn = level === 'error' ? console.error : console.log;
  fn(`[${nowIso()}] [${level}]`, ...args);
}

// Best-effort MAC address lookup for a LAN ip (only possible when the player is on the same network segment
// as this machine, i.e. not through zrok). Uses the host's neighbour table; returns null when unknown.
// Only a well-formed private IPv4 address is ever passed to the `ip` binary (execFile, no shell, so there is
// no command injection; the strict check removes argument abuse and process spam from spoofed headers).
const macCache = new Map();
const MAC_CACHE_MAX = 2000;
const PRIVATE_V4 = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/;
function isPrivateIPv4(ip) {
  return typeof ip === 'string' && ip.length <= 15 && require('net').isIPv4(ip) && PRIVATE_V4.test(ip);
}
function macFor(ip) {
  if (process.platform !== 'linux' || !isPrivateIPv4(ip)) return Promise.resolve(null);
  if (macCache.has(ip)) return Promise.resolve(macCache.get(ip));
  if (macCache.size >= MAC_CACHE_MAX) macCache.delete(macCache.keys().next().value);
  macCache.set(ip, null); // reserve the slot: concurrent requests for the same ip spawn one lookup only
  return new Promise((resolve) => {
    try {
      require('child_process').execFile('ip', ['neigh', 'show', ip], { timeout: 1500 }, (err, out) => {
        const m = !err && /lladdr\s+([0-9a-f:]{17})/i.exec(String(out));
        const mac = m ? m[1].toLowerCase() : null;
        macCache.set(ip, mac);
        resolve(mac);
      });
    } catch {
      resolve(null);
    }
  });
}

module.exports = { get, firstOf, shortHash, parseCookies, parseSetCookies, decodeJwt, parseBody, clientIp, macFor, isPrivateIPv4, nowIso, log };

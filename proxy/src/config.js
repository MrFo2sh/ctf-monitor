'use strict';
const fs = require('fs');
const path = require('path');
const { log } = require('./util');

const CONFIG_DIR = process.env.CONFIG_DIR || path.join(__dirname, '..', '..', 'config');

function safeRegex(pattern, label) {
  try {
    return new RegExp(pattern, 'i');
  } catch (err) {
    log('error', `rules.json: bad pattern for ${label}: ${err.message}`);
    return null;
  }
}

function compile(raw) {
  const cfg = JSON.parse(JSON.stringify(raw)); // deep copy
  const endpoints = (cfg.endpoints && cfg.endpoints.list) || [];
  cfg.compiledEndpoints = endpoints
    .filter((e) => e && e.pattern && e.name)
    .map((e) => {
      const re = safeRegex(e.pattern, `endpoint "${e.name}"`);
      if (!re) return null;
      const idFrom = e.idFrom || 'path';
      return {
        name: e.name,
        methods: (e.methods || []).map((m) => m.toUpperCase()),
        re,
        idFrom,
        idParam: idFrom.startsWith('query:') ? idFrom.slice(6) : idFrom.startsWith('body:') ? idFrom.slice(5) : null,
        owner: e.owner || 'auto',
      };
    })
    .filter(Boolean);

  const id = cfg.identity || {};
  cfg.compiledLogin = id.login && id.login.pathPattern ? safeRegex(id.login.pathPattern, 'identity.login') : null;
  cfg.compiledWhoami = id.whoami && id.whoami.pathPattern ? safeRegex(id.whoami.pathPattern, 'identity.whoami') : null;
  cfg.compiledIgnore = ((cfg.ignore && cfg.ignore.pathPatterns) || []).map((p) => safeRegex(p, 'ignore')).filter(Boolean);
  cfg.maskFields = ((cfg.masking && cfg.masking.fields) || ['password', 'token', 'secret']).map((f) => String(f).toLowerCase());

  const th = cfg.thresholds || {};
  cfg.enumeration = {
    distinctIds: (th.enumeration && th.enumeration.distinctIds) || 5,
    windowSeconds: (th.enumeration && th.enumeration.windowSeconds) || 30,
  };
  cfg.bruteForce = {
    errors: (th.bruteForce && th.bruteForce.errors) || 15,
    windowSeconds: (th.bruteForce && th.bruteForce.windowSeconds) || 20,
    statuses: new Set((th.bruteForce && th.bruteForce.statuses) || [401, 403, 404]),
  };
  cfg.successMinBytes = (th.successMinBytes && th.successMinBytes.value) || 2;
  cfg.learnFromFirstSuccess = !(cfg.ownership && cfg.ownership.learnFromFirstSuccess === false);
  return cfg;
}

function loadOwnership(cfg) {
  const file = (cfg.ownership && cfg.ownership.file) || 'ownership.json';
  const p = path.join(CONFIG_DIR, file);
  const map = {};
  if (!fs.existsSync(p)) return map;
  try {
    const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
    for (const [endpoint, ids] of Object.entries(raw)) {
      if (endpoint.startsWith('_') || !ids || typeof ids !== 'object') continue;
      map[endpoint] = {};
      for (const [oid, owner] of Object.entries(ids)) map[endpoint][String(oid)] = String(owner);
    }
  } catch (err) {
    log('error', `ownership.json could not be read: ${err.message}`);
  }
  return map;
}

class Config {
  constructor() {
    this.listeners = [];
    this.current = null;
    this.reload();
    this.watch();
  }
  reload() {
    const p = path.join(CONFIG_DIR, 'rules.json');
    try {
      const raw = JSON.parse(fs.readFileSync(p, 'utf8'));
      const cfg = compile(raw);
      cfg.ownershipMap = loadOwnership(cfg);
      this.current = cfg;
      this.raw = raw;
      log('info', `config loaded from ${p} (${cfg.compiledEndpoints.length} endpoint rules)`);
      for (const l of this.listeners) l(cfg);
    } catch (err) {
      log('error', `could not load ${p}: ${err.message}${this.current ? ' - keeping previous config' : ''}`);
      if (!this.current) throw err;
    }
  }
  watch() {
    let timer = null;
    try {
      fs.watch(CONFIG_DIR, { persistent: false }, () => {
        clearTimeout(timer);
        timer = setTimeout(() => this.reload(), 300);
      });
    } catch (err) {
      log('info', `config hot-reload unavailable (${err.message})`);
    }
  }
  onChange(fn) {
    this.listeners.push(fn);
  }
  get() {
    return this.current;
  }
}

module.exports = { Config, CONFIG_DIR };

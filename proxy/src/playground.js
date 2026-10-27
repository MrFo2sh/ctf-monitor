'use strict';
// Mock playground: runs the fake CTF app and the fake-student simulator as child processes of the
// monitor, controlled from the dashboard (Playground tab). Nothing here runs unless started there.

const path = require('path');
const { spawn } = require('child_process');
const { log } = require('./util');

const MOCK_DIR = path.join(__dirname, '..', 'mock');
const MAX_LOG = 60;

class Proc {
  constructor(name) {
    this.name = name;
    this.child = null;
    this.startedAt = null;
    this.lines = [];
    this.lastExit = null;
    this.config = null;
  }
  running() {
    return !!this.child && this.child.exitCode === null && !this.child.killed;
  }
  start(script, env, config) {
    if (this.running()) throw new Error(`${this.name} is already running`);
    this.lines = [];
    this.lastExit = null;
    this.config = config || null;
    this.child = spawn(process.execPath, [script], { env: { ...process.env, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    this.startedAt = Date.now();
    const onLine = (chunk) => {
      for (const l of String(chunk).split('\n')) {
        if (!l.trim()) continue;
        this.lines.push(`${new Date().toLocaleTimeString([], { hour12: false })} ${l.trim()}`);
        if (this.lines.length > MAX_LOG) this.lines.shift();
      }
    };
    this.child.stdout.on('data', onLine);
    this.child.stderr.on('data', onLine);
    this.child.on('exit', (code, signal) => {
      this.lastExit = { code, signal, at: Date.now() };
      log('info', `playground: ${this.name} exited (${signal || code})`);
    });
    log('info', `playground: ${this.name} started (pid ${this.child.pid})`);
  }
  stop() {
    if (!this.running()) return false;
    this.child.kill('SIGTERM');
    const c = this.child;
    setTimeout(() => {
      if (c.exitCode === null) c.kill('SIGKILL');
    }, 2000).unref();
    return true;
  }
  status() {
    return { running: this.running(), pid: this.running() ? this.child.pid : null, startedAt: this.startedAt, lastExit: this.lastExit, config: this.config, log: this.lines.slice(-25) };
  }
}

const DEFAULT_SIM = { honest: 4, enumerator: true, sniper: true, noisy: true, anonymous: true, attacker: true, loop: true, pace: 1, rounds: 0 };

class Playground {
  constructor({ proxyPort }) {
    this.proxyPort = proxyPort;
    this.mock = new Proc('mock CTF app');
    this.sim = new Proc('simulator');
    this.mockPort = 3999;
  }

  startMock({ port } = {}) {
    const p = Number(port) || 3999;
    if (p < 1024 || p > 65535) throw new Error('port must be between 1024 and 65535');
    this.mockPort = p;
    this.mock.start(path.join(MOCK_DIR, 'mock-ctf.js'), { PORT: String(p), HOST: '127.0.0.1' }, { port: p });
    return this.status();
  }
  stopMock() {
    this.mock.stop();
    return this.status();
  }
  mockUrl() {
    return `http://127.0.0.1:${this.mockPort}`;
  }

  startSim(cfg = {}) {
    const c = { ...DEFAULT_SIM };
    for (const k of Object.keys(DEFAULT_SIM)) if (cfg[k] !== undefined) c[k] = cfg[k];
    c.honest = Math.max(0, Math.min(4, Number(c.honest) || 0));
    c.pace = Math.max(0.1, Math.min(10, Number(c.pace) || 1));
    c.rounds = Math.max(0, Math.min(1000, Number(c.rounds) || 0));
    for (const k of ['enumerator', 'sniper', 'noisy', 'anonymous', 'attacker', 'loop']) c[k] = !!c[k];
    const target = cfg.target ? String(cfg.target) : `http://127.0.0.1:${this.proxyPort}`;
    this.sim.start(path.join(MOCK_DIR, 'simulate.js'), { TARGET: target, SIM_CONFIG: JSON.stringify(c) }, { ...c, target });
    return this.status();
  }
  stopSim() {
    this.sim.stop();
    return this.status();
  }

  stopAll() {
    this.sim.stop();
    this.mock.stop();
  }

  status() {
    return { mock: { ...this.mock.status(), port: this.mockPort, url: this.mockUrl() }, sim: this.sim.status(), defaults: DEFAULT_SIM, proxyPort: this.proxyPort };
  }
}

module.exports = { Playground, DEFAULT_SIM };

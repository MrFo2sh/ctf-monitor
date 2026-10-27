'use strict';
// Finds candidate CTF apps: listening TCP ports on the host (/proc/net/tcp*, works because the
// monitor shares the host network) plus Docker containers (published ports and bridge IPs via the
// Docker socket, when it is mounted). Each candidate is probed to see whether it speaks HTTP.

const fs = require('fs');
const http = require('http');
const { log } = require('./util');

const DOCKER_SOCK = process.env.DOCKER_SOCK || '/var/run/docker.sock';

function hexAddr(h) {
  // /proc/net/tcp: "0100007F:1F90" -> 127.0.0.1:8080 ; tcp6: 32 hex chars
  const [a, p] = h.split(':');
  const port = parseInt(p, 16);
  let addr;
  if (a.length === 8) {
    const b = Buffer.from(a, 'hex');
    addr = `${b[3]}.${b[2]}.${b[1]}.${b[0]}`;
  } else if (a.length === 32) {
    const b = Buffer.from(a, 'hex');
    // the kernel prints four little-endian 32-bit words: ::ffff:a.b.c.d shows up as 00000000 00000000 FFFF0000 dcba(hex)
    if (b.subarray(0, 8).every((x) => x === 0) && b[8] === 0xff && b[9] === 0xff && b[10] === 0 && b[11] === 0) addr = `${b[15]}.${b[14]}.${b[13]}.${b[12]}`;
    else if (b.every((x) => x === 0)) addr = '::';
    else addr = '[v6]';
  } else addr = a;
  return { addr, port };
}

function parseProcNetTcp(text) {
  const out = [];
  for (const line of String(text).split('\n').slice(1)) {
    const cols = line.trim().split(/\s+/);
    if (cols.length < 4 || cols[3] !== '0A') continue; // 0A = LISTEN
    const { addr, port } = hexAddr(cols[1]);
    if (port > 0) out.push({ addr, port });
  }
  return out;
}

function listeningPorts() {
  const seen = new Map();
  for (const f of ['/proc/net/tcp', '/proc/net/tcp6']) {
    try {
      for (const e of parseProcNetTcp(fs.readFileSync(f, 'utf8'))) {
        const cur = seen.get(e.port);
        if (!cur || e.addr === '0.0.0.0' || e.addr === '::') seen.set(e.port, e);
      }
    } catch {
      /* not linux or not readable */
    }
  }
  return [...seen.values()];
}

function dockerApi(path) {
  return new Promise((resolve) => {
    if (!fs.existsSync(DOCKER_SOCK)) return resolve(null);
    const req = http.request({ socketPath: DOCKER_SOCK, path, method: 'GET', timeout: 2000 }, (res) => {
      const c = [];
      res.on('data', (d) => c.push(d));
      res.on('end', () => {
        try {
          resolve(res.statusCode === 200 ? JSON.parse(Buffer.concat(c).toString()) : null);
        } catch {
          resolve(null);
        }
      });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
    req.end();
  });
}

async function dockerContainers() {
  const list = await dockerApi('/containers/json');
  if (!Array.isArray(list)) return [];
  const out = [];
  for (const c of list) {
    const name = (c.Names && c.Names[0] ? c.Names[0] : c.Id.slice(0, 12)).replace(/^\//, '');
    const published = (c.Ports || []).filter((p) => p.PublicPort && p.Type === 'tcp').map((p) => ({ hostIp: p.IP || '0.0.0.0', hostPort: p.PublicPort, containerPort: p.PrivatePort }));
    let exposed = [...new Set((c.Ports || []).filter((p) => p.Type === 'tcp').map((p) => p.PrivatePort))];
    const ips = Object.values((c.NetworkSettings && c.NetworkSettings.Networks) || {}).map((n) => n.IPAddress).filter(Boolean);
    const hostNet = c.HostConfig && c.HostConfig.NetworkMode === 'host';
    let guessed = false;
    if (!exposed.length && !name.startsWith('ctf-watch')) {
      // no port metadata in the list: ask for the image's EXPOSE list
      const insp = await dockerApi(`/containers/${c.Id}/json`);
      const ex = insp && insp.Config && insp.Config.ExposedPorts ? Object.keys(insp.Config.ExposedPorts) : [];
      exposed = ex.filter((k) => k.endsWith('/tcp')).map((k) => Number(k.split('/')[0])).filter(Boolean);
      if (!exposed.length) guessed = true; // caller probes common ports instead
    }
    out.push({ name, image: c.Image, state: c.State, published, exposed, ips, hostNet, guessed });
  }
  return out;
}

function probeHttp(host, port, timeoutMs = 1500) {
  return new Promise((resolve) => {
    const req = http.request({ host, port, path: '/', method: 'GET', timeout: timeoutMs, headers: { 'User-Agent': 'ctf-watch-probe', Accept: 'text/html' } }, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (d) => {
        if (body.length < 4096) body += d;
        else res.destroy();
      });
      const finish = () => {
        const t = /<title[^>]*>([^<]{0,80})/i.exec(body);
        resolve({ ok: true, status: res.statusCode, server: String(res.headers.server || '').slice(0, 40), title: t ? t[1].trim() : '', location: res.headers.location || '', contentType: String(res.headers['content-type'] || '').split(';')[0] });
      };
      res.on('end', finish);
      res.on('close', finish);
      res.on('error', finish);
    });
    req.on('timeout', () => req.destroy());
    req.on('error', (e) => resolve({ ok: false, error: e.code || e.message }));
    req.end();
  });
}

// Docker Desktop (bridge mode): the monitor is not on the host network, so a "host" app lives at
// host.docker.internal; we probe the usual development ports there.
const DESKTOP_HOST_PORTS = [80, 3000, 3001, 4000, 4200, 5000, 5001, 5173, 7000, 8000, 8001, 8080, 8081, 8082, 8443, 8888, 9000, 9090];

/**
 * discover({ excludePorts, mode }) -> [{ url, host, port, source, container, image, probe }]
 * mode: 'host' (Linux, monitor shares the host network - default) | 'bridge' (Docker Desktop override)
 */
async function discover({ excludePorts = [], mode = process.env.DISCOVERY_MODE || 'host' } = {}) {
  const ex = new Set(excludePorts.map(Number));
  const byUrl = new Map();
  const add = (host, port, extra) => {
    const url = `http://${host}:${port}`;
    if (ex.has(Number(port)) && (host === '127.0.0.1' || host === 'host.docker.internal')) return;
    const cur = byUrl.get(url) || { url, host, port: Number(port), source: 'host', container: null, image: null };
    byUrl.set(url, { ...cur, ...extra });
  };
  const containers = await dockerContainers();
  if (mode === 'bridge') {
    for (const c of containers) {
      if (c.name === 'ctf-watch' || c.name === 'ctf-watch-simulator') continue;
      const ports = c.guessed ? DESKTOP_HOST_PORTS : c.exposed;
      for (const ip of c.ips) for (const p of ports) add(ip, p, { source: c.guessed ? 'docker-guess' : 'docker', container: c.name, image: c.image });
    }
    for (const p of DESKTOP_HOST_PORTS) add('host.docker.internal', p, { source: 'desktop-host' });
  } else {
    for (const e of listeningPorts()) add('127.0.0.1', e.port, { bindAddr: e.addr });
    for (const c of containers) {
      if (c.name === 'ctf-watch' || c.name === 'ctf-watch-simulator') continue;
      if (c.hostNet) {
        for (const p of c.exposed) add('127.0.0.1', p, { source: 'docker', container: c.name, image: c.image });
        continue;
      }
      for (const p of c.published) add('127.0.0.1', p.hostPort, { source: 'docker', container: c.name, image: c.image, containerPort: p.containerPort });
      if (!c.published.length) for (const ip of c.ips) for (const p of c.exposed) add(ip, p, { source: 'docker-bridge', container: c.name, image: c.image });
    }
  }
  let list = [...byUrl.values()].slice(0, 80);
  await Promise.all(list.map(async (c) => (c.probe = await probeHttp(c.host, c.port))));
  // the guessed desktop-host ports are only worth showing when something answers there
  list = list.filter((c) => (c.source !== 'desktop-host' && c.source !== 'docker-guess') || c.probe.ok);
  list.sort((a, b) => Number(b.probe.ok) - Number(a.probe.ok) || (a.source === 'docker' ? -1 : 0) - (b.source === 'docker' ? -1 : 0) || a.port - b.port);
  log('debug', `discover: ${list.length} candidates, ${list.filter((c) => c.probe.ok).length} speak http`);
  return list;
}

function validateTarget(input) {
  const s = String(input || '').trim();
  const pm = /:(\d+)\/?$/.exec(s);
  if (pm && (Number(pm[1]) < 1 || Number(pm[1]) > 65535)) throw new Error('bad port');
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error('target must look like http://127.0.0.1:5000');
  }
  if (u.protocol !== 'http:') throw new Error('only http:// targets are supported (the proxy talks plain http to the app)');
  if (!u.hostname) throw new Error('target needs a host');
  const port = Number(u.port) || 80;
  if (port < 1 || port > 65535) throw new Error('bad port');
  return `http://${u.hostname}:${port}`;
}

module.exports = { discover, listeningPorts, parseProcNetTcp, dockerContainers, probeHttp, validateTarget };

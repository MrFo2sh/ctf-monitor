'use strict';
// Fake students. Sends realistic traffic THROUGH THE PROXY so the dashboard has something to show.
// Started from the dashboard's Playground tab (or by hand):
//   TARGET=http://127.0.0.1:8888 SIM_CONFIG='{"honest":4,"loop":true}' node simulate.js
// SIM_CONFIG keys: honest (0-4), enumerator, sniper, noisy, anonymous, attacker (booleans),
//                  loop (boolean), pace (1 = normal, 0.5 = twice as fast), rounds (0 = unlimited with loop)

const http = require('http');

const TARGET = new URL(process.env.TARGET || 'http://127.0.0.1:8888');
let CFG = { honest: 4, enumerator: true, sniper: true, noisy: true, anonymous: true, attacker: true, loop: process.argv.includes('--loop'), pace: 1, rounds: 0 };
try {
  CFG = { ...CFG, ...JSON.parse(process.env.SIM_CONFIG || '{}') };
} catch {}
const PACE = Math.max(0.1, Number(CFG.pace) || 1);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms * PACE));
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));
let stopping = false;
process.on('SIGTERM', () => { stopping = true; console.log('[sim] stopping'); setTimeout(() => process.exit(0), 300); });
process.on('SIGINT', () => process.exit(0));

class Student {
  constructor(name, ip) {
    this.name = name;
    this.ip = ip;
    this.cookie = null;
    this.id = null;
  }
  req(method, path, body, headers = {}) {
    if (stopping) return Promise.resolve({ status: 0, json: null });
    return new Promise((resolve) => {
      const data = body ? JSON.stringify(body) : null;
      const r = http.request(
        {
          host: TARGET.hostname,
          port: TARGET.port || 80,
          method,
          path,
          headers: {
            'User-Agent': `sim/${this.name}`,
            'X-Forwarded-For': this.ip,
            Accept: 'application/json',
            ...(this.cookie ? { Cookie: this.cookie } : {}),
            ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}),
            ...headers,
          },
        },
        (res) => {
          const c = [];
          res.on('data', (d) => c.push(d));
          res.on('end', () => {
            const sc = res.headers['set-cookie'];
            if (sc) this.cookie = sc.map((s) => s.split(';')[0]).join('; ');
            let json = null;
            try {
              json = JSON.parse(Buffer.concat(c).toString());
            } catch {}
            resolve({ status: res.statusCode, json });
          });
        }
      );
      r.on('error', () => resolve({ status: 0, json: null }));
      if (data) r.write(data);
      r.end();
    });
  }
  async login() {
    const r = await this.req('POST', '/login', { username: this.name, password: 'password' });
    if (r.json && r.json.id) this.id = r.json.id;
    return r;
  }
  async browseOwn(times = 3) {
    if (!this.id) return;
    await this.req('GET', '/api/me');
    for (let i = 0; i < times; i++) {
      await this.req('GET', `/api/users/${this.id}`);
      await sleep(rnd(300, 900));
      await this.req('GET', `/api/orders/${this.order(0)}`);
      await sleep(rnd(300, 900));
      await this.req('GET', `/api/orders/${this.order(1)}`);
      await this.req('GET', '/static/app.js');
      await sleep(rnd(500, 1500));
    }
  }
  order(k) {
    return 1041 + (this.id - 1001) * 2 + k;
  }
}

async function honest(s) {
  await s.login();
  await s.browseOwn(4);
  if (!s.id) return;
  await s.req('GET', `/api/invoice?id=${s.order(0) + 6000}`);
  await s.req('GET', '/api/messages/' + (500 + ((s.id - 1001) % 8) + 8));
  await s.browseOwn(2);
}

async function enumerator(s) {
  await s.login();
  await s.browseOwn(1);
  await sleep(8000); // let the honest students establish ownership first
  for (let id = 1040; id <= 1062; id++) {
    await s.req('GET', `/api/orders/${id}`);
    await sleep(rnd(250, 500));
  }
  await sleep(2000);
  for (let id = 7040; id <= 7050; id++) {
    await s.req('GET', `/api/invoice?id=${id}`);
    await sleep(300);
  }
}

async function sniper(s) {
  await s.login();
  await s.browseOwn(1);
  await sleep(12000);
  await s.req('GET', '/api/users/1001'); // alice's profile - successful IDOR
  await sleep(1500);
  await s.req('GET', '/api/orders/1041'); // alice's order
  await sleep(1500);
  await s.req('GET', '/api/users/1002');
  await s.browseOwn(1);
}

async function noisy(s) {
  await s.login();
  await sleep(5000);
  for (let i = 0; i < 30; i++) {
    await s.req('GET', `/api/messages/${rnd(900, 9999)}`); // mostly 404
    await sleep(rnd(100, 300));
  }
  for (let i = 500; i < 530; i++) {
    await s.req('GET', `/api/messages/${i}`); // mix of 200 / 403
    await sleep(rnd(150, 350));
  }
}

// web exploitation probes (what the "attack classes" detection is for)
async function attacker(s) {
  await s.login();
  await sleep(6000);
  const probes = [
    ['GET', "/api/users/1001'%20OR%20'1'='1"],
    ['GET', '/api/orders/1041%20UNION%20SELECT%20username,password%20FROM%20users'],
    ['GET', '/dashboard?name=%3Cscript%3Ealert(document.cookie)%3C/script%3E'],
    ['GET', '/api/invoice?id=../../../../etc/passwd'],
    ['GET', '/render?tpl={{7*7}}'],
    ['GET', '/api/ping?host=127.0.0.1;id'],
    ['GET', '/fetch?url=http://169.254.169.254/latest/meta-data/'],
  ];
  for (const [m, p] of probes) {
    await s.req(m, p, null, { 'User-Agent': 'sqlmap/1.8#stable (https://sqlmap.org)' });
    await sleep(rnd(400, 900));
  }
  await s.req('POST', '/login', { username: { $ne: null }, password: { $ne: null } });
  await s.browseOwn(1);
}

async function anonymous(s) {
  // never logs in - identified by IP only
  await sleep(3000);
  for (let id = 1; id <= 8; id++) {
    await s.req('GET', `/api/users/${id}`); // 401s
    await sleep(600);
  }
  await s.req('POST', '/login', { username: 'admin', password: 'admin' });
  await s.req('POST', '/login', { username: 'admin', password: '123456' });
}

const HONEST = ['alice', 'bob', 'grace', 'heidi'];

async function round(n) {
  console.log(`[sim] round ${n} -> ${TARGET.origin}`);
  const S = (name, i) => new Student(name, `10.0.${n % 250}.${i}`);
  const jobs = [];
  HONEST.slice(0, CFG.honest).forEach((name, i) => jobs.push((async () => { await sleep(i * 3000); await honest(S(name, i + 1)); })()));
  if (CFG.enumerator) jobs.push(enumerator(S('carol', 3)));
  if (CFG.sniper) jobs.push(sniper(S('dave', 4)));
  if (CFG.noisy) jobs.push(noisy(S('eve', 5)));
  if (CFG.anonymous) jobs.push(anonymous(S('frank', 6)));
  if (CFG.attacker) jobs.push(attacker(S('mallory', 9)));
  await Promise.all(jobs);
  console.log(`[sim] round ${n} done`);
}

(async () => {
  console.log(`[sim] config ${JSON.stringify(CFG)}`);
  for (let i = 0; i < 60 && !stopping; i++) {
    const r = await new Student('probe', '10.0.0.250').req('GET', '/health');
    if (r.status) break;
    if (i === 0) console.log('[sim] waiting for the proxy to answer...');
    await sleep(1000);
  }
  let n = 1;
  do {
    await round(n++);
    if (CFG.rounds && n > CFG.rounds) break;
    if (CFG.loop && !stopping) await sleep(10000);
  } while (CFG.loop && !stopping);
  console.log('[sim] finished');
})();

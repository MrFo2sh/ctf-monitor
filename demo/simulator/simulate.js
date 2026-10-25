'use strict';
// Fake students. Sends realistic traffic THROUGH THE PROXY so the dashboard has something to show.
//   node simulate.js            one round (~70 s) then exit
//   node simulate.js --loop     rounds forever (what `./start.sh --demo` runs)
//   TARGET=http://127.0.0.1:8888 node simulate.js

const http = require('http');

const TARGET = new URL(process.env.TARGET || 'http://127.0.0.1:8888');
const LOOP = process.argv.includes('--loop');
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rnd = (a, b) => a + Math.floor(Math.random() * (b - a + 1));

class Student {
  constructor(name, ip) {
    this.name = name;
    this.ip = ip;
    this.cookie = null;
    this.id = null;
  }
  req(method, path, body, headers = {}) {
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

async function round(n) {
  console.log(`[sim] round ${n} -> ${TARGET.origin}`);
  const S = (name, i) => new Student(name, `10.0.${n % 250}.${i}`);
  const jobs = [
    honest(S('alice', 1)),
    honest(S('bob', 2)),
    enumerator(S('carol', 3)),
    sniper(S('dave', 4)),
    noisy(S('eve', 5)),
    (async () => {
      await sleep(4000);
      await honest(S('grace', 7));
    })(),
    (async () => {
      await sleep(9000);
      await honest(S('heidi', 8));
    })(),
    anonymous(S('frank', 6)),
  ];
  await Promise.all(jobs);
  console.log(`[sim] round ${n} done`);
}

(async () => {
  // wait for the proxy to be up
  for (let i = 0; i < 60; i++) {
    const r = await new Student('probe', '10.0.0.250').req('GET', '/health');
    if (r.status) break;
    await sleep(1000);
  }
  let n = 1;
  do {
    await round(n++);
    if (LOOP) await sleep(10000);
  } while (LOOP);
})();

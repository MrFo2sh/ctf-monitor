'use strict';
// Quick throughput check: hammers the proxy with concurrent requests and prints req/s and latency.
//   node demo/loadtest.js [--target http://127.0.0.1:8888] [--seconds 10] [--concurrency 50]
// Run it against a demo setup (./start.sh --demo) - never against the real CTF during the event.

const http = require('http');

const arg = (name, d) => { const i = process.argv.indexOf('--' + name); return i > 0 ? process.argv[i + 1] : d; };
const TARGET = new URL(arg('target', 'http://127.0.0.1:8888'));
const SECONDS = Number(arg('seconds', 10));
const CONC = Number(arg('concurrency', 50));
const PATHS = ['/api/users/1001', '/api/orders/1041', '/api/orders/999999', '/api/invoice?id=7041', '/api/messages/503', "/api/users/1?id=1'%20OR%201=1", '/'];

const agent = new http.Agent({ keepAlive: true, maxSockets: CONC });
let done = 0, errors = 0, bytes = 0;
const lat = [];
const stopAt = Date.now() + SECONDS * 1000;

function one(i) {
  return new Promise((resolve) => {
    const t0 = process.hrtime.bigint();
    const path = PATHS[(i + done) % PATHS.length];
    const req = http.request({ host: TARGET.hostname, port: TARGET.port || 80, path, agent, headers: { 'X-Forwarded-For': `10.9.${i % 250}.${(i * 7) % 250}`, Cookie: `session=load${i % 40}` } }, (res) => {
      res.on('data', (c) => (bytes += c.length));
      res.on('end', () => { lat.push(Number(process.hrtime.bigint() - t0) / 1e6); done++; resolve(); });
    });
    req.on('error', () => { errors++; resolve(); });
    req.end();
  });
}

async function worker(i) {
  while (Date.now() < stopAt) await one(i);
}

(async () => {
  console.log(`load test -> ${TARGET.origin}  ${CONC} concurrent clients for ${SECONDS}s`);
  const t0 = Date.now();
  await Promise.all(Array.from({ length: CONC }, (_, i) => worker(i)));
  const secs = (Date.now() - t0) / 1000;
  lat.sort((a, b) => a - b);
  const p = (q) => (lat[Math.floor(lat.length * q)] || 0).toFixed(1);
  console.log(`requests: ${done}  errors: ${errors}  ->  ${(done / secs).toFixed(0)} req/s   ${(bytes / secs / 1024).toFixed(0)} KB/s`);
  console.log(`latency ms: p50 ${p(0.5)}  p90 ${p(0.9)}  p99 ${p(0.99)}  max ${(lat[lat.length - 1] || 0).toFixed(1)}`);
  console.log(`memory of this client: ${(process.memoryUsage().rss / 1048576).toFixed(0)} MB`);
})();

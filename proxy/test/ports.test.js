'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('http');
const { parseProcNetTcp, probeHttp, validateTarget } = require('../src/ports');

test('parses LISTEN sockets out of /proc/net/tcp (ipv4 and mapped ipv6)', () => {
  const v4 = `  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:1388 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:A1B2 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 20 4 30 10 -1`;
  const rows = parseProcNetTcp(v4);
  assert.deepEqual(rows, [{ addr: '127.0.0.1', port: 8080 }, { addr: '0.0.0.0', port: 5000 }]);
  const v6 = `  sl  local_address                         remote_address                        st
   0: 00000000000000000000000000000000:22B8 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0
   1: 0000000000000000FFFF00000100007F:0050 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 1 1 0000000000000000 100 0 0 10 0`;
  assert.deepEqual(parseProcNetTcp(v6), [{ addr: '::', port: 8888 }, { addr: '127.0.0.1', port: 80 }]);
});

test('validateTarget normalises and rejects bad input', () => {
  assert.equal(validateTarget('http://127.0.0.1:5000/'), 'http://127.0.0.1:5000');
  assert.equal(validateTarget('http://172.17.0.3'), 'http://172.17.0.3:80');
  assert.throws(() => validateTarget('5000'), /look like/);
  assert.throws(() => validateTarget('https://x:1'), /only http/);
  assert.throws(() => validateTarget('http://127.0.0.1:70000'), /bad port/);
});

test('probeHttp reports status, server and title of an http server, and failure for a closed port', async () => {
  const srv = http.createServer((req, res) => {
    res.writeHead(200, { 'Content-Type': 'text/html', Server: 'mock/1' });
    res.end('<html><head><title>Shop CTF</title></head><body>hi</body></html>');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const port = srv.address().port;
  const p = await probeHttp('127.0.0.1', port);
  assert.deepEqual({ ok: p.ok, status: p.status, server: p.server, title: p.title }, { ok: true, status: 200, server: 'mock/1', title: 'Shop CTF' });
  srv.close();
  const closed = await probeHttp('127.0.0.1', port);
  assert.equal(closed.ok, false);
});

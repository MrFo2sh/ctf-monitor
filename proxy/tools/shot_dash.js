// Screenshot the ctf-watch dashboard through headless Chrome's DevTools protocol.
// usage (Git Bash): MSYS_NO_PATHCONV=1 WS_MODULE=D:/SIEMs/ctf-watch/proxy/node_modules/ws node tools/shot_dash.js http://127.0.0.1:8080 "ctfw_sid=<hex>" /live out.png 1600 1000
// Log in first with curl against /api/login to get the cookie. Headless Chrome only; it never touches the real cursor.
const { spawn } = require('node:child_process');
const fs = require('node:fs');
const WebSocket = require(process.env.WS_MODULE);

const [base, cookie, route, out, w = '1600', h = '1000'] = process.argv.slice(2);
const port = 9333;
const chrome = spawn('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', [
  '--headless=new', `--remote-debugging-port=${port}`, '--no-first-run', '--no-default-browser-check',
  `--window-size=${w},${h}`, '--hide-scrollbars', '--user-data-dir=' + process.env.TEMP + '\\ctfw-chrome', 'about:blank',
], { stdio: 'ignore' });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
(async () => {
  let targets;
  for (let i = 0; i < 40; i++) {
    try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); if (targets.length) break; } catch {}
    await sleep(250);
  }
  const ws = new WebSocket(targets[0].webSocketDebuggerUrl);
  await new Promise((r) => ws.on('open', r));
  let id = 0; const pending = new Map();
  ws.on('message', (m) => { const j = JSON.parse(m); if (pending.has(j.id)) { pending.get(j.id)(j); pending.delete(j.id); } });
  const call = (method, params = {}) => new Promise((r) => { const n = ++id; pending.set(n, r); ws.send(JSON.stringify({ id: n, method, params })); });
  await call('Page.enable'); await call('Network.enable');
  await call('Emulation.setDeviceMetricsOverride', { width: +w, height: +h, deviceScaleFactor: 1, mobile: false });
  if (cookie) {
    const [name, value] = cookie.split('=');
    await call('Network.setCookie', { name, value, url: base });
  }
  const nav = await call('Page.navigate', { url: base + route });
  console.log('navigate:', JSON.stringify(nav.result || nav.error));
  await sleep(3000);
  const title = await call('Runtime.evaluate', { expression: 'document.title + " | " + location.href + " | " + getComputedStyle(document.body).backgroundColor', returnByValue: true });
  console.log('page:', title.result && title.result.result && title.result.result.value);
  const shot = await call('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(out, Buffer.from(shot.result.data, 'base64'));
  console.log('SAVED', out);
  ws.close(); chrome.kill();
  process.exit(0);
})().catch((e) => { console.error(e); chrome.kill(); process.exit(1); });

'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the main-process request helper on the REAL
 * Electron network layer, which the unit tests cannot see (they run the same factory over Node's fetch). Proves:
 *   A) a POST with a body — the credential mint, as sync issues it — reaches a loopback server with its body
 *      intact and a Content-Length set by the network layer itself (a caller-set one is a restricted header
 *      that fails the whole request);
 *   B) a redirect is refused: a server answering 302 to a DIFFERENT loopback origin makes the call fail, and
 *      the second server never sees the request (so the bearer never travels);
 *   C) a plain GET with a bearer works, as the probe and the vault list use it;
 *   D) a body past the 5 MB cap is refused while it streams, without buffering it all.
 * Loopback only; nothing touches the app's data folder. Prints one PASS/FAIL line. Exit 0 = PASS.
 *
 *   node_modules/electron/dist/electron.exe test/net-helper-check.js
 */
const { app, net } = require('electron');
const http = require('node:http');
const { createHttpJson } = require('../src/main/http-json');
const { mintTempCred } = require('../src/main/sftp-cred');

const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; finish(3); }, 60000);
function finish(code) { clearTimeout(watchdog); process.stdout.write(`\nNET HELPER CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${JSON.stringify(out)}\n`); app.exit(code); }
function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}` }));
  });
}

app.whenReady().then(async () => {
  const httpJson = createHttpJson(net);

  // A) POST with a body: the mint, through the helper, to a stub that records what arrived.
  let seen = null;
  const mint = await serve((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen = { method: req.method, url: req.url, auth: req.headers.authorization, len: req.headers['content-length'], te: req.headers['transfer-encoding'], body };
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ temp_username: 'tc_x', credential: 'secret-x', expires_at: '2026-09-06T00:00:00Z' }));
    });
  });
  try {
    const cred = await mintTempCred({ serverOrigin: mint.origin, sessionToken: 't0k', vaultId: 'v1', validityMinutes: 15, vaultPassword: 'pw' }, httpJson);
    const parsed = seen && JSON.parse(seen.body);
    out.A_post = !!(cred && cred.user === 'tc_x' && seen && seen.method === 'POST' && seen.url === '/auth/temp-credentials' && seen.auth === 'Bearer t0k' && parsed && parsed.validity_minutes === 15 && seen.len === String(Buffer.byteLength(seen.body)) && !seen.te);
    out.A_detail = seen && { len: seen.len, te: seen.te || null, bodyBytes: Buffer.byteLength(seen.body) };
  } catch (e) { out.A_post = false; out.A_error = String(e && e.message).slice(0, 120); }
  mint.srv.close();

  // B) a redirect to another loopback origin: refused, and the target never sees the bearer.
  let targetHits = 0;
  const target = await serve((req, res) => { targetHits++; res.end('{}'); });
  const redirector = await serve((req, res) => { res.statusCode = 302; res.setHeader('Location', `${target.origin}/vaults`); res.end(); });
  try {
    await httpJson(`${redirector.origin}/vaults`, { headers: { Authorization: 'Bearer t0k' } });
    out.B_redirect = false; out.B_error = 'followed';
  } catch (e) {
    out.B_redirect = targetHits === 0 && /redirect/i.test(String(e && e.message));
    out.B_error = String(e && e.message).slice(0, 100);
  }
  redirector.srv.close(); target.srv.close();

  // C) a GET with a bearer.
  const list = await serve((req, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ auth: req.headers.authorization })); });
  try {
    const r = await httpJson(`${list.origin}/vaults`, { headers: { Authorization: 'Bearer t0k' } });
    out.C_get = r.ok === true && (await r.json()).auth === 'Bearer t0k';
  } catch (e) { out.C_get = false; out.C_error = String(e && e.message).slice(0, 100); }
  list.srv.close();

  // D) a body past the cap is refused while streaming.
  let sent = 0;
  const big = await serve((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const chunk = Buffer.alloc(256 * 1024, 0x20);
    const push = () => { while (sent < 8 * 1024 * 1024) { sent += chunk.length; if (!res.write(chunk)) { res.once('drain', push); return; } } res.end(); };
    push();
  });
  try {
    await httpJson(`${big.origin}/x`);
    out.D_cap = false; out.D_error = 'accepted';
  } catch (e) {
    out.D_cap = /too large/i.test(String(e && e.message));
    out.D_error = String(e && e.message).slice(0, 60);
  }
  big.srv.close();

  // E) the credential-free health check may follow a redirect and learns where it landed; F) the same
  //    opt-in with a bearer is refused before any request leaves.
  let landHits = 0;
  const landing = await serve((req, res) => { landHits++; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ status: 'healthy', auth: req.headers.authorization || null })); });
  const front = await serve((req, res) => { res.statusCode = 302; res.setHeader('Location', `${landing.origin}/health`); res.end(); });
  try {
    const r = await httpJson(`${front.origin}/health`, { headers: { Accept: 'application/json' }, redirect: 'follow' });
    const body = await r.json();
    out.E_follow = r.ok === true && r.url === `${landing.origin}/health` && body.status === 'healthy' && body.auth === null && landHits === 1;
  } catch (e) { out.E_follow = false; out.E_error = String(e && e.message).slice(0, 100); }
  try {
    await httpJson(`${front.origin}/health`, { headers: { Authorization: 'Bearer t0k' }, redirect: 'follow' });
    out.F_bearerFollowRefused = false;
  } catch (e) {
    out.F_bearerFollowRefused = /may not follow redirects/.test(String(e && e.message)) && landHits === 1;
  }
  front.srv.close(); landing.srv.close();

  out.ok = out.A_post === true && out.B_redirect === true && out.C_get === true && out.D_cap === true && out.E_follow === true && out.F_bearerFollowRefused === true;
  finish(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e).slice(0, 300); finish(2); });

'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the transport the MERGED app actually uses —
 * the installable build's request helper on Electron's network layer — carrying the device client's traffic.
 * The unit suite cannot see any of this: it runs the same helper over Node's fetch, and Node and Chromium
 * fail in different shapes. Loopback only; nothing touches the app's data folder.
 *
 *   A) the device credential mint's POST arrives intact: method, path, Authorization: Bearer <device secret>,
 *      the JSON body, a Content-Length set by the NETWORK LAYER (a caller-set one is refused by Chromium), no
 *      chunking — and the reply is parsed back into a credential bundle;
 *   B) the tray glance composes both truths at once: locked, and the server in force;
 *   C) four real transport failures — connection refused, DNS failure, request timeout, response over the cap —
 *      each read RETRYABLE by BOTH classifiers: the account path (net-errors isTransportError) and the device
 *      path (device-http, which must call it a network failure, never our own bug);
 *   D) the control that keeps C honest: a Node programming error (ERR_INVALID_ARG_TYPE) must read as an
 *      internal error on both, because an internal error is never retried and a bug must not masquerade as
 *      a network blip.
 *
 *   node_modules/electron/dist/electron.exe test/merged-transport-check.js
 */
const { app, net } = require('electron');
const http = require('node:http');
const { createHttpJson } = require('../src/main/http-json');
const { deviceRequest } = require('../src/main/device-http');
const { isTransportError, transportCode } = require('../src/main/net-errors');
const trayPresentation = require('../src/main/tray-presentation');
const { STATE } = require('../src/main/sync-status-model');

const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; finish(3); }, 90000);
function finish(code) {
  clearTimeout(watchdog);
  const rows = ['A_deviceMintPost', 'B_glance', 'C_refused', 'C_dns', 'C_timeout', 'C_tooLarge', 'D_programmingError'];
  out.ok = rows.every((r) => out[r] === true);
  process.stdout.write(`\nMERGED TRANSPORT CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${rows.map((r) => `${r.split('_')[0]}:${r.split('_')[1]}=${out[r]}`).join(' ')}\n${JSON.stringify(out, null, 1)}\n`);
  app.exit(out.ok ? 0 : (code || 1));
}
function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}` }));
  });
}
// Both classifiers on one real error: the account path and the device path must agree.
async function classify(origin, httpJson) {
  const account = {};
  try { await httpJson(`${origin}/device/sync-credential`, { method: 'GET' }); account.threw = false; }
  catch (e) { account.threw = true; account.transport = isTransportError(e); account.code = transportCode(e); account.message = String(e && e.message).slice(0, 60); }
  let device = {};
  try { await deviceRequest({ serverOrigin: origin, deviceSecret: 'dev-secret', route: 'mint', body: { vault_id: 'v1' } }, httpJson); device.threw = false; }
  catch (e) { device = { threw: true, reason: e && e.reason, code: e && e.code, status: e && e.status }; }
  return { account, device };
}

app.whenReady().then(async () => {
  const httpJson = createHttpJson(net);

  // ---- A) the device mint POST over the real network layer --------------------------------------
  let seen = null;
  const mint = await serve((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      seen = { method: req.method, url: req.url, auth: req.headers.authorization, ctype: req.headers['content-type'], len: req.headers['content-length'], te: req.headers['transfer-encoding'] || null, body };
      res.setHeader('Content-Type', 'application/json');
      res.end(JSON.stringify({ username: 'dev_tc', password: 'dev-secret-cred', host: '127.0.0.1', port: 2222, expires_at: '2026-09-08T00:00:00Z', host_public_key: 'ssh-ed25519 AAAATEST' }));
    });
  });
  try {
    const body = await deviceRequest({ serverOrigin: mint.origin, deviceSecret: 'dev-secret', route: 'mint', body: { vault_id: 'v1' } }, httpJson);
    const sent = seen && JSON.parse(seen.body);
    out.A_detail = seen && { method: seen.method, url: seen.url, auth: seen.auth, len: seen.len, te: seen.te, bytes: Buffer.byteLength(seen.body) };
    out.A_deviceMintPost = !!(seen
      && seen.method === 'POST' && seen.url === '/device/sync-credential'
      && seen.auth === 'Bearer dev-secret' && seen.ctype === 'application/json'
      && sent && sent.vault_id === 'v1'
      && seen.len === String(Buffer.byteLength(seen.body)) && !seen.te
      && body && body.username === 'dev_tc');
  } catch (e) { out.A_deviceMintPost = false; out.A_error = String(e && e.message).slice(0, 120); }
  mint.srv.close();

  // ---- B) the glance carries the lock AND the server --------------------------------------------
  try {
    const model = { state: STATE.PAUSED, reason: 'locked', condition: null, online: true, label: 'Paused', vaults: [{ vault: 'v1', state: STATE.SYNCING }, { vault: 'v2', state: STATE.PAUSED, reason: 'locked' }] };
    const locked = trayPresentation.tooltip(model, null, null, { lockReason: 'idle', server: { origin: 'https://vault.example.com' } });
    const noServer = trayPresentation.tooltip(model, null, null, { lockReason: 'idle', server: { origin: null } });
    out.B_detail = { locked, noServer };
    // A device vault keeps syncing under the lock, so the glance leads with the security state and appends
    // the sync truth; with no server in force nothing else can be true.
    out.B_glance = locked === 'DockVault — Locked · syncing 1 vault' && noServer === 'DockVault — Not connected';
  } catch (e) { out.B_glance = false; out.B_error = String(e && e.message).slice(0, 120); }

  // ---- C) four real transport failures, both classifiers ----------------------------------------
  // 1. connection refused: a port that was listening and is now closed.
  const closed = await serve((_req, res) => res.end());
  const closedOrigin = closed.origin;
  await new Promise((r) => closed.srv.close(r));
  const refused = await classify(closedOrigin, httpJson);
  out.C_refusedDetail = refused;
  out.C_refused = refused.account.transport === true && refused.device.reason === 'network';

  // 2. DNS failure: a name that cannot resolve.
  const dns = await classify('http://dockvault-nonexistent-host.invalid', httpJson);
  out.C_dnsDetail = dns;
  out.C_dns = dns.account.transport === true && dns.device.reason === 'network';

  // 3. request timeout: a server that accepts and never answers, against a short-timeout helper.
  const hang = await serve(() => { /* never responds */ });
  const quick = createHttpJson(net, { timeoutMs: 1200 });
  const timedOut = await classify(hang.origin, quick);
  out.C_timeoutDetail = timedOut;
  out.C_timeout = timedOut.account.transport === true && timedOut.device.reason === 'network';
  hang.srv.close();

  // 4. a response past the size cap.
  const big = await serve((_req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const chunk = Buffer.alloc(256 * 1024, 0x20);
    let sent = 0;
    const push = () => { while (sent < 8 * 1024 * 1024) { sent += chunk.length; if (!res.write(chunk)) { res.once('drain', push); return; } } res.end(); };
    push();
  });
  const tooLarge = await classify(big.origin, httpJson);
  out.C_tooLargeDetail = tooLarge;
  out.C_tooLarge = tooLarge.account.transport === true && tooLarge.device.reason === 'network';
  big.srv.close();

  // ---- D) the control: a programming error is OUR bug, never a retryable network blip -----------
  const bug = () => { throw Object.assign(new TypeError('The "url" argument must be of type string'), { code: 'ERR_INVALID_ARG_TYPE' }); };
  let deviceBug = {};
  try { await deviceRequest({ serverOrigin: 'http://127.0.0.1:1', deviceSecret: 'dev-secret', route: 'mint', body: { vault_id: 'v1' } }, bug); }
  catch (e) { deviceBug = { reason: e && e.reason, status: e && e.status }; }
  let accountBug = null;
  try { bug(); } catch (e) { accountBug = isTransportError(e); }
  out.D_detail = { accountTransport: accountBug, deviceReason: deviceBug.reason };
  out.D_programmingError = accountBug === false && deviceBug.reason === 'internal-error';

  finish(0);
}).catch((e) => { out.fatal = String((e && e.stack) || e).slice(0, 300); finish(2); });

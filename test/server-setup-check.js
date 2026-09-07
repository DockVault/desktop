'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the server setup screen end to end — the real
 * page (src/renderer/server-setup.html), the real typed preload, the real main-side module (server-setup.js:
 * the verify step with its two legs, the unreadable-confirm rule, the atomic write) — against loopback stubs
 * (an HTTP stub for the server, a fake SSH server for the SFTP door), in scratch user data, driven the way a
 * person would use it (type both addresses, press Check, read the lights, press Connect, read the line). No
 * network beyond 127.0.0.1. Proves:
 *   A) a DockVault stub that speaks sync + a fake SFTP server → both lights green, the "supports syncing"
 *      sentence, Connect → "Connected to 127.0.0.1:<port>.", origin AND endpoint saved atomically, the caller
 *      is told to open the sign-in page;
 *   B) a stub that is not DockVault → the server light red with "isn't a DockVault server", nothing saved;
 *   C) a closed API port → the server light red with "Couldn't reach", nothing saved;
 *   D) a plain-http REMOTE address → the https-only sentence on the server light, no request made;
 *   E) an unreadable saved setting → the confirm box, nothing written until the checkbox is ticked, then saved;
 *   F) change mode → the title changes and BOTH fields are pre-filled (host, and the remembered SFTP address);
 *   G) a degraded stub → the combined sentence and the sign-in page is scheduled after the hold;
 *   H) the sender gate (a page at the interface root is refused; a saved server is not re-pointed);
 *   I) a front that redirects the health route → the check follows and the landing origin is saved;
 *   J) the SFTP door closed on a server that speaks sync → server green, SFTP red, Connect withheld; a direct
 *      connect() from the page with that address is refused by main as not-verified and writes nothing;
 *   K) a server that does NOT speak sync (device route 404) → the SFTP light set aside, the plain "doesn't
 *      support syncing" sentence, Connect allowed, saved with no endpoint;
 *   L) the SFTP suggestion follows the server host while the field still holds the screen's own suggestion
 *      (a changed port is kept), stops once a host of the person's own is typed, and in change mode the
 *      previous server's address is replaced as soon as a different server host is typed.
 * Writes .local/server-setup-check.json and prints one PASS/FAIL line. Exit 0 = PASS.
 *
 *   node_modules/electron/dist/electron.exe test/server-setup-check.js
 */
const { app, BrowserWindow, ipcMain, session, net } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { createServerSetup, isTrustedSetupSender } = require('../src/main/server-setup');
const serverConfig = require('../src/main/server-config');
const { createHttpJson } = require('../src/main/http-json');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const { APP_ORIGIN } = require('../src/main/config');
const { fakeSshServer, listenFake } = require('./fake-ssh-server');

const RESULT = path.join(__dirname, '..', '.local', 'server-setup-check.json');
const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const SETUP_PAGE = 'server-setup.html';
const PAGE = schemeMod.shellPageUrl(APP_ORIGIN, SETUP_PAGE); // over the app scheme, as the app loads it
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
const httpJson = createHttpJson(net); // the app's own helper: Electron net, the OS trust store
schemeMod.registerPrivileged(); // before 'ready', as the app does
const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 120000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// An HTTP stub for the server: the health body for every route except /devices, which answers `devices`
// (401 = speaks sync, 404 = does not).
function serve(body, { devices = 401 } = {}) {
  return new Promise((resolve) => {
    const srv = http.createServer((req, res) => {
      res.setHeader('Content-Type', 'application/json');
      if (req.url.startsWith('/devices')) { res.statusCode = devices; res.end(JSON.stringify({ detail: 'x' })); return; }
      res.end(JSON.stringify(body));
    });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}`, host: `127.0.0.1:${srv.address().port}` }));
  });
}

// One fake SFTP server for every scenario that needs a green door, plus one closed port.
let sftp = null;
let closedSftp = null;

async function scenario(name, { dir, mode = null, before, drive, stub, pageUrl = null, changeHost, changeSftp }) {
  const saved = [];
  const scheduled = [];
  const setup = createServerSetup({ dir, httpJson, mode: () => mode, changeHost, changeSftp, onSaved: (o) => saved.push(o), schedule: (fn, ms) => { scheduled.push(ms); fn(); } });
  const win = sharedWindow();
  // The same three-leg sender check the app uses, bound to this window.
  const trusted = (e) => isTrustedSetupSender(e, { webContents: win.webContents, appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + SETUP_PAGE });
  ipcMain.removeHandler('dockvault:server.state');
  ipcMain.removeHandler('dockvault:server.check');
  ipcMain.removeHandler('dockvault:server.connect');
  ipcMain.handle('dockvault:server.state', (e) => (trusted(e) ? setup.state() : null));
  ipcMain.handle('dockvault:server.check', (e, a) => (trusted(e) ? setup.check(a) : null));
  ipcMain.handle('dockvault:server.connect', (e, a) => (trusted(e) ? setup.connect(a) : { kind: 'refused' }));
  if (before) await before();
  await win.loadURL(pageUrl || PAGE);
  await sleep(150);
  const r = await drive(win, { saved, scheduled, stub });
  out[name] = r;
  return r;
}

// One hidden window for every scenario, reloaded each time (a fresh window per scenario raced its
// predecessor's teardown on the shared session).
let theWindow = null;
function sharedWindow() {
  if (!theWindow || theWindow.isDestroyed()) {
    theWindow = new BrowserWindow({ show: false, webPreferences: { preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false } });
  }
  return theWindow;
}

const snapshot = `({
  line: document.getElementById('line').textContent, button: document.getElementById('connect').textContent, disabled: document.getElementById('connect').disabled,
  confirmShown: !document.getElementById('confirm').hidden, title: document.getElementById('title').textContent,
  field: document.getElementById('server').value, sftpField: document.getElementById('sftp').value,
  lightsShown: !document.getElementById('lights').hidden,
  api: document.getElementById('light-api').dataset.state, apiWhat: document.getElementById('api-what').textContent,
  sftp: document.getElementById('light-sftp').dataset.state, sftpWhat: document.getElementById('sftp-what').textContent,
  fp: document.getElementById('sftp-fp').textContent, sync: document.getElementById('sync').hidden ? '' : document.getElementById('sync').textContent,
})`;
const settle = `for (let i = 0; i < 400; i++) { await new Promise(r => setTimeout(r, 50)); const b = document.getElementById('connect').textContent; if (b !== 'Checking…' && b !== 'Connecting…') break; } await new Promise(r => setTimeout(r, 50));`;

// Type both addresses the way a person would, press Check, wait for the lights to settle.
const typeAndCheck = (server, sftpAddr) => `(async () => {
  const f = document.getElementById('server'); f.value = ${JSON.stringify(server)}; f.dispatchEvent(new Event('input', { bubbles: true }));
  ${sftpAddr === null ? '' : `const s = document.getElementById('sftp'); s.value = ${JSON.stringify(sftpAddr)}; s.dispatchEvent(new Event('input', { bubbles: true }));`}
  await new Promise(r => setTimeout(r, 30));
  document.getElementById('form').requestSubmit();
  ${settle}
  return ${snapshot};
})()`;
// Press the button again (Connect, when the check passed) and wait. A person reads the lights first; the screen
// ignores a submit that lands within a moment of the check finishing (a second Enter), so wait that moment out.
const pressAgain = `(async () => { await new Promise(r => setTimeout(r, 450)); document.getElementById('form').requestSubmit(); ${settle} return ${snapshot}; })()`;
// Check, then Connect if offered: what a person does on a good server.
const checkThenConnect = (server, sftpAddr) => `(async () => {
  const first = await ${typeAndCheck(server, sftpAddr)};
  if (first.button !== 'Connect') return { first, second: null };
  // A second Enter straight after the check must not connect: the button still reads Connect afterwards.
  document.getElementById('form').requestSubmit(); await new Promise(r => setTimeout(r, 60));
  const immediate = ${snapshot};
  const second = await ${pressAgain};
  return { first, immediate, second };
})()`;

app.whenReady().then(async () => {
  // The app scheme, wired as the app wires it: shell pages from local files, no server behind the proxy.
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, session.defaultSession);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-setup-check-'));
  const fresh = () => { const d = fs.mkdtempSync(path.join(root, 'ud-')); return d; };
  const fake = fakeSshServer();
  sftp = await listenFake(fake.handler);
  closedSftp = await listenFake(() => {}); await closedSftp.close();
  const SFTP_ADDR = `127.0.0.1:${sftp.port}`;
  const SFTP_EP = { host: '127.0.0.1', port: sftp.port };
  const CLOSED_ADDR = `127.0.0.1:${closedSftp.port}`;

  // A) DockVault stub that speaks sync + fake SFTP: Check lights both, Connect saves both
  {
    const stub = await serve({ status: 'healthy', database: 'connected' });
    const dir = fresh();
    const r = await scenario('A_ok', { dir, stub, drive: async (win, ctx) => {
      const ui = await win.webContents.executeJavaScript(checkThenConnect(stub.origin, SFTP_ADDR), true);
      return { ui, saved: serverConfig.readSavedServer(dir), files: fs.readdirSync(dir), opened: ctx.saved.length, scheduled: ctx.scheduled };
    } });
    const f = r.ui.first; const s = r.ui.second;
    out.A_guard = r.ui.immediate && r.ui.immediate.button === 'Connect';
    out.A_pass = out.A_guard === true && !!s && f.api === 'ok' && f.sftp === 'ok' && f.button === 'Connect' && f.disabled === false && f.fp.startsWith('Host key fingerprint SHA256:')
      && f.sync.startsWith('This server can sync folders from this computer. Nothing is syncing yet') && f.line === 'Both addresses check out. Connect to continue.'
      && s.line === `Connected to ${stub.host}.` && s.button === 'Connected' && r.saved.status === 'ok' && r.saved.origin === stub.origin
      && r.saved.sftp && r.saved.sftp.host === SFTP_EP.host && r.saved.sftp.port === SFTP_EP.port && r.files.length === 1 && r.opened === 1 && r.scheduled[0] === 0;
    stub.srv.close();
  }
  // B) not DockVault
  {
    const stub = await serve({ hello: 'world' });
    const dir = fresh();
    const r = await scenario('B_notDockvault', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndCheck(stub.origin, SFTP_ADDR), true), saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length }) });
    out.B_pass = r.ui.api === 'bad' && r.ui.apiWhat.startsWith("That address answers, but it isn't a DockVault server.") && r.ui.button === 'Check again' && r.ui.sftp === 'ok' && r.saved === 'absent' && r.opened === 0;
    stub.srv.close();
  }
  // C) closed API port
  {
    const stub = await serve({});
    await new Promise((res) => stub.srv.close(res));
    const dir = fresh();
    const r = await scenario('C_unreachable', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndCheck(stub.origin, SFTP_ADDR), true), saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length }) });
    out.C_pass = r.ui.api === 'bad' && r.ui.apiWhat === `Couldn't reach ${stub.host}. Check the address and your connection.` && r.ui.button === 'Check again' && r.saved === 'absent' && r.opened === 0;
  }
  // D) plain http to a remote host: refused before any request
  {
    const dir = fresh();
    const r = await scenario('D_httpRefused', { dir, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndCheck('http://vault.example.com', SFTP_ADDR), true), saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length }) });
    out.D_pass = r.ui.api === 'bad' && r.ui.apiWhat === 'DockVault connects over https only. Change http:// to https://.' && r.ui.line === 'Fix the server address, then check again.' && r.saved === 'absent';
  }
  // E) unreadable saved setting: confirm box, nothing written until ticked
  {
    const stub = await serve({ status: 'healthy' });
    const dir = fresh();
    fs.writeFileSync(serverConfig.configFile(dir), '{"origin": "https://old.exa');
    const r = await scenario('E_unreadable', { dir, stub, drive: async (win, ctx) => {
      const first = await win.webContents.executeJavaScript(`(() => ({ confirmShown: !document.getElementById('confirm').hidden, disabled: document.getElementById('connect').disabled }))()`, true);
      const checked = await win.webContents.executeJavaScript(typeAndCheck(stub.origin, SFTP_ADDR), true);
      const stillUnreadable = serverConfig.readSavedServer(dir).status;
      const ticked = await win.webContents.executeJavaScript(`(async () => { const c = document.getElementById('replace'); c.checked = true; c.dispatchEvent(new Event('change', { bubbles: true })); await new Promise(r => setTimeout(r, 30)); return ${snapshot}; })()`, true);
      const ui = await win.webContents.executeJavaScript(pressAgain, true);
      return { first, checked, stillUnreadable, ticked, ui, saved: serverConfig.readSavedServer(dir), opened: ctx.saved.length };
    } });
    out.E_pass = r.first.confirmShown === true && r.checked.api === 'ok' && r.checked.sftp === 'ok' && r.checked.button === 'Connect' && r.checked.disabled === true
      && r.stillUnreadable === 'unreadable' && r.ticked.disabled === false && r.ui.line === `Connected to ${stub.host}.` && r.saved.status === 'ok' && r.opened === 1;
    stub.srv.close();
  }
  // F) change mode: title + pre-filled host AND SFTP address (from memory, as the app keeps them during a switch)
  {
    const dir = fresh();
    const r = await scenario('F_changeMode', { dir, mode: 'change', changeHost: () => 'current.example.com', changeSftp: () => 'files.example.com:2200', drive: async (win) => win.webContents.executeJavaScript(`(() => ${snapshot})()`, true) });
    out.F_pass = r.title === 'Change your DockVault server' && r.field === 'current.example.com' && r.sftpField === 'files.example.com:2200' && r.button === 'Check';
    // First run: the SFTP field is suggested from the server as it is typed.
    const dir2 = fresh();
    const r2 = await scenario('F_suggest', { dir: dir2, drive: async (win) => win.webContents.executeJavaScript(`(async () => { const f = document.getElementById('server'); f.value = 'https://vault.example.com:8443/x'; f.dispatchEvent(new Event('input', { bubbles: true })); await new Promise(r => setTimeout(r, 30)); return ${snapshot}; })()`, true) });
    out.F_suggest = r2.sftpField === 'vault.example.com:2222';
    out.F_pass = out.F_pass && out.F_suggest;
  }
  // G) degraded: combined sentence, hold before the sign-in page
  {
    const stub = await serve({ status: 'degraded', database: 'disconnected' });
    const dir = fresh();
    const r = await scenario('G_degraded', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(checkThenConnect(stub.origin, SFTP_ADDR), true), saved: serverConfig.readSavedServer(dir).status, scheduled: ctx.scheduled }) });
    out.G_pass = !!r.ui.second && r.ui.first.api === 'ok' && r.ui.second.line === `Connected to ${stub.host}. Your server is running but reports a problem — signing in may still work.` && r.saved === 'ok' && r.scheduled[0] === 1500;
    stub.srv.close();
  }

  // H) the sender check: a page at the interface's root (same origin, same preload) is refused and writes nothing;
  //    the setup page itself may not re-point a saved server unless a switch was asked for in the tray.
  {
    const stub = await serve({ status: 'healthy' });
    const dir = fresh();
    const r = await scenario('H_gate', { dir, stub, pageUrl: `${APP_ORIGIN}/`, drive: async (win, ctx) => {
      const fromRoot = await win.webContents.executeJavaScript(`(async () => { const s = await window.dockvault.server.state(); const k = await window.dockvault.server.check(${JSON.stringify(stub.origin)}, ${JSON.stringify(SFTP_ADDR)}); const c = await window.dockvault.server.connect(${JSON.stringify(stub.origin)}, ${JSON.stringify(SFTP_ADDR)}); return { state: s, check: k, connect: c, url: location.href }; })()`, true);
      return { fromRoot, saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length };
    } });
    out.H_rootRefused = r.fromRoot.url === `${APP_ORIGIN}/` && r.fromRoot.state === null && r.fromRoot.check === null && r.fromRoot.connect && r.fromRoot.connect.kind === 'refused' && r.saved === 'absent' && r.opened === 0;
    const dir2 = fresh();
    serverConfig.writeServerOrigin(dir2, 'https://saved.example.com');
    const r2 = await scenario('H_policy', { dir: dir2, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(checkThenConnect(stub.origin, SFTP_ADDR), true), saved: serverConfig.readSavedServer(dir2), opened: ctx.saved.length }) });
    out.H_policyRefused = !!r2.ui.second && r2.ui.second.line === 'This screen is unavailable.' && r2.saved.origin === 'https://saved.example.com' && r2.opened === 0;
    out.H_pass = out.H_rootRefused === true && out.H_policyRefused === true;
    stub.srv.close();
  }

  // I) a front that redirects the health route to another loopback origin: the check follows, the line says
  //    unmissably where the person was sent, and the LANDING origin is what gets saved.
  {
    const real = await serve({ status: 'healthy' });
    const front = await new Promise((resolve) => {
      const srv = http.createServer((req, res) => { res.statusCode = 302; res.setHeader('Location', `${real.origin}${req.url}`); res.end(); });
      srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}`, host: `127.0.0.1:${srv.address().port}` }));
    });
    const dir = fresh();
    const r = await scenario('I_redirectLanding', { dir, stub: front, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(checkThenConnect(front.origin, SFTP_ADDR), true), saved: serverConfig.readSavedServer(dir), opened: ctx.saved.length }) });
    out.I_pass = !!r.ui.second && r.ui.first.apiWhat === `${front.host} sent us to ${real.host} — that's a DockVault server.` && r.ui.second.line === `${front.host} sent us to ${real.host} — connected there.` && r.ui.second.button === 'Connected' && r.saved.status === 'ok' && r.saved.origin === real.origin && r.opened === 1;
    front.srv.close(); real.srv.close();
  }

  // J) the SFTP door closed on a server that speaks sync: server green, SFTP red, Connect withheld; and a direct
  //    connect() from the page with that address is refused by MAIN (not merely by the page) — nothing written.
  {
    const stub = await serve({ status: 'healthy' });
    const dir = fresh();
    const r = await scenario('J_sftpRed', { dir, stub, drive: async (win, ctx) => {
      const ui = await win.webContents.executeJavaScript(typeAndCheck(stub.origin, CLOSED_ADDR), true);
      const direct = await win.webContents.executeJavaScript(`window.dockvault.server.connect(${JSON.stringify(stub.origin)}, ${JSON.stringify(CLOSED_ADDR)})`, true);
      const empty = await win.webContents.executeJavaScript(`window.dockvault.server.connect(${JSON.stringify(stub.origin)}, '')`, true);
      return { ui, direct, empty, saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length };
    } });
    out.J_pass = r.ui.api === 'ok' && r.ui.sftp === 'bad' && r.ui.sftpWhat.startsWith(`Couldn't reach ${CLOSED_ADDR}.`) && r.ui.button === 'Check again' && r.ui.line === 'Fix the file transfer address, then check again.'
      && r.ui.sync.startsWith('This server can sync folders from this computer.')
      && r.direct.kind === 'not-verified' && r.direct.verify.sftp.kind === 'unreachable' && r.empty.kind === 'not-verified' && r.empty.verify.sftp.kind === 'empty'
      && r.saved === 'absent' && r.opened === 0;
    stub.srv.close();
  }

  // K) a server that does NOT speak sync: the SFTP light set aside, the plain sentence, Connect allowed, no endpoint saved.
  {
    const stub = await serve({ status: 'healthy' }, { devices: 404 });
    const dir = fresh();
    const r = await scenario('K_noSync', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(checkThenConnect(stub.origin, CLOSED_ADDR), true), saved: serverConfig.readSavedServer(dir), opened: ctx.saved.length }) });
    const f = r.ui.first; const s = r.ui.second;
    out.K_pass = !!s && f.api === 'ok' && f.sftp === 'skip' && f.sftpWhat === "Not needed — this server doesn't sync folders, so this address is set aside."
      && f.sync === "This server doesn't support syncing folders from this computer. You can still sign in and use your files in the app."
      && f.line === 'Your server checks out. Connect to continue.'
      && f.button === 'Connect' && s.line === `Connected to ${stub.host}.` && r.saved.status === 'ok' && r.saved.origin === stub.origin && r.saved.sftp === null && r.opened === 1;
    stub.srv.close();
  }

  // L) the SFTP suggestion follows the server host, keeps a changed port, and stops once the person types a host.
  {
    const type = (id, value) => `(async () => { const f = document.getElementById(${JSON.stringify(id)}); f.value = ${JSON.stringify(value)}; f.dispatchEvent(new Event('input', { bubbles: true })); await new Promise(r => setTimeout(r, 30)); return document.getElementById('sftp').value; })()`;
    const dir = fresh();
    const r = await scenario('L_suggest', { dir, drive: async (win) => ({
      a: await win.webContents.executeJavaScript(type('server', 'https://one.example.com'), true),          // suggested
      b: await win.webContents.executeJavaScript(type('sftp', 'one.example.com:2200'), true),               // port changed, host still the suggestion
      c: await win.webContents.executeJavaScript(type('server', 'two.example.com'), true),                  // host follows, port kept
      d: await win.webContents.executeJavaScript(type('sftp', 'files.example.com:2200'), true),             // a host of the person's own
      e: await win.webContents.executeJavaScript(type('server', 'three.example.com'), true),                // no longer follows
    }) });
    out.L_follow = r.a === 'one.example.com:2222' && r.b === 'one.example.com:2200' && r.c === 'two.example.com:2200' && r.d === 'files.example.com:2200' && r.e === 'files.example.com:2200';
    // Change mode: the previous server's SFTP address is replaced as soon as a different server host is typed.
    const dir2 = fresh();
    const r2 = await scenario('L_changeFollows', { dir: dir2, mode: 'change', changeHost: () => 'old.example.com', changeSftp: () => 'old.example.com:2200', drive: async (win) => ({
      before: await win.webContents.executeJavaScript(`document.getElementById('sftp').value`, true),
      after: await win.webContents.executeJavaScript(type('server', 'new.example.com'), true),
    }) });
    out.L_change = r2.before === 'old.example.com:2200' && r2.after === 'new.example.com:2200';
    out.L_pass = out.L_follow === true && out.L_change === true;
  }

  const KEYS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L'];
  out.ok = KEYS.every((k) => out[`${k}_pass`] === true);
  try { await sftp.close(); } catch { /* ignore */ }
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nSERVER SETUP CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${KEYS.map((k) => `${k}=${out[`${k}_pass`]}`).join(' ')}\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

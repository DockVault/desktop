'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the server setup screen end to end — the real
 * page (src/renderer/server-setup.html), the real typed preload, the real main-side module (server-setup.js:
 * probe, unreadable-confirm rule, atomic write) — against a loopback stub, in scratch user data, driven the way
 * a person would use it (type, press Connect, read the line). No network beyond 127.0.0.1. Proves:
 *   A) a DockVault stub → "Connected to 127.0.0.1:<port>.", the setting is saved atomically, the caller is told
 *      to open the sign-in page;
 *   B) a stub that is not DockVault → "isn't a DockVault server", nothing saved, button reads Try again;
 *   C) a closed port → "Couldn't reach 127.0.0.1:<port>", nothing saved;
 *   D) a plain-http REMOTE address → the https-only line, inline, no request made;
 *   E) an unreadable saved setting → the confirm box, nothing written until the checkbox is ticked, then saved;
 *   F) change mode → the title changes and the field is pre-filled with the current host;
 *   G) a degraded stub → the combined sentence and the sign-in page is scheduled after the hold.
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

const RESULT = path.join(__dirname, '..', '.local', 'server-setup-check.json');
const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const SETUP_PAGE = 'server-setup.html';
const PAGE = schemeMod.shellPageUrl(APP_ORIGIN, SETUP_PAGE); // over the app scheme, as the app loads it
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
const httpJson = createHttpJson(net); // the app's own helper: Electron net, the OS trust store
schemeMod.registerPrivileged(); // before 'ready', as the app does
const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 90000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function serve(body) {
  return new Promise((resolve) => {
    const srv = http.createServer((_req, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(body)); });
    srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}`, host: `127.0.0.1:${srv.address().port}` }));
  });
}

async function scenario(name, { dir, mode = null, before, drive, stub, pageUrl = null }) {
  const saved = [];
  const scheduled = [];
  const setup = createServerSetup({ dir, httpJson, mode: () => mode, onSaved: (o) => saved.push(o), schedule: (fn, ms) => { scheduled.push(ms); fn(); } });
  const win = sharedWindow();
  // The same three-leg sender check the app uses, bound to this window.
  const trusted = (e) => isTrustedSetupSender(e, { webContents: win.webContents, appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + SETUP_PAGE });
  ipcMain.removeHandler('dockvault:server.state');
  ipcMain.removeHandler('dockvault:server.connect');
  ipcMain.handle('dockvault:server.state', (e) => (trusted(e) ? setup.state() : null));
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

// Type into the field the way a person would, submit, then wait for the line to settle.
const typeAndConnect = (value) => `(async () => {
  const f = document.getElementById('server'); f.value = ${JSON.stringify(value)}; f.dispatchEvent(new Event('input', { bubbles: true }));
  await new Promise(r => setTimeout(r, 30));
  document.getElementById('form').requestSubmit();
  for (let i = 0; i < 200; i++) { await new Promise(r => setTimeout(r, 50)); const b = document.getElementById('connect').textContent; if (b !== 'Checking…') break; }
  await new Promise(r => setTimeout(r, 50));
  return { line: document.getElementById('line').textContent, button: document.getElementById('connect').textContent, disabled: document.getElementById('connect').disabled, confirmShown: !document.getElementById('confirm').hidden, title: document.getElementById('title').textContent, field: f.value };
})()`;

app.whenReady().then(async () => {
  // The app scheme, wired as the app wires it: shell pages from local files, no server behind the proxy.
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, session.defaultSession);
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-setup-check-'));
  const fresh = () => { const d = fs.mkdtempSync(path.join(root, 'ud-')); return d; };

  // A) DockVault stub
  {
    const stub = await serve({ status: 'healthy', database: 'connected' });
    const dir = fresh();
    const r = await scenario('A_ok', { dir, stub, drive: async (win, ctx) => {
      const ui = await win.webContents.executeJavaScript(typeAndConnect(stub.origin), true);
      return { ui, saved: serverConfig.readSavedServer(dir), files: fs.readdirSync(dir), opened: ctx.saved.length, scheduled: ctx.scheduled };
    } });
    out.A_pass = r.ui.line === `Connected to ${stub.host}.` && r.ui.button === 'Connected' && r.saved.status === 'ok' && r.saved.origin === stub.origin && r.files.length === 1 && r.opened === 1 && r.scheduled[0] === 0;
    stub.srv.close();
  }
  // B) not DockVault
  {
    const stub = await serve({ hello: 'world' });
    const dir = fresh();
    const r = await scenario('B_notDockvault', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndConnect(stub.origin), true), saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length }) });
    out.B_pass = r.ui.line === "That address answers, but it isn't a DockVault server." && r.ui.button === 'Try again' && r.saved === 'absent' && r.opened === 0;
    stub.srv.close();
  }
  // C) closed port
  {
    const stub = await serve({});
    await new Promise((res) => stub.srv.close(res));
    const dir = fresh();
    const r = await scenario('C_unreachable', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndConnect(stub.origin), true), saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length }) });
    out.C_pass = r.ui.line === `Couldn't reach ${stub.host}. Check the address and your connection, then try again.` && r.ui.button === 'Try again' && r.saved === 'absent' && r.opened === 0;
  }
  // D) plain http to a remote host: refused before any request
  {
    const dir = fresh();
    const r = await scenario('D_httpRefused', { dir, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndConnect('http://vault.example.com'), true), saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length }) });
    out.D_pass = r.ui.line === 'DockVault connects over https only. Change http:// to https://.' && r.ui.button === 'Connect' && r.saved === 'absent';
  }
  // E) unreadable saved setting: confirm box, nothing written until ticked
  {
    const stub = await serve({ status: 'healthy' });
    const dir = fresh();
    fs.writeFileSync(serverConfig.configFile(dir), '{"origin": "https://old.exa');
    const r = await scenario('E_unreadable', { dir, stub, drive: async (win, ctx) => {
      const first = await win.webContents.executeJavaScript(`(() => ({ confirmShown: !document.getElementById('confirm').hidden, disabled: document.getElementById('connect').disabled }))()`, true);
      const typed = await win.webContents.executeJavaScript(`(async () => { const f = document.getElementById('server'); f.value = ${JSON.stringify(stub.origin)}; f.dispatchEvent(new Event('input', { bubbles: true })); await new Promise(r => setTimeout(r, 30)); return { disabled: document.getElementById('connect').disabled }; })()`, true);
      const stillUnreadable = serverConfig.readSavedServer(dir).status;
      const ticked = await win.webContents.executeJavaScript(`(async () => { const c = document.getElementById('replace'); c.checked = true; c.dispatchEvent(new Event('change', { bubbles: true })); await new Promise(r => setTimeout(r, 30)); return { disabled: document.getElementById('connect').disabled }; })()`, true);
      const ui = await win.webContents.executeJavaScript(typeAndConnect(stub.origin), true);
      return { first, typed, stillUnreadable, ticked, ui, saved: serverConfig.readSavedServer(dir), opened: ctx.saved.length };
    } });
    out.E_pass = r.first.confirmShown === true && r.typed.disabled === true && r.stillUnreadable === 'unreadable' && r.ticked.disabled === false && r.ui.line === `Connected to ${stub.host}.` && r.saved.status === 'ok' && r.opened === 1;
    stub.srv.close();
  }
  // F) change mode: title + pre-filled host
  {
    const dir = fresh();
    serverConfig.writeServerOrigin(dir, 'https://current.example.com');
    const r = await scenario('F_changeMode', { dir, mode: 'change', drive: async (win) => win.webContents.executeJavaScript(`(() => ({ title: document.getElementById('title').textContent, field: document.getElementById('server').value }))()`, true) });
    out.F_pass = r.title === 'Change your DockVault server' && r.field === 'current.example.com';
  }
  // G) degraded: combined sentence, hold before the sign-in page
  {
    const stub = await serve({ status: 'degraded', database: 'disconnected' });
    const dir = fresh();
    const r = await scenario('G_degraded', { dir, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndConnect(stub.origin), true), saved: serverConfig.readSavedServer(dir).status, scheduled: ctx.scheduled }) });
    out.G_pass = r.ui.line === `Connected to ${stub.host}. Your server is running but reports a problem — signing in may still work.` && r.saved === 'ok' && r.scheduled[0] === 1500;
    stub.srv.close();
  }

  // H) the sender check: a page at the interface's root (same origin, same preload) is refused and writes nothing;
  //    the setup page itself may not re-point a saved server unless a switch was asked for in the tray.
  {
    const stub = await serve({ status: 'healthy' });
    const dir = fresh();
    const r = await scenario('H_gate', { dir, stub, pageUrl: `${APP_ORIGIN}/`, drive: async (win, ctx) => {
      const fromRoot = await win.webContents.executeJavaScript(`(async () => { const s = await window.dockvault.server.state(); const c = await window.dockvault.server.connect(${JSON.stringify(stub.origin)}); return { state: s, connect: c, url: location.href }; })()`, true);
      return { fromRoot, saved: serverConfig.readSavedServer(dir).status, opened: ctx.saved.length };
    } });
    out.H_rootRefused = r.fromRoot.url === `${APP_ORIGIN}/` && r.fromRoot.state === null && r.fromRoot.connect && r.fromRoot.connect.kind === 'refused' && r.saved === 'absent' && r.opened === 0;
    const dir2 = fresh();
    serverConfig.writeServerOrigin(dir2, 'https://saved.example.com');
    const r2 = await scenario('H_policy', { dir: dir2, stub, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndConnect(stub.origin), true), saved: serverConfig.readSavedServer(dir2), opened: ctx.saved.length }) });
    out.H_policyRefused = r2.ui.line === 'This screen is unavailable.' && r2.saved.origin === 'https://saved.example.com' && r2.opened === 0;
    out.H_pass = out.H_rootRefused === true && out.H_policyRefused === true;
    stub.srv.close();
  }

  // I) a front that redirects the health route to another loopback origin: the check follows, the line says
  //    unmissably where the person was sent, and the LANDING origin is what gets saved.
  {
    const real = await serve({ status: 'healthy' });
    const front = await new Promise((resolve) => {
      const srv = http.createServer((_req, res) => { res.statusCode = 302; res.setHeader('Location', `${real.origin}/health`); res.end(); });
      srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}`, host: `127.0.0.1:${srv.address().port}` }));
    });
    const dir = fresh();
    const r = await scenario('I_redirectLanding', { dir, stub: front, drive: async (win, ctx) => ({ ui: await win.webContents.executeJavaScript(typeAndConnect(front.origin), true), saved: serverConfig.readSavedServer(dir), opened: ctx.saved.length }) });
    out.I_pass = r.ui.line === `${front.host} sent us to ${real.host} — connected there.` && r.ui.button === 'Connected' && r.saved.status === 'ok' && r.saved.origin === real.origin && r.opened === 1;
    front.srv.close(); real.srv.close();
  }

  out.ok = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'].every((k) => out[`${k}_pass`] === true);
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nSERVER SETUP CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'].map((k) => `${k}=${out[`${k}_pass`]}`).join(' ')}\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): confirm the transparent proxy
 * forwards the reused UI's API calls to the configured server over the custom scheme, against a
 * live instance. Reuses the real scheme + proxy + server-config modules.
 *
 *   DOCKVAULT_SERVER=http://localhost:8295 node_modules/electron/dist/electron.exe test/proxy-check.js
 *
 * Asserts: the UI loads over the scheme; a same-origin fetch of a public endpoint returns the
 * server's real JSON THROUGH the proxy (proving forwarding works); the UI's main script ran; and it
 * records whether a monitor WebSocket attempt failed (expected — a custom-scheme origin cannot form
 * a ws:// URL), which the honest-degradation path must handle. Uses public endpoints only; no creds.
 */

const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const serverConfig = require('../src/main/server-config');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'proxy-check.json');
const out = { server: process.env.DOCKVAULT_SERVER || null, consoleErrors: [], wsErrors: [] };

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});

const watchdog = setTimeout(() => { dump(); app.exit(3); }, 45000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  const resolve = () => serverConfig.readServerOrigin(app.getPath('userData'));
  out.resolvedOrigin = resolve();
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), resolve);

  const win = new BrowserWindow({
    show: false, width: 1200, height: 800,
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true },
  });
  win.webContents.on('console-message', (...a) => {
    const msg = String(a[2] || '');
    if (/websocket|ws:\/\/|wss:\/\//i.test(msg)) out.wsErrors.push(msg.slice(0, 200));
    else if ((a[1] || 0) >= 2) out.consoleErrors.push(msg.slice(0, 160));
  });

  await win.loadURL(`${APP_ORIGIN}/`);
  await new Promise((r) => setTimeout(r, 3000)); // let the UI boot and make its own calls

  // Fetch public endpoints from the renderer (same-origin) — these must be FORWARDED to the server.
  out.viaProxy = await win.webContents.executeJavaScript(`(async () => {
    const get = async (p) => { try { const r = await fetch(p); const t = await r.text(); return { status: r.status, ct: r.headers.get('content-type'), body: t.slice(0, 240) }; } catch (e) { return { error: String(e && e.message || e) }; } };
    return { policy: await get('/auth/policy'), branding: await get('/branding') };
  })()`, true);

  out.probe = await win.webContents.executeJavaScript(`({
    title: document.title,
    mainScriptRan: typeof window.apiRequest === 'function',
    isSecureContext: window.isSecureContext,
    origin: location.origin,
  })`, true);

  const p = out.viaProxy && out.viaProxy.policy;
  out.ok = !!(p && p.status === 200 && /signup_enabled/.test(p.body || '') && out.probe && out.probe.mainScriptRan);
  clearTimeout(watchdog);
  dump();
  win.destroy();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

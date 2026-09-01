'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the authoritative lock state is
 * pushed main -> renderer over the typed preload channel. A renderer with the real preload subscribes
 * via window.dockvault.lock.onState; the main process sends states; the renderer receives exactly
 * them, and the payload carries only { state, reason } — never key material.
 * Writes .local/lockstate-push-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/lockstate-push-check.js
 */

const { app, BrowserWindow, session } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
const RESULT = path.join(__dirname, '..', '.local', 'lockstate-push-check.json');
const PARTITION = 'dockvault-ui';
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 30000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  const ses = session.fromPartition(PARTITION);
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, ses);

  const win = new BrowserWindow({
    show: false,
    webPreferences: { partition: PARTITION, preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false },
  });
  await win.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`); // the reserved blank same-origin page

  out.hasOnState = await win.webContents.executeJavaScript(`typeof window.dockvault?.lock?.onState === 'function'`, true);

  await win.webContents.executeJavaScript(
    `window.__lock = []; window.dockvault.lock.onState((p) => { window.__lock.push(p); }); true;`, true);
  win.webContents.send('dockvault:evt:lockstate', { state: 'locked', reason: 'idle' });
  win.webContents.send('dockvault:evt:lockstate', { state: 'unlocked', reason: null });
  await new Promise((r) => setTimeout(r, 250));
  out.received = await win.webContents.executeJavaScript(`window.__lock`, true);

  const payloadKeysOk = Array.isArray(out.received)
    && out.received.every((p) => Object.keys(p).sort().join(',') === 'reason,state');

  win.destroy();
  out.ok = !!(out.hasOnState
    && Array.isArray(out.received) && out.received.length === 2
    && out.received[0].state === 'locked' && out.received[0].reason === 'idle'
    && out.received[1].state === 'unlocked'
    && payloadKeysOk);                         // authoritative state only; no key material
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

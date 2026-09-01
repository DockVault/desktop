'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the read-only sync-status surface
 * works end-to-end over the typed preload. A renderer with the real preload queries
 * window.dockvault.sync.status() and receives the one computed model that the main-process hub
 * produces; it also observes pushed updates via sync.onStatus. The payload is credential-free — only
 * states, labels, and symbolic reasons, never a credential, host key, token, or raw helper output.
 * Writes .local/sync-status-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/sync-status-check.js
 */

const { app, BrowserWindow, ipcMain, session } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const { SyncStatusHub } = require('../src/main/sync-status-hub');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
const RESULT = path.join(__dirname, '..', '.local', 'sync-status-check.json');
const PARTITION = 'dockvault-ui';
const FORBIDDEN = ['password', 'hostKeys', 'host', 'token', 'obscured', 'credential', 'expiresAt', 'secret'];
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 30000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  // A real hub (no forked helper needed): a configured vault with an unresolved conflict.
  const hub = new SyncStatusHub({ hasSecureStore: true, online: true });
  hub.setVaults(['Marketing']);
  hub.recordOutcome('Marketing', { result: 'conflict-keep-both', resyncRequired: false });
  ipcMain.handle('dockvault:sync.status', () => hub.current());

  const ses = session.fromPartition(PARTITION);
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, ses);

  const win = new BrowserWindow({
    show: false,
    webPreferences: { partition: PARTITION, preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false },
  });
  await win.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`);

  out.hasStatus = await win.webContents.executeJavaScript(`typeof window.dockvault?.sync?.status === 'function'`, true);
  out.hasOnStatus = await win.webContents.executeJavaScript(`typeof window.dockvault?.sync?.onStatus === 'function'`, true);

  // The on-demand query returns the computed model.
  out.queried = await win.webContents.executeJavaScript(`window.dockvault.sync.status()`, true);

  // A pushed update is observed by a subscriber.
  await win.webContents.executeJavaScript(
    `window.__sync = []; window.dockvault.sync.onStatus((m) => { window.__sync.push(m); }); true;`, true);
  win.webContents.send('dockvault:evt:syncstatus', hub.current());
  await new Promise((r) => setTimeout(r, 250));
  out.pushed = await win.webContents.executeJavaScript(`window.__sync`, true);

  const blob = JSON.stringify({ q: out.queried, p: out.pushed });
  out.credFree = FORBIDDEN.every((k) => !blob.includes(k));

  win.destroy();
  out.ok = !!(out.hasStatus && out.hasOnStatus
    && out.queried && out.queried.state === 'needs-decision' && out.queried.reason === 'conflict-keep-both'
    && Array.isArray(out.queried.vaults) && out.queried.vaults.length === 1
    && Array.isArray(out.pushed) && out.pushed.length === 1 && out.pushed[0].state === 'needs-decision'
    && out.credFree);
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

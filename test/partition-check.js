'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): confirm the in-memory UI partition
 * is app-lifetime — its web storage survives a window being destroyed and recreated (the
 * close-to-tray -> reopen path), while never persisting to disk. Writes .local/partition-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/partition-check.js
 */

const { app, BrowserWindow, session } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'partition-check.json');
const PARTITION = 'dockvault-ui';
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 40000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

function makeWin() {
  return new BrowserWindow({
    show: false, webPreferences: { partition: PARTITION, contextIsolation: true, sandbox: true, nodeIntegration: false },
  });
}

app.whenReady().then(async () => {
  const ses = session.fromPartition(PARTITION);
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, ses);

  // Window 1: write a value (as the UI would after login).
  const w1 = makeWin();
  await w1.loadURL(`${APP_ORIGIN}/`);
  await w1.webContents.executeJavaScript(`localStorage.setItem('authToken', 'survives-recreate'); true;`, true);
  out.wroteInWindow1 = await w1.webContents.executeJavaScript(`localStorage.getItem('authToken')`, true);
  w1.destroy(); // close-to-tray reclaims the renderer
  await new Promise((r) => setTimeout(r, 800));

  // Window 2: same partition, freshly created — the value must still be there.
  const w2 = makeWin();
  await w2.loadURL(`${APP_ORIGIN}/`);
  out.readInWindow2 = await w2.webContents.executeJavaScript(`localStorage.getItem('authToken')`, true);
  w2.destroy();

  // A DIFFERENT (fresh) in-memory partition must NOT see it (isolation sanity).
  const otherSes = session.fromPartition('dockvault-ui-other');
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, otherSes);
  const w3 = new BrowserWindow({ show: false, webPreferences: { partition: 'dockvault-ui-other', contextIsolation: true, sandbox: true } });
  await w3.loadURL(`${APP_ORIGIN}/`);
  out.readInOtherPartition = await w3.webContents.executeJavaScript(`localStorage.getItem('authToken')`, true);
  w3.destroy();

  out.ok = out.wroteInWindow1 === 'survives-recreate'
    && out.readInWindow2 === 'survives-recreate'   // survives destroy -> recreate (UX close-to-tray)
    && out.readInOtherPartition === null;          // isolated from other partitions
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

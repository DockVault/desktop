'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): confirm the shell cancels the
 * unreachable live-monitor WebSocket (ws://app/...) so it fails FAST rather than hanging on
 * "connecting". Mirrors the real network cancel from src/main hardenSession. Writes
 * .local/ws-degradation-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/ws-degradation-check.js
 */

const { app, BrowserWindow, session } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'ws-degradation-check.json');
const PARTITION = 'ws-check';
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 30000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  const ses = session.fromPartition(PARTITION);
  // The same cancel the real hardenSession installs.
  ses.webRequest.onBeforeRequest({ urls: ['ws://app/*', 'wss://app/*'] }, (_d, cb) => cb({ cancel: true }));
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, ses);

  const win = new BrowserWindow({ show: false, webPreferences: { partition: PARTITION, contextIsolation: true, sandbox: true } });
  await win.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`); // minimal same-origin page (host 'app')

  // Attempt the monitor WS exactly as the UI would; it must resolve to error/close fast, never open.
  // Start the attempt and record the outcome on a global (avoids returning a Promise over IPC).
  await win.webContents.executeJavaScript(`(() => {
    window.__ws = null; const t0 = Date.now();
    const set = (how) => { if (!window.__ws) window.__ws = { how, ms: Date.now() - t0 }; };
    try {
      const ws = new WebSocket('ws://app/ws/monitor');
      ws.onopen = () => set('open');
      ws.onerror = () => set('error');
      ws.onclose = () => set('close');
    } catch (e) { set('throw:' + ((e && e.name) || 'err')); }
    return true;
  })()`, true);
  await new Promise((r) => setTimeout(r, 2000));
  out.ws = await win.webContents.executeJavaScript(`window.__ws`, true);

  const how = out.ws && out.ws.how;
  out.ok = !!(how && how !== 'open' && how !== 'timeout' && out.ws.ms < 3000);
  win.destroy();
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

'use strict';
/*
 * Functional check (run under Electron on Windows, not part of `npm test`): the start-at-login module against
 * the REAL per-user Run key, exercised through the same functions the tray menu calls. Proves:
 *   A) turning it on writes the Run value under the shared name (the one the uninstaller removes) and the
 *      module reads it back as on;
 *   B) the "startup apps" switch (Task Manager → Startup) flipped off by hand reads as OFF even though the Run
 *      value is still there; turning it on again re-enables it and reads as on;
 *   C) turning it off removes the Run value, and the module reads it as off;
 *   D) a Run value deleted behind the app's back reads as off (no stale on).
 * Cleans up after itself (the Run value and the startup-approval flag are removed at the end). It never
 * touches the app's data folder. Writes .local/login-item-check.json and prints one PASS/FAIL line.
 *
 *   node_modules/electron/dist/electron.exe test/login-item-check.js
 */
const { app } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const { createLoginItem } = require('../src/main/login-item');
const { APP_ID, LOGIN_ITEM_NAME } = require('../src/main/app-identity');
// The real app sets this in index.js; Electron files and finds the login item under it.
app.setAppUserModelId(APP_ID);
const RESULT = path.join(__dirname, '..', '.local', 'login-item-check.json');
const RUN_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run';
const APPROVED_KEY = 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run';
const out = {};
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
function reg(args) { try { return execFileSync('reg', args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }); } catch { return null; } }
function runValue() { const r = reg(['query', RUN_KEY, '/v', LOGIN_ITEM_NAME]); if (!r) return null; const m = r.match(/REG_SZ\s+(.*)$/m); return m ? m[1].trim() : null; }
function cleanup() { reg(['delete', RUN_KEY, '/v', LOGIN_ITEM_NAME, '/f']); reg(['delete', APPROVED_KEY, '/v', LOGIN_ITEM_NAME, '/f']); }

app.whenReady().then(async () => {
  if (process.platform !== 'win32') { out.skipped = 'windows only'; dump(); process.stdout.write('LOGIN ITEM CHECK: SKIPPED (windows only)\n'); app.exit(0); return; }
  const item = createLoginItem({ app, platform: process.platform, fs, homeDir: os.homedir(), env: process.env, execPath: process.execPath });
  // A real registration (an installed DockVault with start-at-login on) is never touched: refuse instead.
  if (runValue() !== null) {
    out.refused = `a real login item exists under ${LOGIN_ITEM_NAME}; refusing to run so it is not removed`;
    dump();
    process.stdout.write(`LOGIN ITEM CHECK: REFUSED (${out.refused})\n`);
    app.exit(4);
    return;
  }
  out.startsOff = item.isEnabled() === false;

  // A) on → Run value under the shared name, pointing at this executable.
  item.setEnabled(true);
  const v = runValue();
  out.A_valueWritten = typeof v === 'string' && v.toLowerCase().includes(process.execPath.toLowerCase());
  out.A_readsOn = item.isEnabled() === true;

  // B) the startup-apps switch off by hand (the binary Windows writes for "disabled": 03 00 00 00 + 8 zero bytes).
  reg(['add', APPROVED_KEY, '/v', LOGIN_ITEM_NAME, '/t', 'REG_BINARY', '/d', '030000000000000000000000', '/f']);
  out.B_disabledReadsOff = item.isEnabled() === false && runValue() !== null;
  item.setEnabled(true);
  out.B_reenabledReadsOn = item.isEnabled() === true;

  // C) off → value gone.
  item.setEnabled(false);
  out.C_valueGone = runValue() === null;
  out.C_readsOff = item.isEnabled() === false;

  // D) deleted behind the app's back.
  item.setEnabled(true);
  reg(['delete', RUN_KEY, '/v', LOGIN_ITEM_NAME, '/f']);
  out.D_externalDeleteReadsOff = item.isEnabled() === false;

  cleanup();
  out.cleanedUp = runValue() === null;
  out.ok = !!(out.startsOff && out.A_valueWritten && out.A_readsOn && out.B_disabledReadsOff && out.B_reenabledReadsOn && out.C_valueGone && out.C_readsOff && out.D_externalDeleteReadsOff && out.cleanedUp);
  dump();
  process.stdout.write(`\nLOGIN ITEM CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${JSON.stringify(out)}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); cleanup(); dump(); app.exit(2); });

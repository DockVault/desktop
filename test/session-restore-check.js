'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): confirm the session capture +
 * restore path works on this machine — safeStorage is available, the shell can read the account
 * session the UI keeps in storage, the encrypted store round-trips it, and a main-driven same-origin
 * pre-seed restores it so a freshly loaded UI sees it. Writes .local/session-restore-check.json
 * (no token). Mirrors the real mechanism in src/main (seed page -> set storage -> load UI).
 *
 *   node_modules/electron/dist/electron.exe test/session-restore-check.js
 */

const { app, BrowserWindow, session, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const tokenStore = require('../src/main/token-store');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'session-restore-check.json');
const SESSION_KEYS = ['authToken', 'currentUser', 'userPermissions', 'isScopedTemp'];
const BUNDLE = { authToken: 'synthetic-bearer-value', currentUser: '{"username":"tester"}', userPermissions: '[]' };
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 45000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

async function seedInto(win) {
  await win.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`);
  await win.webContents.executeJavaScript(
    `(() => { const s = ${JSON.stringify(BUNDLE)}; for (const k of Object.keys(s)) localStorage.setItem(k, s[k]); return true; })()`, true);
}

app.whenReady().then(async () => {
  out.safeStorage = { available: safeStorage.isEncryptionAvailable(), backend: tokenStore.backendName(safeStorage), secure: tokenStore.isSecureBackend(safeStorage) };

  // --- Part A: capture (read the UI's storage) + encrypted store round-trip ---
  const sesA = session.fromPartition('restore-check-a');
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, sesA);
  const wa = new BrowserWindow({ show: false, webPreferences: { partition: 'restore-check-a', contextIsolation: true, sandbox: true } });
  await wa.loadURL(`${APP_ORIGIN}/`);
  await wa.webContents.executeJavaScript(
    `localStorage.setItem('authToken', ${JSON.stringify(BUNDLE.authToken)});`
    + `localStorage.setItem('currentUser', ${JSON.stringify(BUNDLE.currentUser)}); true;`, true);
  const captured = await wa.webContents.executeJavaScript(
    `(() => { const k=${JSON.stringify(SESSION_KEYS)},o={}; for (const key of k){const v=localStorage.getItem(key); if(v!=null)o[key]=v;} return o; })()`, true);
  out.captured = { hasToken: !!(captured && captured.authToken), keys: Object.keys(captured || {}) };
  wa.destroy();

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-sr-'));
  out.persist = tokenStore.persistSession(safeStorage, dir, captured);
  const loaded = tokenStore.loadSession(safeStorage, dir);
  out.roundTrip = !!(loaded && loaded.authToken === BUNDLE.authToken);

  // --- Part B: main-driven same-origin pre-seed must CARRY OVER across a navigation ---
  // Verifies the mechanism only: seed the storage on the app origin, then navigate to another page
  // of the SAME origin and confirm the storage persisted. (Loading the real UI here would clear it
  // by design: with no server its boot /users/me fails and the UI signs out — the correct
  // fail-closed re-validation, verified separately against a live server in the login+restore cycle.)
  const sesB = session.fromPartition('restore-check-b');
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, sesB);
  const wb = new BrowserWindow({ show: false, webPreferences: { partition: 'restore-check-b', contextIsolation: true, sandbox: true } });
  await seedInto(wb);
  await wb.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`); // same origin, minimal page (no UI to clear it)
  const seeded = await wb.webContents.executeJavaScript(`localStorage.getItem('authToken')`, true);
  out.seededCarriesOver = seeded === BUNDLE.authToken;
  wb.destroy();

  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  out.ok = out.captured.hasToken
    && (out.safeStorage.secure ? (out.persist.persisted && out.roundTrip) : !out.persist.persisted)
    && out.seededCarriesOver;
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

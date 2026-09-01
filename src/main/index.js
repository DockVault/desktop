'use strict';

/*
 * DockVault desktop — Electron shell (main process).
 *
 * Responsibilities:
 *   - register the custom privileged secure scheme and serve the reused web UI with a shell-owned,
 *     tightened Content-Security-Policy;
 *   - hardened window defaults: context isolation and sandbox on, node integration off, a minimal
 *     typed preload, deny-all permission requests, no external navigation or popups;
 *   - a boot crypto self-test (a known-answer test) in both engines — Node in the main process and
 *     Chromium in the renderer — that gates the UI and fails closed to a plain-language screen
 *     rather than a stack trace;
 *   - tray-resident with single-instance relaunch (always reopenable), a windowed fallback where no
 *     usable tray exists, close-to-tray with a one-time explainer and a remembered choice, and
 *     window-bounds persistence across destroy and recreate;
 *   - hardware acceleration disabled (a GUI crypto client needs no GPU rasterization, and dropping
 *     the GPU process reclaims its memory).
 *
 * Deliberately out of scope for the shell (added with later components, not silently skipped):
 * session/auth over the origin and the API proxy, the background sync helper and its authoritative
 * status, the fuller capability surface, and hiding rather than destroying the window while a
 * zero-knowledge vault is unlocked. The shell only guarantees an always-reopenable window; it does
 * not hard-wire destroy-always with no reopen path.
 *
 * DOCKVAULT_SMOKE=1 runs a headless functional check (boot self-test, UI load over the scheme,
 * renderer secure-context probe), writes .local/d1-smoke-result.json, and exits.
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, session, dialog, safeStorage } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('./config');
const schemeMod = require('./scheme');
const { buildCsp } = require('./csp');
const selftest = require('./selftest');
const serverConfig = require('./server-config');
const tokenStore = require('./token-store');

const STATIC_ROOT = path.resolve(__dirname, '..', '..', 'vendor', 'vault', 'static');
const PRELOAD = path.join(__dirname, '..', 'preload', 'index.js');
const FAIL_HTML = path.join(__dirname, '..', 'renderer', 'selftest-fail.html');
const TRAY_ICON = path.join(STATIC_ROOT, 'assets', 'logo-small.png');
const SMOKE = process.env.DOCKVAULT_SMOKE === '1';
// A NON-persistent (in-memory) partition, held by the main process for the app's lifetime: the UI's
// web storage never touches disk (so the account bearer the UI keeps in localStorage is never at
// rest on disk), yet it survives window destroy -> recreate on close-to-tray, resetting only on a
// full quit/relaunch. Durable session persistence is handled separately by the encrypted store.
const UI_PARTITION = 'dockvault-ui';
let uiSession = null;
// The account session bundle the shell restores on a fresh launch (loaded from the encrypted store).
// These are the keys the reused UI keeps in localStorage; only the bearer is secret, the rest is
// session metadata. The bundle is re-validated against the server by the UI's own boot check.
const SESSION_KEYS = ['authToken', 'currentUser', 'userPermissions', 'isScopedTemp'];
let sessionBundle = null;
let captureTimer = null;
let restored = false; // the session is seeded once per run (on the first window); tray reopens keep it

let mainWindow = null;
let tray = null;
let trayAvailable = false;
let bootSelfTest = null; // cached for the process lifetime; not re-run per window
let isQuitting = false;
const status = { mainSelfTest: null, rendererProbe: null, shown: false, failCode: null };

// A GUI crypto client needs no GPU rasterization; disabling it drops the GPU process.
app.disableHardwareAcceleration();

// The scheme must be registered before the 'ready' event.
schemeMod.registerPrivileged();

// A second launch must reach the running app, never spawn a rival.
if (!app.requestSingleInstanceLock()) {
  app.quit();
} else {
  // A second launch only brings the running app forward; any dockvault:// argument it carries is
  // deliberately NOT acted upon (deep links are default-deny — see open-url below).
  app.on('second-instance', () => { void showOrCreateWindow(); });
  app.on('activate', () => { void showOrCreateWindow(); });       // macOS dock reopen
  app.on('window-all-closed', () => { /* tray-resident: never auto-quit here */ });
  app.on('before-quit', () => { isQuitting = true; });
  // Deep links are DEFAULT-DENY in this version: the app is not registered as the OS handler for the
  // scheme, and if a dockvault:// URL is delivered anyway it is consumed here and NO action is taken
  // on it (no navigation, no intent). A future version that supports deep links will enumerate the
  // exact allowed actions rather than acting on an arbitrary URL.
  app.on('open-url', (event) => { event.preventDefault(); });
  app.whenReady().then(boot).catch((e) => {
    status.failCode = 'BOOT-' + String((e && e.code) || 'THREW');
    void finishSmokeIfNeeded();
  });
}

// ---------------------------------------------------------------------------------------------
// Persistent shell state (userData): window bounds and the remembered close-to-tray choice.
// ---------------------------------------------------------------------------------------------
function statePath() { return path.join(app.getPath('userData'), 'shell-state.json'); }
function readState() { try { return JSON.parse(fs.readFileSync(statePath(), 'utf8')); } catch { return {}; } }
function writeState(patch) {
  const next = { ...readState(), ...patch };
  try { fs.mkdirSync(path.dirname(statePath()), { recursive: true }); fs.writeFileSync(statePath(), JSON.stringify(next)); } catch { /* best effort */ }
  return next;
}

// ---------------------------------------------------------------------------------------------
async function boot() {
  uiSession = session.fromPartition(UI_PARTITION); // in-memory; created once, reused by every window
  hardenSession(uiSession);
  // Restore the account session from the encrypted store (null on a non-secure keychain or none):
  // the preload seeds it into the UI's storage at document-start on a fresh launch.
  sessionBundle = tokenStore.loadSession(safeStorage, app.getPath('userData'));
  // Keep the encrypted store current while a window is open, so a full quit does not lose the
  // session (the in-memory partition already survives close-to-tray within a run).
  captureTimer = setInterval(() => { void captureSession(); }, 30000);
  if (captureTimer.unref) captureTimer.unref();
  bootSelfTest = await selftest.runInMain();
  status.mainSelfTest = bootSelfTest;
  schemeMod.installHandler(STATIC_ROOT, buildCsp(),
    () => serverConfig.readServerOrigin(app.getPath('userData')), uiSession);
  registerIpc();
  setupTray();
  await showOrCreateWindow();
  await finishSmokeIfNeeded();
}

function hardenSession(ses) {
  // No renderer-initiated permission (camera, geolocation, notifications, etc.) is granted.
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  ses.setPermissionCheckHandler(() => false);
}

function registerIpc() {
  ipcMain.handle('dockvault:app.info', () => ({
    version: app.getVersion(),
    platform: process.platform,
    channel: 'dev',
  }));
}

// Read the account session the UI keeps in its storage and mirror it to the encrypted store, so a
// full quit does not force a re-login. Persists only while a bearer is present; clears the store
// when the UI has none (e.g. after sign-out). Never logs the token; best-effort.
async function captureSession() {
  const win = mainWindow;
  if (!win || win.isDestroyed()) return;
  const dir = app.getPath('userData');
  try {
    const bundle = await win.webContents.executeJavaScript(
      `(() => { const keys = ${JSON.stringify(SESSION_KEYS)}, o = {};`
      + ` for (const k of keys) { const v = localStorage.getItem(k); if (v != null) o[k] = v; } return o; })()`, true);
    if (bundle && bundle.authToken) tokenStore.persistSession(safeStorage, dir, bundle);
    else tokenStore.clearSession(dir);
  } catch { /* best effort; the token is never logged */ }
}

// Restore a stored session once per run, before the UI loads: load a minimal same-origin seed page,
// write the session into the origin's storage, then let showOrCreateWindow load the real UI (same
// origin, so the storage carries over and the UI's boot picks it up + re-validates against the
// server). Only on the first window of the run; tray reopens keep the in-memory partition's copy.
async function seedRestoredSession(win) {
  if (restored || !sessionBundle || !sessionBundle.authToken) return;
  const seed = {};
  for (const k of SESSION_KEYS) if (typeof sessionBundle[k] === 'string') seed[k] = sessionBundle[k];
  try {
    await win.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`);
    await win.webContents.executeJavaScript(
      `(() => { const s = ${JSON.stringify(seed)}; for (const k of Object.keys(s)) localStorage.setItem(k, s[k]); return true; })()`, true);
    restored = true;
  } catch { /* best effort; a failed restore just shows the sign-in screen */ }
}

// ---------------------------------------------------------------------------------------------
function trayImage() {
  try {
    if (fs.existsSync(TRAY_ICON)) {
      const img = nativeImage.createFromPath(TRAY_ICON);
      if (!img.isEmpty()) return img.resize({ width: 16, height: 16 });
    }
  } catch { /* fall through */ }
  return nativeImage.createEmpty();
}

function setupTray() {
  try {
    tray = new Tray(trayImage());
    tray.setToolTip('DockVault');
    tray.setContextMenu(Menu.buildFromTemplate([
      { label: 'Open DockVault', click: () => { void showOrCreateWindow(); } },
      { type: 'separator' },
      { label: 'Quit DockVault', click: () => { isQuitting = true; app.quit(); } },
    ]));
    tray.on('click', () => { void showOrCreateWindow(); });
    trayAvailable = true;
  } catch {
    // Some desktop environments expose no usable tray. Fall back to windowed mode so the app is
    // never a dead-end: closing the window minimizes it instead of destroying it into nothing.
    trayAvailable = false;
  }
}

// ---------------------------------------------------------------------------------------------
async function showOrCreateWindow() {
  if (mainWindow && !mainWindow.isDestroyed()) {
    if (mainWindow.isMinimized()) mainWindow.restore();
    mainWindow.show();
    mainWindow.focus();
    return mainWindow;
  }

  const bounds = readState().bounds || {};
  const win = new BrowserWindow({
    width: bounds.width || 1280,
    height: bounds.height || 860,
    x: bounds.x, y: bounds.y,
    show: false,
    backgroundColor: '#0a0f18',
    webPreferences: {
      partition: UI_PARTITION,
      preload: PRELOAD,
      contextIsolation: true,
      sandbox: true,
      nodeIntegration: false,
      nodeIntegrationInWorker: false,
      webSecurity: true,
      allowRunningInsecureContent: false,
      spellcheck: false,
    },
  });
  mainWindow = win;

  win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));            // no popups
  win.webContents.on('will-navigate', (e, url) => { if (!url.startsWith(APP_ORIGIN)) e.preventDefault(); });

  if (!bootSelfTest || !bootSelfTest.ok) {
    status.failCode = (bootSelfTest && bootSelfTest.code) || 'UNKNOWN';
    await loadFailInto(win, status.failCode);
    if (!SMOKE) win.show();
    return win;
  }

  await seedRestoredSession(win);
  await win.loadURL(`${APP_ORIGIN}/`);

  let probe = null;
  try { probe = await win.webContents.executeJavaScript(selftest.rendererProbeExpression(), true); }
  catch (e) { probe = { ok: false, code: 'RENDERER_PROBE_THREW', detail: String((e && e.message) || e) }; }
  status.rendererProbe = probe;

  if (!probe || !probe.ok || probe.isSecureContext !== true) {
    status.failCode = (probe && probe.code) || 'RENDERER_UNKNOWN';
    await loadFailInto(win, status.failCode);
    if (!SMOKE) win.show();
    return win;
  }

  status.shown = true;
  if (!SMOKE) win.show();      // in smoke mode the window stays hidden; only that it would show is asserted
  wireCloseToTray(win);
  wireBoundsPersistence(win);
  return win;
}

async function loadFailInto(win, code) {
  await win.loadFile(FAIL_HTML);
  try {
    await win.webContents.executeJavaScript(
      `document.getElementById('code').textContent = ${JSON.stringify(String(code))};`, true);
  } catch { /* the screen still reads correctly without the code */ }
  // eslint-disable-next-line no-console
  console.error(`crypto self-test failed SELFTEST-${code} — failing closed`);
}

function wireBoundsPersistence(win) {
  const save = () => { if (!win.isDestroyed()) writeState({ bounds: win.getNormalBounds() }); };
  win.on('resize', save);
  win.on('move', save);
}

function wireCloseToTray(win) {
  win.on('close', (e) => {
    if (isQuitting) return;
    e.preventDefault();
    if (!trayAvailable) { win.minimize(); return; }  // no tray: keep the app reachable
    maybeExplainCloseToTray();
    // Mirror the session to the encrypted store before the renderer is reclaimed, then destroy.
    captureSession().finally(() => {
      if (!win.isDestroyed()) win.destroy(); // reclaim the renderer; the tray "Open" item recreates it
      mainWindow = null;
    });
  });
}

function maybeExplainCloseToTray() {
  const st = readState();
  if (st.closeExplainerShown) return;
  writeState({ closeExplainerShown: true });
  try {
    dialog.showMessageBox({
      type: 'info',
      title: 'DockVault is still running',
      message: 'DockVault keeps running in the background',
      detail: 'Closing this window keeps DockVault in your system tray so sync can continue. Use the tray icon to reopen it, or choose Quit from the tray menu to exit completely.',
      buttons: ['Got it'], defaultId: 0, noLink: true,
    });
  } catch { /* the explainer is best-effort */ }
}

// ---------------------------------------------------------------------------------------------
async function finishSmokeIfNeeded() {
  if (!SMOKE) return;
  const result = {
    ok: !!status.shown && !status.failCode,
    status,
    origin: APP_ORIGIN,
    electron: process.versions.electron,
    utc: new Date().toISOString(),
  };
  try {
    const dir = path.join(__dirname, '..', '..', '.local');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'd1-smoke-result.json'), JSON.stringify(result, null, 2));
  } catch { /* best effort */ }
  isQuitting = true;
  app.quit();
}

module.exports = { __private: { readState, writeState } }; // exposed only for tests

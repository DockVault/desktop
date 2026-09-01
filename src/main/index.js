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
 * renderer secure-context probe), writes .local/shell-smoke-result.json, and exits.
 */

const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, session, dialog, safeStorage, powerMonitor, Notification } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('./config');
const schemeMod = require('./scheme');
const { buildCsp } = require('./csp');
const selftest = require('./selftest');
const serverConfig = require('./server-config');
const tokenStore = require('./token-store');
const { DaemonManager } = require('./daemon-manager');
const { LockState } = require('./lock-state');
const { AutoLock } = require('./auto-lock');
const keyProtect = require('./key-protection');
const { SyncStatusHub } = require('./sync-status-hub');
const trayPresentation = require('./tray-presentation');

const STATIC_ROOT = path.resolve(__dirname, '..', '..', 'vendor', 'vault', 'static');
const PRELOAD = path.join(__dirname, '..', 'preload', 'index.js');
const FAIL_HTML = path.join(__dirname, '..', 'renderer', 'selftest-fail.html');
const APP_ICON = path.join(__dirname, '..', '..', 'build', 'icon.png'); // the DockVault window + tray icon
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
let daemon = null;    // the supervised background sync daemon (a forked utility child)
let lockState = null; // the single source of truth for lock state (main-owned)
let autoLock = null;  // the automatic lock triggers (idle timer + OS suspend/screen-lock)
let syncHub = null;   // the main-owned computed sync status (feeds the tray, notifications, channel)
let lockPhase = 'unlocked'; // the lock machine's current phase, for the tray glance (locking/lock-error/…)

let mainWindow = null;
let tray = null;
let trayAvailable = false;
let bootSelfTest = null; // cached for the process lifetime; not re-run per window
let keyMode = null;      // the OS key-protection posture: 'A' software / 'B' hardware / 'C' none (refuse)
let isQuitting = false;
const status = { mainSelfTest: null, rendererProbe: null, shown: false, failCode: null, keyMode: null };

// A GUI crypto client needs no GPU rasterization; disabling it drops the GPU process.
app.disableHardwareAcceleration();

// Windows taskbar identity: without an explicit AppUserModelID a dev/unpackaged run groups under the
// generic Electron identity and shows its icon. Setting it ties the taskbar button (and notifications)
// to DockVault so the window icon is used. (Kept in step with the packaged app id at packaging time.)
if (process.platform === 'win32') app.setAppUserModelId('DockVault');

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
  app.on('before-quit', () => { isQuitting = true; if (autoLock) autoLock.stop(); if (daemon) daemon.stop(); });
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

// Standard-vault sync uses a pinned rclone binary. Its path + version + SHA-256 are configuration
// (sourced from the environment here; a bundled-binary manifest supplies them once packaging lands).
// Absent a configured binary the daemon simply offers no standard sync — it is never a fatal condition.
function resolveRcloneConfig() {
  const bin = process.env.DOCKVAULT_RCLONE;
  if (!bin) return null;
  return { bin, version: process.env.DOCKVAULT_RCLONE_VERSION || null, sha256: process.env.DOCKVAULT_RCLONE_SHA256 || null };
}

// ---------------------------------------------------------------------------------------------
async function boot() {
  // Verify the crypto primitives FIRST — before the session partition, safeStorage, or any vault
  // content is touched. The self-test is meant to run before any vault content, and running it first
  // also keeps its async WebCrypto known-answer test on a pristine crypto error state (an earlier
  // safeStorage / OSCrypt initialisation can otherwise leave the shared error queue dirty for it).
  bootSelfTest = await selftest.runInMain();
  status.mainSelfTest = bootSelfTest;

  uiSession = session.fromPartition(UI_PARTITION); // in-memory; created once, reused by every window
  hardenSession(uiSession);
  // Restore the account session from the encrypted store (null on a non-secure keychain or none):
  // the preload seeds it into the UI's storage at document-start on a fresh launch.
  sessionBundle = tokenStore.loadSession(safeStorage, app.getPath('userData'));
  // Keep the encrypted store current while a window is open, so a full quit does not lose the
  // session (the in-memory partition already survives close-to-tray within a run).
  captureTimer = setInterval(() => { void captureSession(); }, 30000);
  if (captureTimer.unref) captureTimer.unref();
  // OS key-protection posture. With no real secret store (Mode C: Linux 'basic_text' or no keychain)
  // the app still runs in a memory-only degraded mode — only at-rest persistence and the background
  // daemon are withheld (the session store and DB key already fail closed there). Hardware backing
  // (Mode B) is not asserted without a verified probe (a later phase), so a capable platform reads Mode A.
  keyMode = keyProtect.detectMode(safeStorage, process.platform);
  // Test hook: force the no-secure-store posture so the memory-only degraded path can be exercised. It
  // only ever makes the posture MORE restrictive (Mode C) — it can never grant a capability — so it is
  // safe to leave in place; there is no override that weakens protection.
  if (process.env.DOCKVAULT_FORCE_MODE_C === '1') keyMode = keyProtect.MODE.NONE;
  status.keyMode = keyMode;
  schemeMod.installHandler(STATIC_ROOT, buildCsp(),
    () => serverConfig.readServerOrigin(app.getPath('userData')), uiSession);
  registerIpc();
  setupTray();
  await showOrCreateWindow();
  // Start the supervised sync daemon (skipped under the headless shell smoke, which only exercises the
  // window). It forks a utility child, is handed the DB key once, and auto-restarts on an unexpected exit.
  // The background daemon owns the encrypted state store, so it starts only with a real secret store;
  // under a memory-only posture there is nothing durable for it and background sync is withheld.
  const secureStore = keyProtect.hasSecureStore(keyMode);
  if (!SMOKE && secureStore) { daemon = new DaemonManager(app.getPath('userData'), resolveRcloneConfig()); daemon.start(); }
  // The main-owned computed sync status: the single source of truth the tray glance, the must-act
  // notifications, and the read-only status channel all render. It observes the supervised helper's
  // lifecycle and is fed lock/posture here; with no OS secret store it honestly reports sync as
  // unavailable rather than pretending to run.
  if (!SMOKE) {
    syncHub = new SyncStatusHub({
      daemon,
      hasSecureStore: secureStore,
      onStatus: (m) => { pushSyncStatus(m); refreshTray(); },
      onNotify: (item) => notifyMustAct(item),
    });
    refreshTray(); // reflect the initial computed status now the hub exists (it does not emit on construction)
  }
  // The lock-state single source of truth (main-owned): the window and daemon observe it, and it
  // drives the atomic key purge on a lock. Indicators reflect it honestly (never "syncing" while locked).
  lockState = new LockState({
    getWindow: () => mainWindow,
    getDaemon: () => daemon,
    onChange: (s, reason) => {
      // The renderer observes the authoritative state — it never holds a divergent unlocked state.
      // The payload carries no key material.
      pushLockState(s, reason);
      // Lock is an input to the computed sync status (a locked vault pauses, but an unresolved item
      // still outranks it). The in-flight transients (locking / lock-error) colour the glance directly.
      lockPhase = s;
      if (syncHub && (s === 'locked' || s === 'unlocked')) syncHub.setLocked(s === 'locked');
      refreshTray();
    },
  });
  // Automatic lock triggers: a visibility-independent OS-idle timer plus system suspend / screen-lock,
  // driving the same atomic purge. Skipped under the headless smoke. The idle policy is the default
  // until the deployment's value is available (a later phase); the triggers only fire once unlocked.
  if (!SMOKE) {
    autoLock = new AutoLock({
      powerMonitor, lockState, getWindow: () => mainWindow,
      onDegraded: (code) => { console.warn('[dockvault] auto-lock posture degraded:', code); },
    });
    autoLock.start();
  }
  await finishSmokeIfNeeded();
}

function hardenSession(ses) {
  // No renderer-initiated permission (camera, geolocation, notifications, etc.) is granted.
  ses.setPermissionRequestHandler((_wc, _perm, cb) => cb(false));
  ses.setPermissionCheckHandler(() => false);
  // The reused UI derives its live-monitor WebSocket URL from the origin, which over this scheme is
  // an unreachable host (ws://app/...). Cancel it deterministically so it fails fast to the UI's
  // own "disconnected" state instead of churning host lookups; live push is simply unavailable in
  // the shell (data still loads over the request path), which the UI shows honestly.
  ses.webRequest.onBeforeRequest({ urls: ['ws://app/*', 'wss://app/*'] }, (_details, cb) => cb({ cancel: true }));
}

function registerIpc() {
  ipcMain.handle('dockvault:app.info', () => ({
    version: app.getVersion(),
    platform: process.platform,
    channel: 'dev',
    // Non-secret posture facts so the interface can show honest, graceful copy — e.g. a memory-only
    // note when there is no secret store (nothing kept across launches; stay-unlocked unavailable),
    // never a fail-closed takeover. No key material is exposed.
    keyProtection: keyMode,                              // 'A' | 'B' | 'C'
    persistence: keyProtect.hasSecureStore(keyMode),     // false => memory-only, re-auth each launch
  }));
  // The read-only sync-status query. Returns the one computed, credential-free model (states, labels,
  // symbolic reasons) — never a credential, host key, token, or raw helper output. Observe-only: there
  // is no renderer channel that starts, stops, or configures sync, so the lock and safety gates can
  // never be reached from a page.
  ipcMain.handle('dockvault:sync.status', () => (syncHub
    ? syncHub.current()
    : { state: 'unavailable', label: 'Sync unavailable', reason: 'no-secure-store', vaults: [], condition: 'unavailable' }));
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
    if (fs.existsSync(APP_ICON)) {
      const img = nativeImage.createFromPath(APP_ICON);
      if (!img.isEmpty()) return img.resize({ width: 16, height: 16 });
    }
  } catch { /* fall through */ }
  return nativeImage.createEmpty();
}

function setupTray() {
  try {
    tray = new Tray(trayImage());
    refreshTray(); // sets the initial tooltip + menu from the current status (neutral until the hub is up)
    tray.on('click', () => { void showOrCreateWindow(); });
    trayAvailable = true;
  } catch {
    // Some desktop environments expose no usable tray. Fall back to windowed mode so the app is
    // never a dead-end: closing the window minimizes it instead of destroying it into nothing.
    trayAvailable = false;
  }
}

// The ONE owner of the tray glance and menu: it composes both from the current computed sync status
// and the lock phase, so lock and sync never fight over the tooltip. Called on every status change
// and on every lock-phase change.
function refreshTray() {
  if (!tray) return;
  try {
    if (!syncHub) { tray.setToolTip('DockVault'); tray.setContextMenu(buildTrayMenu([])); return; }
    const model = syncHub.current();
    tray.setToolTip(trayPresentation.tooltip(model, lockPhase));
    tray.setContextMenu(buildTrayMenu(trayPresentation.mustActItems(model)));
  } catch { /* tray gone */ }
}

// Unresolved items sit at the TOP as reachable actions, so a decision, repair, or sign-in is never
// buried inside the (destroyable) main window — the tray always offers a way to act.
function buildTrayMenu(items) {
  const template = [];
  for (const it of items) template.push({ label: it.label, click: () => handleMustAct(it) });
  if (items.length) template.push({ type: 'separator' });
  template.push(
    { label: 'Open DockVault', click: () => { void showOrCreateWindow(); } },
    { label: 'Lock now', click: () => { if (lockState) void lockState.lock('manual').catch(() => { /* state machine surfaces lock-error */ }); } },
    { type: 'separator' },
    { label: 'Quit DockVault', click: () => { isQuitting = true; app.quit(); } },
  );
  return Menu.buildFromTemplate(template);
}

// Restarting a stuck helper is the one deliberate action that lives entirely in the shell. Every
// other must-act (review a conflict, sign in, repair) opens the app to where the person completes it;
// the specific in-app flows arrive with the components that own them.
function handleMustAct(item) {
  if (item && item.kind === 'restart') { if (daemon) daemon.resume(); refreshTray(); return; }
  void showOrCreateWindow();
}

// Push the computed status to the live renderer (main -> renderer). Cred-free by construction (it is
// the same model the tray renders); the renderer observes it read-only.
function pushSyncStatus(model) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    try { mainWindow.webContents.send('dockvault:evt:syncstatus', model); }
    catch { /* window gone mid-send */ }
  }
}

// One OS notification the first time an unresolved item appears (the hub de-duplicates). Cred-free —
// only the human label — and clicking it brings the app forward. Best-effort; never throws.
function notifyMustAct(item) {
  try {
    if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
    const n = new Notification({ title: 'DockVault', body: mustActBody(item) });
    n.on('click', () => { void showOrCreateWindow(); });
    n.show();
  } catch { /* notifications are best-effort */ }
}

function mustActBody(item) {
  if (item && item.kind === 'restart') return 'Sync stopped working. Your files are safe. Open DockVault to restart it.';
  const base = (item && item.label) || 'A sync item needs your attention';
  return `${base}. Your files are safe.`;
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
    icon: APP_ICON, // taskbar + minimized (+ title-bar on Windows/Linux) show the DockVault icon
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

  // With no real OS secret store the app still loads and is fully interactive (memory-only): at-rest
  // persistence and background sync are withheld elsewhere, not the interface. The session store
  // already returned nothing to seed in that case, so a fresh sign-in is required each launch.
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
  // A freshly (re-)created window starts from the authoritative state. It carries no zero-knowledge key
  // (the renderer's key is memory-only and died with any prior window), so re-showing requires re-auth
  // until an unlock flow marks it unlocked; the renderer is told the current state so it never assumes.
  if (lockState) pushLockState(lockState.isUnlocked() ? 'unlocked' : 'locked', null);
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

// Push the authoritative lock state to the live renderer (main -> renderer). The renderer only observes
// this — it never sources its own unlocked state — and the payload carries no key material.
function pushLockState(state, reason) {
  if (mainWindow && !mainWindow.isDestroyed()) {
    try { mainWindow.webContents.send('dockvault:evt:lockstate', { state, reason: reason || null }); }
    catch { /* window gone mid-send */ }
  }
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
    fs.writeFileSync(path.join(dir, 'shell-smoke-result.json'), JSON.stringify(result, null, 2));
  } catch { /* best effort */ }
  isQuitting = true;
  app.quit();
}

module.exports = { __private: { readState, writeState } }; // exposed only for tests

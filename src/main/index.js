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

const { app, BrowserWindow, Tray, Menu, ipcMain, nativeImage, session, dialog, safeStorage, powerMonitor, Notification, shell } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { execFile } = require('node:child_process');
const { net } = require('electron'); // OS-connectivity read for the sync scheduler's online gate (no network request)
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
const syncEnable = require('./sync-enable');
const syncVaults = require('./sync-vaults');
const syncConfig = require('./sync-config');
const syncConfigStore = require('./sync-config-store');
const enableCopy = require('./enable-copy');
const { mintSftpAccess } = require('./sftp-cred');
const { CredCache } = require('./cred-cache');
const { RunStateSnapshot } = require('./run-state-snapshot');
const { SyncScheduler } = require('./sync-scheduler');
const schedulerIo = require('./scheduler-io');
const { manualCompletionBody } = require('./manual-sync-copy');
const { ensureFolderSecure, recoverOwnerOnly, classifyForeignAces } = require('./folder-secure');

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
let rcloneCfg = null; // the pinned rclone config { bin, version, sha256 }; `version` is the pin shown for a helper version-mismatch
let lockState = null; // the single source of truth for lock state (main-owned)
let autoLock = null;  // the automatic lock triggers (idle timer + OS suspend/screen-lock)
let syncHub = null;   // the main-owned computed sync status (feeds the tray, notifications, channel)
let syncScheduler = null;   // the background scheduler (decides when/whether each vault syncs)
let runStateSnapshot = null; // main-side cache of per-vault run-state, refreshed from the daemon
let credCache = null;        // per-vault SFTP credential cache (mint via the account session, send to the daemon)
let syncTickTimer = null;    // the routine sync cadence timer
const SYNC_TICK_MS = 5 * 60 * 1000; // a locked/offline/no-session/uncertain/no-config tick is a cheap gated skip
const BOOT_SYNC_KICK_MS = 2000; // a first gated pass shortly after boot when already unlocked (no lock->unlock transition fires)
let lockPhase = null; // the lock machine's last phase; only the transients colour the glance (see effectiveLockPhase)
// The lock phase the tray glance may use. Only the in-flight transients (locking / lock-error) colour the
// glance; every settled phase is carried by the honest sync model instead. Returning null for a settled
// phase means main never asserts a literal "unlocked" before the first lock event — which on a fresh boot
// would glance unlocked while the account gate is still resolving. Derived, never a stale literal.
function effectiveLockPhase() {
  return (lockPhase === 'locking' || lockPhase === 'lock-error') ? lockPhase : null;
}
let lastSomeExcluded = false; // whether the last vault listing had non-eligible vaults (a bare flag for the picker note)
let syncFlowBusy = false;     // single-flight guard: one enable/stop-sync flow at a time (no dialog races)
// vaultId -> whether the server marks it password-protected, learned from the server-authoritative vault
// listing on every fetch. The mint path consults it to refuse minting a protected vault with no held
// password; an id never seen (or absent from a listing) is treated as protected (fail-safe true).
const standardVaultHasPassword = new Map();
function rememberVaultPasswordFlags(vaults) {
  try { for (const v of (Array.isArray(vaults) ? vaults : [])) if (v && typeof v.vaultId === 'string') standardVaultHasPassword.set(v.vaultId, v.hasPassword !== false); } catch { /* best effort */ }
}
function vaultRequiresPassword(vaultId) {
  // Fail-safe: only an id the server has EXPLICITLY marked unprotected skips the password requirement.
  return standardVaultHasPassword.get(vaultId) !== false;
}

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
  if (!SMOKE && secureStore) { rcloneCfg = resolveRcloneConfig(); daemon = new DaemonManager(app.getPath('userData'), rcloneCfg); daemon.start(); }
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
      onToast: (item) => notifyFirstSuccess(item),
    });
    // Seed the status with the vaults already configured for sync, so a returning user sees them.
    try { syncHub.setVaults(storedConfig().map((e) => e.vaultId)); } catch { /* no config yet */ }
    refreshTray(); // reflect the initial computed status now the hub exists (it does not emit on construction)
    resolveUserSid(); // resolve the account SID once (win32), so ACL checks can match the owner by SID
    startSyncScheduler(); // wire the background scheduler to the hub + daemon (dormant until a tick drives it)
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
      // The hub's locked signal tracks the ACCOUNT-TIER pause, read from the lock-state source of truth (appLocked)
      // rather than the zero-knowledge 'locked'/'unlocked' event vocabulary — so a lock pauses the glance, an
      // account-tier resume clears it, and a (future) zero-knowledge unlock can never clear it while account-tier
      // sync is still paused. The two tiers stay separate on the hub path too.
      if (syncHub) syncHub.setLocked(lockState.snapshot().appLocked);
      // #5 clear-on-lock: a lock pauses sync dispatch, so drop the account-tier SFTP credential as hygiene
      // — the main-side cache AND the helper's prepared config — re-minted from the still-live session on
      // unlock/resume. (The account session itself persists across a lock; only the derived credential is dropped.)
      if (s === 'locked') { if (credCache) credCache.clear(); if (daemon) void daemon.clearSftpCred(); }
      // An account-tier resume ('account-active') re-enables dispatch: nudge setup + kick a sync now the credential
      // can re-mint. Keyed on the account-tier signal, never the zero-knowledge 'unlocked' event, so the sync path
      // stays independent of the zero-knowledge key. 'account-active' asserts NO zero-knowledge key; the lock UI is
      // untouched.
      if (s === 'account-active') { void maybeOfferSyncSetup(); void tickSync(); }
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
    // A first sync pass shortly after boot when the app starts active for account-tier sync: the resume hook
    // only kicks on a lock->resume TRANSITION, so a cold start (appLocked defaults false) would otherwise sit
    // until the routine interval. Deferred a moment so the window and account session settle; gated like any
    // tick (the dispatch still re-checks the live account session, so no run starts before sign-in completes).
    if (lockState.isAccountUsable()) { const t = setTimeout(() => { void tickSync(); }, BOOT_SYNC_KICK_MS); if (t.unref) t.unref(); }
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
  // Enabling and stopping sync are driven entirely from the tray (and the notification click) in the
  // main process — there is deliberately NO renderer IPC to START, configure, or list sync. A
  // renderer initiator would be pure attack surface (a compromised page could pop the native flow),
  // and the read-only status channel above already gives a page everything it needs to observe.
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
    else {
      // Sign-out: the account session ended, so the SFTP credential derived from it is now invalid — clear
      // the persisted session AND the sync credential (main cache + the helper's prepared config), and drop
      // the in-memory session snapshot so the scheduler reads "signed out" and never mints against a dead session.
      tokenStore.clearSession(dir);
      sessionBundle = null;
      if (credCache) credCache.clear();
      if (daemon) void daemon.clearSftpCred();
    }
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

// The Standard-vault ACCESS password is NOT a zero-knowledge secret — the reused web UI already holds it
// in the clear and sends it to the server as the X-Vault-Password header to unlock a password-protected
// vault. To sync such a vault, that same password must reach the SFTP-credential mint. It is pulled from
// the renderer ONCE, at mint time, in a single eval, and bound to the exact vault whose run is in flight:
//   - bound:      the renderer returns the password ONLY when its currently-open vault IS `vaultId`; a
//                 password entered for a different vault is never handed over.
//   - typed:      main accepts only a non-empty string within a sane length bound; anything else -> null.
//   - fresh:      main independently enforces the 15-minute freshness from the renderer's timestamp, so a
//                 stale password (the UI's own expiry not yet swept) is refused here too.
//   - single-use: pulled fresh for THIS mint and never stashed in main; the caller zeroizes after use.
//   - lifecycle:  nothing is retained, so a lock/sign-out purge has nothing to clear here.
// Returns the password string, or null when none is validly available (the caller then refuses to mint
// and surfaces 'needs-unlock' WITHOUT calling the server — so no attempt is spent on the shared limiter).
const VAULT_PW_MAX_LEN = 1024;              // a generous upper bound; longer -> reject as malformed
const VAULT_PW_WINDOW_MS = 15 * 60 * 1000;  // main-enforced freshness, matching the renderer's own window
async function pullVaultPasswordForMint(vaultId) {
  const win = mainWindow;
  if (!win || win.isDestroyed() || typeof vaultId !== 'string' || !vaultId) return null;
  let pulled = null;
  try {
    // Bind in the eval: the raw fields are read only when the open vault matches; the password is
    // never returned for a different or no open vault. `state` is app.js's top-level classic-script binding.
    pulled = await win.webContents.executeJavaScript(
      `(() => { try {`
      + ` if (typeof state === 'undefined' || !state) return null;`
      + ` const want = ${JSON.stringify(vaultId)};`
      + ` if (!state.currentVaultId || String(state.currentVaultId) !== String(want)) return null;`
      + ` const pw = state.vaultPassword;`
      + ` if (typeof pw !== 'string' || pw.length === 0) return null;`
      + ` return { password: pw, ts: state.vaultPasswordTimestamp };`
      + ` } catch (e) { return null; } })()`, true);
  } catch { return null; } // a failed eval is a missing password, never a proceed-without-one
  if (!pulled || typeof pulled.password !== 'string') return null;
  const pw = pulled.password;
  if (pw.length === 0 || pw.length > VAULT_PW_MAX_LEN) { pulled.password = ''; return null; } // typed: reject empty/oversize
  const ts = typeof pulled.ts === 'number' ? pulled.ts : 0;                                    // fresh: the renderer timestamp
  if (!ts || (Date.now() - ts) > VAULT_PW_WINDOW_MS) { pulled.password = ''; return null; }
  pulled.password = ''; // drop our reference to the wrapper's copy; the returned string is the only live one
  return pw;
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
    if (!syncHub) { tray.setToolTip('DockVault'); tray.setContextMenu(buildTrayMenu([], null)); return; }
    const model = syncHub.current();
    tray.setToolTip(trayPresentation.tooltip(model, effectiveLockPhase(), rcloneCfg && rcloneCfg.version));
    tray.setContextMenu(buildTrayMenu(trayPresentation.mustActItems(model), model));
  } catch { /* tray gone */ }
}

// Unresolved items sit at the TOP as reachable actions, so a decision, repair, or sign-in is never
// buried inside the (destroyable) main window — the tray always offers a way to act.
function buildTrayMenu(items, model) {
  const template = [];
  for (const it of items) template.push({ label: it.label, click: () => handleMustAct(it) });
  if (items.length) template.push({ type: 'separator' });
  // The always-available, non-blocking offer (and the reversible list of what is already set up).
  // Sync is offered, never imposed: browsing a vault never requires setting this up.
  if (syncHub) {
    template.push({ label: 'Set up sync…', click: () => { void setupSyncForVault(); } });
    let configured = [];
    try { configured = storedConfig(); } catch { /* none */ }
    if (configured.length) {
      // The honest per-vault submenu content (Sync-now/Syncing… + the last-synced line, matched to live
      // status by id) is composed by the pure, tested trayPresentation.vaultRows; here it is only mapped
      // to menu items and bound to clicks.
      template.push({
        label: 'Synced folders',
        submenu: trayPresentation.vaultRows(configured, model && model.vaults, Date.now()).map((r) => ({
          label: r.vaultName,
          submenu: [
            { label: r.lastSynced, enabled: false },
            { type: 'separator' },
            { label: r.syncLabel, enabled: r.syncEnabled, click: () => syncVaultNow(r.vaultId) },
            { label: `Stop syncing ${r.vaultName}`, click: () => { void stopSyncing(r.vaultId, r.vaultName); } },
          ],
        })),
      });
    }
    template.push({ type: 'separator' });
  }
  template.push({ label: 'Open DockVault', click: () => { void showOrCreateWindow(); } });
  // When the account tier is paused by a lock, offer an explicit way back rather than a "Lock now" that is
  // already in effect. An idle / OS lock resumes on its own when input returns, but a deliberate "Lock now"
  // does NOT auto-resume (by design) — so this is the affordance that keeps a lock from being a one-way door
  // until relaunch. resumeAccount() re-enables ONLY the account tier; it never asserts the ZK key.
  const accountPaused = (() => { try { const s = lockState && lockState.snapshot(); return !!(s && s.appLocked); } catch { return false; } })();
  template.push(accountPaused
    ? { label: 'Resume sync', click: () => { if (lockState) lockState.resumeAccount(); } }
    : { label: 'Lock now', click: () => { if (lockState) void lockState.lock('manual').catch(() => { /* state machine surfaces lock-error */ }); } });
  template.push(
    { type: 'separator' },
    { label: 'Quit DockVault', click: () => { isQuitting = true; app.quit(); } },
  );
  return Menu.buildFromTemplate(template);
}

// Restarting a stuck helper is the one deliberate action that lives entirely in the shell. Every
// other must-act (review a conflict, sign in, repair) opens the app to where the person completes it;
// the specific in-app flows arrive with the components that own them.
function handleMustAct(item) {
  if (item && item.kind === 'restart') { if (daemon) daemon.restart(); refreshTray(); return; }
  if (item && item.kind === 'recover-folder' && item.vault) { void recoverSharedFolder(item.vault); return; }
  // The deliberate Repair: the ONLY thing that clears a blocked-after-run latch (a resync owed, or a
  // >50%-delete abort). It enqueues a manual repair run; the dispatch then asks the keep-both confirm
  // (confirmFirstUpload kind 'repair') before doing a zero-loss resync — nothing is auto-resynced.
  if (item && item.kind === 'repair' && item.vault) { if (syncScheduler) syncScheduler.requestRepair(item.vault); return; }
  // The sync helper (rclone) isn't ready — there is NO in-app install flow (the binary + its pinned version and
  // checksum come from the environment), so this action shows a real how-to dialog rather than a door to nowhere.
  if (item && item.kind === 'setup-helper') { showHelperFixDialog(item); return; }
  void showOrCreateWindow();
}

// A native how-to dialog for an unready sync helper: the specific reason + the pinned version + the (non-secret)
// config variable NAMES + "restart after fixing". Leak-safe — never a path, a value, or a SHA. The helper is
// env-configured until packaging bundles it, so correcting those settings and relaunching is the fix.
function showHelperFixDialog(item) {
  const detail = trayPresentation.helperDetail(item && item.sub, item && item.installed, rcloneCfg && rcloneCfg.version);
  try {
    dialog.showMessageBox(mainWindow, {
      type: 'warning', noLink: true, buttons: ['OK'], defaultId: 0,
      message: "The sync helper isn't ready",
      detail: `${detail}\n\nThe sync helper (rclone) is configured from these settings: DOCKVAULT_RCLONE (the binary), DOCKVAULT_RCLONE_VERSION, and DOCKVAULT_RCLONE_SHA256. Correct whichever is wrong or missing, then restart DockVault.`,
    });
  } catch { /* dialog unavailable; nothing else to offer */ }
}

// The make-private consent dialog, shared by setup and by run-time drift recovery. Its fail-safe default
// (both the default and the cancel button are "Choose a different folder") means Enter or dismissing the
// dialog declines — only an explicit "Make it private" click strips access. Wording is provisional.
async function confirmMakePrivateDialog(folder) {
  const res = await dialog.showMessageBox(mainWindow, {
    type: 'warning', title: 'This folder is shared', noLink: true,
    message: 'Other accounts can currently open this folder',
    detail: `To sync it privately, ${folder} needs to be made accessible only to you. Other accounts on this PC will lose access to it. You can make it private, or choose a different folder instead.`,
    buttons: ['Choose a different folder', 'Make it private'], defaultId: 0, cancelId: 0,
  });
  return res.response === 1 ? 'make-private' : 'choose-different';
}

// A synced folder that was made private at setup can be RE-SHARED later; the run-time check then reads
// 'folder-problem'. Re-present the SAME make-private consent: on an explicit yes, make it private again and
// retry that vault; on decline, open the app so the person can change the folder — nothing is ever
// stripped without the explicit consent.
async function recoverSharedFolder(vaultId) {
  let entry = null;
  try { entry = storedConfig().find((e) => e.vaultId === vaultId) || null; } catch { /* no config to act on */ }
  if (!entry || !entry.localFolder) { void showOrCreateWindow(); return; }
  let decision = 'choose-different';
  try { decision = await confirmMakePrivateDialog(entry.localFolder); } catch { decision = 'choose-different'; }
  if (decision !== 'make-private') { void showOrCreateWindow(); return; } // declined — nothing stripped
  const made = await recoverOwnerOnly(entry.localFolder, folderSecureIo());
  if (made && made.ok) { if (syncScheduler) syncScheduler.requestSync(vaultId, { manual: true }); } // secured — retry this vault
  else {
    try {
      await dialog.showMessageBox(mainWindow, {
        type: 'warning', title: "That folder can't be made private", noLink: true,
        message: "That folder can't be made private right now",
        detail: 'You can try again, or open DockVault to choose a different folder for this vault.',
        buttons: ['OK'],
      });
    } catch { /* best-effort */ }
  }
  refreshTray();
}

// Vaults whose CURRENT run was started by a deliberate "Sync now" press — so its completion earns one quiet
// confirmation. Routine ticks stay silent; a manual press is the exception, because the person who clicked
// it is waiting for a definite answer ("is it safe to close the lid?"). Cleared when that run's terminal
// event fires (or when the press joins an in-flight run, which then carries the confirmation on completion).
const pendingManualSync = new Set();
// The vaultId whose manual-completion toast is guaranteed to fire in the CURRENT onEvent callback — set for
// exactly that synchronous window so notifyMustAct can drop the redundant hub toast for the same event
// without ever silencing a must-act raised outside a press's terminal event.
let manualHookPending = null;

// A per-vault "Sync now" from the tray: only ENQUEUE a manual run. The scheduler coalesces (a run already
// in flight for this vault is not doubled) and serialises across vaults (another vault mid-run queues this
// one), and every dispatch gate stays fail-closed. So this asks for a run and lets the honest status
// surface show waiting/syncing in turn — it never asserts that a sync "started".
function syncVaultNow(vaultId) {
  if (!syncScheduler) return;
  // Flip the glance to the current online state at the moment of the press, so a "Sync now" while offline
  // reads "waiting to reconnect" INSTANTLY rather than green-until-the-next-tick; the dispatch still gates
  // offline (no real run), and the completion answer says "can't reach the server".
  if (syncHub) syncHub.setOnline(isOnlineNow());
  pendingManualSync.add(vaultId);
  syncScheduler.requestSync(vaultId, { manual: true });
}

// The completion answer a deliberate "Sync now" press earns — one notification, scoped to manual runs, so a
// person is never left wondering whether their press did anything. A press that lands "up to date" gets the
// reassurance; a press that ends blocked / offline / needs-sign-in gets the honest reason, never a silent
// no-op; a press the person themselves declined (the consent) gets nothing. Cred-free, best-effort.
function notifyManualComplete(vaultId, ev) {
  try {
    if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
    let name = vaultId;
    try { const e = storedConfig().find((c) => c.vaultId === vaultId); if (e && e.vaultName) name = e.vaultName; } catch { /* name only */ }
    // One source with the tray glance: the answer is derived from the same condition the sink records for this
    // event, so a "can't verify the server" pause is never mislabelled as "can't reach the server". A choice
    // the person made themselves (a declined upload) earns no toast.
    const msg = manualCompletionBody(ev, name);
    if (msg.silent) return;
    const n = new Notification({ title: 'DockVault', body: msg.body });
    n.on('click', () => { void showOrCreateWindow(); });
    n.show();
  } catch { /* notifications are best-effort */ }
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
    // Exactly-one-per-deliberate-press: when THIS vault's manual "Sync now" is ending in the SAME callback,
    // its scoped completion toast is the one answer — drop this redundant transient must-act toast (the tray
    // state still updates from the status emit). Suppress ONLY when the manual toast is guaranteed to fire
    // this callback (manualHookPending is set just for that window), so a must-act raised outside a press's
    // terminal event is never dropped — never zero.
    if (item && item.scope === 'vault' && item.vault === manualHookPending) return;
    const n = new Notification({ title: 'DockVault', body: mustActBody(item) });
    n.on('click', () => { void showOrCreateWindow(); });
    n.show();
  } catch { /* notifications are best-effort */ }
}

function mustActBody(item) {
  if (item && item.kind === 'restart') return 'Sync stopped working. Your files are safe. Open DockVault to restart it.';
  // The unlock-and-reopen guidance already carries its own reassurance and next step — use it verbatim rather
  // than appending the generic "Your files are safe." (which it already states).
  if (item && item.kind === 'reopen') return (item && item.label) || 'DockVault could not read its saved sync state. Your files are safe.';
  // The sync helper isn't ready: the notification body is the per-sub detail (with the app's pinned version for
  // a version-mismatch). The menu label carries the "Set up the sync helper" fix; the body says what's wrong.
  if (item && item.kind === 'setup-helper') return trayPresentation.helperDetail(item.sub, item.installed, rcloneCfg && rcloneCfg.version);
  const base = (item && item.label) || 'A sync item needs your attention';
  return `${base}. Your files are safe.`;
}

// One positive notification the first time a vault syncs successfully (the hub fires it at most once per
// vault, never on later successes). Cred-free — only the vault's own name — and clicking it opens the
// synced folder so "where did my files go" is answered in one click. Best-effort; never throws. The exact
// wording is provisional and settles with the rest of the human copy.
function notifyFirstSuccess(item) {
  try {
    if (!item || item.scope !== 'vault') return;
    if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
    let entry = null;
    try { entry = storedConfig().find((e) => e.vaultId === item.vault) || null; } catch { /* no config to name */ }
    const name = (entry && entry.vaultName) || 'Your vault';
    const n = new Notification({ title: 'DockVault', body: `${name} finished its first sync to this computer.` });
    n.on('click', () => {
      try {
        if (entry && entry.localFolder) shell.openPath(entry.localFolder);
        else void showOrCreateWindow();
      } catch { /* opening the folder is best-effort */ }
    });
    n.show();
  } catch { /* notifications are best-effort */ }
}

// ---------------------------------------------------------------------------------------------
// Enable-sync (set up a vault to sync to a local folder). The renderer only asks to begin; the
// vault pick, the native folder pick, the consent, and the write all happen here in the main process.

function storedConfig() { return syncConfigStore.loadConfig(safeStorage, app.getPath('userData')); }

// The account-session vault list is fetched through the shared JSON GET, which conforms to the
// injected-fetch (url, init) contract the sync modules call with — so the Authorization header they set
// in init.headers is actually sent. Used only to list the account's vaults; never carries a credential.
const mainHttpJson = require('./http-json').httpJson;

// Re-resolve the account session at the moment a flow needs it — never the boot-time snapshot, which
// goes stale (a first-run user who just signed in would otherwise get a false "not signed in" until a
// restart). Prefer the LIVE token from the open window's storage, then the persisted session, then the
// boot bundle.
async function resolveAccountToken() {
  const win = mainWindow;
  if (win && !win.isDestroyed()) {
    try {
      const t = await win.webContents.executeJavaScript("localStorage.getItem('authToken')", true);
      if (typeof t === 'string' && t) return t;
    } catch { /* fall through to the persisted copy */ }
  }
  try { const s = tokenStore.loadSession(safeStorage, app.getPath('userData')); if (s && s.authToken) return s.authToken; } catch { /* fall through */ }
  return (sessionBundle && sessionBundle.authToken) || null;
}

// The input/output surface the enable flow drives — every step that touches the OS lives here.
function syncConfigList() { try { return storedConfig(); } catch { return []; } }
function syncConfiguredIds() { return syncConfigList().map((e) => e.vaultId); }

// The one online reader — the scheduler's dispatch gate and the status hub's glance both read it, so they
// can never disagree. Fail-closed: an unknown state is a calm offline (never a false "syncing"/"up to date").
function isOnlineNow() { try { return net.isOnline(); } catch { return false; } }

// One sync pass: refresh the run-state view from the helper, drop any expired credentials (clearing the
// helper's now-stale slot too), then let the scheduler decide each configured vault. A manual pass
// ("Sync now") asks for each enabled vault ahead of the routine queue; a routine pass ticks them all. The
// run-state view is refreshed for EVERY configured vault (a disabled one still needs an honest status),
// but only enabled vaults are dispatched — matching the routine tick. Every dispatch is still gated
// (locked / offline / signed-out / uncertain → a calm skip), so this is safe to run on a timer regardless
// of state — and a no-config tick is simply a no-op.
async function tickSync({ manual = false } = {}) {
  if (!syncScheduler || !runStateSnapshot) return;
  // Feed the online signal to the STATUS hub, not only the scheduler's dispatch gate, from the one source —
  // so the tray glance and the run gate can never disagree. Without this the glance stays a false green
  // "Up to date" while the machine is offline and edits accrue; the model already renders offline as a calm
  // paused "waiting to reconnect".
  if (syncHub) syncHub.setOnline(isOnlineNow());
  await runStateSnapshot.refresh(syncConfiguredIds()); // a failed refresh keeps it not-fresh → the scheduler skips
  if (manual) { for (const e of syncConfigList()) if (e && e.enabled) syncScheduler.requestSync(e.vaultId, { manual: true }); }
  else syncScheduler.tickAll();
}

// A per-run icacls invocation (an argv array, never a shell string) for the owner-only folder ACL on
// win32. Resolves { code, stdout } so ensureFolderSecure can read the ACL back and verify it.
function runIcacls(args) {
  return new Promise((resolve) => {
    execFile('icacls', args, { windowsHide: true }, (err, stdout) => {
      resolve({ code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, stdout: stdout || '' });
    });
  });
}

// The current user's SID, resolved once at startup (win32) so ACL entries can be matched by SID as well as
// by name — a directory account (Entra/AzureAD) prints in a listing as a display name whose leaf is not the
// login username, which a name-only match would misread as a foreign account. Resolution is async and
// best-effort; until (or unless) it resolves, the name match is the fallback, so nothing blocks on it.
let currentUserSid = null;
function resolveUserSid() {
  if (process.platform !== 'win32') return;
  try {
    execFile('whoami', ['/user', '/fo', 'csv', '/nh'], { windowsHide: true }, (err, stdout) => {
      if (err) return;
      const m = String(stdout || '').match(/S-1-[0-9-]+/); // the account SID in the CSV row
      if (m) currentUserSid = m[0];
    });
  } catch { /* best-effort; name matching remains the fallback */ }
}

// The injected io the folder-secure module needs to apply/verify an owner-only ACL and to run the
// consented recovery: the real platform, the current account (name for the grant, SID for robust matching),
// the icacls runner, and POSIX chmod/mode.
function folderSecureIo() {
  return {
    platform: process.platform,
    user: { name: qualifiedUserName(), sid: currentUserSid },
    icacls: runIcacls,
    chmod: (d, m) => fs.chmodSync(d, m),
    mode: (d) => fs.statSync(d).mode,
  };
}

// The current account as an ACL listing prints it: the FULLY-QUALIFIED "DOMAIN\user" (or "MACHINE\user" for a local
// account), so the owner match is exact and never a bare-leaf over-match. Falls back to the bare username only when
// no domain is known (the SID is the robust match in that case).
function qualifiedUserName() {
  const name = process.env.USERNAME || process.env.USER || '';
  // COMPUTERNAME (the NetBIOS machine name) is what an ACL lists for a LOCAL account, and it equals USERDOMAIN
  // for one — so it is the right fallback when USERDOMAIN is somehow unset, avoiding a bare-name qualifier that
  // (with no SID) would make every folder read acl-non-owner forever. The SID stays the robust primary key.
  const domain = process.platform === 'win32' ? (process.env.USERDOMAIN || process.env.COMPUTERNAME || '') : '';
  return domain && name ? `${domain}\\${name}` : name;
}

// The first upload of a vault is confirmed here. A deliberate Repair always asks (keep-both, nothing
// deleted; default Not now). An initial upload of an already-consented config proceeds silently; a config
// written before the two-way consent was recorded re-asks it now, never assuming it. Copy is provisional.
async function confirmFirstUpload({ vaultId, kind }, entry) {
  if (kind === 'repair') {
    const res = await dialog.showMessageBox(mainWindow, {
      type: 'question', title: 'Repair sync', noLink: true,
      message: 'Repair sync for this vault?',
      detail: 'Nothing is deleted. Where the same file differs in both places, both copies are kept.',
      buttons: ['Repair', 'Not now'], defaultId: 1, cancelId: 1,
    });
    return res.response === 0;
  }
  if (entry && entry.consented) return true; // already agreed at set-up — do not re-ask
  const name = (entry && entry.vaultName) || vaultId;
  const folder = (entry && entry.localFolder) || '';
  // A config written before the two-way consent was recorded re-asks here — with the SAME non-empty warning
  // the setup flow gives: if the folder already holds files, say they will be uploaded, before the first byte.
  let nonEmpty = false;
  try { nonEmpty = !!folder && fs.readdirSync(folder).length > 0; } catch { nonEmpty = false; }
  const res = await dialog.showMessageBox(mainWindow, {
    type: 'question', title: 'Start syncing', noLink: true,
    message: `Start syncing ${name}?`,
    detail: enableCopy.consentMessage(name, folder, { nonEmpty }),
    buttons: ['Start syncing', 'Not now'], defaultId: 1, cancelId: 1,
  });
  return res.response === 0;
}

// Stand up the background sync scheduler once the hub + daemon exist. It wires the already-built,
// already-tested pieces (the credential cache, the run-state snapshot, the injected-IO scheduler) to the
// REAL Electron signals — lock state, the account session, OS connectivity — and folds each run event
// into the honest status hub. Dormant until a tick drives it (the cadence lands with the tray wiring).
function startSyncScheduler() {
  if (SMOKE || !syncHub || !daemon) return;
  const dir = app.getPath('userData');
  const home = app.getPath('home');
  const caseInsensitive = process.platform === 'win32' || process.platform === 'darwin';
  const resolveReal = (p) => { const real = fs.realpathSync.native || fs.realpathSync; try { return real(p); } catch { try { return fs.realpathSync(p); } catch { return path.resolve(p); } } };
  const configuredIds = () => { try { return storedConfig().map((e) => e.vaultId); } catch { return []; } };
  const entryFor = (vaultId) => { try { return storedConfig().find((e) => e.vaultId === vaultId) || null; } catch { return null; } };
  const entryByFolder = (folder) => { try { return storedConfig().find((e) => e.localFolder === folder) || null; } catch { return null; } };

  runStateSnapshot = new RunStateSnapshot({ fetch: (ids) => daemon.runStates(ids) });
  credCache = new CredCache({
    mint: async (vaultId) => {
      const origin = serverConfig.readServerOrigin(dir);
      const token = await resolveAccountToken();
      if (!origin || !token) { const e = new Error('not signed in'); e.status = 401; throw e; } // -> 'no-session' -> sign in
      // A password-protected vault must never be minted without its held password: the server treats a
      // missing password like a wrong one — 400 plus a burnt attempt on the limiter it SHARES with the web
      // UI's vault-open. So pull the access password (bound to THIS vault, fresh) and refuse BEFORE any
      // server call when it isn't available, surfacing the non-retrying 'needs-unlock' rather than minting.
      let vaultPassword;
      if (vaultRequiresPassword(vaultId)) {
        vaultPassword = await pullVaultPasswordForMint(vaultId);
        if (!vaultPassword) { const e = new Error('vault password not available'); e.reason = 'needs-unlock'; throw e; }
      }
      try {
        return await mintSftpAccess({ serverOrigin: origin, sessionToken: token, vaultId, vaultPassword }, mainHttpJson);
      } finally {
        vaultPassword = ''; // single-use: drop the plaintext the moment the mint request has been issued
      }
    },
    // Bind the send to the child epoch sampled at mint time: a restart mid-mint refuses delivery to the
    // replacement child (a credential minted for a child that is gone is never handed to its successor).
    send: (bundle, epoch) => daemon.sendSftpCred(bundle, 12000, epoch),
    epoch: () => daemon.currentEpoch(),
  });
  const sink = new schedulerIo.StatusSink(syncHub);
  const io = schedulerIo.makeSchedulerIo({
    listConfigured: () => { try { return storedConfig().filter((e) => e.enabled !== false); } catch { return []; } },
    snapshot: runStateSnapshot,
    fetchStandard: async () => {
      const origin = serverConfig.readServerOrigin(dir);
      const token = await resolveAccountToken();
      if (!origin || !token) { const e = new Error('not signed in'); e.reason = 'no-session'; throw e; }
      const res = await syncVaults.fetchStandardVaults({ serverOrigin: origin, sessionToken: token }, mainHttpJson);
      rememberVaultPasswordFlags(res && res.vaults); // keep the per-vault protection flags current for the mint gate
      return res;
    },
    remotePathForVault: syncConfig.remotePathForVault,
    secureFolder: async (folder) => {
      const r = await ensureFolderSecure(folder, folderSecureIo());
      if (r && r.ok) return r;
      // A folder made private at setup can be RE-SHARED later. A surviving explicit foreign grant or a deny
      // is recoverable by re-presenting the same make-private consent, so it reads as 'folder-problem'
      // (re-consent); anything else is a folder that cannot be secured at all -> 'folder-insecure' (re-pick).
      const reShared = r && (r.reason === 'acl-non-owner' || r.reason === 'acl-deny-present');
      return { ok: false, reason: reShared ? 'folder-problem' : 'folder-insecure' };
    },
    classify: (folder) => {
      const owner = entryByFolder(folder);
      const ctx = {
        home, userData: dir,
        refuseRoots: syncConfig.platformRefuseRoots(process.platform, process.env),
        existingFolders: storedConfig().filter((e) => !owner || e.vaultId !== owner.vaultId).map((e) => e.localFolder),
        caseInsensitive,
      };
      try { return syncConfig.classifyLocalTarget(resolveReal(folder), ctx); } catch { return { ok: false, reason: 'folder-rejected' }; }
    },
    credCache,
    daemon,
    confirmFirstUpload: (o) => confirmFirstUpload(o, entryFor(o.vaultId)),
    isAccountUsable: () => !!(lockState && lockState.isAccountUsable()),
    vaultHasPassword: (vaultId) => vaultRequiresPassword(vaultId), // route a persistent auth-failed here to needs-unlock
    hasAccount: () => { try { return !!(serverConfig.readServerOrigin(dir) && ((sessionBundle && sessionBundle.authToken) || (tokenStore.loadSession(safeStorage, dir) || {}).authToken)); } catch { return false; } },
    isOnline: isOnlineNow, // the one online source — shared with the status hub's glance (tickSync setOnline)
    onEvent: (vaultId, ev) => {
      // A deliberate "Sync now" press earns one completion answer. 'running'/'noop' are not terminal — the
      // press is still in progress or has joined an in-flight run, so keep waiting; any terminal outcome
      // resolves it. Mark it BEFORE sink.apply so the hub's must-act notification (fired synchronously inside
      // sink.apply) drops its redundant toast for the same event; the manual toast below is the one answer.
      // The auth-failed retry-once backstop emits an interim { phase:'paused', reason:'retrying' } and re-runs;
      // that interim is NOT the press's final answer — the retry's own outcome is. Exclude it here so the press
      // waits for the real result instead of being answered by the transient.
      const manualTerminal = ev && pendingManualSync.has(vaultId) && ['done', 'error', 'blocked', 'paused', 'skipped', 'refused'].includes(ev.phase)
        && !(ev.phase === 'paused' && ev.reason === 'retrying');
      if (manualTerminal) manualHookPending = vaultId;
      try {
        sink.apply(vaultId, ev);
        // Keep the run-state snapshot in step with the daemon's store after every terminal event, so a
        // Repair pressed right after a run never acts on a stale latch (a cheap local read).
        if (ev && ['done', 'error', 'blocked', 'noop'].includes(ev.phase)) void runStateSnapshot.refresh(configuredIds());
        if (manualTerminal) { pendingManualSync.delete(vaultId); notifyManualComplete(vaultId, ev); }
      } finally {
        manualHookPending = null; // the guarantee window is only this callback
      }
    },
  });
  syncScheduler = new SyncScheduler(io);
  // Authorise the helper's per-step credential requests (a resync mints one fresh single-use credential per
  // rclone process). Main holds the say: it mints ONLY for the vault whose run is in flight right now, and only
  // while the app is active for account-tier sync (not lock-paused) with a live account. The gate is the
  // account tier (isAccountUsable), NEVER the ZK unlocked state — Standard sync does not use the ZK key. The
  // helper's requested vaultId is CHECKED against the scheduler's in-flight vault, never trusted as an input;
  // the fresh credential is delivered on the existing sftp-cred path, and this returns only { ok, reason }.
  if (daemon) daemon.setCredProvider(async (vault) => {
    if (!syncScheduler || syncScheduler.current() !== vault) return { ok: false, reason: 'not-in-flight' };
    if (!(lockState && lockState.isAccountUsable())) return { ok: false, reason: 'paused-locked' };
    if (!io.hasAccount()) return { ok: false, reason: 'no-session' };
    return credCache.ensureSent(vault);
  });
  // The routine cadence. Unref'd so it never keeps the process alive; each tick is a cheap gated skip when
  // there is nothing to do. A first pass is kicked shortly after boot (once the window/session settle).
  if (syncTickTimer) clearInterval(syncTickTimer);
  syncTickTimer = setInterval(() => { void tickSync(); }, SYNC_TICK_MS);
  if (syncTickTimer.unref) syncTickTimer.unref();
}

function buildEnableIo() {
  const dir = app.getPath('userData');
  const home = app.getPath('home');
  // Windows and default macOS volumes are case-insensitive; fold case in containment checks so a
  // differently-cased path cannot slip past the overlap / system-root refusals.
  const caseInsensitive = process.platform === 'win32' || process.platform === 'darwin';
  return {
    listVaults: async () => {
      const origin = serverConfig.readServerOrigin(dir);
      const token = await resolveAccountToken();
      // Distinguish "not signed in" from a later network error so the copy can be specific.
      if (!origin || !token) { const e = new Error('not signed in'); e.reason = 'no-session'; throw e; }
      const { vaults, someExcluded } = await syncVaults.fetchStandardVaults({ serverOrigin: origin, sessionToken: token }, mainHttpJson);
      lastSomeExcluded = !!someExcluded; // a bare flag for the picker note; excluded vaults never leave main
      rememberVaultPasswordFlags(vaults); // the picker fetch also refreshes the protection flags for the mint gate
      return vaults;
    },
    pickVault: async (vaults) => {
      const note = lastSomeExcluded
        ? '\n\nSome of your vaults are not shown here — only standard vaults can be synced to a folder.'
        : '';
      const buttons = [...vaults.map((v) => v.vaultName), 'Cancel'];
      const res = await dialog.showMessageBox(mainWindow, {
        type: 'question', title: 'Set up sync', noLink: true,
        message: 'Which vault do you want to sync to this computer?',
        detail: 'Its files will be kept in a folder you choose.' + note,
        buttons, defaultId: 0, cancelId: buttons.length - 1,
      });
      return (res.response >= 0 && res.response < vaults.length) ? vaults[res.response] : null;
    },
    pickFolder: async () => {
      const res = await dialog.showOpenDialog(mainWindow, {
        title: 'Choose a folder to sync into',
        properties: ['openDirectory', 'createDirectory'],
      });
      return (res.canceled || !res.filePaths || !res.filePaths[0]) ? null : res.filePaths[0];
    },
    // Canonicalize casing on win32 via realpathSync.native so the containment checks see the real case.
    resolveReal: (p) => {
      const real = fs.realpathSync.native || fs.realpathSync;
      try { return real(p); } catch { try { return fs.realpathSync(p); } catch { return path.resolve(p); } }
    },
    classifyCtx: (excludeVaultId) => ({
      home,
      userData: dir,
      refuseRoots: syncConfig.platformRefuseRoots(process.platform, process.env),
      // Exclude the vault being (re)configured, so re-picking its OWN folder is not a false overlap.
      existingFolders: storedConfig().filter((e) => e.vaultId !== excludeVaultId).map((e) => e.localFolder),
      caseInsensitive,
    }),
    confirmCloud: async (folder) => {
      const service = enableCopy.cloudServiceName(folder);
      const res = await dialog.showMessageBox(mainWindow, {
        type: 'warning', title: 'Cloud storage folder', noLink: true,
        message: `This folder is inside ${service}`,
        detail: enableCopy.cloudWarnMessage(service),
        buttons: ['Choose another folder', 'Use it anyway'], defaultId: 0, cancelId: 0,
      });
      return res.response === 1;
    },
    // Report who, other than the owner, currently has access to the picked folder (win32). A read of the
    // ACL, classified into deliberate shares vs denies; anything else (POSIX, an unreadable ACL) reports
    // nothing shared, so the gate is skipped and the owner-only enforcement stays at run time.
    inspectFolderSharing: async (folder) => {
      if (process.platform !== 'win32') return { shares: [], denies: [] };
      const read = await runIcacls([String(folder)]);
      if (!read || read.code !== 0) return { shares: [], denies: [] };
      return classifyForeignAces(read.stdout, folderSecureIo().user, folder);
    },
    // The folder-privacy consent gate, shown only when the folder is shared. Its explicit "make it
    // private" is the sole trigger to strip access; declining picks another folder or cancels, stripping
    // nothing. The same dialog is re-presented on run-time drift (recoverSharedFolder).
    confirmMakePrivate: ({ folder }) => confirmMakePrivateDialog(folder),
    // Make the folder owner-only AFTER the person consented above. Never reached without that consent.
    makePrivate: (folder) => recoverOwnerOnly(folder, folderSecureIo()),
    isNonEmptyDir: (p) => { try { return fs.readdirSync(p).length > 0; } catch { return false; } },
    confirmConsent: async ({ vaultId, vaultName, folder, nonEmpty }) => {
      let detail = enableCopy.consentMessage(vaultName, folder, { nonEmpty });
      // Re-targeting an already-configured vault: say what happens to the old folder, never silently orphan it.
      const prior = storedConfig().find((e) => e.vaultId === vaultId);
      if (prior && prior.localFolder && prior.localFolder !== folder) {
        detail += ` The previous folder (${prior.localFolder}) will no longer sync; the files already there are left as they are.`;
      }
      // Windows does not enforce owner-only folder permissions, so a folder outside the user profile can
      // be readable by other local accounts. State that honestly at the consent for such a target.
      if (process.platform === 'win32' && !syncConfig.isWithin(folder, home, caseInsensitive)) {
        detail += ' On Windows, a folder outside your user profile can be read by other accounts on this PC — a folder inside your profile keeps these copies private.';
      }
      const res = await dialog.showMessageBox(mainWindow, {
        type: 'question', title: 'Sync this vault?', noLink: true,
        message: `Sync ${vaultName} to this computer?`,
        detail,
        // Cancel is the Enter-default: a plaintext-on-disk + upload decision must not be confirmed by a stray Enter.
        buttons: ['Cancel', 'Sync this vault'], defaultId: 0, cancelId: 0,
      });
      return res.response === 1;
    },
    ensureFolder: (p) => {
      // The folder receives decrypted, readable copies, so create it owner-only. mode/chmod are
      // enforced on POSIX; on Windows they are effectively no-ops (the folder inherits its ACL), which
      // is why the consent copy states the win32 asymmetry above.
      fs.mkdirSync(p, { recursive: true, mode: 0o700 });
      try { fs.chmodSync(p, 0o700); } catch { /* honoured where the platform supports it */ }
    },
    onRefuse: async (reason) => {
      await dialog.showMessageBox(mainWindow, {
        type: 'warning', title: "That folder can't be used", noLink: true,
        message: "That folder can't be used for sync", detail: enableCopy.refuseMessage(reason),
        buttons: ['OK'],
      });
    },
    save: (entry) => {
      const list = syncConfig.upsertEntry(storedConfig(), entry);
      syncConfigStore.saveConfig(safeStorage, dir, list); // throws CONFIG_UNREADABLE rather than clobber an unreadable file
    },
  };
}

async function setupSyncForVault() {
  if (!syncHub) return { enabled: false, reason: 'unavailable' };
  // Single-flight: never open a second enable/stop flow while one is in progress (the overlap check is
  // read-then-write, so two concurrent flows could both pass it and the second save drop the first).
  if (syncFlowBusy) return { enabled: false, reason: 'busy' };
  // Claim the single-flight guard BEFORE anything that opens a dialog (including the unreadable-config
  // pre-check below), so a second trigger arriving during that dialog is suppressed as busy, not stacked.
  syncFlowBusy = true;
  try {
    // Never drag the person through the pickers over an unreadable config — a save would refuse anyway.
    const cfgState = syncConfigStore.readConfigState(safeStorage, app.getPath('userData'));
    if (syncConfigStore.isUnreadable(cfgState.status)) {
      try {
        await dialog.showMessageBox(mainWindow, {
          type: 'error', title: 'Set up sync', noLink: true,
          message: 'Your sync settings could not be read',
          detail: 'DockVault will not overwrite them. This usually clears up after unlocking your login keychain and reopening DockVault.',
          buttons: ['OK'],
        });
      } catch { /* best-effort */ }
      return { enabled: false, reason: 'config-unreadable' };
    }
    const r = await syncEnable.runEnableFlow(buildEnableIo());
    if (r && r.enabled) {
      try { syncHub.setVaults(storedConfig().map((e) => e.vaultId)); } catch { /* config unreadable */ }
      refreshTray();
      // Kick the first sync right away instead of leaving the freshly-enabled vault at "set up - not running
      // yet" until the next routine tick. Via tickSync so the run-state snapshot is REFRESHED with the new id
      // list FIRST — otherwise the just-enabled id is uncovered and would read never-run, auto-resyncing a
      // re-enabled but still-latched vault instead of blocking it. The dispatch stays gated as usual.
      void tickSync();
    } else if (r && r.reason === 'no-standard-vaults') {
      try {
        await dialog.showMessageBox(mainWindow, {
          type: 'info', title: 'Set up sync', noLink: true,
          message: 'No vaults can be synced to this computer yet',
          detail: 'Syncing to a folder is available for standard vaults. Open DockVault to create one.',
          buttons: ['OK'],
        });
      } catch { /* best-effort */ }
    } else if (r && r.reason === 'bad-vault-name') {
      try {
        await dialog.showMessageBox(mainWindow, {
          type: 'warning', title: 'Set up sync', noLink: true,
          message: "That vault can't be synced to a folder",
          detail: "Its name contains characters that can't be used as a folder name. Rename the vault, then try again.",
          buttons: ['OK'],
        });
      } catch { /* best-effort */ }
    }
    return r;
  } catch (e) {
    const noSession = !!(e && e.reason === 'no-session');
    try {
      await dialog.showMessageBox(mainWindow, {
        type: noSession ? 'info' : 'error', title: 'Set up sync', noLink: true,
        message: noSession ? 'Sign in first' : 'Could not set up sync',
        detail: noSession
          ? 'Open DockVault and sign in to your account, then set up sync from the tray.'
          : 'DockVault could not reach the server. Check your connection and try again.',
        buttons: ['OK'],
      });
    } catch { /* best-effort */ }
    return { enabled: false, reason: noSession ? 'no-session' : 'error' };
  } finally {
    syncFlowBusy = false;
  }
}

async function stopSyncing(vaultId, vaultName) {
  if (syncFlowBusy) return; // single-flight: don't race a setup or another stop
  syncFlowBusy = true;
  try {
    const res = await dialog.showMessageBox(mainWindow, {
      type: 'question', title: 'Stop syncing', noLink: true,
      message: `Stop syncing ${vaultName}?`,
      detail: 'DockVault will stop syncing this vault. The files already copied to your folder are left as they are.',
      buttons: ['Cancel', 'Stop syncing'], defaultId: 0, cancelId: 0,
    });
    if (res.response !== 1) return;
    const dir = app.getPath('userData');
    try {
      syncConfigStore.saveConfig(safeStorage, dir, syncConfig.removeEntry(storedConfig(), vaultId));
    } catch {
      try { await dialog.showMessageBox(mainWindow, { type: 'error', title: 'Stop syncing', noLink: true, message: 'Your sync settings could not be updated', detail: 'DockVault could not read your current sync settings, so it did not change them. Try again after unlocking your login keychain and reopening DockVault.', buttons: ['OK'] }); } catch { /* best-effort */ }
      return;
    }
    try { if (syncHub) syncHub.setVaults(storedConfig().map((e) => e.vaultId)); } catch { /* none */ }
    refreshTray();
  } finally {
    syncFlowBusy = false;
  }
}

// A one-time, non-blocking nudge that sync exists — shown once, on the first unlock, and ONLY when
// the account actually has at least one vault that can be synced this way. A user with nothing
// eligible is never teased about a capability they cannot use. Fail-quiet: if eligibility cannot be
// determined (not signed in yet, or the list cannot be fetched) nothing is shown and nothing is
// marked, so a later unlock can try again — the always-present tray entry covers discovery meanwhile.
async function maybeOfferSyncSetup() {
  if (!syncHub || SMOKE) return;
  if (readState().syncOfferShown) return;
  if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
  let eligible = 0;
  try {
    const dir = app.getPath('userData');
    const origin = serverConfig.readServerOrigin(dir);
    const token = await resolveAccountToken(); // live token, not the stale boot snapshot
    if (!origin || !token) return; // not signed in yet — fail-quiet, retry on a later unlock
    const { vaults } = await syncVaults.fetchStandardVaults({ serverOrigin: origin, sessionToken: token }, mainHttpJson);
    eligible = vaults.length;
  } catch { return; } // any error — show nothing, mark nothing, try again later
  writeState({ syncOfferShown: true }); // eligibility is known now: this is the one-and-only attempt
  if (eligible < 1) return; // nothing to sync — don't nudge; the tray entry still offers it if that changes
  try {
    const n = new Notification({ title: 'DockVault', body: 'You can sync a vault to a folder on this computer — set it up any time from the tray menu.' });
    n.on('click', () => { void setupSyncForVault(); });
    n.show();
  } catch { /* best-effort */ }
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

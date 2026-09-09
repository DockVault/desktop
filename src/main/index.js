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
const syncStatusModel = require('./sync-status-model');
const vaultSpace = require('./vault-space');
const trayPresentation = require('./tray-presentation');
const rcloneBundle = require('./rclone-bundle');
const { APP_ID } = require('./app-identity');
const loginItemMod = require('./login-item');
const serverProbe = require('./server-probe');
const serverSetupMod = require('./server-setup');
const syncEnable = require('./sync-enable');
// Every helper description (tooltip, notification, dialog) speaks as an installed app when it is one.
trayPresentation.setPackaged(app.isPackaged);
// The DOCKVAULT_SERVER variable is honoured only by development runs; an installed app uses its saved setting alone.
serverConfig.setEnvOverrideAllowed(!app.isPackaged);
const syncVaults = require('./sync-vaults');
const syncConfig = require('./sync-config');
const folderMarker = require('./folder-marker');
const folderIdentity = require('./folder-identity');
const syncConfigStore = require('./sync-config-store');
const enableCopy = require('./enable-copy');
const { mintSftpAccess } = require('./sftp-cred');
const { CredCache } = require('./cred-cache');
const deviceSecretStore = require('./device-secret-store');
const deviceRegister = require('./device-register');
const deviceGrant = require('./device-grant');
const deviceGrantStore = require('./device-grant-store');
const devicePending = require('./device-pending-grant');
const { runDeviceSetup } = require('./device-enable');
const { resumePendingGrants, markerActionForRunReason, runSetupAgainGrants } = require('./device-grant-resume');
const { decideMigration } = require('./device-migrate');
const { createSyncWizard } = require('./sync-wizard');
const { createManageView } = require('./manage-view');
const { createTroubleshoot } = require('./troubleshoot');
const { verifySetup } = require('./setup-verify');
const { deviceRemotePath } = require('./mint-path');
const { probeSftp } = require('./sftp-probe');
const { mintDeviceSftpAccess } = require('./device-mint');
const sftpEndpoint = require('./sftp-endpoint');
const { MintPathSelector, identityEndedBy } = require('./mint-path');
const { refreshDeviceSecret, isRotationDue, identityIsStaleAfter, reconcileRotationMarker } = require('./device-refresh');
const { RunStateSnapshot } = require('./run-state-snapshot');
const { SyncScheduler } = require('./sync-scheduler');
const schedulerIo = require('./scheduler-io');
const { manualCompletionBody, turnedAwayBody } = require('./manual-sync-copy');
const { ensureFolderSecure, recoverOwnerOnly, classifyForeignAces } = require('./folder-secure');

const STATIC_ROOT = path.resolve(__dirname, '..', '..', 'vendor', 'vault', 'static');
const PRELOAD = path.join(__dirname, '..', 'preload', 'index.js');
// The shell's own pages, served over the app scheme (a packaged app keeps them inside its archive,
// which the file protocol cannot read). Names under src/renderer; see scheme.js SHELL_PATH.
const FAIL_PAGE = 'selftest-fail.html';
const SETUP_PAGE = 'server-setup.html'; // the first thing an installed app shows
const WIZARD_PAGE = 'sync-wizard.html'; // the in-app "Set up sync" window
const MANAGE_PAGE = 'manage.html';      // the in-app "Computers" window
const TROUBLESHOOT_PAGE = 'troubleshoot.html'; // the in-app Troubleshoot window
// Forgetting this computer on the OLD server when the person switches servers (revoke the device by id under
// the old session when reachable, then drop the device secret). The device registration lives in its own
// modules, which wire this hook; until then it is a documented no-op and the rest of the forget path runs.
let deviceForget = async (/* { origin, sessionToken } */) => {};
const APP_ICON = path.join(__dirname, '..', '..', 'build', 'icon.png'); // the DockVault window + tray icon
const SMOKE = process.env.DOCKVAULT_SMOKE === '1';
// A second in-module self-test flag, modelled on SMOKE above: DOCKVAULT_TRAY_SELFTEST=1 boots the app, forces
// the device-sync tray assembly into one drawn menu and drives its click handlers, then writes
// .local/tray-selftest.json and exits. It exists so the two SILENT merge modes this file has hit — a
// migration/pending/reset assembly dropped from the drawn menu (render), and a click bound to a function the
// merge deleted (a ReferenceError) — are caught by an autonomous check, not only a person at the OS tray.
// Honoured ONLY in an unpackaged run or an explicitly-overridden user-data dir (asserted where it runs), never
// a real profile. See finishTraySelftestIfNeeded at the end of this file.
const TRAY_SELFTEST = process.env.DOCKVAULT_TRAY_SELFTEST === '1';
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
// Whether the UI carried an account session at the LAST successful capture, so a sign-in can be told apart from
// the steady state of being signed in. null until the first successful read; a read that throws leaves it alone.
let hadAccountSession = null;
let captureTimer = null;
let restored = false; // the session is seeded once per run (on the first window); tray reopens keep it
let daemon = null;    // the supervised background sync daemon (a forked utility child)
let rcloneCfg = null; // the pinned rclone config { bin, version, sha256 }; `version` is the pin shown for a helper version-mismatch
let lockState = null; // the single source of truth for lock state (main-owned)
let autoLock = null;  // the automatic lock triggers (idle timer + OS suspend/screen-lock)
let syncHub = null;   // the main-owned computed sync status (feeds the tray, notifications, channel)
let manageReasonIo = null; // the Computers view's io, kept for composing the live card sentence (built lazily)
let syncScheduler = null;
let mintPath = null;      // per-run credential-path choice (device identity vs account session), see mint-path.js
// The scheduled rotation of this computer's sync identity (device-refresh.js): an hourly check that rotates once
// the stored identity is old enough. Single-flight, online-only, never per mint.
const DEVICE_REFRESH_TICK_MS = 60 * 60 * 1000;
let deviceRefreshTimer = null;
let deviceRefreshBusy = false;
// Set when a rotation's answer was lost (the refresh refused the held secret as retired, or the server rotated
// but the new secret could not be kept here): the identity is STALE — presenting it past the server's grace
// would suspend this computer, so the mint path refuses with the server's own literal until the computer is set
// up again. The durable record is the store's stale MARKER (markDeviceSecretStale), read back with the identity
// after a restart; this flag is the in-process fallback for a marker that could not be written.
let deviceIdentityStale = false;   // the background scheduler (decides when/whether each vault syncs)
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
// generic Electron identity and shows its icon. It is the application id the installer stamps on the
// shortcuts, so the taskbar groups the running window with its shortcut and attributes notifications
// to DockVault. (This is separate from app.name, which decides where the app's data lives.)
if (process.platform === 'win32') app.setAppUserModelId(APP_ID);

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

// Standard-vault sync uses a pinned rclone binary that the installer bundles beside the app archive;
// its pinned version + SHA-256 come from the manifest inside the integrity-checked archive (see
// rclone-bundle.js for the rules, including the development-only environment override). Null means the
// manifest has no entry for this platform: the daemon then offers no standard sync — never fatal.
function resolveRcloneConfig() {
  return rcloneBundle.resolveBundledRclone({
    isPackaged: app.isPackaged, resourcesPath: process.resourcesPath, platform: process.platform, arch: process.arch, env: process.env,
  });
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
  // An installed app's first launch registers itself to start at login and says so; see login-item.js
  // for the rule (never unasked once the person has chosen, never from a development run).
  if (!SMOKE) maybeRegisterLoginItem();
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
      // sync is still paused. The two tiers stay separate on the hub path too. The status model composes this
      // lock per vault by credential path (a device vault keeps syncing on its own identity and reads its real
      // state; an account vault reads paused-locked instead of a stale green; the glance leads with "Locked" and
      // appends the sync truth), so the raw appLocked is fed — the honesty is in the model, not a suppressed signal.
      if (syncHub) { syncHub.setLocked(lockState.snapshot().appLocked); syncHub.setDeviceLive(deviceIdentityLive()); }
      // #5 clear-on-lock: a lock pauses sync dispatch, so drop the account-tier SFTP credential as hygiene
      // — the main-side cache AND the helper's prepared config — re-minted from the still-live session on
      // unlock/resume. (The account session itself persists across a lock; only the derived credential is dropped.)
      if (s === 'locked') { if (credCache) credCache.clear(); if (daemon) void daemon.clearSftpCred(); }
      // An account-tier resume ('account-active') re-enables dispatch: nudge setup + kick a sync now the credential
      // can re-mint. Keyed on the account-tier signal, never the zero-knowledge 'unlocked' event, so the sync path
      // stays independent of the zero-knowledge key. 'account-active' asserts NO zero-knowledge key; the lock UI is
      // untouched.
      // Note what this resume does NOT do: it lifts the holds and opens the endpoint gate, but it leaves the
      // per-vault refusal back-off standing. Returning to the computer says nothing about a server that is
      // actively turning this computer's credentials away, and clearing the window here re-minted against that
      // still-refusing door on every idle resume — the credential flood, re-opened by walking away for a while.
      if (s === 'account-active') { deviceUnreadableStreak = 0; if (syncScheduler) syncScheduler.releaseHolds(); void maybeOfferSyncSetup(); void maybeOfferDeviceMigration(); void tickSync(); } // unlock resets the escape-hatch streak: a lock episode never counts toward the reset offer
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
      // On OS wake, kick a sync so a device-path vault (which keeps syncing under the lock) catches up after the
      // freeze. It is gated like any tick — an account-path vault stays paused under the still-held lock, and the
      // ZK key is not re-derived — so it resumes sync only, never the account tier or the key.
      onResume: () => { void tickSync(); },
    });
    autoLock.start();
    // A first sync pass shortly after boot when the app starts active for account-tier sync: the resume hook
    // only kicks on a lock->resume TRANSITION, so a cold start (appLocked defaults false) would otherwise sit
    // until the routine interval. Deferred a moment so the window and account session settle; gated like any
    // tick (the dispatch still re-checks the live account session, so no run starts before sign-in completes).
    // ...and the migration offer on the same cold-start branch: its probe otherwise fills the door only on a
    // lock->unlock transition, so a desktop that boots signed-in and unlocked (or with auto-lock off) would
    // show no door until it happened to lock and unlock once — the one launch where the offer matters most.
    if (lockState.isAccountUsable()) { const t = setTimeout(() => { void tickSync(); void maybeOfferDeviceMigration(); }, BOOT_SYNC_KICK_MS); if (t.unref) t.unref(); }
  }
  await finishSmokeIfNeeded();
  // The tray self-test lands HERE — the END of boot — not beside setupTray(): syncHub is not assigned until
  // later in boot, and refreshTray's pre-hub early return draws buildTrayMenu([], null), which is itself the
  // failure mode (a) exists to catch (a false red). By here syncHub and the tray both exist.
  await finishTraySelftestIfNeeded();
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
  // The server setup screen's two intents. Main owns the route (/health), the normalisation, and the
  // write; the renderer sends what was typed and gets back a kind and a host, never a file's contents.
  // Only the shell's own setup page may ask: the web interface the server supplies runs on the same
  // origin with the same preload, and must never be able to re-point the app.
  // Three checks, all required: the sender is the main window's page, the frame is that page's main
  // frame (not something framed inside it), and its URL is exactly the setup page.
  const fromSetupPage = (e) => serverSetupMod.isTrustedSetupSender(e, {
    webContents: (mainWindow && !mainWindow.isDestroyed()) ? mainWindow.webContents : null,
    appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + SETUP_PAGE,
  });
  ipcMain.handle('dockvault:server.state', (e) => (fromSetupPage(e) ? serverScreenState() : null));
  ipcMain.handle('dockvault:server.check', (e, args) => (fromSetupPage(e) ? checkServer(args) : null));
  ipcMain.handle('dockvault:server.connect', (e, args) => (fromSetupPage(e) ? connectServer(args) : { kind: 'refused' }));
  // The sync setup wizard's intents: the current question, an answer to it, and a close. Only the shell's own
  // wizard page, in its own window, may ask — the same three-leg sender check, bound to that window. The page
  // never names a folder or a config: it answers questions main posed (sync-wizard.js).
  const fromWizardPage = (e) => serverSetupMod.isTrustedSetupSender(e, {
    webContents: (wizardWindow && !wizardWindow.isDestroyed()) ? wizardWindow.webContents : null,
    appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + WIZARD_PAGE,
  });
  ipcMain.handle('dockvault:wizard.state', (e) => (fromWizardPage(e) ? wizardState() : null));
  ipcMain.handle('dockvault:wizard.answer', (e, args) => (fromWizardPage(e) ? wizardAnswer(args) : false));
  ipcMain.handle('dockvault:wizard.close', (e) => { if (fromWizardPage(e)) closeSyncWizard(); return null; });
  ipcMain.handle('dockvault:wizard.open-app', (e) => { if (fromWizardPage(e)) void showOrCreateWindow(); return null; });
  // The Computers view's intents, gated to its own window and page the same way.
  const fromManagePage = (e) => serverSetupMod.isTrustedSetupSender(e, {
    webContents: (manageWindow && !manageWindow.isDestroyed()) ? manageWindow.webContents : null,
    appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + MANAGE_PAGE,
  });
  ipcMain.handle('dockvault:manage.model', (e) => (fromManagePage(e) ? manageModel() : null));
  ipcMain.handle('dockvault:manage.act', (e, args) => (fromManagePage(e) ? manageAct(args) : { ok: false, reason: 'refused' }));
  ipcMain.handle('dockvault:manage.open-setup', (e) => { if (fromManagePage(e)) void openSyncWizard(); return null; });
  ipcMain.handle('dockvault:manage.close', (e) => { if (fromManagePage(e)) closeManageView(); return null; });
  // The Troubleshoot view's intents, gated to its own window and page. A probe reaches only the saved server
  // setting (main reads it; the page names a check, never an address), and nothing here writes.
  const fromTroubleshootPage = (e) => serverSetupMod.isTrustedSetupSender(e, {
    webContents: (troubleshootWindow && !troubleshootWindow.isDestroyed()) ? troubleshootWindow.webContents : null,
    appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + TROUBLESHOOT_PAGE,
  });
  ipcMain.handle('dockvault:troubleshoot.checks', (e) => (fromTroubleshootPage(e) && troubleshootInstance ? troubleshootInstance.checks() : []));
  ipcMain.handle('dockvault:troubleshoot.describe', (e, args) => (fromTroubleshootPage(e) && troubleshootInstance ? troubleshootInstance.describe(args && args.id) : null));
  ipcMain.handle('dockvault:troubleshoot.probe', (e, args) => (fromTroubleshootPage(e) && troubleshootInstance ? troubleshootInstance.probe(args && args.id) : null));
  ipcMain.handle('dockvault:troubleshoot.open-server-setup', (e) => { if (fromTroubleshootPage(e)) void openServerSetupFromTroubleshoot(); return null; });
  ipcMain.handle('dockvault:troubleshoot.close', (e) => { if (fromTroubleshootPage(e)) closeTroubleshoot(); return null; });
  ipcMain.handle('dockvault:sync.status', () => (syncHub
    ? syncStatusModel.publicStatus(syncHub.current())
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
    const signedIn = !!(bundle && bundle.authToken);
    // A genuine sign-IN — there was no account session a moment ago and now there is. Where the door turned the
    // CREDENTIAL away, it was answering about one minted from a session that has since ended, so it says nothing
    // about the one being presented now: forget those windows and let the next tick actually try. This is the
    // "signing in lets it try at once" our own status sentence promises; without it that sentence was simply
    // untrue, and a person told to sign in would watch nothing happen.
    //
    // Only the credential refusals, though — a server that is limiting attempts is left alone, because a fresh
    // sign-in does not change its mind and the retry would just spend another credential against the limit
    // doing the refusing (which is, word for word, what we tell the person in that state). And only the EDGE
    // acts: the steady state of being signed in changes nothing, so a poll every half minute cannot walk
    // credentials out through it. A read that failed leaves `hadAccountSession` untouched (the catch below), so
    // a window in which the page could not be asked never reads as a sign-out and then a sign-in.
    if (signedIn && hadAccountSession === false && syncScheduler) syncScheduler.clearCredentialRefusals();
    hadAccountSession = signedIn;
    if (signedIn) tokenStore.persistSession(safeStorage, dir, bundle);
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
// WHEN a vault was last unlocked, and nothing else — no password crosses this boundary. Used to notice that
// someone has done the very thing the app asked them to do, since there is no event for it: the renderer just
// holds an unlock, and main pulls the proof only when it is about to spend it. Asking for the instant instead
// keeps a secret out of a question that is only about a clock.
const UNLOCK_STAMP_TIMEOUT_MS = 1500; // how long the page gets to answer "when was this unlocked"
async function pullVaultUnlockStamp(vaultId) {
  const win = mainWindow;
  if (!win || win.isDestroyed() || typeof vaultId !== 'string' || !vaultId) return 0;
  try {
    // Bounded, because this now runs AHEAD of the sync pass: a page that is busy or wedged must not be able
    // to hold up the scheduler behind it. A read that does not answer in time is simply "no unlock seen".
    const ts = await Promise.race([
      win.webContents.executeJavaScript(
      `(() => { try {`
      + ` if (typeof state === 'undefined' || !state) return 0;`
      + ` const want = ${JSON.stringify(vaultId)};`
      + ` if (!state.currentVaultId || String(state.currentVaultId) !== String(want)) return 0;`
      + ` if (typeof state.vaultPassword !== 'string' || state.vaultPassword.length === 0) return 0;`
      + ` return typeof state.vaultPasswordTimestamp === 'number' ? state.vaultPasswordTimestamp : 0;`
      + ` } catch (e) { return 0; } })()`, true),
      new Promise((resolve) => { const t = setTimeout(() => resolve(0), UNLOCK_STAMP_TIMEOUT_MS); if (t.unref) t.unref(); }),
    ]);
    return typeof ts === 'number' && Number.isFinite(ts) ? ts : 0;
  } catch { return 0; } // a failed read is simply "no unlock seen", never a reason to stop waiting
}

// A vault waiting on its password stops waiting once that password has been given. The app tells people so in
// as many words, and until this there was no path from doing it to the wait ending: a person did exactly what
// the status asked and watched nothing happen for up to an hour.
async function clearWaitsAnsweredByAnUnlock() {
  if (!syncScheduler || typeof syncScheduler.vaultsAwaitingPassword !== 'function') return;
  let waiting = [];
  try { waiting = syncScheduler.vaultsAwaitingPassword(); } catch { return; }
  for (const { vaultId, since } of waiting) {
    const stamp = await pullVaultUnlockStamp(vaultId);
    // Strictly newer than the refusal: the unlock that was already in hand when the door refused is the one
    // that was refused, and re-offering it would just spend another credential on the same answer.
    if (stamp > since) syncScheduler.clearVaultPasswordRefusals([vaultId]);
  }
}

async function pullVaultUnlock(vaultId) {
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
  return { password: pw, stamp: ts }; // stamp = the unlock instant, so the re-proof gate retries only on a NEWER unlock
}

// The vault password for a device mint: the string form of the unlock above, or null. The device-grant resume
// reads the {password, stamp} form (pullVaultUnlock) directly, so it can refuse to re-prove with an unlock that
// already failed and wait for a fresh one.
async function pullVaultPasswordForMint(vaultId) {
  const u = await pullVaultUnlock(vaultId);
  return u ? u.password : null;
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

// Three-state history of a vault's device grant — the SINGLE source both grant-history readers share, so the
// resume sweep and the tray reminder can never drift into treating an unreadable record differently by
// accident. getGrantMeta throws GRANT_META_UNREADABLE on a transiently-unreadable store (a locked keychain, a
// torn blob), which is DISTINCT from a genuine null (never granted). Collapsing "unreadable" into "never
// granted" is the fail-open we must not have: it would let the resume re-grant — and the server reactivate —
// a grant the owner revoked. So an unreadable read is its OWN answer, and each caller handles it deliberately:
//   'granted'     a record exists → a re-proof (the resume runs the revoked-grant guard);
//   'first-setup' no record → a first setup (nothing to reactivate);
//   'unreadable'  the record could not be read right now → the resume DEFERS (leave the marker, retry), and
//                 the tray shows the neutral first-setup wording — NEVER the "your password changed" line.
function deviceGrantHistory(dir, id) {
  try { return deviceGrantStore.getGrantMeta(safeStorage, dir, id) ? 'granted' : 'first-setup'; }
  catch { return 'unreadable'; } // locked keychain / torn blob — never conflate with "never granted"
}

// The last device-sync support answer for the CURRENT server, cached from the migration probe so the tray door
// can be derived on every refresh without a network call. Keyed by origin so a server switch never reads a stale
// 'ok'/'too-old'; null until the first probe (the door simply waits, like an unprobed server).
let deviceMigrateSupport = null; // { origin, reason } | null

// A short-lived cache of the computed migration view. refreshTray runs on every hub status change — several
// times a second during a sync — while the door's inputs (support, identity, records, config) change only at a
// handful of events, so recomputing per tick is waste. The view is served from cache within a small window and
// force-recomputed the moment a door-changing event calls invalidateMigrationView (a fresh probe, a migration,
// a reset, a completed resume grant).
let _migrationView = null;
let _migrationViewAt = 0;
let _migrationViewOrigin = null;
const MIGRATION_VIEW_TTL_MS = 2000;
function invalidateMigrationView() { _migrationView = null; }

// The device identity status for the DOOR, from NON-SECRET reads only: readIdentityMeta decrypts the blob but
// never surfaces the secret (so the secret is not read into the menu-drawing path — the read-at-use rule), and
// the rotating marker flags the recheck state. A blob that will not read is treated as 'absent' for the door: a
// transient-unreadable click is a harmless account-only outcome, and a persistently-unreadable identity rides
// the escape hatch, not this door.
function migrationDeviceStatus(dir, origin) {
  try { if (deviceSecretStore.hasRotatingMarker(dir)) return 'rechecking'; } catch { /* fall through */ }
  let meta = null;
  try { meta = deviceSecretStore.readIdentityMeta(safeStorage, dir); } catch { meta = null; }
  if (!meta) return 'absent';
  return deviceSecretStore.sameOrigin(meta.serverOrigin, origin) ? 'ok' : 'absent-for-this-server';
}

// The existing-setup migration view: is the "set this computer up to sync on its own" door (or the honest switch
// line, or the too-old note) applicable right now, and which configured vaults would move over. Assembled from
// LOCAL, NON-SECRET reads — the cached support (this origin only), the identity status (no secret decrypted into
// this path), and each configured vault's three-state grant record from ONE readGrantMeta map (never a decrypt
// per vault). Best-effort + throttled: any read failure yields no door, and the result is cached for a short
// window so a busy refresh loop does not recompute it every tick.
function computeMigration(dir) {
  const origin = serverConfig.readServerOrigin(dir);
  const now = Date.now();
  if (_migrationView && _migrationViewOrigin === origin && (now - _migrationViewAt) < MIGRATION_VIEW_TTL_MS) return _migrationView;
  const support = (deviceMigrateSupport && deviceMigrateSupport.origin === origin) ? deviceMigrateSupport.reason : null;
  const deviceStatus = migrationDeviceStatus(dir, origin);
  // One grant-record read for the whole compute: an unreadable store makes every vault 'unreadable' (excluded
  // from the offer), an own-key is 'granted' (already migrated), anything else 'first-setup' (still to move) —
  // the store's three-state from a single map, never flattened and never a decrypt per vault.
  let recordFor;
  try {
    const gm = deviceGrantStore.readGrantMeta(safeStorage, dir);
    recordFor = deviceGrantStore.isUnreadable(gm.status)
      ? () => 'unreadable'
      : (id) => (Object.prototype.hasOwnProperty.call(gm.meta, id) ? 'granted' : 'first-setup');
  } catch { recordFor = () => 'unreadable'; }
  let configured = [];
  try { configured = storedConfig().map((e) => ({ vaultId: e.vaultId, vaultName: e.vaultName, record: recordFor(e.vaultId) })); } catch { configured = []; }
  let offeredOrigin = null;
  try { offeredOrigin = readState().deviceMigrationOfferOrigin || null; } catch { offeredOrigin = null; }
  const view = decideMigration({ support, deviceStatus, configured, offeredOrigin, currentOrigin: origin });
  _migrationView = view; _migrationViewAt = now; _migrationViewOrigin = origin;
  return view;
}

// The ONE owner of the tray glance and menu: it composes both from the current computed sync status
// and the lock phase, so lock and sync never fight over the tooltip. Called on every status change
// and on every lock-phase change.
// The pending re-render for a live wait (see refreshTray). One timer at a time, cleared when nothing waits.
let waitRefreshTimer = null;
const WAIT_REFRESH_MS = 30 * 1000;
function scheduleWaitRefresh(model) {
  if (waitRefreshTimer) { clearTimeout(waitRefreshTimer); waitRefreshTimer = null; }
  const waits = [model && model.retryAt, ...((model && model.vaults) || []).map((v) => v.retryAt)]
    .filter((t) => typeof t === 'number' && Number.isFinite(t) && t > Date.now());
  if (!waits.length) return;
  // Whichever comes first: the next coarse tick, or the moment the earliest wait lapses.
  const due = Math.max(1000, Math.min(WAIT_REFRESH_MS, Math.min(...waits) - Date.now() + 500));
  waitRefreshTimer = setTimeout(() => { waitRefreshTimer = null; refreshTray(); }, due);
  if (waitRefreshTimer.unref) waitRefreshTimer.unref();
}

function refreshTray() {
  if (!tray) return;
  try {
    const server = serverConfigState();
    if (!syncHub) { tray.setToolTip(server.origin ? 'DockVault' : 'DockVault — Not connected'); tray.setContextMenu(buildTrayMenu([], null)); return; }
    const model = syncHub.current();
    // The lock REASON (only while the account tier is actually paused) so the glance can tell a sleep-woken
    // desktop — unlocked but paused until Resume — from a plain screen lock, instead of a bare "Locked".
    const lockReason = (() => { try { const s = lockState && lockState.snapshot(); return s && s.appLocked ? s.reason : null; } catch { return null; } })();
    tray.setToolTip(trayPresentation.tooltip(model, effectiveLockPhase(), rcloneCfg && rcloneCfg.version, { lockReason, server, now: Date.now() }));
    // A wait that is being counted down has to be RE-rendered, or it is not a countdown: the tooltip and the
    // menu labels are strings fixed at build time, and the hub only emits when the picture changes — so a
    // "retrying in about 40 minutes" written once would still say forty minutes thirty-nine minutes later.
    // While any vault is waiting, re-render on a coarse tick (and once more just after the wait lapses, which
    // is when the sentence should stop mentioning it). Idle otherwise: no timer exists when nothing is waiting.
    scheduleWaitRefresh(model);
    // Map each configured vault's id → its name so must-act labels read the vault's NAME, not its id (the
    // model is keyed by id). A vault missing from the config falls back to its id inside mustActItems.
    let nameById = {};
    try { for (const e of storedConfig()) if (e && e.vaultId) nameById[e.vaultId] = e.vaultName; } catch { nameById = {}; }
    const mustAct = trayPresentation.mustActItems(model, nameById, { now: Date.now() });
    // Append the calm "finish setting up on this computer" reminder for any vault whose device grant is
    // pending — only while a device identity is live (else the resume can't complete it), and never for a
    // vault that already has a real must-act line above it. The auto-resume finishes it on the next open;
    // this is just the visible reminder, so it is best-effort.
    let items = mustAct;
    try {
      const dir = app.getPath('userData');
      const pend = deviceIdentityLive() ? devicePending.listPending(safeStorage, dir) : [];
      if (pend.length) {
        const shown = new Set(mustAct.map((it) => it.vault).filter(Boolean));
        const pendingItems = trayPresentation.pendingSetupItems(pend, {
          nameById,
          // Wording only. Only a vault KNOWN to have been granted before earns the "open with its new password"
          // re-proof line; a first setup AND an unreadable record both take the neutral "finish setting it up"
          // wording — an unreadable keychain must never surface an alarming "your password changed" line, and
          // this cosmetic read must not throw (the menu still has to render).
          wasGranted: (id) => deviceGrantHistory(dir, id) === 'granted',
          alreadyShown: (id) => shown.has(id),
        });
        if (pendingItems.length) items = [...mustAct, ...pendingItems];
      }
    } catch { /* the reminder is best-effort; the resume still completes a deferred setup on open */ }
    // Escape hatch: once the identity has been unreadable long enough (the streak crossed the threshold), add
    // the one-time reset offer beneath everything else — the calm paused glance has already had its chances.
    if (deviceUnreadableStreak >= DEVICE_UNREADABLE_RESET_THRESHOLD) items = [...items, trayPresentation.deviceResetItem()];
    let migration = null;
    try { migration = computeMigration(app.getPath('userData')); } catch { migration = null; } // best-effort; the door is never load-bearing
    tray.setContextMenu(buildTrayMenu(items, model, migration));
  } catch { /* tray gone */ }
}

// Unresolved items sit at the TOP as reachable actions, so a decision, repair, or sign-in is never
// buried inside the (destroyable) main window — the tray always offers a way to act.
function buildTrayMenu(items, model, migration = null) {
  const template = [];
  for (const it of items) template.push({ label: it.label, click: () => handleMustAct(it) });
  if (items.length) template.push({ type: 'separator' });
  // The one door to setting up sync: it opens the in-app wizard, which handles this computer's identity, the
  // vault and the folder itself. Sync is offered, never imposed: browsing a vault never requires setting this up.
  // A server known not to support syncing from a computer gets no door at all (the fact was stated at setup).
  if (syncHub) {
    if (migration && migration.tooOldNote) template.push({ label: "This server doesn't support syncing folders from this computer", enabled: false });
    else template.push({ label: 'Set up sync…', click: () => { void openSyncWizard(); } });
    // Everything that is set up — this computer's synced folders, the other computers, and the actions that
    // end a sync — lives in the Computers window; the tray only opens it.
    template.push({ label: 'Computers & synced folders…', click: () => { void openManageView(); } });
    template.push({ type: 'separator' });
  }
  // Which server is in force, honestly: a note when the environment overrides a saved setting, a way to
  // change servers, or a way to set one up when none is known (the same screen the app opens with).
  for (const it of trayPresentation.serverMenuItems(serverConfigState())) {
    if (it.kind === 'change-server') template.push({ label: it.label, click: () => { void changeServer(); } });
    else if (it.kind === 'setup-server') template.push({ label: it.label, click: () => { void showOrCreateWindow(); } });
    else template.push({ label: it.label, enabled: false });
  }
  // Checks a person can run themselves when something does not connect; it works without signing in.
  template.push({ label: 'Troubleshoot…', click: () => { void openTroubleshoot(); } });
  template.push({ label: 'Open DockVault', click: () => { void showOrCreateWindow(); } });
  // When the account tier is paused by a lock, offer an explicit way back rather than a "Lock now" that is
  // already in effect. An IDLE lock reverses on its own when input returns; a SLEEP or OS-screen lock (and a
  // deliberate "Lock now") does NOT auto-resume on mere input — a machine woken from sleep without a password
  // prompt stays paused on an unlocked desktop until this Resume item (or a real unlock-screen). So this
  // affordance keeps a lock from being a one-way door until relaunch. resumeAccount() re-enables ONLY the
  // account tier; it never asserts the ZK key.
  const accountPaused = (() => { try { const s = lockState && lockState.snapshot(); return !!(s && s.appLocked); } catch { return false; } })();
  template.push(accountPaused
    ? { label: 'Resume sync', click: () => { if (lockState) lockState.resumeAccount(); } }
    : { label: 'Lock now', click: () => { if (lockState) void lockState.lock('manual').catch(() => { /* state machine surfaces lock-error */ }); } });
  // Start-at-login as the machine sees it right now (login-item.js reads the real registration on every
  // build of this menu), so the box can never disagree with what will actually happen at login.
  template.push({ ...trayPresentation.loginItemMenu(loginItem().isEnabled()), click: () => toggleLoginItem() });
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
  // The folder is known by its marker and cannot be found (or is not the one at its path): the relocate-or-stop offer.
  if (item && item.kind === 'relocate-folder' && item.vault) { void relocateFolder(item.vault); return; }
  // The sync server can't be reached or isn't answering as one: Troubleshoot's connection check tests the saved
  // server and SFTP address separately and says which leg fails.
  if (item && item.kind === 'troubleshoot') { void openTroubleshoot(); return; }
  // The deliberate Repair: the ONLY thing that clears a blocked-after-run latch (a resync owed, or a
  // >50%-delete abort). It enqueues a manual repair run; the dispatch then asks the keep-both confirm
  // (confirmFirstUpload kind 'repair') before doing a zero-loss resync — nothing is auto-resynced.
  // A Repair turned away by the scheduler (the door is refusing and this window's attempt is spent) still earns
  // its one honest answer — the wait — rather than a press that does nothing.
  if (item && item.kind === 'repair' && item.vault) { if (syncScheduler) notifyTurnedAway(item.vault, syncScheduler.requestRepair(item.vault)); return; }
  // The sync helper (rclone) isn't ready — there is NO in-app install flow (the helper ships with the installer,
  // hash-pinned), so this action shows a real how-to dialog rather than a door to nowhere.
  if (item && item.kind === 'setup-helper') { showHelperFixDialog(item); return; }
  // The escape-hatch reset for a persistently unreadable device identity — its own confirmed forget flow,
  // never the plain open-the-app default.
  if (item && item.kind === 'reset-device') { void resetDeviceIdentity(); return; }
  // Set this computer up again after its identity ended (revoked / expired / not-recognized) or was reset:
  // re-register and re-establish the recorded vaults.
  if (item && item.kind === 'set-up-again') { void runDeviceSetupAgain(); return; }
  void showOrCreateWindow();
}

// The escape hatch itself: a device identity that has read unreadable for too long (the streak crossed the
// threshold), reset on the person's confirmation. forgetDevice takes the id-only path here — the blob is
// unreadable, so there is no origin to read back: an account-scoped, deviceId-only best-effort revoke via the
// sidecar id hint plus the local clear, never a re-register on top of the unreadable blob (the clear leaves an
// ABSENT slot, so the set-up-again that follows registers cleanly). Never touches vault data.
async function resetDeviceIdentity() {
  if (syncFlowBusy) return; // don't race a setup/stop flow
  syncFlowBusy = true;
  try {
    const confirmed = await dialog.showMessageBox(mainWindow, {
      type: 'warning', title: 'Reset sync on this computer', noLink: true,
      message: 'Reset sync on this computer?',
      detail: "DockVault can't read this computer's sync identity, and it hasn't cleared on its own. Resetting removes the identity from this computer so you can set it up again. Your vault files are untouched, and your vaults keep syncing through your sign-in meanwhile. If this computer still appears in your account afterwards, remove it there.",
      buttons: ['Cancel', 'Reset'], defaultId: 0, cancelId: 0,
    }).then((r) => r.response === 1).catch(() => false);
    if (!confirmed) return;
    const dir = app.getPath('userData');
    const accountToken = await resolveAccountToken();
    try { await deviceRegister.forgetDevice({ serverOrigin: serverConfig.readServerOrigin(dir), accountToken, dir, safeStorage }, { fetchFn: mainHttpJson }); }
    catch { /* forgetDevice never throws; the local clear still runs even if the revoke could not */ }
    try { devicePending.clearAllPending(safeStorage, dir); } catch { /* the pending markers belonged to the identity just removed; a set-up-again re-creates the ones it needs */ }
    // A reset re-offers migration: the offer flag is keyed by origin and a reset does not change the origin, so
    // clear it (and the cached support) here, else the one-time nudge would never fire again for this server.
    try { writeState({ deviceMigrationOfferOrigin: null }); } catch { /* best-effort; the standing door still stands */ }
    deviceMigrateSupport = null;
    invalidateMigrationView();
    deviceUnreadableStreak = 0;    // the identity is gone; the streak starts fresh if a new one later turns unreadable
    deviceIdentityStale = false;   // nothing to present any more
    syncIdentityChanged();         // the refusals on record were about the identity just removed
    try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* best-effort */ }
    refreshTray();
    void tickSync();
  } finally { syncFlowBusy = false; }
}

// The set-up-again DOOR: re-register this computer on a FRESH identity and re-establish its recorded vaults —
// reachable from the device-ended tray lines (revoked / expired / not-recognized) and after the escape-hatch
// reset, all of which promised "set it up again" with nowhere to do it. The old identity is forgotten first
// (idempotent: already absent after a server-end or a reset), so register lands on an absent slot; then each
// recorded vault's OLD grant record is dropped so it counts as a FIRST setup on the new identity (else the
// resume guard would read it as "granted before", find nothing on the new identity, and silently drop it), and
// re-granted — no-password vaults now, password vaults via a pending marker the resume finishes on next open.
// Fail-soft: any incomplete step leaves the vaults syncing on the account session. Never touches vault data.
async function runDeviceSetupAgain() {
  if (syncFlowBusy) return;
  syncFlowBusy = true;
  try {
    const dir = app.getPath('userData');
    const origin = serverConfig.readServerOrigin(dir);
    const accountToken = await resolveAccountToken();
    const info = (detail) => { try { return dialog.showMessageBox(mainWindow, { type: 'info', title: 'Set up this computer', noLink: true, message: 'Set up this computer', detail, buttons: ['OK'] }); } catch { return Promise.resolve(); } };
    if (!origin || !accountToken) { await info('Open DockVault and sign in to your account, then set this computer up again from the tray.'); return; }
    // The vaults recorded under the OLD identity — the set to re-establish. The record carries no identity, so
    // it survives the forget; read it up front so a set-up-again always knows which vaults to bring back.
    let recorded = [];
    try {
      const cur = deviceGrantStore.readGrantMeta(safeStorage, dir);
      const meta = (cur && cur.meta) || {};
      recorded = Object.keys(meta).map((vaultId) => ({ vaultId, vaultName: (meta[vaultId] && meta[vaultId].name) || vaultId, hasPassword: !!(meta[vaultId] && meta[vaultId].hasPassword) }));
    } catch { recorded = []; } // an unreadable record: re-register only; the vaults re-establish as they are next used
    const probe = await deviceRegister.checkDeviceSyncSupported({ serverOrigin: origin, accountToken }, mainHttpJson);
    if (probe.reason !== 'ok') {
      await info(probe.reason === 'auth' ? 'Sign in again, then set this computer up from the tray.'
        : probe.reason === 'too-old' ? "This server doesn't support syncing individual computers yet."
          : "Couldn't check right now — try again in a little while.");
      return;
    }
    // The same (a') consent as first setup — taken FIRST, before the one irreversible step (the forget): the
    // permanent name, the can't-rename truth, the under-lock disclosure. A decline costs nothing, leaving any
    // still-present (not-recognised) identity exactly as it was rather than forgetting it for no reason.
    const label = deviceRegister.suggestDeviceLabel(Array.isArray(probe.devices) ? probe.devices.map((d) => d && d.label).filter((l) => typeof l === 'string') : []);
    const consent = await dialog.showMessageBox(mainWindow, {
      type: 'question', title: 'Set up this computer for sync?', noLink: true,
      message: 'Set this computer up to sync again?',
      detail: `It will appear in your account as "${label}". You can't rename it later without setting this computer up again. This computer keeps syncing on its own — even while DockVault or the screen is locked.`,
      buttons: ['Not now', 'Set up'], defaultId: 0, cancelId: 0,
    }).then((r) => r.response === 1).catch(() => false);
    if (!consent) return; // the vaults keep syncing on the account session; nothing forgotten
    // Consented: now the irreversible forget (idempotent — already absent after a server-end or a reset) so
    // register lands on an ABSENT slot, never a refusal over a stale blob.
    try { await deviceRegister.forgetDevice({ serverOrigin: origin, accountToken, dir, safeStorage }, { fetchFn: mainHttpJson }); }
    catch { /* forgetDevice never throws */ }
    const reg = await deviceRegister.registerDevice({ serverOrigin: origin, accountToken, label, dir, safeStorage }, { fetchFn: mainHttpJson });
    if (!reg || !reg.ok) { await info("Setting this computer up didn't finish. Your vaults keep syncing through your sign-in — you can try again."); return; }
    const deviceId = reg.deviceId;
    // Re-establish the recorded vaults on the NEW identity (drop the old record first; no-password now,
    // password pending). The sequencer's order + branch are unit-tested in device-grant-resume.
    await runSetupAgainGrants({
      dropMeta: (vaultId) => { try { deviceGrantStore.removeGrantMeta(safeStorage, dir, vaultId); } catch { /* best-effort; the guard is the backstop */ } },
      addPending: (vaultId) => { devicePending.addPending(safeStorage, dir, vaultId); }, // may throw on an unreadable store → the sequencer records it failed
      grant: async ({ vaultId, vaultName }) => {
        const r = await deviceGrant.grantAndRecord({ serverOrigin: origin, accountToken, deviceId, vaultId, vaultType: 'standard', vaultName, dir, safeStorage }, { fetchFn: mainHttpJson });
        return (r && r.ok) ? { ok: true } : { ok: false, reason: (r && r.reason) || 'grant-failed' };
      },
    }, recorded);
    deviceUnreadableStreak = 0;
    deviceIdentityStale = false;
    // A brand-new identity with brand-new grants. Without this the tick below is silently swallowed by the OLD
    // identity's refusal window — for up to an hour — while the dialog underneath says it is syncing now.
    syncIdentityChanged();
    try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* best-effort */ }
    refreshTray();
    void tickSync();
    await info('This computer is set up to sync again. Your vaults sync on it now; a password-protected vault finishes the moment you next open it.');
  } finally { syncFlowBusy = false; }
}

// A native how-to dialog for an unready sync helper: the specific reason, then the remedy that fits it. Leak-safe —
// never a path, a value, or a SHA. A packaged app's helper came bundled with the installer, so the remedy follows
// the typed reason (reinstall for a damaged helper, allow-and-restart for a blocked one, restart-first otherwise);
// a development checkout is told which settings drive the helper and how to place the bundled one.
function showHelperFixDialog(item) {
  const sub = item && item.sub;
  const detail = trayPresentation.helperDetail(sub, item && item.installed, rcloneCfg && rcloneCfg.version, app.isPackaged);
  const remedy = app.isPackaged
    ? trayPresentation.helperRemedy(sub, process.platform)
    : 'The sync helper (rclone) comes from these settings: DOCKVAULT_RCLONE (the binary), DOCKVAULT_RCLONE_VERSION, and DOCKVAULT_RCLONE_SHA256 — or run `npm run fetch-rclone` to place the bundled helper. Correct whichever is wrong or missing, then restart DockVault.';
  try {
    dialog.showMessageBox(mainWindow, {
      type: 'warning', noLink: true, buttons: ['OK'], defaultId: 0,
      message: "The sync helper isn't ready",
      detail: `${detail}\n\n${remedy}`,
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
  if (made && made.ok) { if (syncScheduler) notifyTurnedAway(vaultId, syncScheduler.requestSync(vaultId, { manual: true })); } // secured — retry this vault (a retry the scheduler turns away says why)
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
  if (!syncScheduler) return { accepted: false, reason: 'refused' };
  // Flip the glance to the current online state at the moment of the press, so a "Sync now" while offline
  // reads "waiting to reconnect" INSTANTLY rather than green-until-the-next-tick; the dispatch still gates
  // offline (no real run), and the completion answer says "can't reach the server".
  if (syncHub) syncHub.setOnline(isOnlineNow());
  // The scheduler answers the REQUEST at once: a press inside the "Sync now" cooldown, or one against a door
  // that is refusing and has had this window's attempt, is turned away without a run (nothing minted) — the
  // caller shows that answer where the person pressed. Only an accepted press earns the completion toast;
  // a turned-away press owes no second answer.
  const verdict = syncScheduler.requestSync(vaultId, { manual: true });
  if (verdict && verdict.accepted) pendingManualSync.add(vaultId);
  return verdict;
}

// The answer a deliberate press earns when the scheduler turned the REQUEST away (a cooldown, or a refusing door's
// spent window): one calm line with the wait, cred-free, best-effort. Nothing for an accepted press — its run answers.
function notifyTurnedAway(vaultId, verdict) {
  try {
    if (!verdict || verdict.accepted !== false) return;
    if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
    let name = 'this vault';
    try { const e = storedConfig().find((c) => c.vaultId === vaultId); if (e && e.vaultName) name = e.vaultName; } catch { /* name only */ }
    const body = turnedAwayBody(verdict, name);
    if (!body) return;
    const n = new Notification({ title: 'DockVault', body });
    n.on('click', () => { void showOrCreateWindow(); });
    n.show();
  } catch { /* notifications are best-effort */ }
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
  // Through the renderer boundary: the same model with the outcome detail (the only field that can carry a
  // file's name) removed. One function, used by both renderer paths — see sync-status-model.publicStatus.
  const safe = syncStatusModel.publicStatus(model);
  if (mainWindow && !mainWindow.isDestroyed()) {
    // The main window renders the interface the SERVER supplies, on the server's own origin. It gets states,
    // labels and numbers and nothing else — never a sentence naming a file.
    try { mainWindow.webContents.send('dockvault:evt:syncstatus', safe); }
    catch { /* window gone mid-send */ }
  }
  if (manageWindow && !manageWindow.isDestroyed()) {
    // The Computers window is the app's OWN page (sender-gated to it), and it is where the honest sentence
    // belongs — it is already handed this computer's local folder for these vaults. Without the sentence on
    // the live push it could only patch the state chip, leaving the explanation beside it either blank or,
    // worse, the previous failure's: a card reading "Needs your decision" with a sentence about a file that is
    // no longer the problem. So the sentence is composed HERE, in main, and pushed with the state it explains.
    try { manageWindow.webContents.send('dockvault:evt:syncstatus', withReasonText(safe, model)); }
    catch { /* window gone mid-send */ }
  }
}

// The pushed model plus, per vault, the one plain sentence for its current reason — composed by the same
// `reasonText` the Computers window's own model uses, so a live patch and a full reload say the same thing.
function withReasonText(safe, model) {
  // The same io the Computers view itself is built from — built once, lazily, so both agree by construction.
  const io = manageReasonIo || (manageReasonIo = buildManageIo());
  if (!io || typeof io.reasonText !== 'function') return safe;
  let names = {};
  try { for (const e of storedConfig()) names[e.vaultId] = e.vaultName; } catch { names = {}; }
  const byId = new Map((model.vaults || []).map((v) => [v.vault, v]));
  return {
    ...safe,
    vaults: safe.vaults.map((v) => {
      const full = byId.get(v.vault);
      if (!full || !full.reason) return { ...v, reasonText: null };
      let text = null;
      try { text = io.reasonText(full, names[v.vault] || null); } catch { text = null; }
      return { ...v, reasonText: text || null };
    }),
  };
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
  // A per-vault must-act: compose the body from the SAME source the tray menu and the Computers card use, with
  // this vault's own outcome detail, so the one message a person gets WITHOUT opening anything names the real
  // cause instead of falling through to "something needs your attention". (The hub carries the detail on the
  // payload for exactly this.)
  if (item && item.scope === 'vault' && item.vault && item.reason) {
    let name = null;
    try { const e = storedConfig().find((c) => c.vaultId === item.vault); name = (e && e.vaultName) || null; } catch { /* no config to name */ }
    const line = trayPresentation.itemForVault(
      { vault: item.vault, reason: item.reason, detail: item.detail, retryAt: item.retryAt, resyncRequired: item.resyncRequired },
      name ? { [item.vault]: name } : {},
    );
    if (line && line.label) return withReassurance(line.label);
  }
  // The unlock-and-reopen guidance already carries its own reassurance and next step — use it verbatim rather
  // than appending the generic "Your files are safe." (which it already states).
  if (item && item.kind === 'reopen') return (item && item.label) || 'DockVault could not read its saved sync state. Your files are safe.';
  // The sync helper isn't ready: the notification body is the per-sub detail (with the app's pinned version for
  // a version-mismatch). The menu label carries the "Set up the sync helper" fix; the body says what's wrong.
  if (item && item.kind === 'setup-helper') return trayPresentation.helperDetail(item.sub, item.installed, rcloneCfg && rcloneCfg.version);
  const base = (item && item.label) || 'A sync item needs your attention';
  // A lost folder: the files may be wherever the folder went, so the one honest promise is what was NOT done.
  if (item && item.kind === 'relocate-folder') return `${base}. Nothing was changed; your vault on the server is untouched.`;
  return withReassurance(base);
}

// Append the standing reassurance to a line, joined properly. The labels are a mix of fragments and full
// sentences now, so appending blindly produced "…keeps syncing.. Your files are safe." A line that already
// says the files are untouched does not need it said twice.
function withReassurance(line) {
  const text = String(line || '').trim();
  if (/untouched|files are safe|nothing here was (?:lost|changed)/i.test(text)) return text;
  return /[.!?]$/.test(text) ? `${text} Your files are safe.` : `${text}. Your files are safe.`;
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
// Every main-process request goes through Electron's network layer, so certificate trust is the
// operating system's store — the same one the interface's proxied requests use. See http-json.js.
const mainHttpJson = require('./http-json').createHttpJson(net);

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

// Whether THIS computer holds a live sync identity of its own for the configured server ('ok' or 'stale', or a
// rotation caught mid-flight and marked stale). The one place both the scheduler's dispatch gate and the lock
// glance ask "is there a device path that keeps syncing under the OS lock?". Fails closed to false — any read
// error, or no configured server, is "no identity" — and reads the non-secret status only, dropping the secret.
function deviceIdentityLive() {
  try {
    const dir = app.getPath('userData');
    const origin = serverConfig.readServerOrigin(dir);
    if (!origin) return false;
    // NON-SECRET read (the last per-draw/per-tick one): migrationDeviceStatus derives presence from
    // readIdentityMeta (which decrypts but NEVER surfaces the secret) + the rotating marker, so answering "is
    // there an identity for this server?" no longer materializes the device secret on every tray draw and tick.
    // 'ok' (a live, origin-matched identity — stale-marked or not) or 'rechecking' (a surviving rotation marker)
    // is exactly the old readDeviceSecret status ok||stale; 'absent' / 'absent-for-this-server' are not.
    const s = migrationDeviceStatus(dir, origin);
    return s === 'ok' || s === 'rechecking' || deviceIdentityStale;
  } catch { return false; }
}

// The device identity's raw read status, for the escape-hatch streak below: 'ok' | 'stale' | 'absent' |
// 'unreadable' | 'absent-for-this-server' | 'no-secure-store'. Reads the non-secret status only and drops the
// secret; fails closed to 'unreadable' (an escalation toward the reset offer, never a false 'ok').
function deviceIdentityStatus() {
  try {
    const dir = app.getPath('userData');
    const origin = serverConfig.readServerOrigin(dir);
    if (!origin) return 'absent';
    const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin);
    if (r && r.secret) { try { deviceSecretStore.zeroizeSecret(r.secret); } catch { /* best-effort */ } r.secret = null; }
    return (r && r.status) || 'absent';
  } catch { return 'unreadable'; }
}

// Escape hatch: consecutive ticks that read the identity UNREADABLE. A persistently locked/torn keychain
// escalates the calm paused glance to a one-time reset offer only after it fails to clear for a while; any
// readable status resets the streak. Per-identity (global), in-memory — a restart re-counts from zero.
const DEVICE_UNREADABLE_RESET_THRESHOLD = 3; // ~15 min at the 5-min tick, so a transient lock clears first
let deviceUnreadableStreak = 0;

// This computer's sync identity has CHANGED — it went stale, the server ended it, it was dropped here, or a
// FRESH one was just registered in its place. Every answer the door gave about the old credential is spent
// history: it was about a secret this computer can no longer present, and holding the new one to it would make
// the app's own remedy ("set this computer up again") appear to do nothing for up to an hour. So lift the
// settled holds, open the endpoint gate, and forget the refusal back-off.
//
// Deliberately ONE function rather than the two calls written out at each site: the failure mode here is a new
// identity path that quietly clears NEITHER, which is invisible in review because it looks like no code at all.
// A mere presence resume is NOT this — it gets releaseHolds() alone (see sync-scheduler.js).
function syncIdentityChanged() {
  if (!syncScheduler) return;
  syncScheduler.releaseHolds();
  syncScheduler.clearRefusalBackoff();
}

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
  if (syncHub) { syncHub.setOnline(isOnlineNow()); syncHub.setDeviceLive(deviceIdentityLive()); } // keep the lock glance's device-identity signal at most one tick behind the gate (same reader)
  // Escape hatch: advance the unreadable streak ONLY while unlocked — a keyring that locks with the screen
  // reads unreadable on every locked tick, and those lock-induced reads must not count toward the reset offer.
  // Any readable status, or a locked tick, resets it; the unlock transition also resets it.
  const appLocked = !!(lockState && typeof lockState.snapshot === 'function' && lockState.snapshot().appLocked);
  deviceUnreadableStreak = deviceRegister.nextUnreadableStreak(deviceUnreadableStreak, { status: deviceIdentityStatus(), appLocked });
  // A surviving rotation marker only resolves on a device-refresh pass; kick one here (when none is in flight)
  // so a sign-in — which fires this tick — reconciles the calm "being re-checked" wait within one pass rather
  // than up to an hour later on the routine device-refresh tick.
  try { if (deviceSecretStore.hasRotatingMarker(app.getPath('userData')) && !deviceRefreshBusy) void tickDeviceRefresh(); } catch { /* best-effort */ }
  // Retry the migration offer's support probe when it is not yet known for the current server (a boot probe that
  // failed offline, or a freshly-switched server): fill the door within one routine tick rather than only on a
  // lock->unlock cycle. Fail-quiet + idempotent; the one-time notification stays governed by the origin flag.
  try { const o = serverConfig.readServerOrigin(app.getPath('userData')); if (o && (!deviceMigrateSupport || deviceMigrateSupport.origin !== o)) void maybeOfferDeviceMigration(); } catch { /* best-effort */ }
  await clearWaitsAnsweredByAnUnlock(); // before dispatch, so a vault whose password has been given goes this pass
  await runStateSnapshot.refresh(syncConfiguredIds()); // a failed refresh keeps it not-fresh → the scheduler skips
  // A deliberate pass (a folder just found again) also looks afresh for a moved folder. It is deliberate but it is
  // NOT a person pressing each vault's button, so it is marked press:false: it neither starts nor is held by the
  // "Sync now" cooldown (which belongs to the button), while the refusal back-off still bounds it like anything
  // else. A vault it cannot run right now is simply picked up by the next routine tick — the folder is already
  // saved — so these verdicts need no surface of their own.
  if (manual) { forgetFolderSearches(); for (const e of syncConfigList()) if (e && e.enabled) syncScheduler.requestSync(e.vaultId, { manual: true, press: false }); }
  else syncScheduler.tickAll();
  // Complete any device grant that deferred at setup, now that this pass may find the vault open (the pass is
  // more frequent than the password-freshness window, so an open vault is never missed). Fire-and-forget and
  // single-flighted, so it never blocks or stacks on the tick.
  void maybeResumeDeviceGrants();
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

  // Which credential path a run takes — this computer's registered identity (the device path) or the account
  // session (the account path, kept for set-ups not yet moved over) — decided ONCE per run from the device
  // identity, the server's fresh grant list and the local grant record, then latched for that run so every
  // credential minted during it (the dispatch mint and each per-step mint) takes the same path. The device
  // secret is read from the OS store at the moment it is needed and never kept on any of these closures.
  const withDeviceSecret = async (fn) => {
    if (deviceIdentityStale) { const e = new Error('device identity is stale'); e.reason = 'device-secret-stale'; throw e; } // never present a retired secret
    const origin = serverConfig.readServerOrigin(dir);
    const id = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin);
    if (id.status === 'stale') { const e = new Error('device identity is stale'); e.reason = 'device-secret-stale'; throw e; } // the durable mark, after a restart
    // The identity was 'ok' when this run began; anything else now is a LOCAL change (a forget raced the run,
    // the keyring locked), never a server refusal — the next pass simply decides afresh.
    if (id.status !== 'ok') { const e = new Error('device identity unavailable'); e.reason = id.status === 'unreadable' ? 'device-secret-unreadable' : 'device-identity-missing'; throw e; }
    try { return await fn(origin, id.secret); } finally { id.secret = null; }
  };
  mintPath = new MintPathSelector({
    readSecret: () => {
      const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, serverConfig.readServerOrigin(dir)); r.secret = null;
      if (r.status === 'absent') deviceIdentityStale = false; // the identity is gone (forgotten; a new one may register) — a merely unreadable one keeps the flag
      if (deviceIdentityStale && r.status === 'ok') return { status: 'stale' }; // an in-memory retired mark over a live blob
      // A raw 'stale' from a surviving ROTATING marker (not the durable retired flag) is being re-checked, not
      // terminal: report it distinctly so the selector shows the calm wait rather than a set-up-again.
      if (r.status === 'stale' && !deviceIdentityStale && deviceSecretStore.hasRotatingMarker(dir)) return { status: 'rechecking' };
      return { status: r.status };
    },
    listGrants: () => withDeviceSecret((origin, secret) => deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: secret, dir, safeStorage }, { fetchFn: mainHttpJson })),
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
    // A grant whose details were never recorded here (or could not be read): fill them in from the account's
    // own vault listing when a session is live, and record them best-effort for next time. The listing holds
    // only Standard vaults, so a vault found there is Standard by construction; one not found stays pending.
    backfill: async (vaultId) => {
      const origin = serverConfig.readServerOrigin(dir);
      const token = await resolveAccountToken();
      if (!origin || !token) return null;
      const res = await syncVaults.fetchStandardVaults({ serverOrigin: origin, sessionToken: token }, mainHttpJson);
      rememberVaultPasswordFlags(res && res.vaults);
      const v = ((res && res.vaults) || []).find((x) => x && x.vaultId === vaultId);
      if (!v) return null;
      const meta = { name: v.vaultName, vaultType: 'standard', hasPassword: v.hasPassword !== false };
      try { deviceGrantStore.setGrantMeta(safeStorage, dir, vaultId, meta); } catch { /* the record is a convenience; the grant list is the authority */ }
      return meta;
    },
  });

  // The SFTP address the person entered and verified at setup replaces whatever host and port the server
  // advertises with a credential: a deployment that publishes SFTP on another host port than the one the
  // vault binds inside its container advertises the inside number, and would otherwise send every sync to
  // the wrong place. A set-up saved before the address was asked for has none, and keeps the advertised values.
  // When the two disagree, that fact is worth one line in the log (hosts and ports only — never the
  // credential): it is the trace a person troubleshooting "the server thinks SFTP is elsewhere" needs.
  let notedAdvertised = null;
  const atVerifiedEndpoint = (bundle) => {
    const r = sftpEndpoint.applySftpEndpoint(bundle, serverConfig.readSftpEndpoint(dir));
    const key = `${r.advertised.host}:${r.advertised.port}`;
    if (r.overridden && notedAdvertised !== key) {
      notedAdvertised = key;
      try { console.warn(`[dockvault] sync connects to the SFTP address verified at setup (${r.bundle.host}:${r.bundle.port}); the server advertises ${key}`); } catch { /* ignore */ }
    }
    return r.bundle;
  };
  credCache = new CredCache({
    mint: async (vaultId) => atVerifiedEndpoint(await mintAtAdvertisedEndpoint(vaultId)),
    // Bind the send to the child epoch sampled at mint time: a restart mid-mint refuses delivery to the
    // replacement child (a credential minted for a child that is gone is never handed to its successor).
    send: (bundle, epoch) => daemon.sendSftpCred(bundle, 12000, epoch),
    epoch: () => daemon.currentEpoch(),
  });
  async function mintAtAdvertisedEndpoint(vaultId) {
    const via = mintPath.current(vaultId);
    // The device path: this computer's own identity mints against its grant. No account session, no vault
    // password. The response carries the host key to pin and the real SFTP host/port. A failure here is the
    // device's own typed refusal and is NEVER retried on the account path within the run.
    if (via === 'device') return withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, mainHttpJson));
    // No path was chosen for this vault's run: a wiring fault (a mint with no eligibility step before it),
    // surfaced as an internal error rather than silently taking either path.
    if (via !== 'account') { const e = new Error('no credential path chosen for this run'); e.reason = 'internal-error'; throw e; }
    // The account path (set-ups not yet moved over to device sync).
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
  }
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
    // The folder by its identity, before every run (folder-identity.js): a moved or renamed folder is followed
    // (and the config re-pointed), a folder that cannot be found pauses the vault with the relocate-or-stop offer.
    resolveFolder: (cfg) => resolveFolderFor(cfg),
    credCache,
    daemon,
    confirmFirstUpload: (o) => confirmFirstUpload(o, entryFor(o.vaultId)),
    isAccountUsable: () => !!(lockState && lockState.isAccountUsable()),
    vaultHasPassword: (vaultId) => vaultRequiresPassword(vaultId), // route a persistent auth-failed here to needs-unlock
    hasAccount: () => { try { return !!(serverConfig.readServerOrigin(dir) && ((sessionBundle && sessionBundle.authToken) || (tokenStore.loadSession(safeStorage, dir) || {}).authToken)); } catch { return false; } },
    // This computer's own sync identity for the configured server: 'ok' dispatches on the device path; 'stale' counts
    // too, so a run reaches the eligibility step and is refused there with the honest device reason rather than a
    // misleading "sign in". Anything else is no identity (absent, another server's, unreadable, no secure store).
    hasDeviceIdentity: deviceIdentityLive,
    isOnline: isOnlineNow, // the one online source — shared with the status hub's glance (tickSync setOnline)
    onEvent: (vaultId, ev) => {
      // Stamp the run with the credential path it took, so the glance can say which kind of sync ran; and
      // once the run has ended in any way, forget the run's latched path so the next run decides afresh.
      if (ev && ev.phase === 'running') ev = { ...ev, via: mintPath.current(vaultId) };
      // A run COMPLETED (a clean run, a resync, or a kept-both run — not an abort or a missing-listing outcome):
      // the engine has carried any listings over, so a move's old path is forgotten, and the server-side path this
      // run used is remembered for the next run's carry-over should it take the other credential path.
      if (ev && ev.phase === 'done' && ev.outcome && ev.outcome.ran === true && ['ok', 'resync-ok', 'conflict-keep-both'].includes(ev.outcome.result)) {
        try {
          const cur = storedConfig().find((e) => e.vaultId === vaultId);
          const usedRemote = typeof ev.remotePath === 'string' && ev.remotePath ? ev.remotePath : null;
          if (cur && (cur.movedFrom || (usedRemote && cur.lastRemotePath !== usedRemote))) {
            const { movedFrom, ...rest } = cur;
            if (usedRemote) rest.lastRemotePath = usedRemote;
            syncConfigStore.saveConfig(safeStorage, dir, syncConfig.upsertEntry(storedConfig(), syncConfig.makeConfigEntry(rest)));
          }
        } catch { /* best-effort; the carry-over is idempotent and runs again next time */ }
      }
      // The server has ended this computer's identity (removed by the owner, or expired): the local secret can
      // never be presented again, so it is wiped now — the state database is left alone, and the recorded grant
      // details stay for the next set-up. The refusal itself is still recorded and held below.
      // Deliberately NOT syncIdentityChanged() even though the identity has ended: this runs inside the
      // scheduler's own event sink, and the hold that carries this very reason was set as the event was
      // emitted — lifting it here would erase it and re-dispatch the vault on every tick from now on. The
      // refusal is recorded and held below; the person's next action (setting this computer up again) is what
      // clears it, and that path does call it.
      if (ev && (ev.phase === 'refused' || ev.phase === 'paused' || ev.phase === 'skipped') && identityEndedBy(ev.reason)) {
        try { deviceSecretStore.clearDeviceSecret(dir); } catch { /* best effort; the next read re-decides */ }
        deviceIdentityStale = false;
        if (syncHub) syncHub.setDeviceLive(false); // the identity is gone -> the lock overlay must not keep a device vault's stale green
      }
      // The pending-grant marker follows the run's reason: a re-proof (the vault password changed) FEEDS it so
      // the resume finishes it on the next open; a revoked/withdrawn grant or an ended identity CLEARS it so the
      // resume never reactivates a grant the owner withdrew. Best-effort — the sweep's own listMyGrants
      // active-check is the second layer, and a first grant reactivates nothing.
      const markerAct = ev && markerActionForRunReason(ev.reason);
      if (markerAct) {
        try {
          if (markerAct === 'add') devicePending.addPending(safeStorage, dir, vaultId);
          else if (markerAct === 'clear') devicePending.clearPending(safeStorage, dir, vaultId);
          else if (markerAct === 'clear-all') devicePending.clearAllPending(safeStorage, dir);
        } catch { /* an unreadable pending store: the sweep's guard still prevents a wrong grant */ }
      }
      const terminal = !!(ev && ['done', 'error', 'blocked', 'paused', 'skipped', 'refused', 'noop'].includes(ev.phase));
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
        if (terminal) mintPath.end(vaultId);
      }
    },
  });
  // The run-time eligibility step decides the credential path first. On the device path the vault must be
  // among this computer's active grants with a recorded Standard tier, and the remote path is the vault's
  // rename-proof id form; on the account path the existing fresh vault-list re-assert runs as before.
  io.credentialPath = (vaultId) => mintPath.current(vaultId); // which path this vault's run took, for the auth-failure routing
  // The endpoint gate's credential-free probe (see sync-scheduler.js): after a connect failure the scheduler asks
  // this INSTEAD of minting. It connects to the SFTP address the runs use — the one verified at set-up when there
  // is one, else the address of the last mint — performs a from-scratch SSH key exchange (no credential is sent;
  // the server signs, the probe verifies) and compares the presented host key with the session's pin. Typed
  // answers only: unreachable, not an SSH server this app can talk to, a changed identity, or ok. No address to
  // probe (a set-up from before the address was asked for, and no mint yet) => ok, and the scheduler's back-off
  // alone bounds the minting.
  io.probeEndpoint = async () => {
    const saved = serverConfig.readSftpEndpoint(dir);
    const at = (saved && saved.host && Number.isInteger(saved.port)) ? { host: saved.host, port: saved.port } : (credCache ? credCache.lastEndpoint() : null);
    if (!at) return { ok: true };
    let r;
    try { r = await probeSftp(at); } catch { r = { kind: 'unreachable' }; }
    if (!r || r.kind === 'unreachable') return { ok: false, reason: 'sync-server-unreachable' };
    if (r.kind !== 'ok') return { ok: false, reason: 'sync-server-unverified' }; // not-ssh / ssh-unsupported
    const pinned = credCache ? credCache.pinnedHostKeys(at.host) : null;
    if (pinned && typeof r.hostKey === 'string' && !pinAccepts(pinned, r.hostKey)) return { ok: false, reason: 'host-key-mismatch' };
    return { ok: true };
  };
  // Asked ONCE, after a run whose file the server took and then did not keep: does the vault's own record say
  // the allowance is spent? A close in this protocol cannot report a failure, so a refused upload is a silence,
  // and the numbers are the only honest way to name the cause. Metadata only (the vault's limit and how much of
  // it is stored, nothing else), over the ACCOUNT session — under the lock, or signed out, there is no answer to
  // be had and the outcome keeps its weaker, true name rather than a guess.
  const VAULT_SPACE_TIMEOUT_MS = 5000;
  io.vaultSpace = async (vaultId) => {
    const unknown = { known: false, limitBytes: null, usedBytes: null, freeBytes: null };
    // Gated on the ACCOUNT tier, like every other account-session call: under the lock (or signed out) this
    // computer syncs on its own device identity precisely so it needs no account session, and reaching for
    // one here would both fail and read the session out of a renderer the lock has paused. No answer is a
    // perfectly good answer — the outcome simply keeps its weaker, true name.
    if (!(lockState && lockState.isAccountUsable())) return unknown;
    const token = await resolveAccountToken();
    // Bounded, because this runs inside the dispatch's critical section: the queue is held while it waits, and
    // a server that is slow to answer must not make a vault read "syncing" for the length of an HTTP timeout.
    // Giving up early costs only the specific wording, never correctness.
    const answer = vaultSpace.fetchVaultSpace({ serverOrigin: serverConfig.readServerOrigin(dir), sessionToken: token, vaultId }, mainHttpJson);
    return Promise.race([answer, new Promise((resolve) => { const t = setTimeout(() => resolve(unknown), VAULT_SPACE_TIMEOUT_MS); if (t.unref) t.unref(); })]);
  };
  const accountEligible = io.verifyEligible;
  io.verifyEligible = async (vaultId) => {
    const d = await mintPath.begin(vaultId);
    if (!d.ok) return d;
    if (d.via === 'device') return { ok: true, via: 'device', remotePath: d.remotePath, vaultName: d.vaultName };
    // Carry the latched path on the account result too, so the dispatch gate's under-lock re-check can tell a
    // device run (which keeps syncing under the account-tier lock) from an account run (which pauses).
    const acc = await accountEligible(vaultId);
    return (acc && acc.ok) ? { ...acc, via: 'account' } : acc;
  };
  syncScheduler = new SyncScheduler(io);
  // Authorise the helper's per-step credential requests (a resync mints one fresh single-use credential per
  // rclone process). Main holds the say: it mints ONLY for the vault whose run is in flight right now, and only
  // while the app is active for account-tier sync (not lock-paused) with a live account. The gate is the
  // account tier (isAccountUsable), NEVER the ZK unlocked state — Standard sync does not use the ZK key. The
  // helper's requested vaultId is CHECKED against the scheduler's in-flight vault, never trusted as an input;
  // the fresh credential is delivered on the existing sftp-cred path, and this returns only { ok, reason }.
  if (daemon) daemon.setCredProvider(async (vault) => {
    // The device path needs no account session; the account path does; a run that chose no path mints nothing.
    const refuse = schedulerIo.perStepGate({
      inFlight: !!(syncScheduler && syncScheduler.current() === vault),
      locked: !(lockState && lockState.isAccountUsable()),
      via: mintPath.current(vault),
      accountLive: io.hasAccount(),
    });
    if (refuse) return { ok: false, reason: refuse };
    return credCache.ensureSent(vault);
  });
  // The routine cadence. Unref'd so it never keeps the process alive; each tick is a cheap gated skip when
  // there is nothing to do. A first pass is kicked shortly after boot (once the window/session settle).
  if (syncTickTimer) clearInterval(syncTickTimer);
  syncTickTimer = setInterval(() => { void tickSync(); }, SYNC_TICK_MS);
  if (syncTickTimer.unref) syncTickTimer.unref();
  // The identity rotation: its own cadence beside the sync tick (never coupled to a mint), with a first look
  // shortly after boot once the network has settled.
  if (deviceRefreshTimer) clearInterval(deviceRefreshTimer);
  deviceRefreshTimer = setInterval(() => { void tickDeviceRefresh(); }, DEVICE_REFRESH_TICK_MS);
  if (deviceRefreshTimer.unref) deviceRefreshTimer.unref();
  const firstLook = setTimeout(() => { void tickDeviceRefresh(); }, BOOT_SYNC_KICK_MS + 15000);
  if (firstLook.unref) firstLook.unref();
}

// One rotation check: rotate this computer's identity when it is old enough. Quiet on every failure other than
// a STALE refusal (the secret held here is already retired): that flips the identity to stale so no run presents
// it again, and the next pass surfaces the honest state. Everything else simply tries again next hour.
async function tickDeviceRefresh() {
  if (SMOKE || deviceRefreshBusy || !isOnlineNow()) return;
  const dir = app.getPath('userData');
  const origin = serverConfig.readServerOrigin(dir);
  if (!origin) return;
  // Rotation RECOVERY takes precedence: a ROTATING marker present when no refresh is in flight (this tick is
  // not busy) is a crash-survivor or an ambiguous-failure keep — the held secret MAY be retired, so it is
  // never presented; reconcile it against the account's device list instead of rotating.
  if (deviceSecretStore.hasRotatingMarker(dir)) {
    deviceRefreshBusy = true;
    try { await reconcileSurvivedRotation(dir, origin); } finally { deviceRefreshBusy = false; }
    return;
  }
  let read;
  try { read = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin); } catch { return; }
  if (read) read.secret = null;
  if (!read || read.status !== 'ok' || deviceIdentityStale || !isRotationDue(read, Date.now())) return;
  deviceRefreshBusy = true;
  try {
    const r = await refreshDeviceSecret({ serverOrigin: origin, dir, safeStorage }, { fetchFn: mainHttpJson });
    // Stale: the server refused the held secret as retired, OR it rotated and this side lost the answer (a store
    // that failed, an answer with no usable secret). Either way the secret held here is retired — stop presenting it.
    if (identityIsStaleAfter(r)) {
      deviceIdentityStale = true;
      deviceSecretStore.markDeviceSecretStale(dir); // durable: survives a restart, so the boot kick never presents the retired secret
      syncIdentityChanged();
      void tickSync(); // let the next pass show the honest state rather than wait for the routine tick
    }
  } catch { /* a rotation never throws; belt-and-suspenders */ }
  finally { deviceRefreshBusy = false; }
}

// Reconcile a SURVIVING rotation marker (a crash between /device/refresh and the store, or an ambiguous
// failure that kept the mark) WITHOUT presenting the possibly-retired secret. The account session's device
// list is the source of truth: match this computer's row by its (non-secret) deviceId and compare the
// server's epoch to the blob's. Only an exact match LIFTS the mark; every doubt keeps it and waits.
//   clear   → the rotation never landed; the held secret is still current → clear the mark, resume.
//   stale   → the server rotated and this side lost the new secret → mark stale + clear the rotating mark
//             (so the state becomes unambiguously terminal), route to set-up-again.
//   revoked → the row is gone/inactive → same terminal treatment; set-up-again.
//   keep    → leave the mark; a later tick (or a sign-in) retries. Meanwhile the identity reads "being
//             re-checked" (a calm paused wait), never a set-up-again alarm.
async function reconcileSurvivedRotation(dir, origin) {
  const accountToken = await resolveAccountToken();
  if (!accountToken) return;                                   // no session → keep the mark + wait (the calm "being re-checked" glance shows)
  const meta = deviceSecretStore.readIdentityMeta(safeStorage, dir);
  if (!meta || !meta.deviceId) return;                         // cannot name the row → keep + wait
  let probe;
  try { probe = await deviceRegister.checkDeviceSyncSupported({ serverOrigin: origin, accountToken }, mainHttpJson); }
  catch { return; }                                            // could not reach/list → doubt → keep + wait
  if (!probe || probe.reason !== 'ok' || !Array.isArray(probe.devices)) return; // not a clean device list → keep
  const row = probe.devices.find((d) => d && (d.device_id === meta.deviceId || d.id === meta.deviceId));
  const lookup = row ? { found: true, isActive: row.is_active !== false, epoch: row.epoch } : { found: false };
  const decision = reconcileRotationMarker(lookup, meta.epoch);
  let changed = false;
  if (decision === 'clear') {
    deviceSecretStore.clearDeviceSecretRotating(dir);          // the held secret IS current → recover
    deviceIdentityStale = false;
    changed = true;
  } else if (decision === 'stale') {
    deviceSecretStore.markDeviceSecretStale(dir);              // the server rotated and this side lost the answer → retired
    deviceSecretStore.clearDeviceSecretRotating(dir);          // drop the rotating mark so the state is unambiguously stale (no longer "being re-checked")
    deviceIdentityStale = true;
    syncIdentityChanged();
    changed = true;
  } else if (decision === 'revoked') {
    deviceSecretStore.clearDeviceSecret(dir);                  // the device row is GONE → wipe the identity so it reads as REMOVED ("set it up again"), not merely "not recognised"
    deviceIdentityStale = false;                               // nothing to present; the blob is gone
    syncIdentityChanged();
    changed = true;
  } // 'keep' → leave the mark untouched; retry next pass (no state change → no tick, so the sign-in kick can't loop)
  if (changed) { try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* best-effort */ } void tickSync(); }
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
    // Give the folder its identity: the hidden marker in its root (folder-marker.js). A marker already there
    // for this same vault is kept, so a folder set up again keeps the identity it had; anything else (none, or
    // a leftover from another sync) is replaced with a fresh id. Returns the sync id the config records.
    markFolder: (folder, vaultId) => markFolderFor(folder, vaultId),
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

// The IO surface for the DEVICE STEP of enabling sync (runDeviceSetup drives the order + the fail-soft
// rules; this only carries each step out). Every server call goes over mainHttpJson — the real Electron net
// the vault-list fetch already uses. Nothing here holds a credential: the device secret lives in the OS
// store, and the vault password is proven ONCE from the renderer's unlock state (pullVaultPasswordForMint),
// the same single-use, never-stored path the mint uses — there is no native password prompt.
function buildDeviceEnableIo(vault) {
  const dir = app.getPath('userData');
  const origin = serverConfig.readServerOrigin(dir);
  let deviceId = null;       // set by a successful register, or read from the store for the grant-only path
  let otherOrigin = null;    // captured from the store for the switch-server dialog
  let existingLabels = [];   // captured from the probe so the suggested label does not collide
  return {
    probe: async () => {
      const accountToken = await resolveAccountToken();
      const r = await deviceRegister.checkDeviceSyncSupported({ serverOrigin: origin, accountToken }, mainHttpJson);
      if (Array.isArray(r.devices)) existingLabels = r.devices.map((d) => d && d.label).filter((l) => typeof l === 'string');
      return { reason: r.reason };
    },
    readStatus: () => {
      try {
        const read = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin);
        const status = (read && read.status) || 'absent';
        if (read && read.status === 'ok' && typeof read.deviceId === 'string') deviceId = read.deviceId; // grant-only path id
        if (read && read.status === 'absent-for-this-server') otherOrigin = read.otherOrigin || null;
        if (read && read.secret) { try { deviceSecretStore.zeroizeSecret(read.secret); } catch { /* best-effort */ } read.secret = null; }
        return status;
      } catch { return 'unreadable'; } // never register on top of a blob we could not read
    },
    confirmSwitchServer: async () => {
      const other = otherOrigin || 'another server';
      const res = await dialog.showMessageBox(mainWindow, {
        type: 'warning', title: 'Switch this computer to this server?', noLink: true,
        message: 'This computer is already set up to sync with another server',
        // The truth of the absent-for-this-server forget: this session CANNOT revoke on the other server
        // (it can't speak for it), so it clears the local identity and registers here — the other server
        // keeps listing this computer until its owner removes it there. Never promise a removal we can't do.
        detail: `This computer will stop using its identity for ${other} and get a new one here. ${other} will still list this computer until its owner removes it there.`,
        buttons: ['Cancel', 'Switch to this server'], defaultId: 0, cancelId: 0,
      });
      return res.response === 1;
    },
    forget: async () => {
      const accountToken = await resolveAccountToken();
      try { await deviceRegister.forgetDevice({ serverOrigin: origin, accountToken, dir, safeStorage }, { fetchFn: mainHttpJson }); }
      catch { /* forgetDevice never throws; belt-and-suspenders */ }
      // Stated HERE rather than left to the caller: the identity is gone the moment this returns, whether or not
      // the registration that usually follows goes on to succeed. A switch whose register then fails would
      // otherwise keep the old server's refusals holding vaults it can no longer say anything about.
      syncIdentityChanged();
      try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* the identity is now absent → refresh the glance */ }
    },
    promptLabel: async () => {
      // (a'): no main-process text input, so auto-assign a non-identifying label (never the hostname) and
      // SHOW the permanent name in the buttons-only consent, alongside the permanence and the lock
      // disclosure — one dialog that carries the register consent and both truths.
      const label = deviceRegister.suggestDeviceLabel(existingLabels);
      const res = await dialog.showMessageBox(mainWindow, {
        type: 'question', title: 'Set up this computer for sync?', noLink: true,
        message: 'Set up this computer for sync?',
        detail: `It will appear in your account as "${label}". You can't rename it later without setting this computer up again. This computer keeps syncing on its own — even while DockVault or the screen is locked.`,
        // Default to the SAFE button: the dialog exists so the permanent name and the under-lock behaviour
        // are READ before they are accepted; an Enter-key default on "Set up" would skip that reading.
        buttons: ['Not now', 'Set up'], defaultId: 0, cancelId: 0,
      });
      return res.response === 1 ? label : null;
    },
    register: async (label) => {
      const accountToken = await resolveAccountToken();
      // registerDevice runs the fail-safe order itself (pre-check store → POST → store → orphan-clean the
      // server row on ANY post-POST failure), so there is no second revoke path to add here.
      const r = await deviceRegister.registerDevice({ serverOrigin: origin, accountToken, label, dir, safeStorage }, { fetchFn: mainHttpJson });
      if (r && r.ok) { deviceId = r.deviceId; syncIdentityChanged(); try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* now present → refresh */ } }
      return r;
    },
    grantVault: async ({ vaultId, vaultName, hasPassword }) => {
      const accountToken = await resolveAccountToken();
      if (!deviceId) { // defensive: the grant-only path if readStatus did not capture the id
        try { const read = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin); if (read) { if (typeof read.deviceId === 'string') deviceId = read.deviceId; if (read.secret) { try { deviceSecretStore.zeroizeSecret(read.secret); } catch { /* best-effort */ } read.secret = null; } } } catch { /* fall through */ }
      }
      if (!deviceId) return { granted: false, reason: 'no-identity' };
      // If the server already lists this vault's grant ACTIVE, the grant STANDS — an earlier local record write
      // may have failed (grantAndRecord is best-effort: a full/locked store leaves recorded:false while the
      // server grant is real). Re-write the record and SKIP the redundant POST: no password is needed, and the
      // recovered record is what makes a later revoke terminal instead of resting on a best-effort write. We do
      // NOT hard-block the 'revoked'/absent answer — checkActiveDeviceGrant returns 'revoked' for a NEVER-granted
      // vault too, so blocking would refuse every genuine first setup; the remaining "revoked + lost record +
      // explicit re-grant" is a bounded, same-principal, explicit-click residual (the server-side distinction is
      // the GA fix). 'inconclusive' → proceed, exactly as a first setup would.
      let active;
      try { active = await checkActiveDeviceGrant(vaultId); } catch { active = 'inconclusive'; }
      if (active === 'active') {
        let recorded = false;
        try { deviceGrantStore.setGrantMeta(safeStorage, dir, vaultId, { name: typeof vaultName === 'string' ? vaultName : '', vaultType: 'standard', hasPassword: !!hasPassword }); recorded = true; } catch { recorded = false; }
        return recorded ? { granted: true } : { granted: true, recordFailed: true };
      }
      let vaultPassword;
      if (hasPassword) {
        // The one place the vault password is proven for the device grant: pulled from the renderer's unlock
        // state (vault open + <15min fresh), single-use. Not open → a calm deferred, never a password box.
        vaultPassword = await pullVaultPasswordForMint(vaultId);
        if (!vaultPassword) return { granted: false, deferred: true };
      }
      try {
        const r = await deviceGrant.grantAndRecord({ serverOrigin: origin, accountToken, deviceId, vaultId, vaultType: 'standard', vaultName, vaultPassword, dir, safeStorage }, { fetchFn: mainHttpJson });
        if (!(r && r.ok)) return { granted: false, reason: (r && r.reason) || 'grant-failed' };
        // The grant is created (server-authoritative). recorded:false means the local record write failed — the
        // grant STANDS, but surface it honestly (never a silent clean success) so the person can clear the cause
        // and the vault is not left silently looking un-set-up.
        return r.recorded ? { granted: true } : { granted: true, recordFailed: true };
      } finally { vaultPassword = undefined; } // drop our reference; grantDeviceVault also drops the wire copy
    },
  };
}

// Carry out the device step for a just-enabled vault, fail-soft on top of the already-saved config. A
// deferred grant (the vault was not open to prove its password) records the intent so the resume path can
// finish it later; any other non-device outcome simply leaves the vault syncing on the account session.
async function runDeviceStepForVault(entry) {
  if (!entry || typeof entry.vaultId !== 'string' || !entry.vaultId) return;
  const dir = app.getPath('userData');
  const vault = { vaultId: entry.vaultId, vaultName: entry.vaultName, hasPassword: vaultRequiresPassword(entry.vaultId) };
  let outcome;
  try { outcome = await runDeviceSetup(buildDeviceEnableIo(vault), vault); }
  catch { outcome = { via: 'account', outcome: 'grant-failed', reason: 'device-step-error' }; } // fail-soft: the vault still syncs on the account session
  if (outcome && outcome.outcome === 'grant-deferred') {
    try { devicePending.addPending(safeStorage, dir, entry.vaultId); } catch { /* an unreadable pending store is non-fatal; the account path still syncs */ }
  }
  try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* glance refresh is best-effort */ }
  void tickSync(); // reflect the resulting path (device vs account) in the tray
  await showDeviceOutcome(outcome, vault);
}

// Tell the person what the device step did. A granted device path is quiet success (the tray shows it
// syncing, the first-success toast fires); every other outcome is one honest, non-blaming line — never a
// dead end, because the vault is already syncing on the account session.
async function showDeviceOutcome(outcome, vault) {
  if (!outcome) return;
  // A granted device path is quiet success (the tray shows it syncing). And after the person's OWN choice to
  // decline — a cancelled setup or a declined switch — a dialog repeating that choice is noise; the tray
  // already reflects it. Keep the honest line only for outcomes the person did NOT choose (deferred, failed,
  // sign-in, account-only), where they need to know the vault fell back to the account session.
  if (outcome.via === 'device' && outcome.outcome === 'granted') return;
  if (outcome.outcome === 'register-cancelled' || outcome.outcome === 'switch-declined') return;
  const { message } = enableCopy.deviceOutcomeCopy(outcome, { vaultName: vault.vaultName, hasPassword: !!vault.hasPassword });
  try {
    await dialog.showMessageBox(mainWindow, {
      type: 'info', title: 'Sync setup', noLink: true,
      message: 'Sync setup', detail: message, buttons: ['OK'],
    });
  } catch { /* best-effort */ }
}

// One acknowledgement that a vault finished setting up on this computer — name only, shown once (the marker is
// cleared on success, so a later pass never re-announces it), the way the first-sync toast is.
function ackDeviceSetupComplete(vaultName) {
  try {
    if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
    new Notification({ title: 'DockVault', body: `${vaultName || 'This vault'} is now set up to sync on this computer.` }).show();
  } catch { /* best-effort */ }
}

// The server's authoritative answer for the re-proof guard: does THIS device still hold an ACTIVE grant for
// the vault? Reads the device secret with the same never-present-a-retired-secret guard the mint uses, asks
// the device-Bearer grant list, and drops the secret. 'active' | 'revoked' | 'inconclusive' — a stale or
// unreadable identity, or any failed / unusable answer, is inconclusive, so the sweep DEFERS rather than
// reactivating a grant on doubt. GET /device/grants returns only active grants, so a clean list that omits
// the vault is a definitive revoke.
async function checkActiveDeviceGrant(vaultId) {
  if (deviceIdentityStale) return 'inconclusive';                 // a retired secret must never be presented (a replay)
  const dir = app.getPath('userData');
  const origin = serverConfig.readServerOrigin(dir);
  if (!origin) return 'inconclusive';
  let id;
  try { id = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin); } catch { return 'inconclusive'; }
  if (!id || id.status !== 'ok') { if (id && id.secret) { try { deviceSecretStore.zeroizeSecret(id.secret); } catch { /* best-effort */ } id.secret = null; } return 'inconclusive'; }
  let res;
  try { res = await deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: id.secret, dir, safeStorage }, { fetchFn: mainHttpJson }); }
  catch { res = null; }
  finally { try { deviceSecretStore.zeroizeSecret(id.secret); } catch { /* best-effort */ } id.secret = null; }
  if (!res || !res.ok || !Array.isArray(res.grants)) return 'inconclusive'; // a failed / unusable answer → defer, never proceed on doubt
  return res.grants.some((g) => g && g.vaultId === vaultId) ? 'active' : 'revoked'; // clean list: present = active, absent = revoked
}

// Per-vault, in-memory: the unlock instant that last got a wrong-password re-proof, so the sweep never re-proves
// again with the SAME unlock (each stale attempt burns the vault's shared web-open limiter). A newer unlock
// re-arms it; a success clears it; a restart clears it (a restart is itself a fresh unlock).
const deviceGrantFailedUnlock = new Map();

// Complete any deferred device grants whose vault is now open + fresh. Called from every sync pass (so an
// unlock is picked up within one tick), single-flighted, and a cheap no-op unless a device identity, an
// account session, and at least one pending marker are all present. The sequencer's keep/clear/ack rules are
// unit-tested in device-grant-resume; here is only the IO it drives.
let deviceGrantResumeBusy = false;
async function maybeResumeDeviceGrants() {
  if (deviceGrantResumeBusy) return;
  const dir = app.getPath('userData');
  if (!deviceIdentityLive()) return;                       // no device identity here → nothing to complete
  let hasPending = false;
  try { hasPending = devicePending.listPending(safeStorage, dir).length > 0; } catch { hasPending = false; }
  if (!hasPending) return;                                 // fast path: nothing waiting
  const origin = serverConfig.readServerOrigin(dir);
  if (!origin) return;
  const accountToken = await resolveAccountToken();
  if (!accountToken) return;                               // grant-create needs the account session
  let deviceId = null;
  try {
    const read = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin);
    if (read) { if (typeof read.deviceId === 'string') deviceId = read.deviceId; if (read.secret) { try { deviceSecretStore.zeroizeSecret(read.secret); } catch { /* best-effort */ } read.secret = null; } }
  } catch { /* fall through: no id → skip */ }
  if (!deviceId) return;
  deviceGrantResumeBusy = true;
  const pulledStamp = new Map(); // vaultId → the unlock stamp used this pass, to attribute a wrong-password to it
  try {
    const out = await resumePendingGrants({
      listPending: () => devicePending.listPending(safeStorage, dir),
      isConfigured: (id) => syncConfiguredIds().includes(id),
      // Granted before → a re-proof: run the active-grant guard so a revoked grant is never reactivated. A
      // never-granted vault (a first setup) skips the guard (it reactivates nothing). An UNREADABLE record is
      // passed through as 'unreadable' — NOT collapsed to first-setup — so the sweep DEFERS on it rather than
      // silently re-granting a vault whose grant the owner may have revoked (unreadable must fail CLOSED).
      wasGranted: (id) => { const h = deviceGrantHistory(dir, id); return h === 'unreadable' ? 'unreadable' : h === 'granted'; },
      checkActiveGrant: (id) => checkActiveDeviceGrant(id),
      vaultRequiresPassword: (id) => vaultRequiresPassword(id),
      pullPassword: async (id) => {
        const u = await pullVaultUnlock(id); // unlock-state, fresh, single-use — same as the mint
        if (!u) return null;
        if (deviceGrantFailedUnlock.get(id) === u.stamp) return null; // this exact unlock already failed → wait for a newer one (limiter gate)
        pulledStamp.set(id, u.stamp);
        return u.password;
      },
      grant: async ({ vaultId, vaultPassword }) => {
        const entry = syncConfigList().find((e) => e.vaultId === vaultId);
        const r = await deviceGrant.grantAndRecord({ serverOrigin: origin, accountToken, deviceId, vaultId, vaultType: 'standard', vaultName: entry ? entry.vaultName : '', vaultPassword, dir, safeStorage }, { fetchFn: mainHttpJson });
        if (r && r.ok) { deviceGrantFailedUnlock.delete(vaultId); return { ok: true }; }
        // A wrong password: remember this unlock so the next pass does not re-prove with it (one limiter burn, not one per tick).
        if (r && r.reason === 'wrong-password') { const st = pulledStamp.get(vaultId); if (st !== undefined) deviceGrantFailedUnlock.set(vaultId, st); }
        return { ok: false, reason: (r && r.reason) || 'grant-failed' };
      },
      clearPending: (id) => { devicePending.clearPending(safeStorage, dir, id); },
      ackComplete: (id) => { const entry = syncConfigList().find((e) => e.vaultId === id); ackDeviceSetupComplete(entry ? entry.vaultName : ''); },
    });
    if (out.granted.length) {
      // A re-proof that landed IS the answer these vaults were waiting on, so stop making them wait: the app
      // tells people that entering the vault password lets it try at once, and this is what makes that true.
      if (syncScheduler) syncScheduler.clearVaultPasswordRefusals(out.granted);
      invalidateMigrationView(); try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* best-effort */ } refreshTray(); } // a resumed grant wrote a record → the door drops that vault; reflect it, the next mint uses the device path
  } finally { deviceGrantResumeBusy = false; }
}

// ---------------------------------------------------------------------------------------------
// The sync setup wizard: an in-app window that walks through setting this computer up to sync (its own identity
// on the server), picking a vault, and choosing a folder — replacing the tray-driven dialogs. The flow itself is
// sync-wizard.js (a conversation of typed questions and answers); this is the window, the wiring of every side
// effect, and the single-flight guard shared with the other sync flows.
let wizardWindow = null;
let wizardInstance = null;

function wizardState() { return wizardInstance ? wizardInstance.currentQuestion() : null; }
function wizardAnswer(args) {
  if (!wizardInstance || !args || typeof args.id !== 'number') return false;
  return wizardInstance.answer(args.id, args.value);
}
function closeSyncWizard() {
  if (wizardInstance) wizardInstance.cancel();
  const win = wizardWindow;
  if (win && !win.isDestroyed()) { try { win.close(); } catch { /* already gone */ } }
}

async function openSyncWizard() {
  const existing = wizardWindow;
  if (existing && !existing.isDestroyed()) {
    // A wizard still asking: bring it forward. One that has finished (its last screen left open) is closed so
    // this click starts a fresh set-up rather than refocusing a stale statement.
    if (!(wizardInstance && wizardInstance.isFinished())) { try { existing.show(); existing.focus(); } catch { /* gone */ } return; }
    try { existing.close(); } catch { /* gone */ }
    wizardWindow = null; wizardInstance = null;
  }
  if (!syncHub) return;
  if (syncFlowBusy) return; // single-flight with the other sync flows: never two set-ups at once
  syncFlowBusy = true;
  let win = null;
  try {
    // Deliberately NOT a child of the main window: closing the app window "to the tray" destroys the main window,
    // and a child would go with it mid-set-up. The wizard stands on its own; the OS folder picker is parented to it.
    win = new BrowserWindow({
      width: 640, height: 760, minWidth: 520, minHeight: 560, show: false,
      title: 'DockVault — Set up sync', icon: APP_ICON, backgroundColor: '#0a0f18', autoHideMenuBar: true,
      webPreferences: {
        partition: UI_PARTITION, preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false,
        nodeIntegrationInWorker: false, webSecurity: true, allowRunningInsecureContent: false, spellcheck: false,
      },
    });
    wizardWindow = win;
    win.setMenuBarVisibility(false);
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.webContents.on('will-navigate', (e) => e.preventDefault()); // the wizard page never navigates anywhere
    const wizard = createSyncWizard(buildWizardIo(win), (q) => {
      try { if (!win.isDestroyed()) win.webContents.send('dockvault:evt:wizard', q); } catch { /* window gone */ }
    });
    wizardInstance = wizard;
    win.on('closed', () => {
      wizard.cancel(); // closing the window ends the flow wherever it stands; nothing is written after this
      if (wizardWindow === win) wizardWindow = null;
      if (wizardInstance === wizard) wizardInstance = null;
    });
    await win.loadURL(schemeMod.shellPageUrl(APP_ORIGIN, WIZARD_PAGE));
    win.show();
    // Resolves at the terminal statement — the window stays so the person can read it — or at a cancel, which
    // closes the window: a "Not now" or "Cancel" means "take me out of here", not a blank screen.
    const result = await wizard.run();
    if (result && result.kind === 'cancelled') { try { if (!win.isDestroyed()) win.close(); } catch { /* gone */ } }
  } catch {
    try { if (win && !win.isDestroyed()) win.close(); } catch { /* best-effort */ }
  } finally {
    syncFlowBusy = false;
  }
}

// ---------------------------------------------------------------------------------------------
// The Computers view: an in-app window listing the account's registered computers and this computer's synced
// vaults, with the actions that end a sync. The model and the action rules are manage-view.js; this is the
// window, the io over the real stores and routes, and the refresh push.
let manageWindow = null;
let manageInstance = null;

function closeManageView() {
  const win = manageWindow;
  if (win && !win.isDestroyed()) { try { win.close(); } catch { /* gone */ } }
}
function manageModel() { return manageInstance ? manageInstance.model() : null; }
async function manageAct(args) {
  if (!manageInstance) return { ok: false, reason: 'refused' };
  const kind = args && args.kind;
  const touchesIdentity = kind === 'revoke-grant' || kind === 'revoke-computer' || kind === 'remove-computer' || kind === 'stop-sync';
  if (!touchesIdentity) return manageInstance.act(args);
  // The same single-flight the wizard and the other sync flows share: a revoke never runs while a set-up is
  // between registering and recording, and vice versa.
  if (syncFlowBusy) return { ok: false, reason: 'busy' };
  syncFlowBusy = true;
  try { return await manageInstance.act(args); } finally { syncFlowBusy = false; }
}
// Tell an open Computers window that what it shows may have changed (a sync ran, a set-up finished).
function notifyManageChanged() {
  const win = manageWindow;
  if (win && !win.isDestroyed()) { try { win.webContents.send('dockvault:evt:manage', { at: Date.now() }); } catch { /* gone */ } }
}

async function openManageView() {
  const existing = manageWindow;
  if (existing && !existing.isDestroyed()) { try { existing.show(); existing.focus(); } catch { /* gone */ } return; }
  let win = null;
  try {
    win = new BrowserWindow({
      width: 760, height: 720, minWidth: 560, minHeight: 480, show: false,
      title: 'DockVault — Computers & synced folders', icon: APP_ICON, backgroundColor: '#0a0f18', autoHideMenuBar: true,
      webPreferences: {
        partition: UI_PARTITION, preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false,
        nodeIntegrationInWorker: false, webSecurity: true, allowRunningInsecureContent: false, spellcheck: false,
      },
    });
    manageWindow = win;
    manageInstance = createManageView(buildManageIo());
    win.setMenuBarVisibility(false);
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.webContents.on('will-navigate', (e) => e.preventDefault());
    win.on('closed', () => { if (manageWindow === win) { manageWindow = null; manageInstance = null; } });
    await win.loadURL(schemeMod.shellPageUrl(APP_ORIGIN, MANAGE_PAGE));
    win.show();
  } catch {
    try { if (win && !win.isDestroyed()) win.close(); } catch { /* best-effort */ }
  }
}

// ---------------------------------------------------------------------------------------------
// The synced folder's identity (folder-marker.js / folder-identity.js): the marker is written at set-up, read
// before every run, followed when the folder moves, and — when the folder cannot be found — the person is
// offered to point at it or to stop. Nothing below ever writes into a folder whose marker does not match.

// Hide the marker on Windows (a dot-name is already hidden elsewhere). Best-effort, asynchronous, never awaited.
function hideFile(p) {
  if (process.platform !== 'win32') return;
  const attrib = path.join(process.env.SystemRoot || 'C:\\Windows', 'System32', 'attrib.exe'); // by full path: never resolved through the cwd or PATH
  try { execFile(attrib, ['+h', String(p)], { windowsHide: true }, () => { /* the marker works unhidden too */ }); } catch { /* best-effort */ }
}

function markFolderFor(folder, vaultId) {
  const m = folderMarker.readMarker(folder);
  const same = m.kind === 'ok' && m.vaultId === String(vaultId).toLowerCase();
  const syncId = same ? m.syncId : folderMarker.newSyncId();
  if (!same) folderMarker.writeMarker(folder, { syncId, vaultId }, { hide: hideFile });
  return { syncId, markerId: folderMarker.markerIdentity(folder) };
}

// A search for a moved folder walks the disk with a budget; it is not repeated on every routine tick. A
// deliberate action (Sync now, the relocate offer, a set-up) clears the throttle so the next look is fresh.
const FOLDER_SEARCH_EVERY_MS = 10 * 60 * 1000;
const folderSearchAt = new Map(); // syncId -> when the last full search ran
function forgetFolderSearches() { folderSearchAt.clear(); }

function resolveFolderFor(cfg) {
  const dir = app.getPath('userData');
  const home = app.getPath('home');
  const io = {
    readMarker: (folder) => folderMarker.readMarker(folder),
    writeMarker: (folder, ids) => folderMarker.writeMarker(folder, ids, { hide: hideFile }),
    markerIdentity: (folder) => folderMarker.markerIdentity(folder),
    find: ({ syncId, vaultId, lastPath }) => {
      const last = folderSearchAt.get(syncId) || 0;
      if (Date.now() - last < FOLDER_SEARCH_EVERY_MS) return { kind: 'not-found', exhausted: false };
      folderSearchAt.set(syncId, Date.now());
      return folderMarker.findFolderByMarker({ syncId, vaultId, lastPath, roots: [home] });
    },
    classify: (folder, vaultId) => classifyFolderFor(folder, vaultId),
    repoint: (entry, { localFolder, syncId, markerId, movedFrom }) => {
      const next = { ...entry, localFolder, syncId };
      if (markerId) next.markerId = markerId;
      if (movedFrom) next.movedFrom = movedFrom;
      const list = syncConfig.upsertEntry(storedConfig(), syncConfig.makeConfigEntry(next));
      syncConfigStore.saveConfig(safeStorage, dir, list); // throws CONFIG_UNREADABLE rather than clobber
      folderSearchAt.delete(syncId);
      if (localFolder !== entry.localFolder) { try { console.log('[sync] a synced folder was found at its new location and is followed'); } catch { /* ignore */ } }
      refreshTray();
      notifyManageChanged();
    },
  };
  return folderIdentity.resolveSyncFolder(cfg, io);
}

// The placement rules for a folder standing in for `vaultId`'s (its own current entry is not an overlap).
function classifyFolderFor(folder, vaultId) {
  const dir = app.getPath('userData');
  const home = app.getPath('home');
  const ctx = {
    home, userData: dir,
    refuseRoots: syncConfig.platformRefuseRoots(process.platform, process.env),
    existingFolders: storedConfig().filter((e) => e.vaultId !== vaultId).map((e) => e.localFolder),
    caseInsensitive: process.platform === 'win32' || process.platform === 'darwin',
  };
  try { return syncConfig.classifyLocalTarget(realFolderPath(folder), ctx); } catch { return { ok: false, reason: 'folder-rejected' }; }
}
function realFolderPath(folder) {
  const real = fs.realpathSync.native || fs.realpathSync;
  try { return real(folder); } catch { try { return fs.realpathSync(folder); } catch { return path.resolve(folder); } }
}

// The relocate-or-stop offer for a vault whose folder cannot be found. Native dialogs, main-driven: the person
// either points at the folder (only the one carrying THIS sync's marker is accepted — a look-alike is refused
// with the reason and the offer stays), stops syncing it here (the local pointer is dropped; files are never
// touched), or leaves it paused. Shares the single-flight with the other set-up flows.
async function relocateFolder(vaultId) {
  if (syncFlowBusy) return;
  syncFlowBusy = true;
  try {
    const dir = app.getPath('userData');
    let entry = null;
    try { entry = storedConfig().find((e) => e.vaultId === vaultId) || null; } catch { entry = null; }
    if (!entry) return;
    const name = entry.vaultName || 'this vault';
    forgetFolderSearches();
    // One more look before asking — the folder may have come back (a drive plugged in, a rename undone).
    let found = null;
    try { found = await resolveFolderFor(entry); } catch { found = null; }
    if (found && found.ok) { refreshTray(); notifyManageChanged(); void tickSync({ manual: true }); return; }
    const reason = (found && found.reason) || 'folder-missing';
    const candidates = (found && Array.isArray(found.folders)) ? found.folders : [];
    const placement = (found && found.placement) || null;
    const findLabel = findVerb(reason);
    let detail = relocateDetail(name, entry.localFolder, reason, candidates, placement);
    for (;;) {
      let res;
      try {
        res = await dialog.showMessageBox(mainWindow, {
          type: 'warning', title: `Where is ${name}'s folder?`, noLink: true,
          message: `The folder for ${name} can't be synced right now`, detail,
          buttons: ['Not now', 'Stop syncing here', findLabel], defaultId: 2, cancelId: 0,
        });
      } catch { return; }
      if (!res || res.response === 0) return;
      if (res.response === 1) {
        // Stop: confirmed like the card's own button, then the local pointer goes; the files stay wherever they are.
        let sure;
        try {
          sure = await dialog.showMessageBox(mainWindow, {
            type: 'question', title: 'Stop syncing', noLink: true,
            message: `Stop syncing ${name} on this computer?`,
            detail: `The files stay where they are, and the vault on the server is untouched. To sync ${name} here again, run Set up sync… from the tray.`,
            buttons: ['Cancel', 'Stop syncing'], defaultId: 0, cancelId: 0,
          });
        } catch { return; }
        if (!sure || sure.response !== 1) continue;
        try { syncConfigStore.saveConfig(safeStorage, dir, syncConfig.removeEntry(storedConfig(), vaultId)); }
        catch (e) { await infoBox('Stop syncing', configWriteTrouble(e)); continue; }
        // The marker belonged to this sync: take it off wherever the folder is known to be (the old place, or the copies found).
        if (entry.syncId) for (const f of [entry.localFolder, ...candidates]) { try { folderMarker.removeMarker(f, entry.syncId); } catch { /* best-effort */ } }
        forgetVaultHistory(vaultId);
        try { deviceGrantStore.removeGrantMeta(safeStorage, dir, vaultId); } catch { /* best-effort */ }
        try { devicePending.clearPending(safeStorage, dir, vaultId); } catch { /* best-effort */ }
        try { if (credCache) credCache.clear(); } catch { /* best-effort */ }
        try { if (syncHub) syncHub.setVaults(storedConfig().map((e) => e.vaultId)); } catch { /* best-effort */ }
        refreshTray(); notifyManageChanged();
        return;
      }
      // Find: the OS picker, then the marker must match. A refusal offers another try or a way out, without
      // re-reading the whole offer each time.
      for (;;) {
        let picked = null;
        try {
          const r = await dialog.showOpenDialog(mainWindow, { title: `Choose ${name}'s folder`, defaultPath: candidates[0] || undefined, properties: ['openDirectory'] });
          picked = (r.canceled || !r.filePaths || !r.filePaths[0]) ? null : r.filePaths[0];
        } catch { picked = null; }
        if (!picked) break; // back to the offer
        picked = realFolderPath(picked); // the real place, after any link — what set-up records too
        const check = folderIdentity.checkRelocation(entry, picked, { readMarker: (f) => folderMarker.readMarker(f), markerIdentity: (f) => folderMarker.markerIdentity(f), classify: (f, v) => classifyFolderFor(f, v) });
        if (!check.ok) {
          const words = relocateRefusal(name, check.reason);
          let again;
          try {
            again = await dialog.showMessageBox(mainWindow, { type: 'info', title: words.title, noLink: true, message: words.title, detail: words.detail, buttons: ['Not now', 'Try another folder'], defaultId: 1, cancelId: 0 });
          } catch { return; }
          if (!again || again.response !== 1) return;
          continue;
        }
        try {
          // The old path rides along until a run completes at the new one, so the engine carries its listings over.
          const next = { ...entry, localFolder: picked, movedFrom: entry.movedFrom || entry.localFolder };
          if (check.markerId) next.markerId = check.markerId; // the person confirmed this one: it is the folder from here on
          const list = syncConfig.upsertEntry(storedConfig(), syncConfig.makeConfigEntry(next));
          syncConfigStore.saveConfig(safeStorage, dir, list);
        } catch (e) { await infoBox('Find the folder', configWriteTrouble(e)); return; }
        // The copies that were NOT chosen stop being recognised as this sync's folder, so a stray copy is never followed later.
        if (entry.syncId) for (const c of candidates) { if (realFolderPath(c) !== picked) { try { folderMarker.removeMarker(c, entry.syncId); } catch { /* best-effort */ } } }
        refreshTray(); notifyManageChanged();
        void tickSync({ manual: true });
        return;
      }
    }
  } finally { syncFlowBusy = false; }
}

// A sync stopped here: the helper forgets the vault's run history and listings, so a later set-up starts with
// a fresh baseline rather than a repair against state from a folder that is gone.
function forgetVaultHistory(vaultId) {
  try { if (daemon) daemon.forgetVault(vaultId); } catch { /* best-effort */ }
}

// Whether a presented host key line ("<type> <base64>") is one of the pinned lines (comma-joined OpenSSH public
// key lines, each possibly carrying a trailing comment). Compared on type + key material only.
function pinAccepts(pinned, presented) {
  const norm = (line) => String(line).trim().split(/\s+/).slice(0, 2).join(' ');
  const want = norm(presented);
  return String(pinned).split(',').some((k) => norm(k) === want);
}

function infoBox(title, detail) {
  try { return dialog.showMessageBox(mainWindow, { type: 'info', title, noLink: true, message: title, detail, buttons: ['OK'] }).then(() => undefined).catch(() => undefined); } catch { return Promise.resolve(); }
}

// Why the sync settings could not be written: the one known cause has its own remedy (the same sentence the
// Computers window shows); anything else is a plain try-again.
function configWriteTrouble(e) {
  if (e && e.code === 'CONFIG_UNREADABLE') return 'Your sync settings could not be read, so nothing was changed. This usually clears up after unlocking your login keychain and reopening DockVault.';
  return "DockVault couldn't update its sync settings just now. Nothing was changed. Try again in a moment.";
}

// The words for the offer: what is known, what is not, and what each button does. Paths named here are the
// person's own, shown on their own screen only. "Marker" is explained once, in the trailer.
function relocateDetail(name, lastPath, reason, candidates, placement) {
  const where = `It was at ${lastPath}.`;
  let what;
  switch (reason) {
    case 'folder-marker-missing': what = `${where} A folder is there now, but it isn't the one DockVault was syncing. If you moved the original folder, find it; if you made a fresh folder on purpose, stop syncing here and set ${name} up again.`; break;
    case 'folder-other-vault': what = `${where} The folder there now is synced by a different vault. Find ${name}'s own folder, or stop syncing here.`; break;
    case 'folder-marker-unreadable': what = `${where} The folder there has a DockVault marker file that can't be read, so DockVault can't tell whether it is ${name}'s folder. If it is, choose Stop syncing here, then Set up sync… from the tray and pick this same folder; nothing in it is lost.`; break;
    case 'folder-ambiguous': what = `${where} Two or more folders now look like ${name}'s (a copy was made):\n${candidates.map((c) => `• ${c}`).join('\n')}\nChoose the one to keep syncing (the picker opens at the first); the others are left as they are.`; break;
    case 'folder-moved-rejected': what = `${where} It is now at ${candidates[0] || 'a new location'}, but DockVault doesn't sync there (${placementWords(placement)}). Move the folder back, or to a folder of your own like Documents, then press Find the folder… and point at it — or stop syncing here.`; break;
    case 'folder-found-elsewhere': what = `${where} A folder that looks like ${name}'s is at ${candidates[0] || 'another place'}, but it isn't the same folder as before — it may be a copy of it, or the folder may have moved to another drive. If it is the right one, press Confirm the folder… and pick it; DockVault syncs it from here on. If not, find the right folder, or stop syncing here.`; break;
    case 'folder-marker-unwritable': what = `${where} DockVault can't write its hidden marker file there — the folder may be read-only. Make the folder writable and press Find the folder… to pick it again, or stop syncing here.`; break;
    default: what = `${where} It may have been moved, renamed, or deleted, or it may be on a drive that isn't plugged in. Nothing is synced until it is found, and no files are touched meanwhile. If you plug the drive back in or put the folder back, syncing carries on by itself.`;
  }
  return `${what}\n\n${findVerb(reason)} lets you point at it; DockVault accepts only the same folder, which it knows by the hidden marker file it left there when the sync was set up. Stop syncing here forgets this sync on this computer. Either way, your files and the vault on the server are not touched.`;
}
function findVerb(reason) { return reason === 'folder-ambiguous' ? 'Choose the folder…' : (reason === 'folder-found-elsewhere' ? 'Confirm the folder…' : 'Find the folder…'); }

// The placement rule a found folder fell foul of, in a few words (the setup screen's own refusal sentences carry more).
function placementWords(reason) {
  switch (reason) {
    case 'system-location': return "it's a system folder";
    case 'home-root-or-above': return "it's your whole home folder, or above it";
    case 'filesystem-root': return "it's the top of a drive";
    case 'app-data-dir': return "it's inside DockVault's own data";
    case 'overlaps-another-sync': return "it's inside, or around, another synced folder";
    case 'inside-cloud-sync': return "it's inside a cloud storage folder, which would sync the same files twice";
    default: return "it's not a place DockVault syncs";
  }
}

// A refused pick: what that folder is, and what to do instead. Each ends with a way forward.
function relocateRefusal(name, reason) {
  switch (reason) {
    case 'no-marker': return { title: `That isn't ${name}'s folder`, detail: `That isn't the folder DockVault was syncing for ${name}. If you want ${name} in a different folder, choose Not now, then Stop syncing here, then Set up sync… from the tray and pick that folder.` };
    case 'other-sync': return { title: `That isn't ${name}'s folder`, detail: `That folder is synced by a different vault, not ${name}. Point at the folder ${name} was using, or stop syncing here.` };
    case 'marker-unreadable': return { title: `That folder can't be recognised`, detail: `That folder has a DockVault marker file that can't be read, so DockVault can't tell whether it is ${name}'s folder. If it is, choose Not now, then Stop syncing here, then Set up sync… from the tray and pick this same folder; nothing in it is lost.` };
    case 'folder-missing': return { title: `That folder can't be opened`, detail: "DockVault can't open that folder. Check it is still there and try again, or choose Not now." };
    default: return { title: `${name}'s folder can't be synced there`, detail: `That is ${name}'s folder, but DockVault doesn't sync in that place (${placementWords(reason)}). Move the folder somewhere of your own, like Documents, then try again.` };
  }
}

// ---------------------------------------------------------------------------------------------
// The Troubleshoot view: a window of checks a person runs from this computer (troubleshoot.js owns the checks
// and their words); this is the window and the io over the saved server setting and the real network.
let troubleshootWindow = null;
let troubleshootInstance = null;

function closeTroubleshoot() {
  const win = troubleshootWindow;
  if (win && !win.isDestroyed()) { try { win.close(); } catch { /* gone */ } }
}

async function openTroubleshoot() {
  const existing = troubleshootWindow;
  if (existing && !existing.isDestroyed()) { try { existing.show(); existing.focus(); } catch { /* gone */ } return; }
  let win = null;
  try {
    win = new BrowserWindow({
      width: 860, height: 680, minWidth: 640, minHeight: 480, show: false,
      title: 'DockVault — Troubleshoot', icon: APP_ICON, backgroundColor: '#0a0f18', autoHideMenuBar: true,
      webPreferences: {
        partition: UI_PARTITION, preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false,
        nodeIntegrationInWorker: false, webSecurity: true, allowRunningInsecureContent: false, spellcheck: false,
      },
    });
    troubleshootWindow = win;
    troubleshootInstance = createTroubleshoot({
      serverState: () => serverConfigState(),
      // The same verify the setup screen runs, over main's request helper and the real SSH probe; it reads the
      // saved addresses main itself passed in and contacts nothing else.
      verify: (fields) => verifySetup(fields, { httpJson: mainHttpJson }),
    });
    win.setMenuBarVisibility(false);
    win.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    win.webContents.on('will-navigate', (e) => e.preventDefault());
    win.on('closed', () => { if (troubleshootWindow === win) { troubleshootWindow = null; troubleshootInstance = null; } });
    await win.loadURL(schemeMod.shellPageUrl(APP_ORIGIN, TROUBLESHOOT_PAGE));
    win.show();
  } catch {
    try { if (win && !win.isDestroyed()) win.close(); } catch { /* best-effort */ }
  }
}

// The one fix the view offers: reach the server setup — the change-server flow when a server is in force,
// the setup screen itself when none is. The view closes only once the setup is really taking over: a consent
// declined leaves the person exactly where they were, with the checks still in front of them.
async function openServerSetupFromTroubleshoot() {
  const s = serverConfigState();
  if (s.origin && s.status !== 'env') { await changeServer({ onConsent: closeTroubleshoot }); return; }
  closeTroubleshoot();
  await showOrCreateWindow();
}

function buildManageIo() {
  const dir = app.getPath('userData');
  const origin = () => serverConfig.readServerOrigin(dir);
  const metaDeviceId = () => { try { const m = deviceSecretStore.readIdentityMeta(safeStorage, dir); return m && typeof m.deviceId === 'string' ? m.deviceId : null; } catch { return null; } };
  const hasIdentityBlob = () => { try { return !!deviceSecretStore.readDeviceIdHint(dir); } catch { return false; } }; // the advisory sidecar survives an undecryptable blob
  const accountCall = async (method, pathname) => {
    const o = origin();
    const token = await resolveAccountToken();
    if (!o || !token) return { ok: false, reason: 'no-session' };
    let res;
    try { res = await mainHttpJson(`${o}${pathname}`, deviceRegister.accountInit(token, method)); } catch { return { ok: false, reason: 'network' }; }
    const s = (res && res.status) || 0;
    if (s === 200) {
      // Only a 200 carrying the route's JSON object confirms the change: a front that answers 200 with a page for
      // a route it does not know must never be read as "revoked" (the same rule the capability probe applies).
      let body = null;
      try { body = await res.json(); } catch { body = null; }
      return body && typeof body === 'object' && !Array.isArray(body) ? { ok: true } : { ok: false, reason: 'indeterminate' };
    }
    if (s >= 200 && s < 300) return { ok: false, reason: 'indeterminate' };
    return { ok: false, reason: s === 404 ? 'not-found' : (s === 401 || s === 403 ? 'auth' : 'refused') };
  };
  const dropLocalVault = (vaultId) => {
    // The local pointer: the sync entry (may throw CONFIG_UNREADABLE rather than clobber), the grant record,
    // and any pending marker. The folder and its files are left alone — except its hidden identity marker,
    // which belonged to this sync and goes with it (only when it is this sync's own; best-effort).
    const gone = storedConfig().find((e) => e.vaultId === vaultId);
    syncConfigStore.saveConfig(safeStorage, dir, syncConfig.removeEntry(storedConfig(), vaultId));
    if (gone && gone.syncId) { try { folderMarker.removeMarker(gone.localFolder, gone.syncId); } catch { /* best-effort */ } }
    forgetVaultHistory(vaultId);
    try { deviceGrantStore.removeGrantMeta(safeStorage, dir, vaultId); } catch { /* best-effort */ }
    try { devicePending.clearPending(safeStorage, dir, vaultId); } catch { /* best-effort */ }
    try { if (credCache) credCache.clear(); } catch { /* best-effort */ }
  };
  return {
    signedIn: () => { try { return !!(origin() && ((sessionBundle && sessionBundle.authToken) || (tokenStore.loadSession(safeStorage, dir) || {}).authToken)); } catch { return false; } },
    listDevices: async () => {
      const o = origin();
      const token = await resolveAccountToken();
      if (!o || !token) return { ok: false, reason: 'auth' };
      const r = await deviceRegister.checkDeviceSyncSupported({ serverOrigin: o, accountToken: token }, mainHttpJson);
      if (!r.supported) return { ok: false, reason: r.reason };
      deviceMigrateSupport = { origin: o, reason: 'ok' };
      return { ok: true, devices: r.devices };
    },
    // The identity's status and id from the NON-SECRET read (the meta decrypts nothing the menu path would not),
    // so building the view never materialises the device secret; only myGrants presents it, briefly.
    myIdentity: () => {
      const o = origin();
      if (!o) return { status: 'absent', deviceId: null };
      try {
        if (deviceSecretStore.hasRotatingMarker(dir)) return { status: 'rechecking', deviceId: metaDeviceId() };
        if (deviceSecretStore.isMarkedStale(dir) || deviceIdentityStale) return { status: 'stale', deviceId: metaDeviceId() };
        const meta = deviceSecretStore.readIdentityMeta(safeStorage, dir);
        if (!meta) return { status: hasIdentityBlob() ? 'unreadable' : 'absent', deviceId: null };
        if (!deviceSecretStore.sameOrigin(meta.serverOrigin, o)) return { status: 'absent-for-this-server', deviceId: null };
        return { status: 'ok', deviceId: typeof meta.deviceId === 'string' ? meta.deviceId : null };
      } catch { return { status: 'unreadable', deviceId: null }; }
    },
    grantRecord: () => {
      const gm = deviceGrantStore.readGrantMeta(safeStorage, dir);
      if (deviceGrantStore.isUnreadable(gm.status)) return { status: 'unreadable', has: () => false };
      const meta = (gm && gm.meta) || {};
      return { status: gm.status === 'absent' ? 'absent' : 'ok', has: (id) => Object.prototype.hasOwnProperty.call(meta, id) };
    },
    reasonText: (live, name) => {
      // The card's sentence comes from the SAME copy source as the tray, so the two can never tell different
      // stories about one vault. Three layers, most specific first:
      //   1. the enriched sentence, when this reason has one — it names the file, the size the server stated,
      //      the room the vault has left, or how long the wait is, from THIS vault's own outcome detail. It is
      //      tried for EVERY state, not just the alarming ones: the calm paused reasons (a server limiting
      //      attempts, a server with no room) are precisely the ones a short glance-suffix under-explains.
      //   2. a decision or a problem: the actionable must-act line, so the card says what to do rather than
      //      leaving a calm restatement while the tray offers the next step.
      //   3. the short glance suffix, as a sentence.
      // A reason with none of the three yields null and the card simply shows no note — never a raw token.
      const rich = trayPresentation.reasonSentence(live.reason, { name, detail: live.detail, retryAt: live.retryAt, repairOwed: !!live.resyncRequired });
      if (rich) return rich;
      if (live.state === 'needs-decision' || live.state === 'sync-problem') {
        const item = trayPresentation.itemForVault({ vault: live.vault, reason: live.reason, detail: live.detail, retryAt: live.retryAt, resyncRequired: live.resyncRequired }, name ? { [live.vault]: name } : {});
        if (item && item.label) return item.label;
      }
      const detail = trayPresentation.REASON_DETAIL[live.reason];
      if (detail) return detail.charAt(0).toUpperCase() + detail.slice(1) + '.';
      return null;
    },
    myGrants: async () => {
      if (deviceIdentityStale) return { ok: false, reason: 'device-secret-stale' };
      let id;
      try { id = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin()); } catch { return { ok: false, reason: 'device-secret-unreadable' }; }
      if (!id || id.status !== 'ok') { if (id && id.secret) { try { deviceSecretStore.zeroizeSecret(id.secret); } catch { /* best-effort */ } id.secret = null; } return { ok: false, reason: 'device-identity-missing' }; }
      try { return await deviceGrant.listMyGrants({ serverOrigin: origin(), deviceSecret: id.secret, dir, safeStorage }, { fetchFn: mainHttpJson }); }
      finally { try { deviceSecretStore.zeroizeSecret(id.secret); } catch { /* best-effort */ } id.secret = null; }
    },
    configured: () => storedConfig().map((e) => ({ vaultId: e.vaultId, vaultName: e.vaultName, localFolder: e.localFolder, enabled: e.enabled !== false })),
    liveStatus: () => (syncHub ? syncHub.current() : { vaults: [] }),
    endpoint: () => ({ serverHost: origin() ? serverProbe.hostOf(origin()) : '', sftp: serverConfig.readSftpEndpoint(dir) }),
    remotePathFor: (vaultId, via, vaultName) => (via === 'device' ? deviceRemotePath(vaultId) : (vaultName ? syncConfig.remotePathForVault(vaultName) : null)),
    revokeGrant: (deviceId, vaultId) => accountCall('POST', `/devices/${encodeURIComponent(deviceId)}/grants/${encodeURIComponent(vaultId)}/revoke`),
    revokeDevice: (deviceId) => accountCall('POST', `/devices/${encodeURIComponent(deviceId)}/revoke`),
    deleteDevice: (deviceId) => accountCall('DELETE', `/devices/${encodeURIComponent(deviceId)}`),
    dropLocalVault,
    relocateFolder: (vaultId) => { void relocateFolder(vaultId); },
    dropLocalIdentity: () => {
      // This computer's identity ended on the server: it can never be presented again, so clear it here along with
      // the records that belong to it. The sync entries stay (the honest "removed — set it up again" state), the
      // synced files are untouched.
      try { deviceSecretStore.clearDeviceSecret(dir); } catch { /* best-effort */ }
      try { devicePending.clearAllPending(safeStorage, dir); } catch { /* best-effort */ }
      try { if (credCache) credCache.clear(); } catch { /* best-effort */ }
      deviceIdentityStale = false;
      deviceUnreadableStreak = 0;
      syncIdentityChanged();
    },
    syncNow: (vaultId) => syncVaultNow(vaultId),
    afterChange: () => {
      try { if (syncHub) syncHub.setVaults(storedConfig().map((e) => e.vaultId)); } catch { /* config unreadable */ }
      try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* best-effort */ }
      invalidateMigrationView();
      refreshTray();
      void tickSync();
    },
  };
}

// Every side effect the wizard's conversation needs, over the same pieces the tray flows used: the enable io's
// checks and save, the device io's register and grant (ONE instance, so a fresh registration's id serves the
// grants that follow), the setup screen's SFTP verify, and the app's own reactions.
function buildWizardIo(win) {
  const dir = app.getPath('userData');
  const home = app.getPath('home');
  const caseInsensitive = process.platform === 'win32' || process.platform === 'darwin';
  const base = buildEnableIo();
  const dev = buildDeviceEnableIo(null);
  let existingLabels = [];
  // NOT syncIdentityChanged(): the wizard signals this at the end of its grant-only flows too, where this
  // computer's identity did not change at all. Clearing the back-off there would let anyone empty a
  // rate-limited server's wait at will, just by adding another folder — the flood, through a wider door.
  // The one place the wizard DOES create an identity is register(), which calls it there.
  const reflect = () => {
    try { if (syncHub) syncHub.setDeviceLive(deviceIdentityLive()); } catch { /* best-effort */ }
    invalidateMigrationView();
    refreshTray();
    void tickSync();
  };
  return {
    gather: async () => {
      const origin = serverConfig.readServerOrigin(dir);
      const token = await resolveAccountToken();
      const signedIn = !!(origin && token);
      let support = 'indeterminate';
      if (signedIn) {
        try {
          const r = await deviceRegister.checkDeviceSyncSupported({ serverOrigin: origin, accountToken: token }, mainHttpJson);
          support = r.reason;
          if (Array.isArray(r.devices)) existingLabels = r.devices.map((d) => d && d.label).filter((l) => typeof l === 'string');
          deviceMigrateSupport = { origin, reason: r.reason }; // the tray's door reads this too
          invalidateMigrationView();
        } catch { support = 'indeterminate'; }
      }
      let deviceStatus = 'unreadable';
      let otherServerHost = null;
      try {
        const read = deviceSecretStore.readDeviceSecret(safeStorage, dir, origin);
        deviceStatus = (read && read.status) || 'absent';
        if (read && read.status === 'absent-for-this-server' && read.otherOrigin) otherServerHost = serverProbe.hostOf(read.otherOrigin);
        if (read && read.secret) { try { deviceSecretStore.zeroizeSecret(read.secret); } catch { /* best-effort */ } read.secret = null; }
      } catch { deviceStatus = 'unreadable'; }
      if (deviceStatus === 'stale' && !deviceIdentityStale) { try { if (deviceSecretStore.hasRotatingMarker(dir)) deviceStatus = 'rechecking'; } catch { /* keep stale */ } }
      let configUnreadable = false;
      try { configUnreadable = syncConfigStore.isUnreadable(syncConfigStore.readConfigState(safeStorage, dir).status); } catch { configUnreadable = true; }
      const sftp = origin ? serverConfig.readSftpEndpoint(dir) : null;
      const suggestion = origin ? sftpEndpoint.suggestSftpEndpoint(origin) : null;
      let existing = [];
      try {
        existing = storedConfig()
          .filter((e) => e && typeof e.vaultId === 'string' && e.vaultId && deviceGrantHistory(dir, e.vaultId) === 'first-setup')
          .map((e) => ({ vaultId: e.vaultId, vaultName: e.vaultName || e.vaultId, hasPassword: vaultRequiresPassword(e.vaultId) }));
      } catch { existing = []; }
      return {
        signedIn, support, deviceStatus, otherServerHost,
        sftpSaved: !!sftp, sftpSuggestion: suggestion ? sftpEndpoint.formatSftpEndpoint(suggestion) : '',
        configUnreadable, label: deviceRegister.suggestDeviceLabel(existingLabels), existing,
      };
    },
    verifySftp: async (text) => {
      const parsed = sftpEndpoint.parseSftpEndpoint(text);
      if (parsed.kind !== 'ok') return { kind: parsed.kind, host: '', port: 0 };
      let r;
      try { r = await probeSftp({ host: parsed.host, port: parsed.port }); } catch { r = { kind: 'unreachable', host: parsed.host, port: parsed.port }; }
      const out = { kind: r.kind, host: r.host, port: r.port };
      if (r.kind === 'ok') out.fingerprint = r.fingerprint; // never the key line: the pin comes from the vault's answer
      return out;
    },
    saveSftp: (ep) => serverConfig.writeSftpEndpoint(dir, ep, serverConfig.readServerOrigin(dir)),
    registration: { probe: dev.probe, readStatus: dev.readStatus, forget: dev.forget, register: dev.register },
    grantVault: dev.grantVault,
    addPending: (vaultId) => devicePending.addPending(safeStorage, dir, vaultId),
    enable: {
      listVaults: base.listVaults,
      someExcluded: () => lastSomeExcluded,
      configuredFolder: (vaultId) => { try { const e = storedConfig().find((x) => x.vaultId === vaultId); return (e && e.localFolder) || null; } catch { return null; } },
      vaultHasPassword: (vaultId) => vaultRequiresPassword(vaultId),
      resolveReal: base.resolveReal,
      classifyCtx: base.classifyCtx,
      inspectFolderSharing: base.inspectFolderSharing,
      makePrivate: base.makePrivate,
      isNonEmptyDir: base.isNonEmptyDir,
      ensureFolder: base.ensureFolder,
      markFolder: base.markFolder,
      save: base.save,
    },
    pickFolderNative: async () => {
      const res = await dialog.showOpenDialog(win, { title: 'Choose a folder to sync into', properties: ['openDirectory', 'createDirectory'] });
      return (res.canceled || !res.filePaths || !res.filePaths[0]) ? null : res.filePaths[0];
    },
    consentNotes: ({ vaultId, folder }) => {
      let priorFolder = null;
      try { const prior = storedConfig().find((e) => e.vaultId === vaultId); if (prior && prior.localFolder && prior.localFolder !== folder) priorFolder = prior.localFolder; } catch { priorFolder = null; }
      // Windows does not enforce owner-only folder permissions, so a folder outside the user profile can be readable
      // by other local accounts; the consent says so for such a target.
      const outsideProfile = process.platform === 'win32' && !syncConfig.isWithin(folder, home, caseInsensitive);
      return { priorFolder, outsideProfile };
    },
    cloudServiceName: (folder) => enableCopy.cloudServiceName(folder),
    copy: {
      refuse: (reason) => enableCopy.refuseMessage(reason),
      cloud: (service) => enableCopy.cloudWarnMessage(service),
      consent: (vaultName, folder, o) => enableCopy.consentMessage(vaultName, folder, o),
      deviceOutcome: (r, ctx) => enableCopy.deviceOutcomeCopy(r, ctx).message,
    },
    afterSave: () => {
      try { if (syncHub) syncHub.setVaults(storedConfig().map((e) => e.vaultId)); } catch { /* config unreadable */ }
      refreshTray();
      notifyManageChanged();
      // Kick the first sync right away instead of leaving the freshly-enabled vault at "set up - not running yet"
      // until the next routine tick. Via tickSync so the run-state snapshot is refreshed with the new id list first.
      void tickSync();
    },
    onIdentityChanged: () => { reflect(); notifyManageChanged(); },
  };
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
    n.on('click', () => { void openSyncWizard(); });
    n.show();
  } catch { /* best-effort */ }
}

// The one-time existing-setup migration nudge — the maybeOfferSyncSetup shape, for a desktop already syncing on
// the account path. Probes the server's device-sync support, caches it (so the standing tray door can be derived
// without a per-refresh network call), and — only when the offer actually applies AND it has not been shown for
// THIS server origin — fires ONE notification whose click opens the setup. Fail-quiet on every uncertain edge:
// not signed in, or a transport error, shows nothing and marks nothing, so a person is never nudged (or told
// their server is old) because they were merely offline; the flag is keyed by origin, so a server switch (or a
// hatch reset, which clears it) offers again, but a decline never re-nudges on the same server.
async function maybeOfferDeviceMigration() {
  if (!syncHub || SMOKE) return;
  const dir = app.getPath('userData');
  const origin = serverConfig.readServerOrigin(dir);
  const token = await resolveAccountToken(); // live token, not the boot snapshot
  if (!origin || !token) return; // not signed in yet — fail-quiet, retry on a later unlock
  let probe;
  try { probe = await deviceRegister.checkDeviceSyncSupported({ serverOrigin: origin, accountToken: token }, mainHttpJson); }
  catch { return; } // transport — cache nothing wrong, retry later
  deviceMigrateSupport = { origin, reason: probe.reason }; // known now: the door derives from this
  invalidateMigrationView(); // the support input just changed → recompute rather than serve the cached view
  refreshTray(); // reflect the door/switch/too-old line the fresh support enables
  const m = computeMigration(dir);
  if (!m.notify) return; // door doesn't apply, or already offered for this origin, or support unknown/too-old
  if (!Notification || !Notification.isSupported || !Notification.isSupported()) return; // can't notify; the door still stands
  try {
    const n = new Notification({ title: 'DockVault', body: 'This computer can now sync on its own, even while the screen is locked — set it up any time from the tray menu.' });
    n.on('click', () => { void openSyncWizard(); });
    n.show();
    writeState({ deviceMigrationOfferOrigin: origin }); // shown once for this origin: a decline won't re-nudge; a server switch will
  } catch { /* best-effort; the standing door still carries the offer */ }
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
  win.webContents.on('will-navigate', (e, url) => {
    if (!url.startsWith(APP_ORIGIN)) { e.preventDefault(); return; }
    // The shell's own pages are reached only through the main process: content the server supplied
    // may never navigate INTO them (so it cannot even show the setup screen), and a shell page never
    // navigates AWAY on its own (so a frame that passed the sender check cannot be repurposed).
    const shell = APP_ORIGIN + schemeMod.SHELL_PATH;
    let current = '';
    try { current = win.webContents.getURL() || ''; } catch { current = ''; }
    if (url.startsWith(shell) || current.startsWith(shell)) e.preventDefault();
  });

  if (!bootSelfTest || !bootSelfTest.ok) {
    status.failCode = (bootSelfTest && bootSelfTest.code) || 'UNKNOWN';
    await loadFailInto(win, status.failCode);
    if (!SMOKE) win.show();
    return win;
  }

  // With no real OS secret store the app still loads and is fully interactive (memory-only): at-rest
  // persistence and background sync are withheld elsewhere, not the interface. The session store
  // already returned nothing to seed in that case, so a fresh sign-in is required each launch.
  // No server known (nothing saved, or a saved setting that cannot be read), or the person chose to
  // switch: the setup screen is what opens, never a web UI with nowhere to send its calls. The smoke
  // check keeps the plain path so it asserts the UI load as before.
  const srv = serverConfigState();
  if (!SMOKE && (setupMode === 'change' || !srv.origin)) {
    await win.loadURL(schemeMod.shellPageUrl(APP_ORIGIN, SETUP_PAGE));
    win.show();
    wireCloseToTray(win);
    wireBoundsPersistence(win);
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
  // A freshly (re-)created window starts from the authoritative state. It carries no zero-knowledge key
  // (the renderer's key is memory-only and died with any prior window), so re-showing requires re-auth
  // until an unlock flow marks it unlocked; the renderer is told the current state so it never assumes.
  if (lockState) pushLockState(lockState.isUnlocked() ? 'unlocked' : 'locked', null);
  return win;
}

async function loadFailInto(win, code) {
  await win.loadURL(schemeMod.shellPageUrl(APP_ORIGIN, FAIL_PAGE));
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

// ---------------------------------------------------------------------------------------------
// DOCKVAULT_TRAY_SELFTEST — the autonomous (a)/(b) tray check for the two SILENT merge modes this file hits
// when the device-sync assembly is brought together with the rest of the app (modelled on DOCKVAULT_SMOKE above):
//   (a) RENDER — a refreshTray that draws the menu WITHOUT the device assembly (the failure a two-argument
//       buildTrayMenu call produces: migration is null, so the migration door, the pending "finish setting up"
//       reminder and the escape-hatch reset offer silently never appear);
//   (b) CLICK  — a drawn menu whose click handlers reference a function the merge deleted (openSyncWizard,
//       resetDeviceIdentity, runDeviceSetupAgain), so the menu draws and the click throws ReferenceError.
// Neither mode lives in Electron's Tray/Menu layer; both live in this module's JavaScript, so an in-module
// check proves them and an OS click adds nothing. State is forced through the EXISTING module seams (the config
// store, the pending-grant store, the migration-support / unreadable-streak module vars) — NO real device
// secret is written: an ABSENT identity keeps the migration door applicable while deviceIdentityStale makes the
// pending reminder live, so the check can neither leak a secret nor forget a real identity. The (b) clicks run
// with the module's own single-flight guard (syncFlowBusy) set, so each device flow returns at its first line —
// no dialog, no network, no forget — while a DELETED function still throws at the click reference BEFORE that
// guard runs, which is exactly the mode (b) must catch.

// Invoke a captured click handler and record whether it settles without throwing. A function the merge dropped
// throws ReferenceError SYNCHRONOUSLY at the call below — the (b) failure — and is recorded false.
async function settlesNoThrow(name, clickFn, record) {
  if (typeof clickFn !== 'function') { record(name, false, 'click handler missing from the drawn menu'); return; }
  try {
    const r = clickFn();                            // a dropped-function reference throws HERE, synchronously
    if (r && typeof r.then === 'function') await r; // a returned thenable must also settle without rejecting
    record(name, true);
  } catch (e) { record(name, false, String((e && e.message) || e)); }
}

async function finishTraySelftestIfNeeded() {
  if (!TRAY_SELFTEST) return;
  // ISOLATION (fail-closed): refuse UNLESS an explicit --user-data-dir override is present, regardless of packaging.
  // An unpackaged run with no override would land on the DEFAULT profile, where the seed replaces the server origin
  // and the whole sync config — so require the override always (it is how every packaged *-check.js and this check
  // are launched). NEVER a real profile, so it cannot touch a person's data.
  if (!app.commandLine.hasSwitch('user-data-dir')) {
    try { console.warn('[dockvault] DOCKVAULT_TRAY_SELFTEST ignored: no --user-data-dir override (refusing to touch a real profile)'); } catch { /* ignore */ }
    return;
  }
  const rows = [];
  const record = (row, ok, note) => { rows.push(note === undefined ? { row, ok } : { row, ok, note }); };
  const dir = app.getPath('userData');
  try {
    if (!tray) {
      record('tray-available', false, 'no system tray in this environment — cannot self-test the tray');
    } else {
      const VAULT = { vaultId: 'selftest-vault', vaultName: 'Self-Test Vault' };
      // Seed the door's, the pending reminder's and the reset offer's inputs through EXISTING seams only.
      // A throwaway server origin is REQUIRED: deviceIdentityLive() (which gates the pending reminder) fails
      // closed to false when no server is configured, so without it the pending row never draws. The `.invalid`
      // TLD never resolves (RFC 6761), and syncFlowBusy (set before the clicks) short-circuits every device
      // flow at its first line anyway, so no request is ever attempted against it.
      const ORIGIN = serverConfig.writeServerOrigin(dir, 'https://tray-selftest.invalid');
      try { syncConfigStore.saveConfig(safeStorage, dir, [{ vaultId: VAULT.vaultId, vaultName: VAULT.vaultName, localFolder: path.join(dir, 'selftest-folder'), remotePath: 'selftest', enabled: true, consented: true }]); }
      catch (e) { record('seed-config', false, String((e && e.message) || e)); }
      try { devicePending.addPending(safeStorage, dir, VAULT.vaultId); } catch (e) { record('seed-pending', false, String((e && e.message) || e)); }
      deviceMigrateSupport = { origin: ORIGIN, reason: 'ok' };    // device support 'ok' for THIS origin (matches computeMigration's readServerOrigin)
      deviceIdentityStale = true;                                 // with an origin set, deviceIdentityLive() -> true on an ABSENT identity, so the pending reminder draws
      deviceUnreadableStreak = DEVICE_UNREADABLE_RESET_THRESHOLD; // the escape-hatch reset offer crosses its threshold
      invalidateMigrationView();                                  // MUST: boot cached an empty pre-seed migration view (2s TTL) — drop it so the door recomputes

      // (a) RENDER — capture the menu refreshTray draws (and the tooltip it sets) WITHOUT changing either.
      let menu = null, tip = null;
      const protoSetMenu = tray.setContextMenu, protoSetTip = tray.setToolTip;
      tray.setContextMenu = function (m) { menu = m; return protoSetMenu.call(tray, m); };
      tray.setToolTip = function (s) { tip = s; return protoSetTip.call(tray, s); };
      try { refreshTray(); } finally { delete tray.setContextMenu; delete tray.setToolTip; }
      const items = (menu && Array.isArray(menu.items)) ? menu.items : [];
      const labels = items.map((it) => (it && typeof it.label === 'string') ? it.label : '');
      // The reset + pending EXPECTED strings come from their OWN presentation functions — immune to wording
      // drift, and present in the drawn menu only if refreshTray actually ran the device assembly (mode (a)). The
      // sync door is drawn whenever the hub is up, so its RENDER row only proves the entry exists; its CLICK row
      // below is what catches a deleted openSyncWizard (mode (b)).
      const RESET = trayPresentation.deviceResetItem().label;
      const pendingItems = trayPresentation.pendingSetupItems([VAULT.vaultId], { nameById: { [VAULT.vaultId]: VAULT.vaultName }, wasGranted: () => false, alreadyShown: () => false });
      const PENDING = (pendingItems[0] && pendingItems[0].label) || '<<no pending item produced>>';
      const DOOR_PHRASE = 'Set up sync…';
      record('render-sync-door', labels.some((l) => l === DOOR_PHRASE));
      record('render-troubleshoot-door', labels.includes('Troubleshoot…'));
      record('render-pending-setup', labels.includes(PENDING));
      record('render-reset-offer', labels.includes(RESET));
      // tooltip lock-reason path: a paused-locked model + a 'sleep' reason reads the sleep glance. The tooltip's
      // 4th parameter is the lock reason on this branch and an options object on the merged tree, so try the branch
      // shape first and fall back to the object — the assertion then holds on BOTH with no merge-side edit.
      const lockedModel = { condition: 'paused', state: 'paused', reason: 'locked', vaults: [] };
      const readsSleep = (arg) => { const t = trayPresentation.tooltip(lockedModel, 'locked', '0.0.0', arg); return typeof t === 'string' && t.includes('paused since sleep'); };
      record('tooltip-lock-reason', readsSleep('sleep') || readsSleep({ lockReason: 'sleep' }));
      // The tooltip SERVER-truth: with no server in force the glance says so, and it OUTRANKS the lock — tooltip
      // reads the server before every lock and state branch, so even a paused-locked model reads "Not connected"
      // rather than a lock phrase with nothing behind it. The `server` option exists only once the two sides are
      // together, so this assertion cannot be written on either branch alone; it is what the merge owes the check.
      record('tooltip-server-truth',
        trayPresentation.tooltip(lockedModel, 'locked', '0.0.0', { server: { origin: null } }) === 'DockVault — Not connected');
      record('refreshtray-set-tooltip', typeof tip === 'string' && tip.length > 0);

      // (b) CLICK — the door + reset (and set-up-again) handlers resolve without a dropped-function throw.
      try { dialog.showMessageBox = () => Promise.resolve({ response: 0 }); } catch { /* belt-and-suspenders; syncFlowBusy short-circuits before any dialog anyway */ }
      syncFlowBusy = true; // the module's own single-flight guard: every device flow returns at its first line
      const door = items.find((it) => it && it.label === DOOR_PHRASE);
      const reset = items.find((it) => it && it.label === RESET);
      await settlesNoThrow('click-sync-door', door && door.click, record);
      await settlesNoThrow('click-reset-offer', reset && reset.click, record);
      await settlesNoThrow('click-set-up-again', () => handleMustAct({ kind: 'set-up-again' }), record);
    }
  } catch (e) {
    record('selftest-harness', false, String((e && e.message) || e));
  }
  const ok = rows.every((r) => r.ok !== false); // a null row (a documented re-merge fold) does not fail the run
  try {
    const outDir = path.join(__dirname, '..', '..', '.local');
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(path.join(outDir, 'tray-selftest.json'), JSON.stringify({ ok, rows }, null, 2));
  } catch { /* best effort */ }
  // Tear the background workers down EXPLICITLY, then app.exit() with the REAL code. Two facts force this shape:
  // app.exit() skips the before-quit handler (:162) that stops the daemon, so its rclone child would be orphaned;
  // but app.quit() does NOT honour process.exitCode (it exits 0 regardless), which would make this check vacuously
  // green on failure. So stop the daemon and auto-lock here as before-quit would, then app.exit(ok ? 0 : 1) so the
  // exit code is the true pass/fail.
  try { if (autoLock) autoLock.stop(); } catch { /* best-effort */ }
  try { if (daemon) daemon.stop(); } catch { /* best-effort */ }
  app.exit(ok ? 0 : 1);
}

module.exports = { __private: { readState, writeState, openSyncWizard, openManageView, openTroubleshoot, tickSync, relocateFolder, handleMustAct } }; // exposed only for tests

// ---------------------------------------------------------------------------------------------
// Start at login. One honest fact, read from the platform every time (login-item.js); the person's
// explicit choice lives in the data folder and only decides whether the app may register itself
// unasked (an installed app's first launch), never what the checkbox shows.
let loginItemInstance = null;
function loginItem() {
  if (!loginItemInstance) {
    loginItemInstance = loginItemMod.createLoginItem({
      app, platform: process.platform, fs, homeDir: app.getPath('home'), env: process.env, execPath: process.execPath,
    });
  }
  return loginItemInstance;
}
function loginChoice() { return loginItemMod.createLoginChoiceStore({ fs, dir: app.getPath('userData') }); }

function maybeRegisterLoginItem() {
  try {
    const store = loginChoice();
    const d = loginItemMod.decideOnLaunch({ storedChoice: store.read(), isPackaged: app.isPackaged });
    if (!d.register) return;
    // The read-back, not the intent: a platform that refuses without throwing leaves it off, and the
    // notice then points at the switch rather than claiming it will start. The choice is stored either
    // way so this never runs unasked again.
    const registered = loginItem().setEnabled(true) === true;
    store.write(registered);
    refreshTray();
    if (d.notify) notifyInstalled(registered);
  } catch { /* the checkbox keeps showing the real state; nothing else to do */ }
}

function toggleLoginItem() {
  try {
    const on = !loginItem().isEnabled();
    loginItem().setEnabled(on);
    loginChoice().write(on);
  } catch { /* leave the real state to the menu */ }
  refreshTray();
}

// The one notification of an installed app's first launch: the visible result of a silent one-click
// install AND the disclosure of the login item, with where to turn it off. Best-effort, like every toast.
function notifyInstalled(registered) {
  try {
    if (!Notification || !Notification.isSupported || !Notification.isSupported()) return;
    const msg = trayPresentation.installedNotification(process.platform, registered);
    const n = new Notification({ title: msg.title, body: msg.body });
    n.on('click', () => { void showOrCreateWindow(); });
    n.show();
  } catch { /* notifications are best-effort */ }
}

// ---------------------------------------------------------------------------------------------
// The server setting: which server is in force, the setup screen, and switching servers. Main owns the
// route, the normalisation, and the write; the screen only ever sees a kind and a host.
let setupMode = null; // 'change' while the person is switching servers; null otherwise
let changeHost = null; // the old server's host, kept in memory only to pre-fill the field during a switch
let changeSftp = null; // likewise the old server's SFTP address ("host:port")

function serverConfigState() {
  try { return serverConfig.readServerConfigState(app.getPath('userData')); }
  catch { return { status: 'unreadable', origin: null, envOrigin: null, fileOrigin: null, envOverrides: false, sftp: null }; }
}

// The screen's two intents, answered by server-setup.js (the probe, the unreadable-confirm rule, the
// atomic write, the degraded hold); this file only supplies the window-side effects.
let serverSetupInstance = null;
function serverSetup() {
  if (!serverSetupInstance) {
    serverSetupInstance = serverSetupMod.createServerSetup({
      dir: app.getPath('userData'), httpJson: mainHttpJson, mode: () => setupMode, changeHost: () => changeHost, changeSftp: () => changeSftp,
      // Saving the server opens the sign-in page and nothing else: sync is set up separately, from its
      // own flow, and only when the person asks for it.
      onSaved: () => { setupMode = null; changeHost = null; changeSftp = null; refreshTray(); void openSignInAfterSetup(); },
    });
  }
  return serverSetupInstance;
}
function serverScreenState() { return serverSetup().state(); }
function checkServer(args) { return serverSetup().check(args); }
function connectServer(args) { return serverSetup().connect(args); }

// Swap the setup screen for the real UI through the one normal path (session seed, renderer probe, lock
// state), so a first run and a later run look the same from here on.
async function openSignInAfterSetup() {
  const win = mainWindow;
  if (win && !win.isDestroyed()) { try { win.destroy(); } catch { /* already gone */ } }
  mainWindow = null;
  try { await showOrCreateWindow(); } catch { /* the tray still offers Open DockVault */ }
}

// Switching servers is a relationship end: the session, the sync credential, the sync setup and this
// computer's registration all belong to the old server, so they are forgotten BEFORE the new address is
// asked for. Every step is best-effort — a person who chose to leave is never left stuck on the old server.
// Resolves true once the person consented (the switch is then under way), false when they did not.
// `onConsent` runs right after the consent, before the old relationship is forgotten — for a caller with a
// window of its own to take down.
async function changeServer({ onConsent = null } = {}) {
  const s = serverConfigState();
  const consent = trayPresentation.changeServerConsent(s.origin ? serverProbe.hostOf(s.origin) : '');
  let res;
  try {
    res = await dialog.showMessageBox(mainWindow, {
      type: 'question', title: consent.title, noLink: true, message: consent.message,
      buttons: consent.buttons, defaultId: 0, cancelId: 0,
    });
  } catch { return false; }
  if (!res || res.response !== 1) return false;
  if (onConsent) { try { onConsent(); } catch { /* the caller's window is not load-bearing */ } }
  changeHost = s.origin ? serverProbe.hostOf(s.origin) : null;
  changeSftp = s.sftp ? sftpEndpoint.formatSftpEndpoint(s.sftp) : null;
  await forgetServerRelationship(s.origin);
  setupMode = 'change';
  refreshTray();
  const win = mainWindow;
  if (win && !win.isDestroyed()) {
    try { await win.loadURL(schemeMod.shellPageUrl(APP_ORIGIN, SETUP_PAGE)); win.show(); win.focus(); return true; } catch { /* recreate below */ }
  }
  await showOrCreateWindow();
  return true;
}

async function forgetServerRelationship(origin) {
  const dir = app.getPath('userData');
  let token = null;
  try { token = (sessionBundle && sessionBundle.authToken) || ((tokenStore.loadSession(safeStorage, dir) || {}).authToken) || null; } catch { token = null; }
  try { tokenStore.clearSession(dir); } catch { /* best effort */ }
  sessionBundle = null;
  try { if (credCache) credCache.clear(); } catch { /* best effort */ }
  try { if (daemon) await daemon.clearSftpCred(); } catch { /* best effort */ }
  try { syncConfigStore.saveConfig(safeStorage, dir, []); } catch { /* best effort */ }
  try { if (syncHub) syncHub.setVaults([]); } catch { /* best effort */ }
  try { await deviceForget({ origin, sessionToken: token }); } catch { /* best effort */ }
  token = null;
  try { if (uiSession) await uiSession.clearStorageData(); } catch { /* best effort */ }
  // The saved address goes too, so a quit and relaunch mid-switch lands on the setup screen with the
  // tray reading "Not connected", never back on the old server's sign-in.
  try { serverConfig.removeServerOrigin(dir); } catch { /* best effort */ }
  // Everything this computer synced through that server is gone, identity included. Whatever its door said
  // about a credential belongs to it, so it must not hold a vault set up against whatever comes next.
  syncIdentityChanged();
}

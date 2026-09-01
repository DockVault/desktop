'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the enable-sync flow and its store
 * work end to end against the REAL OS secret store, and the read-only preload surface is present.
 *
 * The native dialogs cannot be clicked in a headless run, so the picker/consent callbacks are
 * stubbed here (their branch logic is unit-tested separately); everything else is real — the flow
 * derives the remote from the vault, creates the folder owner-only, and persists a credential-free
 * record through the actual safeStorage-wrapped store, which then round-trips. A renderer with the
 * real preload is checked for the observe-only sync surface.
 * Writes .local/sync-enable-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/sync-enable-check.js
 */

const { app, BrowserWindow, session, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const syncEnable = require('../src/main/sync-enable');
const syncConfig = require('../src/main/sync-config');
const store = require('../src/main/sync-config-store');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
const RESULT = path.join(__dirname, '..', '.local', 'sync-enable-check.json');
const PARTITION = 'dockvault-ui';
const FORBIDDEN = ['password', 'hostKeys', 'credential', 'token', 'obscured', 'expiresAt', 'secret'];
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 30000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-enable-check-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-enable-home-'));
  const target = path.join(home, 'Vaults', 'Marketing');

  // Drive the REAL flow with stubbed dialogs; everything else (fs, store, derivation) is real.
  const io = {
    listVaults: async () => [{ vaultId: 'v1', vaultName: 'Marketing' }],
    pickVault: async (vs) => vs[0],
    pickFolder: async () => target,
    // Exercise the SAME resolver the app ships (realpathSync.native), so the check covers the win32
    // short-name / casing canonicalization that plain realpathSync would not.
    resolveReal: (p) => { const real = fs.realpathSync.native || fs.realpathSync; try { return real(p); } catch { try { return fs.realpathSync(p); } catch { return path.resolve(p); } } },
    classifyCtx: () => ({ home, userData: dir, refuseRoots: syncConfig.platformRefuseRoots(process.platform, process.env), existingFolders: store.loadConfig(safeStorage, dir).map((e) => e.localFolder) }),
    confirmCloud: async () => true,
    confirmConsent: async () => true,
    ensureFolder: (p) => { fs.mkdirSync(p, { recursive: true, mode: 0o700 }); try { fs.chmodSync(p, 0o700); } catch {} },
    onRefuse: async () => {},
    save: (entry) => { store.saveConfig(safeStorage, dir, syncConfig.upsertEntry(store.loadConfig(safeStorage, dir), entry)); },
  };

  const r = await syncEnable.runEnableFlow(io);
  out.flow = r;
  out.remoteDerived = !!(r.entry && r.entry.remotePath === 'Marketing'); // from the vault, not the folder
  out.folderExists = fs.existsSync(target);
  out.encAvailable = safeStorage.isEncryptionAvailable();
  const onDisk = JSON.parse(fs.readFileSync(store.configPath(dir), 'utf8'));
  out.wrappedMatchesStore = onDisk.enc === out.encAvailable; // encrypted iff the OS store is available
  const loaded = store.loadConfig(safeStorage, dir);
  out.roundTrip = loaded.length === 1 && loaded[0].vaultId === 'v1' && loaded[0].remotePath === 'Marketing';
  out.storeCredFree = FORBIDDEN.every((k) => !JSON.stringify(loaded).includes(k));
  // POSIX honours the folder mode; assert 0700 there, and just that it exists on Windows.
  out.perms = process.platform === 'win32' ? 'n/a-win32' : (fs.statSync(target).mode & 0o777).toString(8);
  out.permsOk = process.platform === 'win32' ? out.folderExists : (fs.statSync(target).mode & 0o777) === 0o700;

  // The renderer surface is OBSERVE-ONLY: sync.status + sync.onStatus exist; there is NO renderer
  // initiator or list (enabling/stopping is main-side only), so a page cannot start the native flow.
  const ses = session.fromPartition(PARTITION);
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, ses);
  const win = new BrowserWindow({ show: false, webPreferences: { partition: PARTITION, preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false } });
  await win.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`);
  out.hasStatus = await win.webContents.executeJavaScript(`typeof window.dockvault?.sync?.status === 'function'`, true);
  out.hasOnStatus = await win.webContents.executeJavaScript(`typeof window.dockvault?.sync?.onStatus === 'function'`, true);
  out.noSetup = await win.webContents.executeJavaScript(`typeof window.dockvault?.sync?.setup === 'undefined'`, true);
  out.noList = await win.webContents.executeJavaScript(`typeof window.dockvault?.sync?.list === 'undefined'`, true);
  win.destroy();

  try { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(home, { recursive: true, force: true }); } catch {}

  out.ok = !!(r.enabled && out.remoteDerived && out.folderExists && out.wrappedMatchesStore && out.roundTrip
    && out.storeCredFree && out.permsOk && out.hasStatus && out.hasOnStatus && out.noSetup && out.noList);
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

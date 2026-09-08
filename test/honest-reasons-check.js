'use strict';
/*
 * Live check (run under Electron against a RUNNING throwaway vault — not part of `npm test`): a sync that fails
 * for a REAL reason is named in plain words on the surfaces a person actually looks at.
 *
 * Everything here is real: the production scheduler wiring, the real forked sync helper, the bundled rclone, a
 * real device registration, and a throwaway vault created with a deliberately small allowance. Nothing about
 * the failure is simulated — the vault's own SFTP door refuses to keep a file that does not fit, exactly as it
 * would for a person, and the check reads back what the app would then say.
 *
 * The proof has three parts:
 *   1. the run is classified as the vault being out of room — NOT as the generic "this needs a repair" that
 *      bisync's own critical-error wording would otherwise produce, and not as a bare "couldn't sync";
 *   2. the sentence on the tray menu, the tray glance, the Computers card and the "Sync now" toast all name the
 *      real cause, and agree with each other;
 *   3. nothing any of them says is a raw error string or an internal token — the server's refusals name its own
 *      configuration settings, and those must never be quoted at a person.
 *
 * Isolation: its own temporary profile directory, its own throwaway vault (created and deleted here), a fresh
 * device registration that is forgotten at the end. Never a real profile, never a real vault. It draws only a
 * couple of credentials, and opens with a pause so it does not itself trip the server's per-address attempt
 * window, which is the thing that makes repeated live testing painful in the first place.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_INSECURE_TLS   1 to accept the test server's self-signed certificate (test servers only)
 *   DOCKVAULT_PROOF_PACE_MS        the opening pause that lets the server's attempt window pass (default 310000)
 *
 * Writes .local/honest-reasons-check.json (one row per proof step) and prints one PASS/FAIL line. Exit 0 = PASS.
 * No secret, token, or password is ever written to the result.
 *
 *   node_modules/electron/dist/electron.exe test/honest-reasons-check.js
 */
const { app, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DaemonManager } = require('../src/main/daemon-manager');
const { CredCache } = require('../src/main/cred-cache');
const { MintPathSelector } = require('../src/main/mint-path');
const { mintDeviceSftpAccess } = require('../src/main/device-mint');
const deviceSecretStore = require('../src/main/device-secret-store');
const deviceGrant = require('../src/main/device-grant');
const deviceGrantStore = require('../src/main/device-grant-store');
const { registerDevice, forgetDevice } = require('../src/main/device-register');
const rcloneBundle = require('../src/main/rclone-bundle');
const { SyncScheduler, MANUAL_SYNC_COOLDOWN_MS } = require('../src/main/sync-scheduler');
const schedulerIo = require('../src/main/scheduler-io');
const syncVaults = require('../src/main/sync-vaults');
const syncConfig = require('../src/main/sync-config');
const { SyncStatusHub } = require('../src/main/sync-status-hub');
const statusModel = require('../src/main/sync-status-model');
const tray = require('../src/main/tray-presentation');
const manualCopy = require('../src/main/manual-sync-copy');
const vaultSpace = require('../src/main/vault-space');

if (process.env.DOCKVAULT_PROOF_INSECURE_TLS === '1') app.commandLine.appendSwitch('ignore-certificate-errors'); // a TEST server's self-signed cert; never the app
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const PACE_MS = Math.max(0, Number(process.env.DOCKVAULT_PROOF_PACE_MS || 310000) | 0);
const RESULT = path.join(__dirname, '..', '.local', 'honest-reasons-check.json');

// The vault's allowance for this run, and a file comfortably larger than it. Small on purpose: the point is a
// refusal, not a transfer, so the bytes that move are trivial.
const VAULT_LIMIT_GB = 0.001;          // ~1 MB
const OVERSIZE_BYTES = 3 * 1024 * 1024;

// Anything a person reads must contain none of these: the app's own symbols, and the words the server's
// refusals are built from (they name the operator's tuning settings).
const NEVER_SHOWN = /upload-not-stored|file-too-large|server-no-space|vault-full|channel-refused|sync-server-refusing|auth-failed|needs-resync|host-key-mismatch|blocked-needs-resync|SSH_FX|staging buffer setting|maximum file size|sftp:|rclone|bisync|partial file rename|SetModTime|Move Rename/i;

const out = { api: API, rows: [], sentences: {} };
const secrets = [ADMIN_PW];
function row(name, ok, detail) { out.rows.push({ row: name, ok: !!ok, detail: detail === undefined ? null : detail }); }
function scrub(text) { let t = String(text); for (const s of secrets) if (s) t = t.split(s).join('[redacted]'); return t; }
function dump() {
  try {
    fs.mkdirSync(path.dirname(RESULT), { recursive: true });
    const text = JSON.stringify(out, null, 2);
    out.leakFree = secrets.every((s) => !s || !text.includes(s));
    fs.writeFileSync(RESULT, scrub(JSON.stringify(out, null, 2)));
  } catch { /* ignore */ }
}
const watchdog = setTimeout(async () => { row('watchdog', false, 'timed out'); await teardown(); dump(); app.exit(3); }, 30 * 60 * 1000);
app.on('window-all-closed', () => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function api(pathname, init = {}) {
  const res = await httpJson(`${API}${pathname}`, init);
  let body = null; try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}
const auth = (token, extra = {}) => ({ Authorization: `Bearer ${token}`, ...extra });
const jsonBody = () => ({ 'Content-Type': 'application/json' });
const cleanup = { steps: [] };
async function teardown() {
  for (const step of cleanup.steps.splice(0).reverse()) { try { await step(); } catch { /* best effort */ } }
}
async function settle(sch, maxMs = 5 * 60 * 1000) {
  const t0 = Date.now();
  while ((sch._busy || sch._queue.length) && Date.now() - t0 < maxMs) await sleep(50);
  await sleep(150);
}
// One sentence, checked the way a reader would be protected: it exists, it is not empty, and it contains
// nothing a person should never see.
function human(name, text) {
  const ok = typeof text === 'string' && text.trim().length > 0 && !NEVER_SHOWN.test(text);
  out.sentences[name] = text === undefined ? null : text;
  return ok;
}

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE to point at a throwaway server'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-reasons-'));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-reasons-files-'));
  cleanup.steps.push(() => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); });
  const local = path.join(work, 'synced'); fs.mkdirSync(local);
  fs.writeFileSync(path.join(local, 'note.txt'), `honest reasons proof ${crypto.randomBytes(8).toString('hex')}\n`);
  const rand = crypto.randomBytes(4).toString('hex');
  const VAULT_NAME = `Honest reasons proof ${rand}`;
  const OVERSIZE_NAME = 'holiday-video.bin';

  // ---- account-session set-up --------------------------------------------------------------------------------
  const login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { await teardown(); dump(); app.exit(2); return; }
  // A vault with a SMALL allowance: the refusal this check needs is the vault's own, and it is created here
  // rather than arranged by changing anything on the server.
  const vc = await api('/vaults', { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ name: VAULT_NAME, type: 'standard', size_limit_gb: VAULT_LIMIT_GB }) });
  const VID = vc.body && vc.body.id;
  row('create-small-vault', !!VID && (vc.body.size_limit || 0) > 0, { status: vc.status, limitBytes: vc.body && vc.body.size_limit });
  if (!VID) { await teardown(); dump(); app.exit(2); return; }
  cleanup.steps.push(() => api(`/vaults/${VID}/delete`, { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({}) }));

  // ---- this computer: register, grant, the real helper ---------------------------------------------------------
  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Honest reasons proof', dir, safeStorage }, { fetchFn: httpJson });
  row('register', reg.ok === true, reg.ok ? 'ok' : reg.reason);
  const DEVICE_ID = reg.deviceId;
  cleanup.steps.push(() => forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage }, { fetchFn: httpJson }));
  const g = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEVICE_ID, vaultId: VID, vaultType: 'standard', vaultName: VAULT_NAME, dir, safeStorage }, { fetchFn: httpJson });
  row('grant', g.ok === true, g.ok ? 'ok' : g.reason);

  const rc = rcloneBundle.resolveBundledRclone({ isPackaged: false, resourcesPath: process.resourcesPath, platform: process.platform, arch: process.arch, env: process.env });
  const mgr = new DaemonManager(dir, rc);
  cleanup.steps.push(() => { mgr.stop(); });
  const ready = new Promise((resolve) => mgr.on('ready', resolve));
  mgr.start();
  const r0 = await Promise.race([ready, sleep(15000).then(() => ({ type: 'timeout' }))]);
  const hs = await mgr.syncStatus(20000);
  row('helper-ready', r0 && r0.type === 'ready' && hs && hs.ok, { version: hs && hs.version });

  const withDeviceSecret = async (fn) => {
    const id = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
    if (id.status !== 'ok') { const e = new Error('device identity unavailable'); e.reason = 'device-request-refused'; throw e; }
    if (typeof id.secret === 'string' && !secrets.includes(id.secret)) secrets.push(id.secret);
    try { return await fn(API, id.secret); } finally { id.secret = null; }
  };
  const mintPath = new MintPathSelector({
    readSecret: () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); r.secret = null; return { status: r.status }; },
    listGrants: () => withDeviceSecret((origin, secret) => deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: secret, dir, safeStorage }, { fetchFn: httpJson })),
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
  });
  let mints = 0;
  const credCache = new CredCache({
    mint: async (vaultId) => {
      mints += 1;
      const b = await withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, httpJson));
      if (b && typeof b.password === 'string') secrets.push(b.password);
      return b;
    },
    send: (bundle, epoch) => mgr.sendSftpCred(bundle, 12000, epoch),
    epoch: () => mgr.currentEpoch(),
  });
  mgr.setCredProvider(async (vault) => (vault === VID ? credCache.ensureSent(vault) : { ok: false, reason: 'not-in-flight' }));

  // ---- the REAL scheduler + the REAL status sink over the production wiring -----------------------------------
  const runState = { value: null, fresh: true };
  const events = [];
  const hub = new SyncStatusHub({ hasSecureStore: true, online: true, locked: false });
  hub.setVaults([VID]);
  const cfg = () => [{ vaultId: VID, vaultName: VAULT_NAME, localFolder: local, remotePath: syncConfig.remotePathForVault(VAULT_NAME), enabled: true, consented: true }];
  const io = schedulerIo.makeSchedulerIo({
    listConfigured: cfg,
    snapshot: { get: () => runState.value, fresh: () => runState.fresh },
    fetchStandard: () => syncVaults.fetchStandardVaults({ serverOrigin: API, sessionToken: JWT }, httpJson),
    remotePathForVault: syncConfig.remotePathForVault,
    secureFolder: () => ({ ok: true }),
    classify: () => ({ ok: true }),
    isAccountUsable: () => true,
    hasAccount: () => true,
    hasDeviceIdentity: () => true,
    isOnline: () => true,
    credCache,
    daemon: mgr,
    confirmFirstUpload: async () => true,
    onEvent: (vaultId, ev) => {
      // Record the whole outcome, not a summary of it: the press's answer depends on `resyncRequired` (whether
      // the failure left a repair owed), and a lossy record here would test a sentence the app never composes.
      events.push({ phase: ev.phase, reason: ev.reason || null, result: (ev.outcome && ev.outcome.result) || null, detail: (ev.outcome && ev.outcome.detail) || null, resyncRequired: !!(ev.outcome && ev.outcome.resyncRequired), outcome: ev.outcome || null, retryAt: ev.retryAt != null ? ev.retryAt : null });
      schedulerIo.applySchedulerEvent(hub, vaultId, ev);   // the real sink: exactly what the tray reads
      const o = ev.outcome;
      if (o && (ev.phase === 'done' || ev.phase === 'error')) {
        const prior = runState.value || { lastResult: null, resyncRequired: false };
        runState.value = {
          lastResult: o.ran ? (o.result || prior.lastResult) : prior.lastResult,
          resyncRequired: typeof o.resyncRequired === 'boolean' ? o.resyncRequired : prior.resyncRequired,
        };
      }
    },
  });
  io.credentialPath = (vaultId) => mintPath.current(vaultId);
  io.verifyEligible = async (vaultId) => {
    const d = await mintPath.begin(vaultId);
    if (!d.ok) return d;
    return d.via === 'device' ? { ok: true, via: 'device', remotePath: d.remotePath, vaultName: d.vaultName } : { ok: false, reason: 'not-device-path' };
  };
  // The production wiring for the one question a space failure raises: the vault's own allowance, read from the
  // server over the account session. Nothing is claimed about space without it.
  io.vaultSpace = (vaultId) => vaultSpace.fetchVaultSpace({ serverOrigin: API, sessionToken: JWT, vaultId }, httpJson);
  const innerOnEvent = io.onEvent;
  io.onEvent = (vaultId, ev) => { innerOnEvent(vaultId, ev); if (ev && ['done', 'error', 'blocked', 'paused', 'skipped', 'refused', 'noop'].includes(ev.phase)) mintPath.end(vaultId); };
  const sch = new SyncScheduler(io);
  const lastDone = () => [...events].reverse().find((e) => e.phase === 'done') || null;

  // ---- baseline: a small file syncs cleanly, so the failure that follows is unambiguous -----------------------
  out.openingPaceMs = PACE_MS;
  await sleep(PACE_MS); // a fresh attempt window before the first credential of the run
  {
    const e0 = events.length;
    sch.requestSync(VID, { manual: true });
    await settle(sch);
    const le = lastDone();
    row('baseline-ok', !!le && /ok/.test(String(le.result)), { result: le && le.result, results: events.slice(e0).map((e) => e.result).filter(Boolean) });
    if (!le || !/ok/.test(String(le.result))) {
      out.serverJammed = 'the baseline did not complete — most likely the server was rate-limiting this address, so what follows would measure the server, not the app';
    }
  }

  // The baseline press started this vault's "Sync now" cooldown, so a second press right behind it would be
  // turned away without running (that is the previous phase working). Wait it out, so the failure below is
  // answered by a real run and a real press.
  await sleep(MANUAL_SYNC_COOLDOWN_MS + 3000);

  // ---- the real failure: a file the vault has no room for ----------------------------------------------------
  {
    fs.writeFileSync(path.join(local, OVERSIZE_NAME), crypto.randomBytes(OVERSIZE_BYTES));
    const e0 = events.length;
    const press = sch.requestSync(VID, { manual: true });
    row('the-press-was-accepted', press && press.accepted === true, press);
    await settle(sch);
    const le = lastDone();
    out.failure = { result: le && le.result, detail: le && le.detail };
    out.eventsAfterOversize = events.slice(e0);
    // 1. the classification: the vault's own numbers, not a guess, and NOT the generic repair
    row('names-the-vault-as-out-of-space', !!le && le.result === 'vault-full', le && le.result);
    row('not-the-generic-repair', !!le && !/needs-resync|blocked-needs-resync|^error$/.test(String(le.result)), le && le.result);
    row('carries-the-file-and-the-numbers',
      !!(le && le.detail && le.detail.file === OVERSIZE_NAME && le.detail.bytes >= OVERSIZE_BYTES && typeof le.detail.freeBytes === 'number'),
      le && le.detail);

    // 2. what a person is actually shown, read from the REAL status the sink computed
    const model = hub.current();
    const vault = model.vaults[0];
    out.vaultState = { state: vault.state, reason: vault.reason };
    const nameById = { [VID]: VAULT_NAME };
    const items = tray.mustActItems(model, nameById);
    const item = items.find((it) => it.vault === VID) || null;
    const tip = tray.tooltip(model, null, null, {});
    // The Computers card and the press answer are composed exactly as main composes them — including whether
    // the failed run left a repair owed, which decides how every one of these sentences ends. Composing them
    // any other way here would prove a sentence the app never actually shows.
    const card = tray.reasonSentence(vault.reason, { name: VAULT_NAME, detail: vault.detail, retryAt: vault.retryAt, repairOwed: !!vault.resyncRequired })
      || (item && item.label) || null;
    // Composed from the event the app itself would hand the toast — the whole outcome, unchanged.
    const toast = manualCopy.manualCompletionBody({ phase: 'done', outcome: le && le.outcome, retryAt: le && le.retryAt }, VAULT_NAME).body;

    // The vault had a little room left, just not enough for this file — so the honest sentence is that it
    // doesn't have room for THAT file, not the self-contradicting "out of space … 1 MB is free".
    const saysSpace = (t) => typeof t === 'string' && /doesn't have room for|is out of space/.test(t);
    row('tray-menu-offers-one-honest-line', !!item && human('trayItem', item.label) && saysSpace(item.label), item && item.label);
    row('tray-menu-action-is-one-the-app-can-perform', !!item && tray.HANDLED_ACTION_KINDS.includes(item.kind), item && item.kind);
    row('tray-glance-says-it-too', human('trayTooltip', tip) && /room/i.test(tip) && tip.length <= 127, { tip, length: tip.length });
    row('computers-card-says-it-too', human('computersCard', card) && saysSpace(card), card);
    row('sync-now-toast-says-the-same', human('syncNowToast', toast) && toast === card, toast);
    // The run left a repair owed, so every surface must say so — and none may promise a retry that the
    // repair-owed latch has already blocked.
    row('every-surface-names-the-repair-as-the-way-back',
      [item && item.label, card, toast].every((t) => typeof t === 'string' && /se Repair in the DockVault tray menu/.test(t)),
      { repairOwed: !!vault.resyncRequired });
    row('no-surface-promises-a-retry-that-cannot-happen',
      [item && item.label, card, toast].every((t) => typeof t === 'string' && !/will try again|will keep trying|continues on its own|Everything else keeps syncing/.test(t)),
      null);
    row('the-file-that-did-not-fit-is-named', [item && item.label, card, toast].every((t) => typeof t === 'string' && t.includes(OVERSIZE_NAME)), OVERSIZE_NAME);
    row('nothing-shown-is-a-raw-error-or-a-token',
      Object.entries(out.sentences).every(([, t]) => typeof t === 'string' && !NEVER_SHOWN.test(t)), Object.keys(out.sentences));

    // 3. and the model that crosses to a page carries no file name
    const pub = statusModel.publicStatus(model);
    row('no-file-name-crosses-to-a-page', !JSON.stringify(pub).includes(OVERSIZE_NAME), null);
  }

  // ---- clean up ----------------------------------------------------------------------------------------------
  await mgr.clearSftpCred(5000).catch(() => null);
  await teardown();
  await sleep(500);
  out.totalMints = mints;

  out.ok = out.rows.every((r) => r.ok);
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`${out.ok ? 'PASS' : 'FAIL'} honest-reasons-check (${out.rows.filter((r) => r.ok).length}/${out.rows.length}) result=${JSON.stringify(out.failure && out.failure.result)} mints=${out.totalMints}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch(async (e) => { out.fatal = scrub(String((e && e.stack) || e)); await teardown(); dump(); app.exit(2); });

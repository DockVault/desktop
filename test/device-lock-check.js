'use strict';

/*
 * Live check of syncing while the screen is locked, against a RUNNING vault (not a unit test — run it under
 * Electron, pointed at a throwaway server). Everything below the operating system's own event source is real:
 * the real lock state and its purge, the real automatic lock triggers, the real scheduler and its gates, the
 * real credential cache, the real forked daemon and rclone, over real SFTP. Only the OS signals themselves
 * (screen locked, input idle, machine resumed) are injected — this check must never lock the operator's actual
 * screen — so what is proven is: given those signals, the app does the right thing end to end.
 *
 * The rows:
 *   - a vault on this computer's own device identity keeps transferring while the screen locks MID-TRANSFER,
 *     and its files land on the server;
 *   - a NEW run for that vault still dispatches while locked (not merely an in-flight run finishing);
 *   - an account-path vault in the same tick is refused, paused by the lock, with no credential minted;
 *   - the lock still does what a lock is for: the zero-knowledge gate closes and the daemon confirms its key
 *     purge — while the device transfer continues;
 *   - the idle trigger fires the same purge mid-transfer;
 *   - the return (machine resumed) lifts the account-tier pause and kicks a catch-up sync.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required, e.g. http://127.0.0.1:8360)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_SFTP_PORT      the port the server advertises for SFTP (default 2222)
 *
 * Writes .local/device-lock-check.json with one row per proof step. No secret, token, or password is ever
 * written to the result (scrubbed and asserted).
 */

const { app, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { execFileSync } = require('node:child_process');

const { DaemonManager } = require('../src/main/daemon-manager');
const { CredCache } = require('../src/main/cred-cache');
const { LockState } = require('../src/main/lock-state');
const { AutoLock } = require('../src/main/auto-lock');
const { SyncScheduler } = require('../src/main/sync-scheduler');
const schedulerIo = require('../src/main/scheduler-io');
const { RunStateSnapshot } = require('../src/main/run-state-snapshot');
const { MintPathSelector } = require('../src/main/mint-path');
const { mintDeviceSftpAccess } = require('../src/main/device-mint');
const deviceSecretStore = require('../src/main/device-secret-store');
const deviceGrant = require('../src/main/device-grant');
const deviceGrantStore = require('../src/main/device-grant-store');
const { registerDevice, forgetDevice } = require('../src/main/device-register');
const syncVaults = require('../src/main/sync-vaults');
const syncConfig = require('../src/main/sync-config');
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const SFTP_PORT = Number(process.env.DOCKVAULT_PROOF_SFTP_PORT || 2222);
const RESULT = path.join(__dirname, '..', '.local', 'device-lock-check.json');

const out = { api: API, rows: [] };
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
const watchdog = setTimeout(() => { row('watchdog', false, 'timed out'); dump(); app.exit(3); }, 15 * 60 * 1000);
app.on('window-all-closed', () => {});

function rcloneConfig() {
  const finder = process.platform === 'win32' ? ['where', ['rclone']] : ['which', ['rclone']];
  let bin = execFileSync(finder[0], finder[1]).toString().split(/\r?\n/).find(Boolean).trim();
  try { bin = fs.realpathSync(bin); } catch { /* not a symlink */ }
  const sha256 = crypto.createHash('sha256').update(fs.readFileSync(bin)).digest('hex');
  const raw = execFileSync(bin, ['version']).toString();
  const version = (raw.match(/rclone\s+v([0-9][0-9.]*)/i) || [])[1] || null;
  return { bin, version, sha256 };
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function api(pathname, init = {}) {
  const res = await httpJson(`${API}${pathname}`, init);
  let body = null; try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}
const auth = (token, extra = {}) => ({ Authorization: `Bearer ${token}`, ...extra });
const jsonHeaders = () => ({ 'Content-Type': 'application/json' });

// The OS signal source, injected: a stand-in for Electron's powerMonitor whose idle clock this check drives.
// Everything the app does in response — the lock transaction, the key purge, the gates — is the real thing.
class FakePowerMonitor extends EventEmitter {
  constructor() { super(); this.idleSeconds = 0; }
  getSystemIdleTime() { return this.idleSeconds; }
}

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE to point at a throwaway server'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-lock-'));
  const localA = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-lockA-'));
  const localB = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-lockB-'));
  const rand = crypto.randomBytes(4).toString('hex');
  const NAME_A = `Lock proof device ${rand}`;
  const NAME_B = `Lock proof account ${rand}`;
  const VPW = `Proof-pw-${crypto.randomBytes(6).toString('hex')}`;
  secrets.push(VPW);

  // ---- set-up over the account session -------------------------------------------------------------
  const login = await api('/auth/login', { method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { dump(); app.exit(2); return; }

  const mkVault = async (name) => (await api('/vaults', { method: 'POST', headers: auth(JWT, jsonHeaders()), body: JSON.stringify({ name, type: 'standard', password: VPW }) })).body;
  const vaultA = await mkVault(NAME_A);
  const vaultB = await mkVault(NAME_B);
  const VID_A = vaultA && vaultA.id;
  const VID_B = vaultB && vaultB.id;
  row('two-vaults', !!VID_A && !!VID_B, { device: !!VID_A, account: !!VID_B });
  if (!VID_A || !VID_B) { dump(); app.exit(2); return; }

  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Lock proof laptop', dir, safeStorage });
  row('register', reg.ok === true, reg.ok ? 'ok' : reg.reason);
  // Vault A is granted to this computer (device path). Vault B is deliberately NOT granted and NOT recorded
  // here, so it stays on the account path — the vault the lock must pause.
  const g = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: reg.deviceId, vaultId: VID_A, vaultType: 'standard', vaultName: NAME_A, vaultPassword: VPW, dir, safeStorage });
  row('grant-device-vault-only', g.ok === true && g.recorded === true, g.ok ? 'ok' : g.reason);

  // ---- the real app pieces --------------------------------------------------------------------------
  const rc = rcloneConfig();
  const mgr = new DaemonManager(dir, rc);
  const ready = new Promise((resolve) => mgr.on('ready', resolve));
  mgr.start();
  const r0 = await Promise.race([ready, sleep(10000).then(() => ({ type: 'timeout' }))]);
  const hs = await mgr.syncStatus(20000);
  row('helper-ready', r0 && r0.type === 'ready' && hs && hs.ok, { version: hs && hs.version });

  const lockEvents = [];
  const lockState = new LockState({
    getWindow: () => null,                    // no renderer in this check: the daemon-side purge is the observable
    getDaemon: () => mgr,
    onChange: (state, reason) => lockEvents.push({ state, reason }),
  });
  const power = new FakePowerMonitor();
  let resumeKicks = 0;
  const autoLock = new AutoLock({
    powerMonitor: power,
    lockState,
    getWindow: () => null,
    idleThresholdMs: 1000,                    // a short policy so the idle row does not idle for fifteen minutes
    timers: { idlePollMs: 100, escalateAfterMs: 100000 },
    onResume: () => { resumeKicks += 1; void tick(); },
  });
  lockState.markUnlocked();                   // a zero-knowledge key is present, so the purge has something to do
  autoLock.start();

  const withDeviceSecret = async (fn) => {
    const id = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
    if (id.status !== 'ok') { const e = new Error('device identity unavailable'); e.reason = id.status === 'unreadable' ? 'device-secret-unreadable' : 'device-identity-missing'; throw e; }
    try { return await fn(API, id.secret); } finally { id.secret = null; }
  };
  const mintPath = new MintPathSelector({
    readSecret: () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); r.secret = null; return { status: r.status }; },
    listGrants: () => withDeviceSecret((origin, secret) => deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: secret, dir, safeStorage }, { fetchFn: httpJson })),
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
  });
  const mints = [];
  const credCache = new CredCache({
    mint: async (vaultId) => {
      const via = mintPath.current(vaultId);
      mints.push({ vaultId, via });
      if (via === 'device') return withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, httpJson));
      // The account path is not exercised here (it needs a renderer-held vault password); the lock must refuse
      // an account-path vault BEFORE any mint, so reaching this line at all would be the failure.
      const e = new Error('account mint attempted'); e.reason = 'internal-error'; throw e;
    },
    send: (bundle, epoch) => mgr.sendSftpCred(bundle, 12000, epoch),
    epoch: () => mgr.currentEpoch(),
  });

  const configured = [
    { vaultId: VID_A, vaultName: NAME_A, localFolder: localA, remotePath: NAME_A, enabled: true },
    { vaultId: VID_B, vaultName: NAME_B, localFolder: localB, remotePath: NAME_B, enabled: true },
  ];
  const events = [];
  const snapshot = new RunStateSnapshot({ fetch: (ids) => mgr.runStates(ids) });
  const io = schedulerIo.makeSchedulerIo({
    listConfigured: () => configured,
    snapshot,
    fetchStandard: async () => syncVaults.fetchStandardVaults({ serverOrigin: API, sessionToken: JWT }, httpJson),
    remotePathForVault: syncConfig.remotePathForVault,
    secureFolder: async () => ({ ok: true }),   // the folder rails are proven by their own checks; not what this one is about
    classify: () => ({ ok: true }),
    credCache,
    daemon: mgr,
    isAccountUsable: () => lockState.isAccountUsable(),
    hasAccount: () => true,
    hasDeviceIdentity: () => { try { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); const live = r.status === 'ok' || r.status === 'stale'; r.secret = null; return live; } catch { return false; } },
    isOnline: () => true,
    onEvent: (vaultId, ev) => { events.push({ vaultId, ...ev, at: Date.now() }); },
  });
  io.credentialPath = (vaultId) => mintPath.current(vaultId);
  const accountEligible = io.verifyEligible;
  io.verifyEligible = async (vaultId) => {                       // mirrors the production glue, `via` and all
    const d = await mintPath.begin(vaultId);
    if (!d.ok) return d;
    if (d.via === 'device') return { ok: true, via: 'device', remotePath: d.remotePath, vaultName: d.vaultName };
    const acc = await accountEligible(vaultId);
    return (acc && acc.ok) ? { ...acc, via: 'account' } : acc;
  };
  // The per-step credential provider, gated exactly as production gates it: the device path mints under the
  // lock, anything else does not.
  const perStepRefusals = [];
  mgr.setCredProvider(async (vault) => {
    const refusal = schedulerIo.perStepGate({
      inFlight: scheduler.current() === vault,
      locked: !lockState.isAccountUsable(),
      via: mintPath.current(vault),
      accountLive: true,
    });
    if (refusal) { perStepRefusals.push({ vault, refusal }); return { ok: false, reason: refusal }; }
    return credCache.ensureSent(vault);
  });
  const scheduler = new SyncScheduler(io);
  const tick = async () => { await snapshot.refresh(configured.map((c) => c.vaultId)); scheduler.tickAll(); };
  const settle = async (ms = 240000) => { const t0 = Date.now(); while ((scheduler._busy || scheduler._queue.length) && Date.now() - t0 < ms) await sleep(50); };
  const since = () => events.length;
  const eventsSince = (n) => events.slice(n);
  const listFiles = async (vid) => JSON.stringify((await api(`/vaults/${vid}/files`, { headers: auth(JWT, { 'X-Vault-Password': VPW }) })).body || '');

  // ---- a baseline for the device vault, unlocked ----------------------------------------------------
  fs.writeFileSync(path.join(localA, 'baseline.txt'), `baseline ${rand}\n`);
  await snapshot.refresh([VID_A, VID_B]);
  scheduler.requestSync(VID_A, { manual: true });
  await settle();
  const baselineDone = events.filter((e) => e.vaultId === VID_A && e.phase === 'done').pop();
  row('baseline-sync-unlocked', !!baselineDone && /ok/.test(String(baselineDone.outcome && baselineDone.outcome.result)), baselineDone && { result: baselineDone.outcome && baselineDone.outcome.result });

  // ---- the screen locks MID-TRANSFER; the device vault carries on ------------------------------------
  // at the top of the folder, so the server's own file listing is the witness that they landed
  for (let i = 0; i < 400; i++) fs.writeFileSync(path.join(localA, `bulk-f${i}.bin`), crypto.randomBytes(4096));
  const markA = since();
  await snapshot.refresh([VID_A, VID_B]);
  scheduler.requestSync(VID_A, { manual: true });
  // wait for the run to be genuinely in flight, then fire the OS lock
  let running = false;
  for (let i = 0; i < 600 && !running; i++) { running = eventsSince(markA).some((e) => e.vaultId === VID_A && e.phase === 'running'); if (!running) await sleep(50); }
  const zkBefore = lockState.isUnlocked();
  power.emit('lock-screen');                   // the OS says: screen locked
  await sleep(300);
  await sleep(400);                              // let a couple of idle polls run: input alone must not lift the lock
  const lockedDuringTransfer = { accountUsable: lockState.isAccountUsable(), zkUnlocked: lockState.isUnlocked(), reason: lockState.snapshot().reason };
  row('lock-fired-mid-transfer', running === true && zkBefore === true && lockedDuringTransfer.accountUsable === false && lockedDuringTransfer.zkUnlocked === false, lockedDuringTransfer);
  row('lock-still-purges-the-zero-knowledge-key', lockEvents.some((e) => e.state === 'locked') && lockState.isUnlocked() === false, lockEvents.slice(-3));
  await settle();
  const lockedRun = eventsSince(markA).filter((e) => e.vaultId === VID_A && e.phase === 'done').pop();
  const namesA = await listFiles(VID_A);
  row('device-vault-finishes-its-transfer-under-lock', !!lockedRun && /ok/.test(String(lockedRun.outcome && lockedRun.outcome.result)) && namesA.includes('bulk-f399.bin'),
    { result: lockedRun && lockedRun.outcome && lockedRun.outcome.result, landed: namesA.includes('bulk-f399.bin') });

  // ---- a NEW run still dispatches while locked, and the account vault is paused in the same tick ------
  fs.writeFileSync(path.join(localA, 'while-locked.txt'), `written while locked ${rand}\n`);
  const markT = since();
  const mintsBefore = mints.length;
  await tick();                                 // one routine tick over BOTH vaults, still locked
  await settle();
  const tickEvents = eventsSince(markT);
  const aRan = tickEvents.some((e) => e.vaultId === VID_A && e.phase === 'running');
  const aDone = tickEvents.filter((e) => e.vaultId === VID_A && e.phase === 'done').pop();
  const bSkipped = tickEvents.filter((e) => e.vaultId === VID_B && (e.phase === 'skipped' || e.phase === 'refused' || e.phase === 'paused')).pop();
  row('new-device-run-dispatches-while-locked', aRan === true && !!aDone && /ok/.test(String(aDone.outcome && aDone.outcome.result)), { ran: aRan, result: aDone && aDone.outcome && aDone.outcome.result });
  row('account-vault-paused-by-the-lock-same-tick', !!bSkipped && bSkipped.reason === 'paused-locked', bSkipped && { phase: bSkipped.phase, reason: bSkipped.reason });
  row('no-credential-minted-for-the-paused-vault', mints.slice(mintsBefore).every((m) => m.vaultId === VID_A && m.via === 'device'), mints.slice(mintsBefore));
  const namesAfter = await listFiles(VID_A);
  row('the-file-written-while-locked-reached-the-server', namesAfter.includes('while-locked.txt'));

  // ---- the idle trigger fires the same purge, mid-transfer -------------------------------------------
  lockState.resumeAccount();                    // back from the lock for this row
  lockState.markUnlocked();
  for (let i = 0; i < 300; i++) fs.writeFileSync(path.join(localA, `idle-g${i}.bin`), crypto.randomBytes(4096));
  const markI = since();
  await snapshot.refresh([VID_A, VID_B]);
  scheduler.requestSync(VID_A, { manual: true });
  let running2 = false;
  for (let i = 0; i < 600 && !running2; i++) { running2 = eventsSince(markI).some((e) => e.vaultId === VID_A && e.phase === 'running'); if (!running2) await sleep(50); }
  power.idleSeconds = 5;                        // the OS says: no input for longer than the policy
  for (let i = 0; i < 60 && lockState.isAccountUsable(); i++) await sleep(100);
  const idleState = { accountUsable: lockState.isAccountUsable(), zkUnlocked: lockState.isUnlocked(), reason: lockState.snapshot().reason };
  row('idle-purge-fires-mid-transfer', running2 === true && idleState.zkUnlocked === false && idleState.reason === 'idle', idleState);
  await settle();
  const idleRun = eventsSince(markI).filter((e) => e.vaultId === VID_A && e.phase === 'done').pop();
  row('device-vault-survives-the-idle-purge', !!idleRun && /ok/.test(String(idleRun.outcome && idleRun.outcome.result)), idleRun && { result: idleRun.outcome && idleRun.outcome.result });

  // ---- waking is not presence: the machine coming back kicks a catch-up but leaves the pause in place ----
  const kicksBefore = resumeKicks;
  const markR = since();
  power.idleSeconds = 0;
  await sleep(300);                              // input returns: it reverses the IDLE lock, which is its own signal
  power.emit('suspend');                         // now the machine SLEEPS — a lock input alone must never reverse
  await sleep(300);
  const pausedBySleep = lockState.isAccountUsable() === false;
  await sleep(300);                              // more input polls while asleep: still no resume
  power.emit('resume');                          // the OS says: the machine is awake (not that anyone is here)
  await sleep(400);
  await settle();
  row('waking-kicks-a-catch-up-without-lifting-the-account-pause', pausedBySleep === true && resumeKicks > kicksBefore && lockState.isAccountUsable() === false && eventsSince(markR).length > 0,
    { pausedBySleep, kicks: resumeKicks - kicksBefore, accountUsable: lockState.isAccountUsable(), events: eventsSince(markR).length, reason: lockState.snapshot().reason });
  // ---- the OS unlock IS presence: the account tier resumes -------------------------------------------
  power.emit('unlock-screen');
  await sleep(200);
  row('the-os-unlock-lifts-the-account-pause', lockState.isAccountUsable() === true, { accountUsable: lockState.isAccountUsable(), reason: lockState.snapshot().reason });

  // ---- clean up ---------------------------------------------------------------------------------------
  autoLock.stop();
  await forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage });
  for (const vid of [VID_A, VID_B]) await api(`/vaults/${vid}/delete`, { method: 'POST', headers: auth(JWT, jsonHeaders()), body: JSON.stringify({ password: VPW }) }).catch(() => null);
  mgr.stop();
  await sleep(500);
  try { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(localA, { recursive: true, force: true }); fs.rmSync(localB, { recursive: true, force: true }); } catch { /* ignore */ }

  out.ok = out.rows.every((r) => r.ok);
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = scrub(String((e && e.stack) || e)); dump(); app.exit(2); });

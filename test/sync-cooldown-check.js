'use strict';
/*
 * Live check (run under Electron against a RUNNING throwaway vault — not part of `npm test`): the REAL scheduler,
 * over the production io wiring, the real forked sync helper and the real server, mints a BOUNDED number of
 * credentials under the two things that used to flood the server:
 *
 *   - a "Sync now" click storm: many presses in a few seconds mint ONE credential; every other press is answered
 *     at once with how long until the next is allowed, and nothing is run for it;
 *   - a door that keeps refusing this computer's credential (here: the credential is deliberately spoiled before
 *     it reaches the helper, so the server's own auth refusal is what comes back): the first refusal is retried
 *     once (the lapsed-at-connect race), then routine ticks inside the window mint NOTHING, a deliberate press
 *     gets one attempt per window and a second press is turned away with the wait; a Repair burst pressed WHILE a
 *     run is in flight still costs one credential — and once the door accepts a credential again the back-off
 *     clears and syncing resumes.
 *
 * The scheduler's clock is injected, so the windows (minutes to an hour) are stepped without waiting them out;
 * the server's per-address limit on sign-in attempts is real, so the phases are PACED against it with real pauses
 * (an attempt budget per window is the very thing this change protects — the check must not trip it itself).
 *
 * Isolation: its own temporary profile directory, its own throwaway vault (created and deleted here), a fresh
 * device registration that is forgotten at the end. Never a real profile, never a real vault.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_INSECURE_TLS   1 to accept the test server's self-signed certificate (test servers only)
 *   DOCKVAULT_PROOF_PACE_MS        the pause that lets the server's attempt window pass (default 310000)
 *
 * Writes .local/sync-cooldown-check.json (one row per proof step) and prints one PASS/FAIL line. Exit 0 = PASS.
 * No secret, token, or password is ever written to the result.
 *
 *   node_modules/electron/dist/electron.exe test/sync-cooldown-check.js
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
const { SyncScheduler, MANUAL_SYNC_COOLDOWN_MS, REFUSAL_BACKOFF_BASE_MS } = require('../src/main/sync-scheduler');
const schedulerIo = require('../src/main/scheduler-io');
const syncVaults = require('../src/main/sync-vaults');
const syncConfig = require('../src/main/sync-config');

if (process.env.DOCKVAULT_PROOF_INSECURE_TLS === '1') app.commandLine.appendSwitch('ignore-certificate-errors'); // a TEST server's self-signed cert; never the app
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const PACE_MS = Math.max(0, Number(process.env.DOCKVAULT_PROOF_PACE_MS || 310000) | 0);
const RESULT = path.join(__dirname, '..', '.local', 'sync-cooldown-check.json');

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
// Wait until the scheduler is idle (no run in flight, nothing queued), then a beat for the last event.
async function settle(sch, maxMs = 5 * 60 * 1000) {
  const t0 = Date.now();
  while ((sch._busy || sch._queue.length) && Date.now() - t0 < maxMs) await sleep(50);
  await sleep(100);
}

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE to point at a throwaway server'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-cooldown-'));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-cooldown-files-'));
  cleanup.steps.push(() => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); });
  const local = path.join(work, 'synced'); fs.mkdirSync(local);
  fs.writeFileSync(path.join(local, 'note.txt'), `cooldown proof ${crypto.randomBytes(8).toString('hex')}\n`);
  const rand = crypto.randomBytes(4).toString('hex');
  const VAULT_NAME = `Cooldown proof ${rand}`;

  // ---- account-session set-up --------------------------------------------------------------------------------
  const login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { await teardown(); dump(); app.exit(2); return; }
  const vc = await api('/vaults', { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ name: VAULT_NAME, type: 'standard' }) });
  const VID = vc.body && vc.body.id;
  row('create-vault', !!VID, vc.status);
  if (!VID) { await teardown(); dump(); app.exit(2); return; }
  cleanup.steps.push(() => api(`/vaults/${VID}/delete`, { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({}) }));

  // ---- this computer: register, grant, the real helper ---------------------------------------------------------
  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Cooldown proof', dir, safeStorage }, { fetchFn: httpJson });
  row('register', reg.ok === true, reg.ok ? 'ok' : reg.reason);
  const DEVICE_ID = reg.deviceId;
  cleanup.steps.push(() => forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage }, { fetchFn: httpJson }));
  const g = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEVICE_ID, vaultId: VID, vaultType: 'standard', vaultName: VAULT_NAME, dir, safeStorage }, { fetchFn: httpJson });
  row('grant', g.ok === true, g.ok ? 'ok' : g.reason);

  const rc = rcloneBundle.resolveBundledRclone({ isPackaged: false, resourcesPath: process.resourcesPath, platform: process.platform, arch: process.arch, env: process.env });
  row('bundled-helper-resolved', !!(rc && rc.bin && fs.existsSync(rc.bin)), rc && { version: rc.version });
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
    if (typeof id.secret === 'string' && !secrets.includes(id.secret)) secrets.push(id.secret); // attested never-written
    try { return await fn(API, id.secret); } finally { id.secret = null; }
  };
  const mintPath = new MintPathSelector({
    readSecret: () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); r.secret = null; return { status: r.status }; },
    listGrants: () => withDeviceSecret((origin, secret) => deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: secret, dir, safeStorage }, { fetchFn: httpJson })),
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
  });
  // Every credential the app draws passes through here — the count IS the number minted at the server. `spoil`
  // hands the helper a credential the server will refuse (the password is replaced), which is how a refusing door
  // is produced on demand without touching the server: the refusal that comes back is the server's own.
  let mints = 0;
  let spoil = false;
  const credCache = new CredCache({
    mint: async (vaultId) => {
      mints += 1;
      const b = await withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, httpJson));
      if (b && typeof b.password === 'string') secrets.push(b.password); // attested never-written
      if (spoil && b && typeof b.password === 'string') return { ...b, password: `not-${crypto.randomBytes(12).toString('hex')}` };
      return b;
    },
    send: (bundle, epoch) => mgr.sendSftpCred(bundle, 12000, epoch),
    epoch: () => mgr.currentEpoch(),
  });
  mgr.setCredProvider(async (vault) => (vault === VID ? credCache.ensureSent(vault) : { ok: false, reason: 'not-in-flight' }));
  // Every credential REQUEST the scheduler makes, alongside `mints` (what the server actually issued): a cached
  // credential would keep the mint count low on its own, so both are counted and both must stay bounded.
  const credRequests = [];

  // ---- the REAL scheduler over the production io wiring ------------------------------------------------------------
  let skew = 0; // the scheduler's injected clock: real time plus what the check has stepped forward
  const runState = { value: null, fresh: true };
  const events = [];
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
    credCache: { ensureSent: (vaultId) => { credRequests.push(vaultId); return credCache.ensureSent(vaultId); } },
    daemon: mgr,
    confirmFirstUpload: async () => true,
    onEvent: (vaultId, ev) => {
      events.push({ t: Date.now(), phase: ev.phase, reason: ev.reason || null, result: (ev.outcome && ev.outcome.result) || null });
      // As the daemon's own store does: a run that EXECUTED writes its typed result, and the resync latch follows
      // whatever the outcome decided (true/false), or is left alone when the outcome does not decide it (null).
      // A run that did not execute still carries a latch when it has one — a vault blocked awaiting a Repair
      // must READ as blocked on the next tick, or the scheduler would keep dispatching a run that cannot happen.
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
  io.now = () => Date.now() + skew;
  // As in the app: the eligibility step latches the credential path per run (this computer's own identity), the
  // auth-failure routing reads it back, and a terminal event forgets it.
  io.credentialPath = (vaultId) => mintPath.current(vaultId);
  io.verifyEligible = async (vaultId) => {
    const d = await mintPath.begin(vaultId);
    if (!d.ok) return d;
    return d.via === 'device' ? { ok: true, via: 'device', remotePath: d.remotePath, vaultName: d.vaultName } : { ok: false, reason: 'not-device-path' };
  };
  const innerOnEvent = io.onEvent;
  io.onEvent = (vaultId, ev) => { innerOnEvent(vaultId, ev); if (ev && ['done', 'error', 'blocked', 'paused', 'skipped', 'refused', 'noop'].includes(ev.phase)) mintPath.end(vaultId); };
  const el = await mintPath.begin(VID); mintPath.end(VID);
  row('eligibility-device-path', el.ok === true && el.via === 'device', el.ok ? el.via : el.reason);
  const sch = new SyncScheduler(io);
  const lastEvent = () => events[events.length - 1] || null;
  const doneResults = (from) => events.slice(from).filter((e) => e.phase === 'done').map((e) => e.result);

  // ---- baseline: a deliberate press seeds the vault (the initial zero-loss baseline) --------------------------------
  out.openingPaceMs = PACE_MS;
  await sleep(PACE_MS); // a fresh attempt window before the first credentials of the run
  {
    const m0 = mints; const e0 = events.length;
    const v = sch.requestSync(VID, { manual: true });
    await settle(sch);
    const le = lastEvent();
    row('baseline-press-accepted', v && v.accepted === true, v);
    const refusedAtDoor = doneResults(e0).some((r) => /auth-failed|channel-refused/.test(String(r)));
    if (refusedAtDoor) out.serverJammed = 'the baseline was refused at the SFTP door — the server was rate-limiting this address, so the later phases measure the server, not the scheduler';
    row('baseline-ok', le && le.phase === 'done' && /ok/.test(String(le.result)), { results: doneResults(e0), mints: mints - m0, refusedAtDoor });
    row('baseline-credentials-bounded', mints - m0 >= 1 && mints - m0 <= 4, mints - m0);
  }

  // The server's per-address attempt window: let it pass before the next phase draws on it.
  out.paceMs = PACE_MS;
  await sleep(PACE_MS);

  // ---- the click storm: many presses in a few seconds mint ONE credential ----------------------------------------
  {
    skew += MANUAL_SYNC_COOLDOWN_MS + 1000; // the baseline press's cooldown has lapsed
    const m0 = mints; const e0 = events.length; const q0 = credRequests.length;
    const verdicts = [];
    const t0 = Date.now();
    for (let i = 0; i < 25; i += 1) { verdicts.push(sch.requestSync(VID, { manual: true })); await sleep(300); }
    const stormMs = Date.now() - t0;
    await settle(sch);
    const accepted = verdicts.filter((v) => v && v.accepted === true).length;
    const refused = verdicts.filter((v) => v && v.accepted === false);
    const waits = refused.map((v) => v.retryInMs);
    out.storm = { presses: verdicts.length, accepted, refused: refused.length, stormMs, mints: mints - m0, credRequests: credRequests.length - q0, results: doneResults(e0), firstWaitMs: waits[0], lastWaitMs: waits[waits.length - 1] };
    // Presses that arrived while the accepted run was still in flight JOINED it (free); the rest were turned away
    // by the cooldown. Either way: one credential for the whole storm, and one run.
    row('storm-one-credential', mints - m0 === 1 && credRequests.length - q0 === 1, out.storm);
    row('storm-one-run', doneResults(e0).length === 1 && /ok/.test(String(doneResults(e0)[0])), doneResults(e0));
    row('storm-first-press-accepted', verdicts[0] && verdicts[0].accepted === true, verdicts[0]);
    row('storm-refusals-carry-the-wait', refused.length > 0 && refused.every((v) => v.reason === 'sync-cooldown' && v.retryInMs > 0 && v.retryInMs <= MANUAL_SYNC_COOLDOWN_MS), { refused: refused.length, waits: waits.slice(0, 3) });
    row('storm-waits-count-down', waits.length >= 2 && waits[waits.length - 1] < waits[0], { refusals: waits.length, firstWaitMs: waits[0], lastWaitMs: waits[waits.length - 1] });
  }

  // ---- a refusing door: the server refuses the (spoiled) credential; the scheduler backs off ------------------------
  // Attempt budget for this phase against the server's window: 2 (the refusal + its one race retry) + 1 (the press).
  {
    spoil = true;
    skew += MANUAL_SYNC_COOLDOWN_MS + 1000;
    const m0 = mints; const e0 = events.length;
    sch.tickAll();
    await settle(sch);
    const st = sch.refusalState(VID);
    out.refusal = { mints: mints - m0, results: doneResults(e0), state: st };
    row('refusal-is-the-servers-own', doneResults(e0).every((r) => /auth-failed/.test(String(r))) && doneResults(e0).length >= 1, doneResults(e0));
    row('refusal-two-credentials-then-stop', mints - m0 === 2, mints - m0);
    row('refusal-opens-the-window', !!st && st.failures === 1 && st.until - io.now() <= REFUSAL_BACKOFF_BASE_MS && st.manualAllowed === true, st);

    // Routine ticks inside the window: nothing minted, nothing run, nothing emitted.
    const m1 = mints; const e1 = events.length;
    for (let i = 0; i < 4; i += 1) { skew += 60 * 1000; sch.tickAll(); await settle(sch); }
    row('window-routine-ticks-mint-nothing', mints - m1 === 0 && events.length === e1, { mints: mints - m1, events: events.length - e1 });

    // The window's one deliberate attempt: a press is accepted, minted once, refused again (no race retry), and
    // the window lengthens with no attempt left; a storm of further presses is turned away with the wait.
    const m2 = mints; const e2 = events.length;
    const v1 = sch.requestSync(VID, { manual: true });
    await settle(sch);
    const st2 = sch.refusalState(VID);
    row('window-press-one-attempt', v1 && v1.accepted === true && mints - m2 === 1 && doneResults(e2).length === 1, { verdict: v1, mints: mints - m2, results: doneResults(e2) });
    row('window-press-lengthens-and-closes', !!st2 && st2.failures === 2 && st2.manualAllowed === false && st2.until > st.until, st2);
    skew += MANUAL_SYNC_COOLDOWN_MS + 1000; // past the press's own cooldown: what answers now is the back-off
    const m3 = mints;
    const storm = [];
    for (let i = 0; i < 15; i += 1) { storm.push(sch.requestSync(VID, { manual: true })); await sleep(100); }
    await settle(sch);
    row('window-press-storm-mints-nothing', mints - m3 === 0 && storm.every((v) => v && v.accepted === false && v.reason === 'backing-off' && v.retryInMs > 0), { mints: mints - m3, first: storm[0] });
    row('window-repair-also-turned-away', sch.requestRepair(VID).accepted === false, null);
    await settle(sch);

    // The shape that could once slip past the window: a Repair pressed WHILE a run for the same vault is in
    // flight. It is not folded into that run (a Repair must survive it), so before the dispatch became the one
    // authority each press became its own dispatch — and its own credential. Here: the door is still refusing
    // and the window's attempt is spent, so a whole burst must cost NOTHING.
    const m4 = mints; const q4 = credRequests.length;
    skew += Math.max(0, sch.refusalState(VID).until - io.now()) + 1000; // let the window lapse: one attempt again
    sch.tickAll();                                                      // that attempt goes to the routine tick
    await sleep(50);
    const inFlight = sch.current() === VID;
    const during = [];
    for (let i = 0; i < 8; i += 1) { during.push(sch.requestRepair(VID)); await sleep(60); }
    await settle(sch);
    // The window has just lapsed, so it legitimately owes ONE automatic attempt (the tick above) and ONE
    // deliberate attempt. The eight presses may therefore cost at most one credential request between them —
    // they coalesce onto a single pending repair — and never one apiece. (A repair RUN is a zero-loss resync,
    // which mints a small bounded number of per-step credentials of its own; the attempt count is the bound
    // this phase is about.)
    row('inflight-repair-burst-bounded', inFlight && credRequests.length - q4 <= 2,
      { inFlight, presses: during.length, credRequests: credRequests.length - q4, mints: mints - m4, accepted: during.filter((v) => v && v.accepted).length });

    // And with the refusal now on record, the window is shut to deliberate attempts: a second burst costs NOTHING
    // and every press is answered with the wait. This is the state a person hammering the button actually meets.
    const q5 = credRequests.length; const m5 = mints;
    skew += MANUAL_SYNC_COOLDOWN_MS + 1000; // past any press cooldown, so the back-off is what answers
    const after = [];
    for (let i = 0; i < 8; i += 1) { after.push(sch.requestRepair(VID)); await sleep(40); }
    await settle(sch);
    row('inflight-repair-after-refusal-costs-nothing', credRequests.length - q5 === 0 && mints - m5 === 0,
      { credRequests: credRequests.length - q5, mints: mints - m5 });
    row('inflight-repair-burst-answered', after.every((v) => v && v.accepted === false && v.reason === 'backing-off' && v.retryInMs > 0), after[0]);
  }

  // The server's attempt window again, before the door is asked to accept a credential.
  await sleep(PACE_MS);

  // ---- recovery: the door accepts a credential again -> the back-off clears, syncing resumes ------------------------
  {
    spoil = false;
    const st = sch.refusalState(VID);
    skew += Math.max(0, (st ? st.until : 0) - io.now()) + 1000; // the window lapses
    const m0 = mints; const e0 = events.length;
    sch.tickAll();
    await settle(sch);
    const le = lastEvent();
    out.recovery = { mints: mints - m0, results: doneResults(e0), state: sch.refusalState(VID) };
    row('recovery-one-credential', mints - m0 === 1, mints - m0);
    row('recovery-run-ok', le && le.phase === 'done' && /ok/.test(String(le.result)), doneResults(e0));
    row('recovery-clears-the-backoff', sch.refusalState(VID) === null, sch.refusalState(VID));
    // A routine request goes straight through again.
    row('recovery-routine-request-accepted', sch.requestSync(VID).accepted === true, null);
    await settle(sch);
  }
  out.totalMints = mints;

  // ---- clean up: stop the helper, forget the device, delete the throwaway vault, remove the files ------------------
  await mgr.clearSftpCred(5000).catch(() => null);
  await teardown();
  await sleep(500);

  out.ok = out.rows.every((r) => r.ok);
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`${out.ok ? 'PASS' : 'FAIL'} sync-cooldown-check (${out.rows.filter((r) => r.ok).length}/${out.rows.length}) storm=${JSON.stringify(out.storm && { presses: out.storm.presses, mints: out.storm.mints, refused: out.storm.refused })} refusal=${JSON.stringify(out.refusal && { mints: out.refusal.mints })} recovery=${JSON.stringify(out.recovery && { mints: out.recovery.mints, results: out.recovery.results })} totalMints=${out.totalMints}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch(async (e) => { out.fatal = scrub(String((e && e.stack) || e)); await teardown(); dump(); app.exit(2); });

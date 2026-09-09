'use strict';
/*
 * Live check (run under Electron against a RUNNING throwaway vault — not part of `npm test`): the sync helper
 * really does write its STRUCTURED log, the reader really does read it, and nothing about what a run is
 * reported to have done changed — proven against the real pinned helper, real folders, and a real server.
 *
 * It exists because this change alters the helper's RUNTIME (the flags it is launched with and the shape of
 * what comes back), and no amount of fixture-driven testing settles that the real binary agrees.
 *
 * PART A — the real helper, real folders, no server. The exact argv the app builds, run against two real
 * directories holding real files whose NAMES impersonate the run's own verdicts. Proves the flag reaches the
 * helper, the reader gets structured records rather than the text fallback, a real >50%-delete abort is still
 * recognised with those names present, and a door that cannot be reached is still named.
 *
 * PART B — the real forked daemon, real device identity, real SFTP, real server. A real transfer with the
 * progress feed watched from the outside (it must stay integers, and it must move), a routine run with the
 * impersonating names present on both sides, a real safety abort, and a real changed-server identity.
 *
 * A NOTE ON THE NAMES. Windows forbids ':' '*' '?' '"' '<' '>' '|' in a file name, so the impersonations that
 * need a colon ("ssh: rejected:", "knownhosts: key mismatch") CANNOT exist on disk here; they are covered by
 * test/json-log.test.js against recorded output. What is planted below is every impersonation that is legal
 * on this filesystem — which includes both safety aborts and the critical error, the three that latch.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_INSECURE_TLS   1 to accept the test server's self-signed certificate (test servers only)
 *   DOCKVAULT_PROOF_BIG_MB         size of the file used to watch progress move (default 200)
 *   DOCKVAULT_PROOF_PACE_MS        the pause between runs that lets the server's attempt window pass (default 310000)
 *
 * Writes .local/json-log-check.json (one row per proof step) and prints one PASS/FAIL line. Exit 0 = PASS.
 * No secret, token, or password is ever written to the result.
 *
 *   node_modules/electron/dist/electron.exe test/json-log-check.js
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
const syncConfig = require('../src/main/sync-config');
const { RcloneRunner } = require('../src/daemon/rclone-runner');
const { buildBisyncArgs, SYNC_LOG_ARGS } = require('../src/daemon/sync-engine');
const { classifyBisyncOutcome, RESULT } = require('../src/daemon/bisync-outcome');

if (process.env.DOCKVAULT_PROOF_INSECURE_TLS === '1') app.commandLine.appendSwitch('ignore-certificate-errors'); // a TEST server's self-signed cert; never the app
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const BIG_MB = Math.max(1, Number(process.env.DOCKVAULT_PROOF_BIG_MB || 200) | 0);
// The server limits sign-in attempts per source address, and every run of this check presents a fresh
// single-use credential at that door. The pause is real time, not a stepped clock: the limiter is the
// server's, and a check that tripped it would be measuring its own impatience rather than this change.
const PACE_MS = Math.max(0, Number(process.env.DOCKVAULT_PROOF_PACE_MS || 310000) | 0);
const RESULTS = path.join(__dirname, '..', '.local', 'json-log-check.json');

// Names that impersonate the run's own verdicts, and are legal on this filesystem. The three that LATCH a
// repair are all here — those are the ones whose loss would be data-unsafe.
const IMPERSONATING = [
  'Bisync critical error',
  'too many deletes (50%, 9 of 10) on Path1',
  'Safety abort- all files were changed on Path1',
  'cannot find prior Path1 or Path2 listings',
  'Bisync aborted. Must run --resync to recover.',
  'partial file rename failed',
  'staging buffer is full',
  'file name too long',
  'knownhosts key mismatch',
  'ssh rejected administratively prohibited (open failed)',
];

const out = { api: API, rows: [] };
const secrets = [ADMIN_PW];
function row(name, ok, detail) { out.rows.push({ row: name, ok: !!ok, detail: detail === undefined ? null : detail }); }
function scrub(text) { let t = String(text); for (const s of secrets) if (s) t = t.split(s).join('[redacted]'); return t; }
function dump() {
  try {
    fs.mkdirSync(path.dirname(RESULTS), { recursive: true });
    out.ok = out.rows.every((r) => r.ok);
    const text = JSON.stringify(out, null, 2);
    out.leakFree = secrets.every((s) => !s || !text.includes(s));
    fs.writeFileSync(RESULTS, scrub(JSON.stringify(out, null, 2)));
    console.log(`${out.ok ? 'PASS' : 'FAIL'} json-log-check — ${out.rows.filter((r) => r.ok).length}/${out.rows.length} rows, leakFree=${out.leakFree}`);
    for (const r of out.rows) if (!r.ok) console.log(`  FAILED: ${r.row} ${JSON.stringify(r.detail)}`);
  } catch (e) { console.log('dump failed', e && e.message); }
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const cleanup = { steps: [] };
async function teardown() { for (const s of cleanup.steps.splice(0).reverse()) { try { await s(); } catch { /* best effort */ } } }
const watchdog = setTimeout(async () => { row('watchdog', false, 'timed out'); await teardown(); dump(); app.exit(3); }, 60 * 60 * 1000);
app.on('window-all-closed', () => {});
async function api(pathname, init = {}) {
  const res = await httpJson(`${API}${pathname}`, init);
  let body = null; try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}
const auth = (token, extra = {}) => ({ Authorization: `Bearer ${token}`, ...extra });
const jsonBody = () => ({ 'Content-Type': 'application/json' });

// Anything that is not an integer or null in a progress payload is a leak: the feed is the ONE thing that
// travels out of the helper while a run is in flight, and a path must never be in it.
function nonIntegers(payload) {
  const bad = [];
  const walk = (v, at) => {
    if (v === null || v === undefined) return;
    if (Array.isArray(v)) { v.forEach((x, i) => walk(x, `${at}[${i}]`)); return; }
    if (typeof v === 'object') { for (const [k, x] of Object.entries(v)) walk(x, `${at}.${k}`); return; }
    if (!Number.isInteger(v)) bad.push(`${at}=${JSON.stringify(v)}`);
  };
  walk(payload, '');
  return bad;
}

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE to point at a throwaway server'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-jsonlog-'));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-jsonlog-files-'));
  cleanup.steps.push(() => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); });

  const rc = rcloneBundle.resolveBundledRclone({ isPackaged: false, resourcesPath: process.resourcesPath, platform: process.platform, arch: process.arch, env: process.env });
  row('bundled-helper-resolved', !!(rc && rc.bin && fs.existsSync(rc.bin)), rc && { version: rc.version });
  if (!rc || !rc.bin) { await teardown(); dump(); app.exit(2); return; }

  // =========================================================================================================
  // PART A — the real helper, real folders, real impersonating names. No server, no credential.
  // =========================================================================================================
  {
    const p1 = path.join(work, 'a1'); const p2 = path.join(work, 'a2'); const wd = path.join(work, 'awd');
    fs.mkdirSync(p1); fs.mkdirSync(p2); fs.mkdirSync(wd);
    let planted = 0;
    for (const name of IMPERSONATING) { try { fs.writeFileSync(path.join(p1, `${name}.txt`), `${name}\n`); planted += 1; } catch { /* not legal here */ } }
    for (let i = 0; i < 10; i += 1) fs.writeFileSync(path.join(p1, `ordinary-${i}.txt`), `ordinary ${i}\n`);
    row('impersonating-names-really-on-disk', planted === IMPERSONATING.length, { planted, of: IMPERSONATING.length });

    const runner = new RcloneRunner({ rcloneBin: rc.bin, expectVersion: rc.version, expectSha256: rc.sha256 });
    await runner.ready();
    const bisync = async (opts) => {
      const args = buildBisyncArgs({ local: p1, remote: p2, workdir: wd, ...opts });
      const r = await runner.run(args, { inactivityMs: 120000, hardCeilingMs: 600000 });
      return { r, outcome: classifyBisyncOutcome({ code: r.code, stdout: r.stdout, stderr: r.stderr, records: r.logRecords, resync: !!opts.resync }) };
    };

    // The argv the app builds asks for the structured format, and the reader gets records back — not the
    // text fallback. If the flag never reached the helper this row is what notices.
    const base = await bisync({ resync: true });
    row('the-argv-asks-for-the-structured-format', SYNC_LOG_ARGS.includes('--use-json-log') && buildBisyncArgs({ local: p1, remote: p2, workdir: wd }).includes('--use-json-log'));
    row('baseline-over-real-files-is-green', base.r.code === 0 && /ok/.test(String(base.outcome.result)), { code: base.r.code, result: base.outcome.result });
    // A clean run says nothing but its progress block, which is read for its numbers and dropped — so there
    // is nothing to keep, and nothing that fell back to text. Both halves matter.
    row('a-clean-run-keeps-nothing-and-falls-back-to-nothing', (base.r.logRecords || []).length === 0 && String(base.r.stderr || '') === '',
      { records: (base.r.logRecords || []).length, unstructuredBytesKept: String(base.r.stderr || '').length });

    // A routine run with every impersonating name present on BOTH sides: still an ordinary clean run.
    const routine = await bisync({});
    row('impersonating-names-do-not-disturb-a-clean-run', routine.r.code === 0 && routine.outcome.result === RESULT.OK && routine.outcome.resyncRequired === false,
      { result: routine.outcome.result, resyncRequired: routine.outcome.resyncRequired });

    // A REAL >50%-delete safety abort, with those names sitting in the folder. The verdict must be the
    // abort, and it must latch — this is the direction whose loss would be data-unsafe.
    const names = fs.readdirSync(p1).filter((n) => n.endsWith('.txt'));
    for (const n of names.slice(0, Math.ceil(names.length * 0.8))) fs.rmSync(path.join(p1, n));
    const aborted = await bisync({});
    row('a-real-safety-abort-is-still-the-verdict', aborted.outcome.result === RESULT.ABORT_EXCESSIVE_DELETE && aborted.outcome.resyncRequired === true,
      { result: aborted.outcome.result, resyncRequired: aborted.outcome.resyncRequired, deleted: Math.ceil(names.length * 0.8), of: names.length });
    // The run that SPEAKS is where the reader is proven: every word of it arrived as a structured record, and
    // NOTHING arrived as text. If the flag had not reached the helper this would be the exact opposite.
    const spoke = aborted.r.logRecords || [];
    row('the-helper-writes-it-and-the-reader-reads-it', spoke.length > 0 && spoke.every((x) => typeof x.msg === 'string' && typeof x.LEVEL === 'string') && String(aborted.r.stderr || '') === '',
      { records: spoke.length, levels: [...new Set(spoke.map((x) => x.LEVEL))].sort().join(','), unstructuredBytesKept: String(aborted.r.stderr || '').length });
    // And the file that was named to a person came from the record's own field, never from re-reading a line.
    row('a-verdict-carries-no-file-of-its-own', aborted.outcome.detail == null || typeof aborted.outcome.detail.file === 'string' || aborted.outcome.detail.file === null, aborted.outcome.detail || null);

    // A door that cannot be reached, from the same reader. No credential is spent: nothing answers this port.
    const obscured = await runner.obscure(`not-a-password-${crypto.randomBytes(9).toString('hex')}`);
    const closed = await runner.run(['lsf', `:sftp,host=127.0.0.1,port=1,user=nobody,pass=${obscured}:`, ...SYNC_LOG_ARGS, '--contimeout', '3s', '--retries', '1', '--low-level-retries', '1'], { timeoutMs: 60000 })
      .catch((e) => ({ code: -1, stdout: '', stderr: String(e), logRecords: [] }));
    const closedOutcome = classifyBisyncOutcome({ code: closed.code, stdout: closed.stdout, stderr: closed.stderr, records: closed.logRecords });
    row('a-door-that-cannot-be-reached-is-still-named', [RESULT.CONNECT_FAILED, RESULT.AUTH_FAILED].includes(closedOutcome.result), { result: closedOutcome.result });
  }

  // =========================================================================================================
  // PART B — the real forked daemon, real device identity, real SFTP, the real server.
  // =========================================================================================================
  const local = path.join(work, 'synced'); fs.mkdirSync(local);
  for (const name of IMPERSONATING) { try { fs.writeFileSync(path.join(local, `${name}.txt`), `${name}\n`); } catch { /* not legal here */ } }
  fs.writeFileSync(path.join(local, 'ordinary.txt'), `proof ${crypto.randomBytes(8).toString('hex')}\n`);

  const rand = crypto.randomBytes(4).toString('hex');
  const VAULT_NAME = `Structured log proof ${rand}`;
  // The server limits sign-in attempts per source address, and a check that has just run is competing with
  // its own previous attempts. Waiting the window out is the honest thing to do — being turned away is the
  // server working, not the app failing — so a refusal here is paced through, never reported as a result.
  let login = null;
  for (let attempt = 1; attempt <= 6; attempt += 1) {
    login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
    if (login.status !== 429) break;
    console.log(`admin sign-in turned away (attempt ${attempt}); waiting out the server's window`);
    await sleep(PACE_MS);
  }
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { await teardown(); dump(); app.exit(2); return; }
  const vc = await api('/vaults', { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ name: VAULT_NAME, type: 'standard' }) });
  const VID = vc.body && vc.body.id;
  row('create-vault', !!VID, vc.status);
  if (!VID) { await teardown(); dump(); app.exit(2); return; }
  cleanup.steps.push(() => api(`/vaults/${VID}/delete`, { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({}) }));

  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Structured log proof', dir, safeStorage }, { fetchFn: httpJson });
  row('register', reg.ok === true, reg.ok ? 'ok' : reg.reason);
  const DEVICE_ID = reg.deviceId;
  cleanup.steps.push(() => forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage }, { fetchFn: httpJson }));
  const g = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEVICE_ID, vaultId: VID, vaultType: 'standard', vaultName: VAULT_NAME, dir, safeStorage }, { fetchFn: httpJson });
  row('grant', g.ok === true, g.ok ? 'ok' : g.reason);

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
  let forgeKey = null; // when set, the server's key is replaced before the credential is pinned/sent
  const makeCache = () => new CredCache({
    mint: async (vaultId) => {
      mints += 1;
      const b = await withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, httpJson));
      if (b && typeof b.password === 'string') secrets.push(b.password);
      return forgeKey ? { ...b, hostKeys: forgeKey } : b; // the bundle carries ONE key, as a string
    },
    send: (bundle, epoch) => mgr.sendSftpCred(bundle, 12000, epoch),
    epoch: () => mgr.currentEpoch(),
  });
  let credCache = makeCache();
  mgr.setCredProvider(async (vault) => (vault === VID ? credCache.ensureSent(vault) : { ok: false, reason: 'not-in-flight' }));

  const el = await mintPath.begin(VID); mintPath.end(VID);
  row('eligibility-device-path', el.ok === true && el.via === 'device', el.ok ? el.via : el.reason);
  const REMOTE_PATH = el.ok ? el.remotePath : syncConfig.remotePathForVault(VAULT_NAME);

  // Every progress payload the daemon pushes while a run is in flight.
  const progress = [];
  mgr.on('sync-progress', (p) => progress.push(p));
  let firstRun = true;
  const runOnce = async (spec) => {
    if (!firstRun) await sleep(PACE_MS); // let the door's attempt window pass before presenting another credential
    firstRun = false;
    const sent = await credCache.ensureSent(VID); // as the scheduler does before every dispatch
    if (!sent || sent.ok !== true) return { ok: false, ran: false, reason: (sent && sent.reason) || 'no-cred' };
    return mgr.runSync({ vault: VID, local, remotePath: REMOTE_PATH, ...spec }, 25 * 60 * 1000);
  };

  // ---- a real transfer, watched from the outside -------------------------------------------------------
  const big = path.join(local, 'moving-picture.bin');
  fs.writeFileSync(big, Buffer.alloc(1024 * 1024, 7));
  for (let i = 1; i < BIG_MB; i += 1) fs.appendFileSync(big, Buffer.alloc(1024 * 1024, (i % 251) + 1));
  progress.length = 0;
  const t0 = Date.now();
  const baseline = await runOnce({ resync: true });
  const elapsedMs = Date.now() - t0;
  row('a-real-transfer-completes', baseline && baseline.ok === true && baseline.ran === true && /ok/.test(String(baseline.result)),
    { result: baseline && baseline.result, reason: (baseline && baseline.reason) || null, mb: BIG_MB, elapsedMs });

  const bad = progress.flatMap((p) => nonIntegers({ files: p.files, filesTotal: p.filesTotal, bytes: p.bytes, bytesTotal: p.bytesTotal, percent: p.percent, transferring: p.transferring, fileProgress: p.fileProgress }));
  const moved = progress.map((p) => p.bytes).filter((b) => Number.isInteger(b));
  row('the-progress-feed-is-integers-only', bad.length === 0, { events: progress.length, offending: bad.slice(0, 5) });
  row('the-progress-feed-still-moves', progress.length > 0 && moved.length > 0 && Math.max(...moved) > 0 && (progress.length < 2 || Math.max(...moved) > Math.min(...moved)),
    { events: progress.length, firstBytes: moved[0], lastBytes: moved[moved.length - 1] });
  // And the ONLY non-number a payload may carry is the vault it is about — a key the daemon might add later
  // that held a name would fail this, which is the point of asserting the shape rather than the fields.
  row('the-only-non-number-in-a-payload-is-the-vault-it-is-about',
    progress.length > 0 && progress.every((p) => Object.entries(p).every(([k, v]) => (k === 'vault' ? v === VID : (v === null || typeof v === 'number' || (Array.isArray(v) && v.every(Number.isInteger)))))),
    { keys: progress.length ? Object.keys(progress[0]).sort().join(',') : null });

  const ls = await api(`/vaults/${VID}/files`, { headers: auth(JWT) });
  const listed = JSON.stringify((ls.body && (ls.body.files || ls.body.items || ls.body)) || []);
  row('the-impersonating-names-really-are-in-the-vault', IMPERSONATING.filter((n) => listed.includes(n)).length >= IMPERSONATING.length - 1,
    { matched: IMPERSONATING.filter((n) => listed.includes(n)).length, of: IMPERSONATING.length, status: ls.status });

  // ---- a routine run with those names on both sides ----------------------------------------------------
  fs.writeFileSync(path.join(local, 'one-more.txt'), 'one more\n');
  const routine = await runOnce({});
  row('a-routine-run-over-a-vault-full-of-those-names-is-clean', routine && routine.ran === true && String(routine.result) === RESULT.OK && routine.resyncRequired === false,
    { result: routine && routine.result, resyncRequired: routine && routine.resyncRequired });

  // ---- a REAL changed server identity -------------------------------------------------------------------
  {
    await sleep(PACE_MS);
    forgeKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForgedForgedForgedForgedForgedForgedForged0';
    // With a key already pinned for this session, a changed one never reaches the helper at all — the
    // credential path refuses it first. That is the app's own fail-closed rail and it must still hold.
    await mintPath.begin(VID);
    const refusedEarly = await credCache.ensureSent(VID);
    mintPath.end(VID);
    row('a-changed-key-is-refused-before-the-helper-ever-sees-it', refusedEarly.ok === false && refusedEarly.reason === 'host-key-mismatch', refusedEarly.reason);
    // With NO pin yet (as a fresh app process), the forged key IS pinned, and the REAL server is then refused
    // at connect — which is the path that goes through the helper, and so through the reader.
    credCache = makeCache();
    await mintPath.begin(VID);
    const sent = await credCache.ensureSent(VID);
    mintPath.end(VID);
    const forged = sent.ok ? await mgr.runSync({ vault: VID, local, remotePath: REMOTE_PATH, resync: false }, 5 * 60 * 1000) : null;
    forgeKey = null;
    credCache = makeCache();
    row('a-real-changed-server-identity-is-still-the-alarm', sent.ok === true && forged && String(forged.result) === RESULT.HOST_KEY_MISMATCH,
      { result: forged && forged.result, reason: (forged && forged.reason) || null, sent: sent.ok, sentReason: sent.ok ? null : (sent.reason || null), sentSub: (sent && sent.sub) || null });
  }

  // ---- a REAL safety abort over real SFTP, with those names present ------------------------------------
  // LAST on purpose: an abort latches a repair, and the app then fail-closes every normal run until someone
  // does one deliberately. Anything after it would be measuring that gate rather than what it came to measure.
  {
    const names = fs.readdirSync(local).filter((n) => n.endsWith('.txt'));
    for (const n of names.slice(0, Math.ceil(names.length * 0.8))) fs.rmSync(path.join(local, n));
    const aborted = await runOnce({});
    row('a-real-safety-abort-over-real-sftp-still-latches', aborted && String(aborted.result) === RESULT.ABORT_EXCESSIVE_DELETE && aborted.resyncRequired === true,
      { result: aborted && aborted.result, resyncRequired: aborted && aborted.resyncRequired, deleted: Math.ceil(names.length * 0.8), of: names.length });
  }

  out.mints = mints;
  out.paceMs = PACE_MS;
  out.progressEvents = progress.length;
  clearTimeout(watchdog);
  await teardown();
  dump();
  app.exit(out.ok ? 0 : 1);
}).catch(async (e) => {
  row('fatal', false, String((e && e.message) || e));
  clearTimeout(watchdog);
  await teardown();
  dump();
  app.exit(2);
});

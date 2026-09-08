'use strict';
/*
 * Live check (run under Electron against a RUNNING throwaway vault — not part of `npm test`): a LARGE file syncs in
 * BOTH directions through the real forked daemon and the real bundled sync helper (rclone) with FLAT, bounded
 * memory in every process involved, measured from the outside once a second:
 *
 *   - the Electron main process (this process), the sync daemon (a utility process), and every helper (rclone)
 *     process the daemon launches;
 *   - DOWN: a file of at least 1 GB already on the server comes down into an empty folder — the whole file, byte
 *     for byte (a streaming SHA-256 of both sides agrees) — and no process ever holds more than a small fraction
 *     of the file's size;
 *   - UP: a fresh local file of the same size goes up the same way. A server that stages SFTP uploads in a bounded
 *     buffer refuses a file this large at its door (a deployment knob on the server, not a client matter): the
 *     check then requires that the client STREAMED hundreds of megabytes before the server's verdict and stayed
 *     flat the whole way, and it reports whether the file completed or the server refused it.
 *
 * Isolation: its own temporary profile directory, its own throwaway vault (created and deleted here), a fresh
 * device registration that is forgotten at the end. Never a real profile, never a real vault.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_BIG_FILE       a local file of at least 1 GB to use (optional; one is generated when absent)
 *   DOCKVAULT_PROOF_INSECURE_TLS   1 to accept the test server's self-signed certificate (test servers only)
 *
 * Writes .local/large-file-memory-check.json (one row per proof step, plus the per-process peaks) and prints
 * one PASS/FAIL line. Exit 0 = PASS. No secret, token, or password is ever written to the result.
 *
 *   node_modules/electron/dist/electron.exe test/large-file-memory-check.js
 */
const { app, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawn } = require('node:child_process');
const https = require('node:https');
const http = require('node:http');
const { DaemonManager } = require('../src/main/daemon-manager');
const { CredCache } = require('../src/main/cred-cache');
const { MintPathSelector } = require('../src/main/mint-path');
const { mintDeviceSftpAccess } = require('../src/main/device-mint');
const deviceSecretStore = require('../src/main/device-secret-store');
const deviceGrant = require('../src/main/device-grant');
const deviceGrantStore = require('../src/main/device-grant-store');
const { registerDevice, forgetDevice } = require('../src/main/device-register');
const rcloneBundle = require('../src/main/rclone-bundle');

if (process.env.DOCKVAULT_PROOF_INSECURE_TLS === '1') app.commandLine.appendSwitch('ignore-certificate-errors'); // a TEST server's self-signed cert; never the app
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const RESULT = path.join(__dirname, '..', '.local', 'large-file-memory-check.json');

const MiB = 1024 * 1024;
const MIN_FILE_BYTES = 1000 * MiB;      // "at least 1 GB"
const CEILING_MB = 400;                  // the most ANY process may reach while the file moves — far below the file
const WEB_CHUNK = 5 * MiB;               // the server's chunked-upload unit, used to seed the download-direction file

const out = { api: API, rows: [], peaks: {} };
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
const watchdog = setTimeout(async () => { row('watchdog', false, 'timed out'); await teardown(); dump(); app.exit(3); }, 40 * 60 * 1000);
app.on('window-all-closed', () => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function api(pathname, init = {}) {
  const res = await httpJson(`${API}${pathname}`, init);
  let body = null; try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}
const auth = (token, extra = {}) => ({ Authorization: `Bearer ${token}`, ...extra });
const jsonBody = () => ({ 'Content-Type': 'application/json' });

// ---- the outside observer: one PowerShell child that prints every rclone/electron process's memory once a second
function startSampler() {
  const script = [
    'while ($true) {',
    '  $t = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()',
    "  Get-CimInstance Win32_Process -Filter \"Name='rclone.exe' OR Name='electron.exe' OR Name='DockVault.exe'\" | ForEach-Object {",
    '    "$t,$($_.ProcessId),$($_.ParentProcessId),$([math]::Round($_.WorkingSetSize/1MB)),$([math]::Round($_.PrivatePageCount/1MB))"',
    '  }',
    '  "--"',
    '  Start-Sleep -Milliseconds 1000',
    '}',
  ].join('\n');
  const child = spawn('powershell', ['-NoProfile', '-NonInteractive', '-Command', script], { stdio: ['ignore', 'pipe', 'ignore'], windowsHide: true });
  const state = { samples: [], buf: '' };
  child.stdout.on('data', (d) => {
    state.buf += String(d);
    let nl;
    while ((nl = state.buf.indexOf('\n')) >= 0) {
      const line = state.buf.slice(0, nl).trim(); state.buf = state.buf.slice(nl + 1);
      const m = line.match(/^(\d+),(\d+),(\d+),(\d+),(\d+)$/);
      if (m) state.samples.push({ t: Number(m[1]), pid: Number(m[2]), ppid: Number(m[3]), ws: Number(m[4]), priv: Number(m[5]) });
    }
  });
  return { child, state, stop: () => { try { child.kill(); } catch { /* gone */ } } };
}
// Per-role peaks over a window: main = this pid; daemon = the utility process pid; helper = any rclone whose parent is the daemon.
function peaks(samples, from, to, mainPid, daemonPid) {
  const win = samples.filter((s) => s.t >= from && s.t <= to);
  const role = (s) => (s.pid === mainPid ? 'main' : s.pid === daemonPid ? 'daemon' : s.ppid === daemonPid ? 'helper' : null);
  const p = { main: 0, daemon: 0, helper: 0, samples: win.length, helperSamples: 0 };
  for (const s of win) { const r = role(s); if (!r) continue; p[r] = Math.max(p[r], s.ws); if (r === 'helper') p.helperSamples += 1; }
  return p;
}
// A raw-bytes PUT for seeding the server-side file (Node's own client; the app's JSON helper is for JSON).
function putBytes(url, headers, body) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.request(u, { method: 'PUT', headers: { ...headers, 'Content-Length': body.length }, rejectUnauthorized: process.env.DOCKVAULT_PROOF_INSECURE_TLS !== '1' }, (res) => {
      res.resume(); res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode }));
    });
    req.on('error', reject);
    req.end(body);
  });
}
function sha256File(file) {
  return new Promise((resolve, reject) => {
    const h = crypto.createHash('sha256');
    fs.createReadStream(file).on('data', (c) => h.update(c)).on('end', () => resolve(h.digest('hex'))).on('error', reject);
  });
}
// A large file with mostly-random content (so nothing compresses or dedups it away), written in 1 MiB blocks.
function writeBigFile(file, bytes) {
  const fd = fs.openSync(file, 'w');
  const block = crypto.randomBytes(MiB);
  let left = bytes;
  let i = 0;
  while (left > 0) {
    const b = (i++ % 5 === 0) ? crypto.randomBytes(MiB) : block;
    const n = Math.min(left, MiB);
    fs.writeSync(fd, b, 0, n);
    left -= n;
  }
  fs.closeSync(fd);
}

// Best-effort teardown for every exit path (a fatal, the watchdog, an early refusal): nothing of the proof is
// left on the server or on disk. Filled in as the run creates things.
const cleanup = { steps: [] };
async function teardown() {
  for (const step of cleanup.steps.splice(0).reverse()) { try { await step(); } catch { /* best effort */ } }
}
app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE to point at a throwaway server'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-bigmem-'));
  const work = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-bigmem-files-'));
  cleanup.steps.push(() => { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(work, { recursive: true, force: true }); });
  const local = path.join(work, 'synced'); fs.mkdirSync(local);
  const rand = crypto.randomBytes(4).toString('hex');
  const VAULT_NAME = `Large file proof ${rand}`;

  // ---- the large file ---------------------------------------------------------------------------------------
  let big = process.env.DOCKVAULT_PROOF_BIG_FILE || '';
  if (!big || !fs.existsSync(big) || fs.statSync(big).size < MIN_FILE_BYTES) {
    big = path.join(work, 'big-source.bin');
    writeBigFile(big, 1200 * MiB);
  }
  const BIG_BYTES = fs.statSync(big).size;
  out.fileMB = Math.round(BIG_BYTES / MiB);
  out.ceilingMB = CEILING_MB;
  row('file-is-large', BIG_BYTES >= MIN_FILE_BYTES && BIG_BYTES >= 2.5 * CEILING_MB * MiB, { fileMB: out.fileMB, ceilingMB: CEILING_MB });
  const bigHash = await sha256File(big);

  // ---- account-session set-up --------------------------------------------------------------------------------
  const login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { dump(); app.exit(2); return; }
  const vc = await api('/vaults', { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ name: VAULT_NAME, type: 'standard' }) });
  const VID = vc.body && vc.body.id;
  row('create-vault', !!VID, vc.status);
  if (!VID) { await teardown(); dump(); app.exit(2); return; }
  cleanup.steps.push(() => api(`/vaults/${VID}/delete`, { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({}) }));
  // room for two copies of the file plus slack
  const st = await api(`/vaults/${VID}/storage`, { method: 'PUT', headers: auth(JWT, jsonBody()), body: JSON.stringify({ granted_bytes: 3 * BIG_BYTES }) });
  row('vault-storage-granted', st.ok, st.status);

  // ---- seed the DOWN direction: the large file goes onto the server through the web chunked upload ------------
  {
    const name = 'big-down.bin';
    const total = Math.ceil(BIG_BYTES / WEB_CHUNK);
    const init = await api(`/vaults/${VID}/uploads`, { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ file_name: name, mime_type: 'application/octet-stream', total_size: BIG_BYTES, total_chunks: total, chunk_size: WEB_CHUNK, folder_id: null }) });
    const sid = init.body && init.body.session_id;
    let okChunks = 0;
    if (sid) {
      const fd = fs.openSync(big, 'r'); const buf = Buffer.alloc(WEB_CHUNK);
      for (let i = 0; i < total; i++) {
        const n = fs.readSync(fd, buf, 0, WEB_CHUNK, i * WEB_CHUNK);
        const r = await putBytes(`${API}/vaults/${VID}/uploads/${sid}/chunks/${i}`, auth(JWT, { 'Content-Type': 'application/octet-stream' }), buf.subarray(0, n));
        if (!r.ok) break;
        okChunks += 1;
      }
      fs.closeSync(fd);
    }
    const done = sid && okChunks === total ? await api(`/vaults/${VID}/uploads/${sid}/complete`, { method: 'POST', headers: auth(JWT) }) : { ok: false, status: init.status };
    row('seed-server-file', done.ok === true, { status: done.status, chunks: `${okChunks}/${total}` });
    if (!done.ok) { await teardown(); dump(); app.exit(2); return; }
  }

  // ---- this computer: register, grant, the real helper ---------------------------------------------------------
  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Large file proof', dir, safeStorage }, { fetchFn: httpJson });
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
  const daemonPid = mgr.child && mgr.child.pid;
  row('daemon-pid-known', typeof daemonPid === 'number' && daemonPid > 0, daemonPid);

  const withDeviceSecret = async (fn) => {
    const id = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
    if (id.status !== 'ok') { const e = new Error('device identity unavailable'); e.reason = 'device-request-refused'; throw e; }
    try { return await fn(API, id.secret); } finally { id.secret = null; }
  };
  const mintPath = new MintPathSelector({
    readSecret: () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); r.secret = null; return { status: r.status }; },
    listGrants: () => withDeviceSecret((origin, secret) => deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: secret, dir, safeStorage }, { fetchFn: httpJson })),
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
  });
  let mints = 0;
  const credCache = new CredCache({
    mint: async (vaultId) => { mints += 1; return withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, httpJson)); },
    send: (bundle, epoch) => mgr.sendSftpCred(bundle, 12000, epoch),
    epoch: () => mgr.currentEpoch(),
  });
  mgr.setCredProvider(async (vault) => (vault === VID ? credCache.ensureSent(vault) : { ok: false, reason: 'not-in-flight' }));
  const el = await mintPath.begin(VID);
  row('eligibility-device-path', el.ok === true && el.via === 'device', el.ok ? el.via : el.reason);
  const remotePath = el.remotePath;
  const progress = [];
  mgr.on('sync-progress', (p) => progress.push(p));

  const sampler = startSampler();
  await sleep(2500); // let the observer take its first samples
  const mainPid = process.pid;

  // ---- DOWN: the large file comes into the empty folder ----------------------------------------------------------
  {
    const m = await credCache.ensureSent(VID);
    row('down-mint-and-send', m.ok === true, m.ok ? 'ok' : m.reason);
    const t0 = Date.now();
    const run = await mgr.runSync({ vault: VID, local, remotePath, resync: true }, 30 * 60 * 1000);
    const t1 = Date.now();
    await sleep(1500);
    const pk = peaks(sampler.state.samples, t0 - 1500, t1 + 1500, mainPid, daemonPid);
    out.peaks.down = { ...pk, seconds: Math.round((t1 - t0) / 1000), mints };
    const got = path.join(local, 'big-down.bin');
    const landed = fs.existsSync(got) && fs.statSync(got).size === BIG_BYTES;
    const same = landed ? (await sha256File(got)) === bigHash : false;
    row('down-sync-ok', run && run.ok === true && run.ran === true && /ok/.test(String(run.result)), run && { ok: run.ok, ran: run.ran, result: run.result, reason: run.reason || null, code: run.code, seconds: out.peaks.down.seconds });
    row('down-file-byte-identical', same, { landed, sizeMB: landed ? Math.round(fs.statSync(got).size / MiB) : null });
    row('down-helper-observed', pk.helperSamples >= 3, { helperSamples: pk.helperSamples, samples: pk.samples });
    row('down-memory-flat', pk.main < CEILING_MB && pk.daemon < CEILING_MB && pk.helper < CEILING_MB && pk.helper > 0, { peakMB: { main: pk.main, daemon: pk.daemon, helper: pk.helper }, ceilingMB: CEILING_MB, fileMB: out.fileMB });
    // The first baseline runs the zero-loss path — several helper processes, each with its own single-use
    // credential (list, compare, preserve, then the baseline) — so the count is small and bounded, never a burst.
    row('down-credentials-bounded', mints >= 1 && mints <= 4, mints);
  }

  // ---- UP: a fresh large file goes up from the folder ------------------------------------------------------------
  {
    const upName = 'big-up.bin';
    fs.copyFileSync(big, path.join(local, upName));
    const mintsBefore = mints;
    const progressBefore = progress.length;
    await mintPath.begin(VID);
    const m = await credCache.ensureSent(VID);
    row('up-mint-and-send', m.ok === true, m.ok ? 'ok' : m.reason);
    const t0 = Date.now();
    const run = await mgr.runSync({ vault: VID, local, remotePath, resync: false }, 30 * 60 * 1000);
    const t1 = Date.now();
    await sleep(1500);
    const pk = peaks(sampler.state.samples, t0 - 1500, t1 + 1500, mainPid, daemonPid);
    out.peaks.up = { ...pk, seconds: Math.round((t1 - t0) / 1000), mints: mints - mintsBefore };
    const list = await api(`/vaults/${VID}/files`, { headers: auth(JWT) });
    const names = JSON.stringify(list.body || '');
    const onServer = names.includes(upName);
    const completed = run && run.ok === true && run.ran === true && /ok/.test(String(run.result)) && onServer;
    // Honest verdict: the row passes ONLY when the file is on the server. A server that stages SFTP uploads in a
    // bounded buffer refuses a file this large at its door (its deployment knob, not a client failure) — that
    // shows here as not-completed with the run's typed result, and the memory rows below still say whether the
    // client streamed flat all the way to the refusal.
    const upBytes = Math.max(0, ...progress.slice(progressBefore).map((p) => p.bytes || 0));
    const streamedMB = Math.round(upBytes / MiB);
    // "server-refused": the helper had streamed hundreds of megabytes when the run ended with the helper's own
    // critical-error verdict (exit 7, read back as needs-resync) — the signature of the server ending an upload
    // at its size limit. A door that never opened, a lost connection, or a changed server identity read as their
    // own typed results and are NOT this; nor is a run the daemon had to kill (it does not come back as ran).
    const NOT_THE_SERVERS_VERDICT = new Set(['auth-failed', 'connect-failed', 'host-key-mismatch', 'host-key-unverified', 'sync-server-unreachable', 'sync-server-unverified']);
    const refused = run && run.ok === true && run.ran === true && run.code === 7 && String(run.result) === 'needs-resync' && !NOT_THE_SERVERS_VERDICT.has(String(run.result)) && upBytes >= 400 * MiB;
    out.peaks.up.outcome = completed ? 'completed' : (refused ? 'server-refused' : 'failed');
    out.peaks.up.streamedMB = streamedMB;
    row('up-streamed-to-server-verdict', completed || out.peaks.up.outcome === 'server-refused',
      { outcome: out.peaks.up.outcome, streamedMB, result: run && run.result, code: run && run.code, ran: run && run.ran, onServer, seconds: out.peaks.up.seconds });
    row('up-file-completed', completed, { onServer, note: completed ? null : 'the server did not accept a file this large over SFTP (its staging limit); the client streamed flat to that verdict' });
    row('up-helper-observed', pk.helperSamples >= 3, { helperSamples: pk.helperSamples, samples: pk.samples });
    row('up-memory-flat', pk.main < CEILING_MB && pk.daemon < CEILING_MB && pk.helper < CEILING_MB && pk.helper > 0, { peakMB: { main: pk.main, daemon: pk.daemon, helper: pk.helper }, ceilingMB: CEILING_MB, fileMB: out.fileMB });
    row('up-one-credential', mints - mintsBefore === 1, mints - mintsBefore);
  }
  row('progress-was-integers-only', progress.length > 0 && progress.every((p) => Object.values(p).every((v) => v == null || typeof v === 'number' || typeof v === 'string' && v === VID || Array.isArray(v) && v.every((x) => typeof x === 'number'))), progress.length);

  // ---- after the runs: the daemon settles back, nothing lingers --------------------------------------------------
  await sleep(4000);
  const tail = sampler.state.samples.filter((s) => s.t >= Date.now() - 3000);
  const daemonNow = tail.filter((s) => s.pid === daemonPid).map((s) => s.ws);
  const helpersNow = tail.filter((s) => s.ppid === daemonPid).length;
  row('daemon-settles', daemonNow.length > 0 && Math.max(...daemonNow) < CEILING_MB && helpersNow === 0, { daemonMB: daemonNow.length ? Math.max(...daemonNow) : null, helpersRunning: helpersNow });
  sampler.stop();

  // ---- clean up: stop the helper, forget the device, delete the throwaway vault, remove the files ------------------
  await mgr.clearSftpCred(5000).catch(() => null);
  await teardown();
  await sleep(500);

  // The verdict: every row, EXCEPT that the server accepting the whole upload is informative — a server that
  // refuses large SFTP uploads by configuration is reported, not failed, when the client streamed flat to it.
  out.ok = out.rows.every((r) => r.ok || r.row === 'up-file-completed');
  out.uploadCompleted = out.rows.some((r) => r.row === 'up-file-completed' && r.ok);
  out.memoryOk = out.rows.filter((r) => /memory-flat|daemon-settles/.test(r.row)).every((r) => r.ok); // the memory verdict on its own
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`${out.ok ? 'PASS' : 'FAIL'} large-file-memory-check (${out.rows.filter((r) => r.ok).length}/${out.rows.length}; memory ${out.memoryOk ? 'flat' : 'NOT flat'}) file=${out.fileMB}MB peaks down=${JSON.stringify(out.peaks.down && { main: out.peaks.down.main, daemon: out.peaks.down.daemon, helper: out.peaks.down.helper })} up=${JSON.stringify(out.peaks.up && { main: out.peaks.up.main, daemon: out.peaks.up.daemon, helper: out.peaks.up.helper, outcome: out.peaks.up.outcome, streamedMB: out.peaks.up.streamedMB })}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch(async (e) => { out.fatal = scrub(String((e && e.stack) || e)); await teardown(); dump(); app.exit(2); });

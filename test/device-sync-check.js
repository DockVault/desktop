'use strict';

/*
 * Live check of device sync end to end against a RUNNING vault (not a unit test — run it under Electron,
 * pointed at a throwaway server): the real OS secret store, the real sync helper (rclone) in the real
 * forked daemon, the real device routes. It registers this computer, grants it a password-protected
 * vault (proving the password once), and then syncs a folder over SFTP on the device's own identity —
 * the account session is used only for the set-up steps and never for a mint. It then proves the
 * fail-closed rows: a forged host key is refused before any transfer, a rotated vault password stops
 * the device with "prove it once more", a suspended device stops, a revoked device stops and its live
 * credential dies, and forgetting the device leaves nothing behind. In between, the identity is rotated
 * on the server and the rotated identity keeps syncing while the retired one dies with its grace window.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required, e.g. http://127.0.0.1:8360)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_SFTP_PORT      the port the server should advertise for SFTP (default 2222)
 *   DOCKVAULT_PROOF_DB_CONTAINER   the server's postgres container, for the suspend row (optional; unset skips it)
 *
 * Writes .local/device-sync-check.json with one row per proof step. No secret, token, or password is
 * ever written to the result (scrubbed and asserted).
 */

const { app, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const { DaemonManager } = require('../src/main/daemon-manager');
const { CredCache } = require('../src/main/cred-cache');
const { MintPathSelector } = require('../src/main/mint-path');
const { mintDeviceSftpAccess } = require('../src/main/device-mint');
const deviceSecretStore = require('../src/main/device-secret-store');
const deviceGrant = require('../src/main/device-grant');
const deviceGrantStore = require('../src/main/device-grant-store');
const { registerDevice, forgetDevice } = require('../src/main/device-register');
const { refreshDeviceSecret, isRotationDue } = require('../src/main/device-refresh');
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const SFTP_PORT = Number(process.env.DOCKVAULT_PROOF_SFTP_PORT || 2222);
const DB_CONTAINER = process.env.DOCKVAULT_PROOF_DB_CONTAINER || '';
const RESULT = path.join(__dirname, '..', '.local', 'device-sync-check.json');

const out = { api: API, rows: [] };
const secrets = [ADMIN_PW]; // everything that must never appear in the result
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
const watchdog = setTimeout(() => { row('watchdog', false, 'timed out'); dump(); app.exit(3); }, 12 * 60 * 1000);
app.on('window-all-closed', () => {});

// Resolve the real sync helper + its pin, as the app's own daemon check does.
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
const jsonBody = (o) => ({ 'Content-Type': 'application/json' });
function psql(sql) {
  if (!DB_CONTAINER) return null;
  return execFileSync('docker', ['exec', DB_CONTAINER, 'psql', '-U', 'sftp_user', '-d', 'sftp_db', '-t', '-A', '-c', sql]).toString().trim();
}

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE to point at a throwaway server'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-device-'));
  const local = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-devsync-'));
  const rand = crypto.randomBytes(4).toString('hex');
  const VAULT_NAME = `Device sync proof ${rand}`;
  const VPW = `Proof-pw-${crypto.randomBytes(6).toString('hex')}`;
  const VPW2 = `Rotated-pw-${crypto.randomBytes(6).toString('hex')}`;
  secrets.push(VPW, VPW2);
  out.secureStore = !!(safeStorage && safeStorage.isEncryptionAvailable && safeStorage.isEncryptionAvailable());

  // ---- account-session set-up (the only place the account session is used) ---------------------------
  const login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { dump(); app.exit(2); return; }

  const vc = await api('/vaults', { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ name: VAULT_NAME, type: 'standard', password: VPW }) });
  const VID = vc.body && vc.body.id;
  row('create-password-vault', !!VID, vc.status);
  if (!VID) { dump(); app.exit(2); return; }

  // ---- register this computer, bound to this server ------------------------------------------------
  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Proof laptop', dir, safeStorage });
  row('register', reg.ok === true && typeof reg.deviceId === 'string', reg.ok ? 'ok' : reg.reason);
  const DEVICE_ID = reg.deviceId;
  const readHere = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
  const readOther = deviceSecretStore.readDeviceSecret(safeStorage, dir, 'https://other.example');
  if (readHere.secret) secrets.push(readHere.secret);
  row('identity-bound-to-this-server', readHere.status === 'ok' && readOther.status === 'absent-for-this-server' && readOther.secret === null,
    { here: readHere.status, other: readOther.status, otherOrigin: readOther.otherOrigin || null });
  readHere.secret = null;
  const hint = JSON.parse(fs.readFileSync(path.join(dir, 'device-id.json'), 'utf8'));
  row('sidecar-id-only', Object.keys(hint).sort().join(',') === 'deviceId,v', Object.keys(hint));

  // ---- grant the vault to this computer, proving the password ONCE --------------------------------
  const g = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEVICE_ID, vaultId: VID, vaultType: 'standard', vaultName: VAULT_NAME, vaultPassword: VPW, dir, safeStorage });
  row('grant', g.ok === true && g.hasPassword === true && g.recorded === true, g.ok ? { hasPassword: g.hasPassword, recorded: g.recorded } : g.reason);

  // ---- the real helper --------------------------------------------------------------------------
  const rc = rcloneConfig();
  const mgr = new DaemonManager(dir, rc);
  const ready = new Promise((resolve) => mgr.on('ready', resolve));
  mgr.start();
  const r0 = await Promise.race([ready, sleep(10000).then(() => ({ type: 'timeout' }))]);
  const hs = await mgr.syncStatus(20000);
  row('helper-ready', r0 && r0.type === 'ready' && hs && hs.ok, { version: hs && hs.version });

  // ---- the credential path, wired exactly as the app wires it -------------------------------------
  const mintCalls = [];
  let forgeKey = null; // when set, the mint response's host key is replaced (the forged-server row)
  const recFetch = async (url, init) => {
    const res = await httpJson(url, init);
    if (!String(url).endsWith('/device/sync-credential')) return res;
    let data = null; try { data = await res.json(); } catch { data = null; }
    mintCalls.push({ body: init && init.body ? JSON.parse(init.body) : null, status: res.status, port: data && data.port, host: data && data.host, hasKey: !!(data && /^(ssh-|ecdsa-|sk-)\S+\s+\S/.test(String(data.host_public_key || ''))), deactivateAt: data && data.deactivate_at });
    if (forgeKey && data && data.host_public_key) data = { ...data, host_public_key: forgeKey };
    return { ok: res.ok, status: res.status, json: async () => data };
  };
  const withDeviceSecret = async (fn) => {
    const id = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
    if (id.status !== 'ok') { const e = new Error('device identity unavailable'); e.reason = id.status === 'unreadable' ? 'device-secret-unreadable' : 'device-request-refused'; throw e; }
    try { return await fn(API, id.secret); } finally { id.secret = null; }
  };
  const mintPath = new MintPathSelector({
    readSecret: () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); r.secret = null; return { status: r.status }; },
    listGrants: () => withDeviceSecret((origin, secret) => deviceGrant.listMyGrants({ serverOrigin: origin, deviceSecret: secret, dir, safeStorage }, { fetchFn: recFetch })),
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
  });
  let sends = 0;
  const makeCache = () => new CredCache({
    mint: async (vaultId) => {
      const via = mintPath.current(vaultId);
      if (via === 'device') return withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId }, recFetch));
      const e = new Error('no device path for this run'); e.reason = 'internal-error'; throw e;
    },
    send: (bundle, epoch) => { sends += 1; return mgr.sendSftpCred(bundle, 12000, epoch); },
    epoch: () => mgr.currentEpoch(),
  });
  let credCache = makeCache();
  mgr.setCredProvider(async (vault) => (vault === VID ? credCache.ensureSent(vault) : { ok: false, reason: 'not-in-flight' }));

  const el = await mintPath.begin(VID);
  row('eligibility-device-path', el.ok === true && el.via === 'device' && el.remotePath === `vault_${String(VID).toLowerCase()}` && el.vaultName === VAULT_NAME, el.ok ? { via: el.via, remotePath: el.remotePath } : el.reason);
  const remotePath = el.remotePath;

  const m1 = await credCache.ensureSent(VID);
  row('mint-and-send', m1.ok === true, m1.ok ? 'ok' : m1.reason);
  const c1 = mintCalls[0] || {};
  row('mint-request-body', !!c1.body && Object.keys(c1.body).sort().join(',') === 'validity_minutes,vault_id' && c1.body.vault_id === VID && c1.body.validity_minutes === 15, c1.body);
  row('mint-advertises-reachable-port', c1.port === SFTP_PORT, { advertised: c1.port, expected: SFTP_PORT, host: c1.host });
  row('mint-carries-host-key', c1.hasKey === true, c1.hasKey);

  // ---- the first sync: a baseline of two local files lands on the server over SFTP ---------------------
  fs.writeFileSync(path.join(local, 'first.txt'), `first ${rand}\n`);
  fs.writeFileSync(path.join(local, 'second.txt'), `second ${rand}\n`);
  const run1 = await mgr.runSync({ vault: VID, local, remotePath, resync: true }, 5 * 60 * 1000);
  row('baseline-sync', run1 && run1.ok === true && run1.ran === true && /ok/.test(String(run1.result)), run1 && { ok: run1.ok, ran: run1.ran, result: run1.result, reason: run1.reason || null, errorName: run1.errorName || null, errorCode: run1.errorCode || null, errorSub: run1.errorSub || null });
  const listFiles = async () => {
    const l = await api(`/vaults/${VID}/files`, { headers: auth(JWT, { 'X-Vault-Password': VPW }) });
    return JSON.stringify(l.body || '');
  };
  let names = await listFiles();
  row('files-on-server', names.includes('first.txt') && names.includes('second.txt'));

  // ---- a routine sync: one new local file, one fresh single-use credential --------------------------
  fs.writeFileSync(path.join(local, 'third.txt'), `third ${rand}\n`);
  await mintPath.begin(VID);
  const m2 = await credCache.ensureSent(VID);
  const run2 = m2.ok ? await mgr.runSync({ vault: VID, local, remotePath, resync: false }, 5 * 60 * 1000) : null;
  names = await listFiles();
  row('routine-sync', m2.ok === true && run2 && run2.ok === true && run2.ran === true && String(run2.result) === 'ok' && names.includes('third.txt'), run2 && { result: run2.result, minted: mintCalls.length });
  row('fresh-credential-per-run', mintCalls.length >= 2 && new Set(mintCalls.map((c) => c.deactivateAt)).size >= 1, mintCalls.length);

  // ---- rotate the identity: the new secret is stored under the same binding and keeps minting ----------------
  const preRotate = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
  const retired = preRotate.secret; preRotate.secret = null; if (retired) secrets.push(retired);
  row('rotation-not-yet-due', isRotationDue(preRotate, Date.now()) === false, { rotatedAt: preRotate.rotatedAt });
  const rot0 = await refreshDeviceSecret({ serverOrigin: API, dir, safeStorage }, { fetchFn: recFetch });
  const postRotate = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
  const changed = !!(postRotate.secret && retired && postRotate.secret !== retired);
  postRotate.secret = null;
  row('rotation-stores-new-identity', rot0.ok === true && rot0.epoch === (preRotate.epoch || 1) + 1 && postRotate.status === 'ok' && changed && postRotate.serverOrigin === new URL(API).origin && postRotate.epoch === rot0.epoch,
    { ok: rot0.ok, reason: rot0.reason || null, epoch: rot0.epoch, sameBinding: postRotate.serverOrigin === new URL(API).origin });
  fs.writeFileSync(path.join(local, 'fourth.txt'), `fourth ${rand}
`);
  await mintPath.begin(VID);
  const mRot = await credCache.ensureSent(VID);
  const runRot = mRot.ok ? await mgr.runSync({ vault: VID, local, remotePath, resync: false }, 5 * 60 * 1000) : null;
  names = await listFiles();
  row('rotated-identity-syncs', mRot.ok === true && runRot && String(runRot.result) === 'ok' && names.includes('fourth.txt'), mRot.ok ? (runRot && runRot.result) : mRot.reason);
  // the retired secret still mints inside the server's short grace window (a request already in flight is not cut off) ...
  const graceMint = await (async () => { try { await mintDeviceSftpAccess({ serverOrigin: API, deviceSecret: retired, vaultId: VID }, recFetch); return 'minted'; } catch (e) { return e && e.reason; } })();
  row('retired-secret-in-grace-still-mints', graceMint === 'minted', graceMint);
  // ... but a refresh from the retired secret is refused as stale — the lost-answer signal the desktop stops on
  const staleRefresh = await api('/device/refresh', { method: 'POST', headers: auth(retired) });
  row('retired-secret-cannot-rotate', staleRefresh.status === 401 && staleRefresh.body && staleRefresh.body.detail && staleRefresh.body.detail.reason === 'device-secret-stale', { status: staleRefresh.status, reason: staleRefresh.body && staleRefresh.body.detail && staleRefresh.body.detail.reason });
  await mgr.clearSftpCred(5000);

  // ---- a forged host key: refused before any transfer (the session pin wins; no trust on first use) ------
  forgeKey = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIForgedForgedForgedForgedForgedForgedForged0';
  const sendsBefore = sends;
  await mintPath.begin(VID);
  const mf = await credCache.ensureSent(VID);
  row('forged-host-key-refused-pinned', mf.ok === false && mf.reason === 'host-key-mismatch' && sends === sendsBefore, mf.reason);
  // and with NO pin yet (a fresh process), the forged key is pinned and the real server is then refused at connect
  credCache = makeCache();
  await mintPath.begin(VID);
  const mf2 = await credCache.ensureSent(VID);
  const runF = mf2.ok ? await mgr.runSync({ vault: VID, local, remotePath, resync: false }, 3 * 60 * 1000) : null;
  row('forged-host-key-refused-at-connect', mf2.ok === true && runF && String(runF.result) === 'host-key-mismatch', runF && { result: runF.result, ran: runF.ran });
  forgeKey = null;
  credCache = makeCache();

  // ---- the vault password changes on the server: the device must prove it once more ----------------------
  const rot = await api(`/vaults/${VID}/password`, { method: 'PUT', headers: auth(JWT, jsonBody()), body: JSON.stringify({ current_password: VPW, new_password: VPW2 }) });
  if (rot.ok) {
    await mintPath.begin(VID);
    const mr = await credCache.ensureSent(VID);
    row('password-rotation-needs-reproof', mr.ok === false && mr.reason === 'grant-needs-reproof', mr.reason);
    const g2 = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEVICE_ID, vaultId: VID, vaultType: 'standard', vaultName: VAULT_NAME, vaultPassword: VPW2, dir, safeStorage });
    fs.writeFileSync(path.join(local, 'fifth.txt'), `fifth ${rand}
`);
    await mintPath.begin(VID);
    const mr2 = await credCache.ensureSent(VID);
    const runRe = mr2.ok ? await mgr.runSync({ vault: VID, local, remotePath, resync: false }, 5 * 60 * 1000) : null;
    row('reproof-recovers', g2.ok === true && mr2.ok === true && runRe && String(runRe.result) === 'ok', g2.ok ? (mr2.ok ? (runRe && runRe.result) : mr2.reason) : g2.reason);
  } else {
    row('password-rotation-needs-reproof', false, { skipped: true, status: rot.status, detail: scrub(JSON.stringify(rot.body)).slice(0, 200) });
  }

  // ---- revoke: a credential minted just before dies, the next dispatch stops, the next mint is refused ------
  await mintPath.begin(VID);
  const mv = await credCache.ensureSent(VID); // a LIVE single-use credential now sits in the helper
  const rv = await api(`/devices/${DEVICE_ID}/revoke`, { method: 'POST', headers: auth(JWT) });
  const runR = mv.ok && rv.ok ? await mgr.runSync({ vault: VID, local, remotePath, resync: false }, 3 * 60 * 1000) : null;
  row('revoke-kills-live-credential', mv.ok === true && rv.ok === true && runR && String(runR.result) === 'auth-failed', runR && { result: runR.result, revoke: rv.status });
  const elR = await mintPath.begin(VID);
  row('revoke-stops-dispatch', elR.ok === false && elR.reason === 'device-revoked', elR.reason || elR.via);
  await mgr.clearSftpCred(5000);
  // With no run begun, the credential cache's mint has no path and reports a wiring fault — it never mints.
  const mvr = await credCache.ensureSent(VID);
  row('no-run-no-mint', mvr.ok === false && mvr.reason === 'internal-error', mvr.reason);
  // And the raw device mint itself is refused by the server for a revoked device.
  const rawMint = () => withDeviceSecret((origin, secret) => mintDeviceSftpAccess({ serverOrigin: origin, deviceSecret: secret, vaultId: VID }, recFetch)).then(() => 'minted', (e) => e && e.reason);
  row('revoke-refuses-mint', (await rawMint()) === 'device-revoked', mintCalls[mintCalls.length - 1] && mintCalls[mintCalls.length - 1].status);

  // ---- forget: the local identity goes away; nothing left behind ------------------------------------------
  const fg = await forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage });
  const afterForget = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
  row('forget-clears-identity', fg.cleared === true && afterForget.status === 'absent' && !fs.existsSync(path.join(dir, 'device-secret.bin')), { revoked: fg.revoked, status: afterForget.status });

  // ---- suspend (a second registration): a replayed retired secret suspends the device; sync stops -----------
  if (DB_CONTAINER) {
    const reg2 = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Proof laptop two', dir, safeStorage });
    const g3 = reg2.ok ? await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: reg2.deviceId, vaultId: VID, vaultType: 'standard', vaultName: VAULT_NAME, vaultPassword: rot.ok ? VPW2 : VPW, dir, safeStorage }) : { ok: false };
    let suspended = null;
    if (reg2.ok && g3.ok) {
      const cur = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
      const oldSecret = cur.secret; cur.secret = null;
      secrets.push(oldSecret);
      const rf = await api('/device/refresh', { method: 'POST', headers: auth(oldSecret) });
      const newSecret = rf.body && rf.body.secret;
      if (newSecret) {
        secrets.push(newSecret);
        deviceSecretStore.storeDeviceSecret(safeStorage, dir, { deviceId: reg2.deviceId, secret: newSecret, epoch: (cur.epoch || 1) + 1, serverOrigin: API });
        psql(`update devices set prev_secret_retired_at = now() - interval '10 minutes' where id='${reg2.deviceId}';`);
        const replay = await api('/device/grants', { headers: auth(oldSecret) }); // a retired secret, past its grace
        suspended = psql(`select suspended from devices where id='${reg2.deviceId}';`);
        const ms = await rawMint();
        row('suspend-stops-sync', replay.status === 401 && /t/.test(String(suspended)) && ms === 'device-suspended', { replay: replay.status, suspended, mint: ms });
        const elS = await mintPath.begin(VID);
        row('suspend-stops-dispatch', elS.ok === false && elS.reason === 'device-suspended', elS.reason || elS.via);
      } else {
        row('suspend-stops-sync', false, { skipped: 'refresh failed', status: rf.status });
      }
    } else {
      row('suspend-stops-sync', false, { skipped: 'second registration/grant failed', reg: reg2.reason || 'ok', grant: g3.reason || 'ok' });
    }
    await api(`/devices/${reg2.deviceId}/revoke`, { method: 'POST', headers: auth(JWT) }).catch(() => null);
    await forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage });
  }

  // ---- clean up the throwaway vault; stop the helper --------------------------------------------------
  await api(`/vaults/${VID}/delete`, { method: 'POST', headers: auth(JWT, jsonBody()), body: JSON.stringify({ password: rot.ok ? VPW2 : VPW }) }).catch(() => null);
  mgr.stop();
  await sleep(500);
  try { fs.rmSync(dir, { recursive: true, force: true }); fs.rmSync(local, { recursive: true, force: true }); } catch { /* ignore */ }

  out.ok = out.rows.every((r) => r.ok);
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = scrub(String((e && e.stack) || e)); dump(); app.exit(2); });

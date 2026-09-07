'use strict';

/*
 * Live check of the recovery half — the door and the rotation recovery — against a RUNNING vault (run it under
 * Electron, pointed at a throwaway server). The real stores, the real device routes, the real resume sweep and
 * the real reconciliation; the server's answers are the server's own.
 *
 * The rows:
 *   - set-up: the identity registers only from an empty store, the grant is created and recorded, the vault syncs;
 *   - prove-once-more: a server-side vault-password change makes the mint refuse, the re-proof re-grants, sync returns;
 *   - set-up-again: the owner removes this computer, the vault refuses as removed, and the door (forget, register,
 *     re-grant) rewrites the record so the refusal clears and sync returns;
 *   - the resume sweep with an UNREADABLE grant record DEFERS: no grant is created, the marker is kept;
 *   - a rotation cut off before its answer was stored leaves a marker that makes the identity present NOTHING, and
 *     the reconciliation over the account's own device list decides it: the same epoch clears it, a higher epoch
 *     (the server did rotate) is stale, and a device the owner removed reads revoked;
 *   - across every one of those, the retired secret is never presented on any request.
 *
 *   DOCKVAULT_PROOF_API            the vault's API origin (required)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *
 * Writes .local/device-wiring-check.json. No secret, token, or password is ever written to the result.
 */

const { app, safeStorage } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');

const deviceSecretStore = require('../src/main/device-secret-store');
const deviceGrantStore = require('../src/main/device-grant-store');
const pendingGrant = require('../src/main/device-pending-grant');
const deviceGrant = require('../src/main/device-grant');
const { registerDevice, forgetDevice, mayRegisterHere, checkDeviceSyncSupported } = require('../src/main/device-register');
const { resumePendingGrants } = require('../src/main/device-grant-resume');
const { reconcileRotationMarker, refreshDeviceSecret } = require('../src/main/device-refresh');
const { mintDeviceSftpAccess } = require('../src/main/device-mint');
const { MintPathSelector } = require('../src/main/mint-path');
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const RESULT = path.join(__dirname, '..', '.local', 'device-wiring-check.json');

const out = { api: API, rows: [] };
const secrets = [ADMIN_PW];
const retired = [];                     // every secret the server has retired: none may ever be presented again
function row(name, ok, detail) { out.rows.push({ row: name, ok: !!ok, detail: detail === undefined ? null : detail }); }
function scrub(t) { let s = String(t); for (const x of secrets) if (x) s = s.split(x).join('[redacted]'); return s; }
function dump() {
  try {
    fs.mkdirSync(path.dirname(RESULT), { recursive: true });
    out.leakFree = secrets.every((s) => !s || !JSON.stringify(out).includes(s));
    fs.writeFileSync(RESULT, scrub(JSON.stringify(out, null, 2)));
  } catch { /* ignore */ }
}
const watchdog = setTimeout(() => { row('watchdog', false, 'timed out'); dump(); app.exit(3); }, 12 * 60 * 1000);
app.on('window-all-closed', () => {});

// Every request the app makes passes through here, so a row can assert what was and was not sent.
const calls = [];
const recFetch = async (url, init) => {
  const bearer = (init && init.headers && init.headers.Authorization) || '';
  calls.push({ url: String(url), method: (init && init.method) || 'GET', bearer: String(bearer).replace(/^Bearer /, '') });
  return httpJson(url, init);
};
const since = () => calls.length;
const callsSince = (n) => calls.slice(n);
const presentedRetired = () => calls.filter((c) => retired.some((r) => r && c.bearer === r));

async function api(pathname, init = {}) {
  const res = await httpJson(`${API}${pathname}`, init);
  let body = null; try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}
const auth = (t, extra = {}) => ({ Authorization: `Bearer ${t}`, ...extra });
const jsonHeaders = () => ({ 'Content-Type': 'application/json' });

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) { out.fatal = 'set DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE'; dump(); app.exit(2); return; }
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-wiring-'));
  const rand = crypto.randomBytes(4).toString('hex');
  const NAME = `Wiring proof ${rand}`;
  const PW1 = `Proof-pw-${crypto.randomBytes(6).toString('hex')}`;
  const PW2 = `Rotated-pw-${crypto.randomBytes(6).toString('hex')}`;
  secrets.push(PW1, PW2);

  const login = await api('/auth/login', { method: 'POST', headers: jsonHeaders(), body: JSON.stringify({ username: 'admin', password: ADMIN_PW }) });
  const JWT = login.body && login.body.access_token;
  if (JWT) secrets.push(JWT);
  row('admin-login', !!JWT, login.status);
  if (!JWT) { dump(); app.exit(2); return; }
  const vault = (await api('/vaults', { method: 'POST', headers: auth(JWT, jsonHeaders()), body: JSON.stringify({ name: NAME, type: 'standard', password: PW1 }) })).body;
  const VID = vault && vault.id;
  row('create-password-vault', !!VID);
  if (!VID) { dump(); app.exit(2); return; }

  const heldSecret = () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); const s = r.secret; r.secret = null; return { status: r.status, secret: s, epoch: r.epoch, deviceId: r.deviceId }; };
  const mintNow = async () => {
    const id = heldSecret();
    if (id.status !== 'ok') return { refused: id.status };
    try { await mintDeviceSftpAccess({ serverOrigin: API, deviceSecret: id.secret, vaultId: VID }, recFetch); return { minted: true }; }
    catch (e) { return { refused: (e && e.reason) || 'unknown' }; }
  };
  const selectorFor = () => new MintPathSelector({
    readSecret: () => { const r = deviceSecretStore.readDeviceSecret(safeStorage, dir, API); r.secret = null; return { status: r.status }; },
    listGrants: async () => { const id = heldSecret(); if (id.status !== 'ok') { const e = new Error('x'); e.reason = 'device-identity-missing'; throw e; } return deviceGrant.listMyGrants({ serverOrigin: API, deviceSecret: id.secret, dir, safeStorage }, { fetchFn: recFetch }); },
    readGrantRecord: () => deviceGrantStore.readGrantMeta(safeStorage, dir),
  });

  // ---- 1. THE DOOR: set up this computer ------------------------------------------------------------
  const probe = await checkDeviceSyncSupported({ serverOrigin: API, accountToken: JWT }, recFetch);
  const emptyStore = deviceSecretStore.readDeviceSecret(safeStorage, dir, API).status;
  row('probe-and-empty-store-allow-registration', probe.supported === true && probe.reason === 'ok' && emptyStore === 'absent' && mayRegisterHere(emptyStore) === true, { probe: probe.supported, reason: probe.reason, store: emptyStore });
  const reg = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Wiring proof laptop', dir, safeStorage });
  const DEV = reg.deviceId;
  row('register-creates-the-identity', reg.ok === true && heldSecret().status === 'ok', reg.ok ? 'ok' : reg.reason);
  row('a-second-registration-is-refused-over-a-live-identity', mayRegisterHere(heldSecret().status) === false && (await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Second', dir, safeStorage })).reason === 'already-registered');
  const g1 = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEV, vaultId: VID, vaultType: 'standard', vaultName: NAME, vaultPassword: PW1, dir, safeStorage });
  row('grant-is-created-and-recorded', g1.ok === true && g1.recorded === true && !!deviceGrantStore.getGrantMeta(safeStorage, dir, VID), g1.ok ? 'ok' : g1.reason);
  const m1 = await mintNow();
  row('the-vault-mints-on-the-device-identity', m1.minted === true, m1);

  // ---- 2. PROVE ONCE MORE: the vault password changes on the server ----------------------------------
  const rot = await api(`/vaults/${VID}/password`, { method: 'PUT', headers: auth(JWT, jsonHeaders()), body: JSON.stringify({ current_password: PW1, new_password: PW2 }) });
  const m2 = await mintNow();
  row('a-changed-vault-password-refuses-the-mint-as-needing-re-proof', rot.ok === true && m2.refused === 'grant-needs-reproof', { rotated: rot.ok, refused: m2.refused });
  const g2 = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: DEV, vaultId: VID, vaultType: 'standard', vaultName: NAME, vaultPassword: PW2, dir, safeStorage });
  const m3 = await mintNow();
  row('proving-the-new-password-once-restores-sync', g2.ok === true && m3.minted === true, { grant: g2.ok, mint: m3 });

  // ---- 3. THE RESUME SWEEP WITH AN UNREADABLE RECORD MUST DEFER --------------------------------------
  // A grant is pending for the vault, and the record that says whether it was EVER granted cannot be read.
  // The sweep must not guess: no grant may be created, and the marker must stay for a later pass.
  pendingGrant.addPending(safeStorage, dir, VID);
  const recordPath = path.join(dir, 'device-grants.json');
  const goodRecord = fs.readFileSync(recordPath);
  fs.writeFileSync(recordPath, 'corrupt-not-json');
  const markBeforeSweep = since();
  const grantCalls = [];
  const sweep = await resumePendingGrants({
    listPending: () => pendingGrant.listPending(safeStorage, dir),
    isConfigured: () => true,
    wasGranted: (vaultId) => { try { return !!deviceGrantStore.getGrantMeta(safeStorage, dir, vaultId); } catch { return 'unreadable'; } },
    checkActiveGrant: async () => 'inconclusive',
    vaultRequiresPassword: () => true,
    pullPassword: async () => PW2,
    grant: async (o) => { grantCalls.push(o); return { ok: true }; },
    clearPending: (vaultId) => pendingGrant.clearPending(safeStorage, dir, vaultId),
    ackComplete: () => {},
  });
  const postedGrants = callsSince(markBeforeSweep).filter((c) => c.method === 'POST' && /\/grants(\?|$)/.test(c.url));
  row('an-unreadable-grant-record-defers-the-resume-sweep', grantCalls.length === 0 && postedGrants.length === 0 && Array.isArray(sweep.deferred) && sweep.deferred.includes(VID),
    { grantsAttempted: grantCalls.length, postsToGrants: postedGrants.length, deferred: sweep.deferred, granted: sweep.granted });
  row('the-pending-marker-is-kept-for-a-later-pass', pendingGrant.isPending(safeStorage, dir, VID) === true);
  fs.writeFileSync(recordPath, goodRecord);     // the record becomes readable again
  const sweep2 = await resumePendingGrants({
    listPending: () => pendingGrant.listPending(safeStorage, dir),
    isConfigured: () => true,
    wasGranted: (vaultId) => { try { return !!deviceGrantStore.getGrantMeta(safeStorage, dir, vaultId); } catch { return 'unreadable'; } },
    checkActiveGrant: async () => 'active',
    vaultRequiresPassword: () => true,
    pullPassword: async () => PW2,
    grant: async (o) => { grantCalls.push(o); return { ok: true }; },
    clearPending: (vaultId) => pendingGrant.clearPending(safeStorage, dir, vaultId),
    ackComplete: () => {},
  });
  row('once-the-record-reads-again-the-sweep-settles-the-marker', pendingGrant.isPending(safeStorage, dir, VID) === false, { deferred: sweep2.deferred, granted: sweep2.granted, dropped: sweep2.dropped });

  // ---- 4. A ROTATION CUT OFF BEFORE ITS ANSWER WAS STORED --------------------------------------------
  const before = heldSecret();
  deviceSecretStore.markDeviceSecretRotating(dir);          // as if the process died between request and store
  const underMarker = deviceSecretStore.readDeviceSecret(safeStorage, dir, API);
  const markM = since();
  const mUnderMarker = await mintNow();
  row('a-surviving-rotation-marker-presents-nothing', underMarker.status === 'stale' && underMarker.secret === null && mUnderMarker.refused === 'stale' && callsSince(markM).length === 0,
    { status: underMarker.status, secretWithheld: underMarker.secret === null, mint: mUnderMarker.refused, requests: callsSince(markM).length });
  const devicesRow = async () => {
    const list = await api('/devices', { headers: auth(JWT) });
    const rows = Array.isArray(list.body) ? list.body : (list.body && list.body.devices) || [];
    const r = rows.find((x) => x && (x.id === DEV || x.device_id === DEV));
    return r ? { found: true, isActive: r.is_active !== false, epoch: r.epoch } : { found: false };
  };
  const rowSame = await devicesRow();
  row('the-same-epoch-clears-the-marker', reconcileRotationMarker(rowSame, before.epoch) === 'clear', { serverEpoch: rowSame.epoch, blobEpoch: before.epoch, decision: reconcileRotationMarker(rowSame, before.epoch) });
  // the server DID rotate and the answer was lost: rotate for real without keeping it, so its epoch moves on
  const lost = await api('/device/refresh', { method: 'POST', headers: auth(before.secret) });
  let retiredAt = null;
  if (lost.body && lost.body.secret) { secrets.push(lost.body.secret); retired.push(before.secret); retiredAt = since(); }
  const rowAhead = await devicesRow();
  row('a-higher-epoch-on-the-server-reads-stale', lost.ok === true && reconcileRotationMarker(rowAhead, before.epoch) === 'stale', { serverEpoch: rowAhead.epoch, blobEpoch: before.epoch, decision: reconcileRotationMarker(rowAhead, before.epoch) });
  // and a device the owner removed reads revoked, whatever the epoch
  await api(`/devices/${DEV}/revoke`, { method: 'POST', headers: auth(JWT) });
  const rowGone = await devicesRow();
  row('a-removed-device-reads-revoked', reconcileRotationMarker(rowGone, before.epoch) === 'revoked' || rowGone.found === false, { row: rowGone, decision: reconcileRotationMarker(rowGone, before.epoch) });
  row('doubt-inside-a-row-keeps-the-marker', reconcileRotationMarker({ found: true, isActive: true, epoch: 'x' }, before.epoch) === 'keep' && reconcileRotationMarker({ found: true, isActive: true }, before.epoch) === 'keep' && reconcileRotationMarker({ found: true, isActive: true, epoch: 2 }, 'x') === 'keep',
    { malformedEpoch: reconcileRotationMarker({ found: true, isActive: true, epoch: 'x' }, before.epoch), missingEpoch: reconcileRotationMarker({ found: true, isActive: true }, before.epoch) });
  // A row that is genuinely ABSENT is a removal, not doubt — it stops sync and asks for a fresh set-up, the safe
  // direction. Doubt about whether the list could be READ at all never reaches here: the caller returns early and
  // keeps the marker, so the decision below is only ever made on a list the app actually got.
  row('an-unreadable-answer-never-reaches-the-decision-and-an-absent-row-is-a-removal', reconcileRotationMarker({ found: false }, before.epoch) === 'revoked' && reconcileRotationMarker(null, before.epoch) === 'revoked');

  // ---- 5. THE RETIRED SECRET WAS NEVER PRESENTED ------------------------------------------------------
  const refreshAfterMarker = await refreshDeviceSecret({ serverOrigin: API, dir, safeStorage }, { fetchFn: recFetch });
  row('a-marked-identity-refuses-to-rotate-rather-than-present-its-secret', refreshAfterMarker.ok === false && refreshAfterMarker.reason === 'stale', refreshAfterMarker);
  // Only uses AFTER the server retired it can be a replay; before that moment it was simply the current secret.
  const afterRetirement = retiredAt == null ? [] : calls.slice(retiredAt).filter((c) => retired.some((r) => r && c.bearer === r));
  const beforeRetirement = retiredAt == null ? [] : calls.slice(0, retiredAt).filter((c) => retired.some((r) => r && c.bearer === r));
  row('the-retired-secret-is-never-presented-once-the-server-has-retired-it', retiredAt != null && afterRetirement.length === 0,
    { afterRetirement: afterRetirement.map((c) => c.method + ' ' + c.url.replace(API, '')), whileItWasStillCurrent: beforeRetirement.length });

  // ---- 6. THE SET-UP-AGAIN DOOR: forget, register, re-grant ------------------------------------------
  const fg = await forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage });
  const afterForget = deviceSecretStore.readDeviceSecret(safeStorage, dir, API).status;
  row('forget-clears-the-identity-and-its-marks', fg.cleared === true && afterForget === 'absent' && mayRegisterHere(afterForget) === true, { cleared: fg.cleared, status: afterForget });
  const removedDecision = await selectorFor().begin(VID);
  row('before-the-door-runs-the-vault-refuses-as-removed', removedDecision.ok === false && removedDecision.reason === 'device-removed', removedDecision);
  const reg2 = await registerDevice({ serverOrigin: API, accountToken: JWT, label: 'Wiring proof laptop again', dir, safeStorage });
  const g3 = await deviceGrant.grantAndRecord({ serverOrigin: API, accountToken: JWT, deviceId: reg2.deviceId, vaultId: VID, vaultType: 'standard', vaultName: NAME, vaultPassword: PW2, dir, safeStorage });
  const afterDoor = await selectorFor().begin(VID);
  const m4 = await mintNow();
  row('the-door-rewrites-the-record-so-the-refusal-clears-and-sync-returns', reg2.ok === true && g3.ok === true && g3.recorded === true && afterDoor.ok === true && afterDoor.via === 'device' && m4.minted === true,
    { register: reg2.ok, grant: g3.ok, recorded: g3.recorded, decision: afterDoor.ok ? afterDoor.via : afterDoor.reason, mint: m4 });

  // ---- clean up ---------------------------------------------------------------------------------------
  await forgetDevice({ serverOrigin: API, accountToken: JWT, dir, safeStorage });
  await api(`/vaults/${VID}/delete`, { method: 'POST', headers: auth(JWT, jsonHeaders()), body: JSON.stringify({ password: PW2 }) }).catch(() => null);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }

  out.ok = out.rows.every((r) => r.ok);
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = scrub(String((e && e.stack) || e)); dump(); app.exit(2); });

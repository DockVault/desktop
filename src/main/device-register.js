'use strict';

/*
 * Device registration (the account-authenticated half of device sync) and the capability gate that
 * decides whether to OFFER it.
 *
 * registerDevice enforces the fail-safe order at the heart of this change — a device secret
 * must never land on disk with no server device behind it, and a server device must never be orphaned
 * with a secret the desktop could not store:
 *   1. PRE-CHECK a secure keychain backend. If absent, abort BEFORE creating anything server-side — a
 *      clean no-op, nothing to undo.
 *   2. POST /devices under the ACCOUNT session -> the server creates the row and returns the one-time
 *      secret + the deviceId.
 *   3. Store the secret+id in the OS keychain (the device-secret store). ANY failure after step 2 — a THROW
 *      (empty/encrypt/IO) OR a {stored:false} because the keychain backend flipped non-secure in the
 *      window between the pre-check and the store (a real check-then-store race) — is treated IDENTICALLY: the server
 *      row is now an ORPHAN, so delete it (account session) and zeroize the in-memory secret.
 *   4. If that orphan-cleanup delete ITSELF also fails, retain the deviceId in the advisory sidecar so a
 *      later reset/Remove can still name the exact row to revoke — and surface the un-cleaned orphan.
 * The secret is held in memory only from the response to the store, then its reference is dropped
 * (zeroizeSecret) — it is never logged, never returned to the renderer, and no token/secret/body ever
 * appears in a thrown error (only a status + a fixed reason literal).
 *
 * checkDeviceSyncSupported is a CAPABILITY PROBE, not a version-string parse (the version shape is the
 * server's to change): GET /devices under the account session. A clean 200 means the vault speaks the
 * device routes -> offer. A 404 means the route is absent -> the vault is too old. A 401/403 is an
 * auth/session problem, NOT a version signal. Anything else (5xx / transport) is INDETERMINATE -> fail
 * closed (do not offer) but honestly ("could not verify"), never "too old".
 */

const os = require('node:os');
const { isSecureBackend } = require('./token-store');
const defaultStore = require('./device-secret-store');

const MAX_LABEL_LEN = 64;
// Floor for the separator-collapsed identity-echo check: catches multi-segment default hostnames like
// DESKTOP-4KJ9P2 / Johns-MacBook-Pro (whose whole-name never appears as a token) while short fragments
// stay under it and don't over-reject unrelated labels. (A tunable privacy vs false-reject tradeoff.)
const IDENTITY_COLLAPSE_FLOOR = 8;
const IDENTITY_ECHO_MSG = "That looks like this computer's name on the network — pick something that doesn't identify it.";

function safeLower(s) { return (typeof s === 'string' ? s : '').toLowerCase().trim(); }
function osHostname() { try { return os.hostname(); } catch { return ''; } }
function osUsername() { try { return (os.userInfo() || {}).username || ''; } catch { return ''; } }

/**
 * Validate a user-chosen device label as NON-IDENTIFYING. Presence/shape only — never a token/UUID
 * format check. Returns the cleaned label (or null for no label); throws TypeError for an identifying
 * or over-long one. Rejects a path, an @-handle, a bare IPv4, or a label that echoes this machine's
 * hostname or the OS username, so the label can't leak the machine's identity. The label is never
 * DERIVED from those values (see suggestDeviceLabel); the server applies its own account-name check too.
 */
function firstDnsLabel(h) { return (typeof h === 'string' ? h.split('.')[0] : ''); }

function validateDeviceLabel(label, identity) {
  if (label === undefined || label === null) return null;
  if (typeof label !== 'string') throw new TypeError('device label must be a string');
  const cleaned = Array.from(label).filter((ch) => { const n = ch.charCodeAt(0); return n >= 0x20 && n !== 0x7f; }).join('').trim(); // drop control chars; keep normal text
  if (cleaned.length === 0) return null;
  if (cleaned.length > MAX_LABEL_LEN) throw new TypeError('device label is too long');
  // Reject a path, an @-handle, or a bare IPv4 outright — with its own actionable message.
  if (cleaned.includes('/') || cleaned.includes('\\') || cleaned.includes('@') || /^\d{1,3}(\.\d{1,3}){3}$/.test(cleaned)) {
    throw new TypeError("A device label can't be a path, address, or account handle — choose a simple nickname.");
  }
  // Reject a label that ECHOES this machine's identity via THREE complementary arms (any one fires),
  // each applied to both the host (its first DNS label, lowercased) and the username. The identity
  // source is injectable for testing and defaults to this machine's values. collapse() lowercases and
  // keeps only [a-z0-9].
  //  - ARM 1, whole-token: a >= 3 char label token equals the host/user — a literal whole-word echo
  //    ("File Server"/host "server", "My Laptop"/host "laptop", "laptop" from "laptop.corp.example.com").
  //    A short username like "pi" (< 3) can't reject "Raspberry Pi", and "sam" is not a token of
  //    "Samsung TV".
  //  - ARM 2, exact full-collapse (no floor): the whole label collapses to exactly the host/user, i.e.
  //    the label IS the machine name ("Lis-iMac"/host "Lis-iMac", "PC 7"/host "pc-7",
  //    "Johns MacBook Pro"/host "Johns-MacBook-Pro"). Zero false positives by definition.
  //  - ARM 3, collapsed containment (>= IDENTITY_COLLAPSE_FLOOR): a long host/user is a substring of the
  //    collapsed label ("Johns MacBook Pro Work"/host "Johns-MacBook-Pro"). The floor keeps 6-7 char
  //    generic words from over-matching when merely embedded in a longer label.
  const host = firstDnsLabel(safeLower(identity && identity.hostname !== undefined ? identity.hostname : osHostname()));
  const user = safeLower(identity && identity.username !== undefined ? identity.username : osUsername());
  const collapse = (v) => v.toLowerCase().replace(/[^a-z0-9]+/g, '');
  const labelTokens = new Set(cleaned.toLowerCase().split(/[^a-z0-9]+/).filter((t) => t.length >= 3));
  const collapsedLabel = collapse(cleaned);
  for (const id of [host, user]) {
    // A falsy/empty host or user (os.hostname()/os.userInfo() can be '' or throw) is a NO-OP for all
    // three arms — never a match-everything. This continue, ARM 2's `collapsedId &&`, and ARM 3's
    // length-guarded `.includes()` together prevent the reject-all that collapse('')==='' and
    // label.includes('') would otherwise cause.
    if (!id) continue;
    const collapsedId = collapse(id);
    if (id.length >= 3 && labelTokens.has(id)) throw new TypeError(IDENTITY_ECHO_MSG);                                       // ARM 1
    if (collapsedId && collapsedLabel === collapsedId) throw new TypeError(IDENTITY_ECHO_MSG);                               // ARM 2
    if (collapsedId.length >= IDENTITY_COLLAPSE_FLOOR && collapsedLabel.includes(collapsedId)) throw new TypeError(IDENTITY_ECHO_MSG); // ARM 3
  }
  return cleaned;
}

/**
 * Suggest a generic, NON-IDENTIFYING default label that avoids colliding with the account's existing
 * device labels, using a bounded numeric suffix. Never derived from the hostname or username.
 */
function suggestDeviceLabel(existingLabels) {
  const taken = new Set((Array.isArray(existingLabels) ? existingLabels : []).map((l) => safeLower(String(l || ''))));
  const base = 'This computer';
  if (!taken.has(safeLower(base))) return base;
  for (let n = 2; n <= 99; n++) { const c = `${base} ${n}`; if (!taken.has(safeLower(c))) return c; }
  return base; // bounded fallback (labels are not server-unique, so a duplicate is acceptable)
}

// Account-authenticated requests for the registration/management routes. The account token is a bearer
// credential too, so — like the device-Bearer client — nothing here ever puts the token, a body, or a
// response into a thrown error or a log line.
function accountInit(accountToken, method, body) {
  const init = { method, headers: { Authorization: `Bearer ${accountToken}` } };
  if (body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(body); }
  return init;
}

/**
 * Capability probe: does this vault speak the device routes (i.e. is it new enough to offer device
 * sync)? GET /devices under the account session, classified honestly.
 * @returns {Promise<{supported:boolean, reason:'ok'|'too-old'|'auth'|'indeterminate', devices?:Array}>}
 */
async function checkDeviceSyncSupported({ serverOrigin, accountToken }, fetchFn) {
  let res;
  try { res = await fetchFn(`${serverOrigin}/devices`, accountInit(accountToken, 'GET')); }
  catch { return { supported: false, reason: 'indeterminate' }; } // transport error -> can't verify -> honest
  const s = (res && res.status) || 0;
  // ONLY a clean 200 is a capability signal. Any other 2xx (202/203/204/206 from a gateway or a server
  // idiom) is ambiguous, not a confirmed device list, so it must fall through to 'indeterminate' rather
  // than fail OPEN into an offer.
  if (s === 200) {
    // A bare 200 is NOT enough: a reverse proxy, SPA index, login gateway, or captive portal in front of
    // an OLD vault also answers 200 (with HTML, or an empty/other body). The device route returns a JSON
    // object carrying a `devices` array — require exactly that. A throwing / non-object / no-devices-array
    // 200 is ambiguous and must fall through to 'indeterminate', never fail OPEN into an offer.
    let body;
    try { body = await res.json(); } catch { return { supported: false, reason: 'indeterminate' }; }
    if (!body || typeof body !== 'object' || !Array.isArray(body.devices)) {
      return { supported: false, reason: 'indeterminate' };
    }
    return { supported: true, reason: 'ok', devices: body.devices };
  }
  if (s === 404) return { supported: false, reason: 'too-old' };   // route absent -> vault < the device-sync release
  if (s === 401 || s === 403) return { supported: false, reason: 'auth' }; // NOT a version signal
  return { supported: false, reason: 'indeterminate' };            // 5xx / anything else -> fail closed, honest
}

// Map a POST /devices non-2xx to a fixed reason literal (no body leaked). Fail-closed default.
function registerRefusalReason(status) {
  if (status === 409) return 'device-cap-reached';
  if (status === 401 || status === 403) return 'auth';
  if (status === 400) return 'invalid-label'; // server's own account-name / label rejection
  return 'register-refused';
}

// Orphan-cleanup: delete the just-created server row (account session). Fail-safe case: if the delete
// itself fails, retain the deviceId in the advisory sidecar so a later reset/Remove can still name the
// row, and report the un-cleaned orphan. Never throws.
async function cleanupOrphan({ serverOrigin, accountToken, deviceId, dir, store, fetchFn }) {
  let res;
  try { res = await fetchFn(`${serverOrigin}/devices/${encodeURIComponent(deviceId)}`, accountInit(accountToken, 'DELETE')); }
  catch { res = null; }
  if (res && res.ok) return { orphanCleaned: true };
  try { store.writeDeviceIdHint(dir, deviceId); } catch { /* best-effort: the id is also known to the caller */ }
  return { orphanCleaned: false, orphanDeviceId: deviceId };
}

/**
 * Register THIS device: the fail-safe order (see the file header). Never throws — returns a typed
 * result so the caller drives an honest, resolvable UX.
 * @returns {Promise<{ok:true, deviceId:string} | {ok:false, reason:string, orphanCleaned?:boolean, orphanDeviceId?:string}>}
 */
async function registerDevice({ serverOrigin, accountToken, label, dir, safeStorage }, deps = {}) {
  const fetchFn = deps.fetchFn;
  const store = deps.store || defaultStore;

  // 1. PRE-CHECK: no secure keychain -> abort before creating anything server-side (nothing to undo).
  if (!isSecureBackend(safeStorage)) return { ok: false, reason: 'no-secure-store' };
  // Never overwrite an identity that is already here. Only a genuinely EMPTY store registers: an identity for
  // this server is already registered; one bound to another server must be forgotten explicitly first
  // (a plain overwrite would leave that server's device row live with no way to name it); a blob that
  // cannot be read right now might still be valid. Refused before any server row is created.
  let existing;
  try { existing = store.readDeviceSecret(safeStorage, dir, serverOrigin); } catch { existing = { status: 'unreadable' }; }
  if (!mayRegisterHere(existing && existing.status)) {
    if (existing && existing.secret) { store.zeroizeSecret(existing.secret); existing.secret = null; }
    const st = existing && existing.status;
    return { ok: false, reason: st === 'ok' ? 'already-registered' : st === 'absent-for-this-server' ? 'registered-elsewhere' : 'identity-unreadable' };
  }

  let cleanLabel;
  try { cleanLabel = validateDeviceLabel(label, deps.identity); } // deps.identity is a test hook; undefined -> real OS identity
  catch { return { ok: false, reason: 'invalid-label' }; }

  // 2. POST /devices (account session) -> the server creates the row + returns the one-time secret.
  let res;
  try { res = await fetchFn(`${serverOrigin}/devices`, accountInit(accountToken, 'POST', { label: cleanLabel })); }
  // A transport failure with no response. Usually the server never acted (no row); but a lost response
  // after a timeout/reset MAY have created a row this path cannot name — that is reconciled later against
  // the device list (a listed device with no local blob), not from here.
  catch { return { ok: false, reason: 'network' }; }
  if (!res || !res.ok) return { ok: false, reason: registerRefusalReason((res && res.status) || 0) };

  let created;
  try { created = await res.json(); } catch { created = null; }
  const deviceId = created && created.device_id;
  let secret = created && created.secret;
  const haveId = typeof deviceId === 'string' && deviceId.length > 0;

  // 3. ANY failure AFTER the POST means the server row (when a usable id came back) is an orphan: delete
  // it and zeroize the secret. cleanupOrphan retains the id in the sidecar if the delete itself fails, so
  // the row stays nameable for a later reset. When no usable id came back there is nothing we can name.
  const orphan = async (reason) => {
    const c = haveId ? await cleanupOrphan({ serverOrigin, accountToken, deviceId, dir, store, fetchFn }) : {};
    store.zeroizeSecret(secret); secret = null;
    return { ok: false, reason, ...c };
  };

  // A 2xx we cannot turn into a usable identity (id present but secret missing/empty, or a garbled body)
  // is itself a post-POST failure -> orphan-clean it, do NOT just return.
  if (!haveId || typeof secret !== 'string' || !secret) return orphan('register-malformed');

  // Store the secret. A throw (empty/encrypt/IO) OR a {stored:false} (the keychain backend flipped
  // non-secure in the pre-check-to-store window) is treated identically: orphan-cleanup + zeroize.
  let stored;
  try {
    // Bind the issuing server into the stored identity: the EXACT origin this registration was sent to, so
    // the secret is only ever presented back to the server that minted it.
    stored = store.storeDeviceSecret(safeStorage, dir, { deviceId, secret, epoch: 1, serverOrigin });
  } catch {
    return orphan('store-failed');
  }
  if (!stored || !stored.stored) {
    return orphan('no-secure-store');
  }

  // 4. Stored. Drop the in-memory plaintext reference (the keychain holds it now).
  store.zeroizeSecret(secret); secret = null;
  return { ok: true, deviceId };
}

/**
 * FORGET this device — the explicit end of the device relationship (a sign-out that forgets, a
 * Change-server, a reset). Order, always: read the identity -> revoke the server row under the account
 * session -> and only then clear the local files (clearing first would destroy the only copy of the id
 * the revoke needs, leaving a live orphan on the server). Never throws; every branch clears.
 *
 * Two branches, by what can be read:
 *   - the blob decrypts: revoke by its deviceId. When it is bound to the CONFIGURED server ('ok') the
 *     revoke goes to that server under the account session. When it is bound to a DIFFERENT server
 *     ('absent-for-this-server') this account session cannot speak for that server, so no revoke is
 *     attempted there (the row stays visible in that server's own synced-computers list for the owner
 *     to remove); the local files are still cleared so registration with the configured server can go
 *     ahead. The other server is named in the result.
 *   - the blob cannot be decrypted right now (a rotated or locked keychain): degrade to an id-only,
 *     best-effort revoke against the configured server using the advisory sidecar id. It carries ONLY
 *     the account session and the non-secret id — there is no secret to present — and the server scopes
 *     the delete to the account's own devices, so an id from another server or a stale id no-ops.
 * When a revoke this session COULD have made did not succeed (offline, refused), the non-secret id is
 * kept in the advisory sidecar after the clear (hintKept) so a later forget or reset can still name the
 * row — the same retention the registration orphan path uses. The secret itself is always cleared.
 * @returns {Promise<{cleared:boolean, revoked:boolean, deviceId:(string|null), otherOrigin?:string, hintKept?:boolean}>}
 */
async function forgetDevice({ serverOrigin, accountToken, dir, safeStorage }, deps = {}) {
  const fetchFn = deps.fetchFn;
  const store = deps.store || defaultStore;
  let read;
  try { read = store.readDeviceSecret(safeStorage, dir, serverOrigin); } catch { read = { status: 'unreadable', deviceId: null, secret: null, epoch: null }; }
  let deviceId = null;
  let revoked = false;
  let otherOrigin;
  if (read && read.status === 'ok') {
    deviceId = read.deviceId;
    store.zeroizeSecret(read.secret); read.secret = null; // the secret is never used here — a forget needs only the id
    revoked = await revokeById({ serverOrigin, accountToken, deviceId, fetchFn });
  } else if (read && read.status === 'absent-for-this-server') {
    // Bound to another server: this session cannot revoke there. Clear locally; name the other server.
    otherOrigin = read.otherOrigin;
    let hint = null;
    try { hint = store.readDeviceIdHint(dir); } catch { hint = null; }
    deviceId = hint;
  } else {
    // unreadable / absent / no-secure-store: id-only, best-effort, against the configured server.
    let hint = null;
    try { hint = store.readDeviceIdHint(dir); } catch { hint = null; }
    deviceId = hint;
    if (deviceId && accountToken) revoked = await revokeById({ serverOrigin, accountToken, deviceId, fetchFn });
  }
  let cleared = false;
  try { cleared = !!(store.clearDeviceSecret(dir) || {}).removed; } catch { cleared = false; }
  const out = { cleared, revoked, deviceId };
  if (otherOrigin) out.otherOrigin = otherOrigin;
  // A row this session should have revoked but could not: keep its id (never a secret) nameable.
  if (!revoked && deviceId && !otherOrigin) {
    try { store.writeDeviceIdHint(dir, deviceId); out.hintKept = true; } catch { /* best-effort; the id is also in the result */ }
  }
  return out;
}

// DELETE /devices/{id} under the ACCOUNT session: the server scopes it to the account's own devices, so an
// unknown or foreign id is refused and reads as not-revoked here. Never throws; never carries a secret.
async function revokeById({ serverOrigin, accountToken, deviceId, fetchFn }) {
  if (typeof deviceId !== 'string' || !deviceId || typeof accountToken !== 'string' || !accountToken) return false;
  try {
    const res = await fetchFn(`${serverOrigin}/devices/${encodeURIComponent(deviceId)}`, accountInit(accountToken, 'DELETE'));
    return !!(res && res.ok);
  } catch { return false; }
}

/**
 * Whether a registration may be STARTED given the stored identity's read status. Only a genuinely empty
 * store ('absent' — no blob at all) allows one. Every other status refuses: an identity bound to another
 * server, a blob that cannot be read right now, or no secure store at all — a registration over any of
 * those could overwrite a secret that is still valid somewhere. A person ends the old relationship
 * explicitly (forgetDevice) before a new one begins; nothing registers on a guess.
 */
function mayRegisterHere(readStatus) { return readStatus === 'absent'; }

/**
 * The pure decision for the DEVICE STEP of the enable-sync flow: from the capability probe's reason and the
 * stored identity's read status, decide what to do about this computer's device identity before granting the
 * vault. Presentation- and IO-free — the enable flow carries the action out.
 *
 * The probe gates first (only a clean 'ok' means the server speaks the device routes). While the account
 * path still exists, anything that is not a clean device action falls back to 'account-only' — the
 * config is saved and syncs on the account session, and the device path is retried later — EXCEPT an auth
 * failure, which routes to sign-in. Only a genuinely-absent identity registers; an identity bound to another
 * server forgets-then-registers (never a clobber over another server's still-valid secret); an identity already here just grants. A
 * transient/unreadable/unknown identity never registers on top of a blob it could not read — it falls back
 * to the account path (the run-time escape hatch handles a persistently-unreadable identity separately).
 *
 * @param {object} o
 * @param {'ok'|'too-old'|'auth'|'indeterminate'} o.probeReason   checkDeviceSyncSupported's reason
 * @param {'ok'|'absent'|'absent-for-this-server'|'stale'|'unreadable'|'no-secure-store'} o.secretStatus  readDeviceSecret's status
 * @returns {{action:'register'|'grant-only'|'forget-then-register'|'account-only'|'sign-in', reason:(string|null)}}
 */
/**
 * The escape-hatch streak: consecutive ticks that read the device identity UNREADABLE while the app is
 * UNLOCKED. A keyring that locks with the screen makes the identity read unreadable on every locked tick, so
 * a lock-induced unreadable must NOT count toward the reset offer — it only advances while unlocked; any
 * readable status, OR a locked tick, resets it to zero. Pure, so the threshold behaviour is testable.
 * @param {number} prev  the streak so far
 * @param {{status:string, appLocked:boolean}} o  the current identity status and lock state
 * @returns {number} the next streak value
 */
function nextUnreadableStreak(prev, { status, appLocked } = {}) {
  if (status === 'unreadable' && !appLocked) return (Number.isInteger(prev) && prev > 0 ? prev : 0) + 1;
  return 0;
}

function decideEnableDeviceStep({ probeReason, secretStatus }) {
  if (probeReason === 'auth') return { action: 'sign-in', reason: 'no-session' };
  if (probeReason === 'too-old') return { action: 'account-only', reason: 'server-too-old' };
  if (probeReason !== 'ok') return { action: 'account-only', reason: 'indeterminate' }; // could not verify -> honest fallback, never registers
  switch (secretStatus) {
    case 'absent': return { action: 'register', reason: null };                                 // no identity here -> register this computer
    case 'ok': return { action: 'grant-only', reason: null };                                   // already registered here -> just grant the vault
    case 'absent-for-this-server': return { action: 'forget-then-register', reason: 'registered-elsewhere' }; // bound to another server -> forget then register
    case 'no-secure-store': return { action: 'account-only', reason: 'no-secure-store' };        // can't store a device secret -> account path
    case 'stale': return { action: 'account-only', reason: 'identity-stale' };                   // being re-checked (rotation marker); the run-time recovery half owns it -> account path, honest reason
    case 'unreadable': return { action: 'account-only', reason: 'identity-unreadable' };         // transient; never register on an unreadable blob -> account path, retry later
    default: return { action: 'account-only', reason: 'identity-unreadable' };                   // unknown status: fail closed to the account path
  }
}

module.exports = { registerDevice, forgetDevice, mayRegisterHere, checkDeviceSyncSupported, validateDeviceLabel, suggestDeviceLabel, decideEnableDeviceStep, nextUnreadableStreak, accountInit };

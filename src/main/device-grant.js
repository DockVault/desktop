'use strict';

/*
 * Device GRANT creation — the ONE place a vault password is proven for device sync, and the security
 * asymmetry at the heart of the model: the DEVICE SECRET is stored (OS-encrypted, revocable, from the
 * secret store), but the VAULT PASSWORD is TRANSIENT. The account proves the vault password ONCE here,
 * over the account session, to create the grant; the server binds a fingerprint of it to the grant, and
 * every later mint only fingerprint-matches — so a device never re-holds the password.
 *
 * This module therefore:
 *   - sends the vault password EXACTLY once, in the single grant-create POST body, and drops its
 *     reference immediately on BOTH success and failure. It is NEVER written to disk (not raw, not via
 *     safeStorage, not "remembered" for a re-grant), NEVER returned, and NEVER logged (no header, body,
 *     or response text in any error) — the same never-logged discipline the device secret and the
 *     account token follow. A grant failure fails closed (no cached-password retry).
 *   - is FINGERPRINT-BLIND: it never computes, holds, or format-checks the vault-password fingerprint;
 *     the server owns it. The client relies only on the grant plus the device secret for later mints.
 *   - creates the grant ONLY under the ACCOUNT Bearer, never the device principal — a device may LIST
 *     its grants but must never create, widen, or un-revoke one, so grant-create stays OUT of the
 *     device-Bearer client's route allowlist (which is mint / refresh / grants-read-only).
 *
 * A zero-knowledge vault is refused LOCALLY before any password is sent (it is never SFTP-syncable), so
 * a grant-create 400 is then unambiguously a wrong-password proof — the server returns a plain string
 * detail for both cases, which this client deliberately does not parse.
 */

const { accountInit } = require('./device-register'); // single source for the account-Bearer request builder
const { deviceRequest } = require('./device-http');   // read-only device-Bearer client (grants route)
const defaultGrantStore = require('./device-grant-store');

// Best-effort scrub of the transient proof. An immutable JS string cannot be erased in place (the caller
// drops its reference and the real protection is its momentary lifetime); a Buffer form is zeroed.
function dropSecretRef(v) { if (Buffer.isBuffer(v)) v.fill(0); }

// Map a grant-create non-2xx to a fixed reason WITHOUT surfacing the body. Fail-closed default. A ZK
// vault is pre-filtered above, so a 400 here is a wrong-password proof, not the ZK refusal.
function grantRefusalReason(status) {
  if (status === 400) return 'wrong-password';
  if (status === 429) return 'rate-limited';
  if (status === 404) return 'vault-not-accessible'; // oracle-free: not-a-member and nonexistent both 404
  if (status === 401 || status === 403) return 'auth';
  return 'grant-failed';
}

/**
 * Grant one of the account's OWN devices access to a vault, proving the vault password ONCE.
 * @param {{serverOrigin:string, accountToken:string, deviceId:string, vaultId:string, vaultType:string, vaultPassword?:string}} args
 *   vaultType — the vault's type from the account vault list; REQUIRED. The grant proceeds only for an
 *     explicit 'standard' vault; any other or absent value fails closed, so a ZK passphrase never leaves
 *     the client.
 *   vaultPassword — the one-time proof for a password-protected vault (from the native consent dialog);
 *     omit for a no-password vault. TRANSIENT: sent once, then its reference is dropped on every path;
 *     never stored, returned, or logged.
 * @returns {Promise<{ok:true, vaultId:string, hasPassword:boolean, grantedAt:(string|null)} | {ok:false, reason:string}>}
 */
async function grantDeviceVault({ serverOrigin, accountToken, deviceId, vaultId, vaultType, vaultPassword }, deps = {}) {
  const fetchFn = deps.fetchFn;
  let password = vaultPassword; // the transient proof; dropped in the finally below, always
  try {
    // Fail CLOSED on the tier: proceed (and put a password on the wire) ONLY for an explicitly Standard
    // vault. A missing / null / mis-cased / future-tier vaultType therefore refuses LOCALLY rather than
    // leaking a zero-knowledge vault's passphrase — the safe default on the most catastrophic gate is
    // refuse, not proceed. (This also keeps a subsequent 400 unambiguously a wrong-password proof.)
    if (vaultType !== 'standard') return { ok: false, reason: 'vault-not-standard' };
    if (typeof deviceId !== 'string' || !deviceId || vaultId === undefined || vaultId === null || vaultId === '') {
      return { ok: false, reason: 'grant-failed' };
    }
    const body = { vault_id: vaultId };
    if (password !== undefined && password !== null && password !== '') body.vault_password = password;
    let res;
    try { res = await fetchFn(`${serverOrigin}/devices/${encodeURIComponent(deviceId)}/grants`, accountInit(accountToken, 'POST', body)); }
    catch { return { ok: false, reason: 'network' }; } // transport failure carries no message (never the body/pw)
    if (!res || !res.ok) return { ok: false, reason: grantRefusalReason((res && res.status) || 0) };
    let created;
    try { created = await res.json(); } catch { created = null; }
    // The response never echoes the password; only has_password (a boolean) + granted_at are surfaced,
    // for the caller's grant-metadata cache. The fingerprint stays entirely server-side.
    return { ok: true, vaultId: String(vaultId), hasPassword: !!(created && created.password_protected), grantedAt: (created && typeof created.granted_at === 'string') ? created.granted_at : null };
  } finally {
    dropSecretRef(password);
    password = undefined;
  }
}

/**
 * List the vaults this device may sync: the AUTHORITATIVE active grants from the server (device-Bearer
 * GET /device/grants — active vault_ids + granted_at) JOINED with the local non-secret grant-metadata
 * cache (name, vaultType, hasPassword captured at grant time), so the tier re-assert and the name-keyed
 * remote path can run WITHOUT an account session. Read-only (the 'grants' route is a GET; a device never
 * creates or widens a grant). A vault_id the server lists but that is absent from the local cache
 * (cache lost, or — in a later feature — a grant created from another session) surfaces with
 * metaKnown:false and null metadata until an account session can backfill it. A device-Bearer failure
 * (revoked/expired/unreadable-secret/etc.) fails closed with its typed reason.
 * @returns {Promise<{ok:true, grants:Array} | {ok:false, reason:string}>}
 */
async function listMyGrants({ serverOrigin, deviceSecret, dir, safeStorage }, deps = {}) {
  const store = deps.store || defaultGrantStore;
  let body;
  try { body = await deviceRequest({ serverOrigin, deviceSecret, route: 'grants' }, deps.fetchFn); }
  catch (e) { return { ok: false, reason: (e && e.reason) || 'device-request-refused' }; }
  // A valid-JSON 2xx whose `grants` is not an array is unintelligible, not an empty grant list — fail
  // closed with a typed reason rather than silently dropping every synced vault from the list.
  if (!body || !Array.isArray(body.grants)) return { ok: false, reason: 'grants-unreadable' };
  // Read the local metadata ONCE, status-aware: a transiently-unreadable cache (locked keyring / corrupt
  // file) is NOT "absent", so every grant then surfaces metaKnown:false (name-unknown, backfilled from an
  // account session later) rather than a fabricated name. The own-property lookup keeps a server vault_id
  // that collides with an Object.prototype member ('constructor'/'__proto__'/'toString'/...) from
  // resolving to an inherited value; the store's map is also null-prototype (belt-and-suspenders).
  const cache = store.readGrantMeta(safeStorage, dir);
  const cacheReadable = !store.isUnreadable(cache.status);
  const meta = (cache && cache.meta) || {};
  const grants = body.grants.map((g) => {
    const vaultId = (g && typeof g.vault_id === 'string' && g.vault_id) ? g.vault_id : null;
    const m = (cacheReadable && vaultId && Object.prototype.hasOwnProperty.call(meta, vaultId)) ? meta[vaultId] : null;
    return {
      vaultId,
      grantedAt: (g && typeof g.granted_at === 'string') ? g.granted_at : null,
      name: m ? m.name : null,
      vaultType: m ? m.vaultType : null,
      hasPassword: m ? m.hasPassword : null,
      metaKnown: !!m,
    };
  });
  return { ok: true, grants };
}

/**
 * Grant a vault to this device AND record its non-secret details locally, in that order. The grant is the
 * authoritative fact and is created atomically on the server: once grantDeviceVault returns ok:true it
 * exists and is valid, and the server's own grant list will always show it. The local record is a
 * convenience for display and the tier re-assert, written BEST-EFFORT: if the OS secret store refuses or
 * the record cannot be written just now, the grant is still reported as created (recorded:false) — it is
 * never reported as failed and never revoked over a local write hiccup; the details are filled in later
 * from an account session.
 * @returns {Promise<{ok:true, vaultId:string, hasPassword:boolean, grantedAt:(string|null), recorded:boolean} | {ok:false, reason:string}>}
 */
async function grantAndRecord({ serverOrigin, accountToken, deviceId, vaultId, vaultType, vaultName, vaultPassword, dir, safeStorage }, deps = {}) {
  const store = deps.store || defaultGrantStore;
  const r = await grantDeviceVault({ serverOrigin, accountToken, deviceId, vaultId, vaultType, vaultPassword }, deps);
  if (!r.ok) return r;
  let recorded = false;
  try {
    store.setGrantMeta(safeStorage, dir, r.vaultId, { name: typeof vaultName === 'string' ? vaultName : '', vaultType: 'standard', hasPassword: r.hasPassword });
    recorded = true;
  } catch { recorded = false; } // the grant stands; the record is backfilled from an account session later
  return { ...r, recorded };
}

module.exports = { grantDeviceVault, grantRefusalReason, listMyGrants, grantAndRecord };

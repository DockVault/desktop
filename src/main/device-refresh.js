'use strict';

/*
 * Scheduled rotation of this computer's sync identity (the device secret).
 *
 * The device secret is the one long-lived credential the desktop holds, so it is rotated on a schedule:
 * the current secret is presented ONCE to the server's refresh route, which retires it and returns a new
 * one, and the new one replaces it in the OS-encrypted store. The server keeps the retired secret valid
 * for a short grace window (a mint already in flight still succeeds), then treats any later use of it as
 * a replay and suspends the device — so the rotation is written to the store the moment it is received
 * and the retired value is never presented again from here.
 *
 * Three rules are load-bearing:
 *   - ON A SCHEDULE, never per mint: the server rate-limits refresh, and a rotation per credential would
 *     turn every sync into a rotation. `isRotationDue` decides from the time the stored identity was last
 *     written; the caller's tick asks it, not the mint path.
 *   - THE BINDING TRAVELS UNCHANGED: the refreshed secret is stored under the server origin read back from
 *     the existing blob, never under whatever origin the caller happens to be configured for. A rotation
 *     against server A can never yield an identity bound to server B; and no rotation is attempted at all
 *     unless the stored identity reads 'ok' for the configured server (a blob bound elsewhere, an
 *     unreadable blob, or no blob is refused locally, with no request).
 *   - HONEST ON FAILURE: a refresh refused because the presented secret is already retired
 *     ('device-secret-stale') means a previous rotation's answer was lost — this computer can no longer
 *     catch up by itself, and presenting the retired secret past the grace window would suspend the
 *     device. The caller must stop presenting it (the mint path treats the identity as stale) and route
 *     the person to setting the computer up again. The same holds when the server DID rotate but this
 *     side could not keep the answer — a local store that fails (after one retry) or a 2xx without a
 *     usable secret: the secret held here is now the retired one, so it is treated as stale at once
 *     rather than presented until the grace window turns it into a suspension. `identityIsStaleAfter`
 *     names these outcomes for the caller. And the window between the request and the store is covered
 *     by an in-flight marker in the store, written before the request and removed only once the new
 *     secret is on disk (or the server definitely answered without rotating): a crash inside that window
 *     leaves a survivor that the next launch reads as stale, instead of a retired secret with no mark.
 *
 * Secrets never linger: the current secret is read from the store at the moment of the request and the
 * reference dropped in a finally; the new secret is dropped once stored. Neither appears in a result,
 * an error, or a log line (the device client's never-logged discipline carries).
 */

const { deviceRequest, KNOWN_REASONS } = require('./device-http');
const defaultStore = require('./device-secret-store');
const { canonicalOrigin } = require('./device-secret-store');

// How long a stored identity may stand before it is rotated. A proactive, online-only action: a
// computer that is offline past this simply rotates on its next online tick.
const ROTATE_AFTER_MS = 24 * 60 * 60 * 1000;

// Transport failures that mean the request NEVER reached the server (no connection was made), so the
// current secret is certainly still current and the in-flight mark can go. Anything else — a reset or a
// timeout after connecting, an unrecognised code — is ambiguous (the request may have landed and the
// answer been lost) and keeps the mark: a needless "set up again" beats a replay that suspends the device.
const NEVER_SENT_CODES = new Set([
  'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EAI_FAIL', 'ENETUNREACH', 'EHOSTUNREACH', 'EADDRNOTAVAIL', 'ENETDOWN', // Node's transport
  'ERR_CONNECTION_REFUSED', 'ERR_NAME_NOT_RESOLVED', 'ERR_NAME_RESOLUTION_FAILED', 'ERR_ADDRESS_UNREACHABLE', 'ERR_NETWORK_UNREACHABLE', 'ERR_INTERNET_DISCONNECTED', // Chromium's
]);
// Deliberately NOT above, from either layer: a reset, any timeout, an empty response, a closed connection — each can
// happen after the request bytes left, so the server may have rotated. They keep the mark.

/**
 * Whether a rotation is due for the identity in `read` (a readDeviceSecret result) at `nowMs`. Only an
 * 'ok' identity is ever due; one whose write time is unknown or unreadable is due (it is rotated onto a
 * known footing), otherwise due once ROTATE_AFTER_MS has passed since it was written.
 */
function isRotationDue(read, nowMs, afterMs = ROTATE_AFTER_MS) {
  if (!read || read.status !== 'ok') return false;
  const t = typeof read.rotatedAt === 'string' ? Date.parse(read.rotatedAt) : NaN;
  if (!Number.isFinite(t)) return true;
  return nowMs - t >= afterMs;
}

/**
 * Whether, after `result` from refreshDeviceSecret, the secret held here must be treated as RETIRED: the
 * server refused the presented secret as already rotated, or it rotated and this side lost the answer (the
 * store failed, or the answer carried no usable secret). Presenting the held secret past the grace window
 * would suspend the device, so the caller stops presenting it and routes to setting the computer up again.
 */
function identityIsStaleAfter(result) {
  if (!result || result.ok) return false;
  return result.reason === 'device-secret-stale' || result.reason === 'store-failed' || result.reason === 'refresh-malformed';
}

/**
 * The past-grace rotation-recovery decision. A ROTATING marker survived a crash between /device/refresh and
 * the store, so the held secret MAY be retired — it is never presented (the server's grace can be zero and is
 * never told to the client). Instead the account session's device list is consulted, and this pure function
 * decides the marker's fate from the server's row for THIS device (matched by deviceId) and the blob's epoch.
 * Fail-closed: only an exact epoch match LIFTS the marker.
 *   'clear'   server epoch EQUALS the blob's → the rotation never landed → the held secret IS current → clear
 *             the marker and resume (a suspension stays the mint's honest job, not this reconcile's).
 *   'stale'   server epoch GREATER → the server rotated and this side lost the new secret → retired → the
 *             computer must be set up again (the held secret is never presented).
 *   'revoked' the row is absent or inactive → the device was removed → set the computer up again.
 *   'keep'    anything else — a missing / non-integer epoch, a smaller server epoch, a malformed row → doubt,
 *             so keep the marker and wait; a needless re-check beats a wrong lift that could suspend the device.
 * The "no session / the request failed" doubt is the caller's: it does not call this, it keeps the marker.
 * @param {{found:boolean, isActive?:boolean, epoch?:number}|null} row  the server's device row, or {found:false}
 * @param {number} blobEpoch  the epoch stored in the local blob
 * @returns {'clear'|'stale'|'revoked'|'keep'}
 */
function reconcileRotationMarker(row, blobEpoch) {
  if (!row || row.found !== true) return 'revoked';
  if (row.isActive === false) return 'revoked';
  if (!Number.isInteger(row.epoch) || !Number.isInteger(blobEpoch)) return 'keep';
  if (row.epoch === blobEpoch) return 'clear';
  if (row.epoch > blobEpoch) return 'stale';
  return 'keep';
}

/**
 * Rotate the stored device secret for the configured server. Never throws.
 * @param {{serverOrigin:string, dir:string, safeStorage:object, now?:()=>number}} args
 * @param {{store?:object, fetchFn?:Function}} [deps]
 * @returns {Promise<{ok:true, epoch:number, rotatedAt:string} | {ok:false, reason:string, rotated?:boolean}>}
 *   reason: the store status when the identity is not usable here ('absent' | 'unreadable' |
 *   'absent-for-this-server' | 'no-secure-store'); the device client's typed reason on a refusal
 *   ('device-secret-stale', 'device-revoked', 'network', 'server-error', ...); 'refresh-malformed' for a
 *   2xx without a usable secret; 'store-failed' (with rotated:true) when the server rotated but the
 *   local store could not be written.
 */
async function refreshDeviceSecret({ serverOrigin, dir, safeStorage, now } = {}, deps = {}) {
  const store = deps.store || defaultStore;
  const clock = typeof now === 'function' ? now : () => Date.now();
  let read;
  try { read = store.readDeviceSecret(safeStorage, dir, serverOrigin); } catch { read = { status: 'unreadable' }; }
  if (!read || read.status !== 'ok') return { ok: false, reason: (read && read.status) || 'unreadable' };
  const boundOrigin = canonicalOrigin(read.serverOrigin); // the binding travels from the blob, never from the caller
  const deviceId = read.deviceId;
  // Everything the later store needs is checked BEFORE the irreversible request: a rotation whose answer
  // could not be stored would leave this side holding a retired secret.
  if (boundOrigin === null || typeof deviceId !== 'string' || !deviceId) { if (read.secret) store.zeroizeSecret(read.secret); read.secret = null; return { ok: false, reason: 'unreadable' }; }
  const epochBefore = Number.isInteger(read.epoch) ? read.epoch : 1;
  let current = read.secret; read.secret = null;
  // Cover the request-to-store window before anything irreversible happens. If the mark cannot be written the
  // window would be unprotected, so do not rotate now (the next look tries again).
  if (typeof store.markDeviceSecretRotating === 'function' && !store.markDeviceSecretRotating(dir)) {
    store.zeroizeSecret(current); current = null;
    return { ok: false, reason: 'rotation-unprotected' };
  }
  let body;
  try {
    body = await deviceRequest({ serverOrigin, deviceSecret: current, route: 'refresh' }, deps.fetchFn);
  } catch (e) {
    const reason = (e && typeof e.reason === 'string' && e.reason) || 'device-request-refused';
    // The in-flight mark can go when the server certainly did NOT rotate: a typed refusal (the server answered
    // without rotating), or a transport failure that never connected. A failing server, an unrecognised answer,
    // or a transport failure after connecting is ambiguous (the request may have landed): the mark stays, and
    // the identity reads stale until it is set up again — a replay past grace would be worse.
    const neverSent = reason === 'network' && e && NEVER_SENT_CODES.has(e.code);
    if ((KNOWN_REASONS.includes(reason) || neverSent) && typeof store.clearDeviceSecretRotating === 'function') store.clearDeviceSecretRotating(dir);
    return { ok: false, reason };
  } finally {
    store.zeroizeSecret(current); current = null; // presented once; the store still holds it until the new one lands
  }
  let next = body && body.secret;
  if (body && typeof body === 'object') body.secret = null; // the only copy is the local alias below
  if (typeof next !== 'string' || !next) return { ok: false, reason: 'refresh-malformed' }; // a 2xx means the server rotated: the caller treats the held secret as stale
  const epoch = Number.isInteger(body.epoch) ? body.epoch : epochBefore + 1;
  const rotatedAt = new Date(clock()).toISOString();
  let stored = false;
  try {
    for (let attempt = 0; attempt < 2 && !stored; attempt++) {
      try {
        const r = store.storeDeviceSecret(safeStorage, dir, { deviceId, secret: next, epoch, serverOrigin: boundOrigin, rotatedAt });
        stored = !!(r && r.stored);
      } catch { stored = false; }
    }
  } finally {
    store.zeroizeSecret(next); next = null;
  }
  if (!stored) return { ok: false, reason: 'store-failed', rotated: true };
  return { ok: true, epoch, rotatedAt };
}

module.exports = { refreshDeviceSecret, isRotationDue, identityIsStaleAfter, reconcileRotationMarker, ROTATE_AFTER_MS, NEVER_SENT_CODES };

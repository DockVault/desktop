'use strict';

/*
 * "Is this vault out of room?" — asked of the SERVER, and answered only from the server's own two numbers.
 *
 * Why this exists at all: the SFTP door decides whether it will keep an upload at CLOSE time, and the protocol
 * gives a close no way to report a failure. So a file the server refuses for space is simply not there
 * afterwards, and the client learns only that the object it just wrote cannot be found ('upload-not-stored').
 * That says nothing about WHY, and guessing would be exactly the wrong-cause answer honest reasons exist to
 * stop. This module is the one legitimate way to find out: read the vault's own record over the account
 * session — the allowance the owner set and how much of it is stored — and let the numbers say it.
 *
 * FAIL-HONEST, in one direction only: "out of space" is claimed ONLY when both numbers are present, sane, and
 * leave nothing free. Anything else — no session, an unreadable answer, a vault with no allowance at all, a
 * number that isn't one — is `known: false`, and the caller keeps the honest generic instead. It never claims
 * room either, so a caller can't turn a missing answer into "there's plenty of space".
 *
 * Read-only and metadata-only: one GET of the vault the person already syncs, from which exactly two integers
 * are kept. No file name, no listing, no path.
 */

// The vault record's own field names (the server's), with the aliases the reused web UI normalizes to. Only a
// finite, non-negative number counts as either; anything else leaves the pair unknown.
function num(v) {
  return (typeof v === 'number' && Number.isFinite(v) && v >= 0) ? v : null;
}

/**
 * The space picture from one server vault record.
 *
 * A vault with NO size limit (null, 0, or absent — the server's way of saying "no allowance set") can never be
 * reported full: there is no ceiling to be against. That is deliberate — the deployment-wide storage cap is a
 * different limit the client cannot see, so a refused upload on an unlimited vault stays the honest generic
 * rather than being blamed on the vault.
 *
 * @param {object} record the server's vault record (`size_limit`, `total_size_bytes`)
 * @returns {{known:boolean, limitBytes:(number|null), usedBytes:(number|null), freeBytes:(number|null)}}
 */
function vaultSpaceOf(record) {
  const r = record && typeof record === 'object' ? record : {};
  const limitBytes = num(r.size_limit != null ? r.size_limit : r.sizeLimit);
  const usedBytes = num(r.total_size_bytes != null ? r.total_size_bytes : r.totalSizeBytes);
  if (!limitBytes || limitBytes <= 0 || usedBytes == null) {
    return { known: false, limitBytes: null, usedBytes: null, freeBytes: null };
  }
  return { known: true, limitBytes, usedBytes, freeBytes: Math.max(0, limitBytes - usedBytes) };
}

/**
 * Whether the vault's own numbers say there is no room left. Only ever true on a KNOWN pair with nothing free —
 * a vault that still has room is not called full even though this space picture is what a refused upload
 * prompted, because a file may have been refused for a reason that has nothing to do with the allowance.
 */
function isOutOfSpace(space) {
  return !!(space && space.known === true && space.freeBytes != null && space.freeBytes <= 0);
}

/**
 * Fetch one vault's record over the account session and reduce it to the space picture. Never throws: every
 * failure (no session, a network error, a non-200, an unreadable body, a scoped answer that omits the
 * aggregates) resolves to the unknown picture, which the caller reads as "don't claim a cause".
 *
 * @param {object} o
 * @param {string} o.serverOrigin
 * @param {string} o.sessionToken   the account bearer; without one there is no answer to be had
 * @param {string} o.vaultId
 * @param {(url:string, init:object)=>Promise<{status:number, json:()=>Promise<any>}>} fetchFn
 * @returns {Promise<{known:boolean, limitBytes:(number|null), usedBytes:(number|null), freeBytes:(number|null)}>}
 */
async function fetchVaultSpace({ serverOrigin, sessionToken, vaultId }, fetchFn) {
  const unknown = { known: false, limitBytes: null, usedBytes: null, freeBytes: null };
  if (!serverOrigin || !sessionToken || !vaultId || typeof fetchFn !== 'function') return unknown;
  let res;
  try {
    res = await fetchFn(`${String(serverOrigin).replace(/\/+$/, '')}/vaults/${encodeURIComponent(vaultId)}`,
      { method: 'GET', headers: { Authorization: `Bearer ${sessionToken}` } });
  } catch { return unknown; }
  if (!res || res.status !== 200) return unknown;
  let body = null;
  try { body = await res.json(); } catch { return unknown; }
  if (!body || typeof body !== 'object' || Array.isArray(body)) return unknown;
  return vaultSpaceOf(body);
}

module.exports = { vaultSpaceOf, isOutOfSpace, fetchVaultSpace };

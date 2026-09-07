'use strict';

/*
 * Persist the SET of vault ids whose device-grant setup DEFERRED — the person set this computer up to sync
 * the vault, but the vault wasn't open to prove its password once, so the grant is pending. The set lets
 * the resume path (on the next unlock/dispatch, while the vault is open and its password fresh) finish the
 * grant by itself, and lets the tray show one calm "open <vault> once to finish" to-do. It is SCOPED to
 * vaults whose setup deferred — never every account-path vault on a registered computer (that migration is
 * a later, separate change), so a marker only ever exists because a person chose device sync for that vault.
 *
 * It holds NO credential — only opaque vault ids, never a vault password (transient-only) or the device
 * secret. It is nonetheless wrapped by the OS secret store exactly like the grant metadata: device sync
 * never runs without a secure backend (the device secret itself requires one), so there is no legitimate
 * moment for an unwrapped device-sync artifact to sit on disk, and an unwrapped envelope found here is
 * treated as unreadable, never trusted. Reads are STATUS-aware (absent vs unreadable never conflated) and a
 * save refuses to clobber an existing-but-unreadable file, so a locked keyring never silently drops the
 * pending intent. The id map is prototype-free on every path, so a vault id spelling an Object.prototype
 * member ('__proto__', 'constructor', ...) is an ordinary own key on add, read, and remove.
 */

const fs = require('node:fs');
const path = require('node:path');
const { isSecureBackend } = require('./token-store');

const FILE = 'device-pending-grants.json';
const FILE_MODE = 0o600; // owner read/write only (honoured on POSIX; NTFS uses its own ACLs)

function storePath(dir) { return path.join(dir, FILE); }

// Rebuild the id set from an array, keeping only non-empty strings, as a null-prototype map so a vault id
// like '__proto__' is an ordinary own key — never a prototype write or an inherited read.
function sanitizeIds(arr) {
  const out = Object.create(null);
  if (Array.isArray(arr)) for (const v of arr) { if (typeof v === 'string' && v) out[v] = true; }
  return out;
}
function emptyIds() { return Object.create(null); }

/**
 * Read the pending-grant id set with its readability STATUS (absent vs unreadable never conflated).
 * @returns {{status:'absent'|'ok'|'undecryptable'|'unparseable'|'unreadable-io', ids: object}}
 */
function readPending(safeStorage, dir) {
  let text;
  try { text = fs.readFileSync(storePath(dir), 'utf8'); }
  catch (e) { return { status: (e && e.code === 'ENOENT') ? 'absent' : 'unreadable-io', ids: emptyIds() }; }
  let env;
  try { env = JSON.parse(text); } catch { return { status: 'unparseable', ids: emptyIds() }; }
  if (env && env.enc === true) {
    if (!isSecureBackend(safeStorage)) return { status: 'undecryptable', ids: emptyIds() }; // wrapped on disk, no secret store this boot
    try {
      const json = safeStorage.decryptString(Buffer.from(String(env.data || ''), 'base64'));
      return { status: 'ok', ids: sanitizeIds(JSON.parse(json)) };
    } catch { return { status: 'undecryptable', ids: emptyIds() }; }
  }
  // Only a wrapped envelope is ever written, so anything else on disk is not this store's output.
  return { status: 'unparseable', ids: emptyIds() };
}

function isUnreadable(status) {
  return status === 'undecryptable' || status === 'unparseable' || status === 'unreadable-io';
}

// Atomic replace: temp file + fsync + rename (same-filesystem atomic), ALWAYS wrapped; with no secure
// backend the write is refused (a typed error) — never a plaintext file.
function writeIds(safeStorage, dir, map) {
  if (!isSecureBackend(safeStorage)) {
    const err = new Error('no secure OS secret store; refusing to write the pending-grant set unwrapped');
    err.code = 'PENDING_GRANT_NO_SECURE_STORE';
    throw err;
  }
  const json = JSON.stringify(Object.keys(map));
  const env = { v: 1, enc: true, data: safeStorage.encryptString(json).toString('base64') };
  fs.mkdirSync(dir, { recursive: true });
  const tmp = storePath(dir) + '.tmp';
  const fd = fs.openSync(tmp, 'w', FILE_MODE);
  try { fs.writeSync(fd, JSON.stringify(env)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, storePath(dir));
  try { const dfd = fs.openSync(dir, 'r'); try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); } } catch { /* best-effort; directory fsync is unsupported on some platforms (e.g. Windows) */ }
  try { fs.chmodSync(storePath(dir), FILE_MODE); } catch { /* best-effort where the platform honours it */ }
  return { encrypted: true };
}

function refuseIfUnreadable(cur) {
  if (isUnreadable(cur.status)) {
    const err = new Error('the existing pending-grant set could not be read; refusing to overwrite it');
    err.code = 'PENDING_GRANT_UNREADABLE';
    err.status = cur.status;
    throw err;
  }
}

/** Mark a vault's device grant as pending the password. Idempotent; refuses to clobber an unreadable file. */
function addPending(safeStorage, dir, vaultId) {
  if (typeof vaultId !== 'string' || !vaultId) throw new TypeError('vaultId must be a non-empty string');
  const cur = readPending(safeStorage, dir);
  refuseIfUnreadable(cur);
  if (cur.ids[vaultId]) return { added: false };
  cur.ids[vaultId] = true;
  writeIds(safeStorage, dir, cur.ids);
  return { added: true };
}

/** Clear a vault's pending marker (its grant completed, or it stopped syncing). Refuses on an unreadable file. */
function clearPending(safeStorage, dir, vaultId) {
  const cur = readPending(safeStorage, dir);
  refuseIfUnreadable(cur);
  if (!Object.prototype.hasOwnProperty.call(cur.ids, vaultId)) return { removed: false };
  delete cur.ids[vaultId];
  writeIds(safeStorage, dir, cur.ids);
  return { removed: true };
}

/**
 * Clear EVERY marker at once — the device identity itself ended (revoked/expired), so no marker can complete.
 * Refuses to clobber an unreadable file (its markers are unreadable anyway, and listPending fails safe to []).
 * @returns {{removed:number}}
 */
function clearAllPending(safeStorage, dir) {
  const cur = readPending(safeStorage, dir);
  refuseIfUnreadable(cur);
  const removed = Object.keys(cur.ids).length;
  if (removed === 0) return { removed: 0 };
  writeIds(safeStorage, dir, emptyIds());
  return { removed };
}

/**
 * Whether a vault's device grant is pending. Preserves the absent/unreadable distinction: a transiently
 * unreadable store THROWS (via refuseIfUnreadable) rather than answering false, so a caller can never
 * mistake "keyring locked / file corrupt" for "not pending".
 */
function isPending(safeStorage, dir, vaultId) {
  const cur = readPending(safeStorage, dir);
  refuseIfUnreadable(cur);
  return Object.prototype.hasOwnProperty.call(cur.ids, vaultId);
}

/**
 * The pending vault ids, for the resume sweep. FAIL-SAFE: an unreadable store yields [] (the resume simply
 * won't fire this pass and the account path keeps syncing), never a throw that would break the tick.
 */
function listPending(safeStorage, dir) {
  const cur = readPending(safeStorage, dir);
  if (isUnreadable(cur.status)) return [];
  return Object.keys(cur.ids);
}

module.exports = { readPending, isUnreadable, addPending, clearPending, clearAllPending, isPending, listPending };

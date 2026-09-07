'use strict';

/*
 * Persist NON-SECRET per-vault grant metadata — { vault_id -> { name, vaultType, hasPassword } } —
 * captured at grant time so the device sync path can resolve a vault's display NAME, its TIER
 * (vaultType, for the per-run Standard re-assert), and whether it is password-protected WITHOUT an
 * account session at sync time. The account session is needed only at grant time to populate this; the
 * device-Bearer grant LIST (GET /device/grants) supplies the authoritative active vault_ids at sync
 * time, and this store supplies their metadata.
 *
 * It holds NO credential — never a vault password (transient-only, per the grant flow), never the device
 * secret. Every entry is rebuilt through a three-field sanitizer on save AND load, so a secret can never
 * be written and a tampered file can never smuggle an unexpected field back in. Vault names are user
 * data and are treated as sensitive at rest, like the sync config and the state database: the file is
 * ALWAYS wrapped by a real OS secret store. Device sync is never offered without one (the device secret
 * itself requires it), so a write with no secure backend is refused outright rather than degraded to a
 * plaintext file — there is no legitimate moment for a plaintext copy of the vault names to exist, and
 * an unwrapped envelope found on disk is treated as unreadable, never trusted.
 *
 * Reads are STATUS-aware (absent vs unreadable never conflated) and a save refuses to clobber an
 * existing-but-unreadable file, so a locked keyring or a truncated file never silently loses the
 * recorded metadata (it degrades to name-unknown, which the sync path backfills from an account session).
 *
 * The map is prototype-free on EVERY path — including the empty map an absent or unreadable store
 * yields — so a vault id that happens to spell an Object.prototype member ('__proto__', 'toString', ...)
 * is an ordinary own key on write, on read, and on remove: it can never invoke a setter, walk the
 * prototype chain, or be mistaken for an inherited value.
 */

const fs = require('node:fs');
const path = require('node:path');
const { isSecureBackend } = require('./token-store');

const FILE = 'device-grants.json';
const FILE_MODE = 0o600; // owner read/write only (honoured on POSIX; NTFS uses its own ACLs)

function storePath(dir) { return path.join(dir, FILE); }

// Keep ONLY the three known non-secret fields; drop everything else, so a secret can never round-trip.
function sanitizeMeta(raw) {
  return {
    name: typeof (raw && raw.name) === 'string' ? raw.name : '',
    vaultType: typeof (raw && raw.vaultType) === 'string' ? raw.vaultType : '',
    hasPassword: !!(raw && raw.hasPassword),
  };
}
function sanitizeMap(obj) {
  const out = Object.create(null); // null-prototype: a vault_id like '__proto__'/'constructor' is an
  if (obj && typeof obj === 'object') {  // ordinary own key, never a prototype write or an inherited read.
    for (const [k, v] of Object.entries(obj)) { if (v && typeof v === 'object') out[String(k)] = sanitizeMeta(v); }
  }
  return out;
}
// An empty map that is still prototype-free, for every status that carries no entries.
function emptyMap() { return Object.create(null); }

/**
 * Read the grant-metadata map with its readability STATUS (absent vs unreadable never conflated).
 * @returns {{status:'absent'|'ok'|'undecryptable'|'unparseable'|'unreadable-io', meta: object}}
 */
function readGrantMeta(safeStorage, dir) {
  let text;
  try { text = fs.readFileSync(storePath(dir), 'utf8'); }
  catch (e) { return { status: (e && e.code === 'ENOENT') ? 'absent' : 'unreadable-io', meta: emptyMap() }; }
  let env;
  try { env = JSON.parse(text); } catch { return { status: 'unparseable', meta: emptyMap() }; }
  if (env && env.enc === true) {
    if (!isSecureBackend(safeStorage)) return { status: 'undecryptable', meta: emptyMap() }; // wrapped on disk, no secret store this boot
    try {
      const json = safeStorage.decryptString(Buffer.from(String(env.data || ''), 'base64'));
      return { status: 'ok', meta: sanitizeMap(JSON.parse(json)) };
    } catch { return { status: 'undecryptable', meta: emptyMap() }; }
  }
  // Only a wrapped envelope is ever written, so anything else on disk (an unwrapped envelope included) is
  // not this store's output: unreadable, never trusted as metadata.
  return { status: 'unparseable', meta: emptyMap() };
}

function isUnreadable(status) {
  return status === 'undecryptable' || status === 'unparseable' || status === 'unreadable-io';
}

// Atomic replace: temp file + rename (same-filesystem atomic). ALWAYS wrapped by the OS secret store;
// with no secure backend the write is refused (a typed error) — never a plaintext file.
function writeMap(safeStorage, dir, map) {
  if (!isSecureBackend(safeStorage)) {
    const err = new Error('no secure OS secret store; refusing to write the grant metadata unwrapped');
    err.code = 'GRANT_META_NO_SECURE_STORE';
    throw err;
  }
  const json = JSON.stringify(sanitizeMap(map));
  const env = { v: 1, enc: true, data: safeStorage.encryptString(json).toString('base64') };
  fs.mkdirSync(dir, { recursive: true });
  const tmp = storePath(dir) + '.tmp';
  // Durable atomic replace: write the temp, fsync it, THEN rename over the target, then best-effort
  // fsync the directory — so a power loss can't commit the rename while the data blocks are unflushed,
  // leaving a zero-length/garbage file that reads as unreadable and wedges all future recording.
  const fd = fs.openSync(tmp, 'w', FILE_MODE);
  try { fs.writeSync(fd, JSON.stringify(env)); fs.fsyncSync(fd); } finally { fs.closeSync(fd); }
  fs.renameSync(tmp, storePath(dir));
  try { const dfd = fs.openSync(dir, 'r'); try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); } } catch { /* best-effort; directory fsync is unsupported on some platforms (e.g. Windows) */ }
  try { fs.chmodSync(storePath(dir), FILE_MODE); } catch { /* best-effort where the platform honours it */ }
  return { encrypted: true };
}

function refuseIfUnreadable(cur) {
  if (isUnreadable(cur.status)) {
    const err = new Error('the existing grant metadata could not be read; refusing to overwrite it');
    err.code = 'GRANT_META_UNREADABLE';
    err.status = cur.status;
    throw err;
  }
}

/** Upsert one vault's grant metadata. Refuses to clobber an existing-but-unreadable file. */
function setGrantMeta(safeStorage, dir, vaultId, meta) {
  if (typeof vaultId !== 'string' || !vaultId) throw new TypeError('vaultId must be a non-empty string');
  const cur = readGrantMeta(safeStorage, dir);
  refuseIfUnreadable(cur);
  cur.meta[vaultId] = sanitizeMeta(meta);
  return writeMap(safeStorage, dir, cur.meta);
}

/**
 * The metadata for one vault, or null if not recorded. Preserves the absent/unreadable distinction:
 * a transiently-unreadable store THROWS (GRANT_META_UNREADABLE) rather than returning null, so a caller
 * can never mistake "keyring locked / file corrupt" for "no grant recorded". Own-property lookup, so a
 * vault_id colliding with an Object.prototype member can never resolve to an inherited value.
 */
function getGrantMeta(safeStorage, dir, vaultId) {
  const cur = readGrantMeta(safeStorage, dir);
  refuseIfUnreadable(cur);
  return Object.prototype.hasOwnProperty.call(cur.meta, vaultId) ? cur.meta[vaultId] : null;
}

/** Remove one vault's metadata (its grant was revoked). Refuses to clobber an unreadable file. */
function removeGrantMeta(safeStorage, dir, vaultId) {
  const cur = readGrantMeta(safeStorage, dir);
  refuseIfUnreadable(cur);
  if (!Object.prototype.hasOwnProperty.call(cur.meta, vaultId)) return { removed: false }; // own key only, never the chain
  delete cur.meta[vaultId];
  writeMap(safeStorage, dir, cur.meta);
  return { removed: true };
}

module.exports = { readGrantMeta, getGrantMeta, setGrantMeta, removeGrantMeta, isUnreadable };

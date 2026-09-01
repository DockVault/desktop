'use strict';

/*
 * The daemon's encrypted state database.
 *
 * It holds server-correlatable sync metadata (per-vault paths, the per-name blind index, blob/version
 * ids) that is more sensitive at rest than the plaintext filenames the synced folder already exposes,
 * so the whole database is encrypted with a maintained, vetted whole-database cipher (no column is left
 * queryable in plaintext, so there is no missed-column or blind-index-at-rest risk).
 *
 * Key handling (the key material is reviewed separately by the crypto reviewer):
 *  - The database key (DBK) is 32 random bytes, minted once per device. It is NOT the zero-knowledge key
 *    and NOT passphrase-derived, so the daemon can read the operational columns (relative path, counts)
 *    while the vault is locked — which is what lets a "N changes waiting" state be shown honestly.
 *  - At rest the DBK is wrapped by the OS keychain (safeStorage) in a 0600 file. It is FAIL-CLOSED: on a
 *    system whose keychain backend is the hardcoded-key fallback, no key is minted and no encrypted
 *    database is created — the sensitive metadata simply never lands on disk there.
 *  - The DBK is fed to the cipher as the raw page key (hex), so the cipher's own passphrase KDF is not
 *    run over an already-random key. The exact cipher/mode is pinned by the crypto reviewer; the default
 *    below is a placeholder the pin replaces.
 *  - The DBK and database are wiped only when the relationship ends (uninstall / forget-device / reset),
 *    never on an idle-lock. The DBK is never logged and never sent over IPC.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { isSecureBackend } = require('./token-store');

const DBK_FILE = 'state-dbk.bin';
const DB_FILE = 'state.db';

// Cipher parameters, pinned by the crypto review: the SQLCipher scheme (AES-256-CBC + per-page
// HMAC-SHA512), the SQLCipher-v4 compatibility level (fixes page size and HMAC to explicit values so a
// library-default shift cannot silently render the DB unreadable), and a raw page key (kdfIter 0 skips
// the passphrase KDF over an already-random key). On this native build AES has CPU acceleration, so
// AES-256 is the faster whole-DB choice here (a WASM build would have leaned toward ChaCha20).
const CIPHER = Object.freeze({ name: 'sqlcipher', legacy: 4, pageSize: 4096, kdfIter: 0 });

function dbkPath(dir) { return path.join(dir, DBK_FILE); }
function dbPath(dir) { return path.join(dir, DB_FILE); }

/**
 * Load the wrapped DBK, or mint one on first use. Returns a 32-byte Buffer, or null when the keychain
 * backend is not secure (fail-closed: the caller must then NOT persist any zero-knowledge metadata).
 */
function loadOrMintDBK(safeStorage, dir) {
  if (!isSecureBackend(safeStorage)) return null;
  const p = dbkPath(dir);
  try {
    if (fs.existsSync(p)) {
      const dbk = Buffer.from(safeStorage.decryptString(fs.readFileSync(p)), 'base64');
      if (dbk.length === 32) return dbk;
    }
  } catch { /* unreadable/rotated -> mint a fresh one below */ }
  const dbk = nodeCrypto.randomBytes(32);
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(p, safeStorage.encryptString(dbk.toString('base64')), { mode: 0o600 });
  return dbk;
}

/**
 * Open (creating if needed) the encrypted state database with the raw DBK as the page key. Applies the
 * at-rest footguns (no plaintext temp/journal spill) and ensures the starter schema. Throws if the DBK
 * is wrong for an existing database. Requires the native cipher module.
 */
function openStateDb(dir, dbk) {
  if (!Buffer.isBuffer(dbk) || dbk.length !== 32) throw new Error('state-db: DBK must be 32 bytes');
  const Database = require('better-sqlite3-multiple-ciphers');
  fs.mkdirSync(dir, { recursive: true });
  const db = new Database(dbPath(dir));
  try {
    // Cipher configuration is set BEFORE the key. `legacy=4` pins the SQLCipher-v4 parameter set
    // explicitly (page size 4096, per-page HMAC-SHA512, and a HMAC key derived separately from the
    // main key), so a library default shift cannot silently produce an unreadable database. The raw
    // 32-byte DBK is the page key directly (kdf_iter=0 skips the passphrase KDF over an already-random
    // key; the separate HMAC-key derivation is unaffected by kdf_iter).
    db.pragma(`cipher='${CIPHER.name}'`);
    db.pragma(`legacy=${CIPHER.legacy}`);
    db.pragma(`legacy_page_size=${CIPHER.pageSize}`);
    db.pragma(`kdf_iter=${CIPHER.kdfIter}`);
    db.pragma('cipher_memory_security=ON');          // wipe cipher-sensitive memory
    db.pragma(`key="x'${dbk.toString('hex')}'"`);    // the 32-byte DBK as the raw page key
    db.pragma('temp_store=MEMORY');                  // keep temp material off disk in plaintext
    db.pragma('journal_mode=WAL');                   // the WAL pages are covered by the whole-database cipher
    // Touching the DB validates the key now (a wrong key throws here, not later).
    db.prepare('CREATE TABLE IF NOT EXISTS schema_meta(k TEXT PRIMARY KEY, v TEXT)').run();
    db.prepare('CREATE TABLE IF NOT EXISTS sync_state('
      + 'vault TEXT NOT NULL, rel_path TEXT NOT NULL, name_bi TEXT, blob_id TEXT,'
      + ' zk_key_version INTEGER, updated_utc INTEGER, PRIMARY KEY(vault, rel_path))').run();
    // Per-vault standard-sync run-state: when the last run happened, its result, and whether a safe
    // bisync is currently blocked on an explicit resync. `resync_required` defaults to 1 so a vault we
    // have never completed a run for — and one whose last run aborted — is fail-closed to requiring a
    // deliberate, user-initiated resync before a normal (delete-capable) bisync is allowed to run.
    db.prepare('CREATE TABLE IF NOT EXISTS sync_run('
      + 'vault TEXT PRIMARY KEY, last_run_utc INTEGER, last_result TEXT,'
      + ' resync_required INTEGER NOT NULL DEFAULT 1)').run();
    // Restrict the DB and its sidecars to the owner (a no-op on Windows, correct on macOS/Linux).
    for (const f of [dbPath(dir), dbPath(dir) + '-wal', dbPath(dir) + '-shm']) {
      try { if (fs.existsSync(f)) fs.chmodSync(f, 0o600); } catch { /* best effort */ }
    }
    return db;
  } catch (e) {
    // Do not leak the file handle on a failed open (e.g. a wrong key) — a leaked handle keeps the
    // file locked (notably on Windows), which would block a later wipe.
    try { db.close(); } catch { /* ignore */ }
    throw e;
  }
}

/**
 * The standard-sync run-state for one vault. A vault with no recorded run reads as fail-closed:
 * resyncRequired=true (a first run must be a deliberate resync, never a silent delete-capable bisync).
 * @returns {{ lastRunUtc: number|null, lastResult: string|null, resyncRequired: boolean }}
 */
function getRunState(db, vault) {
  const row = db.prepare('SELECT last_run_utc, last_result, resync_required FROM sync_run WHERE vault=?').get(vault);
  if (!row) return { lastRunUtc: null, lastResult: null, resyncRequired: true };
  return { lastRunUtc: row.last_run_utc, lastResult: row.last_result, resyncRequired: !!row.resync_required };
}

/**
 * Record the outcome of a run. `resyncRequired` is stored explicitly by the caller (the sync engine),
 * so a run that aborted on a safety guard can leave the vault blocked on an explicit resync, and a clean
 * run can clear that block. `atUtc` is supplied by the caller (the daemon) so this stays free of a wall
 * clock and is deterministic under test.
 */
function recordRun(db, vault, { result, resyncRequired, atUtc }) {
  db.prepare('INSERT INTO sync_run(vault, last_run_utc, last_result, resync_required) VALUES(?,?,?,?)'
    + ' ON CONFLICT(vault) DO UPDATE SET last_run_utc=excluded.last_run_utc,'
    + ' last_result=excluded.last_result, resync_required=excluded.resync_required')
    .run(vault, atUtc, String(result), resyncRequired ? 1 : 0);
}

/** Remove the database and its wrapped key. Relationship-ends only — never on an idle-lock. */
function wipe(dir) {
  for (const f of [dbkPath(dir), dbPath(dir), dbPath(dir) + '-wal', dbPath(dir) + '-shm']) {
    try { fs.rmSync(f, { force: true }); } catch { /* best effort */ }
  }
}

module.exports = { loadOrMintDBK, openStateDb, wipe, getRunState, recordRun, CIPHER, dbkPath, dbPath };

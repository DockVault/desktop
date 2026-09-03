'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { loadOrMintDBK, openStateDb, wipe, getRunState, recordRun, dbkPath, dbPath } = require('../src/main/state-db');

// safeStorage stand-in: base64 round-trip (so the wrapped DBK is not literally the DBK on disk);
// backend name + availability configurable to exercise the fail-closed gate.
function mockSafe(backend, available = true) {
  return {
    isEncryptionAvailable: () => available,
    getSelectedStorageBackend: () => backend,
    encryptString: (s) => Buffer.from(Buffer.from(s, 'utf8').toString('base64'), 'utf8'),
    decryptString: (buf) => Buffer.from(Buffer.from(buf).toString('utf8'), 'base64').toString('utf8'),
  };
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-sdb-')); }

test('DBK is fail-closed under a non-secure keychain (nothing minted)', () => {
  const dir = tmp();
  assert.strictEqual(loadOrMintDBK(mockSafe('basic_text'), dir), null);
  assert.strictEqual(loadOrMintDBK(mockSafe('gnome_libsecret', false), dir), null);
  assert.ok(!fs.existsSync(dbkPath(dir)), 'no DBK file under a non-secure backend');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('DBK is minted once and then loaded (stable across calls), 32 bytes, not plaintext on disk', () => {
  const dir = tmp();
  const safe = mockSafe('gnome_libsecret');
  const a = loadOrMintDBK(safe, dir);
  assert.ok(Buffer.isBuffer(a) && a.length === 32);
  const b = loadOrMintDBK(safe, dir);
  assert.deepStrictEqual(a, b, 'same DBK on the second call (loaded, not re-minted)');
  const raw = fs.readFileSync(dbkPath(dir));
  assert.ok(!raw.includes(a), 'the raw DBK bytes are not on disk (wrapped)');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an existing wrapped key that FAILS to decrypt is never overwritten — throws db-key-unreadable, bytes intact, recoverable', () => {
  const dir = tmp();
  const good = mockSafe('gnome_libsecret');
  const key = loadOrMintDBK(good, dir);          // mint the real key on true first use
  const before = fs.readFileSync(dbkPath(dir));  // snapshot the wrapped-key bytes
  // A TRANSIENT keychain error: decrypt throws for the existing key file. Minting a fresh key over it would
  // orphan the encrypted DB (only the old key can open it) and destroy the run-state — so it must NOT happen.
  const flaky = { ...good, decryptString: () => { throw new Error('keychain temporarily unavailable'); } };
  assert.throws(() => loadOrMintDBK(flaky, dir), (e) => e && e.reason === 'db-key-unreadable',
    'an undecryptable existing key throws the typed db-key-unreadable, never mints');
  assert.deepStrictEqual(fs.readFileSync(dbkPath(dir)), before, 'the wrapped-key file bytes are UNCHANGED (no overwrite = no data loss)');
  // When the keychain recovers, the ORIGINAL key loads again — the encrypted DB is still openable.
  assert.deepStrictEqual(loadOrMintDBK(good, dir), key, 'the same key is recovered once decrypt works again');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an existing wrapped key that decrypts to the WRONG LENGTH throws db-key-unreadable, bytes intact', () => {
  const dir = tmp();
  const good = mockSafe('gnome_libsecret');
  loadOrMintDBK(good, dir);
  const before = fs.readFileSync(dbkPath(dir));
  // decrypt yields a short (non-32-byte) key — a truncated/corrupt wrapping. Fail closed, do not re-mint.
  const shortKey = { ...good, decryptString: () => Buffer.from([1, 2, 3]).toString('base64') };
  assert.throws(() => loadOrMintDBK(shortKey, dir), (e) => e && e.reason === 'db-key-unreadable');
  assert.deepStrictEqual(fs.readFileSync(dbkPath(dir)), before, 'a wrong-length decrypt leaves the key file bytes unchanged');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('encrypted state DB round-trips, is ciphertext at rest, and rejects a wrong key', () => {
  const dir = tmp();
  const dbk = nodeCrypto.randomBytes(32);
  const db = openStateDb(dir, dbk);
  db.prepare('INSERT INTO sync_state(vault, rel_path, name_bi, blob_id, zk_key_version, updated_utc) VALUES(?,?,?,?,?,?)')
    .run('v1', 'folder/secret-name.txt', 'bi_deadbeef', 'blob_1234', 3, 1);
  const row = db.prepare('SELECT * FROM sync_state WHERE vault=? AND rel_path=?').get('v1', 'folder/secret-name.txt');
  assert.strictEqual(row.blob_id, 'blob_1234');
  assert.strictEqual(row.zk_key_version, 3);
  // Owner-only permissions on the DB (a no-op on Windows).
  if (process.platform !== 'win32') {
    assert.strictEqual(fs.statSync(dbPath(dir)).mode & 0o777, 0o600, 'DB file is 0600');
  }
  // The WAL sidecar the write created must ALSO be ciphertext — the classic plaintext-spill footgun.
  const walPath = dbPath(dir) + '-wal';
  const walRaw = fs.existsSync(walPath) ? fs.readFileSync(walPath) : Buffer.alloc(0);
  db.close();

  // On disk: fully ciphertext — no plaintext markers, and not a standard SQLite header.
  const raw = fs.readFileSync(dbPath(dir));
  assert.ok(!raw.subarray(0, 16).toString('latin1').startsWith('SQLite format 3'), 'header is encrypted');
  for (const marker of ['secret-name.txt', 'bi_deadbeef', 'blob_1234']) {
    assert.ok(!raw.includes(Buffer.from(marker)), `no plaintext "${marker}" in the DB at rest`);
    assert.ok(!walRaw.includes(Buffer.from(marker)), `no plaintext "${marker}" in the -wal at rest`);
  }

  // Reopen with the same key -> reads; with a wrong key -> throws.
  const db2 = openStateDb(dir, dbk);
  assert.strictEqual(db2.prepare('SELECT count(*) c FROM sync_state').get().c, 1);
  db2.close();
  assert.throws(() => { const bad = openStateDb(dir, nodeCrypto.randomBytes(32)); bad.prepare('SELECT count(*) FROM sync_state').get(); },
    'a wrong DBK must not open the database');

  wipe(dir);
  assert.ok(!fs.existsSync(dbPath(dir)) && !fs.existsSync(dbkPath(dir)), 'wipe removes the DB and the wrapped key');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('run-state defaults fail-closed (resync required) and round-trips per vault', () => {
  const dir = tmp();
  const db = openStateDb(dir, nodeCrypto.randomBytes(32));
  // A vault with no recorded run is fail-closed: a first run must be a deliberate resync.
  assert.deepStrictEqual(getRunState(db, 'v1'), { lastRunUtc: null, lastResult: null, resyncRequired: true });
  recordRun(db, 'v1', { result: 'resync-ok', resyncRequired: false, atUtc: 1000 });
  assert.deepStrictEqual(getRunState(db, 'v1'), { lastRunUtc: 1000, lastResult: 'resync-ok', resyncRequired: false });
  // A later run upserts the same vault; a second vault is independent and still fail-closed.
  recordRun(db, 'v1', { result: 'ok', resyncRequired: false, atUtc: 2000 });
  assert.deepStrictEqual(getRunState(db, 'v1'), { lastRunUtc: 2000, lastResult: 'ok', resyncRequired: false });
  assert.strictEqual(getRunState(db, 'v2').resyncRequired, true, 'a different vault keeps its fail-closed default');
  db.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

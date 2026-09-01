'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { isSecureBackend, persistSession, loadSession, clearSession } = require('../src/main/token-store');

// A stand-in for Electron safeStorage. encryptString/decryptString round-trip through base64 (so the
// "not plaintext on disk" assertion is meaningful — the literal token must not appear in the encoded
// bytes); the real safeStorage performs real keychain encryption. Backend name + availability are
// configurable so the fail-closed logic can be exercised.
function mockSafe(backend, available = true) {
  return {
    isEncryptionAvailable: () => available,
    getSelectedStorageBackend: () => backend,
    encryptString: (s) => Buffer.from(Buffer.from(s, 'utf8').toString('base64'), 'utf8'),
    decryptString: (buf) => Buffer.from(Buffer.from(buf).toString('utf8'), 'base64').toString('utf8'),
  };
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-tok-')); }

test('a real keychain backend is secure; basic_text and unavailable are not', () => {
  assert.strictEqual(isSecureBackend(mockSafe('gnome_libsecret')), true);
  assert.strictEqual(isSecureBackend(mockSafe('kwallet')), true);
  assert.strictEqual(isSecureBackend(mockSafe('basic_text')), false);
  assert.strictEqual(isSecureBackend(mockSafe('gnome_libsecret', false)), false);
  assert.strictEqual(isSecureBackend(null), false);
});

test('persist + load round-trips the session bundle on a secure backend', () => {
  const dir = tmp();
  const safe = mockSafe('gnome_libsecret');
  const bundle = { authToken: 'opaque-server-bearer', currentUser: 'alice', ts: 1 };
  const r = persistSession(safe, dir, bundle);
  assert.strictEqual(r.persisted, true);
  assert.strictEqual(r.backend, 'gnome_libsecret');
  assert.ok(fs.existsSync(path.join(dir, 'session.bin')), 'the encrypted store exists');
  const raw = fs.readFileSync(path.join(dir, 'session.bin'), 'utf8');
  assert.ok(!raw.includes('opaque-server-bearer'), 'token is not stored in plaintext');
  assert.deepStrictEqual(loadSession(safe, dir), bundle);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('fail-closed under basic_text: nothing is written and load returns null', () => {
  const dir = tmp();
  const safe = mockSafe('basic_text');
  const r = persistSession(safe, dir, { authToken: 'x' });
  assert.strictEqual(r.persisted, false);
  assert.strictEqual(r.backend, 'basic_text');
  assert.ok(!fs.existsSync(path.join(dir, 'session.bin')), 'no token file under a non-secure backend');
  assert.strictEqual(loadSession(safe, dir), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('clearSession removes the stored session', () => {
  const dir = tmp();
  const safe = mockSafe('kwallet');
  persistSession(safe, dir, { authToken: 'x' });
  clearSession(dir);
  assert.strictEqual(loadSession(safe, dir), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

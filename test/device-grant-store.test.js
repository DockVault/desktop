'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { readGrantMeta, getGrantMeta, setGrantMeta, removeGrantMeta } = require('../src/main/device-grant-store');

function mockSafe(available, backend) {
  return {
    isEncryptionAvailable: () => available,
    getSelectedStorageBackend: () => backend || (available ? 'keychain' : 'unknown'),
    encryptString: (s) => Buffer.from(Buffer.from(s, 'utf8').toString('base64'), 'utf8'),
    decryptString: (b) => Buffer.from(Buffer.from(b).toString('utf8'), 'base64').toString('utf8'),
  };
}
// Read the wrapped file back through the mock's own unwrap, so a leak check can look at what was actually stored.
function unwrapped(dir) {
  const env = JSON.parse(fs.readFileSync(storeFile(dir), 'utf8'));
  return mockSafe(true).decryptString(Buffer.from(env.data, 'base64'));
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-gmeta-')); }
const storeFile = (dir) => path.join(dir, 'device-grants.json');

test('set + get round-trips the metadata, wrapped when a secure store is available', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  setGrantMeta(safe, dir, 'v1', { name: 'Payroll', vaultType: 'standard', hasPassword: true });
  assert.deepStrictEqual(getGrantMeta(safe, dir, 'v1'), { name: 'Payroll', vaultType: 'standard', hasPassword: true });
  const env = JSON.parse(fs.readFileSync(storeFile(dir), 'utf8'));
  assert.strictEqual(env.enc, true);
  assert.ok(!fs.readFileSync(storeFile(dir), 'utf8').includes('Payroll'), 'a wrapped store does not expose the vault name in plaintext');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('without a secure store a write is REFUSED (typed) and nothing is written — never a plaintext file', () => {
  for (const safe of [mockSafe(false), mockSafe(true, 'basic_text'), null, {}]) {
    const dir = tmp();
    assert.throws(() => setGrantMeta(safe, dir, 'v1', { name: 'Payroll', vaultType: 'standard', hasPassword: false }),
      (e) => e.code === 'GRANT_META_NO_SECURE_STORE');
    assert.ok(!fs.existsSync(storeFile(dir)) && !fs.existsSync(storeFile(dir) + '.tmp'), 'no file (not even a temp) is left behind');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('an unwrapped envelope found on disk is unreadable (unparseable), never read as metadata', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  fs.writeFileSync(storeFile(dir), JSON.stringify({ v: 1, enc: false, data: JSON.stringify({ v1: { name: 'Payroll', vaultType: 'standard', hasPassword: false } }) }));
  assert.strictEqual(readGrantMeta(safe, dir).status, 'unparseable');
  assert.throws(() => getGrantMeta(safe, dir, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('sanitize: only {name, vaultType, hasPassword} round-trip — a secret-ish field can never be stored', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  setGrantMeta(safe, dir, 'v1', { name: 'V', vaultType: 'standard', hasPassword: true, vault_password: 'PW', secret: 'S', token: 'T' });
  assert.deepStrictEqual(Object.keys(getGrantMeta(safe, dir, 'v1')).sort(), ['hasPassword', 'name', 'vaultType']);
  const raw = unwrapped(dir); // look INSIDE the wrap: the sanitizer, not the wrap, is what keeps a secret out
  assert.ok(raw.includes('"V"'), 'the unwrap is real (non-vacuous)');
  assert.ok(!raw.includes('vault_password') && !raw.includes('"secret"') && !raw.includes('PW'), 'no secret-ish field reaches disk');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('status-aware: absent vs unparseable vs undecryptable are distinct (never conflated)', () => {
  const dir = tmp();
  assert.strictEqual(readGrantMeta(mockSafe(true), dir).status, 'absent');
  fs.writeFileSync(storeFile(dir), 'not json');
  assert.strictEqual(readGrantMeta(mockSafe(true), dir).status, 'unparseable');
  const dir2 = tmp();
  setGrantMeta(mockSafe(true), dir2, 'v1', { name: 'X', vaultType: 'standard', hasPassword: false });
  assert.strictEqual(readGrantMeta(mockSafe(false), dir2).status, 'undecryptable'); // wrapped, no secret store this boot
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(dir2, { recursive: true, force: true });
});

test('refuses to clobber an existing-but-unreadable file', () => {
  const dir = tmp();
  fs.writeFileSync(storeFile(dir), 'corrupt-not-json');
  assert.throws(() => setGrantMeta(mockSafe(true), dir, 'v1', { name: 'X', vaultType: 'standard', hasPassword: false }),
    (e) => e.code === 'GRANT_META_UNREADABLE');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('getGrantMeta THROWS on an unreadable store (never conflates "keyring locked / corrupt" with "no grant")', () => {
  const dir = tmp();
  fs.writeFileSync(storeFile(dir), 'corrupt-not-json');
  assert.throws(() => getGrantMeta(mockSafe(true), dir, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
  // A wrapped-on-disk store with no secret store this boot is likewise unreadable, not absent.
  const dir2 = tmp();
  setGrantMeta(mockSafe(true), dir2, 'v1', { name: 'X', vaultType: 'standard', hasPassword: false });
  assert.throws(() => getGrantMeta(mockSafe(false), dir2, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(dir2, { recursive: true, force: true });
});

test('getGrantMeta is prototype-safe: a vault_id colliding with an Object.prototype member resolves to null', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  setGrantMeta(safe, dir, 'v1', { name: 'A', vaultType: 'standard', hasPassword: false });
  for (const key of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    assert.strictEqual(getGrantMeta(safe, dir, key), null, `${key} must not resolve to an inherited value`);
  }
  // And on an entirely absent store, too (empty map, still own-property only).
  assert.strictEqual(getGrantMeta(safe, tmp(), 'constructor'), null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('WRITE-path prototype-safety on a fresh store: a colliding vault_id is an ordinary own key, never a setter or the chain', () => {
  const safe = mockSafe(true);
  // set + get round-trip for every colliding name on a FRESH (absent) store — the empty map must be prototype-free too.
  for (const key of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
    const dir = tmp();
    const meta = { name: 'P', vaultType: 'standard', hasPassword: true };
    setGrantMeta(safe, dir, key, meta);
    assert.deepStrictEqual(getGrantMeta(safe, dir, key), meta, `${key} must round-trip as its own entry`);
    assert.deepStrictEqual(Object.keys(readGrantMeta(safe, dir).meta), [key], 'exactly that one own entry exists');
    assert.strictEqual(Object.getPrototypeOf(readGrantMeta(safe, dir).meta), null, 'the map stays prototype-free');
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // remove of an absent colliding name on a FRESH store: a miss, and no file is created.
  for (const key of ['toString', '__proto__', 'constructor']) {
    const dir = tmp();
    assert.deepStrictEqual(removeGrantMeta(safe, dir, key), { removed: false });
    assert.ok(!fs.existsSync(storeFile(dir)), 'a miss writes nothing');
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // and the empty map of every non-ok status is prototype-free as well.
  const dir = tmp();
  assert.strictEqual(Object.getPrototypeOf(readGrantMeta(safe, dir).meta), null, 'absent');
  fs.writeFileSync(storeFile(dir), 'corrupt');
  assert.strictEqual(Object.getPrototypeOf(readGrantMeta(safe, dir).meta), null, 'unparseable');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a wrapped store read under the hardcoded-key backend is undecryptable, never trusted (the read path uses the same secure-backend rule as the write path)', () => {
  const dir = tmp();
  setGrantMeta(mockSafe(true), dir, 'v1', { name: 'Payroll', vaultType: 'standard', hasPassword: true });
  const before = fs.readFileSync(storeFile(dir), 'utf8');
  for (const safe of [mockSafe(true, 'basic_text'), mockSafe(false), null, {}]) {
    const r = readGrantMeta(safe, dir);
    assert.strictEqual(r.status, 'undecryptable');
    assert.strictEqual(Object.getPrototypeOf(r.meta), null, 'the empty undecryptable map is prototype-free');
    assert.deepStrictEqual(Object.keys(r.meta), []);
    assert.throws(() => getGrantMeta(safe, dir, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
    assert.throws(() => setGrantMeta(safe, dir, 'v2', { name: 'X', vaultType: 'standard', hasPassword: false }), (e) => e.code === 'GRANT_META_UNREADABLE' || e.code === 'GRANT_META_NO_SECURE_STORE');
    assert.throws(() => removeGrantMeta(safe, dir, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
  }
  assert.strictEqual(fs.readFileSync(storeFile(dir), 'utf8'), before, 'nothing was rewritten');
  // a wrapped envelope whose ciphertext is damaged is undecryptable too, and equally prototype-free
  const env = JSON.parse(before); env.data = 'not-base64-of-anything!!';
  fs.writeFileSync(storeFile(dir), JSON.stringify(env));
  const damaged = readGrantMeta(mockSafe(true), dir);
  assert.strictEqual(damaged.status, 'undecryptable');
  assert.strictEqual(Object.getPrototypeOf(damaged.meta), null);
  // and an io failure (the store path is a directory) reads unreadable-io with a prototype-free map
  const dir2 = tmp(); fs.mkdirSync(storeFile(dir2));
  const io = readGrantMeta(mockSafe(true), dir2);
  assert.strictEqual(io.status, 'unreadable-io');
  assert.strictEqual(Object.getPrototypeOf(io.meta), null);
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(dir2, { recursive: true, force: true });
});

test('removeGrantMeta refuses an unreadable store (corrupt or wrapped-with-no-secret-store), mirroring set/get', () => {
  const dir = tmp();
  fs.writeFileSync(storeFile(dir), 'corrupt-not-json');
  assert.throws(() => removeGrantMeta(mockSafe(true), dir, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
  assert.strictEqual(fs.readFileSync(storeFile(dir), 'utf8'), 'corrupt-not-json', 'the unreadable file is left untouched');
  const dir2 = tmp();
  setGrantMeta(mockSafe(true), dir2, 'v1', { name: 'X', vaultType: 'standard', hasPassword: false });
  const before = fs.readFileSync(storeFile(dir2), 'utf8');
  assert.throws(() => removeGrantMeta(mockSafe(false), dir2, 'v1'), (e) => e.code === 'GRANT_META_UNREADABLE');
  assert.strictEqual(fs.readFileSync(storeFile(dir2), 'utf8'), before, 'the wrapped file is left untouched');
  fs.rmSync(dir, { recursive: true, force: true });
  fs.rmSync(dir2, { recursive: true, force: true });
});

test('remove drops one entry; a miss reports removed:false; a get miss is null; bad vaultId throws', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  setGrantMeta(safe, dir, 'v1', { name: 'A', vaultType: 'standard', hasPassword: false });
  setGrantMeta(safe, dir, 'v2', { name: 'B', vaultType: 'standard', hasPassword: true });
  assert.deepStrictEqual(removeGrantMeta(safe, dir, 'v1'), { removed: true });
  assert.strictEqual(getGrantMeta(safe, dir, 'v1'), null);
  assert.deepStrictEqual(getGrantMeta(safe, dir, 'v2'), { name: 'B', vaultType: 'standard', hasPassword: true });
  assert.deepStrictEqual(removeGrantMeta(safe, dir, 'nope'), { removed: false });
  for (const bad of ['', undefined, null]) assert.throws(() => setGrantMeta(safe, dir, bad, {}), TypeError);
  fs.rmSync(dir, { recursive: true, force: true });
});

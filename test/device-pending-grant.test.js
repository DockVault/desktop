'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  readPending, isUnreadable, addPending, clearPending, clearAllPending, isPending, listPending,
} = require('../src/main/device-pending-grant');

function mockSafe(available, backend) {
  return {
    isEncryptionAvailable: () => available,
    getSelectedStorageBackend: () => backend || (available ? 'keychain' : 'unknown'),
    encryptString: (s) => Buffer.from(Buffer.from(s, 'utf8').toString('base64'), 'utf8'),
    decryptString: (b) => Buffer.from(Buffer.from(b).toString('utf8'), 'base64').toString('utf8'),
  };
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-pend-')); }
const storeFile = (dir) => path.join(dir, 'device-pending-grants.json');

test('add + isPending + listPending round-trip, wrapped, with no plaintext id on disk', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  assert.deepStrictEqual(addPending(safe, dir, 'vault-abc'), { added: true });
  assert.strictEqual(isPending(safe, dir, 'vault-abc'), true);
  assert.strictEqual(isPending(safe, dir, 'vault-other'), false);
  assert.deepStrictEqual(listPending(safe, dir), ['vault-abc']);
  const env = JSON.parse(fs.readFileSync(storeFile(dir), 'utf8'));
  assert.strictEqual(env.enc, true);
  assert.ok(!fs.readFileSync(storeFile(dir), 'utf8').includes('vault-abc'), 'a wrapped store does not expose the vault id in plaintext');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('add is idempotent; clear removes; clearing an absent marker is a no-op', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  addPending(safe, dir, 'v1');
  assert.deepStrictEqual(addPending(safe, dir, 'v1'), { added: false }, 'a second add does not duplicate');
  addPending(safe, dir, 'v2');
  assert.deepStrictEqual(listPending(safe, dir).sort(), ['v1', 'v2']);
  assert.deepStrictEqual(clearPending(safe, dir, 'v1'), { removed: true });
  assert.deepStrictEqual(clearPending(safe, dir, 'v1'), { removed: false }, 'clearing again is a no-op');
  assert.deepStrictEqual(listPending(safe, dir), ['v2']);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('without a secure store a write is REFUSED (typed) and nothing is written — never a plaintext file', () => {
  for (const safe of [mockSafe(false), mockSafe(true, 'basic_text'), null, {}]) {
    const dir = tmp();
    assert.throws(() => addPending(safe, dir, 'v1'), (e) => e && e.code === 'PENDING_GRANT_NO_SECURE_STORE');
    assert.ok(!fs.existsSync(storeFile(dir)), 'no file written without a secure backend');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('status is absent before anything is written; listPending is empty', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  assert.strictEqual(readPending(safe, dir).status, 'absent');
  assert.strictEqual(isPending(safe, dir, 'v1'), false);
  assert.deepStrictEqual(listPending(safe, dir), []);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an unreadable store never reads as "not pending": mutators/isPending throw, listPending is fail-safe', () => {
  // A wrapped file that this boot has no secure backend to open reads as undecryptable (unreadable).
  const dir = tmp();
  addPending(mockSafe(true), dir, 'v1');
  const noStore = mockSafe(false);
  assert.strictEqual(isUnreadable(readPending(noStore, dir).status), true);
  assert.throws(() => isPending(noStore, dir, 'v1'), (e) => e && e.code === 'PENDING_GRANT_UNREADABLE');
  assert.throws(() => addPending(noStore, dir, 'v2'), (e) => e && e.code === 'PENDING_GRANT_UNREADABLE', 'refuses to clobber an unreadable file');
  assert.throws(() => clearPending(noStore, dir, 'v1'), (e) => e && e.code === 'PENDING_GRANT_UNREADABLE');
  assert.deepStrictEqual(listPending(noStore, dir), [], 'the resume sweep fails safe to empty, never throws');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('clearAllPending drops every marker at once (identity ended), and is a no-op when empty', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  assert.deepStrictEqual(clearAllPending(safe, dir), { removed: 0 }, 'absent store → nothing removed');
  addPending(safe, dir, 'v1');
  addPending(safe, dir, 'v2');
  assert.deepStrictEqual(clearAllPending(safe, dir), { removed: 2 });
  assert.deepStrictEqual(listPending(safe, dir), [], 'all markers gone');
  assert.deepStrictEqual(clearAllPending(safe, dir), { removed: 0 }, 'clearing again is a no-op');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('clearAllPending refuses to clobber an unreadable store', () => {
  const dir = tmp();
  addPending(mockSafe(true), dir, 'v1');
  assert.throws(() => clearAllPending(mockSafe(false), dir), (e) => e && e.code === 'PENDING_GRANT_UNREADABLE');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a garbage (non-envelope) file reads as unreadable, never as absent', () => {
  const dir = tmp();
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(storeFile(dir), 'not json at all');
  const safe = mockSafe(true);
  assert.strictEqual(isUnreadable(readPending(safe, dir).status), true);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a vault id spelling an Object.prototype member is an ordinary own key', () => {
  const dir = tmp();
  const safe = mockSafe(true);
  addPending(safe, dir, '__proto__');
  addPending(safe, dir, 'constructor');
  assert.strictEqual(isPending(safe, dir, '__proto__'), true);
  assert.strictEqual(isPending(safe, dir, 'constructor'), true);
  assert.strictEqual(isPending(safe, dir, 'toString'), false, 'an unset prototype-member id is not pending');
  assert.deepStrictEqual(listPending(safe, dir).sort(), ['__proto__', 'constructor'].sort());
  assert.deepStrictEqual(clearPending(safe, dir, '__proto__'), { removed: true });
  assert.strictEqual(isPending(safe, dir, '__proto__'), false);
  fs.rmSync(dir, { recursive: true, force: true });
});

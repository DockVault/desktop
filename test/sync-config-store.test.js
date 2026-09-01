'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const store = require('../src/main/sync-config-store');
const { makeConfigEntry } = require('../src/main/sync-config');

const abs = (p) => path.resolve(p);
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dv-cfgstore-'));

// A reversible fake of Electron's safeStorage.
const fakeSafe = (available) => ({
  isEncryptionAvailable: () => available,
  encryptString: (s) => Buffer.from('ENC:' + s, 'utf8'),
  decryptString: (buf) => { const s = buf.toString('utf8'); if (!s.startsWith('ENC:')) throw new Error('not our ciphertext'); return s.slice(4); },
});

const entry = (over) => makeConfigEntry({ vaultId: 'v1', vaultName: 'Marketing', localFolder: abs('/Users/t/M'), remotePath: 'Marketing', ...over });

test('save then load round-trips through the OS secret store when available', () => {
  const dir = tmp();
  try {
    const res = store.saveConfig(fakeSafe(true), dir, [entry()]);
    assert.strictEqual(res.encrypted, true);
    const raw = JSON.parse(fs.readFileSync(store.configPath(dir), 'utf8'));
    assert.strictEqual(raw.enc, true);
    assert.ok(!/Marketing/.test(raw.data), 'the payload is wrapped, not plaintext in the file');
    assert.deepStrictEqual(store.loadConfig(fakeSafe(true), dir), [entry()]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('with no secret store it degrades to a plaintext file (feature not disabled), still round-trips', () => {
  const dir = tmp();
  try {
    const res = store.saveConfig(fakeSafe(false), dir, [entry()]);
    assert.strictEqual(res.encrypted, false);
    const raw = JSON.parse(fs.readFileSync(store.configPath(dir), 'utf8'));
    assert.strictEqual(raw.enc, false);
    assert.deepStrictEqual(store.loadConfig(fakeSafe(false), dir), [entry()]);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('load is fail-safe: [] on a missing file, a corrupt file, or an encrypted file with no secret store', () => {
  // Separate dirs so no test step saves OVER an unreadable file (which saveConfig now refuses — see below).
  const a = tmp(); const b = tmp(); const c = tmp();
  try {
    assert.deepStrictEqual(store.loadConfig(fakeSafe(true), a), [], 'missing file');
    fs.writeFileSync(store.configPath(b), 'not json at all');
    assert.deepStrictEqual(store.loadConfig(fakeSafe(true), b), [], 'corrupt file');
    store.saveConfig(fakeSafe(true), c, [entry()]);          // writes an encrypted envelope
    assert.deepStrictEqual(store.loadConfig(fakeSafe(false), c), [], 'encrypted file but no secret store now');
  } finally { for (const d of [a, b, c]) fs.rmSync(d, { recursive: true, force: true }); }
});

test('a credential-bearing or tampered entry is dropped, never persisted or loaded', () => {
  const dir = tmp();
  try {
    // saveConfig sanitizes: an entry carrying a credential field is dropped before disk.
    store.saveConfig(fakeSafe(true), dir, [entry(), { vaultId: 'x', vaultName: 'X', localFolder: abs('/Users/t/X'), remotePath: 'X', password: 'leak' }]);
    assert.deepStrictEqual(store.loadConfig(fakeSafe(true), dir).map((e) => e.vaultId), ['v1']);
    // a file hand-tampered with an extra field is sanitized on load, too.
    const tampered = { v: 1, enc: false, data: JSON.stringify([{ vaultId: 'v1', vaultName: 'M', localFolder: abs('/Users/t/M'), remotePath: 'M', enabled: true, token: 'sneaky' }]) };
    fs.writeFileSync(store.configPath(dir), JSON.stringify(tampered));
    assert.deepStrictEqual(store.loadConfig(fakeSafe(false), dir), [], 'the tampered row is dropped, not loaded with the extra field');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('readConfigState distinguishes absent / ok / unparseable', () => {
  const dir = tmp();
  try {
    assert.strictEqual(store.readConfigState(fakeSafe(true), dir).status, 'absent');
    store.saveConfig(fakeSafe(true), dir, [entry()]);
    assert.strictEqual(store.readConfigState(fakeSafe(true), dir).status, 'ok');
    fs.writeFileSync(store.configPath(dir), 'not json at all');
    assert.strictEqual(store.readConfigState(fakeSafe(true), dir).status, 'unparseable');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('saveConfig refuses to overwrite an existing-but-undecryptable file (no clobber, no downgrade)', () => {
  const dir = tmp();
  try {
    store.saveConfig(fakeSafe(true), dir, [entry()]);                 // encrypted on disk
    assert.strictEqual(store.readConfigState(fakeSafe(false), dir).status, 'undecryptable'); // keyring gone
    assert.throws(() => store.saveConfig(fakeSafe(false), dir, []), /refusing to overwrite/, 'refuses to clobber');
    // the original encrypted file is intact and readable again once the keyring returns
    assert.deepStrictEqual(store.loadConfig(fakeSafe(true), dir), [entry()]);
    // it also refuses over an unparseable file
    fs.writeFileSync(store.configPath(dir), 'corrupt');
    assert.throws(() => store.saveConfig(fakeSafe(true), dir, []), /refusing to overwrite/);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('saveConfig writes atomically and leaves no temp file behind', () => {
  const dir = tmp();
  try {
    store.saveConfig(fakeSafe(true), dir, [entry()]);
    assert.strictEqual(fs.existsSync(store.configPath(dir) + '.tmp'), false, 'no lingering .tmp');
    store.saveConfig(fakeSafe(true), dir, [entry(), entry({ vaultId: 'v2', vaultName: 'F', localFolder: abs('/Users/t/F'), remotePath: 'F' })]); // overwrite ok when readable
    assert.strictEqual(store.loadConfig(fakeSafe(true), dir).length, 2);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

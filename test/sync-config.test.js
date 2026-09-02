'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const cfg = require('../src/main/sync-config');

const abs = (p) => path.resolve(p); // platform-correct absolute path rooted at the current drive

// ---- remotePathForVault ----
test('remotePathForVault: a clean vault directory becomes a single safe segment', () => {
  assert.strictEqual(cfg.remotePathForVault('Marketing'), 'Marketing');
  assert.strictEqual(cfg.remotePathForVault('/Marketing/'), 'Marketing'); // stray separators collapse
});

test('remotePathForVault: rejects root, empty, traversal, nesting, and control chars', () => {
  // Control-char vectors use escapes ('\x00' NUL, '\x01' SOH) so this stays a normal text file.
  for (const bad of ['', '/', '.', '..', 'a/b', 'a\\b', 'a/../b', '\x00', 'a\x01b']) {
    assert.throws(() => cfg.remotePathForVault(bad), `should reject ${JSON.stringify(bad)}`);
  }
  assert.throws(() => cfg.remotePathForVault(undefined));
});

test('remotePathForVault: accepts an ordinary multi-character name', () => {
  assert.strictEqual(cfg.remotePathForVault('My Vault 2024'), 'My Vault 2024');
});

// ---- classifyLocalTarget ----
const ctx = () => ({
  home: abs('/Users/tester'),
  userData: abs('/Users/tester/AppData/DockVault'),
  refuseRoots: [abs('/Windows'), abs('/Program Files')],
  existingFolders: [abs('/Users/tester/Vaults/Finance')],
});

test('classifyLocalTarget: a normal folder under home is accepted', () => {
  assert.deepStrictEqual(cfg.classifyLocalTarget(abs('/Users/tester/Vaults/Marketing'), ctx()), { ok: true });
});

test('classifyLocalTarget: refuses empty / relative / home-root / above-home / app-data / system', () => {
  assert.strictEqual(cfg.classifyLocalTarget('', ctx()).ok, false);
  assert.strictEqual(cfg.classifyLocalTarget('relative/path', ctx()).ok, false);
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Users/tester'), ctx()).reason, 'home-root-or-above');
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Users'), ctx()).reason, 'home-root-or-above');
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Users/tester/AppData/DockVault/sub'), ctx()).reason, 'app-data-dir');
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Windows/System32'), ctx()).reason, 'system-location');
});

test('classifyLocalTarget: refuses overlap with another vault sync (equal, nested, or containing)', () => {
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Users/tester/Vaults/Finance'), ctx()).reason, 'overlaps-another-sync');
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Users/tester/Vaults/Finance/sub'), ctx()).reason, 'overlaps-another-sync');
  assert.strictEqual(cfg.classifyLocalTarget(abs('/Users/tester/Vaults'), ctx()).reason, 'overlaps-another-sync');
});

test('classifyLocalTarget: a folder inside a consumer cloud-sync root is allowed but flagged', () => {
  for (const p of ['/Users/tester/OneDrive/Vaults/M', '/Users/tester/Dropbox/M', '/Users/tester/Google Drive/M', '/Users/tester/iCloud Drive/M']) {
    const r = cfg.classifyLocalTarget(abs(p), ctx());
    assert.strictEqual(r.ok, true, `${p} is allowed`);
    assert.strictEqual(r.warn, 'inside-cloud-sync', `${p} is flagged`);
  }
});

test('classifyLocalTarget: refuses a filesystem root itself (a whole drive / volume top)', () => {
  const root = path.parse(abs('/anything')).root; // 'C:\\' on win32, '/' on POSIX
  assert.strictEqual(cfg.classifyLocalTarget(root, ctx()).reason, 'filesystem-root');
});

test('classifyLocalTarget: case-insensitive mode catches a differently-cased overlap the sensitive mode misses', () => {
  const c = ctx(); // existingFolders = [ .../Vaults/Finance ]
  const cased = c.existingFolders[0].toUpperCase(); // same path, different case, still absolute
  assert.strictEqual(cfg.classifyLocalTarget(cased, { ...c, caseInsensitive: true }).reason, 'overlaps-another-sync');
  assert.notStrictEqual(cfg.classifyLocalTarget(cased, { ...c, caseInsensitive: false }).reason, 'overlaps-another-sync');
});

// ---- config record ----
test('makeConfigEntry: builds a credential-free record and defaults enabled true', () => {
  const e = cfg.makeConfigEntry({ vaultId: 'v1', vaultName: 'Marketing', localFolder: abs('/Users/tester/Vaults/M'), remotePath: 'Marketing' });
  assert.deepStrictEqual(e, { vaultId: 'v1', vaultName: 'Marketing', localFolder: abs('/Users/tester/Vaults/M'), remotePath: 'Marketing', enabled: true, consented: false });
});

test('makeConfigEntry: records consent when given, and never assumes it (defaults false)', () => {
  assert.strictEqual(cfg.makeConfigEntry({ vaultId: 'v', vaultName: 'M', localFolder: abs('/x'), remotePath: 'M', consented: true }).consented, true);
  assert.strictEqual(cfg.makeConfigEntry({ vaultId: 'v', vaultName: 'M', localFolder: abs('/x'), remotePath: 'M' }).consented, false);
});

test('makeConfigEntry: rejects any credential-adjacent or unexpected field, and bad required fields', () => {
  const base = { vaultId: 'v1', vaultName: 'M', localFolder: abs('/Users/tester/M'), remotePath: 'M' };
  for (const bad of ['password', 'credential', 'token', 'hostKeys', 'passphrase']) {
    assert.throws(() => cfg.makeConfigEntry({ ...base, [bad]: 'x' }), new RegExp(bad));
  }
  assert.throws(() => cfg.makeConfigEntry({ ...base, surprise: 1 }), /unexpected config field/);
  assert.throws(() => cfg.makeConfigEntry({ ...base, localFolder: 'relative' }), /absolute localFolder/);
  assert.throws(() => cfg.makeConfigEntry({ vaultName: 'M', localFolder: abs('/x'), remotePath: 'M' }), /vaultId/);
});

test('assertCredFree throws if a credential-adjacent field is ever present', () => {
  assert.throws(() => cfg.assertCredFree({ vaultId: 'v', password: 'p' }), /credential field must never/);
  assert.doesNotThrow(() => cfg.assertCredFree({ vaultId: 'v', vaultName: 'M', localFolder: abs('/x'), remotePath: 'M', enabled: true }));
});

test('upsertEntry keys by vaultId (replace, not duplicate); removeEntry drops it', () => {
  const e1 = cfg.makeConfigEntry({ vaultId: 'v1', vaultName: 'M', localFolder: abs('/Users/tester/M'), remotePath: 'M' });
  const e1b = cfg.makeConfigEntry({ vaultId: 'v1', vaultName: 'M', localFolder: abs('/Users/tester/M2'), remotePath: 'M' });
  const e2 = cfg.makeConfigEntry({ vaultId: 'v2', vaultName: 'F', localFolder: abs('/Users/tester/F'), remotePath: 'F' });
  let list = cfg.upsertEntry([], e1);
  list = cfg.upsertEntry(list, e2);
  list = cfg.upsertEntry(list, e1b); // replaces v1
  assert.strictEqual(list.length, 2);
  assert.strictEqual(list.find((x) => x.vaultId === 'v1').localFolder, abs('/Users/tester/M2'));
  list = cfg.removeEntry(list, 'v1');
  assert.deepStrictEqual(list.map((x) => x.vaultId), ['v2']);
});

test('platformRefuseRoots returns the right system-dir set per platform (win32 honours env)', () => {
  // Use backslash-free override values so the assertions do not depend on escape handling.
  const win = cfg.platformRefuseRoots('win32', { SystemRoot: 'X:/WinTest', ProgramData: 'X:/PDTest' });
  assert.ok(win.includes('X:/WinTest') && win.includes('X:/PDTest'), 'win32 honours SystemRoot/ProgramData env');
  assert.ok(cfg.platformRefuseRoots('win32', {}).some((r) => /Windows/i.test(r)), 'win32 defaults refuse the Windows dir');
  assert.ok(cfg.platformRefuseRoots('darwin', {}).includes('/System'), 'darwin refuses /System');
  const lin = cfg.platformRefuseRoots('linux', {});
  assert.ok(lin.includes('/usr') && lin.includes('/etc') && lin.includes('/boot'), 'linux refuses the core system dirs');
});

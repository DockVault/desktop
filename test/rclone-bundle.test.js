'use strict';

// The helper's location and pin: a packaged app reads the committed manifest and the binary beside the
// archive, ignores the environment entirely, and never falls back anywhere; a development checkout may
// override with the environment; a manifest without a usable entry means "no standard sync", not a crash.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { resolveBundledRclone, MANIFEST } = require('../src/main/rclone-bundle');

const committed = JSON.parse(fs.readFileSync(MANIFEST, 'utf8'));

function tempManifest(obj) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rclone-manifest-'));
  const file = path.join(dir, `m-${Math.random().toString(16).slice(2)}.json`);
  fs.writeFileSync(file, JSON.stringify(obj));
  return file;
}

test('a packaged app resolves the bundled binary beside the archive with the committed pin', () => {
  const r = resolveBundledRclone({ isPackaged: true, resourcesPath: path.join('R', 'res'), platform: 'win32', arch: 'x64', env: { DOCKVAULT_RCLONE: 'C:/elsewhere/rclone.exe', DOCKVAULT_RCLONE_SHA256: 'ff' } });
  assert.deepEqual(r, { bin: path.join('R', 'res', 'rclone', 'rclone.exe'), version: committed.version, sha256: committed.targets['win32-x64'].binarySha256 });
  for (const [target, t] of Object.entries(committed.targets)) {
    const [platform, arch] = target.split('-');
    const got = resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform, arch });
    assert.equal(got.bin, path.join('res', 'rclone', t.binary));
    assert.equal(got.sha256, t.binarySha256);
    assert.equal(got.version, committed.version);
  }
});

test('a packaged app ignores the environment even when it is set', () => {
  const env = { DOCKVAULT_RCLONE: '/tmp/evil', DOCKVAULT_RCLONE_VERSION: '9.9.9', DOCKVAULT_RCLONE_SHA256: 'a'.repeat(64) };
  const r = resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'linux', arch: 'x64', env });
  assert.equal(r.bin, path.join('res', 'rclone', 'rclone'));
  assert.equal(r.version, committed.version);
  assert.notEqual(r.sha256, env.DOCKVAULT_RCLONE_SHA256);
});

test('a development checkout uses the fetched binary under build/rclone, or the environment override', () => {
  const dev = resolveBundledRclone({ isPackaged: false, platform: 'darwin', arch: 'arm64', env: {}, devRoot: 'DEV' });
  assert.deepEqual(dev, { bin: path.join('DEV', 'darwin-arm64', 'rclone'), version: committed.version, sha256: committed.targets['darwin-arm64'].binarySha256 });
  const over = resolveBundledRclone({ isPackaged: false, platform: 'darwin', arch: 'arm64', env: { DOCKVAULT_RCLONE: '/opt/rclone', DOCKVAULT_RCLONE_VERSION: '1.2.3' } });
  assert.deepEqual(over, { bin: '/opt/rclone', version: '1.2.3', sha256: null });
});

test('a platform without a pinned helper, or a malformed manifest, yields null rather than a guess', () => {
  assert.equal(resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'linux', arch: 'arm64' }), null);
  assert.equal(resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'win32', arch: 'x64', manifestPath: path.join(os.tmpdir(), 'does-not-exist.json') }), null);
  const noVersion = tempManifest({ targets: { 'win32-x64': { binary: 'rclone.exe', binarySha256: 'a'.repeat(64) } } });
  assert.equal(resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'win32', arch: 'x64', manifestPath: noVersion }), null);
  const noHash = tempManifest({ version: '1.0.0', targets: { 'win32-x64': { binary: 'rclone.exe' } } });
  assert.equal(resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'win32', arch: 'x64', manifestPath: noHash }), null);
  // The binary name is a bare file name; a manifest cannot steer the app outside resources/rclone.
  const escaping = tempManifest({ version: '1.0.0', targets: { 'win32-x64': { binary: '../../evil.exe', binarySha256: 'a'.repeat(64) } } });
  assert.equal(resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'win32', arch: 'x64', manifestPath: escaping }), null);
});

test('the committed manifest resolves for every installer target and only those', () => {
  const targets = Object.keys(committed.targets).sort();
  assert.deepEqual(targets, ['darwin-arm64', 'darwin-x64', 'linux-x64', 'win32-x64']);
  assert.equal(resolveBundledRclone({ isPackaged: true, resourcesPath: 'res', platform: 'win32', arch: 'arm64' }), null);
});

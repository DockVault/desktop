'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { withEphemeralConfig, sweepStaleConfigs, formatSftpRemote, PREFIX, SUFFIX } = require('../src/daemon/ephemeral-config');

function tmpRun() { return path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'dv-ec-')), 'rclone'); }

test('writes a 0600 config the callback can read, then unlinks it after a successful run', async () => {
  const runDir = tmpRun();
  let seenPath = null; let seenContents = null;
  const ret = await withEphemeralConfig(runDir, '[t]\ntype = sftp\n', async (p) => {
    seenPath = p; seenContents = fs.readFileSync(p, 'utf8');
    if (process.platform !== 'win32') assert.strictEqual(fs.statSync(p).mode & 0o777, 0o600, '0600 while live');
    return 'result';
  });
  assert.strictEqual(ret, 'result');
  assert.match(seenContents, /type = sftp/);
  assert.ok(!fs.existsSync(seenPath), 'the ephemeral config is removed after the run');
  fs.rmSync(path.dirname(runDir), { recursive: true, force: true });
});

test('unlinks the config even when the run throws (finally)', async () => {
  const runDir = tmpRun();
  let seenPath = null;
  await assert.rejects(() => withEphemeralConfig(runDir, 'x', async (p) => { seenPath = p; throw new Error('run failed'); }), /run failed/);
  assert.ok(seenPath && !fs.existsSync(seenPath), 'removed despite the failure');
  fs.rmSync(path.dirname(runDir), { recursive: true, force: true });
});

test('O_EXCL fails closed on a pre-planted path — never follows/overwrites it (anti-TOCTOU)', async () => {
  const runDir = tmpRun();
  fs.mkdirSync(runDir, { recursive: true });
  const fixedName = PREFIX + 'deadbeefdeadbeef' + SUFFIX;
  fs.writeFileSync(path.join(runDir, fixedName), 'PRE-PLANTED');
  let ran = false;
  await assert.rejects(
    () => withEphemeralConfig(runDir, 'new', async () => { ran = true; }, { nameFn: () => fixedName }),
    /EEXIST/,
    'creating over an existing path throws',
  );
  assert.ok(!ran, 'the run never executes against a pre-planted file');
  assert.strictEqual(fs.readFileSync(path.join(runDir, fixedName), 'utf8'), 'PRE-PLANTED', 'the pre-planted file is untouched');
  fs.rmSync(path.dirname(runDir), { recursive: true, force: true });
});

test('sweepStaleConfigs removes orphaned ephemeral configs and leaves unrelated files', () => {
  const runDir = tmpRun();
  fs.mkdirSync(runDir, { recursive: true });
  fs.writeFileSync(path.join(runDir, PREFIX + 'aaaa' + SUFFIX), '1');
  fs.writeFileSync(path.join(runDir, PREFIX + 'bbbb' + SUFFIX), '2');
  fs.writeFileSync(path.join(runDir, 'rc.sock'), 'keep');
  const removed = sweepStaleConfigs(runDir);
  assert.strictEqual(removed, 2, 'both orphaned configs swept');
  assert.ok(!fs.existsSync(path.join(runDir, PREFIX + 'aaaa' + SUFFIX)));
  assert.ok(fs.existsSync(path.join(runDir, 'rc.sock')), 'unrelated files are left alone');
  fs.rmSync(path.dirname(runDir), { recursive: true, force: true });
});

test('sweepStaleConfigs on an absent dir is a no-op', () => {
  assert.strictEqual(sweepStaleConfigs(path.join(os.tmpdir(), 'dv-ec-absent-' + Date.now())), 0);
});

test('formatSftpRemote emits only the connection params + obscured cred + pinned host key', () => {
  const cfg = formatSftpRemote('vault', {
    host: 'sync.example', port: 2222, user: 'tc_abc', obscuredPass: 'OBSCURED_xyz', hostKeys: 'ssh-ed25519 AAAAC3Nz...',
  });
  assert.match(cfg, /^\[vault\]\n/);
  assert.match(cfg, /type = sftp\n/);
  assert.match(cfg, /host = sync\.example\n/);
  assert.match(cfg, /port = 2222\n/);
  assert.match(cfg, /user = tc_abc\n/);
  assert.match(cfg, /pass = OBSCURED_xyz\n/);
  assert.match(cfg, /host_keys = ssh-ed25519 AAAAC3Nz\.\.\.\n/);
  // Field-contents discipline: no key/token fields ever appear.
  assert.ok(!/(\bkey_pem\b|\bkey_file\b|token|dbk|passphrase|secret)/i.test(cfg), 'no key/token material');
  assert.strictEqual(cfg.trim().split('\n').length, 7, 'section header + exactly 6 fields');
});

test('formatSftpRemote rejects config injection (newline in a value) and a bad remote name', () => {
  assert.throws(() => formatSftpRemote('vault', { host: 'h\n[evil]\nx = y', port: 2222, user: 'u', obscuredPass: 'p', hostKeys: 'k' }), /invalid sftp config value for host/);
  assert.throws(() => formatSftpRemote('vault', { host: 'h', port: 2222, user: 'u\nrogue = 1', obscuredPass: 'p', hostKeys: 'k' }), /invalid sftp config value for user/);
  assert.throws(() => formatSftpRemote('bad name]', { host: 'h', port: 2222, user: 'u', obscuredPass: 'p', hostKeys: 'k' }), /invalid remote name/);
  assert.throws(() => formatSftpRemote('vault', { host: 'h', port: 2222, user: 'u', obscuredPass: '', hostKeys: 'k' }), /invalid sftp config value for pass/);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { RcloneRunner, FORBIDDEN_FLAGS } = require('../src/daemon/rclone-runner');

// A fake rclone child: emits the given stdout then exits with the given code on the next tick.
function fakeChild(stdout, code) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => {};
  setImmediate(() => { if (stdout) child.stdout.emit('data', Buffer.from(stdout)); child.emit('exit', code); });
  return child;
}
function makeRunner(stdout, code, rec = {}) {
  return new RcloneRunner({
    rcloneBin: '/pinned/rclone',
    spawnFn: (bin, args, opts) => { rec.bin = bin; rec.args = args; rec.opts = opts; return fakeChild(stdout, code); },
  });
}
// A runner past both gates (as after a successful ready()), for exercising run() behaviour.
function readyRunner(stdout, code, rec = {}) {
  const r = makeRunner(stdout, code, rec);
  r._binaryVerified = true; r._verified = true;
  return r;
}
// A fake child that also captures anything written to stdin.
function fakeChildWithStdin(stdout, code, rec) {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = { end: (d) => { rec.stdin = String(d); } };
  child.kill = () => {};
  setImmediate(() => { if (stdout) child.stdout.emit('data', Buffer.from(stdout)); child.emit('exit', code); });
  return child;
}

test('run() appends --config "" (no rclone.conf) and never starts a server', async () => {
  const rec = {};
  const r = readyRunner('', 0, rec);
  await r.run(['lsd', 'remote:']);
  const ci = rec.args.indexOf('--config');
  assert.ok(ci >= 0 && rec.args[ci + 1] === '', 'run appends --config ""');
  assert.ok(!rec.args.includes('rcd'), 'never launches the rc daemon');
});

test('run() BEFORE ready() fails closed — the checksum gate cannot be bypassed', async () => {
  const r = makeRunner('', 0); // fresh: not verified
  await assert.rejects(() => r.run(['version']), /not verified; call ready\(\) first/);
});

test('the spawn chokepoint refuses to run before the binary checksum is verified', async () => {
  const r = makeRunner('', 0);
  await assert.rejects(() => r.version(), /binary not verified/); // version() uses the chokepoint directly
});

test('run() REFUSES --force (exact and --force= form) so a local wipe cannot override rclone safety aborts', async () => {
  assert.ok(FORBIDDEN_FLAGS.includes('--force'));
  const r = readyRunner('', 0);
  await assert.rejects(() => r.run(['bisync', 'a', 'b', '--force']), /refusing to run rclone with --force/);
  await assert.rejects(() => r.run(['bisync', 'a', 'b', '--force=true']), /refusing to run rclone with --force=true/);
});

test('run() refuses rc-server flags and the rcd/serve subcommands (no listener, by construction)', async () => {
  const r = readyRunner('', 0);
  await assert.rejects(() => r.run(['rcd', '--rc-addr', 'x']), /refusing to run rclone with rcd/);
  await assert.rejects(() => r.run(['serve', 'http', '.']), /refusing to run rclone with serve/);
  await assert.rejects(() => r.run(['lsd', 'r:', '--rc-addr', 'unix://x']), /refusing to run rclone with --rc-addr/);
  await assert.rejects(() => r.run(['lsd', 'r:', '--rc']), /refusing to run rclone with --rc/);
  await assert.rejects(() => r.run(['lsd', 'r:', '--rc-no-auth']), /refusing to run rclone with --rc-no-auth/);
  await assert.rejects(() => r.run(['lsd', 'r:', '--rc-web-gui']), /refusing to run rclone with --rc-web-gui/);
});

test('run() uses an ephemeral --config path when given, else the empty (no-conf) form', async () => {
  const rec = {};
  const r = readyRunner('', 0, rec);
  await r.run(['lsd', 'vault:'], { config: '/run/dir/sync-abc.conf' });
  const ci = rec.args.indexOf('--config');
  assert.strictEqual(rec.args[ci + 1], '/run/dir/sync-abc.conf', 'the per-run config path is passed');
  const rec2 = {};
  const r2 = readyRunner('', 0, rec2);
  await r2.run(['version']);
  const ci2 = rec2.args.indexOf('--config');
  assert.strictEqual(rec2.args[ci2 + 1], '', 'no config path -> empty (no rclone.conf)');
});

test('run() resolves the child exit code + captured stdout', async () => {
  const r = readyRunner('hello\n', 0);
  const out = await r.run(['version']);
  assert.strictEqual(out.code, 0);
  assert.match(out.stdout, /hello/);
});

test('version() parses the rclone version string', async () => {
  const r = makeRunner('rclone v1.75.0\n- os/version: windows\n', 0);
  r._binaryVerified = true; // version() runs after the checksum gate inside ready()
  const v = await r.version();
  assert.strictEqual(v.version, '1.75.0');
});

test('verifyBinary() passes + marks verified on a matching SHA-256, and FAILS CLOSED on a mismatch', () => {
  const bytes = Buffer.from('pretend-rclone-binary');
  const good = crypto.createHash('sha256').update(bytes).digest('hex');
  const ok = new RcloneRunner({ rcloneBin: '/pinned/rclone', expectSha256: good, readFileFn: () => bytes });
  assert.strictEqual(ok.verifyBinary(), good.toLowerCase());
  assert.strictEqual(ok._binaryVerified, true);
  const bad = new RcloneRunner({ rcloneBin: '/pinned/rclone', expectSha256: 'deadbeef', readFileFn: () => bytes });
  assert.throws(() => bad.verifyBinary(), /checksum mismatch/);
  assert.strictEqual(bad._binaryVerified, false, 'a mismatch leaves the binary unverified');
});

test('obscure() feeds the plaintext on STDIN (never argv) and returns the obscured form', async () => {
  const rec = {};
  const r = new RcloneRunner({ rcloneBin: '/pinned/rclone', spawnFn: (bin, args) => { rec.args = args; return fakeChildWithStdin('OBSCURED_abc\n', 0, rec); } });
  r._binaryVerified = true; r._verified = true;
  const out = await r.obscure('secretpass123');
  assert.strictEqual(out, 'OBSCURED_abc', 'returns the trimmed obscured value');
  assert.strictEqual(rec.stdin, 'secretpass123', 'the plaintext is written to stdin');
  assert.ok(rec.args.includes('obscure') && rec.args.includes('-'), 'invokes `obscure -`');
  assert.ok(!rec.args.includes('secretpass123'), 'the plaintext is NEVER on argv');
});

test('ready() fails closed on a version mismatch, and on success enables run()', async () => {
  const bytes = Buffer.from('x');
  const sha = crypto.createHash('sha256').update(bytes).digest('hex');
  const rec = {};
  const bad = new RcloneRunner({
    rcloneBin: '/pinned/rclone', expectVersion: '1.75.0', expectSha256: sha,
    readFileFn: () => bytes, spawnFn: () => fakeChild('rclone v1.70.0\n', 0),
  });
  await assert.rejects(() => bad.ready(), /does not match the pinned 1\.75\.0/);

  const okr = new RcloneRunner({
    rcloneBin: '/pinned/rclone', expectVersion: '1.75.0', expectSha256: sha,
    readFileFn: () => bytes, spawnFn: (b, a) => { rec.args = a; return fakeChild('rclone v1.75.0\n', 0); },
  });
  const v = await okr.ready();
  assert.strictEqual(v.version, '1.75.0');
  assert.strictEqual(okr._verified, true, 'ready() success enables run()');
  await okr.run(['version']); // now permitted
});

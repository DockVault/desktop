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

test('the spawn chokepoint re-verifies the pinned binary AT spawn time and refuses a mismatch (checksum gate cannot be bypassed)', async () => {
  const bytes = Buffer.from('rclone-binary-bytes');
  const r = new RcloneRunner({ rcloneBin: '/pinned/rclone', expectSha256: 'deadbeef', readFileFn: () => bytes, spawnFn: () => fakeChild('', 0) });
  // version() goes through the single spawn chokepoint, which re-hashes the pinned binary FIRST — a mismatch is
  // refused with the typed checksum-mismatch and never spawned, even without a prior ready() (per-spawn gate).
  await assert.rejects(() => r.version(), (e) => e && e.subReason === 'checksum-mismatch' && /checksum mismatch/.test(e.message));
});

test('run() REFUSES --force (exact and --force= form) so a local wipe cannot override rclone safety aborts', async () => {
  assert.ok(FORBIDDEN_FLAGS.includes('--force'));
  const r = readyRunner('', 0);
  await assert.rejects(() => r.run(['bisync', 'a', 'b', '--force']), /refusing to run rclone with --force/);
  await assert.rejects(() => r.run(['bisync', 'a', 'b', '--force=true']), /refusing to run rclone with --force=true/);
});

test('run() REFUSES --ignore-errors (exact and = form) so an errored run cannot pass as a clean completion', async () => {
  assert.ok(FORBIDDEN_FLAGS.includes('--ignore-errors'));
  const r = readyRunner('', 0);
  await assert.rejects(() => r.run(['bisync', 'a', 'b', '--ignore-errors']), /refusing to run rclone with --ignore-errors/);
  await assert.rejects(() => r.run(['bisync', 'a', 'b', '--ignore-errors=true']), /refusing to run rclone with --ignore-errors=true/);
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

// ---- TOCTOU pin rail: per-spawn re-hash with a 60s matching-hash TTL, atomic hash-then-spawn, sticky fail-closed ----
function toctouRunner({ ttl = 60000 } = {}) {
  const GOOD = Buffer.from('good-rclone-binary');
  const good = crypto.createHash('sha256').update(GOOD).digest('hex');
  const state = { bytes: GOOD, now: 0, reads: 0, spawns: 0 };
  const r = new RcloneRunner({
    rcloneBin: '/pinned/rclone', expectSha256: good,
    readFileFn: () => { state.reads += 1; if (state.bytes == null) { const e = new Error('ENOENT: no such file'); e.code = 'ENOENT'; throw e; } return state.bytes; },
    spawnFn: () => { state.spawns += 1; return fakeChild('rclone v1.0.0\n', 0); },
    now: () => state.now, hashTtlMs: ttl,
  });
  return { r, state, GOOD };
}

test('TOCTOU: a same-path binary swap between spawns is caught on the next spawn (TTL=0) — refuse + sticky verified=false', async () => {
  const { r, state } = toctouRunner({ ttl: 0 });
  await r.version();                 // hashes the good binary, verifies, spawns
  assert.strictEqual(r.isVerified(), true);
  state.bytes = Buffer.from('SWAPPED-rclone'); // same path, different bytes
  await assert.rejects(() => r.version(), (e) => e && e.subReason === 'checksum-mismatch');
  assert.strictEqual(r.isVerified(), false, 'sticky fail-closed: verified flipped false — every later spawn refuses');
});

test('TOCTOU: restoring the pinned binary recovers — the next spawn re-hashes and proceeds', async () => {
  const { r, state, GOOD } = toctouRunner({ ttl: 0 });
  await r.version();
  state.bytes = Buffer.from('SWAPPED');
  await assert.rejects(() => r.version(), (e) => e && e.subReason === 'checksum-mismatch');
  assert.strictEqual(r.isVerified(), false);
  state.bytes = GOOD;               // restored
  await r.version();                // re-hashes -> matches -> recovers
  assert.strictEqual(r.isVerified(), true, 'a fresh MATCHING hash recovers verified');
});

test('TOCTOU: an unreadable binary at re-check refuses (never spawns) — checksum-mismatch, verified=false', async () => {
  const { r, state } = toctouRunner({ ttl: 0 });
  await r.version();
  const spawnsBefore = state.spawns;
  state.bytes = null;               // readFileFn throws ENOENT (unreadable at re-check)
  await assert.rejects(() => r.version(), (e) => e && e.subReason === 'checksum-mismatch');
  assert.strictEqual(r.isVerified(), false);
  assert.strictEqual(state.spawns, spawnsBefore, 'no spawn on an unreadable re-check');
});

test('TOCTOU: within the TTL, a 2nd spawn does NOT re-hash (uses the cached matching hash)', async () => {
  const { r, state } = toctouRunner({ ttl: 60000 });
  state.now = 1000;
  await r.version();
  const readsAfterFirst = state.reads;
  state.now = 1000 + 30000;         // 30s later, within the 60s TTL
  await r.version();
  assert.strictEqual(state.reads, readsAfterFirst, 'no 2nd hash within the TTL window');
});

test('TOCTOU: the re-hash is TTL-driven, never metadata-gated — an expired TTL re-hashes even with byte-identical (unchanged size/mtime) contents', async () => {
  const { r, state } = toctouRunner({ ttl: 60000 });
  state.now = 0;
  await r.version();
  const readsAfterFirst = state.reads;
  state.now = 61000;                // TTL expired; the bytes (hence any size/mtime) are unchanged
  await r.version();
  assert.strictEqual(state.reads, readsAfterFirst + 1, 'a re-hash happens on TTL expiry regardless of unchanged metadata (no stat can skip a hash)');
});

test('spawn errors are typed by e.code: ENOENT -> binary-missing (never an AV accusation), any other code -> spawn-failed', async () => {
  const bytes = Buffer.from('good');
  const good = crypto.createHash('sha256').update(bytes).digest('hex');
  const mk = (spawnErr) => new RcloneRunner({ rcloneBin: '/x', expectSha256: good, readFileFn: () => bytes, spawnFn: () => { throw spawnErr; } });
  await assert.rejects(() => mk(Object.assign(new Error('spawn ENOENT'), { code: 'ENOENT' })).version(), (e) => e && e.subReason === 'binary-missing');
  await assert.rejects(() => mk(Object.assign(new Error('spawn EACCES'), { code: 'EACCES' })).version(), (e) => e && e.subReason === 'spawn-failed');
  // A win32 UNKNOWN errno (a SmartScreen/AV block) is NOT ENOENT -> spawn-failed (the AV-detail copy), never prepare-failed.
  await assert.rejects(() => mk(Object.assign(new Error('spawn UNKNOWN'), { code: 'UNKNOWN', errno: -4094 })).version(), (e) => e && e.subReason === 'spawn-failed');
});

test('a version mismatch is typed version-mismatch and carries the daemon-detected installed + the pinned versions', async () => {
  const bytes = Buffer.from('vbytes');
  const sha = crypto.createHash('sha256').update(bytes).digest('hex');
  const r = new RcloneRunner({ rcloneBin: '/pinned/rclone', expectVersion: '1.75.0', expectSha256: sha, readFileFn: () => bytes, spawnFn: () => fakeChild('rclone v1.70.0\n', 0) });
  await assert.rejects(() => r.ready(), (e) => e && e.subReason === 'version-mismatch' && e.installed === '1.70.0' && e.pinned === '1.75.0');
});

// When a version is pinned, ready() owns _verified — a version mismatch flips it false. A later per-spawn SHA
// re-hash (which matches, the bytes are the pinned ones) must NOT quietly re-mark the runner verified: the
// binary is authentic but the WRONG version, so it stays refused until ready() re-confirms the version. Guards
// verifyBinary's `if (!this.expectVersion) this._verified = true` — without that guard a re-hash flips it back.
test('a version mismatch is not re-cleared by a later matching SHA re-hash — verified stays false while a version is pinned', async () => {
  const bytes = Buffer.from('vbytes');
  const sha = crypto.createHash('sha256').update(bytes).digest('hex');
  const r = new RcloneRunner({ rcloneBin: '/pinned/rclone', expectVersion: '1.75.0', expectSha256: sha, hashTtlMs: 0, readFileFn: () => bytes, spawnFn: () => fakeChild('rclone v1.70.0\n', 0) });
  await assert.rejects(() => r.ready(), (e) => e && e.subReason === 'version-mismatch');
  assert.strictEqual(r.isVerified(), false, 'the version mismatch flipped verified false');
  r.recheck(); // a fresh SHA re-hash with TTL=0 — the bytes match the pin, so verifyBinary succeeds...
  assert.strictEqual(r.isVerified(), false, '...but a matching SHA must not silently re-verify a version-mismatched runner');
});

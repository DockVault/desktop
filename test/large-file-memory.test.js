'use strict';

/*
 * Large-file memory discipline: the daemon must never grow with the size of a file (or the length of a run).
 *
 *   - the sync helper's stdout is retained BOUNDED (a cap + a truncation flag), decoded correctly, and the
 *     line relay retains nothing;
 *   - the stderr stats parser's kept-lines buffer and partial-line buffer are bounded too;
 *   - a heap measurement fails on an unbounded buffer: streaming far more output than the cap through the
 *     runner leaves the heap essentially where it was;
 *   - every rclone operation against the remote pins ONE SSH connection and single-stream transfers, so a
 *     single-use credential is never presented twice (rclone's multi-thread download opened extra connections
 *     and failed at the door for every file at or above its cutoff);
 *   - the zero-loss resync REFUSES to act on a truncated server list or compare report (fail-closed).
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { EventEmitter } = require('node:events');
const { RcloneRunner, BoundedOutput, DEFAULT_MAX_STDOUT_BYTES } = require('../src/daemon/rclone-runner');
const { StatsStderrParser, MAX_KEPT_STDERR_BYTES } = require('../src/daemon/stats-parse');
const { buildBisyncArgs, SINGLE_CONNECTION_ARGS, BISYNC_MAX_STDOUT_BYTES } = require('../src/daemon/sync-engine');
const { zeroLossResync } = require('../src/daemon/resync-zeroloss');

function controllableChild() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.kill = () => { child.killed = true; };
  return child;
}
function runnerWith(child) {
  const r = new RcloneRunner({ rcloneBin: '/pinned/rclone', spawnFn: () => child });
  r._binaryVerified = true; r._verified = true;
  return r;
}
const MiB = 1024 * 1024;

// ---- BoundedOutput --------------------------------------------------------------------------------------

test('BoundedOutput: retains at most the cap while the child keeps printing, flags the truncation, relays every complete line without retaining it', () => {
  const lines = [];
  const b = new BoundedOutput(64 * 1024, (l) => lines.push(l));
  const chunk = Buffer.from('some/vault/path/file-000001.jpg\n'.repeat(1000)); // 32 KB per chunk
  let peak = 0;
  for (let i = 0; i < 2000; i++) { b.push(chunk); peak = Math.max(peak, b.retainedBytes()); } // 64 MB streamed
  assert.strictEqual(peak, 64 * 1024, 'never more than the cap is held');
  const out = b.end();
  assert.strictEqual(out.truncated, true);
  assert.ok(out.text.length <= 64 * 1024);
  assert.strictEqual(lines.length, 2000 * 1000, 'every line was relayed exactly once');
});

test('BoundedOutput: output under the cap comes back whole and unflagged; a multi-byte character split across chunks decodes intact', () => {
  const b = new BoundedOutput(DEFAULT_MAX_STDOUT_BYTES);
  const name = 'Φωτογραφίες/été.jpg\n'; // multi-byte
  const bytes = Buffer.from(name);
  b.push(bytes.subarray(0, 3)); b.push(bytes.subarray(3, 4)); b.push(bytes.subarray(4)); // split mid-character
  const out = b.end();
  assert.strictEqual(out.text, name, 'decoded once at the end, never per chunk');
  assert.strictEqual(out.truncated, false);
});

test('BoundedOutput: the relay assembles lines across chunk boundaries and drops an unterminated line that outgrows any real line', () => {
  const lines = [];
  const b = new BoundedOutput(8 * MiB, (l) => lines.push(l)); // retention cap well above what is pushed: only the relay is under test
  b.push(Buffer.from('first ha')); b.push(Buffer.from('lf\r\nsecond\n'));
  assert.deepStrictEqual(lines, ['first half', 'second']);
  for (let i = 0; i < 3; i++) b.push(Buffer.alloc(MiB, 0x61)); // 3 MB with no newline
  b.push(Buffer.from('tail-of-the-dropped-line\nafter\n'));
  assert.deepStrictEqual(lines, ['first half', 'second', 'after'], 'no fragment of the dropped line — not its buffered part, not its remainder — was handed out');
  assert.strictEqual(b.end().truncated, false, 'the relay drop says nothing about the RETAINED stdout, which was complete');
});

// ---- the runner ---------------------------------------------------------------------------------------

test('runner: a child that prints far more than the cap leaves the daemon heap flat (fails on an unbounded buffer) and returns stdoutTruncated', async () => {
  const child = controllableChild();
  const r = runnerWith(child);
  const CAP = 256 * 1024;
  const p = r.run(['lsf'], { timeoutMs: 60000, maxStdoutBytes: CAP });
  if (global.gc) global.gc();
  const before = process.memoryUsage().heapUsed;
  const chunk = Buffer.alloc(MiB, 0x41); // 1 MB of 'A'
  const TOTAL_MB = 200;
  for (let i = 0; i < TOTAL_MB; i++) child.stdout.emit('data', chunk); // 200 MB streamed through stdout
  child.emit('exit', 0);
  const res = await p;
  if (global.gc) global.gc();
  const grewBy = process.memoryUsage().heapUsed - before;
  // An accumulating `stdout += chunk` would have grown the heap by ~200 MB here (+ the string copies).
  assert.ok(grewBy < 32 * MiB, `heap grew by ${Math.round(grewBy / MiB)} MB while streaming ${TOTAL_MB} MB of stdout`);
  assert.strictEqual(res.stdoutTruncated, true);
  assert.ok(Buffer.byteLength(res.stdout) <= CAP, 'no more than the cap came back');
  assert.strictEqual(res.code, 0);
});

test('runner: a run whose stdout stays under the cap is returned whole and unflagged (the file-list commands keep working)', async () => {
  const child = controllableChild();
  const r = runnerWith(child);
  const p = r.run(['lsf', '-R', '--files-only', 'vault:V'], { timeoutMs: 60000 });
  const list = Array.from({ length: 50000 }, (_, i) => `dir${i % 97}/photo-${i}.jpg`).join('\n') + '\n'; // ~1 MB
  const buf = Buffer.from(list);
  for (let off = 0; off < buf.length; off += 65536) child.stdout.emit('data', buf.subarray(off, Math.min(off + 65536, buf.length)));
  child.emit('exit', 0);
  const res = await p;
  assert.strictEqual(res.stdoutTruncated, false);
  assert.strictEqual(res.stdout, list);
});

test('runner: the default stdout cap is a fixed number, and the bisync run asks for a much smaller one', () => {
  assert.strictEqual(DEFAULT_MAX_STDOUT_BYTES, 16 * MiB);
  assert.strictEqual(BISYNC_MAX_STDOUT_BYTES, 256 * 1024);
});

// ---- the stderr parser --------------------------------------------------------------------------------

test('stats parser: kept non-stats stderr is bounded (first error kept, final verdict kept, middle dropped and flagged)', () => {
  const p = new StatsStderrParser();
  p.push('2026/01/01 00:00:00 ERROR : first-thing-that-went-wrong\n');
  const noise = '2026/01/01 00:00:01 INFO  : some/file.jpg: Copied (new)\n';
  for (let i = 0; i < 200000; i++) p.push(noise); // ~11 MB of legitimate non-stats lines
  p.push('2026/01/01 00:10:00 NOTICE: Bisync aborted. Must run --resync to recover.\n');
  p.end();
  const kept = p.stderr();
  assert.ok(kept.length <= MAX_KEPT_STDERR_BYTES + 64, `kept ${kept.length} bytes`);
  assert.ok(kept.includes('first-thing-that-went-wrong'), 'the first real error survives at the head');
  assert.ok(kept.includes('Bisync aborted'), 'the final verdict survives at the tail');
  assert.strictEqual(p.truncated(), true);
});

test('stats parser: a partial line that outgrows any real line is dropped, never assembled without bound and never exposed', () => {
  const p = new StatsStderrParser();
  for (let i = 0; i < 3; i++) p.push('x'.repeat(MiB)); // 3 MB, no newline
  assert.ok(p._buf.length <= MiB, 'the partial-line buffer stays bounded');
  p.push('rest-of-dropped-line\nERROR : real\n');
  p.end();
  assert.ok(p.stderr().includes('ERROR : real'));
  assert.ok(!p.stderr().includes('xxxxxxxxxx') && !p.stderr().includes('rest-of-dropped-line'), 'no part of the dropped line reaches the kept output');
  assert.strictEqual(p.truncated(), true);
});

test('stats parser: once the head is full, later lines go to the tail — the kept text stays in arrival order', () => {
  const p = new StatsStderrParser();
  const half = MAX_KEPT_STDERR_BYTES / 2;
  const big = 'E ' + 'y'.repeat(half - 40) + '\n';   // nearly fills the head
  p.push(big);
  p.push('E ' + 'z'.repeat(200) + '\n');             // does not fit the head -> tail
  p.push('E short\n');                               // would fit the head, but the head is sealed
  p.end();
  const kept = p.stderr();
  assert.ok(kept.indexOf('zzzz') < kept.indexOf('E short'), 'the shorter later line is not hoisted ahead of the earlier one');
});

test('stats parser: a short, ordinary run is kept whole and unflagged', () => {
  const p = new StatsStderrParser();
  p.push('2026/01/01 00:00:00 ERROR : a\n2026/01/01 00:00:01 NOTICE: b\n');
  p.end();
  assert.strictEqual(p.stderr(), '2026/01/01 00:00:00 ERROR : a\n2026/01/01 00:00:01 NOTICE: b\n');
  assert.strictEqual(p.truncated(), false);
});

// ---- one connection, single stream ---------------------------------------------------------------------

test('every rclone op against the remote pins ONE SSH connection and single-stream transfers (a single-use credential is never presented twice)', () => {
  assert.deepStrictEqual(SINGLE_CONNECTION_ARGS, ['--sftp-connections', '1', '--sftp-idle-timeout', '0', '--multi-thread-streams', '0', '--sftp-shell-type', 'none', '--sftp-disable-hashcheck']);
  const args = buildBisyncArgs({ local: '/l', remote: 'vault:V', workdir: '/w' });
  const has = (flag, value) => { const i = args.indexOf(flag); return i >= 0 && args[i + 1] === value; };
  assert.ok(has('--sftp-connections', '1'), 'bisync: one SSH connection');
  assert.ok(has('--multi-thread-streams', '0'), 'bisync: no multi-thread download (it opens one extra connection per stream)');
  assert.ok(has('--sftp-shell-type', 'none') && args.includes('--sftp-disable-hashcheck'), 'bisync: no shell/hash probes (refused channels + a config write-back on every process)');
  assert.ok(has('--sftp-idle-timeout', '0'), 'bisync: the one connection is never reaped for idling (a re-dial would present the spent credential)');
  assert.ok(has('--transfers', '1') && has('--checkers', '1'), 'the one connection is never contended by parallel transfers/checks');
});

test('the zero-loss resync launches every remote step (lsf / check / copyto) with the same one-connection, single-stream discipline', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-zeroloss-'));
  const { openStateDb } = require('../src/main/state-db');
  const local = path.join(dir, 'data'); fs.mkdirSync(local, { recursive: true });
  fs.writeFileSync(path.join(local, 'a.txt'), 'LOCAL');
  const db = openStateDb(path.join(dir, 'db'), nodeCrypto.randomBytes(32));
  const launched = [];
  const runner = { run: async (args) => {
    launched.push(args);
    if (args[0] === 'lsf') return { code: 0, stdout: 'a.txt\nsrvonly.txt\n', stdoutTruncated: false };
    if (args[0] === 'check') return { code: 1, stdout: '* a.txt\n', stdoutTruncated: false };
    return { code: 0, stdout: '', stderr: '', stdoutTruncated: false };
  } };
  await zeroLossResync({ runner, db, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => Date.now(), timeoutMs: 5000 });
  const remoteOps = launched.filter((a) => ['lsf', 'check', 'copyto', 'bisync'].includes(a[0]));
  assert.ok(remoteOps.length >= 4, 'lsf, check, at least one copyto, and the bisync all ran');
  for (const a of remoteOps) {
    for (const f of SINGLE_CONNECTION_ARGS) assert.ok(a.includes(f), `${a[0]} carries ${f}`);
    const has = (flag, value) => { const i = a.indexOf(flag); return i >= 0 && a[i + 1] === value; };
    assert.ok(has('--transfers', '1') && has('--checkers', '1'), `${a[0]} runs one transfer / one checker on the one connection`);
  }
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

// ---- fail-closed on truncated lists -------------------------------------------------------------------

test('zero-loss resync: a TRUNCATED server list is refused outright — nothing is copied, no resync runs', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-zeroloss-'));
  const { openStateDb } = require('../src/main/state-db');
  const local = path.join(dir, 'data'); fs.mkdirSync(local, { recursive: true });
  fs.writeFileSync(path.join(local, 'a.txt'), 'LOCAL');
  const db = openStateDb(path.join(dir, 'db'), nodeCrypto.randomBytes(32));
  const launched = [];
  const runner = { run: async (args) => {
    launched.push(args[0]);
    if (args[0] === 'lsf') return { code: 0, stdout: 'a.txt\n', stdoutTruncated: true }; // the list was cut short
    return { code: 0, stdout: '', stderr: '' };
  } };
  await assert.rejects(
    () => zeroLossResync({ runner, db, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => Date.now(), timeoutMs: 5000 }),
    /too large to hold whole/);
  assert.deepStrictEqual(launched, ['lsf'], 'no check, no copyto, no bisync after a truncated list');
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

test('zero-loss resync: a TRUNCATED compare report is refused — a partial compare is no compare', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-zeroloss-'));
  const { openStateDb } = require('../src/main/state-db');
  const local = path.join(dir, 'data'); fs.mkdirSync(local, { recursive: true });
  fs.writeFileSync(path.join(local, 'a.txt'), 'LOCAL');
  const db = openStateDb(path.join(dir, 'db'), nodeCrypto.randomBytes(32));
  const launched = [];
  const runner = { run: async (args) => {
    launched.push(args[0]);
    if (args[0] === 'lsf') return { code: 0, stdout: 'a.txt\n', stdoutTruncated: false };
    if (args[0] === 'check') return { code: 0, stdout: '= a.txt\n', stdoutTruncated: true }; // looks complete, but was cut
    return { code: 0, stdout: '', stderr: '' };
  } };
  await assert.rejects(
    () => zeroLossResync({ runner, db, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => Date.now(), timeoutMs: 5000 }),
    /could not compare every shared file/);
  assert.deepStrictEqual(launched, ['lsf', 'check'], 'nothing ran after the truncated compare');
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

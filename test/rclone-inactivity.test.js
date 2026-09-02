'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('node:events');
const { RcloneRunner } = require('../src/daemon/rclone-runner');
const { buildBisyncArgs, SYNC_STATS_ARGS } = require('../src/daemon/sync-engine');

// A fake child the test drives by hand: it does NOT auto-emit or auto-exit.
function controllableChild() {
  const child = new EventEmitter();
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.killed = false;
  child.kill = () => { child.killed = true; };
  return child;
}
function runnerWith(child) {
  const r = new RcloneRunner({ rcloneBin: '/pinned/rclone', spawnFn: () => child });
  r._binaryVerified = true; r._verified = true; // past both gates, as after a real ready()
  return r;
}
// The runner's timeout timers are unref'd (they must never keep the app alive), so in a test with a fake
// child there is no other handle on the loop — hold a ref'd keepalive across the await so they still fire.
async function withKeepalive(fn) {
  const ka = setInterval(() => {}, 5);
  try { return await fn(); } finally { clearInterval(ka); }
}

test('the bisync argv carries the fixed stats flags that feed the inactivity timer + the progress glance', () => {
  const args = buildBisyncArgs({ local: '/l', remote: 'vault:V', workdir: '/w' });
  // 5s: the stats period doubles as the "Syncing…" visibility threshold (a UX decision), decoupled from the
  // 120s inactivity window. A shorter period only widens the idle margin.
  assert.deepStrictEqual(SYNC_STATS_ARGS, ['--stats', '5s', '--stats-log-level', 'NOTICE']);
  for (const f of SYNC_STATS_ARGS) assert.ok(args.includes(f), `bisync args include ${f}`);
});

test('inactivity: a run that keeps emitting stats (on stderr) is NOT killed — it survives to completion', async () => {
  await withKeepalive(async () => {
    const child = controllableChild();
    const r = runnerWith(child);
    const p = r.run(['bisync'], { inactivityMs: 80, hardCeilingMs: 100000 });
    for (let i = 1; i <= 4; i++) setTimeout(() => child.stderr.emit('data', Buffer.from('Transferred: 1/2\n')), i * 30);
    setTimeout(() => child.emit('exit', 0), 150);
    const res = await p;
    assert.strictEqual(res.code, 0, 'a progressing run completes, never inactivity-killed');
    assert.strictEqual(child.killed, false);
  });
});

test('inactivity: a silent (hung) run is killed after the window and rejects via the honest error path', async () => {
  await withKeepalive(async () => {
    const child = controllableChild();
    const r = runnerWith(child);
    await assert.rejects(() => r.run(['bisync'], { inactivityMs: 50, hardCeilingMs: 100000 }), /inactivity timeout/);
    assert.strictEqual(child.killed, true, 'the hung child was killed');
  });
});

test('inactivity: stderr stats/path lines are parsed-and-dropped (never onLine, never in returned stderr); counts surface as {files,bytes}; real errors kept', async () => {
  await withKeepalive(async () => {
    const child = controllableChild();
    const r = runnerWith(child);
    const lines = [];
    const progress = [];
    const p = r.run(['bisync'], { inactivityMs: 200, hardCeilingMs: 100000, onLine: (l) => lines.push(l), onProgress: (c) => progress.push(c) });
    // A path-bearing per-file stats line (the leak shape) — must be DROPPED, never kept or relayed.
    setTimeout(() => child.stderr.emit('data', Buffer.from(' *   /Users/me/secret/path.txt: 50% /1Mi, 1/s, 1s\n')), 10);
    // A real aggregate count — surfaces as {files} via onProgress (numbers only).
    setTimeout(() => child.stderr.emit('data', Buffer.from('Transferred: 3 / 8, 38%\n')), 20);
    // A genuine (non-stats) error line — kept for the typed-outcome classifier.
    setTimeout(() => child.stderr.emit('data', Buffer.from('2026/09/03 02:00:00 ERROR : a real problem\n')), 30);
    setTimeout(() => child.stdout.emit('data', Buffer.from('a-stdout-line\n')), 40);
    setTimeout(() => child.emit('exit', 0), 60);
    const res = await p;
    assert.deepStrictEqual(lines, ['a-stdout-line'], 'only stdout reaches onLine; no stderr line ever does');
    assert.doesNotMatch(res.stderr, /secret\/path/, 'the path-bearing stats line is DROPPED — never in the returned stderr');
    assert.match(res.stderr, /a real problem/, 'a genuine non-stats error line is kept for classification');
    assert.ok(progress.some((c) => c.files === 3), 'the aggregate file count surfaces via onProgress (numbers only)');
  });
});

test('utility path: without an inactivity window, the fixed timeout still fires (fail fast, not after 2 min)', async () => {
  await withKeepalive(async () => {
    const child = controllableChild();
    const r = runnerWith(child);
    await assert.rejects(() => r.run(['version'], { timeoutMs: 40 }), /rclone timeout/);
    assert.strictEqual(child.killed, true);
  });
});

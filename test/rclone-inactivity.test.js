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

test('the bisync argv carries the fixed stats flags that feed the inactivity timer', () => {
  const args = buildBisyncArgs({ local: '/l', remote: 'vault:V', workdir: '/w' });
  assert.deepStrictEqual(SYNC_STATS_ARGS, ['--stats', '30s', '--stats-log-level', 'NOTICE']);
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

test('inactivity: stderr (stats, path-bearing) resets the timer but is NEVER relayed to onLine; stdout is', async () => {
  await withKeepalive(async () => {
    const child = controllableChild();
    const r = runnerWith(child);
    const lines = [];
    const p = r.run(['bisync'], { inactivityMs: 200, hardCeilingMs: 100000, onLine: (l) => lines.push(l) });
    setTimeout(() => child.stderr.emit('data', Buffer.from('Transferred: /Users/me/secret/path.txt\n')), 10);
    setTimeout(() => child.stdout.emit('data', Buffer.from('a-stdout-line\n')), 20);
    setTimeout(() => child.emit('exit', 0), 40);
    const res = await p;
    assert.deepStrictEqual(lines, ['a-stdout-line'], 'only stdout reaches onLine; the stderr stats/path line never did');
    assert.match(res.stderr, /secret\/path/, 'stderr is still accumulated for the typed-outcome classification');
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

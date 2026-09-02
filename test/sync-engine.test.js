'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { buildBisyncArgs, runBisync, bisyncWorkdir, MAX_DELETE_PERCENT } = require('../src/daemon/sync-engine');
const { openStateDb, getRunState } = require('../src/main/state-db');

function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-syn-')); }
// A fake runner standing in for a ready RcloneRunner: records the argv + options and returns a canned exit.
function fakeRunner(canned, rec = {}) {
  return { run: async (args, opts) => { rec.args = args; rec.opts = opts; return { code: canned.code, stdout: canned.stdout || '', stderr: canned.stderr || '' }; } };
}

test('buildBisyncArgs bakes in the safety controls and never emits --force/--ignore-errors', () => {
  const a = buildBisyncArgs({ local: '/data', remote: 'vault:folder', workdir: '/wd' });
  assert.strictEqual(a[0], 'bisync');
  assert.deepStrictEqual(a.slice(1, 3), ['/data', 'vault:folder'], 'path1 then path2');
  const wi = a.indexOf('--workdir');
  assert.ok(wi >= 0 && a[wi + 1] === '/wd', 'the short controlled workdir is passed');
  const mi = a.indexOf('--max-delete');
  assert.ok(mi >= 0 && a[mi + 1] === String(MAX_DELETE_PERCENT), 'the delete guard is pinned explicitly');
  assert.ok(!a.includes('--force'), 'never --force');
  assert.ok(!a.includes('--ignore-errors'), 'never --ignore-errors');
  assert.ok(!a.includes('--resync'), 'no resync unless asked');
  const ti = a.indexOf('--transfers');
  const ci = a.indexOf('--checkers');
  assert.ok(ti >= 0 && a[ti + 1] === '1', 'transfers pinned to a single connection');
  assert.ok(ci >= 0 && a[ci + 1] === '1', 'checkers pinned to a single connection');
  const ri = a.indexOf('--retries');
  assert.ok(ri >= 0 && a[ri + 1] === '1', 'the run is attempted once — no re-auth with a spent single-use credential, no re-attempt of a safety abort');
  const ki = a.indexOf('--compare');
  assert.ok(ki >= 0 && a[ki + 1] === 'size', 'change-detection is by size — this server cannot preserve a client mtime, so a modtime compare would spuriously report every file changed');
});

test('buildBisyncArgs adds --resync only when requested; the delete guard is fixed + non-defeatable', () => {
  assert.ok(buildBisyncArgs({ local: 'l', remote: 'r:', workdir: 'w', resync: true }).includes('--resync'));
  assert.throws(() => buildBisyncArgs({ local: '', remote: 'r:', workdir: 'w' }), /needs local/);
  // A caller cannot weaken or disable the guard: there is no override, and any stray field is ignored —
  // the fixed constant always reaches rclone (never 100, i.e. "abort only above 100%" = failsafe off).
  const a = buildBisyncArgs({ local: 'l', remote: 'r:', workdir: 'w', maxDeletePercent: 100 });
  const mi = a.indexOf('--max-delete');
  assert.strictEqual(a[mi + 1], String(MAX_DELETE_PERCENT), 'the fixed guard is emitted regardless of any override attempt');
  assert.notStrictEqual(a[mi + 1], '100', 'the guard-disabling value can never be produced');
});

test('bisyncWorkdir is short, stable per vault, and distinct across vaults', () => {
  const a = bisyncWorkdir('/run', 'vault-uuid-aaaa');
  const b = bisyncWorkdir('/run', 'vault-uuid-aaaa');
  const c = bisyncWorkdir('/run', 'vault-uuid-bbbb');
  assert.strictEqual(a, b, 'same vault -> same workdir across runs (bisync needs the prior listing)');
  assert.notStrictEqual(a, c, 'different vaults -> different workdirs');
  assert.match(path.basename(a), /^[0-9a-f]{16}$/, 'a short 16-hex leaf, not the raw (possibly long) vault id');
});

test('runBisync is FAIL-CLOSED on a first run: a normal bisync is refused until an explicit resync', async () => {
  const dir = tmp();
  const db = openStateDb(dir, nodeCrypto.randomBytes(32));
  const rec = {};
  const runner = fakeRunner({ code: 0 }, rec);
  const r = await runBisync({ runner, db, vault: 'v1', local: 'l', remote: 'vault:p', workdir: path.join(dir, 'wd'), config: '/cfg' });
  assert.strictEqual(r.ran, false, 'the run did not execute');
  assert.strictEqual(r.result, 'blocked-needs-resync');
  assert.strictEqual(rec.args, undefined, 'the runner was never invoked');
  assert.strictEqual(getRunState(db, 'v1').resyncRequired, true, 'still blocked (nothing recorded)');
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

test('runBisync: an explicit resync runs, records run-state, and clears the resync block', async () => {
  const dir = tmp();
  const db = openStateDb(dir, nodeCrypto.randomBytes(32));
  const rec = {};
  const runner = fakeRunner({ code: 0 }, rec);
  const wd = path.join(dir, 'wd');
  const r = await runBisync({ runner, db, vault: 'v1', local: 'l', remote: 'vault:p', workdir: wd, config: '/cfg', resync: true, now: () => 4242 });
  assert.strictEqual(r.ran, true);
  assert.strictEqual(r.result, 'resync-ok');
  assert.strictEqual(r.resyncRequired, false);
  assert.ok(rec.args.includes('--resync') && rec.opts.config === '/cfg', 'ran a resync with the ephemeral config');
  assert.ok(fs.existsSync(wd), 'the workdir was created');
  const st = getRunState(db, 'v1');
  assert.deepStrictEqual([st.resyncRequired, st.lastResult, st.lastRunUtc], [false, 'resync-ok', 4242]);
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

test('runBisync: after the block clears, a normal run proceeds; a plain error leaves the block unchanged', async () => {
  const dir = tmp();
  const db = openStateDb(dir, nodeCrypto.randomBytes(32));
  // Clear the block with a resync first.
  await runBisync({ runner: fakeRunner({ code: 0 }), db, vault: 'v1', local: 'l', remote: 'vault:p', workdir: path.join(dir, 'wd'), config: '/c', resync: true, now: () => 1 });
  // A normal run now proceeds (gate cleared) and a transient error must not silently force a resync.
  const rec = {};
  const r = await runBisync({ runner: fakeRunner({ code: 7 }, rec), db, vault: 'v1', local: 'l', remote: 'vault:p', workdir: path.join(dir, 'wd'), config: '/c', now: () => 2 });
  assert.strictEqual(r.ran, true);
  assert.ok(rec.args && !rec.args.includes('--resync'), 'a normal (non-resync) bisync ran');
  assert.strictEqual(r.result, 'error');
  assert.strictEqual(r.resyncRequired, false, 'a plain error leaves the resync block as it was (was clear)');
  assert.strictEqual(getRunState(db, 'v1').lastResult, 'error');
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

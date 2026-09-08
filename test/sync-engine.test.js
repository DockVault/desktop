'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { buildBisyncArgs, runBisync, bisyncWorkdir, MAX_DELETE_PERCENT, credPrepareOutcome } = require('../src/daemon/sync-engine');
const { openStateDb, getRunState } = require('../src/main/state-db');

test('credPrepareOutcome: a code-fault cred reason (provider-error / internal-error) is a distinct non-retrying sync-error outcome', () => {
  // Nothing ran, so the resync-owed latch is carried through untouched; the result is the distinct sync-error,
  // never the generic retryable 'error' (which would retry-then-escalate a code bug forever).
  const a = credPrepareOutcome('provider-error', true);
  assert.strictEqual(a.result, 'sync-error');
  assert.strictEqual(a.ran, false);
  assert.strictEqual(a.resyncRequired, true);
  assert.strictEqual(credPrepareOutcome('internal-error', false).result, 'sync-error');
  // A transient authority refusal stays a calm skip (result null + the reason), unchanged by this.
  assert.strictEqual(credPrepareOutcome('paused-locked', false).result, null);
});

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
  // The folder's identity marker (and a torn write of it) never travels: excluded at the root, by fixed name.
  const ex = a.map((x, i) => (x === '--exclude' ? a[i + 1] : null)).filter(Boolean);
  assert.deepStrictEqual(ex, ['/.dockvault-sync', '/.dockvault-sync.*.tmp']);
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

// --- the empty-pair baseline (a new vault into a new folder) -----------------------------------------
test('emptyPairBaseline: true only for an empty prior listing AND a local side holding nothing but its marker', () => {
  const { emptyPairBaseline, localHasNoFiles, priorListingEmpty, canonicalPath } = require('../src/daemon/sync-engine');
  const dir = tmp();
  const local = path.join(dir, 'local'); const wd = path.join(dir, 'wd');
  fs.mkdirSync(local); fs.mkdirSync(wd);
  const remote = 'vault:V';
  const key = `${canonicalPath(local)}..vault_V`; // bisync keys the listings by the pair; only this pair's count
  assert.strictEqual(priorListingEmpty(wd, local, remote), false, 'no listing yet: not this rule (the never-run branch)');
  fs.writeFileSync(path.join(wd, 'C__somewhere_else..vault_V.path1.lst'), '# bisync listing v1\n');
  fs.writeFileSync(path.join(wd, `${canonicalPath(local)}..vault_Other.path1.lst`), '# bisync listing v1\n');
  assert.strictEqual(priorListingEmpty(wd, local, remote), false, 'a stale listing of another pairing (either side) decides nothing');
  fs.writeFileSync(path.join(wd, `${key}.path1.lst`), '# bisync listing v1 from 2026-01-01\n');
  assert.strictEqual(priorListingEmpty(wd, local, remote), true);
  assert.strictEqual(localHasNoFiles(local), true);
  fs.writeFileSync(path.join(local, '.dockvault-sync'), '{}');
  fs.mkdirSync(path.join(local, 'empty-sub'));
  assert.strictEqual(localHasNoFiles(local), true, 'the marker and empty folders are not files');
  assert.strictEqual(emptyPairBaseline({ local, remote, workdir: wd }), true);
  fs.writeFileSync(path.join(local, 'empty-sub', 'x.txt'), '1');
  assert.strictEqual(localHasNoFiles(local), false);
  assert.strictEqual(emptyPairBaseline({ local, remote, workdir: wd }), false, 'a local file: the guard stands');
  fs.rmSync(path.join(local, 'empty-sub'), { recursive: true });
  fs.writeFileSync(path.join(wd, `${key}.path1.lst`), '# bisync listing v1\n-        3 - - 0001-01-01T00:00:00.000000000+0000 "f.txt"\n');
  assert.strictEqual(emptyPairBaseline({ local, remote, workdir: wd }), false, 'a folder that HAD files and is now empty: the guard stands');
  // Either side's prior listing being empty is enough (a new vault: the server side recorded nothing).
  fs.writeFileSync(path.join(wd, `${key}.path2.lst`), '# bisync listing v1\n');
  assert.strictEqual(priorListingEmpty(wd, local), true);
  assert.strictEqual(emptyPairBaseline({ local, remote, workdir: wd }), true);
  const { needsZeroLossBaseline } = require('../src/daemon/sync-engine');
  assert.strictEqual(needsZeroLossBaseline({ local, remote, workdir: wd }), false, 'no local files: the plain resync suffices');
  fs.writeFileSync(path.join(local, 'first.txt'), 'the first file after an empty baseline');
  assert.strictEqual(needsZeroLossBaseline({ local, remote, workdir: wd }), true, 'local files + an empty prior listing: the zero-loss path');
  assert.strictEqual(emptyPairBaseline({ local, workdir: wd }), false);
  assert.strictEqual(localHasNoFiles(path.join(dir, 'nope')), false, 'unreadable counts as not empty');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runBisync: an empty pair re-baselines on its own (--resync), and the outcome is read as a resync', async () => {
  const dir = tmp();
  const db = openStateDb(dir, nodeCrypto.randomBytes(32));
  const local = path.join(dir, 'local'); const wd = path.join(dir, 'wd');
  fs.mkdirSync(local); fs.mkdirSync(wd);
  await runBisync({ runner: fakeRunner({ code: 0 }), db, vault: 'v1', local, remote: 'vault:p', workdir: wd, config: '/c', resync: true, now: () => 1 });
  const { canonicalPath } = require('../src/daemon/sync-engine');
  fs.writeFileSync(path.join(wd, `${canonicalPath(local)}..vault_p.path1.lst`), '# bisync listing v1\n'); // the pair key of remote 'vault:p'
  const rec = {};
  const r = await runBisync({ runner: fakeRunner({ code: 0 }, rec), db, vault: 'v1', local, remote: 'vault:p', workdir: wd, config: '/c', now: () => 2 });
  assert.ok(rec.args.includes('--resync'), 'the empty pair re-baselines');
  assert.strictEqual(r.ran, true);
  assert.strictEqual(r.resyncRequired, false);
  // With a file in the folder the same call is a normal run.
  fs.writeFileSync(path.join(local, 'a.txt'), '1');
  const rec2 = {};
  await runBisync({ runner: fakeRunner({ code: 0 }, rec2), db, vault: 'v1', local, remote: 'vault:p', workdir: wd, config: '/c', now: () => 3 });
  assert.ok(!rec2.args.includes('--resync'));
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

// --- carrying the prior listings over a folder move --------------------------------------------------
test('canonicalPath matches rclone\'s listing key: whitespace, separators, colon, ? and * become _, ends trimmed', () => {
  const { canonicalPath } = require('../src/daemon/sync-engine');
  assert.strictEqual(canonicalPath('C:/Users/me/Photos-2026 (new)'), 'C__Users_me_Photos-2026_(new)');
  assert.strictEqual(canonicalPath('C:\\Users\\me\\My Photos\\'), 'C__Users_me_My_Photos');
  assert.strictEqual(canonicalPath('/home/u/what?*'), 'home_u_what__');
});

test('carryListings re-keys every listing file of the old pair to the new one, never overwrites, and is idempotent', () => {
  const { carryListings } = require('../src/daemon/sync-engine');
  const wd = tmp();
  const from = 'C:\\Users\\me\\Photos'; const to = 'C:\\Users\\me\\Pictures\\Photos 2026';
  fs.writeFileSync(path.join(wd, 'C__Users_me_Photos..vault_V.path1.lst'), '1');
  fs.writeFileSync(path.join(wd, 'C__Users_me_Photos..vault_V.path2.lst'), '2');
  fs.writeFileSync(path.join(wd, 'C__Users_me_Photos..vault_V.path1.lst-old'), '3');
  fs.writeFileSync(path.join(wd, 'C__Users_me_Other..vault_V.path1.lst'), 'x');
  assert.strictEqual(carryListings(wd, { from, to }), 3);
  assert.deepStrictEqual(fs.readdirSync(wd).sort(), [
    'C__Users_me_Other..vault_V.path1.lst',
    'C__Users_me_Pictures_Photos_2026..vault_V.path1.lst', 'C__Users_me_Pictures_Photos_2026..vault_V.path1.lst-old', 'C__Users_me_Pictures_Photos_2026..vault_V.path2.lst',
  ]);
  assert.strictEqual(carryListings(wd, { from, to }), 0, 'nothing left under the old key');
  // A stale listing already under the new key (an earlier pairing of that path) is set aside: the LIVE one wins.
  fs.writeFileSync(path.join(wd, 'C__Users_me_Photos..vault_V.path1.lst'), 'live');
  assert.strictEqual(carryListings(wd, { from, to }), 1);
  assert.strictEqual(fs.readFileSync(path.join(wd, 'C__Users_me_Pictures_Photos_2026..vault_V.path1.lst'), 'utf8'), 'live');
  assert.ok(fs.readdirSync(wd).some((n) => n.startsWith('C__Users_me_Pictures_Photos_2026..vault_V.path1.lst.stale-')), 'the stale one is kept aside, never read');
  assert.strictEqual(carryListings(wd, { from, to: from }), 0, 'same key: nothing to do');
  assert.strictEqual(carryListings(path.join(wd, 'nope'), { from, to }), 0, 'no workdir: nothing, no throw');
  fs.rmSync(wd, { recursive: true, force: true });
});

test('the CONNECTION is bounded so a door that will not talk fails fast rather than hanging the run', () => {
  const { buildBisyncArgs, CONNECT_BOUND_ARGS } = require('../src/daemon/sync-engine');
  assert.deepStrictEqual(CONNECT_BOUND_ARGS, ['--contimeout', '20s', '--timeout', '90s', '--low-level-retries', '3']);
  const args = buildBisyncArgs({ local: '/l', remote: 'vault:V', workdir: '/w' });
  for (const flag of ['--contimeout', '--timeout', '--low-level-retries']) assert.ok(args.includes(flag), `bisync carries ${flag}`);
  // The bound sits before the stats args, and low-level-retries caps rclone's own retry loop (default 10).
  assert.strictEqual(args[args.indexOf('--low-level-retries') + 1], '3');
});

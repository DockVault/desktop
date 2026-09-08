'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { parseLsf, parseCheckDiffering, walkLocal, reserveLocalPath, zeroLossResync } = require('../src/daemon/resync-zeroloss');

const AT = new Date(2026, 8, 1, 14, 14);
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-rzl-')); }

test('parseLsf: trims, drops blanks, sorts', () => {
  assert.deepStrictEqual(parseLsf('b.txt\na/c.txt\n\n  x.txt \n'), ['a/c.txt', 'b.txt', 'x.txt']);
});

test('parseCheckDiffering: * among on-both = differing; every on-both must be covered; ! = compare error', () => {
  const onBoth = ['a.txt', 'b.txt'];
  const ok = parseCheckDiffering('= a.txt\n* b.txt\n- serveronly.txt', onBoth);
  assert.deepStrictEqual(ok.differing, ['b.txt']);
  assert.strictEqual(ok.covered.size, 2, 'both on-both files got a verdict');
  assert.strictEqual(ok.compareError, false);
  // a file that could not be checked
  const bad = parseCheckDiffering('= a.txt\n! b.txt', onBoth);
  assert.strictEqual(bad.compareError, true);
  // partial output (b.txt missing) -> not fully covered
  const partial = parseCheckDiffering('= a.txt', onBoth);
  assert.strictEqual(partial.covered.size, 1, 'coverage gap is detectable -> caller fails closed');
});

test('walkLocal: recursive, files-only, rclone-style forward-slash rel paths', () => {
  const d = tmp();
  fs.mkdirSync(path.join(d, 'sub'), { recursive: true });
  fs.writeFileSync(path.join(d, 'top.txt'), '1');
  fs.writeFileSync(path.join(d, 'sub', 'inner.txt'), '2');
  assert.deepStrictEqual(walkLocal(d), ['sub/inner.txt', 'top.txt']);
  fs.rmSync(d, { recursive: true, force: true });
});

test('reserveLocalPath: exclusive-create (never clobbers), path-contained, keep-both collision bumps counter', () => {
  const root = tmp();
  // path escape is rejected
  assert.throws(() => reserveLocalPath(root, { from: 'x', to: '../escape.txt', kind: 'server-only' }, 'the vault', AT), /escapes the target dir/);
  // a fresh reserve makes an empty 0600 file
  const r1 = reserveLocalPath(root, { from: 'budget.xlsx', to: 'budget.xlsx', kind: 'server-only' }, 'the vault', AT);
  assert.ok(fs.existsSync(r1.full));
  // a server-only whose name already exists = state changed = fail-closed
  assert.throws(() => reserveLocalPath(root, { from: 'budget.xlsx', to: 'budget.xlsx', kind: 'server-only' }, 'the vault', AT), /state changed/);
  // a keep-both collision bumps the counter (never overwrites the taken name)
  const kb = 'budget (conflicting copy from the vault, Sep 1 2026 2.14pm).xlsx';
  fs.writeFileSync(path.join(root, kb), 'pre-existing keep-both');
  const r2 = reserveLocalPath(root, { from: 'budget.xlsx', to: kb, kind: 'conflict-keep-both' }, 'the vault', AT);
  assert.strictEqual(r2.rel, 'budget (conflicting copy from the vault, Sep 1 2026 2.14pm) (2).xlsx');
  assert.strictEqual(fs.readFileSync(path.join(root, kb), 'utf8'), 'pre-existing keep-both', 'the existing file is untouched');
  fs.rmSync(root, { recursive: true, force: true });
});

// A fake runner: canned lsf/check responses; records the copyto destination paths.
function fakeRunner(responses, rec) {
  return {
    run: async (args) => {
      if (rec) rec.args = (rec.args || []); // every rclone op the resync launches, for the connection-bound assertion
      if (rec && args[0] !== 'obscure') rec.args.push(args);
      if (args[0] === 'lsf') return responses.lsf || { code: 0, stdout: '' };
      if (args[0] === 'check') return responses.check || { code: 0, stdout: '' };
      if (args[0] === 'copyto') { rec.push({ from: args[1], to: args[2] }); return { code: 0, stdout: '' }; }
      if (args[0] === 'bisync') return { code: 0, stdout: '', stderr: '' };
      return { code: 0, stdout: '' };
    },
  };
}

test('zeroLossResync happy path: both loss modes preserved on LOCAL before the resync', async () => {
  const dir = tmp();
  const { openStateDb } = require('../src/main/state-db');
  const local = path.join(dir, 'data'); fs.mkdirSync(local, { recursive: true });
  fs.writeFileSync(path.join(local, 'a.txt'), 'LOCAL version');   // on both, differs
  fs.writeFileSync(path.join(local, 'localonly.txt'), 'x');       // local-only (no preserve needed)
  const db = openStateDb(path.join(dir, 'db'), nodeCrypto.randomBytes(32));
  const rec = [];
  const runner = fakeRunner({
    lsf: { code: 0, stdout: 'a.txt\nsrvonly.txt\n' },              // server has a.txt (both) + srvonly (server-only)
    check: { code: 1, stdout: '* a.txt\n- localonly.txt\n' },     // a.txt differs; check errors on server-only (ignored)
  }, rec);
  const r = await zeroLossResync({ runner, db, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => AT.getTime(), timeoutMs: 5000 });
  assert.strictEqual(r.preserved, 2, 'server-only + differing both preserved');
  // a kept-both conflict must NOT read as clean, even though the resync succeeded (anti-lie)
  assert.strictEqual(r.result, 'conflict-keep-both');
  assert.strictEqual(r.needsAttention, true);
  // the preserve copies were written to LOCAL before the resync: srvonly under its name, a.txt under a keep-both name
  const dests = rec.map((c) => c.to);
  assert.ok(dests.some((d) => d.endsWith(`${path.sep}srvonly.txt`)), 'server-only kept under its original name');
  assert.ok(dests.some((d) => /a \(conflicting copy from the vault, .*\)\.txt$/.test(d)), 'differing -> keep-both name');
  // and they physically exist locally, alongside the untouched original
  assert.strictEqual(fs.readFileSync(path.join(local, 'a.txt'), 'utf8'), 'LOCAL version', 'canonical local file untouched');
  assert.ok(fs.existsSync(path.join(local, 'srvonly.txt')));
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

test('preserving ONLY a server-only file (no conflict) stays green — a clean recovery, nothing to reconcile', async () => {
  const dir = tmp();
  const { openStateDb } = require('../src/main/state-db');
  const local = path.join(dir, 'data'); fs.mkdirSync(local, { recursive: true });
  fs.writeFileSync(path.join(local, 'localonly.txt'), 'x'); // no file shared with the server -> no conflict
  const db = openStateDb(path.join(dir, 'db'), nodeCrypto.randomBytes(32));
  const rec = [];
  const runner = fakeRunner({ lsf: { code: 0, stdout: 'srvonly.txt\n' }, check: { code: 0, stdout: '' } }, rec);
  const r = await zeroLossResync({ runner, db, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => AT.getTime(), timeoutMs: 5000 });
  assert.strictEqual(r.preserved, 1, 'the server-only file is preserved');
  assert.strictEqual(r.result, 'resync-ok', 'no conflict -> clean recovery stays green');
  assert.strictEqual(r.needsAttention, false);
  db.close(); fs.rmSync(dir, { recursive: true, force: true });
});

test('zeroLossResync FAILS CLOSED when the server cannot be enumerated (no resync)', async () => {
  const root = tmp();
  const runner = { run: async (a) => (a[0] === 'lsf' ? { code: 1, stdout: '', stderr: 'connection lost' } : { code: 0 }) };
  await assert.rejects(() => zeroLossResync({ runner, db: null, vault: 'v', local: root, remote: 'vault:V', workdir: path.join(root, 'wd'), config: '/c', now: () => 1 }), /refusing to resync/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('zeroLossResync FAILS CLOSED when a shared file could not be compared (partial pre-scan)', async () => {
  const root = tmp();
  fs.writeFileSync(path.join(root, 'a.txt'), 'local'); // a.txt is on both sides
  const runner = {
    run: async (a) => {
      if (a[0] === 'lsf') return { code: 0, stdout: 'a.txt\n' };       // server has a.txt (on both)
      if (a[0] === 'check') return { code: -1, stdout: '', stderr: 'dropped' }; // compare produced NO verdict
      return { code: 0 };
    },
  };
  await assert.rejects(() => zeroLossResync({ runner, db: null, vault: 'v', local: root, remote: 'vault:V', workdir: path.join(root, 'wd'), config: '/c', now: () => 1 }), /could not compare every shared file/);
  fs.rmSync(root, { recursive: true, force: true });
});

test('walkLocal: the folder\'s identity marker at the root (and a torn write of it) is never a file to preserve or compare; a same-named file deeper down is', () => {
  const d = tmp();
  fs.mkdirSync(path.join(d, 'sub'), { recursive: true });
  fs.writeFileSync(path.join(d, '.dockvault-sync'), '{}');
  fs.writeFileSync(path.join(d, '.dockvault-sync.123.tmp'), '{}');
  fs.writeFileSync(path.join(d, 'sub', '.dockvault-sync'), 'x');
  fs.writeFileSync(path.join(d, 'a.txt'), '1');
  assert.deepStrictEqual(walkLocal(d), ['a.txt', 'sub/.dockvault-sync']);
  fs.rmSync(d, { recursive: true, force: true });
});

test('zeroLossResync: a CONNECTION-level failure at the first step is a typed outcome (nothing ran, baseline untouched), not a generic refusal', async () => {
  const root = tmp();
  const cases = [
    ["NewFs: couldn't connect SSH: dial tcp 203.0.113.5:22: connectex: No connection could be made because the target machine actively refused it.", 'connect-failed'],
    ['ssh: handshake failed: knownhosts: key mismatch', 'host-key-mismatch'],
    ['ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]', 'auth-failed'],
  ];
  for (const [stderr, result] of cases) {
    const runner = { run: async (a) => (a[0] === 'lsf' ? { code: 1, stdout: '', stderr } : { code: 0 }) };
    const r = await zeroLossResync({ runner, db: null, vault: 'v', local: root, remote: 'vault:V', workdir: path.join(root, 'wd'), config: '/c', now: () => 1 });
    assert.strictEqual(r.result, result, stderr.slice(0, 40));
    assert.strictEqual(r.resyncRequired, null, 'the baseline question is left as it was — a never-run vault must not read "needs repair" for a shut door');
    assert.strictEqual(r.needsAttention, true);
    assert.strictEqual(r.preserved, 0);
  }
  fs.rmSync(root, { recursive: true, force: true });
});

test('every rclone op the zero-loss resync launches carries the connection bound (fail fast, never hang)', async () => {
  const root = tmp();
  fs.writeFileSync(path.join(root, 'a.txt'), 'local');
  const rec = { copies: [] };
  const runner = fakeRunner({ lsf: { code: 0, stdout: 'a.txt\nb.txt\n' }, check: { code: 0, stdout: '= a.txt\n' } }, rec);
  await zeroLossResync({ runner, db: null, vault: 'v', local: root, remote: 'vault:V', workdir: path.join(root, 'wd'), config: '/c', now: () => 1, timeoutMs: 5000 }).catch(() => {});
  const scanOps = rec.args.filter((a) => ['lsf', 'check', 'copyto', 'bisync'].includes(a[0]));
  assert.ok(scanOps.length >= 1);
  for (const a of scanOps) {
    assert.ok(a.includes('--contimeout'), `${a[0]} bounds the TCP connect`);
    assert.ok(a.includes('--low-level-retries'), `${a[0]} caps rclone's own retry loop`);
  }
  fs.rmSync(root, { recursive: true, force: true });
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { runBisync, credPrepareOutcome } = require('../src/daemon/sync-engine');
const { zeroLossResync } = require('../src/daemon/resync-zeroloss');
const { runVaultSync } = require('../src/daemon/sync-run');

const AT = new Date(2026, 8, 1, 14, 14).getTime();
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-cpp-')); }

// The server issues single-use credentials, so a resync's several rclone processes each need their own fresh
// credential. A per-step `prepareCred` provider mints one before each process; a prepare failure becomes the
// run's TYPED outcome (never a generic error), so a mid-run host-key rotation stays the loud mismatch.

test('credPrepareOutcome maps each cred reason to its honest run result', () => {
  assert.strictEqual(credPrepareOutcome('host-key-mismatch', true).result, 'host-key-mismatch');
  assert.strictEqual(credPrepareOutcome('host-key-mismatch', true).needsAttention, true);
  assert.strictEqual(credPrepareOutcome('host-key-unavailable', true).result, 'host-key-unverified');
  assert.strictEqual(credPrepareOutcome('host-key-unavailable', true).needsAttention, false, 'cannot-verify is a calm pause');
  assert.strictEqual(credPrepareOutcome('no-session', true).result, 'auth-failed');
  assert.strictEqual(credPrepareOutcome('mint-failed', true).result, 'error');
  assert.strictEqual(credPrepareOutcome('x', false).resyncRequired, false, 'the resync block is carried through, not invented');
  assert.strictEqual(credPrepareOutcome('host-key-mismatch', true).ran, false, 'nothing ran');
});

// A TRANSIENT refusal (a lock mid-resync) is not a failure: a NOT-RUN shape (result null + the reason) so the
// caller emits the same calm skip the pre-dispatch gate does — never a "couldn't sync" problem. An invariant
// violation stays a plain error.
test('credPrepareOutcome: a lock mid-resync is a calm not-run, an invariant violation is an error', () => {
  const locked = credPrepareOutcome('paused-locked', true);
  assert.strictEqual(locked.ran, false);
  assert.strictEqual(locked.result, null, 'no typed result — a not-run the caller maps to a calm skip');
  assert.strictEqual(locked.reason, 'paused-locked');
  assert.strictEqual(locked.needsAttention, false);
  assert.strictEqual(credPrepareOutcome('not-in-flight', true).result, 'error', 'an invariant violation is a plain error, not a calm skip');
  assert.strictEqual(credPrepareOutcome('cap-exceeded', true).result, 'error');
});

test('runBisync prepares a fresh cred before the run; a prepare failure is the typed outcome with no run', async () => {
  let ran = 0, prepared = 0;
  const runner = { run: async () => { ran += 1; return { code: 0, stdout: '', stderr: '' }; } };
  const wd = tmp();
  const ok = await runBisync({ runner, db: null, vault: 'v', local: '/l', remote: 'vault:V', workdir: wd, config: '/c', resync: true, prepareCred: async () => { prepared += 1; return { ok: true }; } });
  assert.strictEqual(prepared, 1, 'the cred was prepared before the run');
  assert.strictEqual(ran, 1, 'the run happened after a successful prepare');
  assert.strictEqual(ok.ran, true);

  ran = 0;
  const fail = await runBisync({ runner, db: null, vault: 'v', local: '/l', remote: 'vault:V', workdir: wd, config: '/c', resync: true, prepareCred: async () => ({ ok: false, reason: 'host-key-mismatch' }) });
  assert.strictEqual(ran, 0, 'a failed prepare NEVER spawns rclone');
  assert.strictEqual(fail.result, 'host-key-mismatch', 'the typed reason is the run outcome, not a generic error');
  assert.strictEqual(fail.ran, false);
  fs.rmSync(wd, { recursive: true, force: true });
});

test('runBisync with NO provider runs exactly as before (normal path unchanged)', async () => {
  let ran = 0;
  const runner = { run: async () => { ran += 1; return { code: 0, stdout: '', stderr: '' }; } };
  const wd = tmp();
  const r = await runBisync({ runner, db: null, vault: 'v', local: '/l', remote: 'vault:V', workdir: wd, config: '/c', resync: true });
  assert.strictEqual(ran, 1);
  assert.strictEqual(r.ran, true);
  fs.rmSync(wd, { recursive: true, force: true });
});

test('zeroLossResync prepares a fresh cred before EVERY rclone process', async () => {
  const dir = tmp();
  const local = path.join(dir, 'local'); fs.mkdirSync(local, { recursive: true }); // empty local
  const steps = [];
  const runner = { run: async (args) => {
    steps.push(args[0]);
    if (args[0] === 'lsf') return { code: 0, stdout: 'srvonly.txt\n' }; // one server-only -> one copyto, no check
    return { code: 0, stdout: '', stderr: '' };
  } };
  let prepared = 0;
  const r = await zeroLossResync({ runner, db: null, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => AT, prepareCred: async () => { prepared += 1; return { ok: true }; } });
  assert.deepStrictEqual(steps, ['lsf', 'copyto', 'bisync'], 'three rclone processes: enumerate, preserve, baseline');
  assert.strictEqual(prepared, 3, 'a fresh single-use cred was prepared before each of the three processes');
  assert.strictEqual(r.preserved, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('zeroLossResync: a mid-resync cred failure surfaces the typed reason and stops (no further processes)', async () => {
  const dir = tmp();
  const local = path.join(dir, 'local'); fs.mkdirSync(local, { recursive: true });
  const steps = [];
  const runner = { run: async (args) => { steps.push(args[0]); if (args[0] === 'lsf') return { code: 0, stdout: 'srvonly.txt\n' }; return { code: 0, stdout: '' }; } };
  let n = 0;
  const r = await zeroLossResync({ runner, db: null, vault: 'v', local, remote: 'vault:V', workdir: path.join(dir, 'wd'), config: '/c', now: () => AT, prepareCred: async () => { n += 1; return n >= 2 ? { ok: false, reason: 'host-key-mismatch' } : { ok: true }; } });
  assert.strictEqual(r.result, 'host-key-mismatch', 'a rotation caught mid-resync is the loud mismatch, not a generic error');
  assert.strictEqual(r.ran, false);
  assert.deepStrictEqual(steps, ['lsf'], 'only the first process ran; the copyto and the baseline never did');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('runVaultSync passes the prepareCred provider through to whichever engine runs', async () => {
  const seen = {};
  const engines = {
    runBisync: async (o) => { seen.bisync = o.prepareCred; return { ran: true, result: 'ok' }; },
    zeroLossResync: async (o) => { seen.resync = o.prepareCred; return { ran: true, result: 'resync-ok' }; },
  };
  const pc = async () => ({ ok: true });
  await runVaultSync({ runner: {}, db: {}, vault: 'v', local: '/l', remote: 'vault:V', workdir: '/wd', config: '/c', resync: true, prepareCred: pc }, engines);
  assert.strictEqual(seen.resync, pc, 'the resync engine receives the provider');
  await runVaultSync({ runner: {}, db: {}, vault: 'v', local: '/l', remote: 'vault:V', workdir: '/wd', config: '/c', resync: false, prepareCred: pc }, engines);
  assert.strictEqual(seen.bisync, pc, 'the bisync engine receives it too (passed through; the daemon sets it only for a resync)');
});

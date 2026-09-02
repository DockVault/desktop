'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { runVaultSync } = require('../src/daemon/sync-run');

// Record which engine each run reaches, and with what. The real engines are never invoked here — the
// point is to prove the ROUTING, i.e. which engine a run is dispatched to.
function spies(over = {}) {
  const calls = { bisync: [], resync: [] };
  return {
    calls,
    engines: {
      runBisync: async (o) => { calls.bisync.push(o); return over.bisync || { ran: true, code: 0, result: 'ok', resyncRequired: false, needsAttention: false }; },
      zeroLossResync: async (o) => { calls.resync.push(o); return over.resync || { ran: true, result: 'resync-ok', preserved: 2, resyncRequired: false, needsAttention: false }; },
    },
  };
}
const spec = { runner: {}, db: {}, vault: 'v1', local: '/local', remote: 'vault:V1', workdir: '/wd', config: '/cfg' };

test('a normal run goes through the plain bisync, never the resync path', async () => {
  const { calls, engines } = spies();
  const r = await runVaultSync({ ...spec, resync: false }, engines);
  assert.strictEqual(calls.bisync.length, 1, 'the plain bisync ran');
  assert.strictEqual(calls.resync.length, 0, 'the zero-loss path was NOT taken');
  assert.strictEqual(calls.bisync[0].resync, false, 'the plain run never carries --resync');
  assert.strictEqual(r.result, 'ok');
});

test('a resync goes ONLY through the zero-loss keep-both path — never a bare bisync --resync', async () => {
  const { calls, engines } = spies();
  const r = await runVaultSync({ ...spec, resync: true }, engines);
  assert.strictEqual(calls.resync.length, 1, 'the zero-loss resync ran');
  assert.strictEqual(calls.bisync.length, 0, 'a bare destructive bisync --resync was NEVER dispatched');
  assert.strictEqual(r.result, 'resync-ok');
  assert.strictEqual(r.preserved, 2, 'the keep-both preservation count is carried back');
});

test('the run spec is passed through intact to whichever engine is chosen', async () => {
  const { calls, engines } = spies();
  await runVaultSync({ ...spec, resync: true }, engines);
  const passed = calls.resync[0];
  for (const k of ['runner', 'db', 'vault', 'local', 'remote', 'workdir', 'config']) {
    assert.strictEqual(passed[k], spec[k], `${k} reached the engine`);
  }
});

test('a keep-both conflict outcome from the resync is surfaced (not flattened to clean)', async () => {
  const { engines } = spies({ resync: { ran: true, result: 'conflict-keep-both', preserved: 1, resyncRequired: false, needsAttention: true } });
  const r = await runVaultSync({ ...spec, resync: true }, engines);
  assert.strictEqual(r.result, 'conflict-keep-both');
  assert.strictEqual(r.needsAttention, true, 'an unreconciled keep-both never reads as a clean run');
});

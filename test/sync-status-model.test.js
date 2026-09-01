'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { STATE, computeStatus, vaultState, OUTCOME_STATE } = require('../src/main/sync-status-model');

const secure = { hasSecureStore: true, online: true, daemon: 'ready' };
const vault = (over) => ({ vault: 'v', running: false, lastResult: null, resyncRequired: false, ...over });

test('no secure store => unavailable (sync is not dressed up as a running state)', () => {
  const r = computeStatus({ hasSecureStore: false });
  assert.strictEqual(r.state, STATE.UNAVAILABLE);
  assert.strictEqual(r.condition, 'unavailable');
});

test('no vault configured => not-configured (never a false green)', () => {
  const r = computeStatus({ ...secure, vaults: [] });
  assert.strictEqual(r.state, STATE.NOT_CONFIGURED);
  assert.strictEqual(r.condition, 'not-configured');
});

test('every clean vault => up to date', () => {
  const r = computeStatus({ ...secure, vaults: [vault({ lastResult: 'ok' }), vault({ vault: 'w', lastResult: 'resync-ok' })] });
  assert.strictEqual(r.state, STATE.UP_TO_DATE);
  assert.strictEqual(r.label, 'Up to date');
});

test('a single unresolved item forbids green (aggregate takes the highest precedence)', () => {
  const r = computeStatus({ ...secure, vaults: [vault({ lastResult: 'ok' }), vault({ vault: 'w', lastResult: 'conflict-keep-both' })] });
  assert.strictEqual(r.state, STATE.NEEDS_DECISION);
  assert.strictEqual(r.reason, 'conflict-keep-both');
});

test('precedence order: problem > decision > paused > syncing > up-to-date', () => {
  const base = { ...secure };
  // paused (locked) beats a plain syncing/up-to-date
  assert.strictEqual(computeStatus({ ...base, locked: true, vaults: [vault({ lastResult: 'ok' })] }).state, STATE.PAUSED);
  // a decision beats paused — a locked vault that also has a conflict reads "needs your decision"
  assert.strictEqual(computeStatus({ ...base, locked: true, vaults: [vault({ lastResult: 'conflict-keep-both' })] }).state, STATE.NEEDS_DECISION);
  // a problem beats a decision
  assert.strictEqual(computeStatus({ ...base, locked: true, vaults: [vault({ lastResult: 'conflict-keep-both' }), vault({ vault: 'w', lastResult: 'host-key-mismatch' })] }).state, STATE.SYNC_PROBLEM);
});

test('crash-loop latch => sync problem, and it outranks everything', () => {
  const r = computeStatus({ ...secure, crashLoopLatched: true, locked: true, vaults: [vault({ lastResult: 'ok' })] });
  assert.strictEqual(r.state, STATE.SYNC_PROBLEM);
  assert.strictEqual(r.reason, 'sync-stopped');
});

test('locked => paused (reason locked); offline => paused (waiting to reconnect); restarting => paused (reconnecting)', () => {
  assert.deepStrictEqual([computeStatus({ ...secure, locked: true, vaults: [vault({ lastResult: 'ok' })] }).state,
    computeStatus({ ...secure, locked: true, vaults: [vault({ lastResult: 'ok' })] }).reason], [STATE.PAUSED, 'locked']);
  const off = computeStatus({ ...secure, online: false, vaults: [vault({ lastResult: 'ok' })] });
  assert.deepStrictEqual([off.state, off.reason], [STATE.PAUSED, 'waiting-to-reconnect']);
  const restarting = computeStatus({ ...secure, daemon: 'crashed', vaults: [vault({ lastResult: 'ok' })] });
  assert.deepStrictEqual([restarting.state, restarting.reason], [STATE.PAUSED, 'reconnecting']);
});

test('host-key MISMATCH is a problem; host-key UNVERIFIED is a calm paused (cannot verify yet), not a problem', () => {
  assert.strictEqual(computeStatus({ ...secure, vaults: [vault({ lastResult: 'host-key-mismatch' })] }).state, STATE.SYNC_PROBLEM);
  const unv = computeStatus({ ...secure, vaults: [vault({ lastResult: 'host-key-unverified' })] });
  assert.strictEqual(unv.state, STATE.PAUSED);
  assert.strictEqual(unv.reason, 'cannot-verify-yet');
});

test('auth-failed is a decision (sign in), not a problem', () => {
  const r = computeStatus({ ...secure, vaults: [vault({ lastResult: 'auth-failed' })] });
  assert.strictEqual(r.state, STATE.NEEDS_DECISION);
  assert.strictEqual(r.reason, 'sign-in-needed');
});

test('a resync-required latch never reads green, even if the last outcome looked ok', () => {
  const r = vaultState(vault({ lastResult: 'ok', resyncRequired: true }));
  assert.strictEqual(r.state, STATE.NEEDS_DECISION);
  assert.strictEqual(r.reason, 'needs-repair');
});

test('an in-flight run shows "syncing" only when nothing unresolved outranks it', () => {
  // running + clean prior => syncing
  assert.strictEqual(vaultState(vault({ lastResult: 'ok', running: true })).state, STATE.SYNCING);
  // running + an unresolved conflict keeps the decision face (the next run does not paper over it)
  assert.strictEqual(vaultState(vault({ lastResult: 'conflict-keep-both', running: true })).state, STATE.NEEDS_DECISION);
});

test('configured but never run => a calm "syncing / waiting for first sync", never a false green', () => {
  const r = vaultState(vault({ lastResult: null, running: false }));
  assert.strictEqual(r.state, STATE.SYNCING);
  assert.strictEqual(r.reason, 'waiting-first-sync');
});

test('every classifier outcome maps to a defined state', () => {
  for (const k of Object.keys(OUTCOME_STATE)) {
    assert.ok(OUTCOME_STATE[k] && OUTCOME_STATE[k].state, `${k} maps to a state`);
  }
});

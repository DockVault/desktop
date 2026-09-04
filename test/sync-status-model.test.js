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

test("a daemon 'init-failed' is a non-retrying sync problem, surfaced even with no readable vaults", () => {
  // The saved state exists but its key won't unwrap / its DB won't open. The aggregate must be a SYNC_PROBLEM
  // ('state-unreadable'), never a calm 'reconnecting', and never masked as 'not configured' when the vault
  // list cannot be read because the store is down.
  const withVaults = computeStatus({ hasSecureStore: true, daemon: 'init-failed', vaults: [{ vault: 'v1', lastResult: 'ok' }] });
  assert.strictEqual(withVaults.state, STATE.SYNC_PROBLEM);
  assert.strictEqual(withVaults.reason, 'state-unreadable');
  const noVaults = computeStatus({ hasSecureStore: true, daemon: 'init-failed', vaults: [] });
  assert.strictEqual(noVaults.state, STATE.SYNC_PROBLEM, 'never masked as not-configured when the store is down');
  assert.strictEqual(noVaults.reason, 'state-unreadable');
});

test("a 'sync-error' outcome (a code fault in the sync path) reads as a sync problem, distinct from a retryable run error", () => {
  const r = computeStatus({ hasSecureStore: true, online: true, daemon: 'ready', vaults: [{ vault: 'v', lastResult: 'sync-error', resyncRequired: false }] });
  assert.strictEqual(r.state, STATE.SYNC_PROBLEM);
  assert.strictEqual(r.vaults[0].state, STATE.SYNC_PROBLEM);
  assert.strictEqual(r.vaults[0].reason, 'sync-error');
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

// A persistent DOWN helper (wedged or crashed) escalates to 'sync-stopped'/restart — the ONE honest remedy for
// both shapes — never 'not-syncing'/"check your connection". So a per-vault down-helper escalation shares the
// restart lane with the GLOBAL crash-loop latch: the glance is a single 'sync-stopped'/restart whether the helper
// crash-looped (global latch) or WEDGED (per-vault escalation, no latch — the case the kill-and-respawn restart
// serves). This also collapses the earlier menu residual: the per-vault escalation is now the SAME 'sync-stopped'
// lane as the latch, not a separate 'not-syncing' beside restart. (Suppressing a stale per-vault item under a
// latch stays a follow-up.)
test('a persistent DOWN helper escalates to sync-stopped/restart — a WEDGED helper (no latch) reaches the same restart lane as a crash-loop', () => {
  // a wedged helper: no global crash-loop latch, but its per-vault streak escalated to 'sync-stopped'
  const wedged = computeStatus({ ...secure, vaults: [vault({ lastResult: 'ok', condition: { state: STATE.SYNC_PROBLEM, reason: 'sync-stopped' } })] });
  assert.strictEqual(wedged.state, STATE.SYNC_PROBLEM);
  assert.strictEqual(wedged.reason, 'sync-stopped', 'a wedged helper reaches restart even without a crash-loop latch');
  // and with the global latch too, it stays the single restart lane (both are sync-stopped)
  const r = computeStatus({ ...secure, crashLoopLatched: true,
    vaults: [vault({ lastResult: 'ok', condition: { state: STATE.SYNC_PROBLEM, reason: 'sync-stopped' } })] });
  assert.strictEqual(r.state, STATE.SYNC_PROBLEM);
  assert.strictEqual(r.reason, 'sync-stopped', 'crash-loop + per-vault down-helper = one restart lane');
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

test('auth-failed-locked (a password vault past its retry) is a decision to unlock the vault, not to sign in', () => {
  const r = computeStatus({ ...secure, vaults: [vault({ lastResult: 'auth-failed-locked' })] });
  assert.strictEqual(r.state, STATE.NEEDS_DECISION);
  assert.strictEqual(r.reason, 'needs-unlock');
});

test('a resync-required latch never reads green, even if the last outcome looked ok', () => {
  const r = vaultState(vault({ lastResult: 'ok', resyncRequired: true }));
  assert.strictEqual(r.state, STATE.NEEDS_DECISION);
  assert.strictEqual(r.reason, 'needs-repair');
});

test('the "syncing" glance shows only while transferring, and only when nothing unresolved outranks it', () => {
  // transferring + clean prior => syncing
  assert.strictEqual(vaultState(vault({ lastResult: 'ok', transferring: true })).state, STATE.SYNCING);
  // dispatched but merely scanning (running, not transferring) keeps the last real state — quiet, no flicker
  assert.strictEqual(vaultState(vault({ lastResult: 'ok', running: true, transferring: false })).state, STATE.UP_TO_DATE);
  // transferring + an unresolved conflict keeps the decision face (the next run does not paper over it)
  assert.strictEqual(vaultState(vault({ lastResult: 'conflict-keep-both', transferring: true })).state, STATE.NEEDS_DECISION);
});

test('configured but never run => a calm "waiting to start", never SYNCING and never a false green', () => {
  const r = vaultState(vault({ lastResult: null, running: false }));
  assert.strictEqual(r.state, STATE.WAITING);
  assert.strictEqual(r.reason, 'waiting-first-sync');
  assert.notStrictEqual(r.state, STATE.SYNCING, 'nothing is transferring, so it is not "syncing"');
});

test('waiting outranks up-to-date (forbids a false green) but a real in-flight run outranks waiting', () => {
  const secure2 = { hasSecureStore: true, online: true, daemon: 'ready' };
  // one never-run vault + one clean vault => the glance is "Waiting to start", not "Up to date"
  const agg = computeStatus({ ...secure2, vaults: [vault({ vault: 'a', lastResult: null }), vault({ vault: 'b', lastResult: 'ok' })] });
  assert.strictEqual(agg.state, STATE.WAITING);
  // a genuinely TRANSFERRING vault wins over a waiting one
  const agg2 = computeStatus({ ...secure2, vaults: [vault({ vault: 'a', lastResult: null }), vault({ vault: 'b', lastResult: 'ok', transferring: true })] });
  assert.strictEqual(agg2.state, STATE.SYNCING);
});

test('every classifier outcome maps to a defined state', () => {
  for (const k of Object.keys(OUTCOME_STATE)) {
    assert.ok(OUTCOME_STATE[k] && OUTCOME_STATE[k].state, `${k} maps to a state`);
  }
});

test('a live can\'t-run condition overrides a stale green, but never masks a more severe outcome', () => {
  // stale "ok" + a sign-in condition => needs-decision (a vault that cannot run never keeps up-to-date)
  const a = vaultState({ vault: 'a', lastResult: 'ok', condition: { state: STATE.NEEDS_DECISION, reason: 'sign-in-needed' } });
  assert.strictEqual(a.state, STATE.NEEDS_DECISION);
  assert.strictEqual(a.reason, 'sign-in-needed');
  // a prior sync problem outranks a lower condition and is not hidden by it
  const b = vaultState({ vault: 'b', lastResult: 'host-key-mismatch', condition: { state: STATE.PAUSED, reason: 'retrying' } });
  assert.strictEqual(b.state, STATE.SYNC_PROBLEM);
  // consent-declined (WAITING) over a never-run vault carries the consent reason, not the bare waiting one
  const c = vaultState({ vault: 'c', lastResult: null, condition: { state: STATE.WAITING, reason: 'consent-needed' } });
  assert.strictEqual(c.state, STATE.WAITING);
  assert.strictEqual(c.reason, 'consent-needed');
});

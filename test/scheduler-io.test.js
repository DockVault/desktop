'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { makeRunEffects, makeVerifyEligible, makeSession, makeSchedulerIo, applySchedulerEvent, StatusSink } = require('../src/main/scheduler-io');
const { SyncStatusHub } = require('../src/main/sync-status-hub');
const { STATE } = require('../src/main/sync-status-model');

// A hub with one configured vault; assert the PER-VAULT computed state after applying each event, so
// the mapping is checked by its observable consequence in the real status model.
function hubWithVault() {
  const hub = new SyncStatusHub({ locked: false, online: true });
  hub.setVaults(['v1']);
  return hub;
}
const vaultOf = (hub) => hub.current().vaults.find((v) => v.vault === 'v1');

test('run effects map the scheduler spec onto the helper call; a resync is ALWAYS a resync call', async () => {
  const seen = [];
  const daemon = { runSync: async (spec) => { seen.push(spec); return { ok: true, ran: true, result: 'ok' }; } };
  const fx = makeRunEffects(daemon);
  await fx.runSync({ vaultId: 'v1', local: '/l', remotePath: 'V1' });
  await fx.runResync({ vaultId: 'v1', local: '/l', remotePath: 'V1' });
  assert.deepStrictEqual(seen[0], { vault: 'v1', local: '/l', remotePath: 'V1' }, 'a normal run carries no resync');
  assert.strictEqual(seen[0].resync, undefined);
  assert.deepStrictEqual(seen[1], { vault: 'v1', local: '/l', remotePath: 'V1', resync: true }, 'a resync run is sent as a resync');
});

const remotePathForVault = (name) => {
  const parts = String(name).split(/[\\/]+/).filter(Boolean);
  if (parts.length !== 1 || parts[0] === '..') throw new Error('one segment only');
  return parts[0];
};

test('verifyEligible re-fetches fresh, finds the vault, and re-derives the remote from the CURRENT name', async () => {
  const verify = makeVerifyEligible({
    fetchStandard: async () => ({ vaults: [{ vaultId: 'v1', vaultName: 'Renamed' }] }),
    remotePathForVault,
  });
  const r = await verify('v1');
  assert.deepStrictEqual(r, { ok: true, remotePath: 'Renamed', vaultName: 'Renamed' }, 'remote follows the current name, not a stored one');
});

test('verifyEligible fails closed when the vault is absent (re-tiered to zero-knowledge / removed)', async () => {
  const verify = makeVerifyEligible({
    fetchStandard: async () => ({ vaults: [{ vaultId: 'other', vaultName: 'Other' }] }),
    remotePathForVault,
  });
  assert.deepStrictEqual(await verify('v1'), { ok: false, reason: 'not-standard-or-removed' });
});

test('verifyEligible fails closed when the fresh fetch fails (never syncs on a stale/absent list)', async () => {
  const verify = makeVerifyEligible({
    fetchStandard: async () => { const e = new Error('401'); e.reason = 'no-session'; throw e; },
    remotePathForVault,
  });
  assert.deepStrictEqual(await verify('v1'), { ok: false, reason: 'no-session' });
});

test('verifyEligible fails closed when the current name is no longer a single safe segment', async () => {
  const verify = makeVerifyEligible({
    fetchStandard: async () => ({ vaults: [{ vaultId: 'v1', vaultName: '../escape' }] }),
    remotePathForVault,
  });
  assert.deepStrictEqual(await verify('v1'), { ok: false, reason: 'bad-vault-name' });
});

test('applySchedulerEvent: running shows syncing; done records the outcome and clears running', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'running' });
  assert.strictEqual(vaultOf(hub).state, STATE.SYNCING);
  assert.strictEqual(vaultOf(hub).running, true);
  applySchedulerEvent(hub, 'v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } });
  assert.strictEqual(vaultOf(hub).state, STATE.UP_TO_DATE);
  assert.strictEqual(vaultOf(hub).running, false);
});

test('applySchedulerEvent: a conflict outcome reads needs-decision, not up-to-date', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'done', outcome: { result: 'conflict-keep-both', resyncRequired: false } });
  assert.strictEqual(vaultOf(hub).state, STATE.NEEDS_DECISION);
});

test('applySchedulerEvent: an error reads as a sync problem and is never left running', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'running' });
  applySchedulerEvent(hub, 'v1', { phase: 'error', reason: 'run-failed' });
  assert.strictEqual(vaultOf(hub).state, STATE.SYNC_PROBLEM);
  assert.strictEqual(vaultOf(hub).running, false);
});

test('applySchedulerEvent: blocked marks the resync-owed latch (needs a decision), does no work', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'blocked', reason: 'needs-repair' });
  assert.strictEqual(vaultOf(hub).state, STATE.NEEDS_DECISION);
  assert.strictEqual(vaultOf(hub).resyncRequired, true);
  assert.strictEqual(vaultOf(hub).running, false);
});

test('applySchedulerEvent: genuinely transient skips keep the last honest state (never a false "syncing")', () => {
  for (const ev of [{ phase: 'queued' }, { phase: 'paused', reason: 'waiting-to-reconnect' }, { phase: 'skipped', reason: 'paused-locked' }, { phase: 'skipped', reason: 'state-uncertain' }]) {
    const hub = hubWithVault();
    applySchedulerEvent(hub, 'v1', { phase: 'running' });
    applySchedulerEvent(hub, 'v1', ev);
    assert.strictEqual(vaultOf(hub).running, false, `${ev.phase}/${ev.reason || ''} clears running`);
    assert.strictEqual(vaultOf(hub).state, STATE.WAITING, `${ev.phase}/${ev.reason || ''} keeps the calm waiting state`);
  }
});

test('applySchedulerEvent: a PERSISTENT refusal never keeps a stale green — it surfaces a cant-run condition', () => {
  const cases = [
    [{ phase: 'refused', reason: 'not-standard-or-removed' }, STATE.NEEDS_DECISION, 'vault-unavailable'],
    [{ phase: 'refused', reason: 'bad-vault-name' }, STATE.NEEDS_DECISION, 'vault-unavailable'],
    [{ phase: 'refused', reason: 'folder-insecure' }, STATE.NEEDS_DECISION, 'folder-insecure'],
    [{ phase: 'refused', reason: 'folder-rejected' }, STATE.NEEDS_DECISION, 'folder-rejected'],
    [{ phase: 'refused', reason: 'folder-problem' }, STATE.NEEDS_DECISION, 'folder-problem'],
    [{ phase: 'skipped', reason: 'no-session' }, STATE.NEEDS_DECISION, 'sign-in-needed'],
  ];
  for (const [ev, state, reason] of cases) {
    const hub = hubWithVault();
    applySchedulerEvent(hub, 'v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } });
    assert.strictEqual(vaultOf(hub).state, STATE.UP_TO_DATE, 'starts up-to-date');
    applySchedulerEvent(hub, 'v1', ev);
    assert.strictEqual(vaultOf(hub).state, state, `${ev.reason} -> ${state} (never left reading up-to-date)`);
    assert.strictEqual(vaultOf(hub).reason, reason);
  }
});

test('applySchedulerEvent: consent-declined reads as calm WAITING (a re-offerable choice), not an alert', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'skipped', reason: 'consent-declined' });
  assert.strictEqual(vaultOf(hub).state, STATE.WAITING);
  assert.strictEqual(vaultOf(hub).reason, 'consent-needed');
});

test('a consent-declined skip raises NO must-act — so a declined manual press is the one safe zero-toast path', () => {
  // The manual-completion hook stays silent on consent-declined (don't nag a decline). That is only safe if the
  // same skip raises no hub must-act either — otherwise dropping it would leave the press with zero answer AND
  // a swallowed must-act. WAITING is not in the hub's must-act set, so onNotify is never called for it.
  const notifies = [];
  const hub = new SyncStatusHub({ locked: false, online: true, onNotify: (n) => notifies.push(n) });
  hub.setVaults(['v1']);
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'skipped', reason: 'consent-declined' });
  assert.strictEqual(hub.current().vaults.find((v) => v.vault === 'v1').state, STATE.WAITING, 'a declined press reads WAITING, and says why');
  assert.deepStrictEqual(notifies, [], 'and raises no must-act — nothing for the manual hook to drop; the intentional silence is safe');
});

test('applySchedulerEvent: a host-key-mismatch from ANY phase takes the must-act path, not a calm retry', () => {
  for (const ev of [{ phase: 'paused', reason: 'host-key-mismatch' }, { phase: 'refused', reason: 'host-key-mismatch' }]) {
    const hub = hubWithVault();
    applySchedulerEvent(hub, 'v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } });
    applySchedulerEvent(hub, 'v1', ev);
    assert.strictEqual(vaultOf(hub).state, STATE.SYNC_PROBLEM, `${ev.phase} host-key-mismatch -> sync problem`);
    assert.strictEqual(vaultOf(hub).reason, 'host-key-mismatch');
  }
});

test('applySchedulerEvent: a cant-run condition clears once the vault actually runs again', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'skipped', reason: 'no-session' });
  assert.strictEqual(vaultOf(hub).state, STATE.NEEDS_DECISION);
  applySchedulerEvent(hub, 'v1', { phase: 'running' });
  assert.strictEqual(vaultOf(hub).state, STATE.SYNCING, 'a real run clears the condition');
  applySchedulerEvent(hub, 'v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } });
  assert.strictEqual(vaultOf(hub).state, STATE.UP_TO_DATE);
});

test('applySchedulerEvent: a transient skip does NOT erase a persistent condition (no flip back to green)', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } });
  applySchedulerEvent(hub, 'v1', { phase: 'refused', reason: 'not-standard-or-removed' }); // persistent -> condition
  assert.strictEqual(vaultOf(hub).state, STATE.NEEDS_DECISION);
  applySchedulerEvent(hub, 'v1', { phase: 'skipped', reason: 'paused-locked' }); // a transient tick in between
  assert.strictEqual(vaultOf(hub).state, STATE.NEEDS_DECISION, 'the condition survives a lock — never flips back to up-to-date');
  assert.strictEqual(vaultOf(hub).reason, 'vault-unavailable');
});

test('applySchedulerEvent: an older/unverifiable server reads calm cannot-verify-yet, not a bare retry', () => {
  const hub = hubWithVault();
  applySchedulerEvent(hub, 'v1', { phase: 'paused', reason: 'host-key-unavailable' });
  assert.strictEqual(vaultOf(hub).state, STATE.PAUSED);
  assert.strictEqual(vaultOf(hub).reason, 'cannot-verify-yet');
});

function hubWithNotify() {
  const notes = [];
  const hub = new SyncStatusHub({ locked: false, online: true, onNotify: (n) => notes.push(n) });
  hub.setVaults(['v1']);
  return { hub, notes };
}

test('StatusSink: a run error below the threshold reads calm "retrying" with no notification', () => {
  const { hub, notes } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'error', reason: 'run-failed' });
  sink.apply('v1', { phase: 'error', reason: 'run-failed' });
  assert.strictEqual(vaultOf(hub).state, STATE.PAUSED);
  assert.strictEqual(vaultOf(hub).reason, 'retrying');
  assert.deepStrictEqual(notes, [], 'a single timeout / flap never toasts');
});

test('StatusSink: the threshold-th consecutive error escalates to a sync problem + one must-act', () => {
  const { hub, notes } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'error', reason: 'x' });
  sink.apply('v1', { phase: 'error', reason: 'x' });
  sink.apply('v1', { phase: 'error', reason: 'x' }); // 3rd -> sync problem
  assert.strictEqual(vaultOf(hub).state, STATE.SYNC_PROBLEM);
  assert.strictEqual(notes.length, 1, 'the must-act fires once at escalation');
});

test('StatusSink: any completed run resets the streak', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'error', reason: 'x' });
  sink.apply('v1', { phase: 'error', reason: 'x' }); // streak 2
  sink.apply('v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } }); // reset
  assert.strictEqual(vaultOf(hub).state, STATE.UP_TO_DATE);
  sink.apply('v1', { phase: 'error', reason: 'x' }); // streak back to 1 -> retrying, not a problem
  assert.strictEqual(vaultOf(hub).state, STATE.PAUSED);
  assert.strictEqual(vaultOf(hub).reason, 'retrying');
});

test('StatusSink: a host-key-mismatch is an immediate alert, never thresholded as a retry', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'paused', reason: 'host-key-mismatch' });
  assert.strictEqual(vaultOf(hub).state, STATE.SYNC_PROBLEM);
  assert.strictEqual(vaultOf(hub).reason, 'host-key-mismatch');
});

test('StatusSink: non-error events map straight through (running -> syncing)', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'running' });
  assert.strictEqual(vaultOf(hub).state, STATE.SYNCING);
});

test('StatusSink: persistent PRE-DISPATCH failures escalate too (a mint outage never reads calm forever)', () => {
  const { hub, notes } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });
  assert.strictEqual(vaultOf(hub).state, STATE.PAUSED, 'the first couple read calm retrying');
  assert.deepStrictEqual(notes, []);
  sink.apply('v1', { phase: 'refused', reason: 'vault-list-unavailable' }); // same streak, mixed pre-dispatch causes
  assert.strictEqual(vaultOf(hub).state, STATE.SYNC_PROBLEM);
  assert.strictEqual(vaultOf(hub).reason, 'not-syncing');
  assert.strictEqual(notes.length, 1, 'one calm "not syncing" notification at escalation');
});

test('StatusSink: a lock between failures does NOT count toward the streak', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });    // 1
  sink.apply('v1', { phase: 'skipped', reason: 'paused-locked' }); // not a failure — does not advance
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });    // 2
  assert.strictEqual(vaultOf(hub).state, STATE.PAUSED, 'still just retrying — a lock did not push it over');
});

test('StatusSink: a completed run resets a pre-dispatch failure streak', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });
  sink.apply('v1', { phase: 'done', outcome: { result: 'ok', resyncRequired: false } });
  assert.strictEqual(vaultOf(hub).state, STATE.UP_TO_DATE);
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' }); // back to 1 -> retrying, not a problem
  assert.strictEqual(vaultOf(hub).state, STATE.PAUSED);
});

test('StatusSink: an escalated "not-syncing" does not MASK a later, more specific reason', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' });
  sink.apply('v1', { phase: 'paused', reason: 'mint-failed' }); // escalates -> not-syncing
  assert.strictEqual(vaultOf(hub).reason, 'not-syncing');
  sink.apply('v1', { phase: 'skipped', reason: 'no-session' }); // a more specific persistent cause arrives
  assert.strictEqual(vaultOf(hub).state, STATE.NEEDS_DECISION);
  assert.strictEqual(vaultOf(hub).reason, 'sign-in-needed', 'the actionable "sign in" replaces "check your connection"');
});

test('StatusSink: a noop (already-running refusal) leaves the in-flight run reading syncing', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'running' });
  sink.apply('v1', { phase: 'noop', reason: 'already-running' });
  assert.strictEqual(vaultOf(hub).state, STATE.SYNCING, 'still syncing — the guard refusal did not disturb the live run');
  assert.strictEqual(vaultOf(hub).running, true);
});

test('StatusSink: a noop neither increments nor resets the failure streak', () => {
  const { hub } = hubWithNotify();
  const sink = new StatusSink(hub);
  sink.apply('v1', { phase: 'error' });
  sink.apply('v1', { phase: 'noop', reason: 'already-running' }); // must not reset
  sink.apply('v1', { phase: 'error' });
  sink.apply('v1', { phase: 'noop', reason: 'already-running' }); // must not count
  sink.apply('v1', { phase: 'error' }); // 3rd REAL error -> escalate (the noops changed nothing)
  assert.strictEqual(vaultOf(hub).reason, 'not-syncing', 'the noops did not reset the streak; 3 real errors still escalate');
});

test('makeSession: a fresh snapshot yields the three eligibility booleans; not-fresh yields state-uncertain', () => {
  const base = { isUnlocked: () => true, hasAccount: () => true, isOnline: () => true };
  assert.deepStrictEqual(makeSession({ ...base, snapshotFresh: () => true })(), { locked: false, accountLive: true, online: true });
  const stale = makeSession({ ...base, snapshotFresh: () => false })();
  assert.strictEqual(typeof stale.locked, 'undefined', 'no booleans when the run-state view is stale (scheduler reads state-uncertain)');
  assert.strictEqual(stale.uncertain, true);
});

test('makeSession reflects lock / account / online state', () => {
  const s = makeSession({ isUnlocked: () => false, hasAccount: () => false, isOnline: () => false, snapshotFresh: () => true })();
  assert.deepStrictEqual(s, { locked: true, accountLive: false, online: false });
});

test('makeSchedulerIo assembles the io: run-state from the snapshot, resync routing, refreshCred, verifyEligible', async () => {
  const calls = { ensureSent: [], runSync: [] };
  const snapshot = { get: (v) => (v === 'v1' ? { lastResult: 'ok', resyncRequired: false } : null), fresh: () => true };
  const credCache = { ensureSent: async (v) => { calls.ensureSent.push(v); return { ok: true }; } };
  const daemon = { runSync: async (spec) => { calls.runSync.push(spec); return { ok: true, ran: true }; } };
  const io = makeSchedulerIo({
    listConfigured: () => [{ vaultId: 'v1' }],
    snapshot,
    fetchStandard: async () => ({ vaults: [{ vaultId: 'v1', vaultName: 'V1' }] }),
    remotePathForVault: (n) => n,
    secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
    credCache, daemon, confirmFirstUpload: async () => true,
    isUnlocked: () => true, hasAccount: () => true, isOnline: () => true, onEvent: () => {},
  });
  assert.deepStrictEqual(io.runState('v1'), { lastResult: 'ok', resyncRequired: false });
  assert.strictEqual(io.runState('other'), null, 'unknown vault -> never-run');
  assert.deepStrictEqual(io.session(), { locked: false, accountLive: true, online: true });
  assert.deepStrictEqual(await io.verifyEligible('v1'), { ok: true, remotePath: 'V1', vaultName: 'V1' });
  await io.refreshCred('v1');
  assert.deepStrictEqual(calls.ensureSent, ['v1'], 'refreshCred -> the credential cache');
  await io.runResync({ vaultId: 'v1', local: '/l', remotePath: 'V1' });
  assert.strictEqual(calls.runSync[0].resync, true, 'runResync routes to the resync call');
});

test('makeSchedulerIo: session reports uncertain when the snapshot is not fresh (fail-closed carried through)', () => {
  const io = makeSchedulerIo({ snapshot: { get: () => null, fresh: () => false }, credCache: {}, daemon: {}, isUnlocked: () => true, hasAccount: () => true, isOnline: () => true });
  assert.strictEqual(io.session().uncertain, true);
});

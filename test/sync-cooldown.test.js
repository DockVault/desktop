'use strict';

/*
 * Bounded minting under a click storm and under a door that keeps refusing. Every test counts the mints
 * (refreshCred calls): the property being proven is that no burst of presses and no run of refusals can draw
 * more than one credential per window, and that a turned-away request is answered at once with how long to wait.
 */

const test = require('node:test');
const assert = require('node:assert');
const {
  SyncScheduler, REFUSAL_RESULTS, REFUSAL_BACKOFF_BASE_MS, REFUSAL_BACKOFF_MAX_MS, MANUAL_SYNC_COOLDOWN_MS,
} = require('../src/main/sync-scheduler');
const { conditionForReason, streakFailureReason } = require('../src/main/scheduler-io');
const { classifyBisyncOutcome, classifyConnectionFailure, RESULT } = require('../src/daemon/bisync-outcome');
const { OUTCOME_STATE, STATE } = require('../src/main/sync-status-model');
const { createManageView } = require('../src/main/manage-view');
const { turnedAwayBody, waitWords } = require('../src/main/manual-sync-copy');

const vault = (id) => ({ vaultId: id, vaultName: id.toUpperCase(), localFolder: `/folders/${id}`, remotePath: id.toUpperCase(), enabled: true });

function harness(over = {}) {
  const log = [];
  const calls = { refreshCred: [], runSync: [], runResync: [], consent: [] };
  let clock = 1_000_000;
  const io = {
    listConfigured: () => [vault('a'), vault('b')],
    runState: over.runState || (() => ({ lastResult: 'ok', resyncRequired: false })),
    session: () => ({ locked: false, online: true, accountLive: true }),
    verifyEligible: async (v) => ({ ok: true, remotePath: v.toUpperCase() }),
    secureFolder: () => ({ ok: true }),
    classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }),
    refreshCred: async (v) => { calls.refreshCred.push(v); return { ok: true }; },
    runSync: over.runSync || (async (spec) => { calls.runSync.push(spec.vaultId); return { result: 'ok', ran: true }; }),
    runResync: over.runResync || (async (spec) => { calls.runResync.push(spec.vaultId); return { result: 'resync-ok', ran: true }; }),
    confirmFirstUpload: over.confirmFirstUpload,
    credentialPath: over.credentialPath,
    now: () => clock,
    onEvent: (vaultId, ev) => { log.push({ vaultId, ...ev }); },
  };
  const sch = new SyncScheduler(io);
  return { sch, io, log, calls, advance: (ms) => { clock += ms; }, now: () => clock };
}
async function settle(sch) { for (let i = 0; i < 300 && (sch._busy || sch._queue.length); i++) await new Promise((r) => setTimeout(r, 2)); }
const last = (log, id) => log.filter((e) => e.vaultId === id).pop();
const authFailed = async (spec) => ({ result: 'auth-failed', ran: true, resyncRequired: null, needsAttention: true, vault: spec.vaultId });

// ---- "Sync now" cooldown ----------------------------------------------------------------------------------------

test('a rapid click storm mints ONCE: the first press mints, every further press inside the cooldown is turned away at once with the wait', async () => {
  const h = harness();
  const first = h.sch.requestSync('a', { manual: true });
  assert.deepStrictEqual(first, { accepted: true });
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a'], 'the first press minted once');

  const verdicts = [];
  for (let i = 0; i < 20; i += 1) { h.advance(1000); verdicts.push(h.sch.requestSync('a', { manual: true })); await settle(h.sch); }
  assert.deepStrictEqual(h.calls.refreshCred, ['a'], 'twenty more presses over twenty seconds minted NOTHING');
  assert.deepStrictEqual(h.calls.runSync, ['a'], 'and ran nothing');
  for (const v of verdicts) {
    assert.strictEqual(v.accepted, false);
    assert.strictEqual(v.reason, 'sync-cooldown');
    assert.ok(v.retryInMs > 0 && v.retryInMs <= MANUAL_SYNC_COOLDOWN_MS, 'each answer says how long until the next press may mint');
  }
  assert.strictEqual(verdicts[0].retryInMs, MANUAL_SYNC_COOLDOWN_MS - 1000, 'the wait counts down from the press that minted');
  assert.strictEqual(verdicts[19].retryInMs, MANUAL_SYNC_COOLDOWN_MS - 20_000);
  assert.strictEqual(h.log.filter((e) => e.vaultId === 'a' && e.phase !== 'running' && e.phase !== 'done').length, 0, 'a turned-away press emits no event: the glance keeps the real last outcome');

  h.advance(MANUAL_SYNC_COOLDOWN_MS); // the cooldown lapses
  assert.deepStrictEqual(h.sch.requestSync('a', { manual: true }), { accepted: true });
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a'], 'once the cooldown has lapsed a press mints again — exactly one per window');
});

test('the cooldown is per vault and within the 30–60 s acceptance band; a press on another vault is not held by it', async () => {
  assert.ok(MANUAL_SYNC_COOLDOWN_MS >= 30_000 && MANUAL_SYNC_COOLDOWN_MS <= 60_000);
  const h = harness();
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  h.advance(1000);
  assert.deepStrictEqual(h.sch.requestSync('b', { manual: true }), { accepted: true }, 'b was not pressed: no cooldown');
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'b']);
});

test('a press that joins a run already queued or in flight is free (no credential) and never turned away; the cooldown does not touch routine ticks', async () => {
  let release;
  const gate = new Promise((r) => { release = r; });
  const h = harness({ runSync: async (spec) => { h.calls.runSync.push(spec.vaultId); await gate; return { result: 'ok', ran: true }; } });
  h.sch.requestSync('a', { manual: true });
  await new Promise((r) => setTimeout(r, 10)); // a is in flight
  assert.strictEqual(h.sch.current(), 'a');
  assert.deepStrictEqual(h.sch.requestSync('a', { manual: true }), { accepted: true }, 'joins the in-flight run');
  assert.deepStrictEqual(h.sch.requestSync('b', { manual: true }), { accepted: true }, 'b is queued behind a');
  assert.deepStrictEqual(h.sch.requestSync('b', { manual: true }), { accepted: true }, 'a second press on queued b joins the queued entry');
  release(); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'b'], 'one credential per vault for the whole burst');
  // Routine ticks are not presses: inside a's cooldown the routine cadence still runs it (one credential per tick,
  // the cadence itself is the bound there).
  h.advance(1000);
  h.sch.tickAll(); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'b', 'a', 'b']);
});

test('the cooldown clock starts at the MINT, not the press: a press turned away by a cheaper gate (nothing minted) may be repeated and is answered honestly each time', async () => {
  const h = harness();
  h.io.helperReady = async () => ({ ok: false, sub: 'wrong-version', installed: '1.0.0' });
  for (let i = 0; i < 3; i += 1) {
    assert.deepStrictEqual(h.sch.requestSync('a', { manual: true }), { accepted: true }, `press ${i + 1} is accepted — no cooldown was ever started`);
    await settle(h.sch);
    assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'refused', reason: 'helper-not-ready' });
  }
  assert.deepStrictEqual(h.calls.refreshCred, [], 'nothing was minted, so nothing needed bounding');
});

test('a Repair is not subject to the cooldown (it is consented before anything is minted, and is often pressed right after the sync that found it owed)', async () => {
  const h = harness({ runState: () => ({ lastResult: 'abort-excessive-delete', resyncRequired: true }), confirmFirstUpload: async (arg) => { h.calls.consent.push(arg); return true; } });
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'blocked', reason: 'needs-repair' });
  h.advance(2000);
  assert.deepStrictEqual(h.sch.requestRepair('a'), { accepted: true });
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.runResync, ['a']);
});

// ---- consent before the mint ----------------------------------------------------------------------------------

test('the first-upload / Repair consent is asked BEFORE the mint: a declined consent leaves NO unspent credential at the server', async () => {
  const order = [];
  const h = harness({ runState: () => null, confirmFirstUpload: async () => { order.push('consent'); return false; } });
  h.io.refreshCred = async (v) => { order.push('mint'); h.calls.refreshCred.push(v); return { ok: true }; };
  h.sch.requestSync('a'); await settle(h.sch);
  assert.deepStrictEqual(order, ['consent'], 'consent was asked and, declined, nothing was minted');
  assert.deepStrictEqual(h.calls.refreshCred, []);
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'skipped', reason: 'consent-declined' });
  // Accepted: consent still precedes the mint, and the run follows.
  const h2 = harness({ runState: () => null, confirmFirstUpload: async () => { order.push('consent2'); return true; } });
  h2.io.refreshCred = async (v) => { order.push('mint2'); h2.calls.refreshCred.push(v); return { ok: true }; };
  h2.sch.requestSync('a'); await settle(h2.sch);
  assert.deepStrictEqual(order, ['consent', 'consent2', 'mint2']);
  assert.deepStrictEqual(h2.calls.runResync, ['a']);
});

// ---- refusal back-off --------------------------------------------------------------------------------------------

test('a repeatedly-refusing door backs off and does not flood: the race retry once, then routine ticks mint at most once per growing window', async () => {
  const h = harness({ runSync: authFailed, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a'], 'the first refusal is retried once (the lapsed-at-connect race); the second is the door refusing');
  const st = h.sch.refusalState('a');
  assert.strictEqual(st.failures, 1);
  assert.strictEqual(st.until, h.now() + REFUSAL_BACKOFF_BASE_MS, 'the first window is the base wait');
  assert.strictEqual(st.manualAllowed, true, 'a window opened by a routine tick keeps one deliberate attempt');
  assert.strictEqual(last(h.log, 'a').outcome.result, 'auth-failed-device', 'the refusal itself is surfaced as before');

  // Routine ticks INSIDE the window: nothing minted, no event, the surfaced refusal stands.
  const seen = h.log.length;
  for (let i = 0; i < 4; i += 1) { h.advance(60_000); h.sch.tickAll(); await settle(h.sch); }
  const aMints = () => h.calls.refreshCred.filter((v) => v === 'a');
  assert.deepStrictEqual(aMints(), ['a', 'a'], 'four routine ticks inside the window minted nothing for a');
  assert.deepStrictEqual(h.log.slice(seen).filter((e) => e.vaultId === 'a'), [], 'and emitted nothing for a (the last real outcome stands on the glance)');
  assert.ok(h.calls.refreshCred.includes('b'), "the other vault was not held by a's window — the back-off is per vault");

  // The window lapses: ONE attempt, no race retry (the door is on record as refusing), and the window doubles.
  h.advance(REFUSAL_BACKOFF_BASE_MS);
  h.sch.tickAll(); await settle(h.sch);
  assert.deepStrictEqual(aMints(), ['a', 'a', 'a'], 'exactly one credential for the due window — not two');
  assert.strictEqual(h.sch.refusalState('a').failures, 2);
  assert.strictEqual(h.sch.refusalState('a').until, h.now() + 2 * REFUSAL_BACKOFF_BASE_MS, 'the second wait is twice the first');

  // Many windows: the wait is capped, so a door that refuses for a day costs at most one credential an hour.
  let mints = aMints().length;
  for (let i = 0; i < 10; i += 1) {
    h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
    h.sch.tickAll(); await settle(h.sch);
    assert.strictEqual(aMints().length, mints + 1, `window ${i + 3}: one credential`);
    mints += 1;
    assert.ok(h.sch.refusalState('a').until - h.now() <= REFUSAL_BACKOFF_MAX_MS, 'the wait never exceeds the cap');
  }
});

test('a deliberate press against a refusing door gets ONE attempt per window; a second press in the same window is turned away with the wait, and a window opened by a failed press has no attempt at all', async () => {
  const h = harness({ runSync: authFailed, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch); // -> window 1 (routine-opened): one manual attempt available
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a']);
  h.advance(MANUAL_SYNC_COOLDOWN_MS); // (no press has minted yet, but keep the cooldown out of the picture)

  assert.deepStrictEqual(h.sch.requestSync('a', { manual: true }), { accepted: true }, "the window's one attempt");
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a', 'a'], 'the press minted once — and was NOT race-retried');
  const st = h.sch.refusalState('a');
  assert.strictEqual(st.failures, 2, 'its refusal lengthened the window');
  assert.strictEqual(st.manualAllowed, false, 'a window opened by a failed press has no further attempt');

  h.advance(MANUAL_SYNC_COOLDOWN_MS + 1); // past the press cooldown, so what answers is the back-off itself
  const v = h.sch.requestSync('a', { manual: true });
  assert.strictEqual(v.accepted, false);
  assert.strictEqual(v.reason, 'backing-off');
  assert.strictEqual(v.cause, 'auth-failed');
  assert.strictEqual(v.retryInMs, st.until - h.now(), 'the answer says when the next automatic try is');
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a', 'a'], 'a storm of presses now mints nothing');
  for (let i = 0; i < 10; i += 1) { h.advance(5000); assert.strictEqual(h.sch.requestSync('a', { manual: true }).accepted, false); }
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a', 'a']);

  // A Repair is a deliberate press too: same one-attempt rule, so it cannot be used to re-press through the window.
  assert.strictEqual(h.sch.requestRepair('a').accepted, false);

  // Inside the cooldown of the press that minted, the cooldown answers first (it is the sooner truth).
  const h2 = harness({ runSync: authFailed, credentialPath: () => 'device' });
  h2.sch.requestSync('a'); await settle(h2.sch);
  h2.sch.requestSync('a', { manual: true }); await settle(h2.sch);
  h2.advance(1000);
  assert.strictEqual(h2.sch.requestSync('a', { manual: true }).reason, 'sync-cooldown');
});

test('the door taking a credential again clears the back-off; releaseHolds (a sign-in, an unlock, a set-up change) opens it at once', async () => {
  let refuse = true;
  const h = harness({ runSync: async (spec) => (refuse ? authFailed(spec) : { result: 'ok', ran: true }), credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch);
  assert.ok(h.sch.refusalState('a'));
  refuse = false;
  h.advance(REFUSAL_BACKOFF_BASE_MS + 1);
  h.sch.tickAll(); await settle(h.sch);
  assert.strictEqual(h.sch.refusalState('a'), null, 'a run the door accepted clears the record');
  assert.strictEqual(last(h.log, 'a').outcome.result, 'ok');
  // And the next refusal starts a fresh episode: the race retry is available again.
  refuse = true;
  h.advance(60_000); h.sch.tickAll(); await settle(h.sch);
  assert.strictEqual(h.sch.refusalState('a').failures, 1);
  assert.strictEqual(h.calls.refreshCred.filter((v) => v === 'a').length, 2 + 1 + 2, 'the fresh episode retried its first refusal once');

  h.sch.releaseHolds();
  assert.strictEqual(h.sch.refusalState('a'), null);
  assert.deepStrictEqual(h.sch.requestSync('a'), { accepted: true }, 'a routine request goes through again');
  await settle(h.sch);
});

test('the account path backs off the same way: a persistent sign-in refusal no longer mints every tick while it waits for the person', async () => {
  const h = harness({ runSync: authFailed }); // no credentialPath => account path; the second refusal latches sign-in
  h.sch.requestSync('a'); await settle(h.sch);
  assert.strictEqual(last(h.log, 'a').outcome.result, 'auth-failed');
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a']);
  const aMints = () => h.calls.refreshCred.filter((v) => v === 'a');
  for (let i = 0; i < 4; i += 1) { h.advance(60_000); h.sch.tickAll(); await settle(h.sch); }
  assert.deepStrictEqual(aMints(), ['a', 'a'], 'no credential per tick against the refusing door');
  h.advance(REFUSAL_BACKOFF_BASE_MS); h.sch.tickAll(); await settle(h.sch);
  assert.deepStrictEqual(aMints(), ['a', 'a', 'a'], 'one per due window');
});

test('a queued routine entry that meets a freshly-opened window is skipped as backing-off (no mint), and that skip keeps the last state and is not a streak failure', async () => {
  const h = harness({ runSync: authFailed, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch);
  h.sch._queue.push({ vaultId: 'a', manual: false, repair: false }); // an entry queued before the window opened
  h.sch._pump(); await settle(h.sch);
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'skipped', reason: 'backing-off' });
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a'], 'nothing minted for it');
  assert.strictEqual(conditionForReason('skipped', 'backing-off'), null, 'keeps the refusal already on the glance');
  assert.strictEqual(streakFailureReason({ phase: 'skipped', reason: 'backing-off' }), null, 'not a failure: no run was attempted');
});

test('the refusal class is auth-failed + a refused session channel; the channel refusal is its OWN result, so a busy server is never answered with "sign in"', () => {
  assert.deepStrictEqual([...REFUSAL_RESULTS].sort(), ['auth-failed', 'channel-refused']);
  const rejected = 'Failed to create file system for "vault:/x": NewFs: couldn\'t connect SSH: ssh: rejected: administratively prohibited (open failed)';
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: rejected }).result, RESULT.CHANNEL_REFUSED);
  assert.strictEqual(classifyConnectionFailure('', rejected), RESULT.CHANNEL_REFUSED);
  assert.strictEqual(classifyConnectionFailure('', 'ssh: rejected: resource shortage (open failed)'), RESULT.CHANNEL_REFUSED, 'a server with no session slot free is the same class');
  // A real auth refusal keeps its own result (and its account remedies); a channel refusal must NOT borrow them.
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: 'ssh: unable to authenticate, attempted methods [none password]' }).result, RESULT.AUTH_FAILED);
  assert.strictEqual(OUTCOME_STATE['channel-refused'].state, STATE.PAUSED);
  assert.strictEqual(OUTCOME_STATE['channel-refused'].reason, 'sync-server-refusing');
  assert.notStrictEqual(OUTCOME_STATE['channel-refused'].reason, OUTCOME_STATE['auth-failed'].reason, 'a busy or refusing server is not a sign-in matter');
  const line = require('../src/main/manual-sync-copy').bodyForConditionReason('sync-server-refusing', 'Photos');
  assert.match(line, /limiting sync attempts/, 'the real cause, in plain words');
  assert.doesNotMatch(line, /[Ss]ign in( again)? (to|and)|enter the vault password/, 'never a remedy the person cannot carry out');
  assert.match(line, /won't help/, 'and it says so about the two people reach for');
  // Not the same thing: a local file that could not be opened, or the word "rejected" in a path, stays what it was.
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: 'ERROR : notes/rejected: open failed: permission denied' }).result, RESULT.ERROR);
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stdout: 'copied rejected-drafts/ssh notes.txt' }).result, RESULT.OK);
  // Severity order is kept: a changed identity outranks both.
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: 'knownhosts: key mismatch\nssh: rejected: administratively prohibited' }).result, RESULT.HOST_KEY_MISMATCH);
});

test('a refused session channel backs off exactly like an auth refusal — the flood is stopped for both', async () => {
  const channelRefused = async () => ({ result: 'channel-refused', ran: true, resyncRequired: null, needsAttention: true });
  const h = harness({ runSync: channelRefused, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch);
  const aMints = () => h.calls.refreshCred.filter((v) => v === 'a');
  assert.deepStrictEqual(aMints(), ['a', 'a'], 'the race retry once, then the door is on record');
  assert.strictEqual(h.sch.refusalState('a').failures, 1);
  for (let i = 0; i < 4; i += 1) { h.advance(60_000); h.sch.tickAll(); await settle(h.sch); }
  assert.deepStrictEqual(aMints(), ['a', 'a'], 'no credential per tick against the refusing door');
  assert.strictEqual(last(h.log, 'a').outcome.result, 'channel-refused', 'and the run keeps its own honest result');
});

test('a Repair (or a press) while a run is IN FLIGHT cannot slip past the window: the dispatch is the one authority', async () => {
  let release; const gate = new Promise((r) => { release = r; });
  const h = harness({ runSync: authFailed, runResync: async () => { await gate; return authFailed({ vaultId: 'a' }); }, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch); // window 1, routine-opened: one deliberate attempt available
  const m0 = h.calls.refreshCred.length;

  // The window's one attempt goes to a Repair; while it runs, press Repair again and again.
  assert.strictEqual(h.sch.requestRepair('a').accepted, true, "the window's one deliberate attempt");
  await new Promise((r) => setTimeout(r, 20));
  assert.strictEqual(h.sch.current(), 'a', 'that repair is in flight');
  const during = [];
  for (let i = 0; i < 6; i += 1) { during.push(h.sch.requestRepair('a')); await new Promise((r) => setTimeout(r, 5)); }
  release(); await settle(h.sch);
  const spent = h.calls.refreshCred.length - m0;
  assert.strictEqual(spent, 1, 'ONE credential for the attempt and every press piled on behind it — never a burst');
  // Each press is stopped either at the request (the attempt is already spent) or, if it got in before the mint,
  // at the dispatch gate — both honest, neither minting. What must never happen is a press that runs anyway.
  for (const v of during) {
    const stoppedAtRequest = v && v.accepted === false && v.reason === 'backing-off' && v.retryInMs > 0;
    assert.ok(stoppedAtRequest || h.log.some((e) => e.vaultId === 'a' && e.phase === 'skipped' && e.reason === 'backing-off'), 'every press piled on the in-flight run was answered, not run');
  }
  assert.strictEqual(h.sch.refusalState('a').manualAllowed, false, 'the window is closed to further deliberate attempts');
  // And it stays closed: more presses, in flight or not, mint nothing.
  const m1 = h.calls.refreshCred.length;
  for (let i = 0; i < 6; i += 1) { h.sch.requestRepair('a'); await settle(h.sch); }
  assert.strictEqual(h.calls.refreshCred.length, m1, 'still nothing');
});

test('an entry queued BEFORE the window opened is stopped at the dispatch gate, and a press cannot launder it into a free run', async () => {
  let release; const gate = new Promise((r) => { release = r; });
  const h = harness({ runSync: async (spec) => { if (spec.vaultId === 'b') { await gate; return { result: 'ok', ran: true }; } return authFailed(spec); }, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch);                    // a's window opens
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);  // and its one deliberate attempt is spent
  const m0 = h.calls.refreshCred.length;
  const e0 = h.log.length;

  h.sch.requestSync('b', { manual: true });                       // b takes the mutex and holds it
  await new Promise((r) => setTimeout(r, 20));
  // An entry for a that was queued before the window opened (the routine request would be refused outright now).
  h.sch._queue.push({ vaultId: 'a', manual: false, repair: false, press: false });
  h.advance(MANUAL_SYNC_COOLDOWN_MS + 1); // past the earlier press cooldown, so the back-off is what answers
  const v = h.sch.requestSync('a', { manual: true });              // ... and a press tries to upgrade it
  release(); await settle(h.sch);

  assert.strictEqual(h.calls.refreshCred.slice(m0).filter((x) => x === 'a').length, 0, 'the queued entry minted nothing for a, upgraded or not');
  assert.strictEqual(h.calls.refreshCred.length - m0, 1, 'only b, the vault that was actually free to run');
  const aEvents = h.log.slice(e0).filter((e) => e.vaultId === 'a');
  assert.ok(aEvents.some((e) => e.phase === 'skipped' && e.reason === 'backing-off'), 'the queued entry met the gate and said so');
  assert.ok(aEvents.every((e) => e.phase !== 'running'), 'and never ran');
  assert.strictEqual(v.accepted, false, 'the press itself was answered honestly too');
  assert.strictEqual(v.reason, 'backing-off');
});

// A routine request for a vault inside its window is refused before it is even queued, so the gate above is a
// backstop, not the everyday path — assert both halves so neither can quietly stop working.
test('a burst pressed the moment a window LAPSES is still bounded: the window owes one automatic and one deliberate attempt, and the burst gets no more', async () => {
  let release; const gate = new Promise((r) => { release = r; });
  const h = harness({
    listConfigured: () => [vault('a')],
    runSync: async (spec) => { await gate; return authFailed(spec); },
    runResync: async (spec) => { await gate; return authFailed(spec); },
    credentialPath: () => 'device',
  });
  h.io.listConfigured = () => [vault('a')];
  h.sch.requestSync('a'); release(); await settle(h.sch);   // the first episode opens a window
  const st = h.sch.refusalState('a');
  const m0 = h.calls.refreshCred.length;

  // The window lapses, and a routine tick claims its one automatic attempt — while that run is in flight, a
  // person hammers Repair. The presses coalesce onto ONE pending repair: at most one more attempt, never eight.
  h.advance(Math.max(0, st.until - h.now()) + 1000);
  let hold; const gate2 = new Promise((r) => { hold = r; });
  h.io.runSync = async (spec) => { await gate2; return authFailed(spec); };
  h.io.runResync = async (spec) => { await gate2; return authFailed(spec); };
  h.sch.tickAll();
  await new Promise((r) => setTimeout(r, 20));
  assert.strictEqual(h.sch.current(), 'a', 'the tick is in flight');
  const during = [];
  for (let i = 0; i < 8; i += 1) { during.push(h.sch.requestRepair('a')); await new Promise((r) => setTimeout(r, 2)); }
  hold(); await settle(h.sch);
  const spent = h.calls.refreshCred.length - m0;
  assert.ok(spent <= 2, `the lapsed window owes one automatic + one deliberate attempt; the burst cost ${spent}`);

  // With the refusal back on record the window is shut: a second burst costs nothing and every press is answered.
  const m1 = h.calls.refreshCred.length;
  h.advance(MANUAL_SYNC_COOLDOWN_MS + 1);
  const after = [];
  for (let i = 0; i < 8; i += 1) { after.push(h.sch.requestRepair('a')); await settle(h.sch); }
  assert.strictEqual(h.calls.refreshCred.length - m1, 0, 'not one credential for the second burst');
  assert.ok(after.every((v) => v && v.accepted === false && v.reason === 'backing-off' && v.retryInMs > 0), 'and each press was told the wait');
});

test('a routine request inside the window never reaches the queue', async () => {
  const h = harness({ runSync: authFailed, credentialPath: () => 'device' });
  h.sch.requestSync('a'); await settle(h.sch);
  const v = h.sch.requestSync('a');
  assert.strictEqual(v.accepted, false);
  assert.strictEqual(v.reason, 'backing-off');
  assert.ok(v.retryInMs > 0);
  assert.deepStrictEqual(h.sch._queue, [], 'nothing queued');
});

test('a bulk deliberate pass (a folder found again re-runs every vault) is not a press: it neither starts nor reads the cooldown', async () => {
  const h = harness();
  for (const c of ['a', 'b']) h.sch.requestSync(c, { manual: true, press: false });
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'b']);
  h.advance(1000);
  // The person's own press is not answered "you just used Sync now" for something they never pressed.
  assert.deepStrictEqual(h.sch.requestSync('a', { manual: true }), { accepted: true });
  await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'b', 'a']);
  // ... and that real press DOES start the cooldown.
  h.advance(1000);
  assert.strictEqual(h.sch.requestSync('a', { manual: true }).reason, 'sync-cooldown');
});

// ---- the manage page's answer ----------------------------------------------------------------------------------

test('the manage page: a turned-away "Sync now" resolves with the reason and a whole-seconds wait (never 0), an accepted one with ok', async () => {
  const V1 = '11111111-1111-4111-8111-111111111111';
  const answers = [];
  const io = {
    signedIn: () => true, listDevices: async () => ({ ok: true, devices: [] }), myIdentity: () => ({ status: 'ok', deviceId: 'd' }),
    myGrants: async () => ({ ok: true, grants: [] }), grantRecord: () => ({ status: 'ok', has: () => false }), reasonText: () => null,
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: '/p', enabled: true }], liveStatus: () => ({ vaults: [] }),
    endpoint: () => ({ serverHost: 'h', sftp: null }), remotePathFor: () => 'x',
    revokeGrant: async () => ({ ok: true }), revokeDevice: async () => ({ ok: true }), deleteDevice: async () => ({ ok: true }),
    dropLocalVault: () => {}, dropLocalIdentity: () => {}, afterChange: () => {},
    syncNow: () => answers.shift(),
  };
  const view = createManageView(io);
  answers.push({ accepted: true });
  assert.deepStrictEqual(await view.act({ kind: 'sync-now', vaultId: V1 }), { ok: true });
  answers.push({ accepted: false, reason: 'sync-cooldown', retryInMs: 30_400 });
  assert.deepStrictEqual(await view.act({ kind: 'sync-now', vaultId: V1 }), { ok: false, reason: 'cooldown', retryInSec: 31 });
  answers.push({ accepted: false, reason: 'backing-off', retryInMs: 240_000, cause: 'auth-failed' });
  assert.deepStrictEqual(await view.act({ kind: 'sync-now', vaultId: V1 }), { ok: false, reason: 'backing-off', retryInSec: 240, cause: 'auth-failed' }, 'the typed cause rides along so the page can say which refusal this is');
  answers.push({ accepted: false, reason: 'sync-cooldown', retryInMs: 1 });
  assert.deepStrictEqual(await view.act({ kind: 'sync-now', vaultId: V1 }), { ok: false, reason: 'cooldown', retryInSec: 1 }, 'never a 0 that reads as "try now"');
  answers.push(undefined); // a legacy caller that returns nothing is an accepted press
  assert.deepStrictEqual(await view.act({ kind: 'sync-now', vaultId: V1 }), { ok: true });
});

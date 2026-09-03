'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { SyncScheduler } = require('../src/main/sync-scheduler');

function deferred() { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; }
const vault = (id, over = {}) => ({ vaultId: id, vaultName: id.toUpperCase(), localFolder: `/folders/${id}`, remotePath: id.toUpperCase(), enabled: true, ...over });

function harness(over = {}) {
  const log = [];
  const calls = { runSync: [], runResync: [], verifyEligible: [], refreshCred: [], secureFolder: [], classify: [], firstUpload: [] };
  const io = {
    listConfigured: over.listConfigured || (() => [vault('a')]),
    runState: over.runState || (() => ({ lastResult: 'ok', resyncRequired: false })),
    session: over.session || (() => ({ locked: false, online: true, accountLive: true })),
    verifyEligible: over.verifyEligible || (async (v) => { calls.verifyEligible.push(v); return { ok: true, remotePath: v.toUpperCase() }; }),
    secureFolder: over.secureFolder || ((f) => { calls.secureFolder.push(f); return { ok: true }; }),
    classify: over.classify || ((f) => { calls.classify.push(f); return { ok: true }; }),
    refreshCred: over.refreshCred || (async (v) => { calls.refreshCred.push(v); return { ok: true }; }),
    confirmFirstUpload: over.confirmFirstUpload,
    vaultHasPassword: over.vaultHasPassword, // undefined by default -> remap inactive (existing sign-in behaviour)
    runSync: over.runSync || (async (spec) => { calls.runSync.push(spec.vaultId); return { result: 'ok', ran: true }; }),
    runResync: over.runResync || (async (spec) => { calls.runResync.push(spec.vaultId); return { result: 'resync-ok', ran: true }; }),
    onEvent: (vaultId, ev) => { log.push({ vaultId, ...ev }); },
  };
  return { sch: new SyncScheduler(io), log, calls };
}
async function settle(sch) { for (let i = 0; i < 300 && (sch._busy || sch._queue.length); i++) await new Promise((r) => setTimeout(r, 2)); }
const phases = (log, id) => log.filter((e) => e.vaultId === id).map((e) => e.phase);

test('normal completed vault -> runSync (not runResync), remote re-derived at run time', async () => {
  const { sch, calls, log } = harness();
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a']);
  assert.deepStrictEqual(calls.runResync, []);
  assert.strictEqual(calls.verifyEligible.length, 1, 'the run-time re-assert ran');
  assert.ok(phases(log, 'a').includes('running') && phases(log, 'a').includes('done'));
});

test('never-run vault -> INITIAL resync via runResync (never a plain runSync)', async () => {
  const { sch, calls } = harness({ runState: () => null }); // no state-db row
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runResync, ['a'], 'initial baseline goes through zero-loss resync');
  assert.deepStrictEqual(calls.runSync, []);
});

test("run-state 'unknown' is NOT never-run: skip state-uncertain, no run of either kind (no spurious resync)", async () => {
  // 'unknown' = the state store could not be read (a throwing read, or a no-key daemon). Treating it as
  // never-run would blind-dispatch an INITIAL RESYNC of a possibly-established vault; it must skip instead.
  const { sch, calls, log } = harness({ runState: () => 'unknown' });
  sch.requestSync('a'); await settle(sch);
  assert.deepStrictEqual(calls.runResync, [], 'no initial resync on an unknown run-state');
  assert.deepStrictEqual(calls.runSync, [], 'and no plain run either');
  const ev = log.find((e) => e.vaultId === 'a' && e.phase === 'skipped');
  assert.strictEqual(ev && ev.reason, 'state-uncertain');
});

test('interrupted first sync (row exists, lastResult null) is still the never-run branch', async () => {
  const { sch, calls } = harness({ runState: () => ({ lastResult: null, resyncRequired: false }) });
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runResync, ['a']);
  assert.deepStrictEqual(calls.runSync, []);
});

test('BLOCKED-after-run vault is NEVER auto-resynced and does no expensive work (cheap no-op)', async () => {
  const { sch, calls, log } = harness({ runState: () => ({ lastResult: 'abort-excessive-delete', resyncRequired: true }) });
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, []);
  assert.deepStrictEqual(calls.runResync, []);
  assert.deepStrictEqual(calls.verifyEligible, [], 'blocked short-circuits before the re-assert/refresh');
  assert.deepStrictEqual(calls.refreshCred, []);
  assert.deepStrictEqual(phases(log, 'a'), ['blocked']);
});

test('a deliberate Repair runs zero-loss resync and bypasses the block', async () => {
  const { sch, calls } = harness({ runState: () => ({ lastResult: 'abort-excessive-delete', resyncRequired: true }) });
  sch.requestRepair('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runResync, ['a']);
  assert.deepStrictEqual(calls.runSync, []);
});

test('fail-closed eligibility: locked / no-session / offline / uncertain each prevents any run', async () => {
  for (const [sess, phase] of [
    [{ locked: true, online: true, accountLive: true }, 'skipped'],
    [{ locked: false, online: true, accountLive: false }, 'skipped'],
    [{ locked: false, online: false, accountLive: true }, 'paused'],
    [{}, 'skipped'], // uncertain: missing fields
  ]) {
    const { sch, calls, log } = harness({ session: () => sess });
    sch.requestSync('a');
    await settle(sch);
    assert.deepStrictEqual(calls.runSync, [], `no run for ${JSON.stringify(sess)}`);
    assert.deepStrictEqual(calls.runResync, []);
    assert.strictEqual(phases(log, 'a')[0], phase);
  }
});

test('run-time re-assert failure (renamed / re-tiered / gone) refuses the run', async () => {
  const { sch, calls, log } = harness({ verifyEligible: async () => ({ ok: false, reason: 'tier-changed' }) });
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, []);
  assert.deepStrictEqual(calls.runResync, []);
  assert.strictEqual(phases(log, 'a').includes('refused'), true);
});

test('folder re-secure (E) or re-classify (F) failure refuses the run before any dispatch', async () => {
  const a = harness({ secureFolder: () => ({ ok: false, reason: 'acl-failed' }) });
  a.sch.requestSync('a'); await settle(a.sch);
  assert.deepStrictEqual(a.calls.runSync, []); assert.strictEqual(phases(a.log, 'a').includes('refused'), true);
  const b = harness({ classify: () => ({ ok: false, reason: 'overlaps-another-sync' }) });
  b.sch.requestSync('a'); await settle(b.sch);
  assert.deepStrictEqual(b.calls.runSync, []); assert.strictEqual(phases(b.log, 'a').includes('refused'), true);
});

test('secureFolder may be async: the Promise is awaited (an ok:true async secure still dispatches)', async () => {
  // The real glue applies + reads back a real ACL, so secureFolder returns a Promise. If it were not
  // awaited, a Promise reads as a truthy object with no `ok` and would wrongly refuse EVERY run.
  const a = harness({ secureFolder: async () => ({ ok: true }) });
  a.sch.requestSync('a'); await settle(a.sch);
  assert.deepStrictEqual(a.calls.runSync, ['a'], 'an async ok:true secure lets the run dispatch');
  // An async failure still refuses before any dispatch, carrying its reason (here the run-time re-share).
  const b = harness({ secureFolder: async () => ({ ok: false, reason: 'folder-problem' }) });
  b.sch.requestSync('a'); await settle(b.sch);
  assert.deepStrictEqual(b.calls.runSync, []);
  assert.ok(phases(b.log, 'a').includes('refused'));
  assert.strictEqual(b.log.find((e) => e.phase === 'refused' && e.vaultId === 'a').reason, 'folder-problem');
});

test('refresh-before-dispatch: a refresh failure fails closed (no run), surfaced as paused', async () => {
  const { sch, calls, log } = harness({ refreshCred: async () => ({ ok: false, reason: 'sign-in-needed' }) });
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, []);
  assert.strictEqual(phases(log, 'a').includes('paused'), true);
});

test('the first upload of a not-yet-consented config is gated fail-closed (decline => no run)', async () => {
  const { sch, calls, log } = harness({ runState: () => null, confirmFirstUpload: async () => false });
  sch.requestSync('a');
  await settle(sch);
  assert.deepStrictEqual(calls.runResync, [], 'no upload without consent');
  assert.strictEqual(phases(log, 'a').includes('skipped'), true);
});

test('GLOBAL mutex: a second vault does not run until the first completes (one cred at a time)', async () => {
  const d = deferred();
  const { sch, calls } = harness({
    listConfigured: () => [vault('a'), vault('b')],
    runSync: async (spec) => { calls.runSync.push(spec.vaultId); return spec.vaultId === 'a' ? d.promise : { result: 'ok' }; },
  });
  sch.requestSync('a');
  sch.requestSync('b');
  for (let i = 0; i < 20; i++) await new Promise((r) => setTimeout(r, 2)); // let a reach runSync, b stays queued
  assert.deepStrictEqual(calls.runSync, ['a'], 'b is queued while a holds the mutex');
  d.resolve({ result: 'ok' });
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a', 'b'], 'b runs only after a completes');
});

test('manual "Sync now" is ordered ahead of routine ticks in the queue', async () => {
  const d = deferred();
  const { sch, calls } = harness({
    listConfigured: () => [vault('a'), vault('b'), vault('c')],
    runSync: async (spec) => { calls.runSync.push(spec.vaultId); return spec.vaultId === 'a' ? d.promise : { result: 'ok' }; },
  });
  sch.requestSync('a');              // starts, holds the mutex
  await new Promise((r) => setTimeout(r, 6));
  sch.requestSync('b');              // routine, queued
  sch.requestSync('c', { manual: true }); // manual, jumps ahead of b
  d.resolve({ result: 'ok' });
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a', 'c', 'b'], 'manual c runs before routine b');
});

test('a request for a vault already in flight is coalesced (no second run)', async () => {
  const d = deferred();
  const { sch, calls } = harness({ runSync: async (spec) => { calls.runSync.push(spec.vaultId); return d.promise; } });
  sch.requestSync('a');
  await new Promise((r) => setTimeout(r, 6));
  sch.requestSync('a'); // in flight -> coalesced
  d.resolve({ result: 'ok' });
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a'], 'the second press joined the in-flight run, no second dispatch');
});

test('a vault requested while the mutex is busy is surfaced as "queued", not "syncing"', async () => {
  const d = deferred();
  const { sch, log, calls } = harness({
    listConfigured: () => [vault('a'), vault('b')],
    runSync: async (spec) => { calls.runSync.push(spec.vaultId); return spec.vaultId === 'a' ? d.promise : { result: 'ok' }; },
  });
  sch.requestSync('a');
  await new Promise((r) => setTimeout(r, 6));
  sch.requestSync('b');
  assert.strictEqual(phases(log, 'b')[0], 'queued', 'b reads queued while a runs');
  d.resolve({ result: 'ok' });
  await settle(sch);
});

test('a dep that THROWS surfaces as a terminal error, never a stuck "running"', async () => {
  const { sch, log } = harness({ runSync: async () => { throw new Error('dead channel'); } });
  sch.requestSync('a');
  await settle(sch);
  const p = phases(log, 'a');
  assert.strictEqual(p.includes('running'), true, 'it reached the run');
  assert.strictEqual(p.includes('done'), false, 'a throw is never reported as done');
  assert.strictEqual(p[p.length - 1], 'error', 'error is the terminal phase');
  assert.strictEqual(sch._busy, false, 'the mutex is released after the throw');
});

test('a run that could not execute ({ok:false}) is reported as error, not done', async () => {
  const { sch, log } = harness({ runSync: async () => ({ ok: false, ran: false, error: 'no-daemon' }) });
  sch.requestSync('a');
  await settle(sch);
  const p = phases(log, 'a');
  assert.strictEqual(p.includes('error'), true, 'an un-run outcome is an error');
  assert.strictEqual(p.includes('done'), false, 'ok:false is never done');
});

test('a Repair pressed while that vault is mid-run is NOT dropped — it queues and runs after', async () => {
  const d = deferred();
  const { sch, calls } = harness({ runSync: async (spec) => { calls.runSync.push(spec.vaultId); return d.promise; } });
  sch.requestSync('a');                    // routine run starts, holds the mutex
  await new Promise((r) => setTimeout(r, 6));
  sch.requestRepair('a');                  // deliberate Repair while 'a' is in flight — must survive coalescing
  d.resolve({ result: 'ok' });             // the routine run completes
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a'], 'the routine run ran once');
  assert.deepStrictEqual(calls.runResync, ['a'], 'the Repair survived and ran the zero-loss resync after');
});

test('confirmFirstUpload is told the kind: "initial" for a never-run vault, "repair" for a Repair', async () => {
  const seen = [];
  const a = harness({ runState: () => null, confirmFirstUpload: async (arg) => { seen.push(arg); return true; } });
  a.sch.requestSync('a'); await settle(a.sch);
  const b = harness({ runState: () => ({ lastResult: 'abort-excessive-delete', resyncRequired: true }), confirmFirstUpload: async (arg) => { seen.push(arg); return true; } });
  b.sch.requestRepair('a'); await settle(b.sch);
  assert.deepStrictEqual(seen, [{ vaultId: 'a', kind: 'initial' }, { vaultId: 'a', kind: 'repair' }]);
});

test('a tick continues past a BLOCKED vault to a healthy one in the same pass (one bad vault never halts the rest)', async () => {
  const { sch, calls, log } = harness({
    listConfigured: () => [vault('a'), vault('b')],
    runState: (v) => (v === 'a' ? { lastResult: 'abort-excessive-delete', resyncRequired: true } : { lastResult: 'ok', resyncRequired: false }),
  });
  sch.tickAll();
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['b'], 'a is blocked (no run); b still runs');
  assert.ok(phases(log, 'a').includes('blocked'), 'a reported blocked');
  assert.ok(phases(log, 'b').includes('done'), 'b reached done in the same pass');
});

test('a tick continues past a REFUSED vault to a healthy one (a refusal does not stall the queue)', async () => {
  const { sch, calls, log } = harness({
    listConfigured: () => [vault('a'), vault('b')],
    verifyEligible: async (v) => (v === 'a' ? { ok: false, reason: 'ineligible' } : { ok: true, remotePath: v.toUpperCase() }),
  });
  sch.tickAll();
  await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['b'], 'a is refused (no run); b still runs');
  assert.ok(phases(log, 'a').includes('refused'));
  assert.ok(phases(log, 'b').includes('done'));
});

test('a benign already-running refusal is a no-op, not an error (never cries wolf)', async () => {
  const { sch, log } = harness({ runSync: async () => ({ ok: false, ran: false, refused: 'already-running' }) });
  sch.requestSync('a');
  await settle(sch);
  const p = phases(log, 'a');
  assert.ok(p.includes('running'), 'reached the run');
  assert.ok(p.includes('noop'), 'the refusal is a no-op');
  assert.ok(!p.includes('error'), 'the benign refusal is NEVER mapped to error');
});

const { makeSession } = require('../src/main/scheduler-io');

test('a not-fresh run-state snapshot makes the session state-uncertain -> the scheduler SKIPS, never dispatches (fail-closed)', async () => {
  let fresh = false;
  const session = makeSession({ isAccountUsable: () => true, hasAccount: () => true, isOnline: () => true, snapshotFresh: () => fresh });
  const a = harness({ session });
  a.sch.requestSync('a'); await settle(a.sch);
  assert.deepStrictEqual(a.calls.runSync, [], 'a stale/failed run-state view blocks dispatch');
  assert.strictEqual(phases(a.log, 'a')[0], 'skipped', 'rendered as a state-uncertain skip');
  fresh = true;
  const b = harness({ session });
  b.sch.requestSync('a'); await settle(b.sch);
  assert.deepStrictEqual(b.calls.runSync, ['a'], 'a fresh view allows the dispatch');
});

test('a resync stopped mid-run by a transient refusal (a lock) reads as a calm skip, never a sync error', async () => {
  // A never-run vault takes the resync path; its per-step credential request is refused because the app locked
  // mid-baseline -> the engine returns a NOT-RUN outcome (result null + the reason). It must read as the same
  // calm skip the pre-dispatch lock gate emits, not a "couldn't sync" error.
  const { sch, log } = harness({
    runState: () => null, // never-run -> initial resync
    runResync: async () => ({ ok: true, ran: false, result: null, reason: 'paused-locked' }),
  });
  sch.requestSync('a');
  await settle(sch);
  const ph = phases(log, 'a');
  assert.ok(ph.includes('skipped'), 'a transient not-run is a skip');
  assert.ok(!ph.includes('error'), 'never a sync error for a lock mid-baseline');
  assert.ok(log.find((e) => e.vaultId === 'a' && e.phase === 'skipped' && e.reason === 'paused-locked'), 'the calm reason rides through');
});

test('a single auth-failed retries once with a fresh mint before latching a sign-in; the second latches', async () => {
  // 'auth-failed' from a run that executed may be a boundary race (a single-use credential spent at connect)
  // rather than a real session problem — retry ONCE (a fresh dispatch re-mints) before letting it read "sign in".
  let runs = 0;
  const { sch, log } = harness({ runSync: async () => { runs += 1; return { ok: true, ran: true, result: 'auth-failed' }; } });
  sch.requestSync('a');
  await settle(sch);
  const ph = phases(log, 'a');
  assert.strictEqual(runs, 2, 'the auth-failed was retried exactly once');
  assert.strictEqual(ph.filter((p) => p === 'running').length, 2, 'two dispatches: the run and its one retry');
  assert.ok(log.some((e) => e.phase === 'paused' && e.reason === 'retrying'), 'the first auth-failed reads as a calm retry, never an immediate sign-in latch');
  assert.ok(ph.includes('done'), 'the second consecutive auth-failed falls through to done -> sign-in-needed');
});

test('a persistent auth-failed for a PASSWORD-PROTECTED vault latches needs-unlock, not the sign-in latch', async () => {
  // Past its one retry, an auth-failed on a has_password vault is far more likely a rotated vault password
  // (the mint proof voided) than a dead account session, so it must route to "unlock this vault", not "sign in".
  let runs = 0;
  const { sch, log } = harness({
    runSync: async () => { runs += 1; return { ok: true, ran: true, result: 'auth-failed' }; },
    vaultHasPassword: () => true,
  });
  sch.requestSync('a');
  await settle(sch);
  assert.strictEqual(runs, 2, 'still retried exactly once before latching');
  const done = log.find((e) => e.vaultId === 'a' && e.phase === 'done');
  assert.ok(done, 'the second auth-failed latches via a completed event');
  assert.strictEqual(done.outcome && done.outcome.result, 'auth-failed-locked', 'the latching outcome is remapped so the model reads needs-unlock, not sign-in');
});

test('without a password (or no predicate), a persistent auth-failed still latches the plain sign-in outcome', async () => {
  let runs = 0;
  const { sch, log } = harness({
    runSync: async () => { runs += 1; return { ok: true, ran: true, result: 'auth-failed' }; },
    vaultHasPassword: () => false,
  });
  sch.requestSync('a');
  await settle(sch);
  const done = log.find((e) => e.vaultId === 'a' && e.phase === 'done');
  assert.ok(done, 'it latches via a completed event');
  assert.strictEqual(done.outcome && done.outcome.result, 'auth-failed', 'a passwordless vault keeps the sign-in-needed outcome');
});

test('an auth-failed cleared by a success gets a fresh one-shot retry next time', async () => {
  const results = ['auth-failed', 'ok', 'auth-failed', 'ok'];
  let i = 0;
  const { sch, log } = harness({ runSync: async () => ({ ok: true, ran: true, result: results[Math.min(i++, results.length - 1)] }) });
  sch.requestSync('a'); await settle(sch); // auth-failed -> retry -> ok (clears the one-shot)
  sch.requestSync('a'); await settle(sch); // auth-failed again -> retries again, then ok
  assert.ok(log.filter((e) => e.phase === 'paused' && e.reason === 'retrying').length >= 2, 'each episode gets its own retry once a success cleared the one-shot');
});

test('a Repair that hits the auth race retries AS a repair, never a blocked plain run', async () => {
  // A blocked-after-run vault: only a deliberate Repair may run. If the Repair's first attempt hits the auth
  // race and the retry dropped the repair flag, the retry would be a plain run -> the blocked gate -> a false
  // "repair owed again". The retry must stay a repair.
  let rs = 0;
  const { sch, calls, log } = harness({
    runState: () => ({ lastResult: 'ok', resyncRequired: true }),
    runResync: async () => { rs += 1; return { ok: true, ran: true, result: rs === 1 ? 'auth-failed' : 'resync-ok' }; },
    confirmFirstUpload: async () => true,
  });
  sch.requestRepair('a');
  await settle(sch);
  assert.strictEqual(rs, 2, 'auth-failed once, then retried AS a repair (runResync again)');
  assert.deepStrictEqual(calls.runSync, [], 'never fell back to a plain runSync');
  assert.ok(!phases(log, 'a').includes('blocked'), 'the retry never hit the blocked gate');
  assert.ok(phases(log, 'a').includes('done'), 'the repair retry completed');
});

// The real-transition test: a REAL LockState (never a hand-called markUnlocked / hand-flipped gate)
// drives the account-tier eligibility through a cold boot, an idle lock, and a resume. It proves the whole
// reverse edge on the real seam — a signed-in cold start dispatches AND mints a fresh credential; an idle lock
// pauses dispatch and fires the 'locked' signal the shell consumes to drop the account credential; a resume
// reopens dispatch, fires the DISTINCT 'account-active' signal (never the zero-knowledge 'unlocked') that kicks
// the re-mint, and never asserts a zero-knowledge key.
const { LockState } = require('../src/main/lock-state');

test('real LockState drives boot -> dispatch+mint -> idle-lock pause -> resume re-mint (no hand-called markUnlocked)', async () => {
  const events = [];
  const ls = new LockState({
    getWindow: () => null, getDaemon: () => null,
    onChange: (s) => events.push(s),
    timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 },
  });
  // The account-tier gate reads the REAL LockState (signed in + online + a fresh run-state view).
  const session = makeSession({ isAccountUsable: () => ls.isAccountUsable(), hasAccount: () => true, isOnline: () => true, snapshotFresh: () => true });
  const { sch, calls } = harness({ session });

  // COLD BOOT: markUnlocked() is NEVER called (the old dead gate needed it). appLocked defaults active, so a
  // signed-in account-tier user dispatches immediately — and the zero-knowledge key is absent throughout.
  assert.strictEqual(ls.isUnlocked(), false, 'no zero-knowledge key at boot');
  sch.requestSync('a'); await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a'], 'a cold, signed-in, never-hand-unlocked start dispatches');
  assert.deepStrictEqual(calls.refreshCred, ['a'], 'that run minted a fresh credential');

  // IDLE LOCK: the real lock() transaction pauses account-tier dispatch and fires the 'locked' signal the shell
  // consumes to drop the account credential; the zero-knowledge key stays absent (an idle lock asserts none).
  await ls.lock('idle');
  assert.ok(events.includes('locked'), "lock fires the 'locked' signal that drops the account credential");
  assert.strictEqual(ls.isUnlocked(), false, 'an idle lock never asserts a zero-knowledge key');
  sch.requestSync('a'); await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a'], 'no run dispatches while idle-locked');

  // RESUME: the real resumeAccount() reopens dispatch and fires the DISTINCT 'account-active' signal (never the
  // zero-knowledge 'unlocked') that kicks the re-mint. The next run mints a FRESH credential.
  ls.resumeAccount();
  assert.ok(events.includes('account-active'), "resume fires the distinct 'account-active' signal");
  assert.ok(!events.includes('unlocked'), "the account-tier resume never emits the zero-knowledge 'unlocked' event");
  sch.requestSync('a'); await settle(sch);
  assert.deepStrictEqual(calls.runSync, ['a', 'a'], 'resume lets the next run dispatch again');
  assert.deepStrictEqual(calls.refreshCred, ['a', 'a'], 're-mint: a FRESH credential is minted on the post-resume run');
});

'use strict';

/*
 * The endpoint gate: after a run that could not reach the sync server (or met a changed server identity), the
 * scheduler stops minting single-use credentials until the server answers a credential-free probe. Each test
 * counts the mints (refreshCred calls) — the whole point is that a shut door costs zero credentials per tick —
 * and checks that the surfaced reason is the REAL cause, never a credential-limit message.
 */

const test = require('node:test');
const assert = require('node:assert');
const { SyncScheduler, CONNECT_RESULTS, ENDPOINT_BACKOFF_BASE_MS, ENDPOINT_BACKOFF_MAX_MS } = require('../src/main/sync-scheduler');
const { StatusSink, conditionForReason, streakFailureReason } = require('../src/main/scheduler-io');
const { SyncStatusHub } = require('../src/main/sync-status-hub');
const { STATE, OUTCOME_STATE } = require('../src/main/sync-status-model');
const { classifyBisyncOutcome, classifyConnectionFailure, RESULT } = require('../src/daemon/bisync-outcome');
const tray = require('../src/main/tray-presentation');
const copy = require('../src/main/manual-sync-copy');

const vault = (id) => ({ vaultId: id, vaultName: id.toUpperCase(), localFolder: `/folders/${id}`, remotePath: id.toUpperCase(), enabled: true });

function harness(over = {}) {
  const log = [];
  const calls = { refreshCred: [], runSync: [], probe: 0 };
  let clock = 1_000_000;
  const io = {
    listConfigured: () => [vault('a'), vault('b')],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: false, online: true, accountLive: true }),
    verifyEligible: async (v) => ({ ok: true, remotePath: v.toUpperCase() }),
    secureFolder: () => ({ ok: true }),
    classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }),
    refreshCred: async (v) => { calls.refreshCred.push(v); return { ok: true }; },
    runSync: over.runSync || (async (spec) => { calls.runSync.push(spec.vaultId); return { result: 'ok', ran: true }; }),
    runResync: async () => ({ result: 'resync-ok', ran: true }),
    probeEndpoint: over.probeEndpoint === null ? undefined : (over.probeEndpoint || (async () => { calls.probe += 1; return { ok: true }; })),
    now: () => clock,
    onEvent: (vaultId, ev) => { log.push({ vaultId, ...ev }); },
  };
  const sch = new SyncScheduler(io);
  return { sch, log, calls, advance: (ms) => { clock += ms; }, setRun: (fn) => { io.runSync = fn; } };
}
async function settle(sch) { for (let i = 0; i < 300 && (sch._busy || sch._queue.length); i++) await new Promise((r) => setTimeout(r, 2)); }
const last = (log, id) => log.filter((e) => e.vaultId === id).pop();
const connectFailed = async (spec) => ({ result: 'connect-failed', ran: true, resyncRequired: null, needsAttention: true, vault: spec.vaultId });

test('a run that could not reach the server closes the gate: the next routine tick mints NOTHING and names the real cause', async () => {
  const h = harness({ runSync: connectFailed });
  h.sch.requestSync('a'); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a'], 'the first run minted once (the door was not known to be shut)');
  assert.strictEqual(last(h.log, 'a').phase, 'done');
  assert.strictEqual(last(h.log, 'a').outcome.result, 'connect-failed');
  assert.deepStrictEqual(h.sch.endpointState().failures, 1);

  h.sch.tickAll(); await settle(h.sch); // inside the back-off: no probe, no mint, for EVERY vault
  assert.deepStrictEqual(h.calls.refreshCred, ['a'], 'no second credential was minted');
  assert.strictEqual(h.calls.probe, 0, 'and no probe either — the back-off is still running');
  for (const id of ['a', 'b']) {
    const ev = last(h.log, id);
    assert.deepStrictEqual({ phase: ev.phase, reason: ev.reason }, { phase: 'paused', reason: 'sync-server-unreachable' }, `${id}: the real cause, not a credential message`);
  }
});

test('once the back-off is due, a routine tick PROBES without a credential; a shut door costs nothing and doubles the wait', async () => {
  let door = false;
  const h = harness({ runSync: connectFailed, probeEndpoint: async () => { h.calls.probe += 1; return door ? { ok: true } : { ok: false, reason: 'sync-server-unreachable' }; } });
  h.sch.requestSync('a'); await settle(h.sch); // failure 1 -> wait 5 min
  const mintsAfterFirst = h.calls.refreshCred.length;
  h.advance(ENDPOINT_BACKOFF_BASE_MS + 1);
  h.sch.tickAll(); await settle(h.sch);
  assert.strictEqual(h.calls.probe, 1, 'one probe for the whole tick — the first vault probed, the second was answered from the (now longer) back-off');
  assert.strictEqual(h.calls.refreshCred.length, mintsAfterFirst, 'a failed probe mints nothing');
  assert.strictEqual(h.sch.endpointState().failures, 2);
  assert.strictEqual(h.sch.endpointState().until, 1_000_000 + ENDPOINT_BACKOFF_BASE_MS + 1 + 2 * ENDPOINT_BACKOFF_BASE_MS, 'the second wait is twice the first');
  // Many failures: the wait is capped at an hour, so a server that is down for a day costs at most one probe an hour.
  for (let i = 0; i < 8; i += 1) { h.advance(ENDPOINT_BACKOFF_MAX_MS + 1); h.sch.tickAll(); await settle(h.sch); }
  const st = h.sch.endpointState();
  assert.ok(st.until - (1_000_000 + ENDPOINT_BACKOFF_BASE_MS + 1 + 9 * (ENDPOINT_BACKOFF_MAX_MS + 1)) <= ENDPOINT_BACKOFF_MAX_MS, 'the wait never exceeds the cap');
  assert.strictEqual(h.calls.refreshCred.length, mintsAfterFirst, 'still not one credential minted while the door stayed shut');

  // The door opens: the next due probe answers, the gate opens for the dispatch, the run mints and completes.
  door = true;
  h.setRun(async (spec) => { h.calls.runSync.push(spec.vaultId); return { result: 'ok', ran: true }; });
  h.advance(ENDPOINT_BACKOFF_MAX_MS + 1);
  h.sch.tickAll(); await settle(h.sch);
  assert.ok(h.calls.refreshCred.length > mintsAfterFirst, 'a mint follows an answering probe');
  assert.strictEqual(h.sch.endpointState().failures, 0, 'a run that reached the server opens the gate fully');
  assert.strictEqual(last(h.log, 'a').phase, 'done');
});

test('a deliberate press ignores the back-off and probes at once — but still never mints against a shut door', async () => {
  const h = harness({ runSync: connectFailed, probeEndpoint: async () => { h.calls.probe += 1; return { ok: false, reason: 'sync-server-unreachable' }; } });
  h.sch.requestSync('a'); await settle(h.sch);
  const mints = h.calls.refreshCred.length;
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  assert.strictEqual(h.calls.probe, 1, 'the press probed without waiting');
  assert.strictEqual(h.calls.refreshCred.length, mints, 'and minted nothing — the probe said the door is shut');
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'paused', reason: 'sync-server-unreachable' });
});

test('the probe distinguishes what answers: not an SSH server => a problem at once; a changed identity => a settled refusal that holds routine ticks', async () => {
  const h = harness({ runSync: connectFailed, probeEndpoint: async () => ({ ok: false, reason: 'sync-server-unverified' }) });
  h.sch.requestSync('a'); await settle(h.sch);
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'paused', reason: 'sync-server-unverified' });
  assert.deepStrictEqual(conditionForReason('paused', 'sync-server-unverified'), { state: STATE.SYNC_PROBLEM, reason: 'sync-server-unverified' }, 'reads as a problem immediately, not a calm retry');

  const m = harness({ runSync: async () => ({ result: 'host-key-mismatch', ran: true }), probeEndpoint: async () => ({ ok: false, reason: 'host-key-mismatch' }) });
  m.sch.requestSync('a'); await settle(m.sch);
  assert.strictEqual(m.sch.endpointState().reason, 'host-key-mismatch');
  m.sch.requestSync('a', { manual: true }); await settle(m.sch);
  assert.deepStrictEqual({ phase: last(m.log, 'a').phase, reason: last(m.log, 'a').reason }, { phase: 'refused', reason: 'host-key-mismatch' });
  assert.strictEqual(m.sch.held('a'), 'host-key-mismatch', 'a changed identity is settled: routine ticks stop until a person acts');
  const mints = m.calls.refreshCred.length;
  m.sch.tickAll(); await settle(m.sch);
  assert.strictEqual(m.calls.refreshCred.length, mints, 'held: nothing minted on the routine tick');
});

test('with no probe wired the back-off alone bounds the minting: one mint per due window, none inside it', async () => {
  const h = harness({ runSync: connectFailed, probeEndpoint: null });
  h.sch.requestSync('a'); await settle(h.sch);
  h.sch.tickAll(); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a'], 'inside the back-off: no mint');
  h.advance(ENDPOINT_BACKOFF_BASE_MS + 1);
  h.sch.tickAll(); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a', 'a'], 'due: exactly one more mint (the first vault), the second vault waits the longer back-off');
});

test('a probe that throws counts as unreachable (fail-closed: nothing minted); releaseHolds opens the gate (a changed address is tried at once)', async () => {
  const h = harness({ runSync: connectFailed, probeEndpoint: async () => { throw new Error('boom'); } });
  h.sch.requestSync('a'); await settle(h.sch);
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  assert.deepStrictEqual(h.calls.refreshCred, ['a']);
  assert.strictEqual(last(h.log, 'a').reason, 'sync-server-unreachable');
  h.sch.releaseHolds();
  assert.deepStrictEqual(h.sch.endpointState(), { failures: 0, reason: null, until: 0 });
});

test('the gate sits AFTER the cheaper refusals: a down helper is never mistaken for a down server, and nothing is probed for it', async () => {
  const h = harness({ runSync: connectFailed });
  h.sch.requestSync('a'); await settle(h.sch);
  h.sch._io.helperReady = async () => ({ ok: false });
  h.advance(ENDPOINT_BACKOFF_MAX_MS);
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, reason: last(h.log, 'a').reason }, { phase: 'paused', reason: 'helper-unavailable' });
  assert.strictEqual(h.calls.probe, 0, 'the helper gate answered first');
});

test('CONNECT_RESULTS is exactly the two connect-class outcomes; an auth failure or a conflict reopens the gate (the server WAS reached)', async () => {
  assert.deepStrictEqual([...CONNECT_RESULTS].sort(), ['connect-failed', 'host-key-mismatch']);
  const h = harness({ runSync: connectFailed });
  h.sch.requestSync('a'); await settle(h.sch);
  assert.strictEqual(h.sch.endpointState().failures, 1);
  h.setRun(async () => ({ result: 'conflict-keep-both', ran: true }));
  h.sch.requestSync('a', { manual: true }); await settle(h.sch);
  assert.strictEqual(h.sch.endpointState().failures, 0, 'a run that reached the server, whatever it found, opens the gate');
});

// ---- the status side: the cause survives the escalation ----

test('StatusSink: a connect-failed completion is a failure on the streak (not the completion that ends one), and its escalation names the sync server', () => {
  const notes = [];
  const hub = new SyncStatusHub({ locked: false, online: true, onNotify: (n) => notes.push(n) });
  hub.setVaults(['v1']);
  const sink = new StatusSink(hub);
  const vof = () => hub.current().vaults.find((v) => v.vault === 'v1');
  sink.apply('v1', { phase: 'running' });
  sink.apply('v1', { phase: 'done', outcome: { result: 'connect-failed', ran: true } });
  assert.deepStrictEqual({ state: vof().state, reason: vof().reason }, { state: STATE.PAUSED, reason: 'sync-server-unreachable' }, 'calm at first');
  sink.apply('v1', { phase: 'paused', reason: 'sync-server-unreachable' }); // the gate's back-off answer
  assert.deepStrictEqual(notes, [], 'no must-act yet');
  sink.apply('v1', { phase: 'paused', reason: 'sync-server-unreachable' }); // third consecutive
  assert.deepStrictEqual({ state: vof().state, reason: vof().reason }, { state: STATE.SYNC_PROBLEM, reason: 'sync-server-unreachable' }, 'escalated — and STILL the real cause, not "not-syncing"');
  assert.strictEqual(notes.length, 1, 'one must-act');
  assert.strictEqual(notes[0].reason, 'sync-server-unreachable');
  sink.apply('v1', { phase: 'running' });
  sink.apply('v1', { phase: 'done', outcome: { result: 'ok', ran: true } });
  assert.strictEqual(vof().state, STATE.UP_TO_DATE, 'a real completion ends the streak and the problem');
});

test('streakFailureReason: the mapping the sink relies on', () => {
  assert.strictEqual(streakFailureReason({ phase: 'done', outcome: { result: 'connect-failed' } }), 'sync-server-unreachable');
  assert.strictEqual(streakFailureReason({ phase: 'done', outcome: { result: 'ok' } }), null);
  assert.strictEqual(streakFailureReason({ phase: 'paused', reason: 'sync-server-unreachable' }), 'sync-server-unreachable');
  assert.strictEqual(streakFailureReason({ phase: 'paused', reason: 'sync-server-unverified' }), null, 'a problem at once, not a streak');
  assert.strictEqual(streakFailureReason({ phase: 'error', reason: 'run-failed' }), 'run-failed');
  assert.strictEqual(streakFailureReason({ phase: 'refused', reason: 'host-key-mismatch' }), null);
});

test('the model + surfaces: connect-failed reads paused/unreachable; the tray and the notification name the sync server and open Troubleshoot', () => {
  assert.deepStrictEqual(OUTCOME_STATE['connect-failed'], { state: STATE.PAUSED, reason: 'sync-server-unreachable' });
  assert.match(tray.REASON_DETAIL['sync-server-unreachable'], /sync server/);
  const names = { v1: 'Photos' };
  const item = tray.itemForVault({ vault: 'v1', reason: 'sync-server-unreachable' }, names);
  assert.strictEqual(item.kind, 'troubleshoot');
  assert.match(item.label, /Photos.*sync server can't be reached/);
  assert.ok(tray.HANDLED_ACTION_KINDS.includes('troubleshoot'), 'the kind is one the app handles');
  const item2 = tray.itemForVault({ vault: 'v1', reason: 'sync-server-unverified' }, names);
  assert.strictEqual(item2.kind, 'troubleshoot');
  assert.match(item2.label, /isn't a sync server/);
  for (const r of ['sync-server-unreachable', 'sync-server-unverified']) {
    const body = copy.bodyForConditionReason(r, 'Photos');
    assert.match(body, /sync server/); assert.match(body, /Troubleshoot/); assert.doesNotMatch(body, /limit/i, 'never the credential-limit message');
  }
});

// ---- the classifier: rclone's actual connect-failure wording, after the identity and auth signatures ----

test('classifyBisyncOutcome: refused / timed out / no such host => connect-failed; a mismatch or an auth refusal wrapped in the same prefix keeps its own result', () => {
  const refused = "2026/09/08 14:08:20 CRITICAL: Failed to create file system for \"vault:X\": NewFs: couldn't connect SSH: dial tcp 203.0.113.5:22: connectex: No connection could be made because the target machine actively refused it.";
  const timeout = "CRITICAL: Failed to create file system for \"vault:X\": NewFs: couldn't connect SSH: dial tcp 198.51.100.9:22: i/o timeout";
  const nohost = "CRITICAL: Failed to create file system for \"vault:X\": NewFs: couldn't connect SSH: dial tcp: lookup no-such-host.invalid: no such host";
  for (const text of [refused, timeout, nohost]) {
    const r = classifyBisyncOutcome({ code: 1, stdout: '', stderr: text });
    assert.deepStrictEqual(r, { result: RESULT.CONNECT_FAILED, resyncRequired: null, needsAttention: true }, text.slice(-40));
  }
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: "couldn't connect SSH: ssh: handshake failed: knownhosts: key mismatch" }).result, RESULT.HOST_KEY_MISMATCH);
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: "couldn't connect SSH: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password]" }).result, RESULT.AUTH_FAILED);
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stderr: 'NOTICE: dial tcp mentioned in a benign line' }).result, RESULT.OK, 'a clean exit is never re-labelled by a stray word');
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: 'ERROR : something else' }).result, RESULT.ERROR);
});

test('classifyConnectionFailure (the zero-loss resync first step): the same three verdicts, else null', () => {
  assert.strictEqual(classifyConnectionFailure('', "couldn't connect SSH: dial tcp 1.2.3.4:22: i/o timeout"), RESULT.CONNECT_FAILED);
  assert.strictEqual(classifyConnectionFailure('', 'knownhosts: key mismatch'), RESULT.HOST_KEY_MISMATCH);
  assert.strictEqual(classifyConnectionFailure('', 'ssh: unable to authenticate'), RESULT.AUTH_FAILED);
  assert.strictEqual(classifyConnectionFailure('', 'directory not found'), null);
});

test("credPrepareOutcome: the server's per-computer credential cap met mid-resync is a NOT-RUN skip carrying its own reason (named, never a bare error)", () => {
  const { credPrepareOutcome } = require('../src/daemon/sync-engine');
  assert.deepStrictEqual(credPrepareOutcome('device-cred-cap', true), { ran: false, result: null, reason: 'device-cred-cap', resyncRequired: true, needsAttention: false, preserved: 0 });
  assert.deepStrictEqual(conditionForReason('skipped', 'device-cred-cap'), { state: STATE.NEEDS_DECISION, reason: 'device-cred-cap' });
  assert.strictEqual(credPrepareOutcome('mint-failed', false).result, 'error', 'a plain mint hiccup stays the retryable error');
  assert.strictEqual(credPrepareOutcome('paused-locked', false).result, null, 'a transient authority refusal stays the calm skip');
});

test('a genuine safety abort keeps its needs-repair latch even when the stderr also mentions a transient network phrase (connect signature is tested last, and narrow)', () => {
  const deleteAbortWithNoise = 'ERROR : Safety abort: too many deletes (>50%, 6 of 8). Bisync aborted.\nNOTICE : connection reset by peer during an earlier list';
  const r = classifyBisyncOutcome({ code: 1, stdout: '', stderr: deleteAbortWithNoise });
  assert.strictEqual(r.result, RESULT.ABORT_EXCESSIVE_DELETE, 'the delete abort wins, not connect-failed');
  assert.strictEqual(r.resyncRequired, true, 'and its needs-repair latch is kept');
  // A plain connect failure with no abort signature is still connect-failed.
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: "couldn't connect SSH: dial tcp: i/o timeout" }).result, RESULT.CONNECT_FAILED);
});

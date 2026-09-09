'use strict';

/*
 * A refusal back-off must outlive walking away from the computer.
 *
 * The per-vault refusal back-off records a door that ANSWERED and turned this computer's credential away. That
 * is a fact about the SERVER. Returning to the laptop after an idle lock cannot have changed it — yet the resume
 * used to wipe the back-off for every vault, so each time the screen woke up the scheduler minted against the
 * still-refusing door again (twice per vault, in fact: an emptied window also un-blocks the one-shot auth retry).
 * A person who left their laptop for lunch came back to a fresh burst of spent credentials, counting against the
 * very limit that was refusing them.
 *
 * The whole real chain is exercised here — the real idle poller, the real lock state, the real scheduler — and
 * the shell's own wiring is checked against its source, so the behavioural proof below cannot pass while
 * index.js quietly goes back to clearing the window on a resume.
 *
 * The second half covers the fail-closed ordering in the outcome classifier: a data-safety abort carries a latch
 * that holds the vault until a person deliberately repairs it, and no connection phrase in the same output may
 * take the result and drop that latch with it.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const { SyncScheduler, REFUSAL_BACKOFF_BASE_MS, REFUSAL_BACKOFF_MAX_MS } = require('../src/main/sync-scheduler');
const { LockState } = require('../src/main/lock-state');
const { AutoLock } = require('../src/main/auto-lock');
const { classifyBisyncOutcome, classifyConnectionFailure, maskFileNames, RESULT } = require('../src/daemon/bisync-outcome');
const { turnedAwayBody } = require('../src/main/manual-sync-copy');

const vault = (id) => ({ vaultId: id, vaultName: id.toUpperCase(), localFolder: `/folders/${id}`, remotePath: id.toUpperCase(), enabled: true });
const CHANNEL_REFUSED = async () => ({ result: 'channel-refused', ran: true, resyncRequired: null, needsAttention: true });

// The scheduler over injected IO, with the account-tier session gate reading a REAL LockState.
function harness(lockState, over = {}) {
  const log = [];
  const calls = { refreshCred: [], runSync: [] };
  let clock = 1_000_000;
  const sch = new SyncScheduler({
    listConfigured: () => [vault('a')],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: !lockState.isAccountUsable(), online: true, accountLive: true }),
    verifyEligible: async (v) => ({ ok: true, remotePath: v.toUpperCase() }),
    secureFolder: () => ({ ok: true }),
    classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }),
    refreshCred: async (v) => { calls.refreshCred.push(v); return { ok: true }; },
    runSync: over.runSync || CHANNEL_REFUSED,
    runResync: async () => ({ result: 'resync-ok', ran: true }),
    credentialPath: over.credentialPath === null ? undefined : (over.credentialPath || (() => 'device')),
    vaultHasPassword: over.vaultHasPassword,
    now: () => clock,
    onEvent: (vaultId, ev) => { log.push({ vaultId, ...ev }); },
  });
  return { sch, log, calls, advance: (ms) => { clock += ms; }, now: () => clock };
}
async function settle(sch) { for (let i = 0; i < 300 && (sch._busy || sch._queue.length); i += 1) await new Promise((r) => setTimeout(r, 2)); }
const last = (log, id) => log.filter((e) => e.vaultId === id).pop();

// The real idle poller over the real lock state, with the poll and escalation timers handed to the test so an
// idle stretch and the return of input can be driven exactly.
function idlePoller(lockState) {
  const captured = { poll: null };
  const power = {
    idle: 0,
    _h: {},
    on(ev, cb) { (this._h[ev] = this._h[ev] || []).push(cb); },
    getSystemIdleTime() { return this.idle; },
  };
  const al = new AutoLock({
    powerMonitor: power,
    lockState,
    getWindow: () => null,
    idleThresholdMs: 1000,
    timers: { idlePollMs: 10, escalateAfterMs: 100_000 },
    setIntervalFn: (fn) => { captured.poll = fn; return { id: 'poll' }; },
    clearIntervalFn: () => {},
    setTimeoutFn: () => ({ id: 'esc' }),
    clearTimeoutFn: () => {},
  });
  al.start();
  return { power, poll: () => captured.poll() };
}

test('a vault on a refusal back-off survives an idle auto-resume: the real lock/resume chain re-mints NOTHING', async () => {
  const signals = [];
  const lockState = new LockState({
    getWindow: () => null,
    getDaemon: () => null,
    onChange: (s) => {
      signals.push(s);
      // The shell's own handler, wired exactly as index.js wires it: a resume lifts the holds and opens the
      // endpoint gate, then kicks a tick. It does NOT touch the refusal back-off.
      if (s === 'account-active') { sch.releaseHolds(); sch.tickAll(); }
    },
    timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 },
  });
  const h = harness(lockState);
  const { sch } = h;
  const { power, poll } = idlePoller(lockState);

  // The door refuses. One run, one race retry, and then the window is on record.
  sch.requestSync('a'); await settle(sch);
  assert.strictEqual(last(h.log, 'a').outcome.result, 'channel-refused');
  const beforeIdle = h.calls.refreshCred.length;
  const eventsBeforeIdle = h.log.length;
  assert.strictEqual(beforeIdle, 2, 'the refused run and its one race retry — and no more');
  const window = sch.refusalState('a');
  assert.ok(window && window.until > h.now(), 'the refusing door is on record with a live window');

  // AWAY: the idle clock crosses the threshold and the real lock transaction runs.
  power.idle = 2; poll();
  await new Promise((r) => setTimeout(r, 20));
  assert.ok(signals.includes('locked'), 'the idle stretch locked, through the real lock state');
  assert.strictEqual(lockState.isAccountUsable(), false);

  // BACK: input returns, the poller reverses the idle lock, and the shell handler runs for real.
  power.idle = 0; poll();
  await new Promise((r) => setTimeout(r, 20));
  await settle(sch);
  assert.ok(signals.includes('account-active'), 'the return of input resumed the account tier');
  assert.strictEqual(lockState.isAccountUsable(), true);

  // THE POINT: nothing was minted by coming back, and the window is intact.
  assert.strictEqual(h.calls.refreshCred.length, beforeIdle, 'the resume minted NOT ONE credential against the refusing door');
  const after = sch.refusalState('a');
  assert.deepStrictEqual(
    { failures: after.failures, until: after.until, reason: after.reason },
    { failures: window.failures, until: window.until, reason: window.reason },
    'the window survived the resume unchanged — same count, same end, same cause',
  );
  assert.strictEqual(h.log.length, eventsBeforeIdle, 'the post-resume tick emitted nothing at all: a vault inside its window is passed over before it is even queued');
  assert.deepStrictEqual({ phase: last(h.log, 'a').phase, result: last(h.log, 'a').outcome.result }, { phase: 'done', result: 'channel-refused' }, 'so the glance still carries the refusal, which IS the honest current answer');

  // And a whole afternoon of leaving and returning is still nothing: the old behaviour minted twice EACH time.
  for (let i = 0; i < 8; i += 1) {
    power.idle = 2; poll(); await new Promise((r) => setTimeout(r, 15));
    power.idle = 0; poll(); await new Promise((r) => setTimeout(r, 15));
    await settle(sch);
  }
  assert.strictEqual(h.calls.refreshCred.length, beforeIdle, 'eight more lock/resume cycles: still not one credential');
});

test('the window still ends on its own, and the ONE attempt it holds is still there for a person who presses', async () => {
  let refuse = true;
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  const h = harness(lockState, { runSync: async (spec) => (refuse ? CHANNEL_REFUSED(spec) : { result: 'ok', ran: true }) });
  const { sch } = h;
  sch.requestSync('a'); await settle(sch);
  const mints = () => h.calls.refreshCred.length;
  const opened = mints();

  // A deliberate press inside the window still gets through once (the window was opened by a routine tick).
  sch.releaseHolds(); // a resume, mid-window, changes none of this
  assert.deepStrictEqual(sch.requestSync('a', { manual: true }), { accepted: true }, 'the window keeps its one deliberate attempt across a resume');
  await settle(sch);
  assert.strictEqual(mints(), opened + 1);
  assert.strictEqual(sch.requestSync('a', { manual: true }).accepted, false, 'and only the one');

  // The window lapses on its own and a routine tick tries again — the back-off was a wait, never a wall.
  refuse = false;
  h.advance(REFUSAL_BACKOFF_BASE_MS * 4 + 1);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(last(h.log, 'a').outcome.result, 'ok');
  assert.strictEqual(sch.refusalState('a'), null, 'a run the door ACCEPTED clears the record — the one answer that does');
});

test('releaseHolds still does its own job: settled holds lift and the endpoint gate opens (a changed address is tried at once)', async () => {
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  const h = harness(lockState, { runSync: async () => ({ result: 'connect-failed', ran: true, resyncRequired: null, needsAttention: true }) });
  const { sch } = h;
  sch.requestSync('a'); await settle(sch);
  assert.ok(sch.endpointState().failures > 0, 'the door could not be reached: the endpoint gate closed');
  sch._held.set('a', 'device-revoked');

  sch.releaseHolds();
  assert.strictEqual(sch.held('a'), null, 'the settled hold lifted');
  assert.deepStrictEqual(sch.endpointState(), { failures: 0, reason: null, until: 0 }, 'and the endpoint gate opened, so a changed address is tried at once');
});

test('clearRefusalBackoff re-opens the door without also handing back the spent race retry', async () => {
  const authFailed = async () => ({ result: 'auth-failed', ran: true, resyncRequired: null, needsAttention: true });
  const lockState = () => new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });

  // ACCOUNT path: the episode KEEPS its spent one-shot across the refusal, so not clearing it is what holds
  // the re-opened door to a single credential.
  const acct = harness(lockState(), { runSync: authFailed, credentialPath: null });
  acct.sch.requestSync('a'); await settle(acct.sch);
  assert.strictEqual(acct.calls.refreshCred.length, 2, 'the refused run and its one race retry');
  assert.ok(acct.sch._authRetried.has('a'), 'this episode has spent its race retry');
  acct.sch.clearRefusalBackoff();
  assert.strictEqual(acct.sch.refusalState('a'), null, 'the window is forgotten: the next attempt is not held by it');
  assert.deepStrictEqual(acct.sch.requestSync('a'), { accepted: true });
  await settle(acct.sch);
  assert.strictEqual(acct.calls.refreshCred.length, 3, 'ONE credential for the re-opened door, not two');
  assert.ok(acct.sch.refusalState('a'), 'and a door still refusing goes straight back on record');

  // DEVICE path: the honest limit of that. A device auth refusal is routed to its own state and forgets the
  // one-shot on the way, so this vault DOES cost two. Not clearing `_authRetried` is what keeps two from being
  // the number everywhere — it is not a claim that one is the number here.
  const dev = harness(lockState(), { runSync: authFailed });
  dev.sch.requestSync('a'); await settle(dev.sch);
  assert.strictEqual(dev.calls.refreshCred.length, 2);
  assert.strictEqual(dev.sch._authRetried.has('a'), false, 'the device path already forgot the one-shot itself');
  dev.sch.clearRefusalBackoff();
  dev.sch.requestSync('a'); await settle(dev.sch);
  assert.strictEqual(dev.calls.refreshCred.length, 4, 'so the device path costs a run plus its retry — stated, not hidden');
});

test('the shell wires it that way: the presence resume releases holds only, and EVERY identity change goes through the one helper', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');

  // The presence resume: holds lifted, endpoint gate opened, back-off untouched. Checked over the WHOLE
  // handler statement, not one line, so moving the wipe onto the next line cannot slip past.
  const resumeAt = src.indexOf("if (s === 'account-active')");
  assert.ok(resumeAt > 0, 'the account-active branch is there');
  const resumeStmt = src.slice(resumeAt, src.indexOf('\n', src.indexOf('refreshTray();', resumeAt)));
  assert.match(resumeStmt, /releaseHolds\(\)/, 'the resume lifts the holds and opens the endpoint gate');
  assert.doesNotMatch(resumeStmt, /clearRefusalBackoff|syncIdentityChanged/, 'and never wipes the refusal back-off — the bug this fixes');

  // Everything that CHANGES this computer's sync identity goes through the one named helper. Naming each
  // function is the point: the regression this guards against is a new identity path that quietly calls
  // NEITHER method, which no grep for an existing call can ever see — it looks like no code at all.
  const identityChanges = [
    'async function resetDeviceIdentity() {',      // "reset this computer's sync identity"
    'async function runDeviceSetupAgain() {',      // "set this computer up again" — a FRESH identity + grants
    'async function tickDeviceRefresh() {',        // the held secret turned out to be retired
    'async function reconcileSurvivedRotation(',   // a rotation this side lost the answer to: stale or revoked
    '    register: async (label) => {',            // the wizard registering this computer for the first time
    '    dropLocalIdentity: () => {',              // the server ended the identity; the Computers window drops it
    'async function forgetServerRelationship(',    // the whole relationship with a server, identity included
    '    forget: async () => {',                   // the identity is gone whether or not a re-register follows
  ];
  for (const anchor of identityChanges) {
    const at = src.indexOf(anchor);
    assert.ok(at > 0, `still present: ${anchor.trim()}`);
    // The body runs to the closing brace at the anchor's own indentation.
    const indent = anchor.slice(0, anchor.search(/\S/));
    const end = src.indexOf(`\n${indent}}`, at);
    const body = src.slice(at, end === -1 ? src.length : end);
    assert.match(body, /syncIdentityChanged\(\)/, `an identity change clears holds AND the back-off: ${anchor.trim()}`);
  }

  // A genuine sign-IN clears the back-off — the refusals were answers about a credential from a session that
  // has ended — but it is NOT an identity change, so it must not lift the settled holds along with it.
  const signIn = src.split(/\r?\n/).find((l) => l.includes('hadAccountSession === false'));
  assert.ok(signIn, 'the sign-in edge is wired');
  assert.match(signIn, /clearCredentialRefusals\(\)/, 'signing in lets it try at once — which is what the status sentence promises');
  assert.doesNotMatch(signIn, /clearRefusalBackoff|releaseHolds|syncIdentityChanged/, 'but narrowly: a sign-in is not an identity change, lifts no settled hold, and never clears a server that is limiting attempts');

  // Outside those, the primitives are reached only through the helper, so no site can half-wire itself by
  // calling one of them directly and forgetting the other.
  const direct = src.split(/\r?\n/)
    .filter((l) => !l.trim().startsWith('//'))
    .filter((l) => /releaseHolds\(\)|clearRefusalBackoff\(\)/.test(l));
  assert.strictEqual(direct.length, 3, 'the resume, and the helper’s own two calls — nothing else');
});

test('a FLAPPING door keeps escalating: only a run the door demonstrably served clears the wait', async () => {
  // The bound is an escalating wait — 5, 10, 20, 40, then an hour — and it only escalates while the door's
  // refusals stay on record. Deciding "the door accepted a credential" by exclusion meant every result that
  // proves nothing wiped the record: unreachable, a changed identity, our own safety guard, the catch-all
  // error. A door alternating refuse/unreachable therefore never got past the first step, and the whole bound
  // degraded to one credential every five minutes for as long as the flapping lasted.
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  let result = 'channel-refused';
  const h = harness(lockState, { runSync: async () => ({ result, ran: true, resyncRequired: null, needsAttention: true }) });
  const { sch } = h;

  const waits = [];
  for (const flap of ['connect-failed', 'error', 'host-key-mismatch', 'needs-resync', 'path-too-long']) {
    result = 'channel-refused';
    h.advance(REFUSAL_BACKOFF_MAX_MS + 1);           // let whatever window stands lapse, so a tick may try
    sch.tickAll(); await settle(sch);
    const st = sch.refusalState('a');
    assert.ok(st, `the refusal is on record after a refusal (before a ${flap})`);
    waits.push(st.until - h.now());
    // ...and now the door flaps to something that says nothing about whether it would serve a credential.
    result = flap;
    h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
    sch.tickAll(); await settle(sch);
    assert.ok(sch.refusalState('a'), `a ${flap} proves nothing about the door, so the wait stands`);
  }
  // Each refusal lengthened the wait rather than starting over. Asserted as the actual schedule rather than
  // "non-decreasing", which a run of identical values would also satisfy — including the flat five minutes
  // this test exists to rule out.
  const shown = waits.map((w) => `${Math.round(w / 60000)}m`).join(' -> ');
  assert.strictEqual(waits[0], REFUSAL_BACKOFF_BASE_MS, `the first wait is one step (${shown})`);
  for (let i = 1; i < waits.length; i += 1) {
    const doubled = Math.min(waits[i - 1] * 2, REFUSAL_BACKOFF_MAX_MS);
    assert.strictEqual(waits[i], doubled, `each refusal doubles the wait, to the hour and no further (${shown})`);
  }
  assert.ok(waits[waits.length - 1] >= REFUSAL_BACKOFF_BASE_MS * 4, `and it climbed well past the first step, which the old rule never did (${shown})`);

  // The one thing that does clear it is a run the door actually served.
  result = 'ok';
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(sch.refusalState('a'), null, 'a served run clears it');
});

test('a run that finished cleanly serves, whatever else it had to say about a file', async () => {
  // Not every green run is called "ok". A run can finish, refresh the baseline, and still report that one file
  // was skipped for the length of its path. Naming only the happy results meant such a run left a vault waiting
  // out an hour it had already earned its way out of — and the shared connection gate shut behind it.
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  let outcome = { result: 'channel-refused', ran: true, code: 1, resyncRequired: null, needsAttention: true };
  const h = harness(lockState, { runSync: async () => outcome });
  const { sch } = h;
  sch.requestSync('a'); await settle(sch);
  assert.ok(sch.refusalState('a'), 'the door refused: on record');

  outcome = { result: 'path-too-long', ran: true, code: 0, resyncRequired: false, needsAttention: true };
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(sch.refusalState('a'), null, 'a run that exited cleanly served, so the wait is over');
  assert.strictEqual(sch.endpointState().failures, 0, 'and the server was plainly reached');
});

test("a data-safety abort proves the server was REACHED, even though it never proves the door served", async () => {
  // Deciding more than half the files would be deleted takes a full listing of the far side, which cannot be
  // had without talking to the server. Leaving these out of the reachability answer left the connection gate
  // shut — and every routine tick saying "can't reach the sync server" — about a server just listed.
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  let outcome = { result: 'connect-failed', ran: true, code: 1, resyncRequired: null, needsAttention: true };
  const h = harness(lockState, { runSync: async () => outcome });
  const { sch } = h;
  sch.requestSync('a'); await settle(sch);
  assert.ok(sch.endpointState().failures > 0, 'unreachable: the gate closed');

  outcome = { result: 'abort-excessive-delete', ran: true, code: 1, resyncRequired: true, needsAttention: true };
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(sch.endpointState().failures, 0, 'the abort required a listing, so the server was reached');
  // (this vault never had a refusal on record; the point of the test is the gate, above)
});

test('a check that answers lets the next attempt through, but does not restart the wait from the beginning', async () => {
  // The credential-free check and a real run are not the same test: the check is a bare connection, a run has
  // to authenticate and open the file subsystem as well. A server that answers one while refusing the other is
  // exactly what this gate is for — so treating a passing check as proof the door works held the wait at its
  // first step for as long as that lasted, which is the same collapse the per-vault wait was just fixed for.
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  const h = harness(lockState, { runSync: async () => ({ result: 'connect-failed', ran: true, code: 1, resyncRequired: null, needsAttention: true }) });
  const { sch } = h;
  sch._io.probeEndpoint = async () => ({ ok: true }); // the check keeps saying the server is there
  const waits = [];
  for (let i = 0; i < 5; i += 1) {
    h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
    sch.tickAll(); await settle(sch);
    waits.push(sch.endpointState().until - h.now());
  }
  const shown = waits.map((w) => `${Math.round(w / 60000)}m`).join(' -> ');
  for (let i = 1; i < waits.length; i += 1) {
    assert.ok(waits[i] > waits[i - 1] || waits[i - 1] >= 60 * 60 * 1000, `the wait keeps climbing while the runs keep failing (${shown})`);
  }
  assert.ok(waits[waits.length - 1] > waits[0], `and never sits at its first step (${shown})`);

  // And once a run genuinely works, the tally is gone.
  h.sch._io.runSync = async () => ({ result: 'ok', ran: true, code: 0, resyncRequired: false, needsAttention: false });
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(sch.endpointState().failures, 0, 'a run the server served clears it');
});

test('the endpoint gate is opened only by a run that demonstrably REACHED the server', async () => {
  // A weaker fact than "served", and deliberately so: a door that turned a credential away was plainly
  // reached. But a generic error proves nothing here either, and must not re-open the gate.
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  let result = 'connect-failed';
  const h = harness(lockState, { runSync: async () => ({ result, ran: true, resyncRequired: null, needsAttention: true }) });
  const { sch } = h;
  sch.requestSync('a'); await settle(sch);
  assert.ok(sch.endpointState().failures > 0, 'the door could not be reached: the gate closed');

  result = 'error';
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1); sch.tickAll(); await settle(sch);
  assert.ok(sch.endpointState().failures > 0, 'an unclassified failure says nothing about reachability, so the gate stays shut');

  result = 'channel-refused';
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1); sch.tickAll(); await settle(sch);
  assert.strictEqual(sch.endpointState().failures, 0, 'but a door that ANSWERED and refused was plainly reached');
  assert.ok(sch.refusalState('a'), 'and that same answer is what puts it on the refusal record');
});

test("a run stopped by this computer's OWN safety guard neither opens the refusal window nor tears it down", async () => {
  // Naming the abort (the more serious event) must not cost the refusing door its place on record. Otherwise
  // each deliberate Repair press starts the wait again from the bottom of the schedule and mints against a
  // server that is still refusing — the flood, re-entered through the repair button.
  const lockState = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  let result = 'channel-refused';
  const h = harness(lockState, { runSync: async () => ({ result, ran: true, resyncRequired: result.startsWith('abort') ? true : null, needsAttention: true }) });
  const { sch } = h;
  sch.requestSync('a'); await settle(sch);
  const opened = sch.refusalState('a');
  assert.ok(opened, 'the refusing door is on record');

  // The next run is refused AND trips the delete guard, so it is named for the abort.
  result = 'abort-excessive-delete';
  h.advance(REFUSAL_BACKOFF_BASE_MS * 8);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(last(h.log, 'a').outcome.result, 'abort-excessive-delete', 'the mass delete is what the person is told about');
  const after = sch.refusalState('a');
  assert.ok(after, 'and the door is still on record — an abort is not the server accepting a credential');
  assert.strictEqual(after.failures, opened.failures, 'neither lengthened by it nor reset to the bottom of the schedule');

  // A run the door actually serves still clears it, exactly as before.
  result = 'ok';
  h.advance(REFUSAL_BACKOFF_BASE_MS * 8);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(sch.refusalState('a'), null, 'the one answer that does clear it');
});

// --- what a file is CALLED must never decide what the run is reported to have done ------------------------

test('re-entering the vault password lets it try at once — and clears nothing else', async () => {
  // The app says, in as many words, "if its status asks you to sign in or enter the vault password, doing that
  // lets it try at once". The sign-in half became true in the last change; this is the other half. A person who
  // does exactly what the status asks must not watch nothing happen.
  const ls = () => new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  const h = harness(ls(), { credentialPath: null, vaultHasPassword: () => true });
  h.sch._noteRefusal('a', false, 'auth-failed');
  assert.ok(h.sch.refusalState('a'), 'the vault is waiting');

  h.sch.clearVaultPasswordRefusals(['a']);
  assert.strictEqual(h.sch.refusalState('a'), null, 'the password it was waiting on has been given, so the wait is over');

  // And it is narrow. Each of these was waiting on something else, and a vault password answers none of them.
  const others = [
    ['a server limiting attempts', harness(ls()), 'channel-refused'],
    ["this computer's device identity", harness(ls()), 'auth-failed'],
    ['the account session', harness(ls(), { credentialPath: null }), 'auth-failed'],
  ];
  for (const [what, other, reason] of others) {
    other.sch._noteRefusal('a', false, reason);
    other.sch.clearVaultPasswordRefusals(['a']);
    assert.ok(other.sch.refusalState('a'), `${what}: a vault password is no answer to this, so the wait stands`);
  }
  // A vault that was never waiting, and a caller with nothing to say, are both no-ops rather than errors.
  const quiet = harness(ls());
  quiet.sch.clearVaultPasswordRefusals(['a', 'b']);
  quiet.sch.clearVaultPasswordRefusals(undefined);
  assert.strictEqual(quiet.sch.refusalState('a'), null);
});

test('a vault waiting on its password is offered up so the shell can notice the password being given', async () => {
  // There is no event for "a vault was unlocked" — the page simply holds an unlock and main asks for the proof
  // only when it is about to spend it. So the wait has to be visible from outside, with the moment it started,
  // and what is handed over is an id and a timestamp: nothing secret leaves the scheduler.
  const ls = () => new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });
  const h = harness(ls(), { credentialPath: null, vaultHasPassword: () => true });
  const at = h.now();
  h.sch._noteRefusal('a', false, 'auth-failed');

  const waiting = h.sch.vaultsAwaitingPassword();
  assert.deepStrictEqual(waiting, [{ vaultId: 'a', since: at }], 'the vault, and when it started waiting');
  assert.deepStrictEqual(Object.keys(waiting[0]).sort(), ['since', 'vaultId'], 'and nothing else — no secret rides along');

  // A wait that has lapsed is not offered: there is nothing left to shorten.
  h.advance(REFUSAL_BACKOFF_MAX_MS + 1);
  assert.deepStrictEqual(h.sch.vaultsAwaitingPassword(), [], 'a lapsed wait needs no answer');

  // Nor are the waits that a password could not answer.
  for (const [what, other, reason] of [
    ['a server limiting attempts', harness(ls()), 'channel-refused'],
    ["this computer's device identity", harness(ls()), 'auth-failed'],
    ['the account session', harness(ls(), { credentialPath: null }), 'auth-failed'],
  ]) {
    other.sch._noteRefusal('a', false, reason);
    assert.deepStrictEqual(other.sch.vaultsAwaitingPassword(), [], `${what}: a vault password is no answer to it`);
  }
});

test('the shell asks only WHEN a vault was unlocked, never for the password, and acts only on a newer unlock', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const at = src.indexOf('async function pullVaultUnlockStamp(');
  assert.ok(at > 0, 'the stamp-only probe exists');
  const body = src.slice(at, src.indexOf('\n}', at));
  assert.match(body, /vaultPasswordTimestamp/, 'it reads the moment of the unlock');
  // The probe must hand back a NUMBER and nothing else. Asserting the shape it returns, rather than that one
  // particular way of returning a password is absent, is what actually holds the line here.
  assert.match(body, /return typeof ts === 'number'/, 'it answers with a number');
  //  excludes vaultPasswordTimestamp, which it does legitimately return: the moment, never the secret.
  assert.doesNotMatch(body, /return[^;]*vaultPassword/, 'and the password itself never leaves the page');
  assert.match(body, /JSON\.stringify\(vaultId\)/, 'the vault id is bound into the page, not spliced as text');

  const clearAt = src.indexOf('async function clearWaitsAnsweredByAnUnlock(');
  assert.ok(clearAt > 0, 'and the wait is ended where that is noticed');
  const clearBody = src.slice(clearAt, src.indexOf('\n}', clearAt));
  assert.match(clearBody, /stamp > since/, 'strictly newer: the unlock the door already refused is not a fresh answer');
  assert.match(clearBody, /clearVaultPasswordRefusals\(\[vaultId\]\)/, 'and only that vault stops waiting');
  // It has to actually run on the routine pass, or none of the above happens.
  assert.match(src, /await clearWaitsAnsweredByAnUnlock\(\);/, 'the routine pass looks before it dispatches');
});

test('the shell clears the wait at the moment the re-proof lands', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const at = src.indexOf('if (out.granted.length)');
  assert.ok(at > 0, 'the re-proof success branch is there');
  const branch = src.slice(at, at + 600);
  assert.match(branch, /clearVaultPasswordRefusals\(out\.granted\)/, 'the vaults whose password was just re-proved stop waiting');
});

test('a hostile FILE NAME cannot make the run report a changed server, a mass delete, or a repair', () => {
  // The names in a vault are not ours. In a shared vault they arrive from other members, and the sync tool
  // logs each one verbatim in its own per-file error lines. A bare-substring signature therefore handed anyone
  // who could add a file the power to decide this computer's verdict about the RUN — worst of all a changed
  // server identity, which stops syncing for every vault at once and needs a person to clear it.
  const attacks = {
    'docs/key mismatch.txt': RESULT.HOST_KEY_MISMATCH,
    'knownhosts: key mismatch.txt': RESULT.HOST_KEY_MISMATCH,
    'docs/max delete list.md': RESULT.ABORT_EXCESSIVE_DELETE,
    'notes/all files were changed.doc': RESULT.ABORT_ALL_CHANGED,
    'logs/critical error.log': RESULT.NEEDS_RESYNC,
    'archive/must run --resync notes.txt': RESULT.NEEDS_RESYNC,
    'a/path too long.txt': RESULT.PATH_TOO_LONG,
  };
  for (const [name, wouldHaveBeen] of Object.entries(attacks)) {
    for (const line of [
      `2026/09/03 02:00:07 ERROR : ${name}: Failed to copy: permission denied`,   // the shapes rclone really writes
      `ERROR : ${name}: Failed to delete: permission denied`,                  // and a different one
    ]) {
      const o = classifyBisyncOutcome({ code: 1, stderr: line });
      assert.strictEqual(o.result, RESULT.ERROR, `a file called "${name}" is just a failed run, not ${wouldHaveBeen}`);
      assert.strictEqual(o.resyncRequired, null, `and it fabricates no repair: "${name}"`);
    }
  }
});

test('the run wrapping a FILE cause in its own verdict keeps that verdict — the dangerous direction', () => {
  // The tool reports a run-level failure by wrapping whatever caused it: "Bisync critical error: failed to copy
  // Path1 to Path2: ...". That reads exactly like a message about one file, so taking the name off the front of
  // it would throw away the verdict itself. Losing a baseline is far worse than naming a cause wrongly: nothing
  // would latch the repair, and the vault would go on running delete-capable syncs as if all were well.
  for (const wrapped of [
    'ERROR : Bisync critical error: failed to copy Path1 to Path2: context canceled',
    'ERROR : Bisync critical error: failed to delete file: connection lost',
    'ERROR : Bisync critical error: Failed to update listing: i/o error',
    'ERROR : Bisync aborted. Must run --resync to recover.',
  ]) {
    const o = classifyBisyncOutcome({ code: 1, stderr: wrapped });
    assert.strictEqual(o.result, RESULT.NEEDS_RESYNC, `the run's own verdict survives: ${wrapped.slice(0, 56)}`);
    assert.strictEqual(o.resyncRequired, true, 'and the repair it owes is latched');
    assert.strictEqual(maskFileNames(wrapped), wrapped, 'the verdict line is left whole');
  }
  // A safety abort wrapping a file cause the same way.
  const abort = 'ERROR : Safety abort: too many deletes (>50%, 3 of 4). Bisync aborted.';
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: abort }).resyncRequired, true);
  // But a FILE merely NAMED after one of those words is still just a file: what tells them apart is that the
  // run's own verdict is never a path — no folder in it, and no extension on the end.
  for (const name of ['Bisync critical error.log', 'shared/Bisync aborted.md']) {
    const line = `2026/09/03 02:00:07 ERROR : ${name}: corrupted on transfer: sizes differ 5 vs 6`;
    assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: line }).result, RESULT.ERROR, `a file called "${name}" says nothing about the run`);
  }
});

test('a planted name cannot steer WHICH file is named — or how big it is said to be', () => {
  // The file named to a person is also the file whose size is read, and that size is what decides whether the
  // app says a vault is out of room. Finding the name by searching the text again would find whichever line
  // matched first — and someone who can add a file to a shared vault chooses that. A small decoy would hide a
  // genuine "out of space"; a large one would invent it. The name now always comes from the SAME line that
  // decided the outcome.
  const decoy = 'ERROR : shared/partial file rename failed.txt: Failed to copy: permission denied';
  const real = 'ERROR : holiday/video.bin.58de1a09.partial: partial file rename failed: Move Rename failed: file does not exist';
  const o = classifyBisyncOutcome({ code: 1, stderr: `${decoy}\n${real}` });
  assert.strictEqual(o.result, RESULT.UPLOAD_NOT_STORED);
  assert.strictEqual(o.detail.file, 'video.bin', 'the file the run actually failed on');
  assert.strictEqual(o.failedPath, 'holiday/video.bin', 'and its real path, not the decoy sitting above it');

  // The same for a stated size limit: the number quoted must come from the failure that was classified.
  const sizeDecoy = 'ERROR : notes/exceeds the 1 MB upload limit.txt: Failed to copy: permission denied';
  const sizeReal = 'ERROR : big.bin: Failed to copy: sftp: "file exceeds the 25 MB per-file limit" (SSH_FX_FAILURE)';
  const p = classifyBisyncOutcome({ code: 1, stderr: `${sizeDecoy}\n${sizeReal}` });
  assert.strictEqual(p.result, RESULT.FILE_TOO_LARGE);
  assert.strictEqual(p.detail.file, 'big.bin', 'the file the server refused');
  assert.strictEqual(p.detail.maxBytes, 25 * 1024 * 1024, 'and the limit IT stated, not the one a name spelled out');
});

test('KNOWN RESIDUAL: a name that mimics the run\'s own verdict can only ever ask for a repair, never silence one', () => {
  // Where this stops. A line reading `ERROR : Safety abort: all files were changed.txt: corrupted on transfer`
  // and the real `ERROR : Safety abort: all files were changed on Path1 "..."` are the SAME shape: the tool
  // writes names into its lines unescaped, so at this point they are genuinely indistinguishable. Protecting
  // the real verdict — which must never be lost, or a mass delete goes unlatched — necessarily protects a name
  // spelled to look like one.
  //
  // What matters is WHICH WAY it fails, and the answer is the safe one: such a name can only fabricate a
  // repair that was not owed. It can never drop a repair that was, and never raise the changed-server alarm
  // that would stop syncing for every vault. Both of those are pinned below.
  //
  // The real fix is structural — a log format that separates the name from the message and escapes what a name
  // contains — and is out of this change's scope.
  const mimic = 'ERROR : Safety abort: all files were changed.txt: corrupted on transfer: sizes differ 5 vs 6';
  const o = classifyBisyncOutcome({ code: 1, stderr: mimic });
  assert.strictEqual(o.resyncRequired, true, 'at worst it asks for a repair — the cautious direction');
  assert.notStrictEqual(o.result, RESULT.HOST_KEY_MISMATCH, 'and never the alarm that stops every vault');

  // The two that must hold whatever a name says:
  //   a real abort keeps its latch even with a mimicking name in the same run,
  const withMimic = `${mimic}\nERROR : Safety abort: too many deletes (>50%, 3 of 4). Bisync aborted.`;
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: withMimic }).resyncRequired, true, 'a genuine abort is never silenced by a name');
  //   and no name reaches the changed-server alarm, because that one is not protected by the deny-list.
  // A name reaches the alarm only by BOTH opening with one of the run's exact verdict phrases AND carrying a
  // whole ssh handshake chain — at which point it is word for word what a real one looks like, because a
  // genuine critical error can itself be a failed handshake. Everything short of that is stopped:
  for (const name of ['knownhosts: key mismatch.txt', 'shared/knownhosts: key mismatch', 'Bisync: knownhosts: key mismatch.log', 'ssh: handshake failed: knownhosts: key mismatch.txt']) {
    const line = `ERROR : ${name}: corrupted on transfer: sizes differ 5 vs 6`;
    assert.notStrictEqual(classifyBisyncOutcome({ code: 1, stderr: line }).result, RESULT.HOST_KEY_MISMATCH, `no name raises the alarm: ${name}`);
  }
});

test('a name whose break is a carriage return or a unicode separator stays inside its own line', () => {
  // A name can carry characters that end a line for some readers and not others. Those are flattened first, so
  // the name stays inside its own message and the half after the break cannot pose as a fresh line.
  //
  // Note what this does NOT cover: a name containing a real newline genuinely does start a line, and its
  // author writes every character of it, the level included. That one is recorded as a residual below —
  // asserting it here would be claiming a guarantee this does not have.
  // Two defences, both real. A break that is a carriage return or a unicode separator is flattened, so the
  // name never leaves its own message:
  for (const name of ['a\rknownhosts: key mismatch', 'a\rERROR : Safety abort: too many deletes (>50%, 9 of 9). Bisync aborted.', 'a\u2028ERROR : Bisync critical error', 'a\u0085ERROR : cannot find prior Path1']) {
    const o = classifyBisyncOutcome({ code: 1, stderr: `ERROR : ${name}: Failed to copy: permission denied` });
    assert.strictEqual(o.result, RESULT.ERROR, `flattened, so still just a name: ${JSON.stringify(name)}`);
    assert.strictEqual(o.resyncRequired, null, 'and fabricates no repair');
  }
  // And a real newline that does start a line still says nothing, so long as it does not carry the level:
  for (const name of ['evil\nknownhosts: key mismatch.txt', 'evil\nSafety abort: too many deletes (>50%, 9 of 9). Bisync aborted..txt', 'x\nBisync critical error.log', 'y\ncannot find prior Path1.txt']) {
    const o = classifyBisyncOutcome({ code: 1, stderr: `ERROR : ${name}: Failed to copy: permission denied` });
    assert.strictEqual(o.result, RESULT.ERROR, `a split name is still just a name: ${JSON.stringify(name)}`);
    assert.strictEqual(o.resyncRequired, null, 'and fabricates no repair');
  }
});

test('taking the name out is what stops the ones an anchor cannot: the two layers cover each other', () => {
  // Some signatures are distinctive enough to be matched anywhere ("knownhosts: key mismatch" is not a phrase
  // that turns up by accident), so they are not anchored to the start of a line — and a file can be named
  // exactly that. Masking is what answers those. Conversely a per-file message the mask does not recognise
  // leaves the name in place, and the anchor is what answers that. Neither layer is redundant.
  // This one no anchor can help with: "knownhosts: key mismatch" is the ssh library's own phrase and is
  // matched wherever it appears on purpose, because failing to NAME a real key change is worse than a false
  // alarm. Taking the file name out is the only thing between a file called that and a changed-server alarm
  // across every vault.
  const named = 'ERROR : knownhosts: key mismatch.txt: Failed to copy: permission denied';
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: named }).result, RESULT.ERROR, 'the name is taken out before any signature reads it');
  assert.strictEqual(maskFileNames(named), 'ERROR : <file>: Failed to copy: permission denied');
  // The run's own verdict lines are NOT file messages and are left exactly as they are.
  const verdict = 'ERROR : Safety abort: too many deletes (>50%, 3 of 4). Bisync aborted.';
  assert.strictEqual(maskFileNames(verdict), verdict, "a verdict about the run keeps every word");
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: verdict }).result, RESULT.ABORT_EXCESSIVE_DELETE);
});

test('the real signatures still fire, and still name the file they were about', () => {
  const real = {
    'ERROR : Safety abort: too many deletes (>50%, 3 of 4). Run with --force if desired. Bisync aborted.': RESULT.ABORT_EXCESSIVE_DELETE,
    '2026/09/03 02:00:07 ERROR : Safety abort: too many deletes (>50%, 5 of 7). Bisync aborted.': RESULT.ABORT_EXCESSIVE_DELETE,
    'ERROR : Safety abort: all files were changed on Path2 "vault:v/". Bisync aborted.': RESULT.ABORT_ALL_CHANGED,
    'ERROR : Bisync critical error: cannot find prior Path1 listing': RESULT.NEEDS_RESYNC,
    "ERROR : Failed to create file system: NewFs: couldn't connect SSH: ssh: handshake failed: knownhosts: key mismatch": RESULT.HOST_KEY_MISMATCH,
  };
  for (const [line, expected] of Object.entries(real)) {
    assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: line }).result, expected, line.slice(0, 60));
  }
  // And the detail a person is shown still comes from the untouched text, so the file is still named.
  const outOfRoom = 'ERROR : holiday.bin.58de1a09.partial: partial file rename failed: Move Rename failed: file does not exist\nERROR : Bisync aborted. Must run --resync to recover.';
  const o = classifyBisyncOutcome({ code: 1, stderr: outOfRoom });
  assert.strictEqual(o.result, RESULT.UPLOAD_NOT_STORED);
  assert.strictEqual(o.detail && o.detail.file, 'holiday.bin', 'masking is for the verdict, never for what the person is told');
  assert.strictEqual(o.resyncRequired, true, 'and the repair the run owes is still kept');
});

test('a green run is never given a repair it did not earn', () => {
  // The data-safety latch is carried through a connection verdict, but only off a FAILED run: a run that
  // exited green established its own baseline, and latching there would put a vault behind a Repair for nothing.
  const both = `${HOST_KEY}\n${DELETE_ABORT}`;
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: both }).resyncRequired, true, 'a failed run keeps the abort it owes');
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stderr: both }).resyncRequired, null, 'a green one demands nothing new');
});

test('a sign-in clears ONLY the refusals a sign-in could actually fix', async () => {
  const ls = () => new LockState({ getWindow: () => null, getDaemon: () => null, onChange: () => {}, timeouts: { rendererTimeoutMs: 5, daemonTimeoutMs: 5, daemonAttempts: 1 } });

  // The one a new account session genuinely explains: the account's own credential was refused. No device
  // identity in play, no vault password that could have rotated underneath it.
  const account = harness(ls(), { credentialPath: null });
  account.sch._noteRefusal('a', false, 'auth-failed');
  account.sch.clearCredentialRefusals();
  assert.strictEqual(account.sch.refusalState('a'), null, 'a plain account-session refusal: signing in may well fix it');

  // The three that it cannot, each left exactly where it was. Getting any of these wrong re-opens the flood at
  // every sign-in — and against the very limit doing the refusing.
  const cases = [
    ['a server limiting attempts', harness(ls()), 'channel-refused', 'the wait is what clears it — we say so in as many words'],
    ["this computer's device identity", harness(ls()), 'auth-failed', 'a refused device secret is not an account matter; the app never asks for a sign-in there'],
    ['a vault whose password may have rotated', harness(ls(), { credentialPath: null, vaultHasPassword: () => true }), 'auth-failed', 'that wants the vault password, not a session'],
  ];
  for (const [what, h, reason, why] of cases) {
    h.sch._noteRefusal('a', false, reason);
    const before = h.sch.refusalState('a');
    h.sch.clearCredentialRefusals();
    const after = h.sch.refusalState('a');
    assert.ok(after, `${what}: survives a sign-in — ${why}`);
    assert.deepStrictEqual(
      { failures: after.failures, until: after.until, reason: after.reason },
      { failures: before.failures, until: before.until, reason: before.reason },
      `${what}: and survives it untouched, not merely present`,
    );
    // An identity change is the broader event and still forgets all of them.
    h.sch.clearRefusalBackoff();
    assert.strictEqual(h.sch.refusalState('a'), null, `${what}: a changed identity does clear it`);
  }

  // The words the person is shown for the rate-limited door, and the behaviour, have to agree.
  const said = turnedAwayBody({ accepted: false, reason: 'backing-off', retryInMs: 240_000, cause: 'channel-refused' }, 'Photos');
  assert.match(said, /won't help/, 'we tell them signing in will not help');
});

// --- fail-closed ordering in the classifier -----------------------------------------------------------------

// The verbatim shapes: a door refusing the session channel, and the two data-safety aborts bisync raises.
const REJECTED = 'Failed to create file system for "vault:/x": NewFs: couldn\'t connect SSH: ssh: rejected: administratively prohibited (open failed)';
const DELETE_ABORT = 'ERROR : Safety abort: too many deletes (>50%, 7 of 9). Run with --force if desired. Bisync aborted.';
const ALL_CHANGED = 'ERROR : Safety abort: all files were changed on Path2 "vault:v/". Run with --force if desired. Bisync aborted.';
const NEEDS_RESYNC = 'ERROR : Bisync critical error: cannot find prior Path1 listing. Bisync aborted. Must run --resync to recover.';
const AUTH_REFUSED = 'ssh: unable to authenticate, attempted methods [none password]';
const CONN_RESET = 'NOTICE : connection reset by peer during an earlier list';
const HOST_KEY = "ERROR : Failed to create file system: NewFs: couldn't connect SSH: ssh: handshake failed: knownhosts: key mismatch";

test('NO connection verdict can drop a repair the run also owes — every combination keeps the latch', () => {
  // The latch (resyncRequired: true) is what holds a vault until a person deliberately repairs it. Losing it
  // means a later automatic run is free to carry out the very mass delete that was aborted. Three signatures
  // could once take the result and answer `null` — "leave the baseline alone" — throwing away a resync the same
  // run had asked for. rclone keeps a head AND a rolling tail of its log, so an early recovered connection error
  // and the terminal abort line genuinely do arrive in one haystack; this is not a contrived pairing.
  const ABORTS = { 'excessive-delete': DELETE_ABORT, 'all-changed': ALL_CHANGED };
  const CONNECTION = { 'auth-failed': AUTH_REFUSED, 'channel-refused': REJECTED, 'connect-failed': CONN_RESET, 'host-key-mismatch': HOST_KEY };
  for (const [abortName, abort] of Object.entries(ABORTS)) {
    for (const [connName, conn] of Object.entries(CONNECTION)) {
      for (const text of [`${abort}\n${conn}`, `${conn}\n${abort}`]) {
        const o = classifyBisyncOutcome({ code: 1, stderr: text });
        assert.strictEqual(o.resyncRequired, true, `${abortName} + ${connName}: the repair the abort owes survives`);
        assert.strictEqual(o.needsAttention, true, `${abortName} + ${connName}: and it is never silent`);
      }
    }
  }

  // The latch that is carried is the DATA-SAFETY one, and deliberately not bisync's generic critical-error line.
  // bisync frames every failure that way — including an ordinary dropped connection — so latching on it would
  // answer a network blip with "this needs a repair": the wrong cause, and work that cannot help. A genuinely
  // lost baseline still surfaces on the next run, which meets the same missing listing and latches honestly.
  for (const [connName, conn] of Object.entries(CONNECTION)) {
    const o = classifyBisyncOutcome({ code: 1, stderr: `${NEEDS_RESYNC}\n${conn}` });
    assert.strictEqual(o.resyncRequired, null, `${connName} + a generic critical error: no repair is demanded for a connection that failed`);
  }
  const blip = classifyBisyncOutcome({ code: 1, stderr: 'ERROR : Bisync critical error: dial tcp: i/o timeout\nERROR : Bisync aborted. Must run --resync to recover.' });
  assert.strictEqual(blip.result, RESULT.CONNECT_FAILED, 'a dropped connection is named as one');
  assert.strictEqual(blip.resyncRequired, null, 'and it does not send the person to do a repair');
  // A changed server identity still WINS the name whatever else the run said — it may not be the vault at the
  // other end at all — but it no longer costs the latch to say so.
  const mitm = classifyBisyncOutcome({ code: 1, stderr: `${DELETE_ABORT}\n${HOST_KEY}` });
  assert.strictEqual(mitm.result, RESULT.HOST_KEY_MISMATCH, 'the loudest signal is still the one a person is shown');
  assert.strictEqual(mitm.resyncRequired, true, 'and the mass-delete abort keeps its repair');
  // With nothing owing a resync, a connection verdict still decides nothing about the baseline — exactly what
  // it did before. baseline() only ever ADDS the latch back; it never invents one.
  for (const conn of Object.values(CONNECTION)) {
    assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: conn }).resyncRequired, null, 'a bare connection failure establishes no baseline either way');
  }
});

test('a refused channel can never shadow a data-safety abort: the abort wins and keeps its repair latch', () => {
  // Both traces in one run's output. The delete-safety latch is the thing that must not be lost: it is what
  // holds the vault until a person deliberately repairs it, and dropping it would let a >50% delete through on
  // a later automatic run.
  for (const order of [`${REJECTED}\n${DELETE_ABORT}`, `${DELETE_ABORT}\n${REJECTED}`]) {
    const o = classifyBisyncOutcome({ code: 1, stderr: order });
    assert.strictEqual(o.result, RESULT.ABORT_EXCESSIVE_DELETE, 'the mass delete is the more serious event, whichever line came first');
    assert.strictEqual(o.resyncRequired, true, 'and its latch is kept');
  }
  const allChanged = classifyBisyncOutcome({ code: 1, stderr: `${REJECTED}\n${ALL_CHANGED}` });
  assert.strictEqual(allChanged.result, RESULT.ABORT_ALL_CHANGED);
  assert.strictEqual(allChanged.resyncRequired, true, 'the other safety abort keeps its latch too');

  // The same rule the connect-class verdict already follows, now stated for both of them together.
  const connect = classifyBisyncOutcome({ code: 1, stderr: `${DELETE_ABORT}\nNOTICE : connection reset by peer during an earlier list` });
  assert.strictEqual(connect.result, RESULT.ABORT_EXCESSIVE_DELETE);
  assert.strictEqual(connect.resyncRequired, true);
});

test('a refused channel is still named on its own, and a run that exited green is never dressed up as one', () => {
  const alone = classifyBisyncOutcome({ code: 1, stderr: REJECTED });
  assert.strictEqual(alone.result, RESULT.CHANNEL_REFUSED, 'with no abort over it, the refusal is the honest cause');
  assert.strictEqual(alone.resyncRequired, null, 'and it establishes no baseline either way');
  // rclone retries at a low level, so a run that ultimately SUCCEEDED can still carry the phrase in its output.
  // Reading that as a refusal would put a vault on a back-off — and a wait in front of a person — for a sync
  // that actually worked.
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stderr: `${REJECTED}\nNOTICE : retried and succeeded` }).result, RESULT.OK);
  // A changed server identity still outranks it, and a real auth refusal keeps its own account remedies —
  // and, being the narrower claim of the two doors, outranks a refused channel in the same output.
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: `${HOST_KEY}\n${REJECTED}` }).result, RESULT.HOST_KEY_MISMATCH);
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: AUTH_REFUSED }).result, RESULT.AUTH_FAILED);
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: `${REJECTED}\n${AUTH_REFUSED}` }).result, RESULT.AUTH_FAILED, 'the credential itself being refused is the more specific answer');
  // A credential refusal is held to the same exit check as the other two: a run that ultimately exited green
  // carrying a retried-then-recovered auth line is not a failure, and must not be shown as one.
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stderr: `${AUTH_REFUSED}\nNOTICE : retried and succeeded` }).result, RESULT.OK);
  // The connection-level classifier the resync's first step uses is unchanged: it is only ever asked about a
  // process that already failed, so it keeps naming the refusal with no exit code of its own to consult.
  assert.strictEqual(classifyConnectionFailure('', REJECTED), RESULT.CHANNEL_REFUSED);
});

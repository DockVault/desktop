'use strict';

// How this computer's sync-identity refusals travel from the scheduler to the glance: each server answer keeps
// its own honest state (nothing collapses into a sign-in or a "check your connection"), the settled ones hold
// routine ticks until a person acts, and the run record says which credential path a run took.

const test = require('node:test');
const assert = require('node:assert');
const { conditionForReason, applySchedulerEvent, StatusSink, makeSession, perStepGate } = require('../src/main/scheduler-io');
const { identityEndedBy, IDENTITY_ENDED_REASONS } = require('../src/main/mint-path');
const { STATE } = require('../src/main/sync-status-model');
const { SyncStatusHub } = require('../src/main/sync-status-hub');
const { SyncScheduler } = require('../src/main/sync-scheduler');
const tray = require('../src/main/tray-presentation');
const copy = require('../src/main/manual-sync-copy');

const DEVICE_REASONS = {
  'grant-needs-reproof': [STATE.NEEDS_DECISION, 'grant-needs-reproof'],
  'device-revoked': [STATE.NEEDS_DECISION, 'device-revoked'],
  'device-removed': [STATE.NEEDS_DECISION, 'device-revoked'],
  'device-expired': [STATE.NEEDS_DECISION, 'device-expired'],
  'device-suspended': [STATE.NEEDS_DECISION, 'device-suspended'],
  'invalid-device-credential': [STATE.NEEDS_DECISION, 'device-not-recognized'],
  'device-secret-stale': [STATE.NEEDS_DECISION, 'device-not-recognized'],
  'account-inactive': [STATE.NEEDS_DECISION, 'account-inactive'],
  'no-grant': [STATE.NEEDS_DECISION, 'grant-withdrawn'],
  'vault-not-standard': [STATE.NEEDS_DECISION, 'vault-not-standard'],
  'device-cred-cap': [STATE.NEEDS_DECISION, 'device-cred-cap'],
  'device-request-refused': [STATE.SYNC_PROBLEM, 'device-refused'],
  'device-secret-unreadable': [STATE.PAUSED, 'device-identity-unreadable'],
  'device-state-unreadable': [STATE.PAUSED, 'device-identity-unreadable'],
  'grants-unreadable': [STATE.PAUSED, 'device-identity-unreadable'],
  'device-identity-missing': [STATE.PAUSED, 'device-identity-unreadable'],
  'device-access-check': [STATE.PAUSED, 'device-access-check'],
  'no-device-secret': [STATE.SYNC_PROBLEM, 'sync-error'],
  'route-not-allowed': [STATE.SYNC_PROBLEM, 'sync-error'],
  'grant-details-pending': [STATE.PAUSED, 'grant-details-pending'],
  'host-key-unavailable': [STATE.PAUSED, 'cannot-verify-yet'],
};

test('every device-identity reason maps to its OWN state on both the refused and the paused phase — none becomes sign-in, retrying, or an unknown', () => {
  for (const [reason, [state, out]] of Object.entries(DEVICE_REASONS)) {
    for (const phase of ['refused', 'paused', 'skipped']) {
      assert.deepStrictEqual(conditionForReason(phase, reason), { state, reason: out }, `${phase}/${reason}`);
    }
    assert.notStrictEqual(out, 'sign-in-needed', `${reason} is never the sign-in line`);
    assert.notStrictEqual(out, 'retrying', `${reason} is never a calm retry`);
  }
  // 'network' and a failing server ride the existing retry lane (calm, then "check your connection")
  assert.deepStrictEqual(conditionForReason('paused', 'network'), { state: STATE.PAUSED, reason: 'retrying' });
  assert.deepStrictEqual(conditionForReason('paused', 'server-error'), { state: STATE.PAUSED, reason: 'retrying' });
});

test('the streak logic never turns a settled device refusal into not-syncing, and a device network failure does escalate', () => {
  for (const [reason, [state, out]] of Object.entries(DEVICE_REASONS)) {
    const seen = [];
    const hub = { recordCondition: (v, c) => seen.push(c), recordOutcome: () => {}, setRunning: () => {} };
    const sink = new StatusSink(hub, { errorThreshold: 2 });
    for (let i = 0; i < 5; i++) sink.apply('v', { phase: 'paused', reason });
    assert.ok(seen.every((c) => c.state === state && c.reason === out), `${reason}: every condition stays ${out}`);
  }
  const seen = [];
  const sink = new StatusSink({ recordCondition: (v, c) => seen.push(c), recordOutcome: () => {}, setRunning: () => {} }, { errorThreshold: 2 });
  sink.apply('v', { phase: 'paused', reason: 'network' });
  sink.apply('v', { phase: 'paused', reason: 'network' });
  assert.deepStrictEqual(seen.map((c) => c.reason), ['retrying', 'not-syncing']);
});

test('every tray item, for every reason the app can surface, uses an action kind the app actually handles (no door to nowhere)', () => {
  const reasons = [
    'conflict-keep-both', 'sign-in-needed', 'needs-unlock', 'needs-repair', 'confirm-large-delete', 'path-too-long', 'host-key-mismatch',
    'vault-unavailable', 'not-syncing', 'folder-problem', 'folder-insecure', 'folder-rejected', 'sync-error', 'error', 'some-future-reason',
    ...Object.values(DEVICE_REASONS).map(([, out]) => out),
  ];
  for (const reason of reasons) {
    const item = tray.itemForVault({ vault: 'Payroll', state: STATE.NEEDS_DECISION, reason });
    assert.ok(tray.HANDLED_ACTION_KINDS.includes(item.kind), `${reason} -> kind ${item.kind} is not one the app handles`);
  }
  // the kinds with a dedicated handler stay declared, so a rename on either side fails here
  for (const k of ['restart', 'recover-folder', 'repair', 'setup-helper']) assert.ok(tray.HANDLED_ACTION_KINDS.includes(k));
});

test('every device reason has a tray line with a reachable action, and a manual-completion line', () => {
  for (const [, [state, out]] of Object.entries(DEVICE_REASONS)) {
    if (state === STATE.PAUSED) {
      assert.ok(typeof copy.bodyForConditionReason(out, 'Payroll') === 'string' && copy.bodyForConditionReason(out, 'Payroll').length > 10, `copy for ${out}`);
      continue; // calm waits carry a tooltip suffix, not a must-act line
    }
    const item = tray.itemForVault({ vault: 'Payroll', state, reason: out });
    assert.ok(item && item.kind && item.label && !/^Sync problem with/.test(item.label), `${out} has its own tray line, not the generic fallback`);
    const line = copy.bodyForConditionReason(out, 'Payroll');
    assert.ok(typeof line === 'string' && !/Try again in a moment/.test(line), `${out} never promises a self-healing retry`);
    // until the in-app flows exist, no device line may promise an in-app step (sign in to..., review on the web)
    assert.doesNotMatch(item.label + ' ' + line, /sign in to|review it on the web/i, `${out} promises nothing the app cannot do yet`);
  }
  // the account's own state names the ACCOUNT, never this computer
  assert.match(tray.itemForVault({ vault: 'P', state: STATE.NEEDS_DECISION, reason: 'account-inactive' }).label, /account/i);
  assert.doesNotMatch(tray.itemForVault({ vault: 'P', state: STATE.NEEDS_DECISION, reason: 'account-inactive' }).label, /this computer was removed/i);
});

test('the run record carries which credential path the run took (via), kept through its outcome, cleared by a run without one', () => {
  const hub = new SyncStatusHub();
  hub.setVaults(['v']);
  applySchedulerEvent(hub, 'v', { phase: 'running', via: 'device' });
  let rec = hub.current().vaults.find((x) => x.vault === 'v');
  assert.strictEqual(rec.via, 'device');
  hub.recordOutcome('v', { result: 'ok' });
  rec = hub.current().vaults.find((x) => x.vault === 'v');
  assert.strictEqual(rec.via, 'device', 'the last run\'s path survives its outcome');
  applySchedulerEvent(hub, 'v', { phase: 'running', via: 'account' });
  assert.strictEqual(hub.current().vaults.find((x) => x.vault === 'v').via, 'account');
  applySchedulerEvent(hub, 'v', { phase: 'running' });
  assert.strictEqual(hub.current().vaults.find((x) => x.vault === 'v').via ?? null, null, 'an unstated path is never inherited');
  hub.setRunning('v', true, 'bogus');
  assert.strictEqual(hub.current().vaults.find((x) => x.vault === 'v').via ?? null, null, 'only the two known paths are recorded');
});

// A scheduler harness whose eligibility check refuses with a chosen reason.
function harness(reason, opts = {}) {
  const log = [];
  let verify = 0;
  const io = {
    listConfigured: () => [{ vaultId: 'a', localFolder: '/f/a', enabled: true }, { vaultId: 'b', localFolder: '/f/b', enabled: true }],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: false, online: true, accountLive: true }),
    verifyEligible: async (v) => { verify++; return (v === 'a' && reason && !opts.recovered) ? { ok: false, reason } : { ok: true, remotePath: v }; },
    secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }),
    refreshCred: async () => ({ ok: true }),
    runSync: async () => ({ result: 'ok', ran: true }), runResync: async () => ({ result: 'resync-ok', ran: true }),
    onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
  };
  const sch = new SyncScheduler(io);
  return { sch, log, verifies: () => verify, opts };
}
async function settle(sch) { for (let i = 0; i < 300 && (sch._busy || sch._queue.length); i++) await new Promise((r) => setTimeout(r, 2)); }

test('a settled device refusal HOLDS routine ticks for that vault only; a manual press or Repair asks once more; a run lifts it', async () => {
  for (const reason of ['device-revoked', 'device-removed', 'device-expired', 'grant-needs-reproof', 'no-grant', 'device-request-refused', 'host-key-mismatch', 'vault-not-standard']) {
    const h = harness(reason);
    h.sch.tickAll(); await settle(h.sch);
    assert.strictEqual(h.sch.held('a'), reason, `${reason} holds a`);
    assert.strictEqual(h.sch.held('b'), null, 'b is untouched');
    const before = h.verifies();
    h.sch.tickAll(); await settle(h.sch);
    h.sch.requestSync('a'); await settle(h.sch);
    assert.strictEqual(h.verifies(), before + 1, 'routine ticks re-run only b; no re-dispatch of a');
    h.sch.requestSync('a', { manual: true }); await settle(h.sch);
    assert.strictEqual(h.verifies(), before + 2, 'a deliberate press asks once more');
    assert.strictEqual(h.sch.held('a'), reason, 'and the same answer holds again');
    h.opts.recovered = true;
    h.sch.requestRepair('a'); await settle(h.sch);
    assert.strictEqual(h.sch.held('a'), null, 'a run that actually started lifts the hold');
  }
});

test('transient device waits are NOT held — a later tick may genuinely succeed; releaseHolds lifts everything', async () => {
  for (const reason of ['device-secret-unreadable', 'device-state-unreadable', 'grant-details-pending', 'host-key-unavailable', 'network', 'server-error', 'device-cred-cap', 'account-inactive', 'device-suspended', 'device-identity-missing']) {
    const h = harness(reason);
    h.sch.tickAll(); await settle(h.sch);
    assert.strictEqual(h.sch.held('a'), null, `${reason} is not held`);
    const before = h.verifies();
    h.sch.tickAll(); await settle(h.sch);
    assert.strictEqual(h.verifies(), before + 2, 'both vaults re-run on the next tick');
  }
  const h = harness('device-revoked');
  h.sch.tickAll(); await settle(h.sch);
  assert.strictEqual(h.sch.held('a'), 'device-revoked');
  h.sch.releaseHolds();
  assert.strictEqual(h.sch.held('a'), null);
  const before = h.verifies();
  h.sch.tickAll(); await settle(h.sch);
  assert.strictEqual(h.verifies(), before + 2);
});

test('a device-path run refused at the SFTP door records a calm device-access-check outcome, never the sign-in or unlock remedies', async () => {
  for (const [via, expectResult] of [['device', 'auth-failed-device'], ['account', 'auth-failed-locked'], [null, 'auth-failed-locked']]) {
    const log = [];
    let runs = 0;
    const io = {
      listConfigured: () => [{ vaultId: 'a', localFolder: '/f/a', enabled: true }],
      runState: () => ({ lastResult: 'ok', resyncRequired: false }),
      session: () => ({ locked: false, online: true, accountLive: true }),
      verifyEligible: async () => ({ ok: true, remotePath: 'a' }),
      secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
      helperReady: async () => ({ ok: true }), refreshCred: async () => ({ ok: true }),
      vaultHasPassword: () => true,
      credentialPath: () => via,
      runSync: async () => { runs++; return { ok: true, ran: true, result: 'auth-failed' }; },
      runResync: async () => ({ ok: true, ran: true, result: 'auth-failed' }),
      onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
    };
    const sch = new SyncScheduler(io);
    sch.requestSync('a'); await settle(sch);
    assert.strictEqual(runs, 2, `${via}: the one boundary-race retry still happens`);
    const done = log.find((e) => e.phase === 'done');
    assert.ok(done, 'a done event lands');
    assert.strictEqual(done.outcome.result, expectResult, `${via}`);
  }
  // and the outcome maps to a calm pause with its own copy
  const hub = new SyncStatusHub(); hub.setVaults(['v']);
  hub.recordOutcome('v', { result: 'auth-failed-device' });
  const rec = hub.current().vaults.find((x) => x.vault === 'v');
  assert.deepStrictEqual([rec.state, rec.reason], [STATE.PAUSED, 'device-access-check']);
  assert.ok(tray.REASON_DETAIL['device-access-check'] && copy.bodyForConditionReason('device-access-check', 'P').includes('re-checked'));
});

test('the hold also applies on the paused phase (a refused mint), and a paused transient does not hold', async () => {
  for (const [reason, held] of [['device-revoked', true], ['host-key-mismatch', true], ['grant-needs-reproof', true], ['server-error', false], ['device-cred-cap', false], ['device-secret-unreadable', false]]) {
    const log = [];
    const io = {
      listConfigured: () => [{ vaultId: 'a', localFolder: '/f/a', enabled: true }],
      runState: () => ({ lastResult: 'ok', resyncRequired: false }),
      session: () => ({ locked: false, online: true, accountLive: true }),
      verifyEligible: async () => ({ ok: true, remotePath: 'a' }),
      secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
      helperReady: async () => ({ ok: true }),
      refreshCred: async () => ({ ok: false, reason }),
      runSync: async () => ({ ok: true, ran: true, result: 'ok' }), runResync: async () => ({ ok: true, ran: true, result: 'ok' }),
      onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
    };
    const sch = new SyncScheduler(io);
    sch.tickAll(); await settle(sch);
    assert.ok(log.some((e) => e.phase === 'paused' && e.reason === reason), `${reason} surfaces as a paused mint failure`);
    assert.strictEqual(sch.held('a'), held ? reason : null, `${reason} held=${held}`);
  }
});

test('session gate: a device identity alone is a live principal — dispatch proceeds without an account session; neither live skips with no-session; uncertain stays uncertain', async () => {
  const mk = (accountLive, deviceLive) => {
    const log = []; let verified = 0;
    const io = {
      listConfigured: () => [{ vaultId: 'a', localFolder: '/f/a', enabled: true }],
      runState: () => ({ lastResult: 'ok', resyncRequired: false }),
      session: () => ({ locked: false, online: true, accountLive, deviceLive }),
      verifyEligible: async () => { verified++; return { ok: true, remotePath: 'vault_a' }; },
      secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
      helperReady: async () => ({ ok: true }), refreshCred: async () => ({ ok: true }),
      runSync: async () => ({ ok: true, ran: true, result: 'ok' }), runResync: async () => ({ ok: true, ran: true, result: 'ok' }),
      onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
    };
    return { sch: new SyncScheduler(io), log, verified: () => verified };
  };
  for (const [accountLive, deviceLive, runs] of [[true, false, true], [false, true, true], [true, true, true], [false, false, false], [false, undefined, false]]) {
    const h = mk(accountLive, deviceLive);
    h.sch.requestSync('a'); await settle(h.sch);
    assert.strictEqual(h.verified() === 1, runs, `account=${accountLive} device=${deviceLive}`);
    if (!runs) assert.ok(h.log.some((e) => e.phase === 'skipped' && e.reason === 'no-session'));
  }
  // makeSession reports deviceLive as a strict boolean; a missing or throwing reader is "no identity"
  const base = { isAccountUsable: () => true, hasAccount: () => false, isOnline: () => true, snapshotFresh: () => true };
  assert.deepStrictEqual(makeSession({ ...base, hasDeviceIdentity: () => true })(), { locked: false, accountLive: false, deviceLive: true, online: true });
  assert.deepStrictEqual(makeSession({ ...base })(), { locked: false, accountLive: false, deviceLive: false, online: true });
  assert.deepStrictEqual(makeSession({ ...base, hasDeviceIdentity: () => { throw new Error('boom'); } })(), { locked: false, accountLive: false, deviceLive: false, online: true });
  assert.deepStrictEqual(makeSession({ ...base, hasDeviceIdentity: () => 'yes' })().deviceLive, false, 'only an explicit true counts');
  assert.deepStrictEqual(makeSession({ ...base, snapshotFresh: () => false })(), { uncertain: true });
});

test('an account-path vault with no session is refused at eligibility with its own sign-in state; a device-path vault beside it runs', async () => {
  const log = []; const runs = [];
  const io = {
    listConfigured: () => [{ vaultId: 'legacy', localFolder: '/f/l', enabled: true }, { vaultId: 'dev', localFolder: '/f/d', enabled: true }],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: false, online: true, accountLive: false, deviceLive: true }),
    // the eligibility step decides per vault: the legacy vault needs the account listing and there is no session
    verifyEligible: async (v) => (v === 'legacy' ? { ok: false, reason: 'no-session' } : { ok: true, remotePath: 'vault_dev' }),
    secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }), refreshCred: async () => ({ ok: true }),
    runSync: async (spec) => { runs.push(spec.vaultId); return { ok: true, ran: true, result: 'ok' }; }, runResync: async (spec) => { runs.push(spec.vaultId); return { ok: true, ran: true, result: 'ok' }; },
    onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
  };
  const sch = new SyncScheduler(io);
  sch.tickAll(); await settle(sch);
  assert.deepStrictEqual(runs, ['dev']);
  const legacy = log.find((e) => e.vaultId === 'legacy' && e.phase === 'refused');
  assert.ok(legacy && legacy.reason === 'no-session');
  assert.deepStrictEqual(conditionForReason('refused', 'no-session'), { state: STATE.NEEDS_DECISION, reason: 'sign-in-needed' });
});

test('under the OS lock: a device-path vault keeps syncing; an account-path vault and any un-latched path beside it pause (fail-closed)', async () => {
  const log = []; const runs = [];
  const io = {
    listConfigured: () => [
      { vaultId: 'dev', localFolder: '/f/d', enabled: true },
      { vaultId: 'acct', localFolder: '/f/a', enabled: true },
      { vaultId: 'nov', localFolder: '/f/n', enabled: true },
    ],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    // Locked, but this computer holds a device identity — so the account-tier lock does not pause every run.
    session: () => ({ locked: true, online: true, accountLive: true, deviceLive: true }),
    // The eligibility step latches the path: 'dev' runs on the device identity; 'acct' on the account; 'nov' is
    // eligible but names no path (a bare account result), which under the lock must fail closed to a pause.
    verifyEligible: async (v) => {
      if (v === 'dev') return { ok: true, via: 'device', remotePath: 'vault_dev' };
      if (v === 'acct') return { ok: true, via: 'account', remotePath: 'ACCT' };
      return { ok: true, remotePath: 'NOV' };
    },
    secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }), refreshCred: async () => ({ ok: true }),
    runSync: async (spec) => { runs.push(spec.vaultId); return { ok: true, ran: true, result: 'ok' }; },
    runResync: async (spec) => { runs.push(spec.vaultId); return { ok: true, ran: true, result: 'ok' }; },
    onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
  };
  const sch = new SyncScheduler(io);
  sch.tickAll(); await settle(sch);
  assert.deepStrictEqual(runs, ['dev'], 'only the device-path vault runs under the lock');
  const paused = (v) => log.find((e) => e.vaultId === v && e.phase === 'skipped' && e.reason === 'paused-locked');
  assert.ok(paused('acct'), 'the account-path vault pauses under the lock');
  assert.ok(paused('nov'), 'an eligible run that did not latch the device path pauses under the lock (fail-closed)');
});

test('under the OS lock: with no device identity a vault pauses EARLY, before the eligibility network step', async () => {
  const log = []; let eligibilityCalls = 0;
  const io = {
    listConfigured: () => [{ vaultId: 'a', localFolder: '/f/a', enabled: true }],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: true, online: true, accountLive: true, deviceLive: false }),
    verifyEligible: async () => { eligibilityCalls += 1; return { ok: true, via: 'account', remotePath: 'A' }; },
    secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }), refreshCred: async () => ({ ok: true }),
    runSync: async () => ({ ok: true, ran: true, result: 'ok' }), runResync: async () => ({ ok: true, ran: true, result: 'ok' }),
    onEvent: (vaultId, ev) => log.push({ vaultId, ...ev }),
  };
  const sch = new SyncScheduler(io);
  sch.tickAll(); await settle(sch);
  assert.strictEqual(eligibilityCalls, 0, 'no eligibility/network step runs — the lock refuses the account-only vault early');
  assert.ok(log.find((e) => e.vaultId === 'a' && e.phase === 'skipped' && e.reason === 'paused-locked'));
});

test('per-step gate: the device path mints without an account session, the account path needs one, and nothing mints out of flight or without a chosen path', () => {
  assert.strictEqual(perStepGate({ inFlight: true, locked: false, via: 'device', accountLive: false }), null);
  assert.strictEqual(perStepGate({ inFlight: true, locked: false, via: 'device', accountLive: true }), null);
  assert.strictEqual(perStepGate({ inFlight: true, locked: false, via: 'account', accountLive: true }), null);
  assert.strictEqual(perStepGate({ inFlight: true, locked: false, via: 'account', accountLive: false }), 'no-session');
  assert.strictEqual(perStepGate({ inFlight: false, locked: false, via: 'device', accountLive: true }), 'not-in-flight');
  for (const via of [null, undefined, 'other']) assert.strictEqual(perStepGate({ inFlight: true, locked: false, via, accountLive: true }), 'not-in-flight', `via ${via}`);
});

test('per-step gate under the OS lock: the device path keeps minting, the account path pauses, and any un-latched path pauses (fail-closed)', () => {
  // The device path is this computer's own identity — no account session, no ZK key — so the account-tier lock
  // does NOT pause it: a device/Standard vault keeps syncing under the lock.
  assert.strictEqual(perStepGate({ inFlight: true, locked: true, via: 'device', accountLive: true }), null);
  assert.strictEqual(perStepGate({ inFlight: true, locked: true, via: 'device', accountLive: false }), null);
  // The account path pauses under the lock (its credential is dropped as lock hygiene).
  assert.strictEqual(perStepGate({ inFlight: true, locked: true, via: 'account', accountLive: true }), 'paused-locked');
  // Fail-closed: a run that has not latched a path pauses under the lock rather than minting on either path.
  for (const via of [null, undefined, 'other']) assert.strictEqual(perStepGate({ inFlight: true, locked: true, via, accountLive: true }), 'paused-locked', `locked via ${via}`);
  // Out of flight still refuses first, even for the device path under the lock — main mints only for the in-flight vault.
  assert.strictEqual(perStepGate({ inFlight: false, locked: true, via: 'device', accountLive: true }), 'not-in-flight');
});

test('the identity ends on device-revoked and device-expired only — never on a suspension or any other refusal', () => {
  assert.deepStrictEqual([...IDENTITY_ENDED_REASONS], ['device-revoked', 'device-expired']);
  assert.strictEqual(identityEndedBy('device-revoked'), true);
  assert.strictEqual(identityEndedBy('device-expired'), true);
  for (const r of ['device-suspended', 'device-secret-stale', 'grant-needs-reproof', 'no-grant', 'account-inactive', 'network', 'device-request-refused', undefined, null]) {
    assert.strictEqual(identityEndedBy(r), false, String(r));
  }
});

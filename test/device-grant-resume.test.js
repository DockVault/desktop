'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { resumePendingGrants, markerActionForRunReason, runSetupAgainGrants } = require('../src/main/device-grant-resume');

// A fake IO that records the ORDER of calls and returns configured results, so the sweep's sequence and its
// keep/clear/ack rules are asserted without Electron, a network, or a keychain.
function mkIo(over = {}) {
  const calls = [];
  const cleared = [];
  const acked = [];
  const io = {
    listPending: () => { calls.push('listPending'); if (over.listThrows) throw new Error('unreadable'); return (over.pending || []).slice(); },
    isConfigured: (id) => { calls.push(`isConfigured:${id}`); return over.notConfigured ? !over.notConfigured.includes(id) : true; },
    wasGranted: (id) => {
      calls.push(`wasGranted:${id}`);
      if (over.wasGrantedThrows && over.wasGrantedThrows.includes(id)) throw new Error('grant meta unreadable');
      if (over.wasGrantedUnreadable && over.wasGrantedUnreadable.includes(id)) return 'unreadable';
      return over.wasGranted ? over.wasGranted.includes(id) : false;
    },
    checkActiveGrant: async (id) => { calls.push(`checkActive:${id}`); if (over.checkThrows) throw new Error('check failed'); return (over.active && over.active[id]) || 'active'; },
    vaultRequiresPassword: (id) => { calls.push(`needsPw:${id}`); return over.noPw ? !over.noPw.includes(id) : true; },
    pullPassword: async (id) => { calls.push(`pull:${id}`); return Object.prototype.hasOwnProperty.call(over.pw || {}, id) ? over.pw[id] : 'secret'; },
    grant: async ({ vaultId, vaultPassword }) => { calls.push(`grant:${vaultId}:${vaultPassword === undefined ? 'none' : 'pw'}`); return (over.grant && over.grant[vaultId]) || { ok: true }; },
    clearPending: (id) => { calls.push(`clear:${id}`); if (over.clearThrows) throw new Error('unreadable'); cleared.push(id); },
    ackComplete: (id) => { calls.push(`ack:${id}`); acked.push(id); },
  };
  return { io, calls, cleared, acked };
}

test('an open password vault grants, clears its marker, and is acknowledged once', async () => {
  const { io, calls, cleared, acked } = mkIo({ pending: ['v1'] });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out, { granted: ['v1'], deferred: [], failed: [], dropped: [] });
  assert.deepStrictEqual(calls, ['listPending', 'isConfigured:v1', 'wasGranted:v1', 'needsPw:v1', 'pull:v1', 'grant:v1:pw', 'clear:v1', 'ack:v1'], 'pull before grant, clear + ack after');
  assert.deepStrictEqual([cleared, acked], [['v1'], ['v1']]);
});

test('a vault that is not open (no fresh password) is left pending, with NO grant attempted', async () => {
  const { io, calls, cleared } = mkIo({ pending: ['v1'], pw: { v1: null } });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out, { granted: [], deferred: ['v1'], failed: [], dropped: [] });
  assert.ok(!calls.some((c) => c.startsWith('grant')), 'no grant without a password');
  assert.deepStrictEqual(cleared, [], 'the marker is left in place for the next pass');
});

test('a no-password vault grants without pulling a password', async () => {
  const { io, calls } = mkIo({ pending: ['v2'], noPw: ['v2'] });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out.granted, ['v2']);
  assert.ok(!calls.some((c) => c.startsWith('pull')), 'a no-password vault never pulls a password');
  assert.ok(calls.includes('grant:v2:none'), 'grants with no password threaded through');
});

test('a vault no longer configured drops its marker without a grant', async () => {
  const { io, calls, cleared } = mkIo({ pending: ['gone'], notConfigured: ['gone'] });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out, { granted: [], deferred: [], failed: [], dropped: ['gone'] });
  assert.deepStrictEqual(cleared, ['gone']);
  assert.ok(!calls.some((c) => c.startsWith('grant') || c.startsWith('pull')), 'nothing pulled or granted for an unconfigured vault');
});

test('a grant refused because the vault is gone drops the marker; any other failure LEAVES it', async () => {
  const gone = mkIo({ pending: ['v1'], grant: { v1: { ok: false, reason: 'vault-not-accessible' } } });
  assert.deepStrictEqual((await resumePendingGrants(gone.io)).dropped, ['v1']);
  assert.deepStrictEqual(gone.cleared, ['v1'], 'a gone vault is not retried forever');

  const soft = mkIo({ pending: ['v1'], grant: { v1: { ok: false, reason: 'rate-limited' } } });
  const out = await resumePendingGrants(soft.io);
  assert.deepStrictEqual(out.failed, ['v1']);
  assert.deepStrictEqual([soft.cleared, soft.acked], [[], []], 'a transient failure leaves the marker and does not acknowledge');
});

test('the sweep handles several vaults independently in one pass', async () => {
  const { io, cleared } = mkIo({
    pending: ['open', 'closed', 'nopw', 'gone'],
    pw: { open: 'secret', closed: null },
    noPw: ['nopw'],
    notConfigured: ['gone'],
  });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out.granted.sort(), ['nopw', 'open']);
  assert.deepStrictEqual(out.deferred, ['closed']);
  assert.deepStrictEqual(out.dropped, ['gone']);
  assert.deepStrictEqual(cleared.sort(), ['gone', 'nopw', 'open']);
});

test('an unreadable pending store is a calm no-op, never a throw', async () => {
  const { io, calls } = mkIo({ listThrows: true });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out, { granted: [], deferred: [], failed: [], dropped: [] });
  assert.deepStrictEqual(calls, ['listPending'], 'nothing after the failed list');
});

test('a marker-clear that fails does not lose the successful grant (still counted granted)', async () => {
  const { io } = mkIo({ pending: ['v1'], clearThrows: true });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out.granted, ['v1'], 'the grant stands even if the marker clear could not be written');
});

test('a re-proof vault (granted before) is re-granted only when the server still lists it active', async () => {
  const { io, calls } = mkIo({ pending: ['v1'], wasGranted: ['v1'], active: { v1: 'active' } });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out.granted, ['v1'], 'active on the server → the re-grant proceeds');
  assert.ok(calls.includes('checkActive:v1'), 'the active-check ran before the grant');
});

test('a re-proof vault the server no longer lists (revoked) is dropped, never reactivated', async () => {
  const { io, calls, cleared } = mkIo({ pending: ['v1'], wasGranted: ['v1'], active: { v1: 'revoked' } });
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out.dropped, ['v1']);
  assert.deepStrictEqual(cleared, ['v1'], 'the marker is cleared so it is not retried');
  assert.ok(!calls.some((c) => c.startsWith('grant') || c.startsWith('pull')), 'no re-grant and no password pulled for a revoked grant');
});

test('an inconclusive active-check DEFERS: marker left, no grant, no clear (fail closed)', async () => {
  const inc = mkIo({ pending: ['v1'], wasGranted: ['v1'], active: { v1: 'inconclusive' } });
  let out = await resumePendingGrants(inc.io);
  assert.deepStrictEqual(out.deferred, ['v1']);
  assert.deepStrictEqual([inc.cleared, inc.acked], [[], []], 'never clear or ack on an inconclusive check');
  assert.ok(!inc.calls.some((c) => c.startsWith('grant')), 'no grant on doubt');
  const thrown = mkIo({ pending: ['v1'], wasGranted: ['v1'], checkThrows: true });
  out = await resumePendingGrants(thrown.io);
  assert.deepStrictEqual(out.deferred, ['v1'], 'a THROWN check is inconclusive too → defer');
  assert.deepStrictEqual(thrown.cleared, [], 'a failed check never clears the marker');
});

test('a first-setup (never-granted) vault skips the active-check and grants directly', async () => {
  const { io, calls } = mkIo({ pending: ['v1'] }); // wasGranted defaults false
  const out = await resumePendingGrants(io);
  assert.deepStrictEqual(out.granted, ['v1']);
  assert.ok(!calls.some((c) => c.startsWith('checkActive')), 'a first grant reactivates nothing, so it skips the check');
});

// The fail-CLOSED pin for an unreadable grant record: when getGrantMeta throws / the probe answers
// 'unreadable', that must NEVER be collapsed into "never granted". Doing so is fail-OPEN on BOTH sides, so
// this pins both hazards with the SAME unreadable input — the two-sided guarantee:
//   (a) had the record been readable it might say REVOKED — collapsing to first-setup would skip the guard and
//       re-grant it, and POST /grants would REACTIVATE the grant the owner revoked. Deferring never reaches the
//       server, never re-grants.
//   (b) had it been readable it might be a genuine FIRST setup — collapsing the other way (dropping it) would
//       lose a legitimate pending setup. Deferring keeps the marker for a readable pass.
// Either way the answer is the SAME: DEFER — leave the marker, ask nothing, grant nothing, clear nothing — so a
// record that stays unreadable keeps deferring on every pass, never a wrong re-grant and never a lost setup.
test("an unreadable wasGranted DEFERS both ways: never reactivates a revoked grant, never drops a first setup", async () => {
  for (const variant of ['throws', 'sentinel']) {
    const key = variant === 'throws' ? 'wasGrantedThrows' : 'wasGrantedUnreadable';
    // (a) behind the unreadable read the server would say 'revoked' — must NOT reactivate.
    const revoked = mkIo({ pending: ['v1'], [key]: ['v1'], active: { v1: 'revoked' } });
    const outA = await resumePendingGrants(revoked.io);
    assert.deepStrictEqual(outA, { granted: [], deferred: ['v1'], failed: [], dropped: [] }, `${variant}: deferred, never granted/dropped`);
    assert.ok(!revoked.calls.some((c) => c.startsWith('checkActive')), `${variant}: an unreadable read never even consults the server`);
    assert.ok(!revoked.calls.some((c) => c.startsWith('grant') || c.startsWith('pull')), `${variant}: no re-grant, no password pulled`);
    assert.deepStrictEqual([revoked.cleared, revoked.acked], [[], []], `${variant}: the marker is neither cleared nor acked`);

    // (b) behind the unreadable read it is a genuine first setup — must NOT be dropped.
    const fresh = mkIo({ pending: ['v1'], [key]: ['v1'] }); // no server grant at all
    const outB = await resumePendingGrants(fresh.io);
    assert.deepStrictEqual(outB, { granted: [], deferred: ['v1'], failed: [], dropped: [] }, `${variant}: a first setup is deferred, never dropped`);
    assert.deepStrictEqual(fresh.cleared, [], `${variant}: a first setup's marker is kept for a readable pass`);
  }
});

test('markerActionForRunReason: only a re-proof adds; an ended identity clears all; a withdrawn grant clears one; else nothing', () => {
  assert.strictEqual(markerActionForRunReason('grant-needs-reproof'), 'add', 'a re-proof is the only run reason that feeds the marker');
  assert.strictEqual(markerActionForRunReason('device-revoked'), 'clear-all', 'an ended identity drops every marker');
  assert.strictEqual(markerActionForRunReason('device-expired'), 'clear-all');
  assert.strictEqual(markerActionForRunReason('no-grant'), 'clear', 'a withdrawn grant drops just its marker');
  assert.strictEqual(markerActionForRunReason('grant-withdrawn'), 'clear');
  // Everything else leaves the marker: successes, calm waits, a SUSPENSION (reversible, kept for its restore),
  // and device-not-recognized (recoverable via set-up-again; the sweep's guard defers rather than clearing).
  for (const r of ['ok', 'resync-ok', 'needs-unlock', 'device-suspended', 'device-not-recognized', 'invalid-device-credential', 'device-secret-stale', 'retrying', undefined, null, '']) {
    assert.strictEqual(markerActionForRunReason(r), null, `${r} must not touch the marker`);
  }
});

test('runSetupAgainGrants: drops each old record FIRST, then no-password → granted now, password → pending', async () => {
  const calls = [];
  const io = {
    dropMeta: (id) => calls.push(`drop:${id}`),
    addPending: (id) => calls.push(`pend:${id}`),
    grant: async ({ vaultId }) => { calls.push(`grant:${vaultId}`); return { ok: true }; },
  };
  const out = await runSetupAgainGrants(io, [
    { vaultId: 'nopw', vaultName: 'Notes', hasPassword: false },
    { vaultId: 'pw', vaultName: 'Payroll', hasPassword: true },
  ]);
  assert.deepStrictEqual(out, { granted: ['nopw'], pending: ['pw'], failed: [] });
  assert.deepStrictEqual(calls, ['drop:nopw', 'grant:nopw', 'drop:pw', 'pend:pw'], 'the old record is dropped before the grant/pending, so the resume guard never reads a stale "granted"');
});

test('runSetupAgainGrants: a no-password grant failure and a pending-store throw are reported failed, never silently dropped; empty is a clean no-op', async () => {
  const failGrant = { dropMeta() {}, addPending() {}, grant: async () => ({ ok: false, reason: 'x' }) };
  assert.deepStrictEqual((await runSetupAgainGrants(failGrant, [{ vaultId: 'a', vaultName: 'A', hasPassword: false }])).failed, ['a']);
  const failPend = { dropMeta() {}, addPending() { throw new Error('unreadable'); }, grant: async () => ({ ok: true }) };
  assert.deepStrictEqual((await runSetupAgainGrants(failPend, [{ vaultId: 'b', vaultName: 'B', hasPassword: true }])).failed, ['b']);
  assert.deepStrictEqual(await runSetupAgainGrants({ dropMeta() {}, addPending() {}, grant: async () => ({ ok: true }) }, []), { granted: [], pending: [], failed: [] });
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { runDeviceSetup } = require('../src/main/device-enable');

const VAULT = { vaultId: 'v1', vaultName: 'Payroll', hasPassword: true };

// A fake IO that records the ORDER of calls and returns configured outcomes, so the orchestration's sequence
// and fail-soft branches are asserted without Electron, a network, or a keychain.
function mkIo(over = {}) {
  const calls = [];
  const io = {
    probe: async () => { calls.push('probe'); return { reason: over.probeReason || 'ok' }; },
    readStatus: () => { calls.push('readStatus'); return over.secretStatus || 'absent'; },
    confirmSwitchServer: async () => { calls.push('confirmSwitchServer'); return over.switchOk !== false; },
    forget: async () => { calls.push('forget'); },
    promptLabel: async () => { calls.push('promptLabel'); return over.label !== undefined ? over.label : 'This computer'; },
    register: async (label) => { calls.push(`register:${label}`); return over.register || { ok: true }; },
    grantVault: async (a) => { calls.push(`grant:${a.vaultId}:${a.hasPassword}`); return over.grant || { granted: true }; },
  };
  return { io, calls };
}
const noMutation = (calls) => !calls.some((c) => c.startsWith('register') || c.startsWith('grant') || c === 'forget');

test('the probe gates: auth -> sign-in, and every not-ok / account-only status stays on the account path without any device mutation', async () => {
  for (const [probeReason, secretStatus, outcome, reason] of [
    ['auth', 'absent', 'sign-in', 'no-session'],
    ['too-old', 'absent', 'account-only', 'server-too-old'],
    ['indeterminate', 'ok', 'account-only', 'indeterminate'],
    ['ok', 'no-secure-store', 'account-only', 'no-secure-store'],
    ['ok', 'stale', 'account-only', 'identity-stale'],
    ['ok', 'unreadable', 'account-only', 'identity-unreadable'],
  ]) {
    const { io, calls } = mkIo({ probeReason, secretStatus });
    const r = await runDeviceSetup(io, VAULT);
    assert.deepStrictEqual(r, { via: 'account', outcome, reason }, `${probeReason}/${secretStatus}`);
    assert.ok(noMutation(calls), `${probeReason}/${secretStatus}: nothing registered/granted/forgotten`);
  }
});

test('an absent identity: register (with the chosen label) then grant -> the vault syncs on the device path', async () => {
  const { io, calls } = mkIo({ secretStatus: 'absent', label: 'Office laptop' });
  const r = await runDeviceSetup(io, VAULT);
  assert.deepStrictEqual(r, { via: 'device', outcome: 'granted' });
  assert.deepStrictEqual(calls, ['probe', 'readStatus', 'promptLabel', 'register:Office laptop', 'grant:v1:true']);
});

test('a granted vault whose local record write FAILED surfaces as granted-not-recorded, not a silent success', async () => {
  // The server grant succeeded (via device) but grantVault reported recordFailed — the local record could not be
  // written. The outcome must be distinct so the person is told the setup did not fully save, never a plain 'granted'.
  const { io } = mkIo({ secretStatus: 'ok', grant: { granted: true, recordFailed: true } });
  const r = await runDeviceSetup(io, VAULT);
  assert.deepStrictEqual(r, { via: 'device', outcome: 'granted-not-recorded' });
});

test('a cancelled label leaves the vault on the account path, nothing registered', async () => {
  const { io, calls } = mkIo({ secretStatus: 'absent', label: null });
  const r = await runDeviceSetup(io, VAULT);
  assert.deepStrictEqual(r, { via: 'account', outcome: 'register-cancelled' });
  assert.ok(noMutation(calls.filter((c) => c !== 'promptLabel')), 'no register/grant after a cancelled label');
});

test('a register failure (e.g. the server cap) leaves the vault on the account path with the reason', async () => {
  const { io } = mkIo({ secretStatus: 'absent', register: { ok: false, reason: 'device-cap-reached' } });
  const r = await runDeviceSetup(io, VAULT);
  assert.deepStrictEqual(r, { via: 'account', outcome: 'register-failed', reason: 'device-cap-reached' });
});

test('already registered here (ok): grant only, no label prompt', async () => {
  const { io, calls } = mkIo({ secretStatus: 'ok' });
  const r = await runDeviceSetup(io, VAULT);
  assert.deepStrictEqual(r, { via: 'device', outcome: 'granted' });
  assert.deepStrictEqual(calls, ['probe', 'readStatus', 'grant:v1:true'], 'no promptLabel/register for an already-registered computer');
});

test('registered elsewhere: consent -> label -> forget -> register -> grant; declining leaves the vault on the account path with nothing forgotten', async () => {
  const yes = mkIo({ secretStatus: 'absent-for-this-server', label: 'This computer' });
  assert.deepStrictEqual(await runDeviceSetup(yes.io, VAULT), { via: 'device', outcome: 'granted' });
  // The irreversible forget runs only AFTER the label is in hand (both reversible answers collected first).
  assert.deepStrictEqual(yes.calls, ['probe', 'readStatus', 'confirmSwitchServer', 'promptLabel', 'forget', 'register:This computer', 'grant:v1:true']);

  const no = mkIo({ secretStatus: 'absent-for-this-server', switchOk: false });
  assert.deepStrictEqual(await runDeviceSetup(no.io, VAULT), { via: 'account', outcome: 'switch-declined', reason: 'registered-elsewhere' });
  assert.ok(!no.calls.includes('forget') && !no.calls.some((c) => c.startsWith('register')), 'declining the switch forgets and registers nothing');
});

test('a switch cancelled at the label forgets nothing: the identity stays intact on the other server', async () => {
  const { io, calls } = mkIo({ secretStatus: 'absent-for-this-server', switchOk: true, label: null });
  assert.deepStrictEqual(await runDeviceSetup(io, VAULT), { via: 'account', outcome: 'register-cancelled' });
  assert.deepStrictEqual(calls, ['probe', 'readStatus', 'confirmSwitchServer', 'promptLabel'], 'no forget, no register after a cancelled label');
});

test('a switch that fails AFTER the forget carries `switched`, so the copy can say this computer left the other server', async () => {
  const { io, calls } = mkIo({ secretStatus: 'absent-for-this-server', switchOk: true, label: 'This computer', register: { ok: false, reason: 'device-cap-reached' } });
  assert.deepStrictEqual(await runDeviceSetup(io, VAULT), { via: 'account', outcome: 'register-failed', reason: 'device-cap-reached', switched: true });
  assert.deepStrictEqual(calls, ['probe', 'readStatus', 'confirmSwitchServer', 'promptLabel', 'forget', 'register:This computer'], 'the forget ran before the failed register');
});

test('a deferred password ("Later") leaves the vault on the account path as a resumable state, not a failure', async () => {
  const { io } = mkIo({ secretStatus: 'ok', grant: { granted: false, deferred: true } });
  assert.deepStrictEqual(await runDeviceSetup(io, VAULT), { via: 'account', outcome: 'grant-deferred', reason: 'grant-needs-password' });
});

test('a real grant failure is reported on the account path with its reason', async () => {
  const { io } = mkIo({ secretStatus: 'ok', grant: { granted: false, reason: 'wrong-password' } });
  assert.deepStrictEqual(await runDeviceSetup(io, VAULT), { via: 'account', outcome: 'grant-failed', reason: 'wrong-password' });
});

test('a no-password vault still grants (hasPassword false threads through to the grant step)', async () => {
  const { io, calls } = mkIo({ secretStatus: 'ok' });
  assert.deepStrictEqual(await runDeviceSetup(io, { vaultId: 'v2', vaultName: 'Notes', hasPassword: false }), { via: 'device', outcome: 'granted' });
  assert.ok(calls.includes('grant:v2:false'));
});

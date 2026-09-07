'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { refuseMessage, cloudServiceName, cloudWarnMessage, consentMessage, deviceOutcomeCopy, LOCK_DISCLOSURE } = require('../src/main/enable-copy');

test('refuseMessage: every known reason has actionable non-blaming copy; unknown falls back', () => {
  for (const r of ['home-root-or-above', 'app-data-dir', 'system-location', 'overlaps-another-sync', 'not-absolute']) {
    const m = refuseMessage(r);
    assert.ok(m && m.length > 0 && !/you (idiot|should)/i.test(m), `${r} has copy`);
  }
  assert.match(refuseMessage('something-new'), /pick another folder/i);
});

test('cloudServiceName detects the major services and falls back generically', () => {
  assert.strictEqual(cloudServiceName('/Users/t/OneDrive/x'), 'OneDrive');
  assert.strictEqual(cloudServiceName('C:/Users/t/Dropbox/x'), 'Dropbox');
  assert.strictEqual(cloudServiceName('/Users/t/Google Drive/x'), 'Google Drive');
  assert.strictEqual(cloudServiceName('/Users/t/Library/Mobile Documents/com~apple~CloudDocs/x'), 'iCloud Drive');
  assert.strictEqual(cloudServiceName('/Users/t/Documents/x'), 'a cloud storage app');
});

test('cloudWarnMessage names the service; consentMessage is TWO-WAY + warns on a non-empty folder', () => {
  assert.match(cloudWarnMessage('OneDrive'), /inside OneDrive.*conflicts/s);
  const c = consentMessage('Marketing', '/Users/t/Vaults/M');
  assert.match(c, /Marketing/);
  assert.match(c, /\/Users\/t\/Vaults\/M/);
  assert.match(c, /both ways/i, 'states it is bidirectional');
  assert.match(c, /uploaded into the vault/i, 'states the upload direction, not only the download');
  // non-empty folder: the existing contents are called out as being uploaded
  const ne = consentMessage('Marketing', '/Users/t/Vaults/M', { nonEmpty: true });
  assert.match(ne, /already contains files/i);
  // empty folder: no such warning
  assert.doesNotMatch(consentMessage('Marketing', '/Users/t/Vaults/M', { nonEmpty: false }), /already contains files/i);
});

// Every result runDeviceSetup can return, so the copy map is proven exhaustive against its producer.
const ALL_DEVICE_RESULTS = [
  { via: 'device', outcome: 'granted' },
  { via: 'device', outcome: 'granted-not-recorded' },
  { via: 'account', outcome: 'sign-in', reason: 'no-session' },
  { via: 'account', outcome: 'account-only', reason: 'server-too-old' },
  { via: 'account', outcome: 'account-only', reason: 'indeterminate' },
  { via: 'account', outcome: 'account-only', reason: 'no-secure-store' },
  { via: 'account', outcome: 'account-only', reason: 'identity-stale' },
  { via: 'account', outcome: 'account-only', reason: 'identity-unreadable' },
  { via: 'account', outcome: 'switch-declined', reason: 'registered-elsewhere' },
  { via: 'account', outcome: 'register-cancelled' },
  { via: 'account', outcome: 'register-failed', reason: 'device-cap-reached' },
  { via: 'account', outcome: 'register-failed', reason: 'register-refused', switched: true },
  { via: 'account', outcome: 'grant-deferred', reason: 'grant-needs-password' },
  { via: 'account', outcome: 'grant-failed', reason: 'wrong-password' },
  { via: 'account', outcome: 'grant-failed', reason: 'device-error' },
];
const VALID_TONES = new Set(['ok', 'info', 'todo', 'sign-in']);

test('deviceOutcomeCopy: every runDeviceSetup outcome yields a valid tone and a non-blaming, surface-free line', () => {
  for (const r of ALL_DEVICE_RESULTS) {
    const { tone, message } = deviceOutcomeCopy(r, { vaultName: 'Payroll' });
    assert.ok(VALID_TONES.has(tone), `${r.outcome}/${r.reason}: valid tone (got ${tone})`);
    assert.ok(message && message.length > 8, `${r.outcome}/${r.reason}: has copy`);
    // never points at a surface this version lacks (no web page / dashboard / link), never blames the person
    assert.doesNotMatch(message, /https?:|www\.|click here|web (page|site)|dashboard/i, `${r.outcome}: no nonexistent surface`);
    assert.doesNotMatch(message, /you (idiot|should have|failed to)/i, `${r.outcome}: non-blaming`);
  }
});

test('deviceOutcomeCopy: a granted-but-unrecorded setup is honest (not silent), non-blaming, and says it still syncs', () => {
  const { tone, message } = deviceOutcomeCopy({ via: 'device', outcome: 'granted-not-recorded' }, { vaultName: 'Payroll' });
  assert.strictEqual(tone, 'todo');
  assert.match(message, /Payroll/);
  assert.match(message, /couldn't save/i, 'names the real problem (the local record write) plainly');
  assert.match(message, /sign-in/i, 'reassures the vault keeps syncing meanwhile');
  assert.doesNotMatch(message, /fail(ed|ure)/i, 'no blame: the grant succeeded, only the local save did not');
});

test("deviceOutcomeCopy: the device path reads as success; the password reassurance appears only for a password vault, and never as something not saved", () => {
  const { tone, message } = deviceOutcomeCopy({ via: 'device', outcome: 'granted' }, { vaultName: 'Payroll', hasPassword: true });
  assert.strictEqual(tone, 'ok');
  assert.match(message, /Payroll/);
  assert.match(message, /password stays with you/i);
  assert.doesNotMatch(message, /wasn't saved|not saved|fail/i, 'a success line never sounds like a failure');
  const plain = deviceOutcomeCopy({ via: 'device', outcome: 'granted' }, { vaultName: 'Photos', hasPassword: false });
  assert.doesNotMatch(plain.message, /password/i, 'a vault without a password gets no password sentence');
  assert.match(plain.message, /set up to sync on this computer/);
  assert.match(plain.message, /first sync starts now/, 'success does not claim a sync already happened');
});

test("deviceOutcomeCopy: 'sign-in' is the calm held wait, not an alarm", () => {
  const { tone, message } = deviceOutcomeCopy({ via: 'account', outcome: 'sign-in', reason: 'no-session' }, { vaultName: 'Payroll' });
  assert.strictEqual(tone, 'sign-in');
  assert.match(message, /sign in/i);
  assert.doesNotMatch(message, /error|failed|can't|couldn't|problem/i, 'no alarming words');
});

test('deviceOutcomeCopy: a deferred grant says to OPEN the vault (not type a password), and reassures it still syncs', () => {
  const { tone, message } = deviceOutcomeCopy({ outcome: 'grant-deferred', reason: 'grant-needs-password' }, { vaultName: 'Payroll' });
  assert.strictEqual(tone, 'todo');
  assert.match(message, /open Payroll/i, 'the mechanism is opening the vault, which the resume completes');
  assert.doesNotMatch(message, /password/i, 'no native password box: opening the vault proves it once from the unlock state');
  assert.match(message, /keeps syncing using your account sign-in/i, 'reassures it still syncs meanwhile');
});

test('deviceOutcomeCopy: a wrong password is a retryable to-do; a generic grant failure is info', () => {
  assert.strictEqual(deviceOutcomeCopy({ outcome: 'grant-failed', reason: 'wrong-password' }, { vaultName: 'Payroll' }).tone, 'todo');
  assert.strictEqual(deviceOutcomeCopy({ outcome: 'grant-failed', reason: 'device-error' }, { vaultName: 'Payroll' }).tone, 'info');
});

test('deviceOutcomeCopy: a switch that failed AFTER the forget says the computer left the other server; a plain register failure does not, and neither instructs removing a computer', () => {
  const switched = deviceOutcomeCopy({ outcome: 'register-failed', reason: 'device-cap-reached', switched: true }, { otherServer: 'sync.example.com' });
  assert.match(switched.message, /no longer set up with sync\.example\.com/i, 'names the other server when known');
  const plain = deviceOutcomeCopy({ outcome: 'register-failed', reason: 'device-cap-reached' }, {});
  assert.doesNotMatch(plain.message, /no longer set up/i, 'a plain absent-slot failure removed nothing');
  assert.match(plain.message, /limit of synced computers/i, 'names the cap honestly');
  assert.doesNotMatch(plain.message, /remove (one|a computer)/i, 'never instructs a removal surface this version lacks');
  // unknown other server falls back to a clean generic noun
  assert.match(deviceOutcomeCopy({ outcome: 'register-failed', reason: 'register-refused', switched: true }, {}).message, /no longer set up with its previous server/i);
});

test('deviceOutcomeCopy: each account-only reason has its own honest line, all reassuring the vault still syncs', () => {
  assert.match(deviceOutcomeCopy({ outcome: 'account-only', reason: 'server-too-old' }).message, /doesn't support syncing individual computers/i);
  assert.match(deviceOutcomeCopy({ outcome: 'account-only', reason: 'no-secure-store' }).message, /can't store a sync key securely/i);
  assert.match(deviceOutcomeCopy({ outcome: 'account-only', reason: 'identity-stale' }).message, /being re-checked/i);
  assert.match(deviceOutcomeCopy({ outcome: 'account-only', reason: 'identity-unreadable' }).message, /can't be read right now/i);
  assert.match(deviceOutcomeCopy({ outcome: 'account-only', reason: 'indeterminate' }).message, /couldn't check/i);
  for (const reason of ['server-too-old', 'no-secure-store', 'identity-stale', 'identity-unreadable', 'indeterminate'])
    assert.match(deviceOutcomeCopy({ outcome: 'account-only', reason }).message, /keeps syncing using your account sign-in/i, reason);
});

test('deviceOutcomeCopy: reads cleanly with no context, and fails closed on an unmapped outcome', () => {
  assert.match(deviceOutcomeCopy({ outcome: 'granted' }).message, /^This vault is set up to sync on this computer/i, 'generic vault noun, capitalized at the sentence start');
  const unknown = deviceOutcomeCopy({ outcome: 'no-such-outcome' });
  assert.strictEqual(unknown.tone, 'info');
  assert.ok(unknown.message.length > 0, 'never blank');
});

test('LOCK_DISCLOSURE states the under-lock behavior plainly', () => {
  assert.match(LOCK_DISCLOSURE, /locked/i);
  assert.match(LOCK_DISCLOSURE, /keeps syncing/i);
});

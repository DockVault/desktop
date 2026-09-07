'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { decideMigration, groupMigrationOutcomes } = require('../src/main/device-migrate');

const OK = 'https://vault.example';
// A configured vault, defaulting to a genuinely un-recorded one on a migratable slot.
const cfg = (over = {}) => ({ vaultId: 'v1', vaultName: 'Docs', hasPassword: false, record: 'first-setup', ...over });
const base = (over = {}) => ({ support: 'ok', deviceStatus: 'absent', configured: [cfg()], currentOrigin: OK, ...over });

test('a supported server with an un-migrated configured vault shows the door and nudges once', () => {
  const d = decideMigration(base());
  assert.strictEqual(d.doorShow, true);
  assert.deepStrictEqual(d.vaults, [{ vaultId: 'v1', vaultName: 'Docs', hasPassword: false }]);
  assert.strictEqual(d.notify, true, 'fresh origin → nudge');
  assert.strictEqual(d.tooOldNote, false);
});

test('the door vanishes once every configured vault has a grant record here', () => {
  const d = decideMigration(base({ configured: [cfg({ record: 'granted' }), cfg({ vaultId: 'v2', record: 'granted' })] }));
  assert.strictEqual(d.doorShow, false);
  assert.deepStrictEqual(d.vaults, []);
  assert.strictEqual(d.notify, false);
});

test('the door lists ONLY the un-recorded vaults (a mixed desktop: one migrated, one not)', () => {
  const d = decideMigration(base({
    deviceStatus: 'ok', // a live identity, older account-path vault still to move
    configured: [cfg({ vaultId: 'migrated', record: 'granted' }), cfg({ vaultId: 'older', vaultName: 'Old', hasPassword: true, record: 'first-setup' })],
  }));
  assert.strictEqual(d.doorShow, true);
  assert.deepStrictEqual(d.vaults, [{ vaultId: 'older', vaultName: 'Old', hasPassword: true }], 'only the account-path vault, even with a live identity present');
});

test('an UNREADABLE grant record is EXCLUDED — never offered, never granted (a locked keychain must not re-grant)', () => {
  const alone = decideMigration(base({ configured: [cfg({ record: 'unreadable' })] }));
  assert.strictEqual(alone.doorShow, false, 'an unreadable record alone → no door');
  assert.strictEqual(alone.notify, false, 'and no nudge / no flag, like indeterminate');
  const mixed = decideMigration(base({ configured: [cfg({ vaultId: 'readable', record: 'first-setup' }), cfg({ vaultId: 'locked', record: 'unreadable' })] }));
  assert.deepStrictEqual(mixed.vaults.map((v) => v.vaultId), ['readable'], 'the door lists only the readable un-recorded vault');
  assert.strictEqual(mixed.doorShow, true);
});

test('a declined offer keeps the door but does NOT re-nudge on the same origin', () => {
  const d = decideMigration(base({ offeredOrigin: OK }));
  assert.strictEqual(d.doorShow, true, 'the standing door stays');
  assert.strictEqual(d.notify, false, 'no second nudge on the same origin');
});

test('a server switch (new origin) re-nudges', () => {
  const d = decideMigration(base({ offeredOrigin: 'https://old.example' }));
  assert.strictEqual(d.notify, true, 'new origin → offer again');
});

test('a live identity for THIS server (ok) still offers to move older account-path vaults', () => {
  const d = decideMigration(base({ deviceStatus: 'ok' }));
  assert.strictEqual(d.doorShow, true);
});

test("an identity bound to ANOTHER server ('absent-for-this-server') hides the door and shows the honest switch note", () => {
  const d = decideMigration(base({ deviceStatus: 'absent-for-this-server' }));
  assert.strictEqual(d.doorShow, false, 'never a register that does nothing');
  assert.strictEqual(d.notify, false);
  assert.strictEqual(d.otherServerNote, true, 'the account path is not left silent — offer the switch');
});

test('otherServerNote is true EXACTLY when the door is hidden for the other-server reason', () => {
  // true: another server + a configured un-recorded vault + supported
  assert.strictEqual(decideMigration(base({ deviceStatus: 'absent-for-this-server' })).otherServerNote, true);
  // false: nothing left to move (all recorded) — no reason to switch
  assert.strictEqual(decideMigration(base({ deviceStatus: 'absent-for-this-server', configured: [cfg({ record: 'granted' })] })).otherServerNote, false);
  // false: the door itself is showing (a migratable identity)
  assert.strictEqual(decideMigration(base({ deviceStatus: 'absent' })).otherServerNote, false);
  assert.strictEqual(decideMigration(base({ deviceStatus: 'ok' })).otherServerNote, false);
  // false: server not supported (can't switch to a server that can't do it)
  assert.strictEqual(decideMigration(base({ deviceStatus: 'absent-for-this-server', support: 'too-old' })).otherServerNote, false);
  assert.strictEqual(decideMigration(base({ deviceStatus: 'absent-for-this-server', support: 'indeterminate' })).otherServerNote, false);
  // false: a different non-migratable status (stale) is the recheck/hatch story, not a switch
  assert.strictEqual(decideMigration(base({ deviceStatus: 'stale' })).otherServerNote, false);
});

test('a non-migratable identity (stale / rechecking / unreadable / no-secure-store) shows no door', () => {
  for (const deviceStatus of ['stale', 'rechecking', 'unreadable', 'no-secure-store']) {
    const d = decideMigration(base({ deviceStatus }));
    assert.strictEqual(d.doorShow, false, `deviceStatus=${deviceStatus}: no door`);
    assert.strictEqual(d.notify, false);
  }
});

test("a too-old server shows the calm note, never the door or a nudge", () => {
  const d = decideMigration(base({ support: 'too-old' }));
  assert.strictEqual(d.doorShow, false);
  assert.strictEqual(d.notify, false);
  assert.strictEqual(d.tooOldNote, true);
});

test('an indeterminate / auth / unprobed server shows and marks NOTHING (offline never reads as old)', () => {
  for (const support of ['indeterminate', 'auth', null, undefined]) {
    const d = decideMigration(base({ support }));
    assert.deepStrictEqual(
      { doorShow: d.doorShow, notify: d.notify, tooOldNote: d.tooOldNote },
      { doorShow: false, notify: false, tooOldNote: false },
      `support=${support}: nothing shown, nothing marked`,
    );
  }
});

test('no current origin → no nudge even if the door would apply (the flag can not be keyed)', () => {
  const d = decideMigration(base({ currentOrigin: null }));
  assert.strictEqual(d.doorShow, true);
  assert.strictEqual(d.notify, false);
});

test('no configured vaults → no door', () => {
  assert.strictEqual(decideMigration(base({ configured: [] })).doorShow, false);
  assert.strictEqual(decideMigration({ support: 'ok', deviceStatus: 'absent', currentOrigin: OK }).doorShow, false, 'missing configured is []');
});

test('malformed configured entries are ignored (no vaultId, null, wrong type)', () => {
  const d = decideMigration(base({ configured: [null, {}, { vaultId: '' }, cfg({ vaultId: 'good' })] }));
  assert.deepStrictEqual(d.vaults.map((v) => v.vaultId), ['good']);
});

// --- groupMigrationOutcomes (the one-dialog grouping) ---
const oc = (vaultName, outcome, extra = {}) => ({ vault: { vaultName }, outcome: { outcome, ...extra } });

test('groupMigrationOutcomes drops the quiet outcomes (granted + the person\'s own declines)', () => {
  const g = groupMigrationOutcomes([oc('A', 'granted'), oc('B', 'register-cancelled'), oc('C', 'switch-declined')]);
  assert.deepStrictEqual(g, [], 'nothing to show — the tray already reflects these');
});

test('groupMigrationOutcomes groups a per-vault outcome and lists every name, in first-seen order', () => {
  const g = groupMigrationOutcomes([oc('Docs', 'grant-deferred'), oc('Photos', 'grant-deferred')]);
  assert.strictEqual(g.length, 1);
  assert.strictEqual(g[0].outcome, 'grant-deferred');
  assert.strictEqual(g[0].idLevel, false, 'a per-vault outcome — the caller emits one line per name');
  assert.deepStrictEqual(g[0].names, ['Docs', 'Photos']);
});

test('groupMigrationOutcomes keeps distinct groups (granted dropped; deferred and failed kept separately)', () => {
  const g = groupMigrationOutcomes([oc('A', 'granted'), oc('B', 'grant-deferred'), oc('C', 'grant-failed')]);
  assert.deepStrictEqual(g.map((x) => x.outcome), ['grant-deferred', 'grant-failed']);
});

test('groupMigrationOutcomes splits a shared outcome by reason', () => {
  const g = groupMigrationOutcomes([oc('A', 'grant-failed', { reason: 'wrong-password' }), oc('B', 'grant-failed', { reason: 'grant-failed' })]);
  assert.strictEqual(g.length, 2, 'different reasons → different lines');
});

test('groupMigrationOutcomes marks identity-level outcomes and carries the switched flag', () => {
  const acct = groupMigrationOutcomes([oc('A', 'account-only', { reason: 'server-too-old' })]);
  assert.strictEqual(acct[0].idLevel, true, 'account-only is decided once for the whole pass');
  const sw = groupMigrationOutcomes([oc('A', 'register-failed', { switched: true })]);
  assert.strictEqual(sw[0].idLevel, true);
  assert.strictEqual(sw[0].switched, true, 'the switched flag survives for the honest register-failed copy');
});

test('groupMigrationOutcomes tolerates junk entries', () => {
  assert.deepStrictEqual(groupMigrationOutcomes([null, {}, { outcome: {} }, { vault: {}, outcome: { outcome: 'granted' } }]), []);
  assert.deepStrictEqual(groupMigrationOutcomes(undefined), []);
});

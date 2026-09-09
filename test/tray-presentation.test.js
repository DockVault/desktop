'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { tooltip, mustActItems, itemForVault, pendingSetupItems, deviceResetItem, syncNowItem, lastSyncedLabel, HANDLED_ACTION_KINDS, REASON_DETAIL } = require('../src/main/tray-presentation');
const { computeStatus, STATE } = require('../src/main/sync-status-model');

const secure = { hasSecureStore: true, online: true, daemon: 'ready' };
const vault = (over) => ({ vault: 'v', running: false, lastResult: null, resyncRequired: false, ...over });

test('lock transients take the glance while they last', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ lastResult: 'ok' })] });
  assert.strictEqual(tooltip(m, 'locking'), 'DockVault — Locking…');
  assert.strictEqual(tooltip(m, 'lock-error'), 'DockVault — Lock error (retrying)');
});

test('a locked-and-clean vault reads "Locked", not a bare "Paused"', () => {
  const m = computeStatus({ ...secure, locked: true, vaults: [vault({ lastResult: 'ok' })] });
  assert.strictEqual(m.state, STATE.PAUSED);
  assert.strictEqual(tooltip(m, 'locked'), 'DockVault — Locked');
});

test('under the lock the glance leads with "Locked" and appends the sync truth', () => {
  const lockedFor = (vaults) => tooltip(computeStatus({ ...secure, locked: true, deviceLive: true, vaults }), 'locked');
  // Device vaults keep syncing under the lock — the glance says so (plural / singular).
  assert.strictEqual(lockedFor([
    vault({ vault: 'd1', via: 'device', transferring: true, lastResult: 'ok' }),
    vault({ vault: 'd2', via: 'device', transferring: true, lastResult: 'ok' }),
  ]), 'DockVault — Locked · syncing 2 vaults');
  assert.strictEqual(lockedFor([
    vault({ vault: 'd1', via: 'device', transferring: true, lastResult: 'ok' }),
    vault({ vault: 'a', via: 'account', lastResult: 'ok' }),
  ]), 'DockVault — Locked · syncing 1 vault');
  // Device vaults all up to date under the lock.
  assert.strictEqual(lockedFor([
    vault({ vault: 'd1', via: 'device', lastResult: 'ok' }),
    vault({ vault: 'd2', via: 'device', lastResult: 'ok' }),
  ]), 'DockVault — Locked · up to date');
  // A device vault up to date beside an account vault the lock paused.
  assert.strictEqual(lockedFor([
    vault({ vault: 'd1', via: 'device', lastResult: 'ok' }),
    vault({ vault: 'a', via: 'account', lastResult: 'ok' }),
  ]), 'DockVault — Locked · 1 vault paused while locked');
  // Every configured vault paused by the lock -> plain "Locked" (answers the all-account edge).
  assert.strictEqual(lockedFor([
    vault({ vault: 'a1', via: 'account', lastResult: 'ok' }),
    vault({ vault: 'a2', via: 'account', lastResult: 'ok' }),
  ]), 'DockVault — Locked');
  // A needs-repair account vault under the lock outranks the overlay — the decision leads, not "Locked".
  const decision = computeStatus({ ...secure, locked: true, deviceLive: true, vaults: [vault({ vault: 'a', via: 'account', lastResult: 'conflict-keep-both' })] });
  assert.notStrictEqual(decision.state, STATE.PAUSED);
  assert.doesNotMatch(tooltip(decision, 'locked'), /Locked/);
  // L2: offline under the lock reads "waiting to reconnect" (nothing can sync), never a stale "up to date".
  assert.strictEqual(tooltip(computeStatus({ ...secure, online: false, locked: true, deviceLive: true, vaults: [vault({ vault: 'd1', via: 'device', lastResult: 'ok' })] }), 'locked'), 'DockVault — Locked · waiting to reconnect');
});

test('a configured-but-never-run vault reads the set-up-not-running label, never "Syncing"', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ lastResult: null, running: false })] });
  assert.strictEqual(m.state, STATE.WAITING);
  assert.strictEqual(tooltip(m, 'unlocked'), 'DockVault — Sync set up — not running yet');
  assert.doesNotMatch(tooltip(m, 'unlocked'), /Syncing/);
});

test('an unreadable saved-state problem reassures the reader their files are safe', () => {
  const m = computeStatus({ hasSecureStore: true, daemon: 'init-failed', vaults: [vault({ lastResult: 'ok' })] });
  assert.strictEqual(m.state, STATE.SYNC_PROBLEM);
  assert.strictEqual(m.reason, 'state-unreadable');
  assert.match(tooltip(m, 'unlocked'), /your files are safe/);
});

test("a code-fault sync problem reads as a calm, honest 'sync step hit a problem'", () => {
  const m = computeStatus({ ...secure, vaults: [vault({ lastResult: 'sync-error' })] });
  assert.strictEqual(m.state, STATE.SYNC_PROBLEM);
  assert.match(tooltip(m, 'unlocked'), /a sync step hit a problem/);
});

const PINNED = '1.75.0';
const helperVault = (sub, installed) => vault({ lastResult: 'ok', condition: { state: STATE.SYNC_PROBLEM, reason: 'helper-not-ready', sub, installed } });

test('helper-not-ready renders the honest label + correct per-sub detail for all 7 subs AND an unknown/null — non-retrying, with the how-to-fix affordance', () => {
  const cases = [
    ['version-mismatch', '1.60.0', /is version 1\.60\.0, but this app needs 1\.75\.0/],
    ['checksum-mismatch', null, /failed a safety check/],
    ['binary-missing', null, /file is missing/],
    ['spawn-failed', null, /blocked from starting/],
    ['obscure-failed', null, /couldn't be set up/], // a started-then-failed obscure: the neutral lane, never an AV accusation
    ['config-format-failed', null, /couldn't be set up/],
    ['prepare-failed', null, /couldn't be set up/],
    ['some-unknown-future-sub', null, /couldn't be set up/], // honest fallthrough — never blank, never a wrong lane
    [null, null, /couldn't be set up/],
  ];
  for (const [sub, installed, re] of cases) {
    const m = computeStatus({ ...secure, vaults: [helperVault(sub, installed)] });
    assert.strictEqual(m.state, STATE.SYNC_PROBLEM, `${sub}: a non-retrying sync problem`);
    assert.strictEqual(m.reason, 'helper-not-ready', `${sub}: the single helper-not-ready reason`);
    const tip = tooltip(m, 'unlocked', PINNED);
    assert.match(tip, /The sync helper isn't ready/, `${sub}: the honest helper label, not the generic Sync problem`);
    assert.match(tip, re, `${sub}: the correct per-sub detail`);
    assert.ok(mustActItems(m).some((it) => it.kind === 'setup-helper' && it.label === 'How to fix the sync helper'), `${sub}: the how-to-fix affordance is reachable`);
  }
});

test('a helper that RAN is never blamed on antivirus (missing + obscure-failed); only a genuine start-block points at SmartScreen/AV', () => {
  const missing = tooltip(computeStatus({ ...secure, vaults: [helperVault('binary-missing', null)] }), 'unlocked', PINNED);
  assert.match(missing, /file is missing/);
  assert.doesNotMatch(missing, /SmartScreen|antivirus/, 'a MISSING helper is never a blocked-by-AV accusation');
  // obscure-failed is a started-then-failed obscure — it too must never read as an antivirus block.
  const obscure = tooltip(computeStatus({ ...secure, vaults: [helperVault('obscure-failed', null)] }), 'unlocked', PINNED);
  assert.match(obscure, /couldn't be set up/);
  assert.doesNotMatch(obscure, /SmartScreen|antivirus/, 'a helper that RAN is never a blocked-by-AV accusation');
  // Only a genuine START block (spawn-failed) points at SmartScreen/AV.
  assert.match(tooltip(computeStatus({ ...secure, vaults: [helperVault('spawn-failed', null)] }), 'unlocked', PINNED), /SmartScreen/);
});

test('helper-not-ready is ONE app-scoped must-act even across multiple vaults (never duplicated per vault)', () => {
  const m = computeStatus({ ...secure, vaults: [helperVault('checksum-mismatch', null), vault({ vault: 'w', lastResult: 'ok', condition: { state: STATE.SYNC_PROBLEM, reason: 'helper-not-ready', sub: 'checksum-mismatch' } })] });
  assert.strictEqual(mustActItems(m).filter((it) => it.kind === 'setup-helper').length, 1, 'one app-scoped fix, never one per vault');
});

test('state-unreadable surfaces the unlock-and-reopen guidance as a must-act item, no dead reset reference', () => {
  const m = computeStatus({ hasSecureStore: true, daemon: 'init-failed', vaults: [vault({ lastResult: 'ok' })] });
  const it = mustActItems(m).find((x) => x.kind === 'reopen');
  assert.ok(it, 'a reopen-guidance must-act item is present (a real next step now)');
  // It names the keychain AND says what to do with the app afterwards. "reopening DockVault" used to stand
  // here and meant a third thing again — not the file browser, not the Computers window, but quit-and-start —
  // which is why it now says that plainly.
  assert.match(it.label, /unlocking your login keychain/);
  assert.match(it.label, /closing DockVault and starting it again/);
  assert.doesNotMatch(it.label, /reset/i); // no dangling reset reference until that button ships
});

test('a sync-error vault owns the fault in its must-act item (our side, not the user)', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ lastResult: 'sync-error' })] });
  const it = mustActItems(m).find((x) => x.vault === 'v');
  assert.ok(it);
  assert.match(it.label, /on our side/);
  assert.match(it.label, /not your connection or sign-in/);
});

test('must-act labels read the vault NAME via nameById, keep the id for the handler, and fall back to the id when unmapped', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ vault: 'vault-9f3a2b', lastResult: 'conflict-keep-both' })] });
  const named = mustActItems(m, { 'vault-9f3a2b': 'Payroll' }).find((it) => it.vault === 'vault-9f3a2b');
  assert.ok(named, 'the per-vault item is present');
  assert.match(named.label, /Payroll/, 'the label shows the name');
  assert.ok(!named.label.includes('vault-9f3a2b'), 'the label does not leak the id when a name is known');
  assert.strictEqual(named.vault, 'vault-9f3a2b', 'the item still carries the id the handler acts on');
  // unmapped (or no map at all): fall back to the id, never blank or "undefined"
  const bare = mustActItems(m).find((it) => it.vault === 'vault-9f3a2b');
  assert.match(bare.label, /vault-9f3a2b/, 'an unmapped id falls back to the id');
  assert.ok(!/undefined/.test(bare.label), 'never renders "undefined"');
});

test('pendingSetupItems: finish-setup vs keep-syncing wording, id fallback, and suppression when already surfaced', () => {
  const nameById = { v1: 'Payroll', v2: 'Notes' };
  const items = pendingSetupItems(['v1', 'v2'], { nameById, wasGranted: (id) => id === 'v2' });
  const byVault = Object.fromEntries(items.map((it) => [it.vault, it]));
  assert.strictEqual(byVault.v1.kind, 'open');
  assert.match(byVault.v1.label, /Open Payroll once to finish setting it up/i, 'a never-granted vault reads as finishing setup');
  assert.match(byVault.v2.label, /Open Notes with its new password to keep syncing it/i, 'a previously-granted vault reads as a re-proof with the new password');
  // a vault already surfaced with its own must-act line is not repeated as a calm nudge
  assert.deepStrictEqual(pendingSetupItems(['v1'], { nameById, alreadyShown: (id) => id === 'v1' }), []);
  // an unmapped id falls back to the id, never blank
  assert.match(pendingSetupItems(['v3'], {})[0].label, /v3/);
  assert.deepStrictEqual(pendingSetupItems([], {}), [], 'nothing pending → no items');
});

test('the device-ended states offer ONE identity-wide set-up-again action (deduped across vaults), a handled kind', () => {
  const ended = (v) => vault({ vault: v, condition: { state: STATE.NEEDS_DECISION, reason: 'device-revoked' } });
  const m = computeStatus({ ...secure, vaults: [ended('a'), ended('b')] });
  const setups = mustActItems(m).filter((it) => it.kind === 'set-up-again');
  assert.strictEqual(setups.length, 1, 'two revoked vaults collapse to one identity-wide set-up-again line (one re-registration fixes all)');
  assert.match(setups[0].label, /set it up again/i);
  assert.ok(HANDLED_ACTION_KINDS.includes('set-up-again'), 'set-up-again is a handled action kind');
});

test('deviceResetItem (the escape hatch) is a reachable, non-blank reset-device action', () => {
  const it = deviceResetItem();
  assert.strictEqual(it.kind, 'reset-device');
  assert.ok(it.label && it.label.length > 8 && !/undefined/.test(it.label), 'a real, non-blank label');
  assert.ok(HANDLED_ACTION_KINDS.includes('reset-device'), 'reset-device is in HANDLED_ACTION_KINDS so the tray can wire it');
});

test('the calm states carry a short why-suffix; up to date is bare', () => {
  assert.strictEqual(tooltip(computeStatus({ ...secure, vaults: [vault({ lastResult: 'ok' })] }), 'unlocked'), 'DockVault — Up to date');
  assert.strictEqual(tooltip(computeStatus({ ...secure, vaults: [vault({ lastResult: 'host-key-unverified' })] }), 'unlocked'), 'DockVault — Paused · cannot verify the server yet');
});

test('unavailable and not-configured render honestly (no false sync claim)', () => {
  assert.strictEqual(tooltip(computeStatus({ hasSecureStore: false }), 'unlocked'), 'DockVault — Sync unavailable');
  assert.strictEqual(tooltip(computeStatus({ ...secure, vaults: [] }), 'unlocked'), 'DockVault');
});

test('a stuck helper offers exactly one Restart action', () => {
  const m = computeStatus({ ...secure, crashLoopLatched: true, vaults: [vault({ lastResult: 'ok' })] });
  const items = mustActItems(m);
  assert.strictEqual(items.length, 1);
  assert.deepStrictEqual(items[0], { kind: 'restart', label: 'Restart sync' });
});

test('a persistent DOWN helper (per-vault sync-stopped, no crash-loop latch) offers exactly one Restart — no per-vault duplicate', () => {
  // The WEDGED case: no global crash-loop latch, but a vault's down-helper streak escalated to the 'sync-stopped'
  // restart lane. 'sync-stopped' is a GLOBAL helper condition, so it surfaces once as the restart — never also as a
  // per-vault "not syncing" item beside it (the subsumed per-vault item is suppressed, matching the notification).
  const m = computeStatus({ ...secure, vaults: [vault({ vault: 'a', lastResult: 'ok', condition: { state: STATE.SYNC_PROBLEM, reason: 'sync-stopped' } })] });
  const items = mustActItems(m);
  assert.strictEqual(items.length, 1, 'one restart, never a per-vault item beside it');
  assert.deepStrictEqual(items[0], { kind: 'restart', label: 'Restart sync' });
});

test('a down helper (sync-stopped) whose aggregate is STOLEN by another rank-6 vault still surfaces Restart — never dropped', () => {
  // V_other (host-key-mismatch, also rank-6) is ordered FIRST and wins the aggregate glance; V_down's shared helper
  // wedged to 'sync-stopped'. The Restart must STILL surface (it is gated on ANY sync-stopped vault, not only when
  // it wins the aggregate) — otherwise a wedged helper that blocks all sync would have no reachable recovery. The
  // other vault keeps its own action; the down vault stays subsumed (no duplicate).
  const m = computeStatus({ ...secure, vaults: [
    vault({ vault: 'other', lastResult: 'host-key-mismatch' }),
    vault({ vault: 'down', lastResult: 'ok', condition: { state: STATE.SYNC_PROBLEM, reason: 'sync-stopped' } }),
  ] });
  const items = mustActItems(m);
  assert.ok(items.some((it) => it.kind === 'restart'), 'Restart is surfaced even though another rank-6 vault won the aggregate');
  assert.ok(items.some((it) => it.vault === 'other'), "the other vault's own action is still shown");
  assert.ok(!items.some((it) => it.vault === 'down'), 'the down vault is subsumed by the global restart, never duplicated');
});

test('every unresolved vault item becomes a reachable tray action of the right kind', () => {
  const m = computeStatus({ ...secure, vaults: [
    vault({ vault: 'a', lastResult: 'conflict-keep-both' }),
    vault({ vault: 'b', lastResult: 'auth-failed' }),
    vault({ vault: 'c', lastResult: 'needs-resync', resyncRequired: true }),
    vault({ vault: 'd', lastResult: 'host-key-mismatch' }),
    vault({ vault: 'e', lastResult: 'ok' }),
  ] });
  const items = mustActItems(m);
  const byVault = Object.fromEntries(items.filter((i) => i.vault).map((i) => [i.vault, i.kind]));
  assert.strictEqual(byVault.a, 'review');
  assert.strictEqual(byVault.b, 'sign-in');
  assert.strictEqual(byVault.c, 'repair');
  assert.strictEqual(byVault.d, 'check-identity');
  assert.strictEqual(byVault.e, undefined, 'a clean vault offers no action');
});

test('no unresolved item => no must-act menu entries', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ lastResult: 'ok' })] });
  assert.deepStrictEqual(mustActItems(m), []);
});

test('a persistent cant-run condition becomes the right reachable tray action', () => {
  const m = computeStatus({ ...secure, vaults: [
    vault({ vault: 'a', lastResult: 'ok', condition: { state: STATE.NEEDS_DECISION, reason: 'vault-unavailable' } }),
    vault({ vault: 'b', lastResult: 'ok', condition: { state: STATE.NEEDS_DECISION, reason: 'folder-rejected' } }),
    vault({ vault: 'c', lastResult: 'ok', condition: { state: STATE.NEEDS_DECISION, reason: 'folder-problem' } }),
  ] });
  const items = mustActItems(m);
  const byVault = Object.fromEntries(items.filter((i) => i.vault).map((i) => [i.vault, i.kind]));
  assert.strictEqual(byVault.a, 'open', 'an unavailable vault is reachable, calmly worded');
  assert.strictEqual(byVault.b, 'choose-folder', 'a gone folder routes back to picking a folder');
  assert.match(items.find((i) => i.vault === 'b').label, /choose a folder again/);
  // A re-shared folder is a DISTINCT action: re-present the make-private consent, not pick a new folder.
  assert.strictEqual(byVault.c, 'recover-folder', 'a re-shared folder offers to make it private again');
  assert.match(items.find((i) => i.vault === 'c').label, /shared again — make it private/);
});

test('consent-declined reads as calm WAITING and earns NO must-act item (never nags a made choice)', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ vault: 'a', condition: { state: STATE.WAITING, reason: 'consent-needed' } })] });
  assert.strictEqual(m.vaults[0].state, STATE.WAITING);
  assert.deepStrictEqual(mustActItems(m), []);
});

test('"Sync now" is offered when idle, but a running vault shows the run in progress, never a false new start', () => {
  const idle = syncNowItem({ vault: 'a', running: false });
  assert.deepStrictEqual(idle, { kind: 'sync-now', vault: 'a', enabled: true, label: 'Sync a now' });
  const running = syncNowItem({ vault: 'a', running: true });
  assert.strictEqual(running.kind, 'syncing');
  assert.strictEqual(running.enabled, false, 'a run in flight is not clickable as a fresh "Sync now"');
  assert.doesNotMatch(running.label, /Sync a now/);
});

test('"Last synced" reads from the last-success time only, never fabricating one', () => {
  const now = 10 * 24 * 60 * 60 * 1000; // a fixed reference instant
  assert.strictEqual(lastSyncedLabel(null, now), 'Not synced yet');
  assert.strictEqual(lastSyncedLabel(now - 30 * 1000, now), 'Last synced just now');
  assert.strictEqual(lastSyncedLabel(now - 5 * 60 * 1000, now), 'Last synced 5 min ago');
  assert.strictEqual(lastSyncedLabel(now - 3 * 60 * 60 * 1000, now), 'Last synced 3 h ago');
  assert.strictEqual(lastSyncedLabel(now - 2 * 24 * 60 * 60 * 1000, now), 'Last synced 2 d ago');
  assert.strictEqual(lastSyncedLabel(now + 5000, now), 'Last synced just now', 'a clock step to the future never reads as a negative age');
});

test('a sleep-woken desktop reads "paused since sleep — Resume sync", not a bare Locked; other lock reasons keep Locked', () => {
  const m = computeStatus({ ...secure, locked: true, deviceLive: true, vaults: [vault({ vault: 'a', via: 'account', lastResult: 'ok' })] });
  assert.strictEqual(m.state, STATE.PAUSED, 'an account vault under lock is paused');
  assert.strictEqual(tooltip(m, null, null, { lockReason: 'sleep' }), 'DockVault — Sync paused since sleep — Resume sync to continue');
  assert.match(tooltip(m, null, null, { lockReason: 'os-lock' }), /^DockVault — Locked/, 'a real screen lock still reads Locked');
  assert.match(tooltip(m, null, null, {}), /^DockVault — Locked/, 'no reason → the existing Locked glance');
});

test('a lost folder is a relocate-folder must-act with a plain line per way of losing it', () => {
  const kinds = new Set();
  for (const reason of ['folder-missing', 'folder-marker-missing', 'folder-other-vault', 'folder-marker-unreadable', 'folder-ambiguous', 'folder-moved-rejected', 'folder-found-elsewhere', 'folder-marker-unwritable']) {
    const it = itemForVault({ vault: 'v1', reason }, { v1: 'Photos' });
    assert.strictEqual(it.kind, 'relocate-folder', reason);
    assert.ok(HANDLED_ACTION_KINDS.includes(it.kind));
    assert.ok(it.label.includes('Photos'), it.label);
    assert.ok(/find|choose|confirm|check the folder/i.test(it.label), it.label);
    kinds.add(it.label);
    assert.ok(typeof REASON_DETAIL[reason] === 'string' && REASON_DETAIL[reason].length > 10, `detail for ${reason}`);
  }
  assert.strictEqual(kinds.size, 8, 'each reason reads differently');
  assert.strictEqual(itemForVault({ vault: 'v1', reason: 'config-unwritable' }, { v1: 'Photos' }).kind, 'open');
  assert.ok(REASON_DETAIL['config-unwritable']);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { tooltip, mustActItems, syncNowItem, lastSyncedLabel, vaultRows } = require('../src/main/tray-presentation');
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

test('a configured-but-never-run vault reads the set-up-not-running label, never "Syncing"', () => {
  const m = computeStatus({ ...secure, vaults: [vault({ lastResult: null, running: false })] });
  assert.strictEqual(m.state, STATE.WAITING);
  assert.strictEqual(tooltip(m, 'unlocked'), 'DockVault — Sync set up — not running yet');
  assert.doesNotMatch(tooltip(m, 'unlocked'), /Syncing/);
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

test('vaultRows matches each configured vault to its live status, honestly, with a safe fallback', () => {
  const now = 10 * 24 * 60 * 60 * 1000;
  const configured = [
    { vaultId: 'v1', vaultName: 'Marketing' },
    { vaultId: 'v2', vaultName: 'Finance' },
    { vaultId: 'v3', vaultName: 'Design' },
  ];
  const modelVaults = [
    { vault: 'v1', running: true, lastSyncedAt: now - 5 * 60 * 1000 },   // a run in flight
    { vault: 'v2', running: false, lastSyncedAt: now - 60 * 1000 },      // idle, synced a minute ago
    // v3 has no computed status entry yet
  ];
  const rows = vaultRows(configured, modelVaults, now);
  assert.strictEqual(rows.length, 3);
  // v1: in flight -> shows the run, the "Sync now" is not offered as a fresh start
  assert.strictEqual(rows[0].syncLabel, 'Syncing…');
  assert.strictEqual(rows[0].syncEnabled, false);
  assert.match(rows[0].lastSynced, /Last synced/);
  // v2: idle -> "Sync now" offered (enqueues), and a real last-synced time
  assert.strictEqual(rows[1].syncLabel, 'Sync now');
  assert.strictEqual(rows[1].syncEnabled, true);
  assert.strictEqual(rows[1].lastSynced, 'Last synced 1 min ago');
  // v3: no status yet -> safe fallback (not running, never synced), never a stale/false view
  assert.strictEqual(rows[2].syncLabel, 'Sync now');
  assert.strictEqual(rows[2].syncEnabled, true);
  assert.strictEqual(rows[2].lastSynced, 'Not synced yet');
  assert.strictEqual(rows[2].vaultId, 'v3');
  assert.strictEqual(rows[2].vaultName, 'Design');
});

test('vaultRows is empty when nothing is configured, regardless of stray status entries', () => {
  assert.deepStrictEqual(vaultRows([], [{ vault: 'ghost', running: true }], 0), []);
  assert.deepStrictEqual(vaultRows(undefined, undefined, 0), []);
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

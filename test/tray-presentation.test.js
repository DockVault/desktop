'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { tooltip, mustActItems } = require('../src/main/tray-presentation');
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
  assert.strictEqual(tooltip(m, 'unlocked'), 'DockVault — Sync set up - not running yet');
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

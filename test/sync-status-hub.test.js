'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { SyncStatusHub } = require('../src/main/sync-status-hub');
const { STATE } = require('../src/main/sync-status-model');

function fakeDaemon() {
  const ls = [];
  return { on(e, cb) { ls.push([e, cb]); return this; }, emit(e, d) { for (const [ev, cb] of ls) if (ev === e) cb(d); } };
}

function harness(deps = {}) {
  const statuses = [];
  const notifies = [];
  const daemon = fakeDaemon();
  const hub = new SyncStatusHub({ daemon, onStatus: (m) => statuses.push(m), onNotify: (n) => notifies.push(n), hasSecureStore: true, online: true, ...deps });
  return { hub, daemon, statuses, notifies };
}

test('emits the computed status on change and suppresses no-op re-emits', () => {
  const { hub, daemon, statuses } = harness();
  daemon.emit('ready', { encrypted: true }); // the helper is up (until then, sync is honestly paused)
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'ok', resyncRequired: false });
  const n = statuses.length;
  hub.recordOutcome('a', { result: 'ok', resyncRequired: false }); // same picture
  assert.strictEqual(statuses.length, n, 'an unchanged recompute does not re-emit');
  assert.strictEqual(statuses[statuses.length - 1].state, STATE.UP_TO_DATE);
});

test('daemon lifecycle drives the state: crash -> paused(reconnecting), crash-loop -> sync problem, resume -> starting', () => {
  const { hub, daemon, statuses, notifies } = harness();
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'ok' });
  daemon.emit('exit', { code: 1 });
  assert.strictEqual(hub.current().state, STATE.PAUSED);
  assert.strictEqual(hub.current().reason, 'reconnecting');
  daemon.emit('crash-loop', { restarts: 5 });
  assert.strictEqual(hub.current().state, STATE.SYNC_PROBLEM);
  assert.ok(notifies.some((x) => x.scope === 'daemon' && x.reason === 'sync-stopped'), 'a stuck helper raises one must-act notification');
  daemon.emit('resume', {});
  assert.strictEqual(hub.current().reason, 'reconnecting'); // starting again, below the ceiling
  assert.ok(statuses.length > 0);
});

test('a must-act item notifies once, not on every recompute, and re-notifies only after it clears and recurs', () => {
  const { hub, notifies } = harness();
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'conflict-keep-both' });
  assert.strictEqual(notifies.length, 1);
  hub.setRunning('a', true);  // a recompute that keeps the conflict outstanding
  hub.setRunning('a', false);
  assert.strictEqual(notifies.length, 1, 'still just the one notification');
  hub.recordOutcome('a', { result: 'ok' });       // cleared
  hub.recordOutcome('a', { result: 'conflict-keep-both' }); // recurs
  assert.strictEqual(notifies.length, 2, 're-announced after clearing and recurring');
});

test('lock pauses a clean vault (no notification) but never hides an unresolved item', () => {
  const { hub, notifies } = harness();
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'ok' });
  hub.setLocked(true);
  assert.strictEqual(hub.current().state, STATE.PAUSED);
  assert.strictEqual(notifies.length, 0, 'a plain locked-and-clean vault is not a must-act');
  hub.recordOutcome('a', { result: 'conflict-keep-both' });
  assert.strictEqual(hub.current().state, STATE.NEEDS_DECISION, 'a locked vault with a conflict is a decision, not merely paused');
  assert.strictEqual(notifies.length, 1);
});

test('no secure store => unavailable; no vaults => not-configured', () => {
  const a = harness({ hasSecureStore: false });
  assert.strictEqual(a.hub.current().state, STATE.UNAVAILABLE);
  const b = harness();
  assert.strictEqual(b.hub.current().state, STATE.NOT_CONFIGURED);
});

test('the emitted model is cred-free (no credential, host key, token, or user field anywhere)', () => {
  const { hub, statuses } = harness();
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'auth-failed' });
  const blob = JSON.stringify(statuses);
  for (const forbidden of ['password', 'hostKeys', 'host', 'token', 'obscured', 'credential', 'expiresAt', 'secret']) {
    assert.strictEqual(blob.includes(forbidden), false, `no "${forbidden}" on the status surface`);
  }
});

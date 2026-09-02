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
  const toasts = [];
  const daemon = fakeDaemon();
  const hub = new SyncStatusHub({ daemon, onStatus: (m) => statuses.push(m), onNotify: (n) => notifies.push(n), onToast: (t) => toasts.push(t), hasSecureStore: true, online: true, ...deps });
  return { hub, daemon, statuses, notifies, toasts };
}

test('emits the computed status on change and suppresses no-op re-emits', () => {
  // A fixed clock so two identical successes stamp the same last-synced time: an unchanged picture must
  // not re-emit. (A success at a genuinely later instant SHOULD re-emit — that is covered separately.)
  const { hub, daemon, statuses } = harness({ now: () => 5000 });
  daemon.emit('ready', { encrypted: true }); // the helper is up (until then, sync is honestly paused)
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'ok', resyncRequired: false });
  const n = statuses.length;
  hub.recordOutcome('a', { result: 'ok', resyncRequired: false }); // same picture, same instant
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

test('"Last synced" is stamped only by a successful run, and advances with each later success', () => {
  let clock = 1000;
  const { hub } = harness({ now: () => clock });
  hub.setVaults(['a']);
  const at = () => hub.current().vaults.find((v) => v.vault === 'a').lastSyncedAt;
  assert.strictEqual(at(), null, 'never synced yet -> no last-synced time');
  hub.recordOutcome('a', { result: 'error' });
  assert.strictEqual(at(), null, 'a failed run does not stamp a last-synced time');
  hub.recordOutcome('a', { result: 'conflict-keep-both' });
  assert.strictEqual(at(), null, 'a conflict (needs a decision) does not stamp a last-synced time');
  clock = 2000;
  hub.recordOutcome('a', { result: 'ok' });
  assert.strictEqual(at(), 2000, 'a success stamps the time');
  hub.recordOutcome('a', { result: 'needs-resync', resyncRequired: true });
  assert.strictEqual(at(), 2000, 'a later blocked run leaves the last SUCCESS time untouched, not cleared');
  clock = 3000;
  hub.recordOutcome('a', { result: 'resync-ok', resyncRequired: false });
  assert.strictEqual(at(), 3000, 'a later success advances it');
});

test('the first successful sync of a vault toasts once; failures never toast, later successes do not re-toast', () => {
  const { hub, toasts } = harness({ now: () => 42 });
  hub.setVaults(['a', 'b']);
  hub.recordOutcome('a', { result: 'error' });
  hub.recordOutcome('a', { result: 'auth-failed' });
  assert.strictEqual(toasts.length, 0, 'no toast until a real success');
  hub.recordOutcome('a', { result: 'resync-ok' });
  assert.deepStrictEqual(toasts, [{ scope: 'vault', vault: 'a', kind: 'first-success' }], 'the first success toasts once, naming the vault (so the layer can offer Open folder)');
  hub.recordOutcome('a', { result: 'ok' });
  assert.strictEqual(toasts.length, 1, 'a later success does not re-toast');
  hub.recordOutcome('b', { result: 'ok' });
  assert.strictEqual(toasts.length, 2, 'a different vault gets its own first-success toast');
  assert.strictEqual(toasts[1].vault, 'b');
});

test('a first-success toast carries no file count and no credential-shaped field', () => {
  const { hub, toasts } = harness();
  hub.setVaults(['a']);
  hub.recordOutcome('a', { result: 'ok' });
  const blob = JSON.stringify(toasts);
  for (const forbidden of ['count', 'files', 'password', 'hostKeys', 'token', 'path']) {
    assert.strictEqual(blob.includes(forbidden), false, `the toast carries no "${forbidden}"`);
  }
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

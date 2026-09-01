'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { DaemonManager } = require('../src/main/daemon-manager');

// These exercise the zk-lock request->ack contract in isolation with a fake child; the full forked
// round-trip is covered by the Electron functional check (test/daemon-check.js).

test('zkLock() resolves true once the daemon acks (request->ack, id-correlated)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  const p = mgr.zkLock(1000);
  assert.strictEqual(sent.type, 'zk-lock');
  assert.ok(typeof sent.id === 'number', 'the request carries a correlation id');
  mgr._onMessage({ type: 'zk-locked', id: sent.id });
  assert.strictEqual(await p, true);
});

test('zkLock() resolves false on ack timeout while the daemon is alive (fail-closed input)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.child = { postMessage: () => { /* never acks */ } };
  assert.strictEqual(await mgr.zkLock(20), false);
});

test('zkLock() resolves true when there is no daemon (a dead process holds no key)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.child = null;
  assert.strictEqual(await mgr.zkLock(20), true);
});

test('a daemon exit mid-purge resolves the pending ack as clean (crash = key gone)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.stopping = true; // suppress the restart path in this unit context
  mgr.child = { postMessage: () => {} };
  const p = mgr.zkLock(5000);
  mgr._onExit(1);
  assert.strictEqual(await p, true);
});

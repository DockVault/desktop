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

test('runSync() round-trips a summarized bisync outcome (id-correlated), never raw output', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  const p = mgr.runSync({ vault: 'v1', local: 'l', remotePath: 'p', resync: true }, 1000);
  assert.strictEqual(sent.type, 'sync-run');
  assert.deepStrictEqual(sent.spec, { vault: 'v1', local: 'l', remotePath: 'p', resync: true });
  assert.ok(typeof sent.id === 'number');
  mgr._onMessage({ type: 'sync-run-result', id: sent.id, ok: true, ran: true, result: 'abort-excessive-delete', resyncRequired: true, needsAttention: true, code: 2 });
  assert.deepStrictEqual(await p, { ok: true, ran: true, result: 'abort-excessive-delete', resyncRequired: true, needsAttention: true, code: 2, error: null });
});

test('runSync() resolves not-ok when there is no daemon, or the send fails', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.child = null;
  assert.deepStrictEqual(await mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 20), { ok: false, ran: false, error: 'no daemon' });
  mgr.child = { postMessage: () => { throw new Error('channel gone'); } };
  assert.deepStrictEqual(await mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 20), { ok: false, ran: false, error: 'send failed' });
});

test('a daemon exit mid-run resolves the pending bisync as not-ok (never hangs)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.stopping = true;
  mgr.child = { postMessage: () => {} };
  const p = mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 5000);
  mgr._onExit(1);
  assert.deepStrictEqual(await p, { ok: false, ran: false, error: 'daemon exited' });
});

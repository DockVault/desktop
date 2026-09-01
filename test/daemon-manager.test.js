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

// ---- crash-loop ceiling ----

function laddered(opts) {
  let clock = 0;
  const mgr = new DaemonManager('/nonexistent', null, { now: () => clock, ...opts });
  mgr._spawn = () => { mgr._spawned = (mgr._spawned || 0) + 1; }; // never fork in a unit test
  const events = [];
  mgr.on('crash-loop', (d) => events.push(['crash-loop', d]));
  mgr.on('exit', (d) => events.push(['exit', d]));
  mgr.on('resume', () => events.push(['resume']));
  return { mgr, events, tick: (t) => { clock = t; } };
}

test('crash-loop ceiling: repeated exits inside the window latch a stuck state and stop restarting', () => {
  const { mgr, events, tick } = laddered({ maxRestarts: 3, crashWindowMs: 1000 });
  tick(0); mgr._onExit(1);
  tick(100); mgr._onExit(1);
  assert.strictEqual(mgr.crashLoopLatched, false, 'below the ceiling it keeps restarting');
  assert.strictEqual(mgr.status, 'crashed');
  tick(200); mgr._onExit(1); // third exit in the window -> ceiling
  assert.strictEqual(mgr.crashLoopLatched, true);
  assert.strictEqual(mgr.status, 'crash-looped');
  assert.strictEqual(mgr._spawned || 0, 0, 'the ceiling path does not spawn; only a deliberate resume() does');
  const cl = events.filter((e) => e[0] === 'crash-loop');
  assert.strictEqual(cl.length, 1);
  assert.strictEqual(cl[0][1].restarts, 3);
});

test('crash-loop ceiling: exits spread beyond the window never latch (window is pruned)', () => {
  const { mgr, tick } = laddered({ maxRestarts: 3, crashWindowMs: 1000 });
  tick(0); mgr._onExit(1);
  tick(5000); mgr._onExit(1);
  tick(10000); mgr._onExit(1);
  assert.strictEqual(mgr.crashLoopLatched, false, 'far-apart crashes are not a loop');
  assert.strictEqual(mgr._restartTimes.length, 1);
});

test('resume() only ever restarts FROM the latched state, never forces a second helper', () => {
  const { mgr, events } = laddered({ maxRestarts: 2, crashWindowMs: 1000 });
  assert.strictEqual(mgr.resume(), false, 'a no-op when not latched');
  assert.strictEqual(mgr._spawned || 0, 0);
  mgr._onExit(1); mgr._onExit(1); // latch
  assert.strictEqual(mgr.crashLoopLatched, true);
  assert.strictEqual(mgr.resume(), true);
  assert.strictEqual(mgr.crashLoopLatched, false);
  assert.strictEqual(mgr.restarts, 0);
  assert.strictEqual(mgr._restartTimes.length, 0);
  assert.strictEqual(mgr._spawned, 1, 'exactly one respawn');
  assert.ok(events.some((e) => e[0] === 'resume'));
});

test('a clean ready breaks the loop history (counters + latch reset)', () => {
  const { mgr } = laddered({ maxRestarts: 2, crashWindowMs: 1000 });
  mgr._onExit(1);
  assert.strictEqual(mgr.restarts, 1);
  mgr._onMessage({ type: 'ready', encrypted: true });
  assert.strictEqual(mgr.status, 'ready');
  assert.strictEqual(mgr.restarts, 0);
  assert.strictEqual(mgr._restartTimes.length, 0);
  assert.strictEqual(mgr.crashLoopLatched, false);
});

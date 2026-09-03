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
  assert.deepStrictEqual(await p, { ok: true, ran: true, result: 'abort-excessive-delete', reason: null, resyncRequired: true, needsAttention: true, code: 2, preserved: null, refused: null });
});

test('sync-run-result and sync-status resolves carry a bounded reason, never a raw error string (leak-close)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  // A run failure carries the bounded reason; any raw error a message might carry is dropped, never passed on.
  const p1 = mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 1000);
  mgr._onMessage({ type: 'sync-run-result', id: sent.id, ok: false, reason: 'run-error', error: 'a raw message that could carry a host or path' });
  const r1 = await p1;
  assert.strictEqual(r1.reason, 'run-error');
  assert.ok(!('error' in r1), 'the run resolve never carries an error field');
  // The rclone health status is the same: a bounded reason only.
  const p2 = mgr.syncStatus(1000);
  mgr._onMessage({ type: 'sync-status', id: sent.id, ok: false, sub: 'checksum-mismatch', installed: null, pinned: '1.65.2', error: 'a raw message that could carry a path' });
  const r2 = await p2;
  assert.strictEqual(r2.sub, 'checksum-mismatch');
  assert.strictEqual(r2.pinned, '1.65.2');
  assert.ok(!('error' in r2), 'the status resolve never carries an error field');
});

test('_sendInit PRODUCES the typed keyReason from a loadOrMintDBK throw — never mints, never re-escapes', () => {
  const stateDb = require('../src/main/state-db');
  const origLoad = stateDb.loadOrMintDBK;
  try {
    const mgr = new DaemonManager('/nonexistent');
    let sent = null;
    mgr.child = { postMessage: (m) => { sent = m; } };

    // (a) An existing-but-undecryptable wrapped key: loadOrMintDBK throws the typed error. _sendInit must
    // hand in NO key and carry the extracted reason — a fresh key is never minted (the DB is never orphaned)
    // and the throw never re-escapes to leave the supervisor stuck 'starting'.
    stateDb.loadOrMintDBK = () => { const e = new Error('unreadable'); e.reason = 'db-key-unreadable'; throw e; };
    mgr._sendInit();
    assert.strictEqual(sent.type, 'init');
    assert.strictEqual(sent.dbk, null, 'no key is handed in when the wrapped key cannot be unwrapped');
    assert.strictEqual(sent.keyReason, 'db-key-unreadable');

    // (b) A throw with no reason falls back to the typed db-key-unreadable (extraction is robust).
    stateDb.loadOrMintDBK = () => { throw new Error('opaque'); };
    mgr._sendInit();
    assert.strictEqual(sent.dbk, null);
    assert.strictEqual(sent.keyReason, 'db-key-unreadable');

    // (c) The insecure-backend case (loadOrMintDBK returns null) is benign: no key, no reason -> the daemon
    // reports 'no-secure-store', not a problem.
    stateDb.loadOrMintDBK = () => null;
    mgr._sendInit();
    assert.strictEqual(sent.dbk, null);
    assert.strictEqual(sent.keyReason, null);

    // (d) The happy path still hands the key in, with no keyReason.
    stateDb.loadOrMintDBK = () => Buffer.alloc(32, 7);
    mgr._sendInit();
    assert.ok(sent.dbk instanceof Uint8Array && sent.dbk.length === 32, 'the key is handed in on the normal path');
    assert.strictEqual(sent.keyReason, null);
  } finally {
    stateDb.loadOrMintDBK = origLoad;
  }
});

test('runSync() surfaces a TYPED already-running refusal (never a failure or a completion)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  const p = mgr.runSync({ vault: 'v1', local: 'l', remotePath: 'p' }, 1000);
  mgr._onMessage({ type: 'sync-run-result', id: sent.id, ok: false, ran: false, refused: 'already-running' });
  const r = await p;
  assert.strictEqual(r.refused, 'already-running');
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.ran, false);
});

test('runSync() carries the keep-both preservation count back when a resync reports one', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  const p = mgr.runSync({ vault: 'v1', local: 'l', remotePath: 'p', resync: true }, 1000);
  mgr._onMessage({ type: 'sync-run-result', id: sent.id, ok: true, ran: true, result: 'conflict-keep-both', resyncRequired: false, needsAttention: true, preserved: 3 });
  const r = await p;
  assert.strictEqual(r.preserved, 3, 'the keep-both count round-trips to the caller');
  assert.strictEqual(r.result, 'conflict-keep-both');
});

test('runSync() resolves not-ok when there is no daemon, or the send fails', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.child = null;
  assert.deepStrictEqual(await mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 20), { ok: false, ran: false, error: 'no daemon' });
  mgr.child = { postMessage: () => { throw new Error('channel gone'); } };
  assert.deepStrictEqual(await mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 20), { ok: false, ran: false, error: 'send failed' });
});

test('a daemon exit mid-run resolves the pending bisync as not-ok with a typed reason (never hangs)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.stopping = true;
  mgr.child = { postMessage: () => {} };
  const p = mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 5000);
  mgr._onExit(1);
  // A daemon exit resolves in-flight requests with a BOUNDED typed reason ('daemon-exited'), never a free-text
  // string — consistent with the op-only error events, so no raw text rides the exit path either.
  assert.deepStrictEqual(await p, { ok: false, ran: false, reason: 'daemon-exited' });
});

test('a daemon exit resolves in-flight status + cred requests with the same typed reason (no free-text, no bundle echo)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.stopping = true;
  mgr.child = { postMessage: () => {} };
  const ps = mgr.syncStatus(5000);
  const pc = mgr.sendSftpCred({ host: 'h', port: 22, user: 'u', password: 'topsecret', hostKeys: 'k' }, 5000);
  mgr._onExit(1);
  assert.deepStrictEqual(await ps, { ok: false, version: null, reason: 'daemon-exited' });
  const cred = await pc;
  assert.deepStrictEqual(cred, { ok: false, reason: 'daemon-exited' }, 'typed reason only — no free-text error, no credential echoed back');
  assert.ok(!JSON.stringify(cred).includes('topsecret'), 'the bundle never rides the exit resolve');
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

test('clearSftpCred() sends sftp-cred-clear and resolves ok on the ack; ok (vacuously) with no daemon', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  const p = mgr.clearSftpCred(1000);
  assert.strictEqual(sent.type, 'sftp-cred-clear');
  assert.ok(typeof sent.id === 'number');
  mgr._onMessage({ type: 'sftp-cred-ack', id: sent.id, ok: true });
  assert.deepStrictEqual(await p, { ok: true, sub: null, installed: null, pinned: null });
  mgr.child = null;
  assert.deepStrictEqual(await mgr.clearSftpCred(20), { ok: true }, 'no daemon holds no credential — nothing to clear');
});

test('sftp-cred-ack carries only the typed `sub` enum, never a raw error string (leak-close)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  // A failure ack from a helper that no longer echoes the raw error resolves with sub:null (=> the caller
  // maps to a generic, honest reason), and any stray `error` the helper might send is dropped, never passed on.
  const p1 = mgr.sendSftpCred({ vault: 'v1', host: 'h', port: 22, user: 'u', password: 'p', hostKeys: ['k'] }, 1000);
  mgr._onMessage({ type: 'sftp-cred-ack', id: sent.id, ok: false, error: 'raw failure text that could carry a host or path' });
  const r1 = await p1;
  assert.deepStrictEqual(r1, { ok: false, sub: null, installed: null, pinned: null }, 'a raw error on the ack is dropped, not surfaced');
  assert.ok(!('error' in r1), 'the resolved ack never carries an error field');
  // The typed sub + the non-secret version strings pass through; a raw error never does.
  const p2 = mgr.sendSftpCred({ vault: 'v1', host: 'h', port: 22, user: 'u', password: 'p', hostKeys: ['k'] }, 1000);
  mgr._onMessage({ type: 'sftp-cred-ack', id: sent.id, ok: false, sub: 'version-mismatch', installed: '1.60.0', pinned: '1.65.2', error: 'raw text with a /path that must not pass' });
  assert.deepStrictEqual(await p2, { ok: false, sub: 'version-mismatch', installed: '1.60.0', pinned: '1.65.2' });
});

test('runStates() round-trips the per-vault snapshot; null for a never-run vault', async () => {
  const mgr = new DaemonManager('/nonexistent');
  let sent = null;
  mgr.child = { postMessage: (m) => { sent = m; } };
  const p = mgr.runStates(['a', 'b'], 1000);
  assert.strictEqual(sent.type, 'run-state');
  assert.deepStrictEqual(sent.vaults, ['a', 'b']);
  mgr._onMessage({ type: 'run-state-result', id: sent.id, states: { a: { lastResult: 'ok', resyncRequired: false }, b: null } });
  assert.deepStrictEqual(await p, { ok: true, states: { a: { lastResult: 'ok', resyncRequired: false }, b: null } });
});

test('runStates() distinguishes a FAILED query ({ok:false}) from a successful-but-empty snapshot', async () => {
  // no daemon -> failure, not an empty success (so the glue never reads it as "every vault never-run")
  const noDaemon = new DaemonManager('/nonexistent');
  noDaemon.child = null;
  assert.deepStrictEqual(await noDaemon.runStates(['a'], 20), { ok: false });
  // a real answer with no rows -> success with an empty snapshot (all genuinely never-run)
  const live = new DaemonManager('/nonexistent');
  let sent = null;
  live.child = { postMessage: (m) => { sent = m; } };
  const p = live.runStates(['a'], 1000);
  live._onMessage({ type: 'run-state-result', id: sent.id, states: {} });
  assert.deepStrictEqual(await p, { ok: true, states: {} });
});

test('a daemon exit resolves an in-flight run-state query as a FAILURE (never an empty success)', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.stopping = true;
  mgr.child = { postMessage: () => {} };
  const p = mgr.runStates(['a'], 5000);
  mgr._onExit(1);
  assert.deepStrictEqual(await p, { ok: false });
});

// The helper-initiated per-step credential request (resync fresh-cred-per-process). Main AUTHORISES it: it
// bounds the count per run, delegates the in-flight-vault/unlock/account checks + mint to an injected provider,
// and replies with only { ok, reason } — never a credential (that travels on the sftp-cred path).
test('need-sftp-cred: authorises via the injected provider and replies only {ok,reason}, no credential', async () => {
  const mgr = new DaemonManager('/nonexistent');
  const posted = [];
  mgr.child = { postMessage: (m) => posted.push(m) };
  let asked = null;
  mgr.setCredProvider(async (vault) => { asked = vault; return { ok: true }; });
  await mgr._onNeedSftpCred({ type: 'need-sftp-cred', id: 'nc1', vault: 'v1' });
  assert.strictEqual(asked, 'v1', 'the provider is asked for the requested vault');
  const reply = posted.find((m) => m.type === 'need-sftp-cred-result');
  assert.deepStrictEqual(reply, { type: 'need-sftp-cred-result', id: 'nc1', ok: true, reason: null });
  assert.ok(!('bundle' in reply) && !('password' in reply) && !('hostKeys' in reply), 'the reply carries no credential');
});

test('need-sftp-cred: a provider refusal (not-in-flight / locked) rides back as the reason, mints nothing extra', async () => {
  const mgr = new DaemonManager('/nonexistent');
  const posted = [];
  mgr.child = { postMessage: (m) => posted.push(m) };
  mgr.setCredProvider(async () => ({ ok: false, reason: 'not-in-flight' }));
  await mgr._onNeedSftpCred({ type: 'need-sftp-cred', id: 'nc2', vault: 'other' });
  assert.deepStrictEqual(posted.pop(), { type: 'need-sftp-cred-result', id: 'nc2', ok: false, reason: 'not-in-flight' });
});

test('need-sftp-cred: a provider that THROWS surfaces a distinct provider-error, never the generic mint-failed', async () => {
  const mgr = new DaemonManager('/nonexistent');
  const posted = [];
  mgr.child = { postMessage: (m) => posted.push(m) };
  // A code error in the provider (e.g. calling an unexposed io method) must NOT be swallowed as the generic
  // retryable 'mint-failed' — that hid a real bug behind an endless per-tick retry. It surfaces distinctly.
  mgr.setCredProvider(async () => { throw new TypeError('io.hasAccount is not a function'); });
  await mgr._onNeedSftpCred({ type: 'need-sftp-cred', id: 'nc3', vault: 'v1' });
  assert.deepStrictEqual(posted.pop(), { type: 'need-sftp-cred-result', id: 'nc3', ok: false, reason: 'provider-error' });
});

test('need-sftp-cred: a bad request and a missing provider fail closed without minting', async () => {
  const mgr = new DaemonManager('/nonexistent');
  const posted = [];
  mgr.child = { postMessage: (m) => posted.push(m) };
  let called = 0;
  mgr.setCredProvider(async () => { called += 1; return { ok: true }; });
  await mgr._onNeedSftpCred({ type: 'need-sftp-cred', id: 'x', vault: null }); // no vault
  assert.strictEqual(called, 0, 'a bad request never reaches the provider');
  assert.strictEqual(posted.pop().reason, 'bad-request');

  const mgr2 = new DaemonManager('/nonexistent');
  const posted2 = [];
  mgr2.child = { postMessage: (m) => posted2.push(m) };
  await mgr2._onNeedSftpCred({ type: 'need-sftp-cred', id: 'y', vault: 'v1' }); // no provider wired
  assert.strictEqual(posted2.pop().reason, 'no-provider');
});

test('need-sftp-cred: the per-run request count is bounded — past the cap mints nothing', async () => {
  const mgr = new DaemonManager('/nonexistent');
  const posted = [];
  mgr.child = { postMessage: (m) => posted.push(m) };
  let called = 0;
  mgr.setCredProvider(async () => { called += 1; return { ok: true }; });
  mgr._credRequestsThisRun = 1e9; // well past any cap — a runaway helper
  await mgr._onNeedSftpCred({ type: 'need-sftp-cred', id: 'z', vault: 'v1' });
  assert.strictEqual(called, 0, 'past the cap, nothing is minted');
  assert.strictEqual(posted.pop().reason, 'cap-exceeded');
});

test('need-sftp-cred: the per-run request budget resets at the start of each run', async () => {
  const mgr = new DaemonManager('/nonexistent');
  mgr.child = { postMessage: () => {} };
  mgr._credRequestsThisRun = 500;
  mgr.runSync({ vault: 'v', local: 'l', remotePath: 'p' }, 1000); // sends + awaits; not awaited here
  assert.strictEqual(mgr._credRequestsThisRun, 0, 'a fresh run resets the per-step credential budget');
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { LockState } = require('../src/main/lock-state');

// A live window whose renderer purge succeeds (records the injected JS).
function okWin(rec) {
  return {
    isDestroyed: () => false,
    destroy: () => { rec.destroyed = true; },
    webContents: { executeJavaScript: (js) => { rec.js = js; return Promise.resolve(true); } },
  };
}
// A daemon that acks the purge.
function okDaemon(rec) {
  return { zkLock: () => { rec.daemonLocked = true; return Promise.resolve(true); } };
}
const FAST = { rendererTimeoutMs: 30, daemonTimeoutMs: 30, daemonAttempts: 2 };

test('lock() awaits both purges, then flips to locked via a transitional "locking" (atomic dual-key purge)', async () => {
  const rec = {};
  const changes = [];
  const ls = new LockState({
    getWindow: () => okWin(rec),
    getDaemon: () => okDaemon(rec),
    onChange: (s, r) => changes.push([s, r]),
    timeouts: FAST,
  });
  ls.markUnlocked();
  assert.strictEqual(ls.isUnlocked(), true);

  const ok = await ls.lock('idle');
  assert.strictEqual(ok, true);
  assert.strictEqual(ls.isUnlocked(), false);
  assert.ok(rec.js && rec.js.includes('zkResetKeys'), 'the renderer purge resets the UI key');
  assert.ok(rec.js.includes('vaultPassword'), 'the renderer purge clears the remembered passphrase');
  assert.strictEqual(rec.daemonLocked, true, 'the daemon is told to drop its sync key');
  // Order: unlocked -> locking -> locked (never "safe" mid-purge).
  assert.deepStrictEqual(changes.map((c) => c[0]), ['unlocked', 'locking', 'locked']);
  assert.deepStrictEqual(changes[changes.length - 1], ['locked', 'idle'], 'indicators flip to locked last');
});

test('lock() with no live window and no daemon still confirms locked, and is idempotent (tray case)', async () => {
  const changes = [];
  const ls = new LockState({ getWindow: () => null, getDaemon: () => null, onChange: (s, r) => changes.push([s, r]), timeouts: FAST });
  assert.strictEqual(await ls.lock('sleep'), true);
  assert.strictEqual(ls.isUnlocked(), false);
  assert.deepStrictEqual(changes[changes.length - 1], ['locked', 'sleep']);
  assert.strictEqual(await ls.lock('os-lock'), true); // locking an already-locked state is safe
  assert.strictEqual(ls.isUnlocked(), false);
});

test('a destroyed window is treated as already hard-purged and does not throw', async () => {
  const ls = new LockState({
    getWindow: () => ({ isDestroyed: () => true, webContents: { executeJavaScript: () => { throw new Error('should not run'); } } }),
    getDaemon: () => null,
    onChange: () => {},
    timeouts: FAST,
  });
  assert.strictEqual(await ls.lock('idle'), true);
  assert.strictEqual(ls.isUnlocked(), false);
});

test('FAIL-CLOSED: an unacked daemon purge never reports "locked"', async () => {
  const rec = {};
  const changes = [];
  const ls = new LockState({
    getWindow: () => okWin(rec),
    getDaemon: () => ({ zkLock: () => Promise.resolve(false) }), // never acks
    onChange: (s) => changes.push(s),
    timeouts: FAST,
  });
  const ok = await ls.lock('idle');
  assert.strictEqual(ok, false, 'lock() reports failure when a purge cannot be confirmed');
  assert.strictEqual(ls.isUnlocked(), false, 'the unlocked gate still closed');
  assert.ok(!changes.includes('locked'), '"locked/safe" is never reported while a key might live');
  assert.strictEqual(changes[changes.length - 1], 'lock-error', 'fail-closed error state is surfaced');
});

test('FAIL-CLOSED escalation: a renderer purge that rejects escalates P1 -> P2 (destroy)', async () => {
  const rec = {};
  const ls = new LockState({
    getWindow: () => ({
      isDestroyed: () => false,
      destroy: () => { rec.destroyed = true; },
      webContents: { executeJavaScript: () => Promise.reject(new Error('purge blew up')) },
    }),
    getDaemon: () => okDaemon(rec),
    onChange: () => {},
    timeouts: FAST,
  });
  const ok = await ls.lock('idle');
  assert.strictEqual(rec.destroyed, true, 'the renderer is destroyed when P1 cannot be confirmed');
  assert.strictEqual(ok, true, 'a destroyed renderer is a confirmed hard purge');
});

test('FAIL-CLOSED escalation: a renderer purge that TIMES OUT escalates P1 -> P2 (destroy)', async () => {
  const rec = {};
  const ls = new LockState({
    getWindow: () => ({
      isDestroyed: () => false,
      destroy: () => { rec.destroyed = true; },
      webContents: { executeJavaScript: () => new Promise(() => { /* never resolves */ }) },
    }),
    getDaemon: () => okDaemon(rec),
    onChange: () => {},
    timeouts: { rendererTimeoutMs: 20, daemonTimeoutMs: 30, daemonAttempts: 2 },
  });
  const ok = await ls.lock('idle');
  assert.strictEqual(rec.destroyed, true, 'a hung renderer purge is bounded and escalated to destroy');
  assert.strictEqual(ok, true);
});

test('the account-session lifecycle is separate — lock only affects the ZK unlocked state', async () => {
  const ls = new LockState({ getWindow: () => null, getDaemon: () => null, timeouts: FAST });
  ls.markUnlocked();
  await ls.lock('idle');
  assert.deepStrictEqual(ls.snapshot(), { unlocked: false, reason: 'idle' });
  // There is no API on this SoT that clears the account token — the two lifecycles are separate by
  // construction, so an idle/OS lock can never become an account sign-out.
});

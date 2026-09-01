'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { AutoLock, UNATTENDED } = require('../src/main/auto-lock');

function fakePower() {
  return {
    idle: 0,
    _h: {},
    on(ev, cb) { (this._h[ev] = this._h[ev] || []).push(cb); },
    emit(ev) { (this._h[ev] || []).forEach((f) => f()); },
    getSystemIdleTime() { return this.idle; },
  };
}
function fakeLock() {
  return {
    unlocked: true,
    reasons: [],
    isUnlocked() { return this.unlocked; },
    lock(r) { this.reasons.push(r); this.unlocked = false; return Promise.resolve(true); },
  };
}
function fakeWin() {
  return { destroyed: false, isDestroyed() { return this.destroyed; }, destroy() { this.destroyed = true; } };
}

// Injected timers: capture the poll callback and the escalation callback so tests drive them by hand.
function harness(extra = {}) {
  const captured = { poll: null, esc: null };
  const deps = {
    powerMonitor: extra.power || fakePower(),
    lockState: extra.lock || fakeLock(),
    getWindow: extra.getWindow || (() => null),
    idleThresholdMs: 1000,
    timers: { idlePollMs: 10, escalateAfterMs: 100 },
    setIntervalFn: (fn) => { captured.poll = fn; return { id: 'poll' }; },
    clearIntervalFn: () => {},
    setTimeoutFn: (fn) => { captured.esc = fn; return { id: 'esc' }; },
    clearTimeoutFn: () => { captured.esc = null; },
    ...extra.overrides,
  };
  const al = new AutoLock(deps);
  return { al, captured, power: deps.powerMonitor, lock: deps.lockState };
}

test('idle poll locks once OS input-idle crosses the threshold, and latches (no re-fire while idle)', () => {
  const { al, captured, power, lock } = harness();
  al.start();
  power.idle = 0; captured.poll();
  assert.deepStrictEqual(lock.reasons, [], 'not idle enough -> no lock');
  power.idle = 2; captured.poll();
  assert.deepStrictEqual(lock.reasons, ['idle'], 'idle past threshold -> a single idle lock');
  captured.poll();
  assert.deepStrictEqual(lock.reasons, ['idle'], 'still idle -> latched, not re-fired');
});

test('the idle timer is visibility-independent: it reads OS idle time, not window state', () => {
  // No window is provided at all; the idle lock must still fire from the OS input-idle signal.
  const { al, captured, power, lock } = harness({ getWindow: () => null });
  al.start();
  power.idle = 5; captured.poll();
  assert.deepStrictEqual(lock.reasons, ['idle']);
});

test('idle re-arms after OS input resumes and the app is unlocked again', () => {
  const { al, captured, power, lock } = harness();
  al.start();
  power.idle = 2; captured.poll();
  assert.deepStrictEqual(lock.reasons, ['idle']);
  power.emit('resume'); power.idle = 0; captured.poll(); // input came back
  lock.unlocked = true; // the unlock flow re-armed the key (a later phase)
  power.idle = 2; captured.poll();
  assert.deepStrictEqual(lock.reasons, ['idle', 'idle'], 'a fresh idle stretch locks again');
});

test('system suspend and screen-lock drop the key immediately', () => {
  const { al, power, lock } = harness();
  al.start();
  power.emit('suspend');
  power.emit('lock-screen');
  assert.deepStrictEqual(lock.reasons, ['sleep', 'os-lock']);
});

test('an unattended lock escalates: a still-locked live window is destroyed after the bounded interval', () => {
  const win = fakeWin();
  const { al, captured, power, lock } = harness({ getWindow: () => win });
  al.start();
  power.emit('suspend');          // unattended -> arms escalation
  assert.ok(captured.esc, 'the escalation timer is armed for an unattended lock');
  lock.unlocked = false;          // still locked when the interval expires
  captured.esc();                 // fire the escalation
  assert.strictEqual(win.destroyed, true, 'the lingering renderer is hard-purged');
});

test('escalation is cancelled by return: an unlocked-again window is left alone', () => {
  const win = fakeWin();
  const { al, captured, power, lock } = harness({ getWindow: () => win });
  al.start();
  power.emit('lock-screen');      // unattended -> arms escalation
  lock.unlocked = true;           // the user came back and unlocked before it expired
  captured.esc();
  assert.strictEqual(win.destroyed, false, 'an actively-used window is not destroyed');
});

test('idle locks also arm the unattended escalation', () => {
  const win = fakeWin();
  const { al, captured, power } = harness({ getWindow: () => win });
  al.start();
  power.idle = 2; captured.poll();
  assert.ok(captured.esc, 'an idle lock arms the escalation too');
});

test('an unavailable OS idle clock surfaces a one-time degraded posture (not silent)', () => {
  const codes = [];
  const power = fakePower();
  power.getSystemIdleTime = () => { throw new Error('no idle clock on this desktop'); };
  const al = new AutoLock({
    powerMonitor: power,
    lockState: fakeLock(),
    onDegraded: (c) => codes.push(c),
    idleThresholdMs: 1000,
    timers: { idlePollMs: 10, escalateAfterMs: 100 },
    setIntervalFn: () => ({ id: 'poll' }),
    clearIntervalFn: () => {},
    setTimeoutFn: () => ({ id: 'esc' }),
    clearTimeoutFn: () => {},
  });
  al.start();
  assert.deepStrictEqual(codes, ['idle-clock-unavailable'], 'the degraded posture is reported once at start');
  // The OS suspend/screen-lock triggers still work even with no idle clock.
  power.emit('suspend');
  assert.deepStrictEqual(al.lockState.reasons, ['sleep']);
});

test('only unattended reasons escalate (a present-user manual lock never destroys the window)', () => {
  // Guard the policy directly: manual is not in the unattended set that arms escalation.
  assert.ok(UNATTENDED.has('idle') && UNATTENDED.has('sleep') && UNATTENDED.has('os-lock'));
  assert.ok(!UNATTENDED.has('manual'), 'a present user manual lock stays soft');
});

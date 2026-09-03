'use strict';

/*
 * Automatic lock triggers (main process). The lock STATE and the atomic key purge live in
 * lock-state.js; this module decides only WHEN to lock and drives the unattended-window escalation.
 * It holds no key material.
 *
 * Triggers:
 *  - Idle: a visibility-INDEPENDENT timer. It samples the OS input-idle time (via powerMonitor), NOT
 *    window focus or visibility, so a hidden, minimised, or tray-only window still locks. After the
 *    deployment's idle policy (minutes) with no OS input, the zero-knowledge key is dropped.
 *  - OS signals: system suspend and screen-lock drop the key immediately — the user has stepped away.
 *
 * Unattended-window escalation (required): a soft in-place purge leaves the reused UI process alive,
 * so an UNATTENDED lock (idle / suspend / screen-lock — never a present user's manual lock) arms a
 * short bounded timer; if the window is still live and still locked when it expires, the renderer is
 * destroyed (a hard purge), closing the walked-away-window-left-open gap. A present user's manual lock
 * stays soft: they are there, at the lock screen.
 *
 * The idle timer only fires while the app is actually unlocked (a zero-knowledge key is present). Until
 * the unlock flow exists (a later phase), nothing marks the app unlocked, so these triggers are wired
 * and exercised but drop nothing yet; the unlock flow makes them live without any change here.
 */

const DEFAULTS = {
  idlePollMs: 30000,            // how often the OS input-idle time is sampled
  idleThresholdMs: 15 * 60000,  // idle-lock policy (minutes) used when the deployment sets none
  escalateAfterMs: 2 * 60000,   // an unattended, still-locked live window is destroyed after this
};
const UNATTENDED = new Set(['idle', 'sleep', 'os-lock']);

class AutoLock {
  /**
   * @param {object} deps
   * @param {object} deps.powerMonitor   Electron powerMonitor (getSystemIdleTime + on)
   * @param {object} deps.lockState      the LockState source of truth (lock(), isUnlocked())
   * @param {() => (Electron.BrowserWindow|null)} [deps.getWindow]  the live UI window, or null
   * @param {number} [deps.idleThresholdMs]  idle-lock policy in ms (deployment override; default 15 min)
   * @param {object} [deps.timers]  { idlePollMs, escalateAfterMs } overrides (tests)
   * @param {Function} [deps.setIntervalFn] [deps.clearIntervalFn] [deps.setTimeoutFn] [deps.clearTimeoutFn]
   *        injectable timers (tests)
   */
  constructor(deps) {
    this.power = deps.powerMonitor;
    this.lockState = deps.lockState;
    this.getWindow = deps.getWindow || (() => null);
    this.onDegraded = deps.onDegraded || (() => {}); // surfaced once if the OS idle clock is unavailable
    this._degraded = new Set();
    const t = deps.timers || {};
    this.idlePollMs = t.idlePollMs || DEFAULTS.idlePollMs;
    this.idleThresholdMs = deps.idleThresholdMs || DEFAULTS.idleThresholdMs;
    this.escalateAfterMs = t.escalateAfterMs || DEFAULTS.escalateAfterMs;
    this._setInterval = deps.setIntervalFn || setInterval;
    this._clearInterval = deps.clearIntervalFn || clearInterval;
    this._setTimeout = deps.setTimeoutFn || setTimeout;
    this._clearTimeout = deps.clearTimeoutFn || clearTimeout;
    this._pollTimer = null;
    this._escalateTimer = null;
    this._started = false;
    this._idleLatched = false; // set once idle fires; cleared when OS input resumes (no re-fire spam)
  }

  start() {
    if (this._started) return this;
    this._started = true;
    if (this.power && typeof this.power.on === 'function') {
      // The user has stepped away — drop the key immediately, then arm the unattended escalation.
      this.power.on('suspend', () => this._trigger('sleep'));
      this.power.on('lock-screen', () => this._trigger('os-lock'));
      // OS input resumed — allow the idle timer to arm again, and auto-resume account-tier sync if it was paused by
      // an OS/idle lock (never a manual "Lock now", which waits for the explicit Resume item).
      this.power.on('resume', () => { this._idleLatched = false; this._maybeAutoResume(); });
      this.power.on('unlock-screen', () => { this._idleLatched = false; this._maybeAutoResume(); });
    }
    // The idle poll is installed only if the OS input-idle clock is actually usable. If it is not, the
    // degraded posture is surfaced once (not silent): the OS suspend/screen-lock triggers and the reused
    // UI's own in-window idle-lock still stand, but the shell's hidden-window backstop is unavailable.
    if (this.power && typeof this.power.getSystemIdleTime === 'function' && this._idleClockUsable()) {
      this._pollTimer = this._setInterval(() => this._pollIdle(), this.idlePollMs);
      if (this._pollTimer && this._pollTimer.unref) this._pollTimer.unref();
    } else {
      this._reportDegraded('idle-clock-unavailable');
    }
    return this;
  }

  _idleClockUsable() {
    try { return typeof this.power.getSystemIdleTime() === 'number'; } catch { return false; }
  }

  _reportDegraded(code) {
    if (this._degraded.has(code)) return;
    this._degraded.add(code);
    try { this.onDegraded(code); } catch { /* reporter must never break the trigger */ }
  }

  _pollIdle() {
    let idleSec = 0;
    try { idleSec = this.power.getSystemIdleTime(); } catch { this._reportDegraded('idle-clock-unavailable'); return; }
    if (idleSec * 1000 >= this.idleThresholdMs) {
      // Fire the idle lock when EITHER tier is active: the ZK key present, OR the account tier usable. A Standard-only
      // user has no ZK key (isUnlocked() is always false), so without the account-tier condition the idle lock would
      // never fire for them and account sync + its credential would live on unattended. lock() is safe with no ZK key
      // (the purge no-ops) and still pauses dispatch + drops the account credential via onChange('locked').
      if (!this._idleLatched && (this.lockState.isUnlocked() || this.lockState.isAccountUsable())) this._trigger('idle');
      this._idleLatched = true; // don't re-fire until OS input resumes
    } else {
      this._idleLatched = false;
      this._maybeAutoResume(); // input resumed below the idle threshold -> reverse an idle lock for the account tier
    }
  }

  // Reverse edge for the account tier: re-enable Standard-vault sync once the user returns (input resumed / screen
  // unlocked / system resumed), but ONLY for the auto (UNATTENDED) reasons — a manual "Lock now" is a deliberate pause
  // and waits for the explicit "Resume sync" item, never auto-resumed here. Idempotent: acts only while sync is paused.
  _maybeAutoResume() {
    try {
      if (this.lockState.isAccountUsable()) return;                  // already active — nothing to resume
      if (!UNATTENDED.has(this.lockState.snapshot().reason)) return; // a manual lock waits for the Resume item
      this.lockState.resumeAccount();
    } catch { /* the SoT surfaces its own errors; never break the poll */ }
  }

  _trigger(reason) {
    // Fire the atomic purge; the SoT owns confirmation and fail-closed. Escalate only when unattended.
    void Promise.resolve(this.lockState.lock(reason)).catch(() => { /* SoT surfaces lock-error */ });
    if (UNATTENDED.has(reason)) this._armEscalation();
  }

  _armEscalation() {
    if (this._escalateTimer) return; // one pending escalation is enough
    this._escalateTimer = this._setTimeout(() => {
      this._escalateTimer = null;
      if (this.lockState.isUnlocked() || this.lockState.isAccountUsable()) return; // came back (ZK unlock OR account resume) -> leave the window
      const win = this.getWindow();
      if (win && !win.isDestroyed() && typeof win.destroy === 'function') {
        try { win.destroy(); } catch { /* already gone */ }
      }
    }, this.escalateAfterMs);
    if (this._escalateTimer && this._escalateTimer.unref) this._escalateTimer.unref();
  }

  /** Cancel a pending unattended escalation — called by the unlock flow (a later phase) on unlock. */
  cancelEscalation() {
    if (this._escalateTimer) { this._clearTimeout(this._escalateTimer); this._escalateTimer = null; }
  }

  stop() {
    if (this._pollTimer) this._clearInterval(this._pollTimer);
    if (this._escalateTimer) this._clearTimeout(this._escalateTimer);
    this._pollTimer = null;
    this._escalateTimer = null;
    this._started = false;
  }
}

module.exports = { AutoLock, DEFAULTS: { ...DEFAULTS }, UNATTENDED };

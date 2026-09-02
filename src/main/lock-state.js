'use strict';

/*
 * The single source of truth for lock state, owned by the main process.
 *
 * The window and the daemon OBSERVE this; they never hold divergent unlocked state. Two INDEPENDENT
 * lifecycles that must never be conflated:
 *   - "signed in" (the account session): persists until sign-out; a lock never re-prompts for sign-in.
 *     But it does NOT mean sync runs while locked: Standard-vault sync DISPATCH pauses on any lock (no new
 *     run starts), and the account-tier SFTP credential is dropped as hygiene on the lock and re-minted
 *     from the still-live session on unlock.
 *   - "unlocked" (the zero-knowledge key is present): memory-only; on a lock event it is dropped
 *     atomically across BOTH the renderer's UI key AND the daemon's sync key.
 *
 * This module holds only the STATE and drives the purge; it never holds zero-knowledge key material
 * (that lives in the renderer's reused UI and, later, in the daemon). The database key is separate
 * (account-tier, held by the daemon for the whole run) and is deliberately NOT part of this purge.
 *
 * Atomicity contract (the state + indicator flip to "locked/safe" ONLY after every purge is
 * confirmed; fail-closed otherwise):
 *   1. The in-memory `unlocked` gate closes IMMEDIATELY when lock() begins — no crypto op may use a
 *      ZK key once a lock is under way. The user-facing indicator goes to a transitional "locking"
 *      (never "safe" while a key might still live).
 *   2. Renderer purge (P1/P2 hybrid): the reused UI's own zkResetKeys() + clearing the remembered
 *      passphrase runs and is AWAITED with a bounded timeout. Awaiting confirms the purge JS RAN
 *      (references nulled) — it does NOT prove the WebCrypto CryptoKey bytes are gone, which cannot
 *      be observed or forced while the renderer lives. So a confirmed P1 = refs released, not bytes
 *      zeroized. If P1 cannot be confirmed (throws/times out), FAIL-CLOSED by ESCALATING to P2:
 *      destroy the renderer, so the key dies with the process (the real hard guarantee). The tray
 *      case already destroyed the window (P2 by construction).
 *   3. Daemon purge: a request->ack over the private channel, AWAITED with a bounded timeout. Today
 *      the daemon has no ZK key, so the hook acks immediately; when the sync engine gives it a key
 *      (a later phase), the true zeroize (Node Buffer .fill(0)) happens BEFORE the ack. The renderer
 *      (release-only) vs daemon (byte-zeroize) asymmetry is inherent: WebCrypto keys vs raw bytes.
 *   4. Only once BOTH sides are confirmed does the state flip to "locked" and the indicator to
 *      "safe". If either cannot be confirmed, the state stays fail-closed ("lock-error"): the error
 *      is surfaced and "safe" is never reported while a key might live.
 */

// Run in the page's own world: the reused UI exposes zkResetKeys() and a `state` holding the vault
// passphrase. Reset the key material and clear the remembered passphrase; tolerate their absence.
const RENDERER_PURGE_JS =
  'try{if(typeof zkResetKeys==="function")zkResetKeys();}catch(e){}' +
  'try{if(typeof state!=="undefined"){state.vaultPassword=null;state.vaultPasswordTimestamp=null;}}catch(e){}' +
  'true;';

const DEFAULTS = { rendererTimeoutMs: 2000, daemonTimeoutMs: 2000, daemonAttempts: 3 };

class LockState {
  /**
   * @param {object} deps
   * @param {() => (Electron.BrowserWindow|null)} deps.getWindow   the live UI window, or null
   * @param {() => (object|null)} deps.getDaemon                   the daemon manager (with zkLock()), or null
   * @param {(state: 'unlocked'|'locking'|'locked'|'lock-error', reason?: string) => void} [deps.onChange]
   *        indicator/observer hook — the ONLY place a user-facing "state" is reported
   * @param {object} [deps.timeouts]  override the bounded purge timeouts (tests)
   */
  constructor(deps) {
    this.getWindow = deps.getWindow;
    this.getDaemon = deps.getDaemon;
    this.onChange = deps.onChange || (() => {});
    const t = deps.timeouts || {};
    this.rendererTimeoutMs = t.rendererTimeoutMs || DEFAULTS.rendererTimeoutMs;
    this.daemonTimeoutMs = t.daemonTimeoutMs || DEFAULTS.daemonTimeoutMs;
    this.daemonAttempts = t.daemonAttempts || DEFAULTS.daemonAttempts;
    this.unlocked = false;      // no ZK key until an unlock flow (a later phase) provides one
    this.lastReason = null;
    this.locking = false;       // a lock() transaction is in flight
  }

  isUnlocked() { return this.unlocked; }

  /** Called by the unlock flow (a later phase) once a ZK key is present. */
  markUnlocked() { this.unlocked = true; this.lastReason = null; this.onChange('unlocked'); }

  /**
   * Atomic dual-key purge. Async: closes the unlocked gate immediately, then confirms the renderer
   * purge (P1, escalating to P2/destroy if it cannot be confirmed) AND the daemon ack before reporting
   * "locked". The account session and the database key are untouched. Idempotent; safe to call with no
   * live window and no daemon.
   * @param {string} reason  e.g. 'idle' | 'sleep' | 'os-lock' | 'manual' | 'sign-out'
   * @returns {Promise<boolean>} true once both purges are confirmed; false if it fell to fail-closed
   */
  async lock(reason) {
    this.lastReason = reason || 'manual';
    this.unlocked = false;          // gate closes now: no crypto op may use the ZK key once lock begins
    this.locking = true;
    this.onChange('locking', this.lastReason); // honest transitional state; never "safe" mid-purge

    const rendererOk = await this._purgeRenderer();
    const daemonOk = await this._purgeDaemon();

    this.locking = false;
    if (rendererOk && daemonOk) {
      this.onChange('locked', this.lastReason);   // "safe" ONLY after BOTH purges confirmed
      return true;
    }
    // Fail-closed: at least one purge could not be confirmed — surface the error, never report "safe".
    this.onChange('lock-error', this.lastReason);
    return false;
  }

  // Renderer UI key. Confirm the in-place purge (P1); on any failure to confirm, escalate to P2 by
  // destroying the renderer so the key dies with the process. Returns true when the renderer side is
  // confirmed clean (P1 ran, or P2 destroyed, or no window), false only if it could neither confirm
  // P1 nor destroy the window.
  async _purgeRenderer() {
    const win = this.getWindow && this.getWindow();
    if (!win || win.isDestroyed()) return true;   // tray case: already destroyed = hard-purged (P2)
    try {
      await this._withTimeout(win.webContents.executeJavaScript(RENDERER_PURGE_JS, true), this.rendererTimeoutMs);
      return true;                                 // P1 confirmed: the purge JS ran (references nulled)
    } catch {
      // Cannot confirm P1 -> fail-closed escalation to P2: destroy the renderer (hard purge).
      try {
        if (!win.isDestroyed() && typeof win.destroy === 'function') win.destroy();
        return true;
      } catch {
        return false;                              // neither confirmed nor destroyed -> not clean
      }
    }
  }

  // Daemon sync key. Await the request->ack (a no-op that acks immediately until the sync engine gives
  // the daemon a key). Bounded retries; returns false if no ack after the last attempt (fail-closed).
  async _purgeDaemon() {
    const daemon = this.getDaemon && this.getDaemon();
    if (!daemon || typeof daemon.zkLock !== 'function') return true; // no daemon wired -> nothing to purge
    for (let attempt = 0; attempt < this.daemonAttempts; attempt += 1) {
      let ok = false;
      try { ok = await daemon.zkLock(this.daemonTimeoutMs); } catch { ok = false; }
      if (ok) return true;
    }
    return false;
  }

  // Bounded wait on a foreground purge. The timer stays ref'd for its short window (we are actively
  // waiting on a security operation) and is cleared the moment the wrapped purge settles.
  _withTimeout(promise, ms) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error('purge-timeout')), ms);
      Promise.resolve(promise).then(
        (v) => { clearTimeout(timer); resolve(v); },
        (e) => { clearTimeout(timer); reject(e); },
      );
    });
  }

  snapshot() { return { unlocked: this.unlocked, reason: this.lastReason }; }
}

module.exports = { LockState, RENDERER_PURGE_JS };

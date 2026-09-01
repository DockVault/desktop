'use strict';

/*
 * The main-process owner of the live sync status. It gathers the raw signals as they change — the
 * supervised helper's lifecycle and crash-loop state, whether the app is locked, network
 * reachability, and each configured vault's last outcome and in-flight flag — folds them through the
 * one status model, and, only when the picture actually changes, hands out the computed result:
 *   - onStatus(model): the tray glance and the read-only status channel both render this. The model
 *     is cred-free by construction — it carries states, labels, and symbolic reasons, never a
 *     credential, host key, token, or any raw helper output.
 *   - onNotify(item): a single must-act notification when an unresolved item first appears (a
 *     conflict to review, a repair or sign-in that is owed, a stuck helper). De-duplicated so the
 *     same unresolved item is announced once, not on every recompute, and re-announced only if it
 *     clears and then recurs.
 *
 * The hub holds no key material and performs no IO; the scheduler feeds it outcomes and the app
 * feeds it lock/posture, keeping one source of truth that the tray, notifications, and channel share.
 */

const model = require('./sync-status-model');

// The states that require a deliberate person to act — the ones that earn a must-act notification.
const MUST_ACT = new Set([model.STATE.NEEDS_DECISION, model.STATE.SYNC_PROBLEM]);

class SyncStatusHub {
  constructor(deps = {}) {
    this._daemon = deps.daemon || null;
    this._onStatus = typeof deps.onStatus === 'function' ? deps.onStatus : () => {};
    this._onNotify = typeof deps.onNotify === 'function' ? deps.onNotify : () => {};
    this._sig = {
      hasSecureStore: deps.hasSecureStore !== false,
      locked: !!deps.locked,
      online: deps.online !== false,
      daemon: 'starting',
      crashLoopLatched: false,
    };
    this._vaults = new Map(); // vault -> { running, lastResult, resyncRequired }
    this._lastSnapshot = null; // serialized last-emitted model, to suppress no-op emits
    this._activeMustAct = new Set(); // must-act keys currently outstanding, for notify de-dup
    if (this._daemon && typeof this._daemon.on === 'function') this._wireDaemon();
  }

  _wireDaemon() {
    this._daemon.on('ready', (m) => {
      const noStore = !!(m && m.encrypted === false);
      this._sig.daemon = noStore ? 'ready-no-store' : 'ready';
      if (noStore) this._sig.hasSecureStore = false;
      this._sig.crashLoopLatched = false;
      this._recompute();
    });
    this._daemon.on('exit', () => { this._sig.daemon = 'crashed'; this._recompute(); });
    this._daemon.on('crash-loop', () => { this._sig.daemon = 'crash-looped'; this._sig.crashLoopLatched = true; this._recompute(); });
    this._daemon.on('resume', () => { this._sig.daemon = 'starting'; this._sig.crashLoopLatched = false; this._recompute(); });
    this._daemon.on('error', () => { this._recompute(); });
  }

  // ---- signal setters (the app + the scheduler drive these) ----
  setLocked(locked) { this._sig.locked = !!locked; this._recompute(); }
  setOnline(online) { this._sig.online = online !== false; this._recompute(); }
  setSecureStore(has) { this._sig.hasSecureStore = has !== false; this._recompute(); }

  /** Declare which vaults are configured for sync (drops any no longer configured). */
  setVaults(list) {
    const next = new Map();
    for (const v of Array.isArray(list) ? list : []) {
      const prev = this._vaults.get(v) || { running: false, lastResult: null, resyncRequired: false };
      next.set(v, prev);
    }
    this._vaults = next;
    this._recompute();
  }

  setRunning(vault, running) {
    const e = this._vaults.get(vault); if (!e) return;
    e.running = !!running; this._recompute();
  }

  /** Record a completed run's typed outcome for a vault (from the scheduler). */
  recordOutcome(vault, { result, resyncRequired } = {}) {
    const e = this._vaults.get(vault); if (!e) return;
    e.lastResult = result != null ? result : e.lastResult;
    if (typeof resyncRequired === 'boolean') e.resyncRequired = resyncRequired;
    e.running = false;
    this._recompute();
  }

  /** The current computed model (also what the read-only channel returns on demand). */
  current() {
    return model.computeStatus({
      hasSecureStore: this._sig.hasSecureStore,
      locked: this._sig.locked,
      online: this._sig.online,
      daemon: this._sig.daemon,
      crashLoopLatched: this._sig.crashLoopLatched,
      vaults: [...this._vaults.entries()].map(([vault, e]) => ({ vault, ...e })),
    });
  }

  _recompute() {
    const m = this.current();
    const snap = JSON.stringify(m);
    if (snap !== this._lastSnapshot) {
      this._lastSnapshot = snap;
      try { this._onStatus(m); } catch { /* a consumer error is not ours */ }
    }
    this._diffNotifications(m);
  }

  // Fire a must-act notification the first time each unresolved item appears; forget it once cleared.
  _diffNotifications(m) {
    const nowActive = new Map(); // key -> notification payload
    if (m.condition == null) {
      for (const v of m.vaults) {
        if (MUST_ACT.has(v.state)) nowActive.set(`${v.vault}:${v.state}:${v.reason || ''}`, { scope: 'vault', vault: v.vault, state: v.state, reason: v.reason || null });
      }
      // A stuck helper is one global must-act item.
      if (m.state === model.STATE.SYNC_PROBLEM && m.reason === 'sync-stopped') {
        nowActive.set('daemon:sync-stopped', { scope: 'daemon', state: m.state, reason: 'sync-stopped' });
      }
    }
    for (const [key, payload] of nowActive) {
      if (!this._activeMustAct.has(key)) { try { this._onNotify(payload); } catch { /* consumer error */ } }
    }
    this._activeMustAct = new Set(nowActive.keys());
  }
}

module.exports = { SyncStatusHub, MUST_ACT };

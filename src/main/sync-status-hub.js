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
    // A single positive notification the FIRST time each vault syncs successfully this session. Distinct
    // from onNotify (which is for must-act items) — it is the only "good news" toast, and it is fired at
    // most once per vault, never on later successes.
    this._onToast = typeof deps.onToast === 'function' ? deps.onToast : () => {};
    this._now = typeof deps.now === 'function' ? deps.now : () => Date.now();
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
      const reason = m && m.reason;
      if (reason === 'db-key-unreadable' || reason === 'db-unreadable') {
        // The saved sync state EXISTS on this machine but cannot be unlocked/opened (the wrapped key won't
        // unwrap, or the database itself won't open). This is NOT a benign no-store — it is a real problem
        // the person must resolve, and it must never present as a calm 'starting' that retries every tick.
        // The store is present (it just can't be opened), so this is a sync PROBLEM, not an "unavailable"
        // (no-keychain) — force hasSecureStore true so the problem surfaces instead of reading unavailable.
        this._sig.daemon = 'init-failed';
        this._sig.hasSecureStore = true;
      } else if (m && m.encrypted === false) {
        // A benign no-store: no secure keychain backend. Nothing durable to sync => unavailable.
        this._sig.daemon = 'ready-no-store';
        this._sig.hasSecureStore = false;
      } else {
        this._sig.daemon = 'ready';
      }
      this._sig.crashLoopLatched = false;
      this._recompute();
    });
    this._daemon.on('exit', () => { this._sig.daemon = 'crashed'; this._recompute(); });
    this._daemon.on('crash-loop', () => { this._sig.daemon = 'crash-looped'; this._sig.crashLoopLatched = true; this._recompute(); });
    this._daemon.on('resume', () => { this._sig.daemon = 'starting'; this._sig.crashLoopLatched = false; this._recompute(); });
    this._daemon.on('error', () => { this._recompute(); });
    // In-flight transfer progress from the helper: the two aggregate integers only (files, bytes) for a
    // vault, never a path. Drives the "syncing" glance so it shows only while bytes actually move.
    this._daemon.on('sync-progress', (p) => { if (p && p.vault) this.recordProgress(p.vault, { files: p.files, bytes: p.bytes }); });
  }

  // ---- signal setters (the app + the scheduler drive these) ----
  setLocked(locked) { this._sig.locked = !!locked; this._recompute(); }
  setOnline(online) { this._sig.online = online !== false; this._recompute(); }
  setSecureStore(has) { this._sig.hasSecureStore = has !== false; this._recompute(); }

  /** Declare which vaults are configured for sync (drops any no longer configured). */
  setVaults(list) {
    const next = new Map();
    for (const v of Array.isArray(list) ? list : []) {
      const prev = this._vaults.get(v) || { running: false, transferring: false, progress: null, lastResult: null, resyncRequired: false, condition: null, lastSyncedAt: null, everSucceeded: false };
      next.set(v, prev);
    }
    this._vaults = next;
    this._recompute();
  }

  setRunning(vault, running) {
    const e = this._vaults.get(vault); if (!e) return;
    e.running = !!running;
    // Transfer motion is per-run: starting or ending a run clears any prior counts, so a fresh run begins
    // with no "syncing" motion (it surfaces only once bytes move) and a finished one trails none.
    e.transferring = false;
    e.progress = null;
    if (e.running) e.condition = null; // a run actually starting clears any prior can't-run reason
    this._recompute();
  }

  /**
   * Record in-flight transfer progress for a vault: the two aggregate integers the daemon extracted from
   * rclone's stats (files + bytes transferred — never a path). Motion, and so the "syncing" glance, is
   * shown ONLY when real bytes are moving (a positive count); a run that is merely scanning reports nothing
   * and keeps the vault quiet at its last real state.
   */
  recordProgress(vault, { files, bytes } = {}) {
    const e = this._vaults.get(vault); if (!e || !e.running) return; // only the run in flight has progress
    const f = typeof files === 'number' ? files : null;
    const b = typeof bytes === 'number' ? bytes : null;
    if (!((f != null && f > 0) || (b != null && b > 0))) return; // a zero/empty report is not motion — stay quiet
    e.transferring = true;
    e.progress = { files: f, bytes: b };
    this._recompute();
  }

  /** Record a completed run's typed outcome for a vault (from the scheduler). */
  recordOutcome(vault, { result, resyncRequired } = {}) {
    const e = this._vaults.get(vault); if (!e) return;
    e.lastResult = result != null ? result : e.lastResult;
    if (typeof resyncRequired === 'boolean') e.resyncRequired = resyncRequired;
    e.running = false;
    e.transferring = false; // the run is over — no motion trails it
    e.progress = null;
    e.condition = null; // a completed run supersedes any prior can't-run reason
    // Success-ONLY bookkeeping: a run counts as a success exactly when it lands the vault at "up to date"
    // (an 'ok'/'resync-ok' outcome with nothing unresolved outranking it). Reuse the one status model so
    // there is no second, drifting notion of success. A failed, blocked, or conflicted outcome stamps
    // nothing and never toasts.
    const landed = model.vaultState({ vault, running: false, lastResult: e.lastResult, resyncRequired: e.resyncRequired, condition: null });
    let firstSuccess = false;
    if (landed.state === model.STATE.UP_TO_DATE) {
      e.lastSyncedAt = this._now();          // "Last synced" advances only on a real success
      if (!e.everSucceeded) { e.everSucceeded = true; firstSuccess = true; }
    }
    this._recompute();
    if (firstSuccess) { try { this._onToast({ scope: 'vault', vault, kind: 'first-success' }); } catch { /* a consumer error is not ours */ } }
  }

  /**
   * Record a live reason a vault could NOT run this dispatch (refused/paused/skipped for a persistent
   * cause), so it stops reading as its stale last state. Distinct from a completed outcome — it leaves
   * lastResult/resyncRequired untouched and is cleared once the vault actually runs or completes.
   */
  recordCondition(vault, { state, reason, sub, installed } = {}) {
    const e = this._vaults.get(vault); if (!e || !state) return;
    // `sub`/`installed` are the helper-not-ready DETAIL (a bounded enum + a non-secret version string) — carried
    // for the tray's per-sub message only; they never affect the state, which the reason alone decides.
    e.condition = { state, reason: reason || null, sub: sub || null, installed: installed || null };
    e.running = false;
    e.transferring = false; // a vault that cannot run is not transferring
    e.progress = null;
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

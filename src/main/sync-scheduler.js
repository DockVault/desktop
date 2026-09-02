'use strict';

/*
 * The background sync scheduler — the first caller of the proven-but-dormant sync engine. It decides
 * WHEN and WHETHER to dispatch a run for each configured Standard vault, and enforces the run-time
 * safety gate on EVERY dispatch, never trusting the enable-time config (which may predate these checks).
 *
 * Load-bearing invariants (all enforced here, unit-tested one by one):
 *   - GLOBAL mutex: mint/refresh-cred -> send -> run is ONE atomic critical section across ALL vaults,
 *     so exactly one credential is ever live in the helper at a time. Further requests QUEUE; a manual
 *     "Sync now" is ordered ahead of routine ticks; a request for a vault already queued or in flight is
 *     coalesced (a manual press joins the in-flight run rather than stacking a second).
 *   - Fail-closed eligibility: a run happens only when the app is UNLOCKED, the account session is live,
 *     and the network is reachable; if any of those is unknown, it does NOT dispatch (never sync blind).
 *     Lock keys off the ACCOUNT-session lifecycle here (Standard sync holds no zero-knowledge key) —
 *     coded explicitly Standard-only so a future zero-knowledge path can add its own key-state gate.
 *   - Run-time re-assertion before every write: the vault is re-confirmed Standard and its remote is
 *     re-derived from the CURRENT name (a renamed / re-tiered / removed vault fails closed); the folder
 *     is re-secured and re-classified.
 *   - Refresh-before-dispatch: the credential is refreshed-if-needed and re-sent before the run; a
 *     refresh failure fails closed (no run on a stale credential).
 *   - Two resync branches: a NEVER-RUN vault (no completed run yet, including an interrupted first sync)
 *     gets its consented INITIAL baseline resync; a vault BLOCKED after a completed run (a safety abort
 *     or an owed resync) is NEVER auto-resynced — it waits for a deliberate Repair. Both resync paths go
 *     through the zero-loss resync (keep-both), never a destructive bare resync.
 *
 * Pure orchestration over injected IO, so every invariant is unit-testable with no Electron or network.
 */

class SyncScheduler {
  /**
   * @param {object} io injected input/output surface (all side effects live in the caller)
   * @param {() => Array<{vaultId,vaultName,localFolder,remotePath,enabled}>} io.listConfigured
   * @param {(vaultId:string) => ({lastResult:(string|null),resyncRequired:boolean}|null)} io.runState  null => never-run
   * @param {() => ({locked:boolean,online:boolean,accountLive:boolean})} io.session
   * @param {(vaultId:string) => Promise<{ok:true,remotePath:string,vaultName?:string}|{ok:false,reason:string}>} io.verifyEligible
   * @param {(localFolder:string) => (({ok:boolean,reason?:string})|Promise<{ok:boolean,reason?:string}>)} io.secureFolder  may be async (applies + reads back a real ACL); it is awaited
   * @param {(localFolder:string) => ({ok:boolean,reason?:string})} io.classify
   * @param {(vaultId:string) => Promise<{ok:boolean,reason?:string}>} io.refreshCred
   * @param {(vaultId:string) => Promise<boolean>} [io.confirmFirstUpload]  gate the first upload of a not-yet-consented config
   * @param {(spec:{vaultId,local,remotePath}) => Promise<object>} io.runSync    normal bidirectional run
   * @param {(spec:{vaultId,local,remotePath}) => Promise<object>} io.runResync  zero-loss resync (initial baseline / Repair)
   * @param {(vaultId:string, ev:{phase:string,reason?:string,after?:string,outcome?:object}) => void} [io.onEvent]
   */
  constructor(io = {}) {
    this._io = io;
    this._busy = false;
    this._current = null;       // vaultId of the in-flight dispatch, or null
    this._queue = [];           // [{ vaultId, manual, repair }], at most one entry per vaultId
    this._authRetried = new Set(); // vaultIds that have already used their one auth-failed retry this episode
  }

  _emit(vaultId, ev) { try { if (this._io.onEvent) this._io.onEvent(vaultId, ev); } catch { /* consumer error is not ours */ } }

  // Enqueue a request, coalescing per vault. A request for the IN-FLIGHT vault is dropped (the running
  // dispatch already serves it). A manual request is ordered ahead of routine ticks and upgrades an
  // already-queued routine entry to manual.
  _enqueue(vaultId, { manual = false, repair = false } = {}) {
    // A request for the vault whose run is in flight folds into it — EXCEPT a deliberate Repair, which
    // must SURVIVE (its intent is to re-baseline AFTER the current run, not to join it).
    if (this._current === vaultId && !repair) return;
    const existing = this._queue.find((q) => q.vaultId === vaultId);
    if (existing) {
      if (repair) existing.repair = true;
      if (manual && !existing.manual) { existing.manual = true; this._toManualFifo(existing); } // keep manual FIFO
      return;
    }
    const item = { vaultId, manual: !!manual, repair: !!repair };
    if (manual) {
      // ahead of routine ticks, behind any earlier manual requests
      const lastManual = this._queue.reduce((i, q, idx) => (q.manual ? idx : i), -1);
      this._queue.splice(lastManual + 1, 0, item);
    } else {
      this._queue.push(item);
    }
    // If something is already running or ahead in the queue, this one is honestly "queued", not syncing.
    if (this._busy || this._queue[0] !== item) this._emit(vaultId, { phase: 'queued', after: this._current || undefined });
  }

  // Move an entry to just after the last EARLIER manual entry, so manual requests keep FIFO order
  // (an upgraded routine entry does not jump ahead of manual presses that were already waiting).
  _toManualFifo(entry) {
    const rest = this._queue.filter((q) => q !== entry);
    const lastManual = rest.reduce((i, q, idx) => (q.manual ? idx : i), -1);
    rest.splice(lastManual + 1, 0, entry);
    this._queue = rest;
  }

  /** Request a routine or manual sync for one vault. Returns nothing; progress arrives via onEvent. */
  requestSync(vaultId, { manual = false } = {}) { this._enqueue(vaultId, { manual }); this._pump(); }

  /** The deliberate Repair action (the only thing that clears a blocked-after-run latch). */
  requestRepair(vaultId) { this._enqueue(vaultId, { manual: true, repair: true }); this._pump(); }

  /**
   * The vaultId whose run is in flight right now, or null. It is the ONLY vault a per-step credential request
   * may be authorised for: the helper's requested vaultId is checked against this, never trusted as an input.
   */
  current() { return this._busy ? this._current : null; }

  /** A routine cadence tick: enqueue a run for every enabled configured vault (coalesced). */
  tickAll() {
    for (const c of this._io.listConfigured() || []) if (c && c.enabled) this._enqueue(c.vaultId, { manual: false });
    this._pump();
  }

  _pump() {
    if (this._busy || this._queue.length === 0) return;
    const item = this._queue.shift();
    this._busy = true;
    this._current = item.vaultId;
    Promise.resolve()
      .then(() => this._dispatch(item))
      .catch(() => { /* a dispatch never rejects into the pump; _dispatch handles its own errors */ })
      .finally(() => { this._busy = false; this._current = null; this._pump(); });
  }

  // The atomic critical section: one credential live, one run, at a time. Every gate below is
  // fail-closed — on any doubt it emits a non-running status and returns WITHOUT dispatching. The whole
  // body is wrapped: a dep that THROWS (a fetch that rejects, a dead helper channel) must surface as a
  // terminal 'error', never leave the vault stuck at 'running' (which the status would read as an endless
  // "syncing" — the exact lie this design forbids).
  async _dispatch(item) {
    const { vaultId, repair } = item;
    const io = this._io;
    try {
      const cfg = (io.listConfigured() || []).find((c) => c && c.vaultId === vaultId);
      if (!cfg || !cfg.enabled) { this._emit(vaultId, { phase: 'skipped', reason: 'not-configured' }); return; }

      // Eligibility, fail-closed on uncertainty.
      const s = io.session ? io.session() : {};
      if (!s || typeof s.locked !== 'boolean' || typeof s.online !== 'boolean' || typeof s.accountLive !== 'boolean') {
        this._emit(vaultId, { phase: 'skipped', reason: 'state-uncertain' }); return;
      }
      if (s.locked) { this._emit(vaultId, { phase: 'skipped', reason: 'paused-locked' }); return; } // lock stops dispatch (Standard-gated)
      if (!s.accountLive) { this._emit(vaultId, { phase: 'skipped', reason: 'no-session' }); return; }
      if (!s.online) { this._emit(vaultId, { phase: 'paused', reason: 'waiting-to-reconnect' }); return; } // offline

      // A vault BLOCKED after a completed run is never auto-resynced — cheap no-op, needs a deliberate Repair.
      const st = io.runState ? io.runState(vaultId) : null;
      // 'unknown' = the run-state could not be read (a throwing store, or no state DB this session). It is NOT
      // never-run: dispatching would spuriously initial-resync a possibly-established vault. Skip, uncertain.
      if (st === 'unknown') { this._emit(vaultId, { phase: 'skipped', reason: 'state-uncertain' }); return; }
      const neverRun = !st || st.lastResult == null;
      if (!repair && !neverRun && st.resyncRequired) { this._emit(vaultId, { phase: 'blocked', reason: 'needs-repair' }); return; }

      // Run-time re-assertion (fail-closed): still a server-confirmed Standard vault; remote re-derived from the CURRENT name.
      const el = await io.verifyEligible(vaultId);
      if (!el || !el.ok) { this._emit(vaultId, { phase: 'refused', reason: (el && el.reason) || 'ineligible' }); return; }
      const remotePath = el.remotePath;

      // Re-secure + re-classify the folder before any write (covers configs/folders created before these
      // checks). secureFolder may be async (it applies + reads back a real ACL), so it is awaited — a
      // Promise left unawaited would read as a truthy object with no `ok` and wrongly refuse every run.
      const sec = await io.secureFolder(cfg.localFolder);
      if (!sec || !sec.ok) { this._emit(vaultId, { phase: 'refused', reason: (sec && sec.reason) || 'folder-insecure' }); return; }
      const cl = io.classify(cfg.localFolder);
      if (!cl || !cl.ok) { this._emit(vaultId, { phase: 'refused', reason: (cl && cl.reason) || 'folder-rejected' }); return; }

      // Refresh + re-send the credential before dispatch; a refresh failure fails closed.
      const cr = await io.refreshCred(vaultId);
      if (!cr || !cr.ok) { this._emit(vaultId, { phase: 'paused', reason: (cr && cr.reason) || 'cred-refresh-failed' }); return; }

      const spec = { vaultId, local: cfg.localFolder, remotePath };
      const useResync = repair || neverRun; // initial baseline OR deliberate Repair — always zero-loss (keep-both)
      // The first upload is gated, fail-closed. `kind` lets the caller show the right dialog: an initial
      // first-upload (the two-way consent for a not-yet-consented config) vs a Repair confirm — and lets an
      // already-consented config's Repair skip the two-way consent it was already asked.
      if (useResync && io.confirmFirstUpload) {
        let proceed = false;
        try { proceed = await io.confirmFirstUpload({ vaultId, kind: repair ? 'repair' : 'initial' }); } catch { proceed = false; }
        if (!proceed) { this._emit(vaultId, { phase: 'skipped', reason: 'consent-declined' }); return; }
      }
      this._emit(vaultId, { phase: 'running' });
      const outcome = useResync ? await io.runResync(spec) : await io.runSync(spec);
      // A BENIGN refusal: the helper already has a run in flight for this vault (its in-flight guard fired,
      // which only happens when a healthy long run is still going). Route it by the TYPED field, never the
      // prose. It is neither a failure nor a completion — emit a no-op that leaves the in-flight run's
      // status untouched, so it is never counted toward the failure streak nor stamped as a completed run.
      if (outcome && outcome.refused === 'already-running') {
        this._emit(vaultId, { phase: 'noop', reason: 'already-running' });
        return outcome;
      }
      // A run stopped by a TRANSIENT authority refusal mid-resync (a per-step credential request refused because
      // the app locked, or went offline) did not happen and carries no typed result — read it as the same calm
      // skip the pre-dispatch gate emits (keeps the last state, no notification), never a 'couldn't sync' error.
      if (outcome && outcome.ran === false && outcome.result == null && outcome.reason) {
        this._emit(vaultId, { phase: 'skipped', reason: outcome.reason });
        return outcome;
      }
      // A single 'auth-failed' from a run that DID execute may be a boundary race (the single-use credential
      // lapsed or was spent right at connect) rather than a real account problem — the two are otherwise
      // indistinguishable. Retry ONCE with a fresh mint (a fresh dispatch re-mints) before letting it latch a
      // "sign in": emit a calm retry and re-enqueue, not the 'done' that maps to sign-in-needed. A SECOND
      // consecutive auth-failed falls through to 'done' and latches — a genuine session problem. Any other
      // outcome clears the one-shot, so each episode gets its single retry.
      if (outcome && outcome.ran === true && outcome.result === 'auth-failed' && !this._authRetried.has(vaultId)) {
        this._authRetried.add(vaultId);
        this._emit(vaultId, { phase: 'paused', reason: 'retrying' });
        // Queue the one retry directly: _enqueue would coalesce it away because _current is still this vault
        // mid-dispatch. It dispatches on the next pump, once the finally has cleared _current. Skip if the vault
        // is already queued (a manual press, say) — that pending run is the retry. Carry the dispatch's identity:
        // a Repair must retry AS a repair (else it re-hits the blocked gate and reads "repair owed again"), and a
        // manual press must retry AS manual so the press is answered by the retry's real outcome.
        if (!this._queue.some((q) => q.vaultId === vaultId)) this._queue.push({ vaultId, manual: !!item.manual, repair: !!repair });
        return outcome;
      }
      if (!(outcome && outcome.ran === true && outcome.result === 'auth-failed')) this._authRetried.delete(vaultId);
      // A run that could not EXECUTE (timeout / no helper / send-failed) resolves { ok:false } — that is an
      // 'error', not 'done'. 'done' means the run ran; its typed result (which may still be a conflict or a
      // safety abort) is carried in `outcome` for the status model to classify.
      if (!outcome || outcome.ok === false) {
        this._emit(vaultId, { phase: 'error', reason: (outcome && (outcome.error || outcome.result)) || 'run-failed', outcome: outcome || null });
      } else {
        this._emit(vaultId, { phase: 'done', outcome });
      }
      return outcome;
    } catch (e) {
      this._emit(vaultId, { phase: 'error', reason: String((e && e.message) || e) });
    }
  }
}

module.exports = { SyncScheduler };

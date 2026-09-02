'use strict';

/*
 * A main-side cache of each configured vault's run-state (last typed result + whether a resync is owed),
 * refreshed from the helper's authoritative store. The scheduler reads it SYNCHRONOUSLY to tell a
 * never-run vault from a blocked one.
 *
 * The load-bearing rule: a FAILED refresh must NEVER look like "every vault never-run" (which would
 * blind-dispatch a genuinely blocked vault). So the snapshot tracks whether its LAST refresh actually
 * SUCCEEDED — `fresh()` — and the caller gates dispatch on that: a stale-or-failed snapshot makes the
 * scheduler's session read state-uncertain and skip, rather than reading absent entries as never-run.
 * `get()` still returns the last known entry for display; only `fresh()` authorises a dispatch decision.
 */

class RunStateSnapshot {
  /**
   * @param {object} io
   * @param {(vaultIds:string[]) => Promise<{ok:boolean, states?:object}>} io.fetch  the helper query
   *   (daemon-manager.runStates): { ok:true, states } on a real answer (states may be empty = all
   *   genuinely never-run), { ok:false } on failure/timeout/dead helper.
   */
  constructor(io = {}) {
    this._fetch = io.fetch;
    this._states = new Map(); // vaultId -> { lastResult, resyncRequired } | null
    this._fresh = false;      // did the LAST refresh succeed?
  }

  /**
   * Refresh from the helper. On a real answer, replace the snapshot and mark it fresh. On a failed query,
   * mark it NOT fresh (keeping the prior entries only for display) so the caller fails closed.
   * @returns {Promise<boolean>} whether the refresh succeeded
   */
  async refresh(vaultIds) {
    const ids = Array.isArray(vaultIds) ? vaultIds : [];
    let res;
    try { res = await this._fetch(ids); } catch { res = { ok: false }; }
    if (res && res.ok) {
      const states = res.states || {};
      const next = new Map();
      for (const v of ids) next.set(v, Object.prototype.hasOwnProperty.call(states, v) ? states[v] : null);
      this._states = next;
      this._fresh = true;
      return true;
    }
    this._fresh = false;
    return false;
  }

  /** Whether the last refresh succeeded — the ONLY basis for authorising a dispatch decision. */
  fresh() { return this._fresh; }

  /**
   * The scheduler's io.runState(vaultId): the stored entry for a vault the last refresh COVERED — a real
   * entry, or null for a genuinely never-run vault (asked about, no row). An id the last refresh did NOT
   * cover (e.g. a just-enabled vault kicked before a refresh) reads 'unknown', NOT null — so the scheduler
   * skips it state-uncertain rather than mistaking "never asked" for "never run" and auto-resyncing a
   * possibly-latched vault. The property holds by construction: no dispatch runs against a vault the daemon
   * was not asked about in the current snapshot.
   */
  get(vaultId) { return this._states.has(vaultId) ? this._states.get(vaultId) : 'unknown'; }
}

module.exports = { RunStateSnapshot };

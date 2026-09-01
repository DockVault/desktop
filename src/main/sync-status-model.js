'use strict';

/*
 * The single computed sync-status model — the one place that turns raw signals (the supervised
 * daemon's lifecycle, the app lock, network reachability, and each vault's last typed sync outcome)
 * into ONE honest state for the tray glance, plus a per-vault breakdown for the menu and the
 * read-only status channel.
 *
 * The vocabulary is fixed and small — five running states only:
 *   up-to-date · syncing · paused · needs-decision · sync-problem
 * and two non-running conditions that are NOT sync states because sync cannot or does not run in
 * them: 'unavailable' (no OS secret store, so nothing durable to sync) and 'not-configured' (no
 * vault has been offered a folder yet). Keeping those separate avoids dressing "sync can't run" up
 * as a calm sync state.
 *
 * Two rules keep the aggregate honest:
 *   - Precedence: sync-problem > needs-decision > paused > syncing > up-to-date. The overall glance
 *     is the HIGHEST-precedence contributor across every vault and every global signal — a single
 *     unresolved item forbids the green "up to date" face. A locked vault that ALSO has a conflict
 *     reads "needs your decision", not merely "paused".
 *   - A dead/looping daemon is a sync problem, never a sixth state and never a calm face: once the
 *     supervisor gives up (the crash-loop ceiling), the glance is "sync problem" until a deliberate
 *     restart, so a stopped background helper is never presented as working.
 *
 * Pure and side-effect free (no Electron, no IO) so it can be exhaustively unit-tested; the tray,
 * notifications, channel, and scheduler consume it.
 */

// The five running states (fixed vocabulary) plus the two non-running conditions.
const STATE = Object.freeze({
  UP_TO_DATE: 'up-to-date',
  SYNCING: 'syncing',
  PAUSED: 'paused',
  NEEDS_DECISION: 'needs-decision',
  SYNC_PROBLEM: 'sync-problem',
  // Non-running conditions — sync is not running, and honestly is not claimed to be.
  UNAVAILABLE: 'unavailable',       // no OS secret store: nothing durable, background helper withheld
  NOT_CONFIGURED: 'not-configured', // no vault has been given a local folder yet
});

// Higher wins the aggregate. The two non-running conditions are handled before ranking (they mean
// "no running state applies"), so they carry no rank here.
const RANK = Object.freeze({
  [STATE.SYNC_PROBLEM]: 5,
  [STATE.NEEDS_DECISION]: 4,
  [STATE.PAUSED]: 3,
  [STATE.SYNCING]: 2,
  [STATE.UP_TO_DATE]: 1,
});

// The human label for each state. These five are the fixed vocabulary; the finer per-reason wording
// (paused-because-locked vs waiting-to-reconnect vs can't-verify-yet, and the per-outcome sentences)
// is carried in `reason`/`detail` and finalized alongside the rest of the human copy.
const LABEL = Object.freeze({
  [STATE.UP_TO_DATE]: 'Up to date',
  [STATE.SYNCING]: 'Syncing',
  [STATE.PAUSED]: 'Paused',
  [STATE.NEEDS_DECISION]: 'Needs your decision',
  [STATE.SYNC_PROBLEM]: 'Sync problem',
  [STATE.UNAVAILABLE]: 'Sync unavailable',
  [STATE.NOT_CONFIGURED]: 'Sync not set up',
});

/*
 * Map one vault's last typed sync outcome to a running state. The outcome strings are exactly those
 * the sync engine's outcome classifier emits (plus the engine's own 'blocked-needs-resync' when a
 * run is refused because a resync is owed). A null outcome means the vault is configured but has not
 * completed a run yet — surfaced as a calm "waiting to sync", never as green.
 *
 * The three states that need a deliberate person to act are 'needs-decision' (a choice or a repair)
 * and 'sync-problem' (something is wrong). 'auth-failed' is a decision (sign in again), not a scary
 * problem. A host-key MISMATCH is a problem that must be acted on (a changed server identity); a
 * host key that simply cannot be verified yet (an older server without the endpoint) is a calm
 * paused state, not a problem.
 */
const OUTCOME_STATE = Object.freeze({
  'ok': { state: STATE.UP_TO_DATE },
  'resync-ok': { state: STATE.UP_TO_DATE },
  'conflict-keep-both': { state: STATE.NEEDS_DECISION, reason: 'conflict-keep-both' },
  'needs-resync': { state: STATE.NEEDS_DECISION, reason: 'needs-repair' },
  'blocked-needs-resync': { state: STATE.NEEDS_DECISION, reason: 'needs-repair' },
  'abort-excessive-delete': { state: STATE.NEEDS_DECISION, reason: 'confirm-large-delete' },
  'auth-failed': { state: STATE.NEEDS_DECISION, reason: 'sign-in-needed' },
  'path-too-long': { state: STATE.NEEDS_DECISION, reason: 'path-too-long' },
  'host-key-unverified': { state: STATE.PAUSED, reason: 'cannot-verify-yet' },
  'host-key-mismatch': { state: STATE.SYNC_PROBLEM, reason: 'host-key-mismatch' },
  'error': { state: STATE.SYNC_PROBLEM, reason: 'error' },
});

/**
 * @param {object} v one vault's signals
 * @param {string} v.vault            vault identifier
 * @param {boolean} [v.running]       a run is in flight right now
 * @param {string|null} [v.lastResult] the last typed outcome, or null if it has never completed a run
 * @param {boolean} [v.resyncRequired] a resync is owed (a blocked latch)
 * @returns {{vault:string, state:string, reason:(string|null), running:boolean, resyncRequired:boolean}}
 */
function vaultState(v) {
  const running = !!v.running;
  const resyncRequired = !!v.resyncRequired;
  // A blocked latch (a resync is owed) is a decision the person must make, even mid-run: it never
  // silently clears and it never reads as green. It outranks the transient "syncing" face.
  if (resyncRequired && (v.lastResult == null || OUTCOME_STATE[v.lastResult] == null
      || RANK[OUTCOME_STATE[v.lastResult].state] < RANK[STATE.NEEDS_DECISION])) {
    return { vault: v.vault, state: STATE.NEEDS_DECISION, reason: 'needs-repair', running, resyncRequired };
  }
  if (v.lastResult != null && OUTCOME_STATE[v.lastResult]) {
    const m = OUTCOME_STATE[v.lastResult];
    // A run in flight still shows "syncing" only when nothing unresolved outranks it; an unresolved
    // outcome (a decision or a problem) keeps its face even while the next run is moving.
    if (running && RANK[m.state] <= RANK[STATE.SYNCING]) {
      return { vault: v.vault, state: STATE.SYNCING, reason: null, running, resyncRequired };
    }
    return { vault: v.vault, state: m.state, reason: m.reason || null, running, resyncRequired };
  }
  // Configured but no completed run yet.
  if (running) return { vault: v.vault, state: STATE.SYNCING, reason: null, running, resyncRequired };
  return { vault: v.vault, state: STATE.SYNCING, reason: 'waiting-first-sync', running, resyncRequired };
}

/**
 * Compute the one honest aggregate plus the per-vault breakdown.
 *
 * @param {object} s the raw signals
 * @param {boolean} [s.hasSecureStore]  false => 'unavailable' (nothing durable to sync)
 * @param {boolean} [s.locked]          the app is locked => paused (unless something unresolved outranks it)
 * @param {boolean} [s.online=true]     false => a calm "waiting to reconnect" (a paused-tier transient)
 * @param {string}  [s.daemon]          supervised-helper lifecycle: 'ready'|'starting'|'crashed'|'stopped'
 * @param {boolean} [s.crashLoopLatched] the supervisor gave up after repeated crashes => a sync problem
 * @param {Array}   [s.vaults]          per-vault signals (see vaultState)
 * @returns {{state:string, label:string, reason:(string|null), vaults:Array, condition:(string|null)}}
 */
function computeStatus(s) {
  const store = s.hasSecureStore !== false;
  if (!store) {
    return { state: STATE.UNAVAILABLE, label: LABEL[STATE.UNAVAILABLE], reason: 'no-secure-store', vaults: [], condition: 'unavailable' };
  }
  const vaults = Array.isArray(s.vaults) ? s.vaults.map(vaultState) : [];
  if (vaults.length === 0) {
    return { state: STATE.NOT_CONFIGURED, label: LABEL[STATE.NOT_CONFIGURED], reason: null, vaults: [], condition: 'not-configured' };
  }

  // Global contributors, each carrying the reason that drives its wording.
  const contributors = [];
  // A helper that has given up (crash-loop ceiling) is a problem, and must never hide behind a calm
  // face. It outranks everything below and is surfaced until a deliberate restart.
  if (s.crashLoopLatched) contributors.push({ state: STATE.SYNC_PROBLEM, reason: 'sync-stopped' });
  // The app being locked pauses sync — but only wins the glance if nothing unresolved outranks it.
  if (s.locked) contributors.push({ state: STATE.PAUSED, reason: 'locked' });
  // Offline is a calm, transient paused-tier state, never an alarm.
  if (s.online === false) contributors.push({ state: STATE.PAUSED, reason: 'waiting-to-reconnect' });
  // A helper that is restarting (below the ceiling) is a calm transient, not a problem yet.
  if (!s.crashLoopLatched && (s.daemon === 'starting' || s.daemon === 'crashed')) {
    contributors.push({ state: STATE.PAUSED, reason: 'reconnecting' });
  }
  for (const v of vaults) contributors.push({ state: v.state, reason: v.reason, vault: v.vault });

  // The aggregate is the highest-precedence contributor; ties keep the first seen (global before
  // per-vault only where ranks are equal, which does not change the surfaced severity).
  let winner = { state: STATE.UP_TO_DATE, reason: null };
  for (const c of contributors) {
    if (RANK[c.state] > RANK[winner.state]) winner = c;
  }
  return {
    state: winner.state,
    label: LABEL[winner.state],
    reason: winner.reason || null,
    vaults,
    condition: null,
  };
}

module.exports = { STATE, RANK, LABEL, OUTCOME_STATE, vaultState, computeStatus };

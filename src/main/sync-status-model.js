'use strict';

/*
 * The single computed sync-status model — the one place that turns raw signals (the supervised
 * daemon's lifecycle, the app lock, network reachability, and each vault's last typed sync outcome)
 * into ONE honest state for the tray glance, plus a per-vault breakdown for the menu and the
 * read-only status channel.
 *
 * The vocabulary is fixed and small:
 *   up-to-date · syncing · paused · needs-decision · sync-problem
 * plus 'waiting' for a vault that is set up but has not run yet — a calm, NON-active state that is
 * deliberately NOT "syncing" (nothing is transferring) and NOT "up to date" (it has never synced), so
 * a configured vault never claims to be syncing while no run is happening;
 * and two non-running conditions that are NOT sync states because sync cannot or does not run in
 * them: 'unavailable' (no OS secret store, so nothing durable to sync) and 'not-configured' (no
 * vault has been offered a folder yet). Keeping those separate avoids dressing "sync can't run" up
 * as a calm sync state.
 *
 * Two rules keep the aggregate honest:
 *   - Precedence: sync-problem > needs-decision > paused > syncing > waiting > up-to-date. The overall glance
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

// The running/active states plus the calm 'waiting' (set up, not run yet) and the two non-running
// conditions.
const STATE = Object.freeze({
  UP_TO_DATE: 'up-to-date',
  WAITING: 'waiting',               // configured but not run yet — calm, non-active, never "syncing"
  SYNCING: 'syncing',
  PAUSED: 'paused',
  NEEDS_DECISION: 'needs-decision',
  SYNC_PROBLEM: 'sync-problem',
  // Non-running conditions — sync is not running, and honestly is not claimed to be.
  UNAVAILABLE: 'unavailable',       // no OS secret store: nothing durable, background helper withheld
  NOT_CONFIGURED: 'not-configured', // no vault has been given a local folder yet
});

// Higher wins the aggregate. The two non-running conditions are handled before ranking (they mean
// "no running state applies"), so they carry no rank here. 'waiting' sits above up-to-date (a
// never-run vault forbids the green "up to date" glance) and below syncing (a real in-flight run wins).
const RANK = Object.freeze({
  [STATE.SYNC_PROBLEM]: 6,
  [STATE.NEEDS_DECISION]: 5,
  [STATE.PAUSED]: 4,
  [STATE.SYNCING]: 3,
  [STATE.WAITING]: 2,
  [STATE.UP_TO_DATE]: 1,
});

// The human label for each state. The finer per-reason wording (paused-because-locked vs
// waiting-to-reconnect vs can't-verify-yet, and the per-outcome sentences) is carried in
// `reason`/`detail` and finalized alongside the rest of the human copy.
const LABEL = Object.freeze({
  [STATE.UP_TO_DATE]: 'Up to date',
  [STATE.WAITING]: 'Sync set up — not running yet',
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
  // A different safety abort than the delete cap (all files on one side read as changed). It needs a deliberate
  // resync to re-establish the baseline — surfaced as a repair, NOT as a "large delete" (which it is not).
  'abort-all-changed': { state: STATE.NEEDS_DECISION, reason: 'needs-repair' },
  'auth-failed': { state: STATE.NEEDS_DECISION, reason: 'sign-in-needed' },
  // A persistent auth-failed for a password-protected vault (past its one retry): the likely cause is a rotated
  // vault password, so the remedy is to unlock the vault (re-enter its password), NOT to sign in again.
  'auth-failed-locked': { state: STATE.NEEDS_DECISION, reason: 'needs-unlock' },
  'path-too-long': { state: STATE.NEEDS_DECISION, reason: 'path-too-long' },
  'host-key-unverified': { state: STATE.PAUSED, reason: 'cannot-verify-yet' },
  'host-key-mismatch': { state: STATE.SYNC_PROBLEM, reason: 'host-key-mismatch' },
  'error': { state: STATE.SYNC_PROBLEM, reason: 'error' },
  // Persistent failure to sync at all (repeated run errors, or repeated failures before a run even starts).
  // A must-act — sync is not happening — but framed by DURATION, not danger: it is far more often a
  // connection/sign-in issue than corruption, so its copy stays calm.
  'not-syncing': { state: STATE.SYNC_PROBLEM, reason: 'not-syncing' },
});

/**
 * @param {object} v one vault's signals
 * @param {string} v.vault            vault identifier
 * @param {boolean} [v.running]       a run is in flight right now (dispatch..completion) — drives the per-vault
 *   "Sync now" affordance's honest-concurrency state, NOT the glance; a run may be scanning without transferring.
 * @param {boolean} [v.transferring]  the run is actually moving bytes right now — THIS drives the "syncing"
 *   glance, so a routine no-op check (running but not transferring) stays quiet at its last real state.
 * @param {{files:(number|null), bytes:(number|null)}|null} [v.progress] the two aggregate transfer counts for
 *   the "Syncing… N files / X" detail; carried through untouched, numbers only, never a path.
 * @param {string|null} [v.lastResult] the last typed outcome, or null if it has never completed a run
 * @param {boolean} [v.resyncRequired] a resync is owed (a blocked latch)
 * @param {{state:string, reason:(string|null)}|null} [v.condition] a live reason the vault cannot run
 *   right now (e.g. it is no longer eligible, the folder is gone, sign-in is needed, consent is owed).
 *   Distinct from a completed run's outcome: it is set when a dispatch was refused/paused rather than run,
 *   and it FORBIDS a stale green — a vault that cannot run must never keep reading "Up to date".
 * @param {number|null} [v.lastSyncedAt] epoch-ms of this vault's last SUCCESSFUL run, or null if it has
 *   never succeeded this session. Carried through untouched for the "Last synced" glance; it never
 *   affects the state (a stale success time must not make a failing vault read green).
 * @returns {{vault:string, state:string, reason:(string|null), running:boolean, resyncRequired:boolean, lastSyncedAt:(number|null)}}
 */
function vaultState(v) {
  const running = !!v.running;
  const transferring = !!v.transferring;
  const resyncRequired = !!v.resyncRequired;
  const base = baseVaultState(v, transferring, running, resyncRequired);
  // Fold a live can't-run condition over the last-outcome state: it wins whenever it is at least as
  // severe, so a persistent refusal (a decision or a problem) replaces a stale "up to date", while a
  // strictly more severe completed outcome (e.g. a prior sync problem) is not masked by it.
  const cond = v.condition && v.condition.state ? v.condition : null;
  const out = (cond && RANK[cond.state] >= RANK[base.state])
    ? { vault: v.vault, state: cond.state, reason: cond.reason || null, running, resyncRequired }
    : base;
  // progress rides along ONLY while the vault is actually syncing; any other state clears it so a stale
  // count never trails a finished or paused vault.
  const progress = out.state === STATE.SYNCING && v.progress ? v.progress : null;
  return { ...out, running, progress, lastSyncedAt: v.lastSyncedAt != null ? v.lastSyncedAt : null };
}

function baseVaultState(v, transferring, running, resyncRequired) {
  // A blocked latch (a resync is owed) is a decision the person must make, even mid-run: it never
  // silently clears and it never reads as green. It outranks the transient "syncing" face.
  if (resyncRequired && (v.lastResult == null || OUTCOME_STATE[v.lastResult] == null
      || RANK[OUTCOME_STATE[v.lastResult].state] < RANK[STATE.NEEDS_DECISION])) {
    return { vault: v.vault, state: STATE.NEEDS_DECISION, reason: 'needs-repair', running, resyncRequired };
  }
  if (v.lastResult != null && OUTCOME_STATE[v.lastResult]) {
    const m = OUTCOME_STATE[v.lastResult];
    // The "syncing" glance shows ONLY while bytes are actually moving (transferring) and nothing unresolved
    // outranks it. A run that is merely dispatched/scanning (running but not transferring) keeps the vault's
    // last real state — a routine no-op tick never flickers "syncing". An unresolved outcome (a decision or a
    // problem) keeps its face even while the next run moves.
    if (transferring && RANK[m.state] <= RANK[STATE.SYNCING]) {
      return { vault: v.vault, state: STATE.SYNCING, reason: null, running, resyncRequired };
    }
    return { vault: v.vault, state: m.state, reason: m.reason || null, running, resyncRequired };
  }
  // Configured but no completed run yet. Only an actual transfer reads "syncing"; a dispatched-but-scanning
  // first run stays the calm "waiting to start" — never "syncing" while nothing is transferring, never green.
  if (transferring) return { vault: v.vault, state: STATE.SYNCING, reason: null, running, resyncRequired };
  return { vault: v.vault, state: STATE.WAITING, reason: 'waiting-first-sync', running, resyncRequired };
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
  for (const v of vaults) contributors.push({ state: v.state, reason: v.reason, vault: v.vault, progress: v.progress || null });

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
    // The glance's transfer detail, present only when the winning contributor is a syncing vault.
    progress: (winner.state === STATE.SYNCING && winner.progress) ? winner.progress : null,
    vaults,
    condition: null,
  };
}

module.exports = { STATE, RANK, LABEL, OUTCOME_STATE, vaultState, computeStatus };

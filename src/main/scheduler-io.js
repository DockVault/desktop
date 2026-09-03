'use strict';

/*
 * The testable half of the background scheduler's injected IO: the two pieces whose CORRECTNESS is a
 * pure transformation and must be proven without Electron or a network. The Electron-only glue (folder
 * ACLs, the credential cache, the live session signals, the tray) stays in the main entry and is
 * exercised by the app-level checks; this module is the logic those wrappers wrap.
 *
 *  - The run effects map the scheduler's run spec onto the helper's run call, and — the load-bearing
 *    rule — a resync run is ALWAYS the resync call (which the helper routes only through the keep-both
 *    path), never a plain run. A normal run is never sent as a resync.
 *  - verifyEligible is the run-time re-assertion: it re-fetches the account's Standard vaults FRESH
 *    (never a cached list), confirms THIS vault is still among them (a vault re-tiered to zero-knowledge
 *    or removed is simply absent → fail closed), and re-derives the remote path from the vault's CURRENT
 *    name — so a rename is followed, and a name that is no longer a single safe segment fails closed.
 *  - applySchedulerEvent folds each run event into the status hub, keeping the tray glance honest.
 */

const { STATE } = require('./sync-status-model');

/**
 * Bind the scheduler's run effects to a ready helper handle whose runSync(spec) takes
 * { vault, local, remotePath, resync? }. The scheduler speaks { vaultId, local, remotePath }.
 * @param {{ runSync: (spec:object)=>Promise<object> }} daemon
 */
function makeRunEffects(daemon) {
  const toSpec = (s) => ({ vault: s.vaultId, local: s.local, remotePath: s.remotePath });
  return {
    runSync: (spec) => daemon.runSync(toSpec(spec)),
    runResync: (spec) => daemon.runSync({ ...toSpec(spec), resync: true }),
  };
}

/**
 * Build the run-time eligibility check. `fetchStandard` returns the FRESH Standard-vault set as
 * { vaults: [{ vaultId, vaultName }], ... } (it fails closed on a non-OK response by throwing);
 * `remotePathForVault(name)` returns the validated single-segment remote path or throws.
 * @param {{ fetchStandard: ()=>Promise<{vaults:Array<{vaultId:string,vaultName:string}>}>, remotePathForVault: (name:string)=>string }} io
 * @returns {(vaultId:string)=>Promise<{ok:true,remotePath:string,vaultName:string}|{ok:false,reason:string}>}
 */
function makeVerifyEligible({ fetchStandard, remotePathForVault }) {
  return async (vaultId) => {
    let res;
    try { res = await fetchStandard(); }
    catch (e) { return { ok: false, reason: (e && e.reason) || 'vault-list-unavailable' }; }
    const v = (res && res.vaults || []).find((x) => x && x.vaultId === vaultId);
    if (!v) return { ok: false, reason: 'not-standard-or-removed' }; // re-tiered / renamed-away id / deleted → all fail closed
    let remotePath;
    try { remotePath = remotePathForVault(v.vaultName); }
    catch { return { ok: false, reason: 'bad-vault-name' }; }
    return { ok: true, remotePath, vaultName: v.vaultName };
  };
}

/*
 * Build the scheduler's session() signal — the eligibility gate read before every dispatch. It reports the
 * three booleans the scheduler needs (account-usable, a live account session, online) EXCEPT when the
 * run-state snapshot is not fresh, when it reports state-uncertain (an object carrying no booleans) so the
 * scheduler SKIPS rather than deciding never-run-vs-blocked from a stale or failed run-state view. This is
 * where the run-state fail-closed is realized: the snapshot only carries `fresh`; the caller must gate here.
 *
 * `locked` is the ACCOUNT-TIER pause: the negation of isAccountUsable() (app active + not lock-paused). It is
 * deliberately NOT the ZK unlocked state — Standard-vault sync authenticates with the account session and the
 * daemon-held DB key, never the zero-knowledge key, so this path must never read isUnlocked().
 * @param {{ isAccountUsable:()=>boolean, hasAccount:()=>boolean, isOnline:()=>boolean, snapshotFresh:()=>boolean }} io
 */
function makeSession({ isAccountUsable, hasAccount, isOnline, snapshotFresh }) {
  return () => {
    if (!snapshotFresh()) return { uncertain: true }; // no fresh run-state view → don't decide blind
    return { locked: !isAccountUsable(), accountLive: !!hasAccount(), online: !!isOnline() };
  };
}

/*
 * Assemble the full injected IO the SyncScheduler needs, from primitive dependencies. Every method is a
 * thin binding onto an already-tested piece (run effects, the fresh-fetch eligibility check, the session
 * gate, the credential cache, the run-state snapshot), so the scheduler's whole IO surface is built in one
 * place and the index.js glue only has to supply the REAL Electron signals (lock / account / online),
 * the daemon handle, and the folder/consent effects. Pure — no Electron, no network.
 * @param {object} deps
 * @param {()=>Array} deps.listConfigured
 * @param {{get:(v:string)=>object|null, fresh:()=>boolean}} deps.snapshot  a RunStateSnapshot
 * @param {()=>Promise<{vaults:Array}>} deps.fetchStandard
 * @param {(name:string)=>string} deps.remotePathForVault
 * @param {(folder:string)=>({ok:boolean,reason?:string})} deps.secureFolder
 * @param {(folder:string)=>({ok:boolean,reason?:string})} deps.classify
 * @param {{ensureSent:(v:string)=>Promise<object>}} deps.credCache
 * @param {{runSync:(spec:object)=>Promise<object>}} deps.daemon
 * @param {(o:object)=>Promise<boolean>} [deps.confirmFirstUpload]
 * @param {()=>boolean} deps.isAccountUsable
 * @param {()=>boolean} deps.hasAccount
 * @param {()=>boolean} deps.isOnline
 * @param {(vaultId:string, ev:object)=>void} deps.onEvent
 */
function makeSchedulerIo(deps) {
  const fx = makeRunEffects(deps.daemon);
  return {
    listConfigured: deps.listConfigured,
    runState: (vaultId) => deps.snapshot.get(vaultId),
    session: makeSession({ isAccountUsable: deps.isAccountUsable, hasAccount: deps.hasAccount, isOnline: deps.isOnline, snapshotFresh: () => deps.snapshot.fresh() }),
    verifyEligible: makeVerifyEligible({ fetchStandard: deps.fetchStandard, remotePathForVault: deps.remotePathForVault }),
    secureFolder: deps.secureFolder,
    classify: deps.classify,
    refreshCred: (vaultId) => deps.credCache.ensureSent(vaultId),
    confirmFirstUpload: deps.confirmFirstUpload,
    runSync: fx.runSync,
    runResync: fx.runResync,
    onEvent: deps.onEvent,
  };
}

/*
 * Translate one scheduler progress event into the status hub's signal setters, so the tray glance stays
 * honest as runs come and go. The hub turns per-vault { running, lastResult, resyncRequired, condition }
 * plus the global signals into the one computed state; this decides which setter each event drives:
 *
 *   running  -> a run is in flight now
 *   done     -> the run completed; its typed outcome (which may itself be a conflict or a safety abort)
 *               is recorded, and running clears
 *   error    -> the run could not complete (threw, or could not start) — recorded as a sync problem
 *   blocked  -> a completed-then-blocked vault owes a deliberate repair; mark the resync-owed latch
 *   refused / skipped / paused -> no run happened. A PERSISTENT cause (the vault is no longer eligible,
 *               the folder is gone, sign-in is owed, consent is owed) records a live can't-run CONDITION
 *               so the vault stops reading "up to date"; a genuinely TRANSIENT cause (queued, offline,
 *               locked, momentarily uncertain) clears the condition and keeps the last honest state,
 *               since the global signals already carry those glances.
 *
 * One cause is routed regardless of phase: a detected server-identity change ('host-key-mismatch') —
 * which the credential cache now catches BEFORE dispatch and surfaces as a refresh failure — takes the
 * same must-act path as the helper's connect-time detection, never a calm "retrying".
 *
 * `hub` exposes setRunning, recordOutcome and recordCondition({state,reason}).
 */
function applySchedulerEvent(hub, vaultId, ev) {
  const phase = ev && ev.phase;
  const reason = ev && ev.reason;
  if (reason === 'host-key-mismatch') { hub.recordOutcome(vaultId, { result: 'host-key-mismatch' }); return; }
  switch (phase) {
    case 'running': hub.setRunning(vaultId, true); return;
    case 'done': {
      const o = ev.outcome || {};
      hub.recordOutcome(vaultId, { result: o.result, resyncRequired: o.resyncRequired });
      return;
    }
    case 'error': hub.recordOutcome(vaultId, { result: 'error' }); return;
    case 'blocked': hub.recordOutcome(vaultId, { resyncRequired: true }); return;
    case 'refused':
    case 'skipped':
    case 'paused': {
      const cond = conditionForReason(phase, reason);
      if (cond) hub.recordCondition(vaultId, cond);
      // A transient skip must NOT erase a persistent condition — only an actual run (setRunning true) or a
      // completed run (recordOutcome) clears it. Otherwise one lock/unlock or uncertain tick would flip a
      // stuck vault back to its stale last state. So just stop showing running and keep whatever holds.
      else hub.setRunning(vaultId, false);
      return;
    }
    case 'queued': hub.setRunning(vaultId, false); return;
    // A no-op (e.g. a benign 'already-running' refusal): touch NOTHING — the in-flight run's status stands.
    case 'noop': return;
    default: return; // an unknown phase changes nothing
  }
}

// The ratified persistent-vs-transient table. A persistent reason yields a live can't-run condition
// (a non-green honest state); a transient one yields null (keep the last state). Exact reason->state
// vocabulary owned by the status/UX side; the persistent-vs-transient distinction is the anti-lie rule.
function conditionForReason(phase, reason) {
  switch (reason) {
    case 'not-standard-or-removed':
    case 'bad-vault-name':   return { state: STATE.NEEDS_DECISION, reason: 'vault-unavailable' };
    case 'folder-insecure':  return { state: STATE.NEEDS_DECISION, reason: 'folder-insecure' };
    case 'folder-rejected':  return { state: STATE.NEEDS_DECISION, reason: 'folder-rejected' };
    // A folder that was made private and is now RE-SHARED (a foreign ACE reappeared): the same consent can
    // fix it, so this is a distinct decision from a folder that is simply gone/unusable (choose-folder).
    case 'folder-problem':   return { state: STATE.NEEDS_DECISION, reason: 'folder-problem' };
    case 'no-session':       return { state: STATE.NEEDS_DECISION, reason: 'sign-in-needed' };
    // A password-protected vault whose password main does not hold (window closed to tray, or not captured), or a
    // vault-password mint refusal (400/429). A NON-retrying must-act: the remedy is to unlock THIS vault so its
    // password reaches the mint — never a retry (which would burn the server's shared vault rate limit). Deliberately
    // NOT in RETRYABLE_FAILURE_REASONS, so it surfaces once and stays put rather than looping.
    case 'needs-unlock':     return { state: STATE.NEEDS_DECISION, reason: 'needs-unlock' };
    case 'host-key-unavailable': return { state: STATE.PAUSED, reason: 'cannot-verify-yet' }; // older/unverifiable server — calm, not an alarm
    case 'consent-declined': return { state: STATE.WAITING, reason: 'consent-needed' }; // a user choice: re-offerable, never a notification
    case 'waiting-to-reconnect':
    case 'paused-locked':
    case 'state-uncertain':
    case 'not-configured':   return null; // transient — the global signals carry these
    default:
      // A credential-refresh failure surfaces as 'paused': an auth failure arrives as 'no-session'
      // (handled above -> sign-in); any other refresh hiccup is a calm, retryable pause.
      if (phase === 'paused') return { state: STATE.PAUSED, reason: 'retrying' };
      return null; // unknown refusal reason: conservatively keep the last state rather than invent one
  }
}

// The retryable failures that a vault can hit BEFORE a run is even dispatched — a mint that could not be
// obtained, a credential the helper would not accept, a vault list that could not be fetched. Like a run
// 'error', these should read as a calm retry at first but must NOT read that way forever: repeated, they
// mean the vault simply is not syncing. The reasons that already have their own honest state — sign-in,
// cannot-verify-yet, a host-key mismatch, a bad folder or an unavailable vault — are deliberately NOT here.
const RETRYABLE_FAILURE_REASONS = new Set(['mint-failed', 'cred-send-failed', 'cred-refresh-failed', 'vault-list-unavailable']);

function isRetryableFailure(phase, reason) {
  if (phase === 'error') return reason !== 'host-key-mismatch'; // a dispatched run that failed (identity alert excluded)
  if (phase === 'paused' || phase === 'refused') return RETRYABLE_FAILURE_REASONS.has(reason);
  return false;
}

/*
 * A thin stateful sink over the pure mapping that thresholds retryable FAILURES — whether a dispatched run
 * failed or the vault could not even start (mint / credential / vault-list). A single timeout or flap does
 * not raise an alarm: the first few consecutive failures read as a calm "retrying" (PAUSED, no
 * notification). Once they persist to the threshold it becomes ONE honest, calm-but-not-green escalation —
 * "not syncing" — with a single notification, rather than staying "retrying" forever. Any completed run
 * resets the streak. Every non-failure event maps straight through (a host-key-mismatch stays an immediate
 * alert, never a retry).
 */
class StatusSink {
  constructor(hub, { errorThreshold = 3 } = {}) {
    this._hub = hub;
    this._threshold = Math.max(1, errorThreshold | 0);
    this._errors = new Map(); // vaultId -> consecutive failure count (dispatched OR pre-dispatch)
  }

  apply(vaultId, ev) {
    const phase = ev && ev.phase;
    const reason = ev && ev.reason;
    if (phase === 'done') this._errors.set(vaultId, 0); // a completed run ends the failure streak
    if (isRetryableFailure(phase, reason)) {
      const n = (this._errors.get(vaultId) || 0) + 1;
      this._errors.set(vaultId, n);
      // Escalate as a CONDITION, not a stored outcome: a later, more specific reason (a sign-in owed, a bad
      // folder, an unavailable vault) then REPLACES it, instead of a sticky 'not-syncing' outranking and
      // masking the real fix. The underlying last outcome is left intact and a completed run clears it.
      if (n >= this._threshold) this._hub.recordCondition(vaultId, { state: STATE.SYNC_PROBLEM, reason: 'not-syncing' });
      else this._hub.recordCondition(vaultId, { state: STATE.PAUSED, reason: 'retrying' }); // still just a retry
      return;
    }
    applySchedulerEvent(this._hub, vaultId, ev);
  }
}

module.exports = { makeRunEffects, makeVerifyEligible, makeSession, makeSchedulerIo, applySchedulerEvent, conditionForReason, StatusSink };

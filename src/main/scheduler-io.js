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
const { isTransportError } = require('./net-errors');

/**
 * Bind the scheduler's run effects to a ready helper handle whose runSync(spec) takes
 * { vault, local, remotePath, movedFrom?, remoteMovedFrom?, resync? }. The scheduler speaks { vaultId, local, remotePath, … }.
 * @param {{ runSync: (spec:object)=>Promise<object> }} daemon
 */
function makeRunEffects(daemon) {
  const toSpec = (s) => ({
    vault: s.vaultId, local: s.local, remotePath: s.remotePath,
    ...(typeof s.movedFrom === 'string' ? { movedFrom: s.movedFrom } : {}),
    ...(typeof s.remoteMovedFrom === 'string' ? { remoteMovedFrom: s.remoteMovedFrom } : {}),
  });
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
    catch (e) {
      if (e && e.reason) return { ok: false, reason: e.reason };
      // A 401/403 on the vault list is an expired or invalid ACCOUNT SESSION, not connectivity — surface it as
      // 'no-session' so the person is shown "sign in", never "check your connection" or "our own step failed".
      // (Checked before the transport test, which would otherwise read the status as a generic retryable fault.)
      if (e && (e.status === 401 || e.status === 403)) return { ok: false, reason: 'no-session' };
      // A genuine fetch/transport failure is a retryable 'vault-list-unavailable'. A code fault (no status, no
      // network code) is NOT connectivity — surface it as a non-retryable 'internal-error' and log its
      // class/code, rather than retrying a programming bug forever behind the retryable reason.
      if (isTransportError(e)) return { ok: false, reason: 'vault-list-unavailable' };
      try { console.error('[sync] eligibility internal error:', (e && e.name) || 'Error', (e && e.code) || ''); } catch { /* ignore */ }
      return { ok: false, reason: 'internal-error' };
    }
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
 * booleans the scheduler needs (account-usable, a live account session, a usable device identity, online)
 * EXCEPT when the run-state snapshot is not fresh, when it reports state-uncertain (an object carrying no
 * booleans) so the scheduler SKIPS rather than deciding never-run-vs-blocked from a stale or failed run-state
 * view. This is where the run-state fail-closed is realized: the snapshot only carries `fresh`; the caller
 * must gate here.
 *
 * `locked` is the ACCOUNT-TIER pause: the negation of isAccountUsable() (app active + not lock-paused). It is
 * deliberately NOT the ZK unlocked state — Standard-vault sync authenticates with the account session and the
 * daemon-held DB key, never the zero-knowledge key, so this path must never read isUnlocked().
 *
 * `deviceLive` says this computer holds a sync identity of its own (registered here, for this server). A vault
 * synced on that identity needs no account session at all, so the scheduler dispatches when EITHER the account
 * session or the device identity is live; which one a given vault actually uses is decided per run by the
 * eligibility step, and a vault that needs the missing one is refused there with its own honest reason.
 * @param {{ isAccountUsable:()=>boolean, hasAccount:()=>boolean, hasDeviceIdentity?:()=>boolean, isOnline:()=>boolean, snapshotFresh:()=>boolean }} io
 */
function makeSession({ isAccountUsable, hasAccount, hasDeviceIdentity, isOnline, snapshotFresh }) {
  return () => {
    if (!snapshotFresh()) return { uncertain: true }; // no fresh run-state view → don't decide blind
    let deviceLive = false;
    try { deviceLive = typeof hasDeviceIdentity === 'function' && hasDeviceIdentity() === true; } catch { deviceLive = false; }
    return { locked: !isAccountUsable(), accountLive: !!hasAccount(), deviceLive, online: !!isOnline() };
  };
}

/**
 * The gate a per-step credential request (one rclone process of a multi-step run asking for a fresh single-use
 * credential) must pass, decided from the run's credential path. Returns null when the mint may proceed, else the
 * typed reason to refuse with. The device path needs no account session; the account path does; a request for
 * a vault that is not in flight, or a run that never chose a path, is refused — main authorises, it never guesses.
 *
 * The ACCOUNT-TIER lock splits by path: a vault synced on THIS computer's own device identity keeps running
 * under the OS lock — its device secret needs no account session and no zero-knowledge key — while the account
 * path still pauses (its credential is dropped as lock hygiene). The split keys on the LATCHED credential path and
 * fails closed: only an explicit device path bypasses the lock; an account path or an un-latched one pauses.
 * @param {{inFlight:boolean, locked:boolean, via:('device'|'account'|null), accountLive:boolean}} o
 */
function perStepGate({ inFlight, locked, via, accountLive }) {
  if (!inFlight) return 'not-in-flight';
  // The device path is not gated by the account-tier lock — a device/Standard vault keeps syncing under the lock.
  if (via === 'device') return null;
  // Everything else the lock pauses: the account path, and — fail-closed — a run that has not latched a path, so
  // any doubt about the path pauses under the lock rather than minting.
  if (locked) return 'paused-locked';
  if (via === 'account') return accountLive ? null : 'no-session';
  return 'not-in-flight'; // no path chosen for this run: a mint would be unauthorised
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
 * @param {(cfg:object)=>Promise<object>} [deps.resolveFolder]  the folder by its marker (folder-identity.js)
 * @param {{ensureSent:(v:string)=>Promise<object>}} deps.credCache
 * @param {{runSync:(spec:object)=>Promise<object>}} deps.daemon
 * @param {(o:object)=>Promise<boolean>} [deps.confirmFirstUpload]
 * @param {()=>boolean} deps.isAccountUsable
 * @param {()=>boolean} deps.hasAccount
 * @param {()=>boolean} [deps.hasDeviceIdentity]  this computer holds a usable sync identity for the configured server
 * @param {(vaultId:string)=>boolean} [deps.vaultHasPassword]
 * @param {()=>boolean} deps.isOnline
 * @param {(vaultId:string, ev:object)=>void} deps.onEvent
 */
function makeSchedulerIo(deps) {
  const fx = makeRunEffects(deps.daemon);
  return {
    listConfigured: deps.listConfigured,
    runState: (vaultId) => deps.snapshot.get(vaultId),
    session: makeSession({ isAccountUsable: deps.isAccountUsable, hasAccount: deps.hasAccount, hasDeviceIdentity: deps.hasDeviceIdentity, isOnline: deps.isOnline, snapshotFresh: () => deps.snapshot.fresh() }),
    // Exposed for the per-step credential provider's live-account gate: it calls io.hasAccount() before
    // minting a fresh credential for each rclone process of a first-run/resync. Threading it only into
    // makeSession left io.hasAccount undefined, so that gate threw (a swallowed TypeError) on every per-step
    // request while the dispatch path — refreshCred below — never touched it and worked.
    hasAccount: deps.hasAccount,
    // Exposed for the scheduler's auth-failed reroute (sync-scheduler.js): a password-protected vault past its
    // one retry maps auth-failed -> needs-unlock (re-enter the vault password) rather than a sign-in. Same
    // omission as hasAccount above — it was threaded nowhere — but this read is typeof-guarded, so instead of
    // throwing it silently stayed false and dropped the reroute (a wrong sign-in state for a rotated password).
    vaultHasPassword: deps.vaultHasPassword,
    verifyEligible: makeVerifyEligible({ fetchStandard: deps.fetchStandard, remotePathForVault: deps.remotePathForVault }),
    secureFolder: deps.secureFolder,
    classify: deps.classify,
    resolveFolder: deps.resolveFolder,
    refreshCred: (vaultId) => deps.credCache.ensureSent(vaultId),
    // gate-before-mint readiness check: the helper's health (rclone checksum + version), side-effect-free (no
    // mint, no SFTP) and cheap (cached on a healthy helper — one `rclone version` spawn only while not ready).
    // A not-ready result carries the typed sub in the same {ok:false,sub,installed,pinned} no-error shape, so
    // the dispatch surfaces helper-not-ready and SKIPS the mint rather than burn a single-use credential.
    helperReady: () => deps.daemon.syncStatus(),
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
  // A code fault in our OWN path — a credential provider that threw, or an unclassified internal error — is a
  // NON-retrying problem regardless of the phase it surfaced in. Record it as a distinct sync-problem outcome
  // so it reads as a problem at once, never the generic retryable 'error' that retries-then-escalates.
  if (reason === 'provider-error' || reason === 'internal-error') { hub.recordOutcome(vaultId, { result: 'sync-error' }); return; }
  switch (phase) {
    // `via` names the credential path this run took ('device' | 'account'), so the glance can say which.
    case 'running': hub.setRunning(vaultId, true, ev.via || null); return;
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
      if (cond) {
        // Carry the helper-not-ready DETAIL (the specific sub + the daemon-detected installed version) onto the
        // condition for the tray's per-sub message. The sub NEVER affects the state — that is fixed to the
        // single non-retrying 'helper-not-ready' reason at conditionForReason, so an unknown sub cannot escape.
        if (ev.sub != null) cond.sub = ev.sub;
        if (ev.installed != null) cond.installed = ev.installed;
        hub.recordCondition(vaultId, cond);
      }
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
// vocabulary is a presentation-layer concern; the persistent-vs-transient distinction is the anti-lie rule.
function conditionForReason(phase, reason) {
  switch (reason) {
    case 'not-standard-or-removed':
    case 'bad-vault-name':   return { state: STATE.NEEDS_DECISION, reason: 'vault-unavailable' };
    case 'folder-insecure':  return { state: STATE.NEEDS_DECISION, reason: 'folder-insecure' };
    case 'folder-rejected':  return { state: STATE.NEEDS_DECISION, reason: 'folder-rejected' };
    // A folder that was made private and is now RE-SHARED (a foreign ACE reappeared): the same consent can
    // fix it, so this is a distinct decision from a folder that is simply gone/unusable (choose-folder).
    case 'folder-problem':   return { state: STATE.NEEDS_DECISION, reason: 'folder-problem' };
    // The folder is known by its marker (folder-identity.js). Each way of not finding it is its own decision:
    // the folder is gone from where it was (moved away, deleted, a drive unplugged); something else now sits
    // at that path; the marker was torn; two folders carry the marker (a copy was made). All pause the vault
    // — never sync the wrong place — and offer relocate-or-stop; none is retried into a "check your connection".
    case 'folder-missing':          return { state: STATE.NEEDS_DECISION, reason: 'folder-missing' };
    case 'folder-marker-missing':   return { state: STATE.NEEDS_DECISION, reason: 'folder-marker-missing' };
    case 'folder-other-vault':      return { state: STATE.NEEDS_DECISION, reason: 'folder-other-vault' };
    case 'folder-marker-unreadable': return { state: STATE.NEEDS_DECISION, reason: 'folder-marker-unreadable' };
    case 'folder-ambiguous':        return { state: STATE.NEEDS_DECISION, reason: 'folder-ambiguous' };
    case 'folder-moved-rejected':   return { state: STATE.NEEDS_DECISION, reason: 'folder-moved-rejected' }; // found, but now somewhere it must not sync
    case 'folder-found-elsewhere':  return { state: STATE.NEEDS_DECISION, reason: 'folder-found-elsewhere' }; // a look-alike (a copy, or moved across drives): confirm first
    case 'folder-marker-unwritable': return { state: STATE.NEEDS_DECISION, reason: 'folder-marker-unwritable' }; // the folder refuses the marker (read-only)
    case 'config-unwritable':       return { state: STATE.NEEDS_DECISION, reason: 'config-unwritable' };       // the sync settings could not be saved
    case 'no-session':       return { state: STATE.NEEDS_DECISION, reason: 'sign-in-needed' };
    // A password-protected vault whose password main does not hold (window closed to tray, or not captured), or a
    // vault-password mint refusal (400/429). A NON-retrying must-act: the remedy is to unlock THIS vault so its
    // password reaches the mint — never a retry (which would burn the server's shared vault rate limit). Deliberately
    // NOT in RETRYABLE_FAILURE_REASONS, so it surfaces once and stays put rather than looping.
    case 'needs-unlock':     return { state: STATE.NEEDS_DECISION, reason: 'needs-unlock' };
    case 'host-key-unavailable': return { state: STATE.PAUSED, reason: 'cannot-verify-yet' }; // older/unverifiable server — calm, not an alarm
    // The endpoint gate's answers (a credential-free probe of the sync server, run instead of minting after a
    // connect failure): the door can't be reached — calm, retried with a growing back-off, escalated by the sink
    // when it persists; or something answers there that is not an SSH server this app can talk to — a problem at
    // once (the address is wrong, or the server is misconfigured), never retried as "try again in a moment".
    case 'sync-server-unreachable': return { state: STATE.PAUSED, reason: 'sync-server-unreachable' };
    case 'sync-server-unverified': return { state: STATE.SYNC_PROBLEM, reason: 'sync-server-unverified' };
    // This computer's sync identity (device sync). Each server answer is its OWN honest state — none collapses
    // into a sign-in line, a generic retry, or an alarm it does not deserve. None is retried by the streak logic
    // below (a refused identity does not become "check your connection"); the calm ones simply wait.
    case 'grant-needs-reproof': return { state: STATE.NEEDS_DECISION, reason: 'grant-needs-reproof' }; // re-prove the vault password once
    case 'device-being-rechecked': return { state: STATE.PAUSED, reason: 'device-being-rechecked' };   // a rotation cut off mid-flight is being re-checked against the account — a calm wait, never a set-up-again
    case 'device-revoked':
    case 'device-removed':      return { state: STATE.NEEDS_DECISION, reason: 'device-revoked' };      // this computer was removed (the server said so, or its identity is already gone)
    case 'device-expired':      return { state: STATE.NEEDS_DECISION, reason: 'device-expired' };      // its access ran out
    case 'device-suspended':    return { state: STATE.NEEDS_DECISION, reason: 'device-suspended' };    // paused by the server pending the owner
    case 'invalid-device-credential':
    case 'device-secret-stale': return { state: STATE.NEEDS_DECISION, reason: 'device-not-recognized' }; // the identity held here is not current
    case 'account-inactive':    return { state: STATE.NEEDS_DECISION, reason: 'account-inactive' };    // the ACCOUNT is locked — not a device fault
    case 'no-grant':            return { state: STATE.NEEDS_DECISION, reason: 'grant-withdrawn' };     // this vault's access for this computer was withdrawn
    case 'vault-not-standard':  return { state: STATE.NEEDS_DECISION, reason: 'vault-not-standard' };  // only Standard vaults sync — an explanation, not a fault
    case 'device-cred-cap':     return { state: STATE.NEEDS_DECISION, reason: 'device-cred-cap' };     // the server's per-computer credential limit — named, never retried per tick
    case 'device-request-refused': return { state: STATE.SYNC_PROBLEM, reason: 'device-refused' };    // an unrecognised refusal: fail closed, non-retrying
    case 'device-secret-unreadable':
    case 'device-state-unreadable':
    case 'device-identity-missing':
    case 'grants-unreadable':   return { state: STATE.PAUSED, reason: 'device-identity-unreadable' }; // transient: the OS store / the grant list could not be read just now
    // A device-path run whose transfer was refused at the SFTP door: the identity is being re-checked on the
    // next pass (a revoke, a suspension, or a rotated password shows up there as its own state) — never the
    // account-session remedies, which do not apply to a device-minted credential.
    case 'device-access-check': return { state: STATE.PAUSED, reason: 'device-access-check' };
    // Local wiring faults in the device client (a missing secret at request time, a route not on the
    // allowlist): a problem in our own path, surfaced as such, never retried as connectivity.
    case 'no-device-secret':
    case 'route-not-allowed':   return { state: STATE.SYNC_PROBLEM, reason: 'sync-error' };
    case 'grant-details-pending': return { state: STATE.PAUSED, reason: 'grant-details-pending' };     // waiting for the vault's details from an account session
    // The sync helper did NOT answer — the daemon is down, timed out, or exited (a NO-ANSWER transport failure,
    // never a typed not-ready). Calm + RETRYABLE (below), NOT the non-retrying 'helper-not-ready' misconfigured
    // lane: a crashed-but-fine helper self-recovers, and the one must-act on a crash is the hub's own 'restart'.
    // (On the streak path this is intercepted as a retryable — shown as 'reconnecting' below threshold and
    // escalated to 'sync-stopped'/restart when it persists; this case gives a direct manual press its own honest,
    // calm line rather than the generic retry default.)
    case 'helper-unavailable': return { state: STATE.PAUSED, reason: 'helper-unavailable' };
    // The sync helper (rclone) is not ready — a wrong version, a failed checksum, or it could not start/prepare.
    // ONE non-retrying must-act, decided at the gate; the specific sub rides as a DETAIL, never as the reason,
    // so an unknown/new sub can never fall through to the calm 'retrying' default. NOT in RETRYABLE below.
    case 'helper-not-ready': return { state: STATE.SYNC_PROBLEM, reason: 'helper-not-ready' };
    case 'consent-declined': return { state: STATE.WAITING, reason: 'consent-needed' }; // a user choice: re-offerable, never a notification
    case 'waiting-to-reconnect':
    case 'paused-locked':
    case 'state-uncertain':
    case 'not-configured':   return null; // transient — the global signals carry these
    // A routine tick skipped inside the vault's refusal back-off: nothing new was learned, so the refusal already
    // on the glance (the last run's real outcome) stands. Not a failure on the streak either — no run was attempted.
    case 'backing-off':      return null;
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
const RETRYABLE_FAILURE_REASONS = new Set(['mint-failed', 'cred-send-failed', 'cred-refresh-failed', 'vault-list-unavailable', 'helper-unavailable', 'network', 'server-error', 'sync-server-unreachable']);

function isRetryableFailure(phase, reason) {
  if (phase === 'error') return reason !== 'host-key-mismatch'; // a dispatched run that failed (identity alert excluded)
  if (phase === 'paused' || phase === 'refused') return RETRYABLE_FAILURE_REASONS.has(reason);
  return false;
}

// The failure a scheduler event stands for on the retry streak, or null when it is not one. A completed run whose
// typed result says the door could not be reached is a failure like any other on the streak (it is NOT the
// completion that ends one), carried under the endpoint reason so its escalation keeps naming the real cause.
function streakFailureReason(ev) {
  const phase = ev && ev.phase;
  const reason = ev && ev.reason;
  if (phase === 'done' && ev.outcome && ev.outcome.result === 'connect-failed') return 'sync-server-unreachable';
  if (isRetryableFailure(phase, reason)) return reason || 'error';
  return null;
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
    const reason = streakFailureReason(ev);
    if (phase === 'done' && reason == null) this._errors.set(vaultId, 0); // a completed run ends the failure streak
    if (reason != null) {
      const n = (this._errors.get(vaultId) || 0) + 1;
      this._errors.set(vaultId, n);
      // Escalate as a CONDITION, not a stored outcome: a later, more specific reason (a sign-in owed, a bad
      // folder, an unavailable vault) then REPLACES it, instead of a sticky problem outranking and masking the
      // real fix. The underlying last outcome is left intact and a completed run clears it.
      //
      // A DOWN helper (a no-answer transport failure — the daemon wedged, crashed, or exited) has ONE honest
      // remedy whether it crash-LOOPED or WEDGED: restart it. So a persistent 'helper-unavailable' escalates to
      // 'sync-stopped'/restart — never 'not-syncing'/"check your connection", which would misattribute the cause
      // and offer no working fix — and reads 'reconnecting' while it retries. This shares the restart lane with a
      // crash-loop latch, so a wedged helper (which has no latch) still reaches the same "restart it". Every other
      // retryable failure keeps the generic 'retrying' -> 'not-syncing'.
      //
      // The sync server that cannot be reached keeps ITS cause through the escalation: "waiting for the sync
      // server" while it retries, "can't reach the sync server" once it persists — never the generic "check your
      // connection", and never the credential-limit message the old per-tick minting used to end in.
      const down = reason === 'helper-unavailable';
      const unreachable = reason === 'sync-server-unreachable';
      if (n >= this._threshold) this._hub.recordCondition(vaultId, { state: STATE.SYNC_PROBLEM, reason: down ? 'sync-stopped' : unreachable ? 'sync-server-unreachable' : 'not-syncing' });
      else this._hub.recordCondition(vaultId, { state: STATE.PAUSED, reason: down ? 'helper-unavailable' : unreachable ? 'sync-server-unreachable' : 'retrying' }); // helper-unavailable reads 'reconnecting'
      return;
    }
    applySchedulerEvent(this._hub, vaultId, ev);
  }
}

module.exports = { makeRunEffects, makeVerifyEligible, makeSession, makeSchedulerIo, perStepGate, applySchedulerEvent, conditionForReason, streakFailureReason, StatusSink };

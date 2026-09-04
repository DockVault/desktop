'use strict';

/*
 * The single source of the one completion answer a deliberate "Sync now" press earns. Pure (no Notification,
 * no Electron), so every phase/reason maps to exactly one honest line and is unit-tested per reason.
 *
 * The event is resolved through the SAME two tables the status sink and the tray glance use, so the toast can
 * never tell a different story than the tray:
 *   - a run that HAPPENED ('done'/'error') is classified through OUTCOME_STATE (the sink's recordOutcome table);
 *   - a run that did NOT happen ('paused'/'refused'/'skipped') is classified through conditionForReason.
 * Both resolve to a per-vault (state, reason); the reason maps to one line here. In particular a server whose
 * identity cannot be VERIFIED reads as a verification pause, never as "can't reach the server", and a server
 * whose identity has CHANGED reads as the loud must-act — never the vague "couldn't sync" — even on a manual
 * press, whose exactly-one-toast window would otherwise suppress the hub's own identity alarm.
 *
 * Returns { silent: true } when no toast should fire (the person themselves declined the upload), else { body }.
 * The wording is provisional and is finalized with the rest of the human copy; the one-source structure is not.
 */

const { conditionForReason } = require('./scheduler-io');
const { STATE, OUTCOME_STATE } = require('./sync-status-model');

// A resolved per-vault (state, reason) -> the manual completion line. Shares the reason vocabulary with the
// tray so the toast and the glance stay one source.
function bodyForConditionReason(reason, name) {
  switch (reason) {
    case 'cannot-verify-yet':
      // A fail-closed VERIFICATION pause, NOT a connectivity blip: the server's identity cannot be confirmed
      // yet. Deliberately promises no specific remedy — this state covers a server that is too old to publish
      // its full key, an absent endpoint, or a fetch that failed — so it says only that verification is pending.
      return `DockVault can't verify ${name}'s server yet — paused until its identity is confirmed.`;
    case 'host-key-mismatch':
      // A CHANGED server identity — a security must-act, at least as loud as the hub alert this replaces on a
      // manual press. Never the vague "couldn't sync": the user must be told to stop and check.
      return `${name}'s server identity has changed — don't sync until you've confirmed this is really your server. Open DockVault.`;
    case 'sign-in-needed': return `Sign in to keep ${name} syncing.`;
    case 'needs-unlock': return `Unlock ${name} to sync it.`; // password-protected vault: unlock it in DockVault so its password reaches the sync (provisional copy)
    case 'needs-repair':
    case 'confirm-large-delete': return `${name} needs a repair before it can sync. Open DockVault to fix it.`;
    case 'path-too-long': return `A file in ${name} needs a shorter path. Open DockVault to fix it.`;
    case 'folder-insecure':
    case 'folder-rejected':
    case 'folder-problem': return `${name} can't sync until its folder is fixed. Open DockVault to sort it out.`;
    case 'vault-unavailable': return `${name} can't be synced any more. Open DockVault for details.`;
    case 'conflict-keep-both': return `${name} has conflicting copies — open DockVault to review them.`;
    case 'not-syncing': return `${name} hasn't synced for a while. Open DockVault to check your connection.`;
    case 'helper-not-ready':
      // The sync helper (rclone) isn't ready — a NON-retrying must-act (a wrong/missing/blocked binary, or one
      // that won't start), so NEVER the calm "try again in a moment" that would tell a different story than the
      // tray. Points at the same how-to the tray offers; the per-sub specifics live on the glance/dialog.
      return `${name} can't sync — the sync helper isn't ready. Open DockVault to see how to fix it.`;
    case 'helper-unavailable':
      // The sync helper did NOT answer (the daemon is down / restarting) — DISTINCT from 'helper-not-ready'
      // (a misconfigured helper): this one self-recovers, so it is a calm, retryable line, NEVER the "how to
      // fix it" setup pointer, and never "misconfigured". (Provisional copy — finalized with the human copy pass.)
      return `Can't reach the sync helper for ${name} right now — it'll keep trying.`;
    case 'error': return `${name} couldn't sync. Open DockVault to see why.`;
    case 'retrying':
    default: return `${name} couldn't sync just now. Try again in a moment.`;
  }
}

function manualCompletionBody(ev, name) {
  const phase = ev && ev.phase;
  const reason = ev && ev.reason;
  const result = ev && ev.outcome && ev.outcome.result;

  // A changed server identity is the loud must-act whatever phase carries it — a run that failed on it, a
  // completed run that reported it, or the cred cache catching it before dispatch. Route it FIRST, exactly as
  // applySchedulerEvent does, so a pending press never gets the vague error line while the exactly-one-toast
  // window suppresses the hub's own identity alarm.
  if (reason === 'host-key-mismatch' || result === 'host-key-mismatch') {
    return { body: bodyForConditionReason('host-key-mismatch', name) };
  }

  // A run that HAPPENED — classify its typed outcome through the sink's OUTCOME_STATE table.
  if (phase === 'done' || phase === 'error') {
    const mapped = OUTCOME_STATE[result] || OUTCOME_STATE[reason] || null;
    if (mapped && mapped.state === STATE.UP_TO_DATE) return { body: `${name} is up to date — safe to work offline.` };
    if (mapped && mapped.reason) return { body: bodyForConditionReason(mapped.reason, name) };
    // 'done' with no typed result, or an unrecognised error: an honest, non-specific line for each.
    return { body: phase === 'error'
      ? `${name} couldn't sync. Open DockVault to see why.`
      : `${name} finished, but it needs your attention. Open DockVault to review.` };
  }
  if (phase === 'blocked') return { body: bodyForConditionReason('needs-repair', name) };

  // paused / refused / skipped: a run did not happen. A choice the person made themselves earns no toast.
  if (reason === 'consent-declined') return { silent: true };
  const cond = conditionForReason(phase, reason);
  if (cond) return { body: bodyForConditionReason(cond.reason, name) };
  // Reasons conditionForReason leaves null — the global signals carry the glance for these — still owe a manual
  // press an honest answer.
  switch (reason) {
    case 'waiting-to-reconnect': return { body: `Can't reach the server right now — ${name} will sync as soon as you're back online.` };
    case 'paused-locked': return { body: `${name} will sync after you unlock DockVault.` };
    case 'ineligible': return { body: `${name} can't be synced any more. Open DockVault for details.` };
    default: return { body: `${name} couldn't sync just now. Try again in a moment.` };
  }
}

module.exports = { manualCompletionBody };

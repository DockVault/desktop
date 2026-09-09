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
const { reasonSentence, waitWords } = require('./tray-presentation');

// A resolved per-vault (state, reason) -> the manual completion line. Shares the reason vocabulary with the
// tray so the toast and the glance stay one source.
function bodyForConditionReason(reason, name, opts = {}) {
  // The reasons that can name a file, a stated size, the room a vault has left, or a wait get their sentence
  // from the ONE copy source the tray and the Computers card also read, so a press is answered with exactly
  // what the glance says — never a second, vaguer version of the same failure.
  const rich = reasonSentence(reason, { name, detail: opts.detail, retryAt: opts.retryAt, now: opts.now, repairOwed: opts.repairOwed });
  if (rich) return rich;
  switch (reason) {
    case 'cannot-verify-yet':
      // A fail-closed VERIFICATION pause, NOT a connectivity blip: the server's identity cannot be confirmed
      // yet. Deliberately promises no specific remedy — this state covers a server that is too old to publish
      // its full key, an absent endpoint, or a fetch that failed — so it says only that verification is pending.
      return `DockVault can't verify ${name}'s server yet — paused until its identity is confirmed.`;
    case 'host-key-mismatch':
      // A CHANGED server identity — a security must-act, at least as loud as the hub alert this replaces on a
      // manual press. Never the vague "couldn't sync": the user must be told to stop and check.
      return `${name}'s server identity has changed — don't sync until you've confirmed this is really your server. Open Computers & synced folders in the DockVault tray menu to check it.`;
    case 'sign-in-needed': return `Sign in to keep ${name} syncing.`;
    case 'needs-unlock': return `Unlock ${name} to sync it.`; // password-protected vault: unlock it in DockVault so its password reaches the sync (provisional copy)
    case 'needs-repair':
    case 'confirm-large-delete': return `${name} needs a repair before it can sync. Open Computers & synced folders in the DockVault tray menu and use Repair.`;
    case 'path-too-long': return `A file in ${name} needs a shorter path. Open Computers & synced folders in the DockVault tray menu to see which one.`;
    case 'folder-insecure':
    case 'folder-rejected':
    case 'folder-problem': return `${name} can't sync until its folder is fixed. Open Computers & synced folders in the DockVault tray menu to sort it out.`;
    case 'vault-unavailable': return `${name} can't be synced any more. Open Computers & synced folders in the DockVault tray menu for details.`;
    // DELIBERATELY still the file browser, and the only line here that is. Conflicting copies ARE files, and
    // that window is where they can be seen; Computers & synced folders has no conflict surface at all, so
    // sending someone there would repeat the mistake this phase exists to fix, just at a different door.
    case 'conflict-keep-both': return `${name} has conflicting copies — open DockVault to review them.`;
    case 'not-syncing': return `${name} hasn't synced for a while. Open Computers & synced folders in the DockVault tray menu to check on it.`;
    // The SYNC SERVER (the SFTP address), not the account or the network in general — named as such, with the
    // one thing that helps: Troubleshoot checks the saved server and SFTP address separately.
    case 'sync-server-unreachable': return `${name} can't sync: the sync server can't be reached right now. Run Troubleshoot in the DockVault tray menu to check the address.`;
    case 'sync-server-unverified': return `${name} can't sync: what's at the sync server address isn't answering as a sync server. Run Troubleshoot in the DockVault tray menu to check it.`;
    case 'helper-not-ready':
      // The sync helper (rclone) isn't ready — a NON-retrying must-act (a wrong/missing/blocked binary, or one
      // that won't start), so NEVER the calm "try again in a moment" that would tell a different story than the
      // tray. Points at the same how-to the tray offers; the per-sub specifics live on the glance/dialog.
      return `${name} can't sync — the sync helper isn't ready. Open Computers & synced folders in the DockVault tray menu to see how to fix it.`;
    case 'helper-unavailable':
      // The sync helper did NOT answer (the daemon is down / restarting) — DISTINCT from 'helper-not-ready'
      // (a misconfigured helper): this one self-recovers, so it is a calm, retryable line, NEVER the "how to
      // fix it" setup pointer, and never "misconfigured".
      return `Can't reach the sync helper for ${name} right now — it'll keep trying.`;
    // Device sync (this computer's identity and per-vault access) — one honest line each, no retry promise.
    case 'grant-needs-reproof': return `${name}'s password changed — this computer needs it entered once more before it can keep syncing.`;
    case 'device-revoked': return `This computer was removed from your synced computers. It can't sync until it's set up again.`;
    case 'device-expired': return `This computer's sync access has expired. It can't sync until it's renewed.`;
    case 'device-suspended': return `Syncing on this computer is paused by your server pending the owner's review.`;
    case 'device-not-recognized': return `Your server no longer recognises this computer. It can't sync until it's set up again.`;
    case 'account-inactive': return `Your DockVault account is locked — syncing resumes when it's active again.`;
    case 'grant-withdrawn': return `This computer isn't set up to sync ${name} any more.`;
    case 'vault-not-standard': return `${name} is end-to-end encrypted, so it stays on the web — only Standard vaults sync here.`;
    case 'device-cred-cap': return `${name} can't sync yet: this computer has reached your server's sync-credential limit. Try again in a while.`;
    case 'device-refused': return `${name} couldn't sync — your server refused this computer. Open Computers & synced folders in the DockVault tray menu for details.`;
    case 'device-identity-unreadable': return `${name} will sync once this computer's sync identity can be read again.`;
    case 'grant-details-pending': return `Sign in once to finish setting up ${name} on this computer.`;
    case 'device-access-check': return `${name} couldn't sync just now — this computer's access is being re-checked.`;
    // NOTHING here could identify what went wrong — not the server turning this computer away, not a file, not
    // the account, not the folder. Say that plainly (and that nothing was changed), rather than a bare
    // "couldn't sync" that sends a person hunting through their own account and connection.
    case 'error': return `${name} couldn't sync and DockVault couldn't tell why. Nothing here was changed and it will keep trying — run Troubleshoot in the DockVault tray menu to check the server.`;
    // A fault in our OWN sync step (not the connection, not sign-in) — own it, and never promise a retry.
    case 'sync-error': return `Something in DockVault's own sync step failed for ${name} — this is on our side. Open Computers & synced folders in the DockVault tray menu for details.`;
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
    // The run's own detail (which file, which stated size, the vault's room) and its back-off time travel with
    // it, so the press earns the SPECIFIC sentence and not the generic version of it.
    if (mapped && mapped.reason) return { body: bodyForConditionReason(mapped.reason, name, { detail: ev.outcome && ev.outcome.detail, retryAt: ev.retryAt, repairOwed: !!(ev.outcome && ev.outcome.resyncRequired) }) };
    // 'done' with no typed result, or an unrecognised error: an honest, non-specific line for each.
    return { body: phase === 'error'
      ? bodyForConditionReason('error', name)
      : `${name} finished, but it needs your attention. Open DockVault to review.` };  // conflicting copies: see above
  }
  if (phase === 'blocked') return { body: bodyForConditionReason('needs-repair', name) };

  // paused / refused / skipped: a run did not happen. A choice the person made themselves earns no toast.
  if (reason === 'consent-declined') return { silent: true };
  // The vault's door is refusing this computer's credentials and this wait's one attempt is already spent, so the
  // dispatch stopped before minting. Same sentence as a press turned away at the request — one source, one story.
  if (reason === 'backing-off') return { body: turnedAwayBody({ accepted: false, reason: 'backing-off', retryInMs: ev && ev.retryInMs, cause: ev && ev.cause }, name) };
  const cond = conditionForReason(phase, reason);
  if (cond) return { body: bodyForConditionReason(cond.reason, name) };
  // Reasons conditionForReason leaves null — the global signals carry the glance for these — still owe a manual
  // press an honest answer.
  switch (reason) {
    case 'waiting-to-reconnect': return { body: `Can't reach the server right now — ${name} will sync as soon as you're back online.` };
    case 'paused-locked': return { body: `${name} will sync after you unlock DockVault.` };
    case 'ineligible': return { body: `${name} can't be synced any more. Open Computers & synced folders in the DockVault tray menu for details.` };
    default: return { body: `${name} couldn't sync just now. Try again in a moment.` };
  }
}

/**
 * The one line a deliberate press earns when the scheduler turns the REQUEST away before any run (its verdict
 * { accepted:false, reason, retryInMs }): a press inside the "Sync now" cooldown, or one against a door that is
 * refusing this computer's credentials and has had this window's attempt. Honest about the wait, and — for the
 * refusal — that the state already shown is what to act on: signing in or entering the vault password, when the
 * status asks for it, lets DockVault try at once; otherwise waiting is what helps, not a fresh credential.
 * Returns null for an accepted verdict (nothing to say yet: the run's own outcome is the answer).
 */
function turnedAwayBody(verdict, name) {
  if (!verdict || verdict.accepted !== false) return null;
  const wait = waitWords(verdict.retryInMs);
  switch (verdict.reason) {
    case 'sync-cooldown': return `${name} was asked to sync a moment ago — you can ask again in ${wait}. Changes are still picked up on the regular schedule.`;
    // Two different doors, two different answers, told apart by the typed cause the scheduler carries:
    //   channel-refused — the server ANSWERED and turned the connection away (a limit it is applying, or no
    //     session slot free). It clears itself. Naming a sign-in or a credential to deactivate here would send
    //     someone to do work that cannot help, so this branch names them as the things that DON'T.
    //   auth-failed (or an unknown cause) — the credential itself was refused, and a sign-in or the vault's
    //     password genuinely may be what unblocks it, so that offer stays.
    case 'backing-off':
      return verdict.cause === 'channel-refused'
        ? `The sync server is temporarily limiting sync attempts from this computer, so DockVault is waiting before it tries ${name} again (${wait}). Signing in again or deactivating credentials won't help — the wait is what clears it.`
        : `The sync server is refusing this computer's sync credentials for ${name}, so DockVault is waiting before it tries again (${wait}). If its status asks you to sign in or enter the vault password, doing that lets it try at once.`;
    default: return `${name} couldn't be asked to sync just now. Try again in a moment.`;
  }
}

module.exports = { manualCompletionBody, bodyForConditionReason, turnedAwayBody, waitWords };

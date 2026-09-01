'use strict';

/*
 * Compose the tray tooltip and the must-act menu items from the computed sync status and the current
 * lock phase. Pure and side-effect free — the Electron tray layer applies whatever this returns — so
 * the exact glance and the set of menu actions are unit-testable without a display.
 *
 * Two concerns share the one tray glance. The lock machine's in-flight transients (a purge underway,
 * or a purge that could not be confirmed) take the glance while they last, because a lock that is
 * mid-change or in error is the more urgent thing to show. Otherwise the glance reflects the sync
 * status. A vault that is paused because the app is locked reads as "Locked" — the security state —
 * rather than a bare "Paused".
 *
 * The must-act items are the second half of the anti-lie surface: every unresolved item that needs a
 * person (a conflict to review, a repair or sign-in that is owed, a stuck helper to restart, a
 * changed server identity to check) is offered as a tray-menu action, so it is always reachable even
 * when the main window has been closed to the tray. The wording here is provisional and is finalized
 * with the rest of the human copy; the structure — one reachable action per unresolved item — is not.
 */

const { STATE } = require('./sync-status-model');

// A short suffix appended to the tooltip for the calmer paused/transient reasons, so the glance says
// a little about WHY without a novel. The alarming states carry their meaning in the label itself.
const REASON_DETAIL = Object.freeze({
  'waiting-to-reconnect': 'waiting to reconnect',
  'reconnecting': 'reconnecting',
  'cannot-verify-yet': 'cannot verify the server yet',
  // 'waiting-first-sync' carries no suffix: the "Waiting to start" label already says it plainly, and
  // a configured-but-never-run vault must read as not-yet-running, never as active "syncing".
});

function tooltip(model, lockPhase) {
  if (lockPhase === 'locking') return 'DockVault — Locking…';
  if (lockPhase === 'lock-error') return 'DockVault — Lock error (retrying)';
  if (model.condition === 'unavailable') return 'DockVault — Sync unavailable';
  if (model.condition === 'not-configured') return 'DockVault';
  if (model.state === STATE.PAUSED && model.reason === 'locked') return 'DockVault — Locked';
  const detail = REASON_DETAIL[model.reason];
  return 'DockVault — ' + model.label + (detail ? ' · ' + detail : '');
}

// One reachable action per unresolved item. `kind` is the stable action the tray layer wires to a
// handler; `label` is the (provisional) menu text; `vault` names the affected vault where relevant.
function itemForVault(v) {
  switch (v.reason) {
    case 'conflict-keep-both': return { kind: 'review', vault: v.vault, label: `Review conflicting copies in ${v.vault}` };
    case 'sign-in-needed': return { kind: 'sign-in', vault: v.vault, label: `Sign in to keep ${v.vault} syncing` };
    case 'needs-repair':
    case 'confirm-large-delete': return { kind: 'repair', vault: v.vault, label: `Repair sync for ${v.vault}` };
    case 'path-too-long': return { kind: 'repair', vault: v.vault, label: `A file in ${v.vault} needs a shorter path` };
    case 'host-key-mismatch': return { kind: 'check-identity', vault: v.vault, label: `Check ${v.vault}: the server identity changed` };
    default: return { kind: 'open', vault: v.vault, label: `Sync problem with ${v.vault}` };
  }
}

function mustActItems(model) {
  const items = [];
  if (model.condition != null) return items; // unavailable / not-configured: nothing to act on here
  // A stuck helper is one global action: restart it deliberately.
  if (model.state === STATE.SYNC_PROBLEM && model.reason === 'sync-stopped') {
    items.push({ kind: 'restart', label: 'Restart sync' });
  }
  for (const v of model.vaults) {
    if (v.state === STATE.NEEDS_DECISION || v.state === STATE.SYNC_PROBLEM) items.push(itemForVault(v));
  }
  return items;
}

module.exports = { tooltip, mustActItems, REASON_DETAIL };

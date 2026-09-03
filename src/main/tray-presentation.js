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
  'retrying': 'retrying',
  'consent-needed': 'approve syncing to start',
  // The saved sync state exists but cannot be unlocked/opened on this machine. Lead with reassurance —
  // the person's actual files are never touched by this — because a bare "sync problem" over an unreadable
  // database could read as data loss. (The deliberate reset that clears it is a fast-follow.)
  'state-unreadable': "the saved state can't be unlocked here — your files are safe",
  // A sync step failed in our own code path (an unclassified internal error, or a credential provider that
  // threw) rather than a connection/sign-in issue. Honest and non-alarming; not retried forever.
  'sync-error': 'a sync step hit a problem',
  // 'waiting-first-sync' carries no suffix: the "Waiting to start" label already says it plainly, and
  // a configured-but-never-run vault must read as not-yet-running, never as active "syncing".
});

// Human-readable transfer size for the "Syncing…" detail. Binary steps (1024) with familiar labels; a
// round number below 10 of a unit, one decimal otherwise. Returns null for a non-positive/absent count so
// the caller can omit it. Numbers only — never a path.
function formatBytes(n) {
  if (typeof n !== 'number' || !(n > 0)) return null;
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let v = n;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
  const val = (i === 0 || v >= 10) ? Math.round(v) : Math.round(v * 10) / 10;
  return `${val} ${units[i]}`;
}

// The honest, percentage-free transfer detail from the two aggregate counts: "3 files", "4.2 MB", or both.
// Never a total (the size-compare can't know total work ahead), never a path — just what has moved so far.
function progressDetail(progress) {
  if (!progress) return null;
  const parts = [];
  if (typeof progress.files === 'number' && progress.files > 0) parts.push(progress.files === 1 ? '1 file' : `${progress.files} files`);
  const b = formatBytes(progress.bytes);
  if (b) parts.push(b);
  return parts.length ? parts.join(' · ') : null;
}

function tooltip(model, lockPhase) {
  if (lockPhase === 'locking') return 'DockVault — Locking…';
  if (lockPhase === 'lock-error') return 'DockVault — Lock error (retrying)';
  if (model.condition === 'unavailable') return 'DockVault — Sync unavailable';
  if (model.condition === 'not-configured') return 'DockVault';
  if (model.state === STATE.PAUSED && model.reason === 'locked') return 'DockVault — Locked';
  // A persistent no-sync is a must-act, but its glance reads by duration, not alarm (it is usually a
  // connection or sign-in issue). Keep the calm phrasing rather than the bare "Sync problem" label.
  if (model.state === STATE.SYNC_PROBLEM && model.reason === 'not-syncing') return "DockVault — Sync hasn't run for a while";
  // While transferring, show the honest count detail ("Syncing… · 3 files · 4.2 MB") — numbers only, no
  // percentage and no total implied, from the aggregate counts the daemon parsed.
  if (model.state === STATE.SYNCING) {
    const d = progressDetail(model.progress);
    return 'DockVault — ' + model.label + (d ? ' · ' + d : '');
  }
  const detail = REASON_DETAIL[model.reason];
  return 'DockVault — ' + model.label + (detail ? ' · ' + detail : '');
}

// One reachable action per unresolved item. `kind` is the stable action the tray layer wires to a
// handler; `label` is the (provisional) menu text; `vault` names the affected vault where relevant.
function itemForVault(v) {
  switch (v.reason) {
    case 'conflict-keep-both': return { kind: 'review', vault: v.vault, label: `Review conflicting copies in ${v.vault}` };
    case 'sign-in-needed': return { kind: 'sign-in', vault: v.vault, label: `Sign in to keep ${v.vault} syncing` };
    case 'needs-unlock': return { kind: 'unlock', vault: v.vault, label: `Unlock ${v.vault} to sync it` };
    case 'needs-repair':
    case 'confirm-large-delete': return { kind: 'repair', vault: v.vault, label: `Repair sync for ${v.vault}` };
    case 'path-too-long': return { kind: 'repair', vault: v.vault, label: `A file in ${v.vault} needs a shorter path` };
    case 'host-key-mismatch': return { kind: 'check-identity', vault: v.vault, label: `Check ${v.vault}: the server identity changed` };
    case 'vault-unavailable': return { kind: 'open', vault: v.vault, label: `${v.vault} can't sync right now — it may have been changed or removed` };
    case 'not-syncing': return { kind: 'open', vault: v.vault, label: `${v.vault} hasn't synced for a while — check your connection` };
    case 'folder-problem': return { kind: 'recover-folder', vault: v.vault, label: `The sync folder for ${v.vault} is shared again — make it private` };
    case 'folder-insecure':
    case 'folder-rejected': return { kind: 'choose-folder', vault: v.vault, label: `The sync folder for ${v.vault} can't be used — choose a folder again` };
    // A code fault in our OWN sync path — own it plainly so the person doesn't go hunting their own
    // connection/sign-in/keychain for a fault only we can fix. (A "Report a problem" action is a follow-up.)
    case 'sync-error': return { kind: 'open', vault: v.vault, label: "Something in DockVault's own sync step failed — this is on our side, not your connection or sign-in." };
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
  // The saved state can't be unlocked on this machine. Give the real, NON-destructive next step available
  // now (no dedicated button needed): unlock the login keychain and reopen. Clicking opens the app (the
  // "reopen" half); the deliberate "Reset sync state" is a follow-up, appended to this copy only when it ships.
  if (model.state === STATE.SYNC_PROBLEM && model.reason === 'state-unreadable') {
    items.push({ kind: 'reopen', label: "The saved sync state can't be unlocked on this machine — your files are safe and sync is paused. Try unlocking your login keychain and reopening DockVault." });
  }
  for (const v of model.vaults) {
    if (v.state === STATE.NEEDS_DECISION || v.state === STATE.SYNC_PROBLEM) items.push(itemForVault(v));
  }
  return items;
}

// The per-vault "Sync now" affordance, honest about concurrency. While a run is actually in flight for
// this vault it does NOT offer to start another — the runs are serialised (one credential, one run at a
// time) and a second is refused — so it shows the run in progress instead. When the vault is not running
// it offers "Sync now", which merely ENQUEUES a manual run: if another vault is mid-run the scheduler
// queues this one, and the glance moves to syncing in its turn. So the menu never claims a fresh sync
// "started" while one is already underway; it states what is true right now.
function syncNowItem(v) {
  if (v.running) return { kind: 'syncing', vault: v.vault, enabled: false, label: `Syncing ${v.vault}…` };
  return { kind: 'sync-now', vault: v.vault, enabled: true, label: `Sync ${v.vault} now` };
}

const MINUTE_MS = 60 * 1000;
const HOUR_MS = 60 * MINUTE_MS;
const DAY_MS = 24 * HOUR_MS;

// A calm "Last synced …" line for a vault, from the last-SUCCESS time the model carries. A vault that
// has never synced successfully reads "Not synced yet" — never a fabricated or stale-from-failure time.
// Coarse buckets only; the exact wording here is provisional and is finalized with the rest of the human
// copy (the buckets themselves are the stable part). A time in the future (a clock step) reads "just now"
// rather than a negative age.
function lastSyncedLabel(lastSyncedAt, now) {
  if (lastSyncedAt == null) return 'Not synced yet';
  const t = typeof now === 'number' ? now : Date.now();
  const age = t - lastSyncedAt;
  if (age < MINUTE_MS) return 'Last synced just now';
  if (age < HOUR_MS) return `Last synced ${Math.floor(age / MINUTE_MS)} min ago`;
  if (age < DAY_MS) return `Last synced ${Math.floor(age / HOUR_MS)} h ago`;
  return `Last synced ${Math.floor(age / DAY_MS)} d ago`;
}

// Compose the per-vault tray rows, ready for the menu. Each configured vault (its stored id + display
// name) is matched by id to its LIVE per-vault status; a vault with no computed status yet falls back to
// a not-running, never-synced view — never a stale or fabricated one. Pure, so the exact menu content —
// the honest "Sync now"/"Syncing…" affordance and the "Last synced" line per vault — is unit-tested
// without a tray. The Electron layer maps each row to menu items and binds the clicks. The per-item
// label omits the vault name (the row is nested under a menu labelled with the name).
function vaultRows(configured, modelVaults, now) {
  const byId = new Map((Array.isArray(modelVaults) ? modelVaults : []).map((v) => [v.vault, v]));
  return (Array.isArray(configured) ? configured : []).map((e) => {
    const v = byId.get(e.vaultId) || { vault: e.vaultId, running: false, lastSyncedAt: null };
    const item = syncNowItem({ vault: e.vaultId, running: !!v.running });
    const inFlight = item.kind === 'syncing';
    return {
      vaultId: e.vaultId,
      vaultName: e.vaultName,
      lastSynced: lastSyncedLabel(v.lastSyncedAt, now),
      running: inFlight,
      syncLabel: inFlight ? 'Syncing…' : 'Sync now',
      syncEnabled: item.enabled,
      // The honest transfer detail, shown only while this vault is actually syncing (numbers only, no path).
      syncingDetail: v.state === STATE.SYNCING ? progressDetail(v.progress) : null,
    };
  });
}

module.exports = { tooltip, mustActItems, syncNowItem, lastSyncedLabel, vaultRows, formatBytes, progressDetail, REASON_DETAIL };

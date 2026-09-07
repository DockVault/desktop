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
  'helper-unavailable': 'reconnecting', // a down helper (wedged/crashed) retrying — reads as reconnecting until it escalates to restart
  'cannot-verify-yet': 'cannot verify the server yet',
  'retrying': 'retrying',
  'consent-needed': 'approve syncing to start',
  // Device sync, the calm waits: the OS secret store could not be read just now; the vault's details are
  // still to be filled in from a signed-in session. Neither is a fault and neither needs an action yet.
  'device-identity-unreadable': "this computer's sync identity can't be read right now",
  'device-being-rechecked': "this computer's sync identity is being re-checked — sign in once to finish",
  'grant-details-pending': 'sign in once to finish setting up this vault',
  'device-access-check': "re-checking this computer's access",
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

// The per-sub helper-not-ready DETAIL — composed from the bounded sub + the non-secret installed/pinned version
// strings ONLY (never the raw message, path, or SHA). Every known sub gets a specific line; an unknown/null sub
// falls through to an honest generic — NEVER a blank, never a misleading "blocked by antivirus" for a MISSING
// binary (its own line), and never "couldn't verify" for a config/prepare failure.
// Set ONCE by main at startup (app.isPackaged), so every surface that describes the helper — tooltip,
// notification body, dialog — speaks the same way: an installed app's helper came with the installer.
let PACKAGED = false;
function setPackaged(v) { PACKAGED = v === true; }

function helperDetail(sub, installed, pinned, packaged = PACKAGED) {
  switch (sub) {
    case 'version-mismatch': return `The sync helper (rclone) is version ${installed || 'unknown'}, but this app needs ${pinned || 'a different version'}.`;
    case 'checksum-mismatch': return "The sync helper failed a safety check — it doesn't match its expected version.";
    // In a packaged app the helper came with the installer, so "set it up again" would point at nothing;
    // the remedy line (helperRemedy) carries the fix there.
    case 'binary-missing': return packaged ? 'The sync helper file is missing.' : 'The sync helper file is missing. Set it up again.';
    // Only a genuinely-blocked START (a present file that won't launch — SmartScreen / antivirus). A helper that
    // RAN and then failed (obscure-failed) is NOT a start-block, so it falls to the neutral default — asserting an
    // antivirus block for it would be a wrong-cause accusation, the same mistake removed from the missing case.
    case 'spawn-failed': return 'The sync helper was blocked from starting — this can be Windows SmartScreen or your antivirus.';
    default: return packaged ? "The sync helper couldn't be started." : "The sync helper couldn't be set up — check its setup."; // obscure-failed / config-format-failed / prepare-failed / null / any unknown
  }
}

// The REMEDY paragraph under the detail, for a packaged app whose helper came bundled and hash-pinned with the
// installer (no fallback, no user-supplied binary). It follows the typed reason, because the honest fix differs:
// a missing / altered / wrong-version helper IS a damaged installation and only a reinstall repairs it; a helper
// that was BLOCKED from starting is not damaged and a reinstall would change nothing; a helper that ran and then
// failed gets the calm remedy first. Never a path, a value, or a SHA. Development checkouts get their own text.
function helperRemedy(sub, platform) {
  switch (sub) {
    case 'version-mismatch':
    case 'checksum-mismatch':
    case 'binary-missing':
      return "DockVault's installation looks damaged: the sync helper that came with it is missing or has been altered. Reinstall DockVault by running the installer again to repair it. Your files and settings are not affected.";
    case 'spawn-failed':
      if (platform === 'win32') return "Windows SmartScreen or your antivirus stopped the sync helper from starting. Allow DockVault's sync helper (or restore it from quarantine), then restart DockVault. Your files and settings are not affected.";
      if (platform === 'darwin') return 'macOS blocked the sync helper from starting. Allow it under System Settings → Privacy & Security, then restart DockVault. Your files and settings are not affected.';
      return 'Your system stopped the sync helper from starting — a security policy or a missing execute permission. Allow it, then restart DockVault. Your files and settings are not affected.';
    default:
      return "DockVault couldn't start its sync helper. Restart DockVault; if this keeps happening, reinstall it by running the installer again to repair the helper. Your files and settings are not affected.";
  }
}

// Under the app-lock the glance LEADS with "Locked" — the security state the person chose — and APPENDS the
// sync truth from the per-vault breakdown, so it never reads a bare "Paused" implying sync stopped: a vault on
// this computer's own device identity keeps syncing under the lock while the account path is paused. Faces:
// "Locked · waiting to reconnect" when offline (nothing can sync); "Locked · syncing N vaults" while device
// vaults transfer; "Locked · N vaults paused while locked" when the lock is holding account-path vaults;
// "Locked · up to date" when every vault is up to date; plain "Locked" when every configured vault is paused
// by the lock (or nothing more specific is true).
function lockedGlance(model, lockReason) {
  const vs = Array.isArray(model && model.vaults) ? model.vaults : [];
  // A machine woken from sleep does NOT auto-resume the account tier on mere input (unlike an idle lock, and
  // unlike an OS-screen lock which resumes on the unlock-screen): the desktop is unlocked but sync stays
  // paused until Resume. Say exactly that — never a bare "Locked" glance on a visibly-unlocked desktop.
  if (lockReason === 'sleep') return 'Sync paused since sleep — Resume sync to continue';
  if (model && model.online === false) return 'Locked · waiting to reconnect';                     // offline: don't claim progress or up-to-date
  const total = vs.length;
  const syncing = vs.filter((v) => v.state === STATE.SYNCING).length;
  if (syncing > 0) return `Locked · syncing ${syncing} ${syncing === 1 ? 'vault' : 'vaults'}`;
  const pausedLocked = vs.filter((v) => v.state === STATE.PAUSED && v.reason === 'locked').length;
  if (total > 0 && pausedLocked === total) return 'Locked';                                        // every vault paused by the lock
  if (pausedLocked > 0) return `Locked · ${pausedLocked} ${pausedLocked === 1 ? 'vault' : 'vaults'} paused while locked`;
  const upToDate = vs.filter((v) => v.state === STATE.UP_TO_DATE).length;
  if (total > 0 && upToDate === total) return 'Locked · up to date';                              // device vaults, all up to date
  return 'Locked';                                                                                 // mixed — lead with the lock, don't overclaim
}

// The glance has two extra inputs and they arrive in ONE options object, not a positional tail:
// { server } is which server is in force (the installable build), { lockReason } is why the account tier
// is paused (device sync). A fourth and fifth positional slot is exactly the shape that made this
// function collide in the first place, so the object is deliberate — callers name what they pass.
function tooltip(model, lockPhase, pinned, options = {}) {
  const { server = null, lockReason = null } = options || {};
  // With no server in force nothing below can be true — not even the lock — so the glance says that
  // rather than a name with nothing behind it.
  if (server && !server.origin) return 'DockVault — Not connected';
  if (lockPhase === 'locking') return 'DockVault — Locking…';
  if (lockPhase === 'lock-error') return 'DockVault — Lock error (retrying)';
  if (model.condition === 'unavailable') return 'DockVault — Sync unavailable';
  if (model.condition === 'not-configured') return 'DockVault';
  if (model.state === STATE.PAUSED && model.reason === 'locked') return 'DockVault — ' + lockedGlance(model, lockReason);
  // A persistent no-sync is a must-act, but its glance reads by duration, not alarm (it is usually a
  // connection or sign-in issue). Keep the calm phrasing rather than the bare "Sync problem" label.
  if (model.state === STATE.SYNC_PROBLEM && model.reason === 'not-syncing') return "DockVault — Sync hasn't run for a while";
  // The sync helper (rclone) isn't ready — override the generic "Sync problem" label with the honest helper
  // phrasing + the per-sub detail. `pinned` is supplied by main (the app's pinned version) for version-mismatch.
  if (model.state === STATE.SYNC_PROBLEM && model.reason === 'helper-not-ready') return "DockVault — The sync helper isn't ready · " + helperDetail(model.sub, model.installed, pinned);
  // While transferring, show the honest count detail ("Syncing… · 3 files · 4.2 MB") — numbers only, no
  // percentage and no total implied, from the aggregate counts the daemon parsed.
  if (model.state === STATE.SYNCING) {
    const d = progressDetail(model.progress);
    return 'DockVault — ' + model.label + (d ? ' · ' + d : '');
  }
  const detail = REASON_DETAIL[model.reason];
  return 'DockVault — ' + model.label + (detail ? ' · ' + detail : '');
}

// The action kinds the app can actually perform today. Every item this module emits MUST use one of
// these, so a label never promises a door the app cannot open: the first four have their own handler
// (restart the helper, make the folder private again, a zero-loss repair, the helper how-to); the rest
// open the app, where the person completes the step themselves. A device-sync step the app cannot yet
// perform in-app (prove a vault password once more; set this computer up again) is therefore an 'open'
// with copy that states the fact — a dedicated kind lands together with its flow.
const HANDLED_ACTION_KINDS = Object.freeze([
  'restart', 'recover-folder', 'repair', 'setup-helper',
  'open', 'reopen', 'review', 'sign-in', 'unlock', 'check-identity', 'choose-folder', 'reset-device', 'set-up-again',
]);

// The vault's display NAME for a label, resolved from the caller's id→name map (the configured list). The
// model is keyed by vault id, so without this every label would show the raw UUID; a missing name falls back
// to the id, never blank or "undefined". nameById may be a function or a plain {id:name} object.
function displayName(v, nameById) {
  const n = typeof nameById === 'function' ? nameById(v.vault)
    : (nameById && typeof nameById === 'object' ? nameById[v.vault] : undefined);
  return (typeof n === 'string' && n) ? n : v.vault;
}

// One reachable action per unresolved item. `kind` is the stable action the tray layer wires to a handler;
// `label` is the (provisional) menu text with the vault's NAME; `vault` stays the vault ID the handler acts on.
function itemForVault(v, nameById) {
  const name = displayName(v, nameById);
  switch (v.reason) {
    case 'conflict-keep-both': return { kind: 'review', vault: v.vault, label: `Review conflicting copies in ${name}` };
    case 'sign-in-needed': return { kind: 'sign-in', vault: v.vault, label: `Sign in to keep ${name} syncing` };
    case 'needs-unlock': return { kind: 'unlock', vault: v.vault, label: `Unlock ${name} to sync it` };
    case 'needs-repair':
    case 'confirm-large-delete': return { kind: 'repair', vault: v.vault, label: `Repair sync for ${name}` };
    case 'path-too-long': return { kind: 'repair', vault: v.vault, label: `A file in ${name} needs a shorter path` };
    case 'host-key-mismatch': return { kind: 'check-identity', vault: v.vault, label: `Check ${name}: the server identity changed` };
    case 'vault-unavailable': return { kind: 'open', vault: v.vault, label: `${name} can't sync right now — it may have been changed or removed` };
    case 'not-syncing': return { kind: 'open', vault: v.vault, label: `${name} hasn't synced for a while — check your connection` };
    case 'folder-problem': return { kind: 'recover-folder', vault: v.vault, label: `The sync folder for ${name} is shared again — make it private` };
    case 'folder-insecure':
    case 'folder-rejected': return { kind: 'choose-folder', vault: v.vault, label: `The sync folder for ${name} can't be used — choose a folder again` };
    // A code fault in our OWN sync path — own it plainly so the person doesn't go hunting their own
    // connection/sign-in/keychain for a fault only we can fix. (A "Report a problem" action is a follow-up.)
    case 'sync-error': return { kind: 'open', vault: v.vault, label: "Something in DockVault's own sync step failed — this is on our side, not your connection or sign-in." };
    // Device sync: this computer's identity and its per-vault access. Each is its own line with its own next step;
    // an account problem is named as the account's, never as this computer's fault. (Copy provisional.)
    case 'grant-needs-reproof': return { kind: 'open', vault: v.vault, label: `${name}'s password changed — this computer needs it entered once more before it can keep syncing` };
    case 'device-revoked': return { kind: 'set-up-again', vault: v.vault, label: `This computer was removed from your synced computers — set it up again to keep syncing here` };
    case 'device-expired': return { kind: 'set-up-again', vault: v.vault, label: `This computer's sync access has expired — set it up again to keep syncing here` };
    case 'device-suspended': return { kind: 'open', vault: v.vault, label: `Syncing on this computer is paused by your server pending the owner's review` };
    case 'device-not-recognized': return { kind: 'set-up-again', vault: v.vault, label: `Your server no longer recognises this computer — set it up again to keep syncing here` };
    case 'account-inactive': return { kind: 'open', vault: v.vault, label: `Your DockVault account is locked — syncing resumes when it's active again` };
    case 'grant-withdrawn': return { kind: 'open', vault: v.vault, label: `This computer isn't set up to sync ${name} any more` };
    case 'vault-not-standard': return { kind: 'open', vault: v.vault, label: `${name} is end-to-end encrypted, so it stays on the web — only Standard vaults sync here` };
    case 'device-cred-cap': return { kind: 'open', vault: v.vault, label: `${name} can't sync yet: this computer has reached your server's sync-credential limit — try again in a while` };
    case 'device-refused': return { kind: 'open', vault: v.vault, label: `${name} couldn't sync — your server refused this computer. Open DockVault.` };
    default: return { kind: 'open', vault: v.vault, label: `Sync problem with ${name}` };
  }
}

function mustActItems(model, nameById) {
  const items = [];
  if (model.condition != null) return items; // unavailable / not-configured: nothing to act on here
  // A stuck helper (crash-looped OR a persistent per-vault down-helper escalation) is ONE global restart. Surface
  // it whenever the aggregate is sync-stopped OR ANY vault escalated to it — NOT only when it wins the aggregate,
  // or a co-present rank-6 vault (a host-key alert, say) ordered first would steal the glance and DROP the restart
  // for a wedged helper that blocks all sync. The per-vault loop below suppresses the (subsumed) per-vault items.
  if (model.reason === 'sync-stopped' || model.vaults.some((v) => v.reason === 'sync-stopped')) {
    items.push({ kind: 'restart', label: 'Restart sync' });
  }
  // The saved state can't be unlocked on this machine. Give the real, NON-destructive next step available
  // now (no dedicated button needed): unlock the login keychain and reopen. Clicking opens the app (the
  // "reopen" half); the deliberate "Reset sync state" is a follow-up, appended to this copy only when it ships.
  if (model.state === STATE.SYNC_PROBLEM && model.reason === 'state-unreadable') {
    items.push({ kind: 'reopen', label: "The saved sync state can't be unlocked on this machine — your files are safe and sync is paused. Try unlocking your login keychain and reopening DockVault." });
  }
  // The sync helper (rclone) isn't ready — an APP-scoped problem (one shared binary), so it surfaces as ONE
  // must-act with the "Set up the sync helper" fix even if several vaults hit it, carrying the sub/installed
  // for the per-sub notification detail. The per-vault loop below skips these so it is never duplicated.
  const hnr = model.vaults.find((v) => v.state === STATE.SYNC_PROBLEM && v.reason === 'helper-not-ready');
  if (hnr) items.push({ kind: 'setup-helper', label: 'How to fix the sync helper', sub: hnr.sub || null, installed: hnr.installed || null });
  for (const v of model.vaults) {
    if (v.reason === 'helper-not-ready') continue; // handled once, app-scoped, above
    if (v.reason === 'sync-stopped') continue; // a global down-helper condition — handled once as the restart above
    if (v.state === STATE.NEEDS_DECISION || v.state === STATE.SYNC_PROBLEM) items.push(itemForVault(v, nameById));
  }
  // The device-ended states are IDENTITY-wide (every configured vault reports the same removal/expiry), so
  // their set-up-again offer collapses to a SINGLE line — one re-registration fixes them all — rather than
  // one identical line per vault.
  const firstSetupAgain = items.findIndex((it) => it.kind === 'set-up-again');
  if (firstSetupAgain !== -1) return items.filter((it, i) => it.kind !== 'set-up-again' || i === firstSetupAgain);
  return items;
}

// Calm "finish setting up on this computer" to-dos for vaults whose device grant is pending — a deferred setup
// (finish it) or a password re-proof after a change (keep syncing it), told apart by whether the vault was ever
// granted. kind 'open': the door opens the app to that vault, where opening it proves the password once and the
// resume sweep completes the grant. Suppressed for a vault that already has its own must-act line — a real sync
// problem outranks a calm setup nudge — so the caller passes alreadyShown for the ids it already surfaced.
function pendingSetupItems(pendingVaultIds, opts = {}) {
  const nameById = opts.nameById;
  const wasGranted = typeof opts.wasGranted === 'function' ? opts.wasGranted : () => false;
  const alreadyShown = typeof opts.alreadyShown === 'function' ? opts.alreadyShown : () => false;
  const out = [];
  for (const vaultId of (Array.isArray(pendingVaultIds) ? pendingVaultIds : [])) {
    if (!vaultId || alreadyShown(vaultId)) continue;
    const name = displayName({ vault: vaultId }, nameById);
    // A vault granted before is a re-proof: its password changed on the server, so the person must open it with
    // the NEW password. A never-granted vault is a first setup: any open finishes it.
    const label = wasGranted(vaultId)
      ? `Open ${name} with its new password to keep syncing it on this computer`
      : `Open ${name} once to finish setting it up on this computer`;
    out.push({ kind: 'open', vault: vaultId, label });
  }
  return out;
}

// The escape hatch: a device identity that has read UNREADABLE (a locked/rotated keychain, a torn blob) for
// long enough that it is not going to clear on its own. One global reset offer — forget this computer's
// identity and set it up again — distinct from, and shown only after, the calm 'device-identity-unreadable'
// paused glance that precedes it. kind 'reset-device' runs the forget itself (not an 'open'), so the caller
// wires it to a confirmed reset; never auto-fires.
function deviceResetItem() {
  return { kind: 'reset-device', label: "This computer's sync identity can't be read — reset it to set this computer up again" };
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

// The one notification an installed app shows on its first launch: it is BOTH the "something happened"
// after a silent one-click install and the disclosure that a login item now exists, with where to turn
// it off. No promise about syncing — nothing is set up yet. (When a first-run server screen exists, the
// body should instead point at it: "Set up your server to start syncing — click to begin.")
// `registered` is the READ-BACK after registering, not the intent: a platform that refuses without
// throwing (a policy blocking the Run key) gets the honest variant, which points at the switch instead.
function installedNotification(platform, registered = true) {
  const signIn = platform === 'win32' ? 'sign in to Windows' : platform === 'darwin' ? 'log in to your Mac' : 'log in';
  const body = registered === true
    ? `It starts when you ${signIn}. You can turn that off in the tray menu.`
    : `Turn on Start at login in the tray menu if you want it to start when you ${signIn}.`;
  return { title: 'DockVault is installed and running in the tray', body };
}

// The tray's "Start at login" checkbox. `enabled` MUST be the platform's real registration read at menu-build
// time (login-item.js isEnabled), never a remembered preference, so the box can never disagree with the machine.
function loginItemMenu(enabled) {
  return { label: 'Start at login', type: 'checkbox', checked: enabled === true };
}

// The tray's view of which server is in force, from server-config's state: a saved setting that the
// DOCKVAULT_SERVER variable silently overrode would be a lie, so when the two differ (or the saved one
// cannot be read while the variable is set) the menu says so. "Change server…" is offered whenever a
// server is in force; with none, the setup screen is what opening the app shows anyway.
function serverMenuItems(state) {
  const items = [];
  if (!state) return items;
  if (state.status === 'env') {
    // The variable is a development override that wins over anything saved: a change made here would be
    // saved and then ignored, so the menu only says what is in force.
    if (state.envOverrides) items.push({ kind: 'server-note', label: 'Using DOCKVAULT_SERVER override', enabled: false });
    return items;
  }
  if (state.origin) items.push({ kind: 'change-server', label: 'Change server…' });
  else items.push({ kind: 'setup-server', label: 'Set up server…' }); // reopens the setup screen; never a blank state
  return items;
}

// The consent before a server change: the device, the session, the grants, and the sync setup all
// belong to the old server, so the change is a relationship end and says so. Files stay.
function changeServerConsent(host) {
  return {
    title: 'Switch to a different server?',
    message: `Switching servers signs you out and removes this computer from sync on ${host || 'the current server'}. Files already synced stay in their folders.`,
    buttons: ['Cancel', 'Switch server'],
  };
}

module.exports = { tooltip, lockedGlance, mustActItems, itemForVault, pendingSetupItems, deviceResetItem, syncNowItem, lastSyncedLabel, vaultRows, formatBytes, progressDetail, helperDetail, REASON_DETAIL, HANDLED_ACTION_KINDS, helperRemedy, setPackaged, installedNotification, loginItemMenu, serverMenuItems, changeServerConsent };

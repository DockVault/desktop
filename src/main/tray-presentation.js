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
  // The sync server (the SFTP address) can't be reached, or what answers there isn't a sync server. Worded so it
  // reads honestly whether calm (a laptop that woke before its network) or, once it persists, a must-act.
  'sync-server-unreachable': "the sync server can't be reached right now",
  // The server answered and refused this computer's sync connection (a turned-away credential, or no session
  // slot free). A wait, not an action: DockVault is already spacing out its tries. The tooltip is cut at about
  // 127 characters on Windows, so the WAIT and the "don't go deactivating credentials" part live on the menu
  // item's fuller sentence; this stays the short glance.
  'sync-server-refusing': 'the server is limiting sync attempts for now',
  // The server said it had no room for a file. Nothing on this computer to fix, and it may have room later.
  'server-no-space': 'the sync server has no free space for new files right now',
  'sync-server-unverified': "what's at that address isn't answering as a sync server",
  // The saved sync state exists but cannot be unlocked/opened on this machine. Lead with reassurance —
  // the person's actual files are never touched by this — because a bare "sync problem" over an unreadable
  // database could read as data loss. (The deliberate reset that clears it is a fast-follow.)
  'state-unreadable': "the saved state can't be unlocked here — your files are safe",
  // A sync step failed in our own code path (an unclassified internal error, or a credential provider that
  // threw) rather than a connection/sign-in issue. Honest and non-alarming; not retried forever.
  'sync-error': 'a sync step hit a problem',
  // Nothing here could work out what went wrong. Say that, rather than leave the glance as the bare label.
  'error': "the reason couldn't be identified — it will keep trying",
  // A file did not land on the server. Short here (the tooltip is cut at about 127 characters on Windows);
  // the fuller sentence — WHICH file, the size the server stated, the room the vault has left — is composed
  // by reasonSentence from the outcome's detail and shown on the menu item and the Computers card.
  'file-too-large': 'a file is larger than the sync server will accept',
  'vault-full': "this vault doesn't have room for a file",
  'upload-not-stored': "the sync server didn't keep a file it accepted",
  // The folder is known by its marker: these say why it cannot be synced right now (the must-act line says what to do).
  // (Short: the tray tooltip is cut at about 127 characters on Windows.)
  'folder-missing': "its folder isn't where it was — moved, deleted, or on a drive that isn't plugged in",
  'folder-marker-missing': 'a different folder is now where its folder was',
  'folder-other-vault': "another vault's folder is now where its folder was",
  'folder-marker-unreadable': "its folder's hidden marker file can't be read",
  'folder-ambiguous': 'two or more folders look like its folder — a copy was made',
  'folder-moved-rejected': "its folder was moved somewhere DockVault doesn't sync",
  'folder-found-elsewhere': 'a folder that looks like its folder was found elsewhere — confirm it first',
  'folder-marker-unwritable': "its folder won't let DockVault write its marker file",
  'config-unwritable': "the sync settings couldn't be saved",
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

// The transfer detail from the numbers the helper parsed out of rclone's stats: the percentage when rclone
// states one, what has moved of what is queued ("4.2 MB of 9.1 MB", "3 of 8 files"), or just what has moved so
// far when no total is known yet. Numbers only — never a path.
function progressDetail(progress) {
  if (!progress) return null;
  const parts = [];
  if (Number.isInteger(progress.percent) && progress.percent >= 0 && progress.percent <= 100) parts.push(`${progress.percent}%`);
  const f = progress.files; const ft = progress.filesTotal;
  if (typeof f === 'number' && typeof ft === 'number' && ft > 0) parts.push(`${f} of ${ft} ${ft === 1 ? 'file' : 'files'}`);
  else if (typeof f === 'number' && f > 0) parts.push(f === 1 ? '1 file' : `${f} files`);
  const b = formatBytes(progress.bytes);
  const t = formatBytes(progress.bytesTotal);
  if (b && t) parts.push(`${b} of ${t}`); else if (b) parts.push(b);
  return parts.length ? parts.join(' · ') : null;
}

// A wait in words a person can act on: whole seconds under a minute and a half, else whole minutes rounded up.
// Defined here, with the rest of the human copy, so the tray glance, the Computers card and the "Sync now"
// toast all say a wait the same way — one phrasing, one rounding, no surface saying "2 minutes" while another
// says "in about 90 seconds" for the same instant.
function waitWords(ms) {
  const sec = Math.max(1, Math.ceil((Number(ms) || 0) / 1000));
  if (sec < 90) return sec === 1 ? '1 second' : `${sec} seconds`;
  const min = Math.ceil(sec / 60);
  return `about ${min === 1 ? '1 minute' : `${min} minutes`}`;
}

// The wait until an absolute time, in words — or null when there is no time, or it has already passed. A wait
// that has lapsed says NOTHING rather than "0 seconds": the next tick is what will actually try again, and a
// promise about a moment already gone is worse than no promise.
function waitUntilWords(retryAt, now) {
  if (typeof retryAt !== 'number' || !Number.isFinite(retryAt)) return null;
  const left = retryAt - (typeof now === 'number' ? now : Date.now());
  return left > 0 ? waitWords(left) : null;
}

// A file's name as it may appear in a sentence, or null. The name arrives already bounded and checked twice
// (the helper builds a BASE name only and re-checks it as it leaves; the main process re-checks it as it
// arrives). This is the same check once more at the place it would actually be RENDERED — deliberately
// IDENTICAL to those, since a backstop weaker than the check it backs up is not a backstop. It rejects
// direction-overriding and zero-width characters too: a name can come from the remote side of a shared
// vault, and one that reverses the text around it must never reach a menu. Quoted, so a name with spaces
// reads as one thing.
const RENDERABLE_NAME = /^(?!\.\.?$)[^\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff\\/:*?"<>|]{1,80}$/;
function fileWord(detail) {
  const f = detail && typeof detail.file === 'string' ? detail.file : null;
  return f && RENDERABLE_NAME.test(f) ? `“${f}”` : null;
}
// A byte count from a detail, in words, or null — the same formatting as everywhere else in the app.
function sizeWord(n) { return formatBytes(typeof n === 'number' && Number.isFinite(n) ? n : 0); }

/*
 * WHERE A PERSON IS SENT WHEN A SYNC NEEDS THEM. One phrase, one place, because it was previously written
 * out by hand in three files and said the wrong thing in all of them.
 *
 * "Open DockVault" is what those messages used to say, and it names the wrong window. To the person using it,
 * DockVault IS the files app — so "Open DockVault" means the file browser, which is exactly where the tray's
 * own `Open DockVault` item takes them. Nothing in that window can repair a sync, tell them which folder is
 * missing, or stop syncing a vault. A notification saying a folder "can't sync until its folder is fixed —
 * Open DockVault to sort it out" therefore sent someone to a screen with no trace of the problem it had just
 * told them about, and left them to find the tray on their own.
 *
 * Everything that can actually be acted on lives in ONE place — the tray menu's "Computers & synced folders",
 * where every vault has a card showing its state and what to do about it. So that is what these sentences
 * name, in the words the menu itself uses, so the instruction and the thing being pointed at read the same.
 *
 * MANAGE_ITEM is kept identical to the tray item's own label on purpose: a test asserts they match, because
 * an instruction that names a menu entry which no longer exists is worse than a vague one.
 */
const MANAGE_ITEM = 'Computers & synced folders';

/**
 * Which window a must-act item opens when it has no action of its own.
 *
 * Split out from the shell so it can be ASKED rather than read. The bug this exists to prevent was not in the
 * words — it was that every unhandled kind fell through to the file browser, so "needs attention" opened a
 * screen with no mention of the vault, the problem, or any way to act on it. A test over source text could not
 * have seen that; it is a fallthrough, not a statement.
 *
 * 'manage' is the default for a SYNC problem, because Computers & synced folders is where a vault's card,
 * state and remedies are. 'window' is only for the things that genuinely live in the vault's own web
 * interface: signing in, unlocking an end-to-end encrypted vault, and reviewing conflicting copies — which are
 * files, and which the Computers view has no surface for.
 *
 * @param {string} kind  a HANDLED_ACTION_KINDS value
 * @returns {'manage'|'window'} which door to open
 */
function destinationFor(kind) {
  return (kind === 'review' || kind === 'sign-in' || kind === 'unlock' || kind === 'check-identity' || kind === 'reopen')
    ? 'window'
    : 'manage';
}

/**
 * The FULL, plain-English sentence for the reasons whose honest answer needs more than a label: the ones that
 * can name a file, a size the server stated, the room a vault has left, or how long a wait is. It is the ONE
 * place that copy lives, so the tray menu item, the notification body and the Computers card cannot tell three
 * different stories about the same failure.
 *
 * Every branch is written to the same rule: say the specific thing ONLY from a value that is actually present,
 * and otherwise fall back within the same sentence to the true, less specific form. So a missing file name
 * yields "a file", a missing limit drops the "(max …)", a lapsed wait drops the "in about …" — and nothing is
 * ever invented to fill a gap. Returns null for a reason with no enriched sentence, leaving the caller's own
 * table to answer.
 *
 * @param {string} reason         the vault's symbolic reason
 * @param {object} [opts]
 * @param {string} [opts.name]    the vault's display name
 * @param {object} [opts.detail]  the outcome detail ({ file, maxBytes, limitBytes, freeBytes })
 * @param {number} [opts.retryAt] when the back-off will next let an attempt through
 * @param {number} [opts.now]     the clock, injectable for tests
 * @returns {string|null}
 */
function reasonSentence(reason, opts = {}) {
  const name = (opts && typeof opts.name === 'string' && opts.name) ? opts.name : 'This vault';
  const d = (opts && opts.detail && typeof opts.detail === 'object') ? opts.detail : null;
  const file = fileWord(d);
  const wait = waitUntilWords(opts && opts.retryAt, opts && opts.now);
  // Whether a REPAIR is owed decides how every one of these sentences must end. A file the server would not
  // take makes the sync abort, so nothing more will transfer until a person runs the repair — and a sentence
  // that ends "everything else keeps syncing" or "DockVault will try again" would then be simply untrue, for
  // the whole time the person is looking at it. So the promise is made only when it holds, and when it does
  // not, the sentence says what will actually get the vault moving again.
  const repairOwed = !!(opts && opts.repairOwed);
  // Two shapes of the same clause: one that follows an INSTRUCTION ("Take it out of the folder. Then use
  // Repair…") and one that follows a plain STATEMENT, where a "Then" would imply a sequence that isn't there.
  const useRepair = ` Use Repair in the DockVault tray menu to start ${name} syncing again.`;
  const thenRepair = ` Then use Repair in the DockVault tray menu to start ${name} syncing again.`;
  switch (reason) {
    // The vault's own allowance — and it is only ever said when the server's own numbers said so
    // (vault-space.js). Two shapes, and which is true decides the wording: an allowance entirely spent is
    // "out of space"; an allowance with room left that is simply smaller than the file is NOT (saying "out of
    // space … 1 MB is free" in one breath contradicts itself), so that one says what is actually wrong.
    case 'vault-full': {
      const limit = sizeWord(d && d.limitBytes);
      const free = sizeWord(d && d.freeBytes);
      const size = sizeWord(d && d.bytes);
      const ofLimit = (limit && limit !== free) ? ` of ${limit}` : '';   // "1 MB free of 1 MB" reads as a mistake
      const fix = `Remove something from the vault, or raise its size limit.${repairOwed ? thenRepair : ` Syncing continues on its own once ${name} has room.`}`;
      if (size && file && free) return `${name} doesn't have room for ${file}: it needs ${size}, and only ${free} is free${ofLimit}. ${fix}`;
      return `${name} is out of space.${limit ? ` It has used all ${limit} of its allowance.` : ''} ${fix}`;
    }
    // One file is bigger than the server will take. Nothing is wrong with the sync or the account, and no wait
    // will change it — so the sentence names the file, the maximum the server ITSELF stated (never a guessed
    // one), and the only two things that resolve it.
    case 'file-too-large': {
      const max = sizeWord(d && d.maxBytes);
      const what = file || 'A file';
      return `${what} in ${name} is larger than the sync server accepts${max ? ` (max ${max})` : ''}. Take it out of the folder or make it smaller.${repairOwed ? thenRepair : ' Everything else keeps syncing.'}`;
    }
    // The bytes went up and the file was not there afterwards, and the reason is NOT knowable from here: the
    // door decides whether to keep an upload after the transfer, and this protocol gives that decision no way
    // to report itself. So this says exactly what is known and no more — never a guessed cause — while adding
    // the vault's remaining room when the numbers were readable, since that is often the answer.
    case 'upload-not-stored': {
      const free = sizeWord(d && d.freeBytes);
      const limit = sizeWord(d && d.limitBytes);
      const room = free && limit ? ` ${name} has ${free} free of ${limit}.` : '';
      const next = repairOwed
        ? ` Your copy on this computer is untouched.${useRepair}`
        : ' Your copy on this computer is untouched, and DockVault will try again.';
      return `The sync server accepted ${file || 'a file'} from ${name} and then didn't keep it.${next}${room}`;
    }
    // The server said it had no room. Its side, not this computer's, and it may well have room later — so it
    // asks nothing of the person beyond the repair, if the failed run left one owed.
    case 'server-no-space':
      return `The sync server has no free space to take new files from ${name} right now. Nothing here was lost.${repairOwed ? useRepair : ' DockVault will keep trying.'}`;
    // The server is turning this computer's sync connections away — a limit it is applying, or no session slot
    // free. It clears ITSELF, so the sentence gives the wait and, pointedly, the two remedies people reach for
    // and that do NOT help here: this is not an account matter and not a stale-credential matter, so anyone
    // told to sign in or to go deactivating credentials would be sent to do harmless, useless work.
    case 'sync-server-refusing':
      return `The sync server is temporarily limiting sync attempts from this computer for ${name}. It will try again on its own${wait ? ` in ${wait}` : ''} — signing in again or deactivating credentials won't help.`;
    default: return null;
  }
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
  const { server = null, lockReason = null, now = null } = options || {};
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
  // The rate-limit glance carries its WAIT, because "it will try again on its own" is only half an answer
  // without when. The rest of that sentence (that signing in and deactivating credentials do not help) is too
  // long for a tooltip and lives on the menu item, which is one click away. A lapsed wait simply drops.
  const wait = model.reason === 'sync-server-refusing' ? waitUntilWords(model.retryAt, now) : null;
  return 'DockVault — ' + model.label + (detail ? ' · ' + detail : '') + (wait ? ` (retrying in ${wait})` : '');
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
  'relocate-folder', 'troubleshoot',
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
function itemForVault(v, nameById, opts = {}) {
  const name = displayName(v, nameById);
  // The reasons that can name a file, a stated size, the room left, or a wait get their full sentence from the
  // ONE copy source, composed from THIS vault's own outcome detail. The switch below still owns everything
  // else, so adding a rich reason never silently changes an existing label.
  const rich = reasonSentence(v.reason, { name, detail: v.detail, retryAt: v.retryAt, now: opts && opts.now, repairOwed: !!v.resyncRequired });
  if (rich) return { kind: RICH_ACTION[v.reason] || 'open', vault: v.vault, label: rich };
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
    // The sync server itself, not the account: the address can't be reached, or what answers there is not a sync
    // server. Both open Troubleshoot, whose connection check tests the saved server and SFTP address separately.
    case 'sync-server-unreachable': return { kind: 'troubleshoot', vault: v.vault, label: `${name} can't sync — the sync server can't be reached` };
    case 'sync-server-unverified': return { kind: 'troubleshoot', vault: v.vault, label: `${name} can't sync — what's at the sync server address isn't a sync server` };
    case 'folder-problem': return { kind: 'recover-folder', vault: v.vault, label: `The sync folder for ${name} is shared again — make it private` };
    case 'folder-insecure':
    case 'folder-rejected': return { kind: 'choose-folder', vault: v.vault, label: `The sync folder for ${name} can't be used — choose a folder again` };
    // The folder is known by the marker it carries (folder-identity.js). Each way of losing it is said plainly,
    // and each opens the same relocate-or-stop offer; nothing syncs until the person answers.
    case 'folder-missing': return { kind: 'relocate-folder', vault: v.vault, label: `The folder for ${name} can't be found — find it, or stop syncing` };
    case 'folder-marker-missing': return { kind: 'relocate-folder', vault: v.vault, label: `A different folder is where ${name}'s was — find ${name}'s folder, or stop syncing` };
    case 'folder-other-vault': return { kind: 'relocate-folder', vault: v.vault, label: `Another vault's folder is where ${name}'s was — find ${name}'s folder, or stop syncing` };
    case 'folder-marker-unreadable': return { kind: 'relocate-folder', vault: v.vault, label: `${name}'s folder can't be recognised — find it, or stop syncing` };
    case 'folder-ambiguous': return { kind: 'relocate-folder', vault: v.vault, label: `Two or more folders look like ${name}'s — choose which one to sync` };
    case 'folder-moved-rejected': return { kind: 'relocate-folder', vault: v.vault, label: `${name}'s folder was moved somewhere DockVault can't sync — move it, then find it` };
    case 'folder-found-elsewhere': return { kind: 'relocate-folder', vault: v.vault, label: `A folder that looks like ${name}'s was found — confirm it, or stop syncing` };
    case 'folder-marker-unwritable': return { kind: 'relocate-folder', vault: v.vault, label: `${name}'s folder won't let DockVault write its marker file — check the folder, or stop syncing` };
    case 'config-unwritable': return { kind: 'open', vault: v.vault, label: `${name}'s sync settings couldn't be saved — unlock your login keychain, then quit DockVault and start it again` };
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
    case 'device-refused': return { kind: 'open', vault: v.vault, label: `${name} couldn't sync — your server refused this computer` };
    // 'error' is the honest name for a run that failed in a way NOTHING here could identify — not the server
    // turning this computer away, not a file, not the account, not the folder. Say exactly that, and say what
    // is being done about it, rather than a bare "sync problem" that leaves a person guessing at their own
    // account, connection, or files. Troubleshoot is the door because it is the one that actually tests
    // something (the server address and the SFTP address, separately, from this computer).
    case 'error':
      return { kind: 'troubleshoot', vault: v.vault, label: `${name} couldn't sync and DockVault couldn't tell why. Nothing here was changed; it will keep trying. Run Troubleshoot to check the server.` };
    // A reason with no line of its own. It is a bug for this to be reached — every reason the app can produce
    // is answered above — so it must never leak the symbol itself into a menu: an internal token in front of a
    // person is worse than an honest admission that this one has no words yet.
    default:
      return { kind: 'open', vault: v.vault, label: `${name} needs attention — open its card to see what's wrong` };
  }
}

// Which door each rich-sentence reason opens. A full vault and an oversized file are resolved in the vault
// itself (open the app); the two the server owns are worth a Troubleshoot look, which tests the server and the
// SFTP address separately from this computer. Every value here MUST be in HANDLED_ACTION_KINDS.
// Which door each rich-sentence reason opens. All of them open the app: what these need is done in the vault
// (free some room, take a file out of the folder) or is a wait, and the repair the sentence names is in the
// tray menu the person is already in. Deliberately NOT Troubleshoot: none of these sentences mentions it, and
// for a server that is answering and merely limiting attempts Troubleshoot would report everything fine —
// a door that contradicts the sentence that opened it is worse than no door. Every value MUST be in
// HANDLED_ACTION_KINDS.
const RICH_ACTION = Object.freeze({
  'vault-full': 'open',
  'file-too-large': 'open',
  'upload-not-stored': 'open',
  'server-no-space': 'open',
  'sync-server-refusing': 'open',
});

function mustActItems(model, nameById, opts = {}) {
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
    items.push({ kind: 'reopen', label: "The saved sync state can't be unlocked on this machine — your files are safe and sync is paused. Try unlocking your login keychain, then closing DockVault and starting it again." });
  }
  // The sync helper (rclone) isn't ready — an APP-scoped problem (one shared binary), so it surfaces as ONE
  // must-act with the "Set up the sync helper" fix even if several vaults hit it, carrying the sub/installed
  // for the per-sub notification detail. The per-vault loop below skips these so it is never duplicated.
  const hnr = model.vaults.find((v) => v.state === STATE.SYNC_PROBLEM && v.reason === 'helper-not-ready');
  if (hnr) items.push({ kind: 'setup-helper', label: 'How to fix the sync helper', sub: hnr.sub || null, installed: hnr.installed || null });
  for (const v of model.vaults) {
    if (v.reason === 'helper-not-ready') continue; // handled once, app-scoped, above
    if (v.reason === 'sync-stopped') continue; // a global down-helper condition — handled once as the restart above
    if (v.state === STATE.NEEDS_DECISION || v.state === STATE.SYNC_PROBLEM) items.push(itemForVault(v, nameById, opts));
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
/**
 * The "Start at login" switch, as the machine really has it.
 *
 * A PORTABLE RUN GETS IT DISABLED, WITH THE REASON IN THE LABEL. The write guard that keeps a portable copy
 * from touching the registration is correct and stays — but on its own it made this box a control that does
 * nothing: a person clicked it, the click was refused, the tick never appeared, and nothing said why. Worse
 * than that, the click still left a `login-item.json` behind in the portable data folder saying
 * `{"startAtLogin":true}`, so the app had a record of a preference it had deliberately not honoured.
 *
 * Not hidden, because the absence of a switch someone has used before reads as a bug or a missing feature.
 * Disabled with a reason answers the question instead of raising it.
 *
 * @param {boolean} enabled     whether the OS really has a registration for this app
 * @param {boolean} [isPortable] a portable run cannot own one
 */
function loginItemMenu(enabled, isPortable = false) {
  if (isPortable) {
    return {
      label: 'Start at login — not for a portable copy',
      type: 'checkbox',
      checked: false,
      enabled: false,
    };
  }
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

module.exports = { tooltip, lockedGlance, mustActItems, itemForVault, reasonSentence, destinationFor, MANAGE_ITEM, waitWords, waitUntilWords, pendingSetupItems, deviceResetItem, syncNowItem, lastSyncedLabel, formatBytes, progressDetail, helperDetail, REASON_DETAIL, HANDLED_ACTION_KINDS, helperRemedy, setPackaged, installedNotification, loginItemMenu, serverMenuItems, changeServerConsent };

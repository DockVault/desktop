'use strict';

/*
 * Human copy for the enable-sync flow, kept in one place so the wording is consistent and reviewable.
 * Every refusal says plainly what to do next and never blames the person; the cloud-storage case is a
 * strong warning the person can still override; the consent line states plainly that readable copies
 * land on the computer.
 */

// Refusal reasons (from the folder classifier) → a short, non-blaming, actionable sentence.
const REFUSE_COPY = Object.freeze({
  'filesystem-root': "That's a whole drive. Pick a folder inside it instead, like a folder in Documents.",
  'home-root-or-above': "That's your whole home folder — pick a folder inside it instead, like Documents.",
  'app-data-dir': 'That folder belongs to DockVault. Pick a folder of your own.',
  'system-location': "That's a system folder. Pick a folder in your own space, like Documents.",
  'overlaps-another-sync': 'Another vault already syncs to that folder (or one inside it). Pick a separate folder — two vaults sharing a folder would overwrite each other.',
  'not-absolute': "That folder can't be used. Pick a folder on this computer.",
  'no-folder': 'No folder was chosen.',
});

function refuseMessage(reason) {
  return REFUSE_COPY[reason] || "That folder can't be used for sync. Please pick another folder.";
}

// The consumer cloud-sync services worth naming in the warning, matched against the chosen path.
const CLOUD_SERVICES = Object.freeze([
  { re: /onedrive/i, name: 'OneDrive' },
  { re: /dropbox/i, name: 'Dropbox' },
  { re: /google ?drive/i, name: 'Google Drive' },
  { re: /icloud|clouddocs/i, name: 'iCloud Drive' },
]);

function cloudServiceName(p) {
  const s = String(p || '');
  for (const c of CLOUD_SERVICES) if (c.re.test(s)) return c.name;
  return 'a cloud storage app';
}

function cloudWarnMessage(service) {
  return `This folder is inside ${service}. Syncing here can cause conflicts because two apps would sync the same files. We recommend a folder outside your cloud storage.`;
}

// Two-way consent: this is a bidirectional sync, so the person must know BOTH directions — vault
// files are copied here readable, AND anything in this folder is uploaded into the (server-readable)
// vault. When the folder already holds files, say plainly that those existing files will be uploaded.
function consentMessage(vaultName, folder, opts = {}) {
  let m = `DockVault will sync ${vaultName} with ${folder} on this computer, both ways: files in your vault are kept here as readable copies, and files you put in this folder are uploaded into the vault.`;
  if (opts && opts.nonEmpty) m += ` ${folder} already contains files — those will be uploaded into ${vaultName}.`;
  return m;
}

// The one-time disclosure shown while setting this computer up for sync: the device path keeps running under
// the screen lock (decision-h, now true). Shown at the register step, not as a gate.
const LOCK_DISCLOSURE = 'This computer keeps syncing even when the screen is locked.';

// The reassurance every fail-soft device-step outcome shares: the vault's sync config is already saved, so it
// keeps syncing on the account session regardless of what the device step did — no result is ever a dead end.
const SYNCS_ON = 'keeps syncing using your account sign-in';
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

/**
 * Human copy for the result of the device step (runDeviceSetup). Returns { tone, message }:
 *   tone 'ok'      the vault is on its own device identity now (success);
 *   tone 'info'    a fail-soft outcome with nothing for the person to do — the vault syncs on the account session;
 *   tone 'todo'    the vault syncs on the account session AND there is a clear next step to move it onto this computer;
 *   tone 'sign-in' the person needs to sign in before anything can sync (the calm held wait, never an alarm).
 * Never blames the person, and never names a surface this version lacks (no "remove a computer" page, no link).
 * ctx.vaultName and ctx.otherServer fill in when the caller knows them; the copy reads cleanly without either.
 *
 * @param {{via:string, outcome:string, reason?:string, switched?:boolean}} result
 * @param {{vaultName?:string, otherServer?:string, hasPassword?:boolean}} [ctx]
 * @returns {{tone:'ok'|'info'|'todo'|'sign-in', message:string}}
 */
function deviceOutcomeCopy(result, ctx = {}) {
  const r = result || {};
  const vault = (ctx && ctx.vaultName) || 'this vault';
  const trailing = `It ${SYNCS_ON}.`; // a self-contained sentence; "it" = the vault, so no name is required

  switch (r.outcome) {
    case 'granted': {
      // Success says what happens now. The privacy fact — the vault's password was proven once and is not kept
      // anywhere — is worth a sentence only for a vault that HAS a password, and it is phrased as the reassurance
      // it is, never as something that "wasn't saved" (which reads like a failure under a green light).
      const pw = ctx && ctx.hasPassword ? ' Its password stays with you: DockVault used it once to set this up and does not keep it.' : '';
      return { tone: 'ok', message: `${cap(vault)} is set up to sync on this computer — on its own, even while DockVault or the screen is locked. The first sync starts now; the tray shows its status.${pw}` };
    }

    case 'granted-not-recorded':
      // The server grant SUCCEEDED (the vault is set up on this computer), but the local record write did not —
      // the OS secret store is full, locked, or refusing. Not a failure and not a dead end: it ${SYNCS_ON}
      // meanwhile and the details save on their own once the cause clears. Honest about the one thing the person
      // could act on (free up space / unlock the keychain), never blaming.
      return { tone: 'todo', message: `${cap(vault)} is set up to sync on this computer, but this computer couldn't save the setup details just now — its storage may be full or locked. It ${SYNCS_ON} meanwhile, and finishes saving on its own once that clears.` };

    case 'sign-in':
      return { tone: 'sign-in', message: `Sign in again to finish setting up sync — ${vault} will start syncing once you do.` };

    case 'grant-deferred':
      // The mechanism is opening the vault (its password is proven once from the unlock state), NOT typing a
      // password into a box — the resume sweep completes the grant on the next pass once the vault is open.
      return { tone: 'todo', message: `Almost there — open ${vault} once to finish setting it up on this computer. Until then, it ${SYNCS_ON}.` };

    case 'grant-failed':
      if (r.reason === 'wrong-password')
        return { tone: 'todo', message: `That password didn't match, so ${vault} isn't set up on this computer yet. ${trailing} Try again when you're ready.` };
      return { tone: 'info', message: `Couldn't finish setting up ${vault} on this computer. ${trailing} You can try again.` };

    case 'register-cancelled':
      return { tone: 'info', message: `No problem — this computer wasn't set up for sync. ${trailing}` };

    case 'switch-declined':
      return { tone: 'info', message: `Left as it is — this computer stays set up with its current server. ${trailing}` };

    case 'register-failed': {
      // `switched` means the forget already removed this computer from the other server (the ordering guarantee
      // in runDeviceSetup): say so, so the person isn't left thinking nothing changed.
      const other = (ctx && ctx.otherServer) || 'its previous server';
      const lead = r.switched ? `This computer is no longer set up with ${other}. ` : '';
      const why = r.reason === 'device-cap-reached'
        ? "You've reached this server's limit of synced computers, so it couldn't be added here."
        : "Setting up this computer for sync didn't finish.";
      return { tone: 'info', message: `${lead}${why} ${trailing} You can try again.` };
    }

    case 'account-only':
      switch (r.reason) {
        case 'server-too-old':
          return { tone: 'info', message: `This server doesn't support syncing individual computers yet. ${trailing}` };
        case 'no-secure-store':
          return { tone: 'info', message: `This computer can't store a sync key securely, so it can't sync on its own. ${trailing}` };
        case 'identity-stale':
          return { tone: 'info', message: `This computer's sync identity is being re-checked right now. ${trailing}` };
        case 'identity-unreadable':
          return { tone: 'info', message: `This computer's sync identity can't be read right now — this often clears on its own. ${trailing}` };
        case 'indeterminate':
        default:
          return { tone: 'info', message: `Couldn't check whether this computer can sync on its own right now. ${trailing} You can try again later.` };
      }

    default:
      // Defensive: an unmapped outcome fails closed to the benign, honest fallback — never a blank or a scary line.
      return { tone: 'info', message: `Sync is set up. ${trailing}` };
  }
}

module.exports = {
  refuseMessage, cloudServiceName, cloudWarnMessage, consentMessage, REFUSE_COPY,
  deviceOutcomeCopy, LOCK_DISCLOSURE,
};

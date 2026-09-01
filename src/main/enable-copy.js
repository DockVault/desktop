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

module.exports = { refuseMessage, cloudServiceName, cloudWarnMessage, consentMessage, REFUSE_COPY };

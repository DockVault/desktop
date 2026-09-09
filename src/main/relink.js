'use strict';

/*
 * WHAT A FOLDER HAS ALREADY BEEN USED FOR, decided before anything is written to it.
 *
 * Setting up sync used to look at a picked folder's marker and act on it silently. If the marker named the
 * SAME vault it kept the sync id — correct, but unannounced. In the other three shapes it OVERWROTE the
 * marker without a word, and one of those shapes matters: a folder carrying ANOTHER vault's marker had that
 * vault's folder identity taken from it, so the vault it belonged to could no longer recognise its own folder
 * after a rename or a move. Nobody was told, and nothing said it had happened.
 *
 * The second half is the sync BASELINE. `rclone bisync` keeps a prior listing to diff against; the engine
 * keys that workdir by VAULT and the listings inside it by the local+remote path PAIR. So:
 *
 *   - the same vault, re-linked to the SAME path, finds its listings and genuinely resumes;
 *   - the same vault re-linked to a DIFFERENT path finds no listing for that pair, and takes the
 *     fresh-baseline branch — every file is re-examined and the first run is a full comparison;
 *   - any other shape is a fresh baseline too.
 *
 * That distinction is why this returns a KIND rather than a boolean. "Re-using this folder — resetting the
 * sync baseline" is the honest thing to say in the second and third cases and a lie in the first, and the
 * failure this exists to end is the opaque one: a person re-links a folder they synced last month and gets
 * "waiting to start" with nothing to explain why the first run is doing so much work, or why their other
 * vault has since stopped recognising its folder.
 *
 * Pure: it takes the marker read and the two paths, and returns a verdict. The caller decides what to show
 * and what to do; nothing here reads or writes a disk.
 */

const path = require('node:path');

/** Same directory, allowing for separator and case differences on the platforms that have them. */
function samePath(a, b, caseInsensitive = process.platform === 'win32') {
  if (typeof a !== 'string' || typeof b !== 'string' || a === '' || b === '') return false;
  const norm = (p) => {
    const r = path.resolve(p).replace(/[\\/]+$/, '');
    return caseInsensitive ? r.toLowerCase() : r;
  };
  return norm(a) === norm(b);
}

/**
 * Classify what the person has just picked.
 *
 * @param {object} o
 * @param {{kind: string, vaultId?: string, syncId?: string}} o.marker  folder-marker.js readMarker shape
 * @param {string} o.vaultId        the vault being set up
 * @param {string} o.folder         the folder just picked
 * @param {string} [o.knownFolder]  where this vault's sync was last pointed, when it has one
 * @returns {{kind: 'fresh'|'resume'|'moved'|'other-vault'|'unreadable', resetsBaseline: boolean,
 *            keepsSyncId: boolean, takesOverMarker: boolean, otherVaultId: string|null}}
 */
function classifyPick({ marker, vaultId, folder, knownFolder = null }) {
  const m = marker && typeof marker === 'object' ? marker : { kind: 'absent' };
  const want = String(vaultId || '').toLowerCase();
  const has = typeof m.vaultId === 'string' ? m.vaultId.toLowerCase() : null;

  // No marker: an ordinary first setup. Nothing to warn about and nothing to take over.
  if (m.kind !== 'ok' && m.kind !== 'unreadable') {
    return { kind: 'fresh', resetsBaseline: false, keepsSyncId: false, takesOverMarker: false, otherVaultId: null };
  }

  // A marker that cannot be read is not evidence of anything, and MUST NOT be assumed to be ours. It is
  // replaced — but said out loud, because the folder plainly was used for something.
  if (m.kind === 'unreadable') {
    return { kind: 'unreadable', resetsBaseline: true, keepsSyncId: false, takesOverMarker: true, otherVaultId: null };
  }

  // Another vault's folder. The marker is what that vault uses to find this folder again after a rename,
  // so taking it over is a real loss to that vault, not a formality.
  if (has && has !== want) {
    return { kind: 'other-vault', resetsBaseline: true, keepsSyncId: false, takesOverMarker: true, otherVaultId: has };
  }

  // Our own vault's folder. Whether this resumes depends on the PATH, because that is what the prior
  // listings are keyed by — not on the marker, which is the same either way.
  const same = knownFolder ? samePath(folder, knownFolder) : true;
  return same
    ? { kind: 'resume', resetsBaseline: false, keepsSyncId: true, takesOverMarker: false, otherVaultId: null }
    : { kind: 'moved', resetsBaseline: true, keepsSyncId: true, takesOverMarker: false, otherVaultId: null };
}

/**
 * What to tell the person, as { title, detail }, or null when there is nothing worth saying.
 *
 * Each sentence states what will happen to THEIR files, because that is the question behind the question.
 * A reset baseline is not data loss and must not read as one — nothing is deleted, the first run simply
 * compares everything — and the one case that costs something (taking over another vault's marker) says so
 * plainly rather than being folded in with the rest.
 */
function pickMessage(verdict, { vaultName = 'this vault', otherVaultName = null } = {}) {
  if (!verdict || verdict.kind === 'fresh') return null;
  const other = otherVaultName || 'another vault';
  switch (verdict.kind) {
    case 'resume':
      return {
        title: 'This folder was synced here before',
        detail: `DockVault recognises this folder from an earlier sync of ${vaultName}, and will carry on from where that left off. Nothing is re-uploaded and nothing is deleted.`,
      };
    case 'moved':
      return {
        title: 'Re-using this folder — resetting the sync baseline',
        detail: `This folder was synced to ${vaultName} before, but from a different place on this computer. DockVault will compare everything in it against the vault once, which takes longer than a normal sync. Nothing is deleted; files that differ are kept as both copies.`,
      };
    case 'other-vault':
      return {
        title: `This folder is already ${other}'s`,
        detail: `It carries ${other}'s sync marker, which is how DockVault finds that folder again if it is renamed or moved. Using it for ${vaultName} takes that marker over, so ${other} will no longer recognise this folder and its sync will need pointing at a folder again. The sync baseline is reset too: the first run compares everything, and nothing is deleted.`,
      };
    case 'unreadable':
      return {
        title: 'Re-using this folder — resetting the sync baseline',
        detail: `This folder carries a DockVault sync marker that can't be read, so it has been used for a sync before but there is no way to tell which one. DockVault will write a fresh marker and compare everything in the folder against ${vaultName} once. Nothing is deleted.`,
      };
    default:
      return null;
  }
}

module.exports = { classifyPick, pickMessage, samePath };

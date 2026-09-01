'use strict';

/*
 * The enable-sync flow, as one testable sequence. The main process supplies the input/output surface
 * (list the vaults, present the pickers and dialogs, resolve + create the folder, persist) as injected
 * callbacks; this module drives the ORDER and the SAFETY decisions between them:
 *
 *   list Standard vaults -> pick one -> pick a local folder -> (resolve symlinks) -> classify it ->
 *   refuse + re-pick when unsafe -> warn + let the user reconsider a cloud-storage folder -> take an
 *   explicit consent -> derive the remote path from the chosen vault -> create the folder -> persist.
 *
 * Two invariants are enforced here in code, not by convention:
 *   - The remote path is ALWAYS remotePathForVault(the chosen vault's name), never anything the picker
 *     or a page could supply — so the stored target is structurally the vault's own directory.
 *   - The record is built by the credential-free constructor, so nothing credential-adjacent can be
 *     persisted.
 *
 * Nothing is written until the folder passes the hard checks AND the person consents; a cancel or a
 * refused-then-abandoned pick leaves no config behind.
 */

const { remotePathForVault, makeConfigEntry, classifyLocalTarget } = require('./sync-config');

/**
 * @param {object} io injected input/output surface
 * @param {() => Promise<Array<{vaultId:string,vaultName:string}>>} io.listVaults  main-side Standard-only fetch
 * @param {(vaults:Array) => Promise<{vaultId:string,vaultName:string}|null>} io.pickVault  null => cancel
 * @param {() => Promise<string|null>} io.pickFolder  native directory picker; null => cancel
 * @param {(p:string) => string} io.resolveReal  resolve symlinks to the real absolute target
 * @param {() => object} io.classifyCtx  fresh { home, userData, refuseRoots, existingFolders }
 * @param {(folder:string) => Promise<boolean>} io.confirmCloud  a cloud-folder warning; true => use anyway
 * @param {(vaultName:string, folder:string) => Promise<boolean>} io.confirmConsent  the readable-copies consent
 * @param {(folder:string) => void} io.ensureFolder  create the folder not-world-accessible (idempotent)
 * @param {(reason:string) => (void|Promise<void>)} io.onRefuse  surface why a folder was refused
 * @param {(entry:object) => (void|Promise<void>)} io.save  persist the accepted entry
 * @returns {Promise<{enabled:boolean, entry?:object, cancelled?:boolean, reason?:string}>}
 */
async function runEnableFlow(io) {
  const vaults = await io.listVaults();
  if (!Array.isArray(vaults) || vaults.length === 0) return { enabled: false, reason: 'no-standard-vaults' };

  const vault = await io.pickVault(vaults);
  if (!vault) return { enabled: false, cancelled: true };
  // The selection MUST be a member of the server-fetched Standard list. The list is
  // server-authoritative and excludes zero-knowledge vaults; enforcing membership here means a
  // substituted or non-eligible vault id can never be persisted (which would later route the wrong
  // vault through the server-decrypt sync). Server-authoritative list AND server-honoured selection.
  if (!vaults.some((v) => v.vaultId === vault.vaultId)) return { enabled: false, reason: 'vault-not-eligible' };

  // Derive + validate the remote from the chosen vault BEFORE any folder pick or consent. A name that
  // cannot be a safe single path segment ('/'|'\'|control char) then fails SPECIFICALLY and early,
  // never with a generic dead-end after the person has already consented.
  let remotePath;
  try { remotePath = remotePathForVault(vault.vaultName); }
  catch { return { enabled: false, reason: 'bad-vault-name', vaultName: vault.vaultName }; }

  // Re-pick until a folder is accepted, or the person cancels.
  for (;;) {
    const picked = await io.pickFolder();
    if (!picked) return { enabled: false, cancelled: true };

    const resolved = io.resolveReal(picked); // the REAL target, after any symlink
    // Pass the vault being (re)configured so its OWN current folder is not counted as an overlap
    // (re-running setup and re-picking the same folder must not be refused as "another vault syncs here").
    const verdict = classifyLocalTarget(resolved, io.classifyCtx(vault.vaultId));
    if (!verdict.ok) { await io.onRefuse(verdict.reason); continue; }
    if (verdict.warn === 'inside-cloud-sync') {
      const useAnyway = await io.confirmCloud(resolved);
      if (!useAnyway) continue; // "choose another folder"
    }

    // Consent is two-way and folder-aware: a bisync uploads the folder's existing (and future)
    // contents into the server-readable vault, so the consent must know whether the folder is non-empty.
    const nonEmpty = typeof io.isNonEmptyDir === 'function' ? !!io.isNonEmptyDir(resolved) : false;
    const consented = await io.confirmConsent({ vaultId: vault.vaultId, vaultName: vault.vaultName, folder: resolved, nonEmpty });
    if (!consented) return { enabled: false, cancelled: true };

    // The remote is ALWAYS the value derived from the chosen vault above — never a picker/renderer value.
    io.ensureFolder(resolved);
    const entry = makeConfigEntry({ vaultId: vault.vaultId, vaultName: vault.vaultName, localFolder: resolved, remotePath, enabled: true });
    await io.save(entry);
    return { enabled: true, entry };
  }
}

module.exports = { runEnableFlow };

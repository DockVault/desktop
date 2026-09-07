'use strict';

/*
 * The DEVICE STEP of enabling sync for one vault — the orchestration that turns decideEnableDeviceStep's
 * decision into the actual sequence (register this computer / grant the vault / switch servers first), driven
 * entirely by injected IO so the ORDER and the fail-soft rules are testable without Electron, a network, or a
 * real keychain. The Electron dialogs and the register/grant/forget calls live in the caller (buildEnableIo);
 * this module never opens a dialog, sends a request, or reads the store itself.
 *
 * Fail-soft, because the account path still exists: the vault's sync config is already saved by the folder
 * flow before this runs, so ANY device-step outcome short of a granted device path simply leaves the vault on
 * the account session (it keeps syncing) and returns a typed outcome for the caller's honest copy. The device
 * step never blocks or undoes the enable; it only tries to move the vault onto its own device identity.
 *
 * Load-bearing rules enforced here (not by the caller's convention):
 *   - probe/decision FIRST: a vault only registers when the identity is genuinely absent, only switches
 *     servers (forget-then-register) on an identity bound elsewhere, and otherwise stays on the account path
 *     with an honest reason (never a clobber, never a register over an unreadable/stale blob).
 *   - the switch is CONSENTED: forget-then-register runs the forget only after the person agrees to move this
 *     computer off the other server; declining leaves the vault on the account path, nothing forgotten.
 *   - the password is the caller's to prompt (only for a password vault) and is never seen here; a person who
 *     defers it leaves the vault on the account path as a calm, resumable state, never a failure.
 */

const { decideEnableDeviceStep } = require('./device-register');

/**
 * Carry out the device step for one vault. Every branch returns { via, outcome, reason? }: via is the path the
 * vault will sync on now ('device' once a grant exists, else 'account'); outcome names what happened for the
 * caller's copy; reason carries the honest sub-cause for the account-path outcomes.
 *
 * @param {object} io
 * @param {() => Promise<{reason:('ok'|'too-old'|'auth'|'indeterminate')}>} io.probe   checkDeviceSyncSupported
 * @param {() => ('ok'|'absent'|'absent-for-this-server'|'stale'|'unreadable'|'no-secure-store')} io.readStatus  readDeviceSecret's status
 * @param {() => Promise<boolean>} io.confirmSwitchServer   name the other server + consent to move this computer here (forget-then-register); false = leave it
 * @param {() => Promise<void>} io.forget                   forgetDevice (local clear + revoke-under-read-back-origin / id-only best-effort); never throws
 * @param {() => Promise<string|null>} io.promptLabel        the register label dialog; null = the person cancelled
 * @param {(label:string) => Promise<{ok:boolean, reason?:string}>} io.register   registerDevice for this label
 * @param {(o:{vaultId:string,vaultName:string,hasPassword:boolean}) => Promise<{granted:boolean, deferred?:boolean, reason?:string}>} io.grantVault
 *   prompt the vault password ONLY when hasPassword, then grantAndRecord; deferred:true when the person chose "Later"
 * @param {{vaultId:string, vaultName:string, hasPassword:boolean}} vault
 * @returns {Promise<{via:'device'|'account', outcome:string, reason?:string}>}
 */
async function runDeviceSetup(io, vault) {
  let probeReason;
  try { probeReason = (await io.probe()).reason; } catch { probeReason = 'indeterminate'; } // could not verify -> account path, honest
  let secretStatus;
  try { secretStatus = io.readStatus(); } catch { secretStatus = 'unreadable'; }

  const decision = decideEnableDeviceStep({ probeReason, secretStatus });
  if (decision.action === 'sign-in') return { via: 'account', outcome: 'sign-in', reason: decision.reason };
  if (decision.action === 'account-only') return { via: 'account', outcome: 'account-only', reason: decision.reason };

  // An identity bound to ANOTHER server: never a clobber, and never a strand. Both answers that CAN be taken back
  // — the consent to switch and the label — are collected before the one step that cannot: forget (local clear +
  // revoke under the read-back old origin, or id-only when the blob is undecryptable). So a cancel anywhere before
  // the forget costs nothing and leaves the identity intact on the other server.
  const isSwitch = decision.action === 'forget-then-register';
  if (isSwitch) {
    let proceed = false;
    try { proceed = await io.confirmSwitchServer(); } catch { proceed = false; }
    if (!proceed) return { via: 'account', outcome: 'switch-declined', reason: 'registered-elsewhere' };
  }

  // register (absent) or the register half of a switch: name this computer FIRST (reversible), then — only for a
  // switch — run the irreversible forget, then create the server row + store the secret. Ordering the forget after
  // the label is why a cancelled label forgets nothing.
  if (decision.action === 'register' || isSwitch) {
    const label = await io.promptLabel();
    if (label === null) return { via: 'account', outcome: 'register-cancelled' }; // nothing forgotten; the config still syncs on the account session
    if (isSwitch) {
      try { await io.forget(); } catch { /* forget never throws; a failed revoke keeps the id nameable, the clear still runs */ }
    }
    const reg = await io.register(label);
    if (!reg || !reg.ok) {
      // A switch that fails AFTER the forget has already removed this computer from the other server carries
      // `switched`, so the caller's copy can be honest ("no longer set up with the other server"), not just
      // "didn't finish". A plain absent-slot register-failed removed nothing, so it carries no flag.
      const failed = { via: 'account', outcome: 'register-failed', reason: (reg && reg.reason) || 'register-refused' };
      if (isSwitch) failed.switched = true;
      return failed;
    }
  }

  // grant-only, or after a successful register/switch: grant this vault (the caller prompts the password only
  // when the vault has one). A completed grant moves the vault to the device path; a deferred password leaves
  // it on the account path as a calm, resumable "enter the password" state; a real failure is reported as such.
  const g = await io.grantVault({ vaultId: vault.vaultId, vaultName: vault.vaultName, hasPassword: !!vault.hasPassword });
  // A granted vault is on the device path. `recordFailed` means the SERVER grant succeeded but the local record
  // write did not — surface it as a distinct outcome (not a silent 'granted') so the person is told the setup
  // didn't fully save on this computer, rather than the vault silently looking un-set-up later.
  if (g && g.granted) return { via: 'device', outcome: g.recordFailed ? 'granted-not-recorded' : 'granted' };
  if (g && g.deferred) return { via: 'account', outcome: 'grant-deferred', reason: 'grant-needs-password' };
  return { via: 'account', outcome: 'grant-failed', reason: (g && g.reason) || 'grant-failed' };
}

module.exports = { runDeviceSetup };

'use strict';

/*
 * Existing-setup migration — the pure decision behind moving a desktop that already syncs on the ACCOUNT
 * path onto this computer's own registered identity. From local facts alone it answers whether to surface
 * the one-line "set this computer up to sync on its own" door, whether to show the one-time nudge, and WHICH
 * configured vaults still need moving over.
 *
 * It changes nothing about how a run mints: a configured vault with no grant record here already runs on the
 * account path, and keeps doing so until the person accepts the offer — migration only makes that account
 * path VISIBLE (a calm door), never a forced pause. A vault gains a grant record the moment it is granted, at
 * which point it drops out of the door's list and the next run mints on the device path on its own. So the
 * door derives its own vanishing from records + config, and never needs a "migrated" flag.
 *
 * The per-vault grant record is read as the SAME three-state the store returns — 'granted' / 'first-setup' /
 * 'unreadable' — never flattened to a boolean. Only a DEFINITELY-un-recorded ('first-setup') vault is offered:
 * an 'unreadable' record is EXCLUDED (a merely-locked keychain must not make a migrated vault look un-migrated
 * and get re-granted, which for a no-password vault would upsert — and reactivate — a grant the owner may have
 * revoked; "unreadable is its own answer", the same rule the resume sweep follows). Excluded vaults reappear
 * the moment the store reads again.
 *
 * Pure + injected facts, so the trigger and the one-time-per-origin nudge are testable without Electron, a
 * network, or a keychain.
 */

/**
 * @param {object} facts
 * @param {'ok'|'too-old'|'auth'|'indeterminate'|null|undefined} facts.support
 *   checkDeviceSyncSupported's reason (null/undefined = not probed yet this session). ONLY 'ok' offers;
 *   'too-old' shows the calm note; everything else (auth / indeterminate / offline / unknown) shows nothing
 *   and marks nothing — so a person is never told their server is old because they were merely offline.
 * @param {'absent'|'ok'|'absent-for-this-server'|'no-secure-store'|'stale'|'rechecking'|'unreadable'|string|null|undefined} facts.deviceStatus
 *   readDeviceSecret's status. Migration registers on a genuinely-empty slot ('absent') or adds vaults to this
 *   server's live identity ('ok'). Any other status is NOT a migration: 'absent-for-this-server' is the switch
 *   flow (a different server's identity — never forget it here), 'stale'/'rechecking'/'unreadable' are the
 *   recheck / escape-hatch states, 'no-secure-store' cannot register at all. The door stays hidden for them
 *   rather than becoming a register that does nothing.
 * @param {Array<{vaultId:string, vaultName?:string, hasPassword?:boolean, record:'granted'|'first-setup'|'unreadable'}>} facts.configured
 *   the vaults configured for sync + the three-state grant record here (feed deviceGrantHistory verbatim).
 * @param {string|null} [facts.offeredOrigin]  the server origin the one-time nudge was last shown for (state)
 * @param {string|null} [facts.currentOrigin]  the current server origin
 * @returns {{ doorShow:boolean, vaults:Array<{vaultId:string,vaultName?:string,hasPassword?:boolean}>, notify:boolean, tooOldNote:boolean, otherServerNote:boolean }}
 */
function decideMigration(facts = {}) {
  const support = facts.support;
  const deviceStatus = facts.deviceStatus;
  const configured = Array.isArray(facts.configured) ? facts.configured : [];
  // The un-migrated set: a configured vault whose record here is DEFINITELY absent ('first-setup'). 'granted'
  // is already migrated; 'unreadable' is excluded (never offered → never granted on a locked keychain). The
  // list shrinks to empty as vaults are granted (each grant writes its record), so the door vanishes on its own.
  const vaults = configured
    .filter((v) => v && typeof v.vaultId === 'string' && v.vaultId && v.record === 'first-setup')
    .map((v) => ({ vaultId: v.vaultId, vaultName: typeof v.vaultName === 'string' ? v.vaultName : undefined, hasPassword: !!v.hasPassword }));
  const supported = support === 'ok';
  const migratable = deviceStatus === 'absent' || deviceStatus === 'ok';
  const doorShow = supported && migratable && vaults.length >= 1;
  const currentOrigin = typeof facts.currentOrigin === 'string' && facts.currentOrigin ? facts.currentOrigin : null;
  const offeredOrigin = typeof facts.offeredOrigin === 'string' && facts.offeredOrigin ? facts.offeredOrigin : null;
  // The one-time nudge fires only when the door applies AND support is known here AND there is a current
  // origin we have not already nudged for. A server switch (a new origin) re-offers; a decline (the origin is
  // recorded as offered) stays quiet; adding another account-path vault on the SAME origin does NOT re-nudge —
  // the standing door already covers it.
  const notify = doorShow && !!currentOrigin && currentOrigin !== offeredOrigin;
  const tooOldNote = support === 'too-old';
  // An identity bound to ANOTHER server, with account-path vaults configured for THIS one, is the one hidden
  // case that must NOT go silent: it is exactly the silent account path this offer exists to replace, and
  // "Set up sync…" (the new-vault flow) is not a route a person with already-configured vaults would open. So
  // the door is replaced by an honest switch line — true precisely when the door is hidden for this reason —
  // whose click hands off to the existing switch consent (forget the other server's identity, register here).
  const otherServerNote = supported && deviceStatus === 'absent-for-this-server' && vaults.length >= 1;
  return { doorShow, vaults, notify, tooOldNote, otherServerNote };
}

// The QUIET migration outcomes — nothing to tell the person, because the tray already reflects them: a granted
// vault shows syncing, and a decline the person just made needs no dialog repeating it.
const QUIET_MIGRATION_OUTCOMES = new Set(['granted', 'register-cancelled', 'switch-declined']);
// The identity-level outcomes — decided ONCE for the whole pass (the shared register / switch / sign-in step),
// so they name the vaults collectively rather than one line each.
const IDENTITY_MIGRATION_OUTCOMES = new Set(['account-only', 'sign-in', 'register-failed']);

/**
 * Group a migration pass's per-vault outcomes for ONE result dialog — never one dialog per vault. Quiet outcomes
 * (granted, or the person's own decline) are dropped; the rest are grouped by outcome+reason in first-seen order,
 * each carrying the vault names it covers and whether it is identity-level (decided once for the whole pass, so
 * the caller names those collectively). Pure, so the suppression and grouping are testable without Electron.
 * @param {Array<{vault:{vaultName?:string}, outcome:{outcome?:string, reason?:string, switched?:boolean}}>} outcomes
 * @returns {Array<{outcome:string, reason:(string|null), names:string[], idLevel:boolean, switched:boolean}>}
 */
function groupMigrationOutcomes(outcomes) {
  const order = [];
  const byKey = new Map();
  for (const entry of (Array.isArray(outcomes) ? outcomes : [])) {
    const o = entry && entry.outcome && entry.outcome.outcome;
    if (!o || QUIET_MIGRATION_OUTCOMES.has(o)) continue;
    const reason = (entry.outcome && entry.outcome.reason) || null;
    const key = `${o}|${reason || ''}`;
    if (!byKey.has(key)) {
      // `switched` (from the first outcome of the group) is carried so the caller's register-failed copy can be
      // honest that a switch already removed this computer from the other server; it applies only to the shared
      // identity step, so the group's first value holds for the group.
      const g = { outcome: o, reason, names: [], idLevel: IDENTITY_MIGRATION_OUTCOMES.has(o), switched: !!(entry.outcome && entry.outcome.switched) };
      byKey.set(key, g); order.push(g);
    }
    byKey.get(key).names.push((entry.vault && entry.vault.vaultName) || 'this vault');
  }
  return order;
}

module.exports = { decideMigration, groupMigrationOutcomes };

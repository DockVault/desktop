'use strict';

const { identityEndedBy } = require('./mint-path');

/*
 * The RESUME half of device grants. When a vault's grant was DEFERRED at setup (the vault wasn't open to
 * prove its password once), the grant is completed the next time the vault is open and its password fresh —
 * by itself, so a person just opens the vault to work and the setup finishes behind them. This module drives
 * the ORDER and the keep/clear/acknowledge rules from injected IO, so they are testable without Electron, a
 * network, or a keychain; the caller runs it on the same passes the account path mints on (the routine pass
 * is more frequent than the password-freshness window, so an open vault is never missed).
 *
 * Rules enforced here, not by the caller's convention:
 *   - a vault no longer configured for sync drops its marker — never a grant on a vault the person stopped
 *     syncing;
 *   - a vault whose password is not available right now (not open, or gone stale) is LEFT pending — a calm
 *     skip, never a failure, retried on the next pass;
 *   - a completed grant clears the marker and is acknowledged ONCE (name only);
 *   - a grant refused because the vault is gone ('vault-not-accessible') drops the marker — retrying is
 *     futile;
 *   - any OTHER failure leaves the marker in place (it self-heals on a fresh unlock, and the server spaces
 *     its own retries), so a transient refusal is not lost and a permanent one is not hammered indefinitely.
 * The vault password is the caller's to pull (only for a password vault); it is never stored here and is
 * dropped as soon as the grant call returns.
 */

/**
 * Complete every pending device grant whose vault is open and fresh right now.
 * @param {object} io
 * @param {() => string[]} io.listPending                       vault ids with a pending device grant (fail-safe [] when unreadable)
 * @param {(vaultId:string) => boolean} io.isConfigured         is the vault still set up to sync?
 * @param {(vaultId:string) => (boolean|'unreadable')} [io.wasGranted]  did this vault EVER hold a grant? true (re-proof) / false (first setup) / 'unreadable' or throw (record unreadable → DEFER, never collapse to first setup)
 * @param {(vaultId:string) => Promise<'active'|'revoked'|'inconclusive'>} [io.checkActiveGrant]  the server's authoritative active-grant answer
 * @param {(vaultId:string) => boolean} io.vaultRequiresPassword whether the vault needs a password proven
 * @param {(vaultId:string) => Promise<string|null>} io.pullPassword  the unlock-state password, or null if the vault isn't open/fresh
 * @param {(o:{vaultId:string, vaultPassword?:string}) => Promise<{ok:boolean, reason?:string}>} io.grant  grantAndRecord for this vault
 * @param {(vaultId:string) => void} io.clearPending            clear the marker (grant done, or the vault is gone)
 * @param {(vaultId:string) => void} io.ackComplete             acknowledge a completed setup ONCE (name only)
 * @returns {Promise<{granted:string[], deferred:string[], failed:string[], dropped:string[]}>}
 */
async function resumePendingGrants(io) {
  const out = { granted: [], deferred: [], failed: [], dropped: [] };
  let pending;
  try { pending = io.listPending() || []; } catch { return out; } // an unreadable pending store: nothing to do this pass
  for (const vaultId of pending) {
    if (!io.isConfigured(vaultId)) { safeClear(io, vaultId); out.dropped.push(vaultId); continue; } // stopped syncing → drop
    // Re-proof only: a vault that was granted before must NEVER be reactivated if the owner revoked it. Consult
    // the server's authoritative active grants first, FAIL CLOSED: a clean "revoked" clears the marker and
    // skips; an inconclusive answer (a failed / unusable check) DEFERS — leave the marker, never proceed on
    // doubt, never clear on a mere check failure. A first setup grant reactivates nothing, so it skips the check.
    if (io.wasGranted) {
      // An UNREADABLE grant record must NEVER collapse to "not granted": that would skip the guard below and
      // re-grant a vault whose grant the owner revoked (POST /grants reactivates it) — a fail-open that
      // silently defeats a revocation. So an 'unreadable' answer (or a probe that THROWS) is a DEFER, exactly
      // like an inconclusive active-check: leave the marker, ask nothing, grant nothing, retry next pass. A
      // record that stays unreadable keeps deferring on every pass — never a wrong re-grant.
      let granted;
      try { granted = io.wasGranted(vaultId); } catch { granted = 'unreadable'; }
      if (granted === 'unreadable') { out.deferred.push(vaultId); continue; }
      if (granted && io.checkActiveGrant) {
        let active;
        try { active = await io.checkActiveGrant(vaultId); } catch { active = 'inconclusive'; }
        if (active === 'revoked') { safeClear(io, vaultId); out.dropped.push(vaultId); continue; }
        if (active !== 'active') { out.deferred.push(vaultId); continue; } // inconclusive → leave the marker, retry next pass
      }
    }
    let vaultPassword;
    if (io.vaultRequiresPassword(vaultId)) {
      try { vaultPassword = await io.pullPassword(vaultId); } catch { vaultPassword = null; }
      if (!vaultPassword) { out.deferred.push(vaultId); continue; } // not open/fresh yet → leave the marker, try next pass
    }
    let r;
    try { r = await io.grant({ vaultId, vaultPassword }); }
    catch { r = { ok: false, reason: 'grant-error' }; }
    finally { vaultPassword = undefined; } // drop our reference the moment the grant call returns
    if (r && r.ok) { safeClear(io, vaultId); try { io.ackComplete(vaultId); } catch { /* the grant stands regardless */ } out.granted.push(vaultId); }
    else if (r && r.reason === 'vault-not-accessible') { safeClear(io, vaultId); out.dropped.push(vaultId); } // the vault is gone → retrying is futile
    else { out.failed.push(vaultId); } // leave the marker: self-heals on a fresh unlock, or the server spaces retries
  }
  return out;
}

function safeClear(io, vaultId) { try { io.clearPending(vaultId); } catch { /* an unreadable store retries the clear next pass */ } }

/**
 * What a completed run's reason means for the pending-grant marker — the re-proof FEED and the fail-closed
 * CLEARS, so a marker only ever tracks a grant that can still be re-proved and never one the owner withdrew:
 *   'add'       a re-proof (the vault password changed on the server): mark it pending so the resume finishes
 *               it on the next open. This is the ONLY reason that ever adds a marker from a run.
 *   'clear-all' the identity itself ended (revoked / expired): every marker belongs to an identity that no
 *               longer exists — drop them all; the set-up-again door re-creates whatever is needed.
 *   'clear'     this vault's grant is gone (revoked / withdrawn) while the identity lives: drop just its
 *               marker, so the resume never reactivates a grant the owner withdrew.
 *   null        everything else (success, a calm wait, a suspension kept for its restore) leaves markers as-is.
 * @param {string} reason  the run's reason (the raw device/mint reason, as onEvent sees it)
 * @returns {('add'|'clear'|'clear-all'|null)}
 */
function markerActionForRunReason(reason) {
  if (reason === 'grant-needs-reproof') return 'add';
  if (identityEndedBy(reason)) return 'clear-all';           // device-revoked / device-expired
  if (reason === 'no-grant' || reason === 'grant-withdrawn') return 'clear';
  return null;
}

/**
 * The re-grant loop of setting this computer up AGAIN on a fresh identity (after a reset, or a server-ended
 * identity: revoked / expired / not-recognized). For each vault recorded under the OLD identity, drop its old
 * grant record FIRST — this is load-bearing: the record has no identity in it, so if it survived, the resume
 * guard would read the vault as "granted before", ask the NEW identity's (empty) grant list, get "revoked",
 * and silently clear the marker, leaving the vault on the account path with no line. Dropped, the vault counts
 * as a FIRST setup on the new identity (no guard). Then a no-password vault is granted right away; a password
 * vault is marked pending so opening it once completes the grant through the resume. Pure + injected IO, so the
 * ORDER (drop before anything) and the per-vault branch are testable without Electron or a network.
 * @param {object} io
 * @param {(vaultId:string) => void} io.dropMeta   remove the OLD identity's grant record for this vault
 * @param {(vaultId:string) => void} io.addPending mark a password vault pending (the resume finishes it on open)
 * @param {(o:{vaultId:string, vaultName:string}) => Promise<{ok:boolean, reason?:string}>} io.grant  grant a no-password vault now
 * @param {Array<{vaultId:string, vaultName:string, hasPassword:boolean}>} vaults  the vaults recorded under the old identity
 * @returns {Promise<{granted:string[], pending:string[], failed:string[]}>}
 */
async function runSetupAgainGrants(io, vaults) {
  const out = { granted: [], pending: [], failed: [] };
  for (const v of (Array.isArray(vaults) ? vaults : [])) {
    if (!v || !v.vaultId) continue;
    try { io.dropMeta(v.vaultId); } catch { /* best-effort; a surviving record self-heals when a grant re-writes it, and the guard is the backstop */ }
    if (v.hasPassword) {
      try { io.addPending(v.vaultId); out.pending.push(v.vaultId); } catch { out.failed.push(v.vaultId); } // an unreadable pending store: report failed, never silently drop
    } else {
      let r;
      try { r = await io.grant({ vaultId: v.vaultId, vaultName: v.vaultName }); } catch { r = { ok: false }; }
      if (r && r.ok) out.granted.push(v.vaultId); else out.failed.push(v.vaultId);
    }
  }
  return out;
}

module.exports = { resumePendingGrants, markerActionForRunReason, runSetupAgainGrants };

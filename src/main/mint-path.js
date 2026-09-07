'use strict';

/*
 * Which credential path a sync run takes — and the rule that it never changes mid-run.
 *
 * Two mint paths coexist while existing set-ups are moved over to device sync: the DEVICE path (this
 * computer's registered identity mints against its own grant; no account session and no vault password
 * involved) and the ACCOUNT path (the account session mints, as before). The choice is made ONCE per
 * run, from a fixed rule over three local facts, and is latched for that run:
 *
 *   - the device secret's read status: 'ok' means this computer is registered; 'absent' (or no secure
 *     store) means it is not, so the account path applies; 'unreadable' is TRANSIENT (a locked keyring,
 *     a torn file) and pauses the run — it is never "not registered", never re-registers, and never
 *     drops to the account path as a workaround, since that would hide a device-side fault behind a
 *     working account mint.
 *   - the device's ACTIVE grants, fetched fresh from the server for every run (the authority on what
 *     this device may still sync). A grant present for the vault means the device path. A failure to
 *     list them is the device's own typed refusal (revoked, expired, suspended, offline, ...) and is
 *     surfaced as such — never turned into an account-path run.
 *   - the local grant record: whether THIS computer ever recorded a grant for the vault. A vault the
 *     server no longer lists but that was recorded here has had its grant withdrawn ('no-grant', its
 *     own calm state); a vault never recorded here simply has not been moved over yet and keeps the
 *     account path. An unreadable record cannot tell those two apart, so it pauses rather than guess.
 *
 * The device path also fixes the REMOTE PATH: the vault's opaque id in the server's machine form
 * (vault_<id>), which the SFTP server resolves for a scoped credential. It is rename-proof and needs
 * no display name. The tier IS needed: it is re-asserted from the recorded metadata before every run
 * (only an explicit Standard proceeds), so a grant whose metadata is not known here — never recorded,
 * or unreadable this moment — WAITS calmly for the details to be filled in from an account session
 * (the optional backfill below) rather than running on an unverified tier or dropping to the account
 * path. The server re-asserts the tier on every mint regardless; this is the local defence in depth.
 */

const { remotePathForVault } = require('./sync-config');

// The server answers after which this computer's identity is OVER: removed by the owner, or expired. The local
// secret is then wiped (it can never be presented again), the state database is left alone (a relationship end
// wipes no synced data), and the recorded grant details stay for the next set-up. A suspension is deliberately
// NOT here — it is reversible on the server, so the identity is kept for its restore.
const IDENTITY_ENDED_REASONS = Object.freeze(['device-revoked', 'device-expired']);
function identityEndedBy(reason) { return IDENTITY_ENDED_REASONS.includes(reason); }

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The server's rename-proof machine form of a vault's directory, validated as one safe segment. */
function deviceRemotePath(vaultId) {
  if (typeof vaultId !== 'string' || !UUID.test(vaultId)) throw new Error('a device sync remote path needs the vault id');
  return remotePathForVault('vault_' + vaultId.toLowerCase());
}

/**
 * The pure decision. `secretStatus` is readDeviceSecret's status; `grants` is listMyGrants' result
 * (consulted only when the secret is 'ok'); `record` is the local grant record read
 * ({ status, hasEntry }). Returns { ok:true, via:'device'|'account', grant? } or { ok:false, reason }.
 */
function decideMintPath({ secretStatus, grants, record, vaultId }) {
  if (secretStatus === 'unreadable') return { ok: false, reason: 'device-secret-unreadable' };
  // A rotation cut off mid-flight, not yet reconciled against the account's device list: the held secret is
  // withheld (it MAY be retired), but this is a calm "being re-checked" — never the terminal retired 'stale'
  // and never a set-up-again alarm — until the reconcile clears it or turns it terminal.
  if (secretStatus === 'rechecking') return { ok: false, reason: 'device-being-rechecked' };
  // A rotation's answer was lost and the server has moved on: the secret held here is retired, and presenting
  // it past its grace would suspend the device. Refuse with the server's own literal; a person sets it up again.
  if (secretStatus === 'stale') return { ok: false, reason: 'device-secret-stale' };
  // No identity here. A vault this computer once synced on its own identity (it has a grant record here) does
  // NOT quietly fall back to the account path: the identity is gone because the owner removed this computer
  // (or it expired) and the secret was wiped — the honest state is "removed, set it up again", held like a
  // revocation, until the set-up-again door re-grants and re-records. A vault never recorded here has simply
  // not been moved over yet and keeps the account path. An unreadable record cannot tell the two apart: pause.
  if (secretStatus === 'absent') {
    if (!record || record.status === 'unreadable') return { ok: false, reason: 'device-state-unreadable' };
    if (record.hasEntry) return { ok: false, reason: 'device-removed' };
    return { ok: true, via: 'account' };
  }
  // 'no-secure-store': nothing can be registered here. 'absent-for-this-server' (registered with a DIFFERENT
  // server) is likewise no identity for THIS server's vaults while the account path still exists; it never
  // registers here by itself. Once the account path is retired it becomes its own honest state instead.
  if (secretStatus !== 'ok') return { ok: true, via: 'account' };
  if (!grants || grants.ok !== true) return { ok: false, reason: (grants && grants.reason) || 'device-request-refused' };
  const list = Array.isArray(grants.grants) ? grants.grants : [];
  const g = list.find((x) => x && typeof x.vaultId === 'string' && x.vaultId === vaultId) || null;
  if (g) {
    // Local tier re-assert: only an explicitly recorded Standard tier proceeds. Unknown details (never
    // recorded here, or the record is unreadable this moment) wait for a backfill — calm, transient, and
    // never a reason to run on the account path instead.
    if (!g.metaKnown) return { ok: false, reason: 'grant-details-pending' };
    if (g.vaultType !== 'standard') return { ok: false, reason: 'vault-not-standard' };
    return { ok: true, via: 'device', grant: g };
  }
  if (!record || record.status === 'unreadable') return { ok: false, reason: 'device-state-unreadable' };
  if (record.hasEntry) return { ok: false, reason: 'no-grant' }; // recorded here, no longer granted: withdrawn
  return { ok: true, via: 'account' };                          // never recorded here: not moved over yet
}

/**
 * Makes the per-run choice from injected reads and LATCHES it until the run ends, so every credential
 * minted during one run (the dispatch mint and each per-step mint of a multi-process run) takes the same
 * path. A per-step mint reads the latch; it never re-decides, so a grant withdrawn or a secret lost
 * mid-run fails that run closed on its own path instead of quietly finishing on the other.
 */
class MintPathSelector {
  /**
   * @param {object} io
   * @param {() => {status:string}} io.readSecret            readDeviceSecret bound to the app's store
   * @param {() => Promise<{ok:boolean, grants?:Array, reason?:string}>} io.listGrants  listMyGrants bound to the store + a fresh secret read
   * @param {() => {status:string, meta:object}} io.readGrantRecord  readGrantMeta bound to the app's store
   * @param {(vaultId:string) => Promise<{name:string,vaultType:string,hasPassword:boolean}|null>} [io.backfill]
   *   fill in a grant's missing details from a live account session (and record them); null when it cannot
   */
  constructor(io = {}) {
    this._io = io;
    this._latched = new Map(); // vaultId -> 'device' | 'account'
  }

  /**
   * Decide the path for a run of `vaultId` and latch it. Resolves the decision; on the device path it
   * also carries the id-keyed remote path and the recorded display name (null when unknown).
   */
  async begin(vaultId) {
    this._latched.delete(vaultId);
    let secretStatus;
    try { secretStatus = (this._io.readSecret() || {}).status; } catch { secretStatus = 'unreadable'; }
    let grants = null;
    let record = null;
    if (secretStatus === 'ok') {
      try { grants = await this._io.listGrants(); } catch (e) { grants = { ok: false, reason: (e && typeof e.reason === 'string' && e.reason) || 'device-request-refused' }; }
    }
    if (secretStatus === 'ok' || secretStatus === 'absent') {
      try {
        const r = this._io.readGrantRecord() || {};
        const readable = r.status === 'ok' || r.status === 'absent';
        record = { status: readable ? r.status : 'unreadable', hasEntry: readable && !!(r.meta && Object.prototype.hasOwnProperty.call(r.meta, vaultId)) };
      } catch { record = { status: 'unreadable', hasEntry: false }; }
    }
    let d = decideMintPath({ secretStatus, grants, record, vaultId });
    // A grant whose details are not known here: try ONE backfill from an account session, then decide
    // again with the filled-in details. No session, or nothing usable, leaves it waiting (not failed).
    if (!d.ok && d.reason === 'grant-details-pending' && typeof this._io.backfill === 'function') {
      let m = null;
      try { m = await this._io.backfill(vaultId); } catch { m = null; }
      if (m && typeof m === 'object' && typeof m.vaultType === 'string') {
        const filled = grants.grants.map((x) => (x && x.vaultId === vaultId ? { ...x, name: typeof m.name === 'string' ? m.name : null, vaultType: m.vaultType, hasPassword: !!m.hasPassword, metaKnown: true } : x));
        d = decideMintPath({ secretStatus, grants: { ok: true, grants: filled }, record, vaultId });
      }
    }
    if (!d.ok) return d;
    if (d.via === 'device') {
      let remotePath;
      try { remotePath = deviceRemotePath(vaultId); } catch { return { ok: false, reason: 'bad-vault-name' }; }
      this._latched.set(vaultId, 'device');
      return { ok: true, via: 'device', remotePath, vaultName: (d.grant && typeof d.grant.name === 'string' && d.grant.name) || null };
    }
    this._latched.set(vaultId, 'account');
    return { ok: true, via: 'account' };
  }

  /** The latched path for an in-progress run, or null when no run of this vault has begun. */
  current(vaultId) { return this._latched.get(vaultId) || null; }

  /** The run is over (any terminal outcome): forget its choice so the next run decides afresh. */
  end(vaultId) { this._latched.delete(vaultId); }
}

module.exports = { decideMintPath, deviceRemotePath, MintPathSelector, identityEndedBy, IDENTITY_ENDED_REASONS };

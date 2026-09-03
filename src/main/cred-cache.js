'use strict';

/*
 * The main-process SFTP credential minting seam for the background scheduler, and the session host-key pin.
 *
 * The server's temporary SFTP credential is SINGLE-USE: the first successful SFTP authentication atomically
 * burns it, and any later authentication with the same credential is refused. So a credential must be minted
 * FRESH for every rclone authentication (every dispatch, and every process of a multi-step resync) and used
 * exactly once — it must never be cached and re-sent, or the second use presents a spent credential and the
 * run fails "auth-failed". (Embracing single-use also HARDENS the rail: a leaked or intercepted credential is
 * useless after its one use — stronger anti-replay than any cache-and-reuse.)
 *
 * What IS reused is the host-key PIN: the server's identity does not change per credential, so the first
 * successful fetch is pinned for the whole process and carried into every mint unchanged; a later fetch that
 * DIFFERS is a mid-session host-key change and fails closed as a mismatch (never a silent re-accept). The pin
 * survives a lock (it holds no secret); the CREDENTIAL never lingers — it is dropped the moment it is sent.
 *
 * These are load-bearing, not hygiene:
 *   - RAM ONLY, never disk; delivery to the helper is over the private parent<->child channel (`send`).
 *   - MINT-FRESH-PER-USE: never cache or re-send a credential (the single-use contract).
 *   - The plaintext password reference is zeroized once the helper has been handed the bundle.
 *   - The host-key pin is the ONLY retained state; it is carried unchanged and mismatch fails closed.
 *
 * Pure over injected effects (mint/send/clock), so mint-per-use + the session pin are unit-tested without
 * Electron, a network, or a real helper.
 */

// Turn a mint/host-key error into a status reason the scheduler can map honestly: an expired/invalid account
// session (401/403) needs a sign-in; a server that cannot be verified yet is a calm "can't verify"; anything
// else (throttle, 5xx, network) is a retryable failure. A pre-tagged reason wins.
function classifyMintError(e) {
  const reason = e && e.reason;
  if (reason === 'host-key-unverified') return 'host-key-unavailable';
  if (reason) return reason;
  const status = e && e.status;
  // A vault-password mint refusal (400) or its rate limit (429): a NON-retrying must-act, NEVER retryable
  // 'mint-failed'. The server treats a missing/wrong vault password like a wrong one and burns an attempt on a
  // limiter it SHARES with the web UI's vault open — so retrying would lock the owner out of their own vault in
  // the browser. Surfaced as 'needs-unlock' (unlock the vault so its password reaches the mint), a must-act.
  if (status === 400 || status === 429) return 'needs-unlock';
  if (status === 401 || status === 403) return 'no-session';
  return 'mint-failed';
}

class CredCache {
  /**
   * @param {object} io
   * @param {(vaultId:string)=>Promise<{user:string,password:string,hostKeys:string,expiresAt:string,host?:string,port?:number}>} io.mint  mint a fresh single-use access bundle (mintSftpAccess)
   * @param {(bundle:object)=>Promise<{ok:boolean,sub?:string}>} io.send  hand the helper the bundle (sendSftpCred). On failure it carries a typed reason enum (`sub`) only — never a raw error string.
   * @param {()=>number} [io.now]
   */
  constructor(io = {}) {
    this._mint = io.mint;
    this._send = io.send;
    this._now = io.now || (() => Date.now());
    this._pins = new Map(); // host -> pinnedHostKeys  (SESSION pin: carried unchanged; a restart re-fetches)
  }

  /**
   * Mint a FRESH single-use credential for `vaultId`, resolve the session host-key pin, and send it to the
   * helper for exactly ONE rclone authentication. Never caches or re-sends: a temp credential is spent on its
   * first use. Fail-closed — any mint/pin/send failure returns { ok:false, reason } and leaves no credential in
   * play; the plaintext password is dropped once the helper holds it.
   * @returns {Promise<{ok:true}|{ok:false,reason:string}>}
   */
  async ensureSent(vaultId) {
    let access;
    try { access = await this._mint(vaultId); }
    catch (e) { return { ok: false, reason: classifyMintError(e) }; }
    // Resolve the SESSION pin for this server: pin once, carry it unchanged, mismatch on a changed re-fetch.
    const pin = this._resolvePin(access && access.host, (access && access.hostKeys) || null);
    if (!pin.ok) { this._zeroize(access); return { ok: false, reason: pin.reason }; }
    const bundle = { ...access, hostKeys: pin.hostKeys };
    let ack;
    try { ack = await this._send(bundle); }
    catch (e) { this._zeroize(bundle); this._zeroize(access); return { ok: false, reason: (e && e.reason) || 'cred-send-failed' }; }
    // The helper now holds the obscured cred for its single run; drop our plaintext references.
    this._zeroize(bundle); this._zeroize(access);
    // Surface only the helper's TYPED reason enum (`sub`), never a raw error string it might carry — an
    // rclone/obscure failure message can hold the host or a path. A missing/untyped failure collapses to the
    // known 'cred-send-failed', which counts toward not-syncing (escalates) rather than retrying forever.
    if (!ack || !ack.ok) return { ok: false, reason: (ack && ack.sub) || 'cred-send-failed' };
    return { ok: true };
  }

  /**
   * On lock / sign-out: there is no cached credential to drop (mint-fresh-per-use holds none between runs), so
   * this only exists for the call site's symmetry — the caller clears the helper's in-flight slot in the same
   * step. The SESSION host-key pin is deliberately NOT dropped; it holds no secret and lives for the process.
   */
  clear(/* vaultId */) { /* no credential is cached to clear; the helper cred is cleared by the caller */ }

  /**
   * No credential is cached between runs (single-use is minted fresh per dispatch and used once), so there is
   * nothing to sweep; kept so the tick's call site is unchanged. Returns 0 (the caller clears the helper slot
   * only when this is > 0).
   */
  sweepExpired() { return 0; }

  /** Nothing is ever cached, so nothing is ever re-sent. */
  has() { return false; }

  // Resolve the session pin for `host`: pin the first fetch of the process, carry it unchanged thereafter, and
  // fail closed on a fetch that DIFFERS from the pin (a mid-session host-key change — surfaced, never accepted).
  _resolvePin(host, fetched) {
    if (host == null) return { ok: false, reason: 'host-key-unavailable' };
    const existing = this._pins.get(host);
    if (existing == null) {
      if (fetched == null) return { ok: false, reason: 'host-key-unavailable' };
      this._pins.set(host, fetched);
      return { ok: true, hostKeys: fetched };
    }
    if (fetched != null && fetched !== existing) return { ok: false, reason: 'host-key-mismatch' };
    return { ok: true, hostKeys: existing };
  }

  // Release the only reference to the plaintext password so it can be collected (a JS string cannot be wiped in
  // place; dropping the reference is the honest best effort).
  _zeroize(o) { if (o && typeof o.password === 'string') o.password = ''; }
}

module.exports = { CredCache };

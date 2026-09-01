'use strict';

/*
 * Refresh-before-expiry for the short-TTL Standard-vault SFTP credential.
 *
 * The temp-cred is minted with a short validity. A sync run dispatched at/near its expiry — or one that
 * opens a fresh connection after it lapses — would fail SFTP auth. This decides when the current cred is
 * too close to expiry and re-mints it BEFORE a run, so a run always starts with a valid credential.
 *
 * The token boundary is preserved exactly as at the first mint: the re-mint runs via the MAIN process's
 * account session (the injected `mint`), and only the resulting per-run bundle is handed to the daemon
 * (the injected `send`). The account session token never crosses into the daemon here.
 *
 * Fail-safe: a missing/unparseable expiry refreshes (never assume a stale cred is still valid), and a
 * refresh that cannot be delivered to the daemon throws — the caller must not proceed on a stale cred.
 */

const DEFAULT_MARGIN_MS = 2 * 60 * 1000; // refresh once under ~2 minutes of validity remains

function expiryMs(expiresAt) {
  if (!expiresAt) return null;
  const t = Date.parse(expiresAt);
  return Number.isNaN(t) ? null : t;
}

/**
 * @param {string|null} expiresAt  ISO expiry of the current cred (from mintSftpAccess), or null
 * @param {number} nowMs           current time in ms
 * @param {number} [marginMs]      refresh this long before the actual expiry (default ~2 min)
 * @returns {boolean} true if the cred is missing an expiry, already expired, or within the margin
 */
function credNeedsRefresh(expiresAt, nowMs, marginMs = DEFAULT_MARGIN_MS) {
  const exp = expiryMs(expiresAt);
  if (exp === null) return true; // unknown expiry -> refresh rather than risk a stale credential
  return nowMs >= exp - marginMs;
}

/**
 * Re-mint + re-send the SFTP cred to the daemon iff the current one is at/near expiry.
 * @param {object} o
 * @param {string|null} o.expiresAt        current cred expiry (ISO)
 * @param {number|(()=>number)} o.now      current time (ms) or a clock function
 * @param {number} [o.marginMs]
 * @param {() => Promise<{expiresAt:string,hostKeys?:string}>} o.mint  re-mint via the account session (mintSftpAccess); returns the new access bundle
 * @param {(access:object) => Promise<{ok:boolean,error?:string}>} o.send  hand the daemon the new per-run bundle (sendSftpCred)
 * @param {string} o.pinnedHostKeys  the host key pinned at the FIRST mint. REQUIRED whenever a refresh is
 *   actually performed: it is carried over into the refreshed bundle unchanged (rotate only the credential,
 *   never the pinned host identity), and a refresh refuses to proceed without it so carry-over can never be
 *   bypassed by a caller that forgets to pass it.
 * @returns {Promise<{refreshed:boolean, expiresAt:(string|null), ack?:object}>}
 */
async function refreshSftpCredIfNeeded(o) {
  const nowMs = typeof o.now === 'function' ? o.now() : o.now;
  if (!credNeedsRefresh(o.expiresAt, nowMs, o.marginMs)) return { refreshed: false, expiresAt: o.expiresAt };
  // Non-bypassable pin: a refresh MUST carry the originally pinned host key. Refuse (before minting) rather
  // than let carry-over silently degrade to whatever the re-mint re-fetched — that would be a re-TOFU at the
  // refresh boundary. This makes the carry-over a capability-level invariant, not a call-site convention.
  if (o.pinnedHostKeys == null) throw new Error('cred refresh requires the pinned host key — refusing to re-pin from a re-fetched key');
  const access = await o.mint();
  // Rotate ONLY the credential; carry the pinned host identity over unchanged, never re-fetched/re-pinned
  // here (no cry-wolf, no trust-on-first-use at refresh). A genuine host-key change is still caught fail-closed
  // at CONNECTION time by the daemon's existing pin, then resolved through the deliberate re-pin flow.
  const bundle = { ...access, hostKeys: o.pinnedHostKeys };
  const ack = await o.send(bundle);
  if (!ack || !ack.ok) throw new Error(`cred refresh could not be delivered to the daemon: ${(ack && ack.error) || 'no ack'}`);
  return { refreshed: true, expiresAt: (access && access.expiresAt) || null, ack };
}

module.exports = { credNeedsRefresh, refreshSftpCredIfNeeded, DEFAULT_MARGIN_MS };

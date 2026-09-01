'use strict';

/*
 * Mints a scoped, short-lived SFTP credential for a Standard vault, in the MAIN process, over the
 * authenticated account session. The daemon receives ONLY the resulting per-run credential bundle —
 * the account session token NEVER leaves main, and a vault-password proof (for a locked vault) is used
 * here at mint time and is likewise never handed to the daemon or rclone.
 *
 * The bundle carries exactly what one sync run needs: the SFTP host + port, the temporary username and
 * password (plaintext — the daemon obscures it into rclone's config form just-in-time), the PINNED
 * server host key(s), and the expiry. The host key is fetched over the same authenticated HTTPS session
 * (its trust anchor) and MUST be present — a missing/unavailable host key fails closed (never
 * trust-on-first-use), so rclone can verify the server rather than blindly trusting it.
 *
 * The temp credential is minted least-privilege: read+write on the ONE target vault, no navigation
 * pages, and no ability to mint further credentials — never an account-wide credential. (The exact
 * vault capability tokens are modelled from the server's own client and are confirmed against the live
 * API when an SFTP-enabled deployment is available.)
 */

const SFTP_PORT = 2222;

// A least-privilege scope granting SFTP read+write on a single vault and nothing else.
function buildSyncScope(vaultId, vaultPassword) {
  const entry = { vault_id: vaultId, caps: ['read', 'write'] };
  if (vaultPassword) entry.password = vaultPassword; // proof for a locked vault — used at mint only
  return {
    scope: { v: 1, pages: [], caps: [], vault_caps_default: [], temp: {} },
    vault_access_mode: 'selected',
    selected_vaults: [entry],
  };
}

async function postJson(fetchFn, url, sessionToken, body) {
  const res = await fetchFn(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${sessionToken}` },
    body: JSON.stringify(body),
  });
  if (!res || !res.ok) throw new Error(`mint request failed: ${(res && res.status) || 'no response'}`);
  return res.json();
}

// POST /auth/temp-credentials over the account session; return only { user, password, expiresAt }.
async function mintTempCred({ serverOrigin, sessionToken, vaultId, validityMinutes = 15, vaultPassword }, fetchFn) {
  const body = { ...buildSyncScope(vaultId, vaultPassword), validity_minutes: validityMinutes };
  const data = await postJson(fetchFn, `${serverOrigin}/auth/temp-credentials`, sessionToken, body);
  if (!data || !data.temp_username || !data.credential) throw new Error('mint response missing credentials');
  return { user: data.temp_username, password: data.credential, expiresAt: data.expires_at || null };
}

// GET /sftp/host-key over the authenticated account session (the trust anchor). Returns the server's
// FULL public key(s) to pin as rclone's host_keys. Fails closed — the server must be verifiable and we
// never trust-on-first-use — when the key is unavailable, when nothing usable is returned, OR when the
// server offers only a FINGERPRINT (a fingerprint alone cannot be used to pin the connection; the
// server must expose its full public key, or a separate step must fetch the full key and verify it
// against this fingerprint before pinning).
async function fetchHostKey({ serverOrigin, sessionToken }, fetchFn) {
  const res = await fetchFn(`${serverOrigin}/sftp/host-key`, { headers: { Authorization: `Bearer ${sessionToken}` } });
  if (!res || !res.ok) throw new Error(`host-key request failed: ${(res && res.status) || 'no response'}`);
  const data = (await res.json()) || {};
  if (data.available === false) throw new Error('SFTP host key unavailable — refusing to connect without server verification');
  const raw = data.host_keys || data.hostKeys || data.public_keys || data.public_key || data.key || null;
  const list = (Array.isArray(raw) ? raw : (raw ? [raw] : [])).map((k) => String(k).trim()).filter(Boolean);
  // Only accept actual OpenSSH public-key lines (ssh-ed25519 / ssh-rsa / ecdsa-* / sk-*), never a bare fingerprint.
  const full = list.filter((k) => /^(ssh-|ecdsa-|sk-)\S+\s+\S/.test(k));
  if (full.length === 0) {
    throw new Error('server did not provide a full SFTP host public key to pin — refusing to connect (a fingerprint alone is insufficient; no trust-on-first-use)');
  }
  return full.join(',');
}

// The full flow: mint the scoped cred + fetch the pinned host key. Returns the per-run bundle for the
// daemon. Contains no account token and no vault-password proof.
async function mintSftpAccess({ serverOrigin, sessionToken, vaultId, validityMinutes, vaultPassword }, fetchFn) {
  const hostKeys = await fetchHostKey({ serverOrigin, sessionToken }, fetchFn);
  const cred = await mintTempCred({ serverOrigin, sessionToken, vaultId, validityMinutes, vaultPassword }, fetchFn);
  let host;
  try { host = new URL(serverOrigin).hostname; } catch { throw new Error('invalid server origin'); }
  return { host, port: SFTP_PORT, user: cred.user, password: cred.password, hostKeys, expiresAt: cred.expiresAt };
}

module.exports = { buildSyncScope, mintTempCred, fetchHostKey, mintSftpAccess, SFTP_PORT };

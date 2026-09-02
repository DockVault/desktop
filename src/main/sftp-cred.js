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

// The file/folder capabilities a bidirectional sync needs on the ONE target vault, and nothing else:
// list + download + upload, plus the rename/delete/folder operations bisync performs to mirror moves,
// conflict keep-both renames, and legitimate deletions. These are the vault's own capability tokens
// (confirmed against a live SFTP-enabled deployment). It stays least-privilege — only file/folder ops on
// the single selected vault: no navigation pages, no permission changes, and no ability to mint further
// credentials. Excessive deletions are held back by the sync engine's own --max-delete guard, not by
// withholding file.delete (which the sync legitimately needs to propagate a real deletion).
const SYNC_CAPS = Object.freeze([
  'vault.see_files', 'file.download', 'file.upload', 'file.rename', 'file.delete', 'folder.create', 'folder.delete',
]);

// A least-privilege scope granting the sync capabilities on a single vault and nothing else. The vault
// applies the per-vault capabilities from `vault_caps_default`, so the sync caps are set there AND on the
// selected-vault entry (the server's own client sends them in both places); leaving vault_caps_default
// empty grants nothing and SFTP writes are denied. Global `caps`/`pages` stay empty, and only the one
// vault is selected, so the grant is confined to file/folder operations on that single vault.
function buildSyncScope(vaultId, vaultPassword) {
  const entry = { vault_id: vaultId, caps: SYNC_CAPS.slice() };
  if (vaultPassword) entry.password = vaultPassword; // proof for a locked vault — used at mint only
  return {
    scope: { v: 1, pages: [], caps: [], vault_caps_default: SYNC_CAPS.slice(), temp: {} },
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
  if (!res || !res.ok) { const e = new Error(`mint request failed: ${(res && res.status) || 'no response'}`); e.status = res && res.status; throw e; }
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
  if (!res || !res.ok) {
    const e = new Error(`host-key request failed: ${(res && res.status) || 'no response'}`);
    e.status = res && res.status;
    // A server that does not even expose this endpoint (404) cannot be verified — a calm "can't verify yet",
    // fail-closed with no trust-on-first-use, not an auth problem or a bare retry.
    if (res && res.status === 404) e.reason = 'host-key-unverified';
    throw e;
  }
  const data = (await res.json()) || {};
  // The server cannot verify itself yet (or offers nothing usable to pin): a calm "can't verify yet", not an auth
  // problem — tag it so the caller can surface it as such rather than a generic retry.
  if (data.available === false) { const e = new Error('SFTP host key unavailable — refusing to connect without server verification'); e.reason = 'host-key-unverified'; throw e; }
  const raw = data.host_keys || data.hostKeys || data.public_keys || data.public_key || data.key || null;
  const list = (Array.isArray(raw) ? raw : (raw ? [raw] : [])).map((k) => String(k).trim()).filter(Boolean);
  // Only accept actual OpenSSH public-key lines (ssh-ed25519 / ssh-rsa / ecdsa-* / sk-*), never a bare fingerprint.
  const full = list.filter((k) => /^(ssh-|ecdsa-|sk-)\S+\s+\S/.test(k));
  if (full.length === 0) {
    const e = new Error('server did not provide a full SFTP host public key to pin — refusing to connect (a fingerprint alone is insufficient; no trust-on-first-use)');
    e.reason = 'host-key-unverified';
    throw e;
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

module.exports = { buildSyncScope, mintTempCred, fetchHostKey, mintSftpAccess, SYNC_CAPS, SFTP_PORT };

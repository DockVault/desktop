'use strict';

/*
 * Mint a single-use SFTP credential for a device-granted vault, in the MAIN process, over the DEVICE
 * principal — the registered device's own secret, never the account session and never a vault password.
 * This is the device-side counterpart of the account mint in sftp-cred.js and produces the SAME per-run
 * bundle shape the credential cache and the helper already consume, so everything downstream of the
 * mint (the host-key pin, the single-use delivery, the transfer path) is unchanged.
 *
 * What the server returns with the credential, and what is done with it here:
 *   - host_public_key: the FULL OpenSSH public-key line of the SFTP server, returned by the same request
 *     that minted the credential (the device principal cannot reach the account-only host-key route). It
 *     is validated as a real public-key line — a fingerprint, an empty value, or anything else FAILS
 *     CLOSED as "cannot verify yet" (never trust-on-first-use); the caller pins it against the session
 *     pin, so a key that differs from the one already pinned is refused before any transfer.
 *   - port: the SFTP port the deployment actually serves, replacing any assumed default.
 *   - host: the deployment's advertised SFTP host when it set one, otherwise the API host the app already
 *     talks to. A malformed advertised host is refused rather than silently substituted.
 *
 * The device secret rides ONLY in the device client's Authorization header; it is never placed in the
 * bundle, a thrown error, or a log line. A refusal propagates as the device client's typed reason (a
 * revoked or expired device, a grant that needs re-proof, a cap, an unavailable host key, ...) so the
 * scheduler renders each as its own honest state; a 2xx whose body is not a usable credential is refused
 * with the fixed non-retrying literal, never retried against a broken server.
 */

const { deviceRequest, UNKNOWN_REFUSAL } = require('./device-http');

// The credential validity the device path asks for, in minutes. The server only ever SHORTENS to this
// (it clamps to its own ceiling), so an unspent credential ages out quickly; it matches the account path.
const DEVICE_MINT_VALIDITY_MINUTES = 15;

const OPENSSH_KEY_LINE = /^(ssh-|ecdsa-|sk-)\S+\s+\S/;
// A hostname or IPv4 literal (letters, digits, dots, hyphens), or a bracket-free IPv6 literal.
const HOST_SHAPE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$|^(?=.*:)[0-9A-Fa-f:]{2,45}$/;

function refused(reason) {
  const e = new Error(`device mint refused: ${reason}`); // fixed literal only — never the body or a header
  e.reason = reason;
  return e;
}

// Turn the mint response into the per-run bundle, refusing anything that is not a usable, verifiable
// credential. Exported for the unit tests; `apiHost` is the fallback SFTP host (the API's hostname).
function bundleFromMintResponse(data, apiHost) {
  if (!data || typeof data !== 'object') throw refused(UNKNOWN_REFUSAL);
  const user = data.temp_username;
  const password = data.credential;
  if (typeof user !== 'string' || !user || typeof password !== 'string' || !password) throw refused(UNKNOWN_REFUSAL);
  // The host key must be a full OpenSSH public-key line; a fingerprint, an empty string, or a non-string
  // cannot pin the connection, so the credential is unusable — fail closed as "cannot verify yet".
  const key = typeof data.host_public_key === 'string' ? data.host_public_key.trim() : '';
  if (!key || !OPENSSH_KEY_LINE.test(key)) throw refused('host-key-unavailable');
  const port = data.port;
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw refused(UNKNOWN_REFUSAL);
  let host = apiHost;
  if (data.host != null) {
    // An advertised host must look like a host. Anything else is a server misconfiguration, refused here
    // rather than silently replaced (a silent fallback would hide the misconfiguration behind a working sync).
    if (typeof data.host !== 'string' || !HOST_SHAPE.test(data.host.trim())) throw refused(UNKNOWN_REFUSAL);
    host = data.host.trim();
  }
  if (typeof host !== 'string' || !host) throw refused(UNKNOWN_REFUSAL);
  return {
    host,
    port,
    user,
    password,
    hostKeys: key,
    expiresAt: typeof data.deactivate_at === 'string' ? data.deactivate_at : null,
  };
}

/**
 * Mint a fresh single-use SFTP credential for `vaultId` over the device principal and return the per-run
 * bundle { host, port, user, password, hostKeys, expiresAt }. Throws a typed error (`reason`) on every
 * refusal: the device client's fixed literals for a non-2xx or transport failure, 'host-key-unavailable'
 * for a credential the app could not pin, and the non-retrying unknown-refusal literal for a malformed body.
 * @param {{serverOrigin:string, deviceSecret:string, vaultId:string, validityMinutes?:number}} args
 * @param {(url:string, init:object)=>Promise<{ok:boolean,status:number,json:()=>Promise<any>}>} [fetchFn]
 */
async function mintDeviceSftpAccess({ serverOrigin, deviceSecret, vaultId, validityMinutes } = {}, fetchFn) {
  if (typeof vaultId !== 'string' || !vaultId) throw refused(UNKNOWN_REFUSAL);
  let apiHost;
  try { apiHost = new URL(serverOrigin).hostname; } catch { throw refused(UNKNOWN_REFUSAL); }
  const minutes = Number.isInteger(validityMinutes) && validityMinutes > 0 ? validityMinutes : DEVICE_MINT_VALIDITY_MINUTES;
  const body = { vault_id: vaultId, validity_minutes: minutes }; // exactly these two fields, nothing else
  const data = await deviceRequest({ serverOrigin, deviceSecret, route: 'mint', body }, fetchFn);
  return bundleFromMintResponse(data, apiHost);
}

module.exports = { mintDeviceSftpAccess, bundleFromMintResponse, DEVICE_MINT_VALIDITY_MINUTES };

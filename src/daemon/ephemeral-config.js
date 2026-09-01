'use strict';

/*
 * Writes a short-lived rclone config for ONE standard-vault sync run, then removes it immediately.
 *
 * The Standard-tier SFTP temp-cred is PLAINTEXT AT REST while this file exists — rclone's "obscure" is
 * reversible obfuscation under a public key, NOT encryption — so the file handling here (plus the
 * temp-cred being narrowly scoped and short-lived) is the ENTIRE confidentiality control, never any
 * rclone-side crypto:
 *   - it lives under the caller's user-scoped userData directory, NEVER a shared temp dir;
 *   - it is created O_EXCL with an unpredictable random name at 0600, so a pre-planted file or symlink
 *     makes the create FAIL CLOSED rather than redirect the write (anti-TOCTOU);
 *   - it exists only across a single run and is unlinked in a finally (success or failure);
 *   - any orphan left by a crash mid-run is swept on the next daemon start (fail-closed if it cannot be
 *     removed — a lingering cred file is never left silently).
 * The contents (built by the caller) hold ONLY the scoped temp-cred + connection params — never a ZK
 * key, DEK, the database key, or the account session token.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');

const PREFIX = 'sync-';
const SUFFIX = '.conf';

function defaultName() { return PREFIX + crypto.randomBytes(9).toString('hex') + SUFFIX; }

/**
 * Write `contents` to a fresh 0600 ephemeral config under `runDir`, invoke `fn(configPath)`, and unlink
 * the file no matter how `fn` settles. Rejects (without leaving a file) if the O_EXCL create fails.
 * @param {string} runDir      a user-scoped dir (e.g. userData/rclone)
 * @param {string} contents    the full rclone config text (caller-formatted; temp-cred + params only)
 * @param {(configPath: string) => Promise<any>} fn
 * @param {{ nameFn?: () => string }} [opts]  test seam for the filename
 */
async function withEphemeralConfig(runDir, contents, fn, opts = {}) {
  fs.mkdirSync(runDir, { recursive: true });
  try { fs.chmodSync(runDir, 0o700); } catch { /* Windows: userData ACL is already user-only */ }
  const file = path.join(runDir, (opts.nameFn || defaultName)());
  // 'wx' = O_CREAT|O_EXCL|O_WRONLY: refuse to follow/overwrite an existing path (fail closed).
  const fd = fs.openSync(file, 'wx', 0o600);
  try { fs.writeSync(fd, contents); } finally { try { fs.closeSync(fd); } catch { /* ignore */ } }
  try { fs.chmodSync(file, 0o600); } catch { /* best effort on Windows */ }
  try {
    return await fn(file);
  } finally {
    try { fs.rmSync(file, { force: true }); } catch { /* left for the next start's crash-sweep */ }
  }
}

/**
 * Remove any orphaned ephemeral configs left by a crash mid-run. Called on daemon start. Fail-closed:
 * throws if an orphan cannot be removed, so a lingering cred file is surfaced, never left silently.
 */
function sweepStaleConfigs(runDir) {
  let entries;
  try { entries = fs.readdirSync(runDir); } catch { return 0; } // dir absent => nothing to sweep
  let n = 0;
  for (const name of entries) {
    if (name.startsWith(PREFIX) && name.endsWith(SUFFIX)) { fs.rmSync(path.join(runDir, name), { force: true }); n += 1; }
  }
  return n;
}

// Build the rclone config text for a standard-vault SFTP remote. It contains ONLY the connection
// params + the scoped temp-cred (obscured `pass`) + the PINNED server host key(s) — never a ZK key,
// DEK, the database key, or the account session token. `host_keys` pins the vault's SFTP host key so
// the server is verified (no trust-on-first-use, no MITM). Every value is single-line: any newline is
// rejected (rclone config is line-based; a newline would be config injection). Callers keep the field
// set to exactly these keys — the field-contents discipline the cred gate requires.
function formatSftpRemote(name, params) {
  const fields = {
    type: 'sftp',
    host: params.host,
    port: String(params.port),
    user: params.user,
    pass: params.obscuredPass, // rclone "obscure" form (reversible; NOT protection — the 0600 file + TTL are)
    host_keys: params.hostKeys, // pinned server host key(s): verifies the server, defeats MITM/TOFU
  };
  const safe = (v) => typeof v === 'string' || typeof v === 'number';
  if (!/^[A-Za-z0-9_-]+$/.test(String(name))) throw new Error('invalid remote name');
  for (const [k, v] of Object.entries(fields)) {
    if (!safe(v) || String(v).length === 0 || /[\r\n]/.test(String(v))) throw new Error(`invalid sftp config value for ${k}`);
  }
  const body = Object.entries(fields).map(([k, v]) => `${k} = ${v}`).join('\n');
  return `[${name}]\n${body}\n`;
}

module.exports = { withEphemeralConfig, sweepStaleConfigs, formatSftpRemote, PREFIX, SUFFIX };

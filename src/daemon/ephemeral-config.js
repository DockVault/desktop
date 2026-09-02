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
 * Atomically replace the contents of an existing ephemeral config `configPath` with `contents`, for the
 * per-process credential refresh of a multi-step resync (the server burns a temp credential on first use, so
 * each rclone process needs a fresh one written before it runs). Writes a fresh 0600 temp file in the SAME
 * directory and renames it over the target, so no rclone process can ever read a half-written config — and the
 * previous process has already exited (the runner awaits), so there is no concurrent reader. The temp shares
 * the ephemeral PREFIX/SUFFIX, so the crash-sweep still reclaims it if a crash lands between write and rename.
 * @param {string} configPath  the ephemeral config to replace (created by withEphemeralConfig)
 * @param {string} contents    the fresh rclone config text
 * @param {{ nameFn?: () => string }} [opts]  test seam for the temp filename
 */
function rewriteEphemeralConfig(configPath, contents, opts = {}) {
  const dir = path.dirname(configPath);
  const tmp = path.join(dir, (opts.nameFn || defaultName)());
  const fd = fs.openSync(tmp, 'wx', 0o600); // O_EXCL: never follow/overwrite a planted path
  try { fs.writeSync(fd, contents); } finally { try { fs.closeSync(fd); } catch { /* ignore */ } }
  try { fs.chmodSync(tmp, 0o600); } catch { /* best effort on Windows */ }
  try {
    fs.renameSync(tmp, configPath); // atomic replace within the one directory
  } catch (e) {
    try { fs.rmSync(tmp, { force: true }); } catch { /* left for the crash-sweep */ }
    throw e;
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
    // This deployment's SFTP refuses SETSTAT/setmodtime (SSH_FX_OP_UNSUPPORTED), which would fail every upload;
    // disable it. A fixed benign flag, not a credential. Consequence for change-detection: the server assigns its
    // OWN mtime (its upload timestamp), so a client mtime never survives a round-trip and mtime is unreliable for
    // comparison — the bisync runs therefore compare by SIZE (see buildBisyncArgs `--compare size`), not modtime.
    // The blind spot of size-compare — a same-size content overwrite — is NOT caught by a routine run and does NOT
    // self-heal: it is reconciled only by a DELIBERATE Repair (the zero-loss resync's byte-true `check --download`),
    // which runs on the first baseline or a user-initiated Repair, never automatically. (Closing it in routine sync
    // needs a server that persists a client mtime or exposes a hash — a vault-side change, tracked as a follow-up.)
    set_modtime: 'false',
  };
  const safe = (v) => typeof v === 'string' || typeof v === 'number';
  if (!/^[A-Za-z0-9_-]+$/.test(String(name))) throw new Error('invalid remote name');
  for (const [k, v] of Object.entries(fields)) {
    if (!safe(v) || String(v).length === 0 || /[\r\n]/.test(String(v))) throw new Error(`invalid sftp config value for ${k}`);
  }
  const body = Object.entries(fields).map(([k, v]) => `${k} = ${v}`).join('\n');
  return `[${name}]\n${body}\n`;
}

module.exports = { withEphemeralConfig, rewriteEphemeralConfig, sweepStaleConfigs, formatSftpRemote, PREFIX, SUFFIX };

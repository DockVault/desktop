'use strict';

/*
 * Pure helpers for enabling sync of a Standard vault to a local folder — the rules, with no IO. The
 * main process performs the native folder pick, resolves symlinks, sets permissions, wraps the store
 * with the OS secret store, and writes disk; this module gives it the checks to enforce and the shape
 * of the credential-free config record.
 *
 * Two safety ideas drive it:
 *   - The remote (server) path is DERIVED from the chosen vault, never typed by a person or a page.
 *     A whole-vault sync targets the vault's own directory — a single non-empty path segment — and
 *     never the connection root (an empty or root remote is the opaque permission error we want to
 *     make structurally impossible). The value is normalized and re-validated as defence in depth.
 *   - The local folder receives readable, decrypted copies of the vault's files, so the chosen target
 *     is checked against containment and footgun rules: never a system location, the home root, or the
 *     app's own data dir; never overlapping another vault's folder (two syncs over one tree corrupt
 *     each other); and a folder inside a consumer cloud-sync root is flagged, because two sync engines
 *     over the same files cause conflict pileups.
 *
 * The config record holds only operational metadata. It is credential-free by construction: the SFTP
 * credential is minted fresh per run over the private channel and is NEVER persisted here.
 */

const path = require('node:path');

// The only fields the persisted config may carry. Anything credential-adjacent is rejected outright.
const CONFIG_FIELDS = Object.freeze(['vaultId', 'vaultName', 'localFolder', 'remotePath', 'enabled', 'consented']);
const FORBIDDEN_CONFIG_FIELDS = Object.freeze([
  'password', 'credential', 'cred', 'secret', 'token', 'accessToken', 'sessionToken',
  'hostKey', 'hostKeys', 'key', 'passphrase', 'obscured',
]);

// A path segment is unsafe if empty, a traversal marker, or carries a separator, null, or control char.
function isUnsafeSegment(seg) {
  if (typeof seg !== 'string' || seg.length === 0) return true;
  if (seg === '.' || seg === '..') return true;
  // eslint-disable-next-line no-control-regex
  return /[\\/\x00-\x1f]/.test(seg);
}

/**
 * Normalize + validate the server-side directory a whole-vault sync targets, into a single safe
 * path segment. Throws on anything that could escape or resolve to the connection root.
 * @param {string} vaultDir the server-canonical vault directory name (from the vault listing)
 * @returns {string} the validated single-segment remote path
 */
function remotePathForVault(vaultDir) {
  if (typeof vaultDir !== 'string') throw new Error('remote path needs the vault directory name');
  // Collapse any accidental separators/dot-segments to their bare parts, then insist it is exactly
  // one safe, non-empty, non-traversal segment — never nested, never root, never a climb.
  const parts = vaultDir.split(/[\\/]+/).filter((p) => p !== '');
  if (parts.length !== 1 || isUnsafeSegment(parts[0])) {
    throw new Error('a whole-vault sync targets exactly one vault directory segment');
  }
  return parts[0];
}

// ---- local target classification -------------------------------------------------------------
// Consumer cloud-sync roots: a folder inside one of these double-syncs the same files.
const CLOUD_MARKERS = Object.freeze([
  /(^|[\\/])onedrive([\\/]|$| )/i,
  /(^|[\\/])dropbox([\\/]|$)/i,
  /(^|[\\/])google ?drive([\\/]|$)/i,
  /(^|[\\/])(icloud ?drive|com~apple~clouddocs)([\\/]|$)/i,
]);

// Case-insensitive filesystems (Windows, default macOS volumes) would otherwise let a differently
// cased path evade a containment check — `C:\Users\x\Docs` vs `...\docs`, or a system-root whose
// casing differs from the dialog's. When `ci` is set, compare case-folded.
function fold(p, ci) { return ci ? p.toLowerCase() : p; }

// True when a and b are the same directory, or one contains the other (either nesting corrupts).
function overlaps(a, b, ci = false) {
  if (!a || !b) return false;
  const na = fold(path.resolve(a), ci);
  const nb = fold(path.resolve(b), ci);
  if (na === nb) return true;
  const aSep = na.endsWith(path.sep) ? na : na + path.sep;
  const bSep = nb.endsWith(path.sep) ? nb : nb + path.sep;
  return na.startsWith(bSep) || nb.startsWith(aSep);
}

// True when `child` is the same as or nested inside `ancestor`.
function isWithin(child, ancestor, ci = false) {
  if (!child || !ancestor) return false;
  const c = fold(path.resolve(child), ci);
  const a = fold(path.resolve(ancestor), ci);
  if (c === a) return true;
  const aSep = a.endsWith(path.sep) ? a : a + path.sep;
  return c.startsWith(aSep);
}

/**
 * Classify a RESOLVED absolute local folder against the containment + footgun rules.
 * @param {string} resolvedAbs the chosen folder AFTER symlink resolution (the real target)
 * @param {object} ctx
 * @param {string} ctx.home          the user's home directory
 * @param {string} ctx.userData      the app's own data directory
 * @param {string[]} [ctx.refuseRoots] platform system roots to refuse (e.g. the OS + program dirs)
 * @param {string[]} [ctx.existingFolders] folders already in use by other vault syncs
 * @param {RegExp[]} [ctx.cloudMarkers] override for the consumer cloud-sync patterns
 * @param {boolean} [ctx.caseInsensitive] fold case in containment checks (Windows / default macOS)
 * @returns {{ok:boolean, reason?:string, warn?:string}}
 */
function classifyLocalTarget(resolvedAbs, ctx = {}) {
  if (typeof resolvedAbs !== 'string' || resolvedAbs.trim() === '') return { ok: false, reason: 'no-folder' };
  if (!path.isAbsolute(resolvedAbs)) return { ok: false, reason: 'not-absolute' };
  const target = path.resolve(resolvedAbs);
  const ci = !!ctx.caseInsensitive;
  const home = ctx.home ? path.resolve(ctx.home) : null;

  // Never a filesystem root itself (C:\, D:\, /) — a whole drive or volume top is never a sync folder,
  // and a root on a different drive than home slips past the home-ancestor check below.
  if (path.parse(target).root === target) return { ok: false, reason: 'filesystem-root' };
  // Never the home root itself, nor an ancestor of it (which would include far too much).
  if (home && (target === home || isWithin(home, target, ci))) return { ok: false, reason: 'home-root-or-above' };
  // Never the app's own data/config directory.
  if (ctx.userData && isWithin(target, ctx.userData, ci)) return { ok: false, reason: 'app-data-dir' };
  // Never a system location.
  for (const root of ctx.refuseRoots || []) {
    if (isWithin(target, root, ci)) return { ok: false, reason: 'system-location' };
  }
  // Never overlap another vault's sync folder (two syncs over one tree corrupt each other).
  for (const other of ctx.existingFolders || []) {
    if (overlaps(target, other, ci)) return { ok: false, reason: 'overlaps-another-sync' };
  }
  // A folder inside a consumer cloud-sync root is allowed but flagged.
  const markers = ctx.cloudMarkers || CLOUD_MARKERS;
  for (const re of markers) {
    if (re.test(target)) return { ok: true, warn: 'inside-cloud-sync' };
  }
  return { ok: true };
}

// The system locations a sync folder must never be placed in or under, per platform. Pure so the
// set is reviewable and testable; the caller passes the current platform and environment.
function platformRefuseRoots(platform, env = {}) {
  if (platform === 'win32') {
    return [
      env.SystemRoot || env.windir || 'C:\\Windows',
      env.ProgramFiles || 'C:\\Program Files',
      env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)',
      env.ProgramData || 'C:\\ProgramData',
    ];
  }
  if (platform === 'darwin') {
    return ['/System', '/Library', '/usr', '/bin', '/sbin', '/Applications', '/private'];
  }
  // Linux and other POSIX.
  return ['/usr', '/bin', '/sbin', '/etc', '/boot', '/lib', '/lib64', '/opt', '/var', '/proc', '/sys', '/dev', '/run'];
}

// ---- config record (credential-free) ---------------------------------------------------------
/**
 * Build a credential-free config record from operational fields only. Throws if any
 * credential-adjacent field is present, so a credential can never be persisted to the config.
 */
function makeConfigEntry(o = {}) {
  for (const k of Object.keys(o)) {
    if (FORBIDDEN_CONFIG_FIELDS.includes(k)) throw new Error(`config must not carry a credential field: ${k}`);
    if (!CONFIG_FIELDS.includes(k)) throw new Error(`unexpected config field: ${k}`);
  }
  if (!o.vaultId || typeof o.vaultId !== 'string') throw new Error('config needs a vaultId');
  if (!o.vaultName || typeof o.vaultName !== 'string') throw new Error('config needs a vaultName');
  if (!o.localFolder || typeof o.localFolder !== 'string' || !path.isAbsolute(o.localFolder)) throw new Error('config needs an absolute localFolder');
  if (!o.remotePath || typeof o.remotePath !== 'string') throw new Error('config needs a remotePath');
  // `consented` records that the two-way readable-copies consent was given at set-up. It defaults false,
  // so a config written before this existed reads as not-yet-consented and the first upload re-asks — the
  // consent is never assumed, only ever recorded when it was actually given.
  return { vaultId: o.vaultId, vaultName: o.vaultName, localFolder: path.resolve(o.localFolder), remotePath: o.remotePath, enabled: o.enabled !== false, consented: !!o.consented };
}

// Guard used before persisting or shipping a record anywhere: no credential-adjacent field, ever.
function assertCredFree(entry) {
  if (!entry || typeof entry !== 'object') return;
  for (const k of Object.keys(entry)) {
    if (FORBIDDEN_CONFIG_FIELDS.includes(k)) throw new Error(`credential field must never reach the config: ${k}`);
  }
}

// Add or replace the entry for a vault; the store is keyed by vaultId.
function upsertEntry(list, entry) {
  assertCredFree(entry);
  const rest = (Array.isArray(list) ? list : []).filter((e) => e.vaultId !== entry.vaultId);
  return [...rest, entry];
}

function removeEntry(list, vaultId) {
  return (Array.isArray(list) ? list : []).filter((e) => e.vaultId !== vaultId);
}

module.exports = {
  CONFIG_FIELDS, FORBIDDEN_CONFIG_FIELDS, CLOUD_MARKERS,
  remotePathForVault, classifyLocalTarget, overlaps, isWithin, platformRefuseRoots,
  makeConfigEntry, assertCredFree, upsertEntry, removeEntry,
};

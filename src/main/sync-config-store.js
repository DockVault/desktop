'use strict';

/*
 * Persist the per-vault sync configuration to disk in the app's data directory, wrapped by the OS
 * secret store when one is available.
 *
 * The config holds operational metadata only — vault id/name, the chosen local folder, the derived
 * remote path, and an enabled flag — and never a credential (the SFTP credential is minted fresh per
 * run over the private channel). Because it carries no secret, a platform with no real secret store
 * degrades to a permission-restricted plaintext file rather than disabling sync; the wrapping, when
 * present, uses the OS secret store's own key and is never derived from or mixed with any vault,
 * database, or session key (a separate key domain).
 *
 * Defence in depth: every entry is rebuilt through the credential-free config constructor on both
 * save and load, so a credential can never be written, and a tampered file can never smuggle an
 * unexpected or credential-adjacent field back into the running app.
 */

const fs = require('node:fs');
const path = require('node:path');
const { makeConfigEntry, assertCredFree } = require('./sync-config');

const FILE = 'sync-config.json';
const FILE_MODE = 0o600; // owner read/write only (honoured on POSIX; NTFS uses its own ACLs)

function configPath(dir) { return path.join(dir, FILE); }

// Rebuild each raw entry through the credential-free constructor; drop anything that does not
// validate (a corrupt or tampered row is skipped, never crashes boot and never leaks a bad field in).
function sanitize(list) {
  const out = [];
  for (const raw of Array.isArray(list) ? list : []) {
    try { out.push(makeConfigEntry(raw)); } catch { /* drop an invalid/tampered entry */ }
  }
  return out;
}

/**
 * Read the config with its readability STATUS, distinguishing "absent" (no file yet — genuinely
 * not set up) from "undecryptable"/"unparseable" (a file exists but cannot be read this boot, e.g. a
 * locked/changed OS keyring, or a truncated file from a crash mid-write). Callers must never treat an
 * unreadable file as absent — doing so would lose real settings and silently downgrade encrypted to
 * plaintext on the next save.
 * @returns {{status:'absent'|'ok'|'undecryptable'|'unparseable'|'unreadable-io', entries:Array}}
 */
function readConfigState(safeStorage, dir) {
  let text;
  try { text = fs.readFileSync(configPath(dir), 'utf8'); }
  catch (e) { return { status: (e && e.code === 'ENOENT') ? 'absent' : 'unreadable-io', entries: [] }; }
  let env;
  try { env = JSON.parse(text); } catch { return { status: 'unparseable', entries: [] }; }
  if (env && env.enc === true) {
    if (!safeStorage || !safeStorage.isEncryptionAvailable || !safeStorage.isEncryptionAvailable()) {
      return { status: 'undecryptable', entries: [] }; // encrypted on disk, but no secret store this boot
    }
    try {
      const json = safeStorage.decryptString(Buffer.from(String(env.data || ''), 'base64'));
      return { status: 'ok', entries: sanitize(JSON.parse(json)) };
    } catch { return { status: 'undecryptable', entries: [] }; }
  }
  if (env && env.enc === false) {
    try { return { status: 'ok', entries: sanitize(JSON.parse(String(env.data || '[]'))) }; }
    catch { return { status: 'unparseable', entries: [] }; }
  }
  return { status: 'unparseable', entries: [] }; // unknown envelope shape
}

// An existing file we could not read — never to be treated as absent, never to be overwritten.
function isUnreadable(status) {
  return status === 'undecryptable' || status === 'unparseable' || status === 'unreadable-io';
}

/**
 * Load the sync config list. Returns [] when the file is absent OR unreadable (fail-safe: never a
 * thrown boot error). Use readConfigState when the caller must distinguish the two — the save path
 * and the enable flow do, so they never overwrite an unreadable file.
 */
function loadConfig(safeStorage, dir) {
  return readConfigState(safeStorage, dir).entries;
}

/**
 * Save the sync config list. Wraps with the OS secret store when encryption is available; otherwise
 * writes a permission-restricted plaintext file (the config is not a secret). Every entry is asserted
 * credential-free before anything touches disk. Refuses to overwrite an existing-but-unreadable file
 * (a locked keyring or a corrupt file) — overwriting would lose the real settings and downgrade
 * encrypted to plaintext. Writes a temp file then renames, so a crash mid-write cannot truncate the
 * live file. Returns { encrypted }; throws with code CONFIG_UNREADABLE when refusing.
 */
function saveConfig(safeStorage, dir, list) {
  const cur = readConfigState(safeStorage, dir);
  if (isUnreadable(cur.status)) {
    const err = new Error('the existing sync configuration could not be read; refusing to overwrite it');
    err.code = 'CONFIG_UNREADABLE';
    err.status = cur.status;
    throw err;
  }
  const clean = sanitize(list);
  for (const e of clean) assertCredFree(e);
  const json = JSON.stringify(clean);
  const encAvailable = !!(safeStorage && safeStorage.isEncryptionAvailable && safeStorage.isEncryptionAvailable());
  const env = encAvailable
    ? { v: 1, enc: true, data: safeStorage.encryptString(json).toString('base64') }
    : { v: 1, enc: false, data: json };
  fs.mkdirSync(dir, { recursive: true });
  const tmp = configPath(dir) + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(env), { mode: FILE_MODE });
  try { fs.chmodSync(tmp, FILE_MODE); } catch { /* best-effort where the platform honours it */ }
  fs.renameSync(tmp, configPath(dir)); // atomic replace on the same filesystem
  try { fs.chmodSync(configPath(dir), FILE_MODE); } catch { /* best-effort */ }
  return { encrypted: encAvailable };
}

module.exports = { loadConfig, saveConfig, readConfigState, isUnreadable, configPath, FILE };

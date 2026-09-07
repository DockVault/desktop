'use strict';

/*
 * Resolves the configured vault server origin (the address the shell forwards the UI's API calls to).
 *
 * The server address is not a secret (it is just where the vault lives), so it is persisted in plain
 * app config, not the OS keychain — only the session token goes in the keychain. A development
 * override via the DOCKVAULT_SERVER environment variable takes precedence, so the shell can be run
 * against a local instance without a stored config.
 *
 * normalizeServer enforces transport safety: a remote server must use https; plain http is allowed
 * only for loopback (localhost / 127.0.0.1 / [::1]) during development.
 */

const fs = require('node:fs');
const path = require('node:path');

const LOOPBACK = /^(localhost|127\.0\.0\.1|\[::1\]|::1)$/i;

function normalizeServer(input) {
  const u = new URL(String(input)); // throws on a malformed value
  if (u.protocol !== 'http:' && u.protocol !== 'https:') {
    throw new Error('server URL must use http or https');
  }
  const isLoopback = LOOPBACK.test(u.hostname);
  if (u.protocol === 'http:' && !isLoopback) {
    throw new Error('a remote server must use https');
  }
  const origin = u.origin;                          // scheme://host[:port]
  const wssOrigin = origin.replace(/^http/i, 'ws');  // ws(s)://host[:port]
  return { origin, wssOrigin, isLoopback };
}

function configFile(userDataDir) { return path.join(userDataDir, 'server-config.json'); }

/**
 * The saved server setting as a fact with a status, never a bare null that hides why:
 *   { status: 'absent' }                      no file — the first run, nothing decided yet
 *   { status: 'ok', origin }                  a saved, valid origin
 *   { status: 'unreadable' }                  a file exists but cannot be trusted (truncated, malformed,
 *                                             not an https origin, unreadable) — NOT absent: the app must
 *                                             not treat it as "nothing saved" and quietly write over it
 * Unreadable is kept apart from absent for the same reason the other stores do it: a person's setting
 * that cannot be read is still their setting until they say otherwise.
 */
function readSavedServer(userDataDir) {
  let raw;
  try { raw = fs.readFileSync(configFile(userDataDir), 'utf8'); } catch (e) {
    return (e && e.code === 'ENOENT') ? { status: 'absent' } : { status: 'unreadable' };
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed.origin !== 'string') return { status: 'unreadable' };
    return { status: 'ok', origin: normalizeServer(parsed.origin).origin };
  } catch { return { status: 'unreadable' }; }
}

/**
 * Everything that decides which server is in force, so the shell can be honest about it:
 *   { status: 'env' | 'ok' | 'absent' | 'unreadable', origin, envOrigin, fileOrigin, envOverrides }
 * The DOCKVAULT_SERVER variable still wins (a development convenience), but when it and a saved
 * setting both exist and differ, envOverrides is true so the tray can say which one is used — a
 * saved setting silently ignored would be a lie. An env value that does not normalise is ignored.
 */
// The DOCKVAULT_SERVER variable is a development convenience. An installed app never honours it
// (main switches this off once at startup for a packaged build), so nothing in a person's
// environment can quietly re-point the app; the saved setting alone decides.
let envOverrideAllowed = true;
function setEnvOverrideAllowed(allowed) { envOverrideAllowed = allowed === true; }

function readServerConfigState(userDataDir, env = process.env) {
  let envOrigin = null;
  if (envOverrideAllowed && env.DOCKVAULT_SERVER) {
    try { envOrigin = normalizeServer(env.DOCKVAULT_SERVER).origin; } catch { envOrigin = null; }
  }
  const saved = readSavedServer(userDataDir);
  const fileOrigin = saved.status === 'ok' ? saved.origin : null;
  if (envOrigin) {
    return { status: 'env', origin: envOrigin, envOrigin, fileOrigin, envOverrides: !!(fileOrigin && fileOrigin !== envOrigin) || saved.status === 'unreadable' };
  }
  return { status: saved.status, origin: fileOrigin, envOrigin: null, fileOrigin, envOverrides: false };
}

/** The configured server origin, or null if none. Env override wins. */
function readServerOrigin(userDataDir) {
  return readServerConfigState(userDataDir).origin;
}

/**
 * Persist a user-entered server URL (validated). Returns the normalized origin. Written through a
 * temporary file and a rename so a crash mid-write can never leave a truncated file that reads as
 * "not configured" (or as unreadable) on the next launch.
 */
function writeServerOrigin(userDataDir, input) {
  const { origin } = normalizeServer(input);
  fs.mkdirSync(userDataDir, { recursive: true });
  const file = configFile(userDataDir);
  const partial = `${file}.tmp`;
  fs.writeFileSync(partial, JSON.stringify({ origin }) + '\n', { mode: 0o600 });
  fs.renameSync(partial, file);
  return origin;
}

/** Forget the saved server (a server switch): a missing file is already the wanted state. */
function removeServerOrigin(userDataDir) {
  try { fs.unlinkSync(configFile(userDataDir)); } catch (e) { if (!e || e.code !== 'ENOENT') throw e; }
}

module.exports = { normalizeServer, readSavedServer, readServerConfigState, readServerOrigin, writeServerOrigin, removeServerOrigin, setEnvOverrideAllowed, configFile };

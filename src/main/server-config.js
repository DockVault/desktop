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

/** The configured server origin, or null if none. Env override wins. */
function readServerOrigin(userDataDir) {
  if (process.env.DOCKVAULT_SERVER) {
    try { return normalizeServer(process.env.DOCKVAULT_SERVER).origin; } catch { return null; }
  }
  try {
    const raw = JSON.parse(fs.readFileSync(configFile(userDataDir), 'utf8'));
    if (raw && raw.origin) return normalizeServer(raw.origin).origin;
  } catch { /* not configured yet */ }
  return null;
}

/** Persist a user-entered server URL (validated). Returns the normalized origin. */
function writeServerOrigin(userDataDir, input) {
  const { origin } = normalizeServer(input);
  fs.mkdirSync(userDataDir, { recursive: true });
  fs.writeFileSync(configFile(userDataDir), JSON.stringify({ origin }));
  return origin;
}

module.exports = { normalizeServer, readServerOrigin, writeServerOrigin };

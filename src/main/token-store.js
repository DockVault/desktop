'use strict';

/*
 * Durable, encrypted store for the account session (the server bearer token plus the small,
 * non-secret session metadata the UI keeps alongside it).
 *
 * The session is encrypted with the OS keychain via Electron's safeStorage and written to the app
 * data directory. It is FAIL-CLOSED on a non-secure backend: on a system where safeStorage would
 * fall back to a hardcoded key ("basic_text", e.g. a Linux session with no Secret Service), the
 * session is NOT written to disk at all — the caller keeps it in memory for the session only and the
 * user signs in again next launch, rather than a token sitting on disk under a public constant.
 *
 * The keychain backend is injected so the fail-closed logic and the round-trip are unit-testable
 * without a live keychain; the real Electron safeStorage is passed in at runtime.
 */

const fs = require('node:fs');
const path = require('node:path');

const FILE = 'session.bin';

function backendName(safeStorage) {
  try {
    if (safeStorage && typeof safeStorage.getSelectedStorageBackend === 'function') {
      return safeStorage.getSelectedStorageBackend();
    }
  } catch { /* fall through */ }
  return 'unknown';
}

/** True only when the keychain is available AND not the hardcoded-key fallback. */
function isSecureBackend(safeStorage) {
  try {
    if (!safeStorage || typeof safeStorage.isEncryptionAvailable !== 'function') return false;
    if (!safeStorage.isEncryptionAvailable()) return false;
    if (backendName(safeStorage) === 'basic_text') return false; // hardcoded key — treated as insecure
    return true;
  } catch { return false; }
}

function storePath(dir) { return path.join(dir, FILE); }

/**
 * Persist the session bundle, encrypted, only if the backend is secure. Never throws for a
 * non-secure backend — it reports { persisted:false } so the caller can fall back to session-only.
 * @returns {{persisted: boolean, backend: string}}
 */
function persistSession(safeStorage, dir, bundle) {
  const backend = backendName(safeStorage);
  if (!isSecureBackend(safeStorage)) return { persisted: false, backend };
  const enc = safeStorage.encryptString(JSON.stringify(bundle));
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(storePath(dir), enc, { mode: 0o600 });
  return { persisted: true, backend };
}

/** Load + decrypt the session bundle, or null (no store, non-secure backend, or a decrypt failure). */
function loadSession(safeStorage, dir) {
  try {
    if (!isSecureBackend(safeStorage)) return null;
    const enc = fs.readFileSync(storePath(dir));
    return JSON.parse(safeStorage.decryptString(enc));
  } catch { return null; }
}

/** Remove the stored session (sign-out / OS-lock / uninstall). Best-effort. */
function clearSession(dir) {
  try { fs.rmSync(storePath(dir), { force: true }); } catch { /* best effort */ }
}

module.exports = { isSecureBackend, persistSession, loadSession, clearSession, backendName };

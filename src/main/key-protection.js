'use strict';

/*
 * Key-protection posture (main process): how strongly the OS can protect secrets at rest. This decides
 * what may be persisted or synced in the background, and (later) how the unlock experience reads. It
 * does NOT decide whether the app runs — the app is usable in every mode.
 *
 * Three modes:
 *  - Mode C (none): the platform secret store is unavailable, or it is plaintext (Linux 'basic_text').
 *    The app still runs, in a memory-only degraded mode: the interface loads, sign-in and unlock work,
 *    but nothing sensitive is written at rest (the session is re-entered each launch, the encrypted
 *    state store is not created, and background zero-knowledge sync and any persist-unwrapped-key /
 *    stay-unlocked path are refused). Zero-knowledge keys are memory-only in every mode, so this is
 *    the web app's own model and is safe — it just cannot remember anything across launches.
 *  - Mode A (software-backed): a real OS keychain — Windows DPAPI, the macOS login keychain, or a Linux
 *    secret service (gnome-libsecret / kwallet). Secrets are encrypted at rest under the OS user.
 *  - Mode B (hardware-backed): a Secure Enclave / TPM-bound keychain. HARDWARE-BACKED ONLY, and NEVER
 *    asserted on Linux. It is claimed solely on a POSITIVE hardware signal; without a verified signal
 *    the posture reports Mode A rather than over-claiming hardware protection.
 *
 * safeStorage cannot itself report whether a backend is hardware-backed, so Mode B is gated on an
 * injected platform probe (Windows Hello / TPM, Secure Enclave) that a later phase supplies; until then
 * a capable desktop platform reads as Mode A. The distinction enforced NOW is whether a real secret
 * store exists (persistence + background sync allowed) vs. not (memory-only) — which safeStorage reports.
 */

const MODE = { HARDWARE: 'B', SOFTWARE: 'A', NONE: 'C' };

/**
 * @param {object} safeStorage  Electron safeStorage (isEncryptionAvailable, getSelectedStorageBackend)
 * @param {string} platform     process.platform ('win32' | 'darwin' | 'linux' | ...)
 * @param {() => boolean} [hwProbe]  a verified hardware-backing signal (a later phase); absent => Mode A
 * @returns {'A'|'B'|'C'}
 */
function detectMode(safeStorage, platform, hwProbe) {
  if (!safeStorage || typeof safeStorage.isEncryptionAvailable !== 'function' || !safeStorage.isEncryptionAvailable()) {
    return MODE.NONE; // no OS encryption available at all -> hard refuse
  }
  if (platform === 'linux') {
    // The one Linux backend that is not real encryption is 'basic_text'. Hardware backing is never
    // asserted on Linux, so any real secret-service backend is Mode A.
    let backend = null;
    try { backend = safeStorage.getSelectedStorageBackend && safeStorage.getSelectedStorageBackend(); } catch { backend = null; }
    if (backend === 'basic_text') return MODE.NONE;
    return MODE.SOFTWARE;
  }
  // Windows / macOS: DPAPI / Keychain is at least software-backed. Claim hardware ONLY on a verified
  // positive probe — never over-claim a protection the app cannot confirm.
  let hw = false;
  try { hw = typeof hwProbe === 'function' && hwProbe() === true; } catch { hw = false; }
  return hw ? MODE.HARDWARE : MODE.SOFTWARE;
}

// A real OS secret store exists (Mode A or B): at-rest persistence and background zero-knowledge sync
// are allowed. Mode C has none, so those are refused (the app still runs, memory-only).
function hasSecureStore(mode) { return mode === MODE.HARDWARE || mode === MODE.SOFTWARE; }
function isHardwareBacked(mode) { return mode === MODE.HARDWARE; }

module.exports = { MODE, detectMode, hasSecureStore, isHardwareBacked };

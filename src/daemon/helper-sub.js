'use strict';

// Map a helper-prep failure to ONE bounded, leak-safe sub-reason for the credential ack. The runner tags its
// own failures on the thrown error (err.subReason: checksum-mismatch / binary-missing / spawn-failed /
// version-mismatch / obscure-failed) — those pass through verbatim. A malformed rclone config throw is named
// here as the FIXED enum 'config-format-failed': its message is TESTED (never surfaced), so a bad host/user/
// remote value cannot leak through the ack. Anything else is the generic 'prepare-failed'. This NEVER returns
// the raw error message, path, or checksum — the only outputs are the fixed enum literals.
function deriveCredSub(err) {
  if (err && typeof err.subReason === 'string') return err.subReason;
  const msg = String((err && err.message) || '');
  return /invalid sftp config value|invalid remote name/i.test(msg) ? 'config-format-failed' : 'prepare-failed';
}

module.exports = { deriveCredSub };

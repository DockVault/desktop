'use strict';

/*
 * Classifies the outcome of one `rclone bisync` child into a single TYPED result plus a resync-required
 * decision. The point is an honest, specific state — never a generic "not-ok", and never a silent swallow
 * of a data-safety event.
 *
 * Each value is DISTINCT on purpose. The daemon relays only this typed result to the main process (not
 * raw rclone output), so a distinction not captured here cannot be re-derived downstream: the
 * human-facing layer maps each value to its own message, and notification urgency (must-act vs routine)
 * is read off it. Collapsing two outcomes into one value would erase, e.g., the difference between a
 * server setup hiccup and an active interception.
 *
 * The signatures key on rclone's own emitted phrases (observed against a real server). They are matched
 * defensively — case-insensitive substrings — and evaluated in SEVERITY order so the most serious event
 * wins when a run emits more than one.
 */

// Typed run-state `result` values. Green = a clean run; every other value is a non-green attention state.
const RESULT = Object.freeze({
  OK: 'ok',                                          // green: a clean incremental run
  RESYNC_OK: 'resync-ok',                            // green: a clean, user-initiated resync
  CONFLICT_KEEP_BOTH: 'conflict-keep-both',          // run completed, both sides kept, no byte lost — attention
  ABORT_EXCESSIVE_DELETE: 'abort-excessive-delete',  // safety abort: too many DELETES; server copy intact; resync required
  ABORT_ALL_CHANGED: 'abort-all-changed',            // safety abort: ALL files on one side changed (a different guard); resync required
  NEEDS_RESYNC: 'needs-resync',                      // missing prior listing / critical error; resync required
  HOST_KEY_MISMATCH: 'host-key-mismatch',            // pinned != presented (MITM signal) — block, no auto-TOFU
  AUTH_FAILED: 'auth-failed',                        // SFTP auth refused (e.g. a lapsed credential) — sign-in-needed
  PATH_TOO_LONG: 'path-too-long',                    // a file skipped for OS path length — surface which one
  ERROR: 'error',                                    // any other non-zero exit
});

// The can't-verify-yet host-key state (host-key-unverified) is decided BEFORE a run — where the server's
// full host key cannot be obtained/pinned and the run never launches — so it is not a bisync-exit outcome
// and is not produced here. It is a distinct typed result surfaced by the credential/prep path.
const HOST_KEY_UNVERIFIED = 'host-key-unverified';

const SIG = Object.freeze({
  // "Safety abort: too many deletes (>50%, N of M) ... Run with --force if desired. Bisync aborted." NARROW to
  // the DELETE wording — the bare "safety abort" is shared with the all-changed guard below, a different abort.
  excessiveDelete: /too many deletes|max delete/i,
  // "Safety abort: all files were changed on Path1/Path2 ... Run with --force". A DIFFERENT safety guard than the
  // delete cap: every file on one side read as changed (here, mtime drift under set_modtime=false), NOT deletions.
  allChanged: /all files were changed|all files changed/i,
  // "cannot find prior Path1 or Path2 listings ... Must run --resync to recover." / a bisync critical error.
  needsResync: /must run --resync|cannot find prior|critical error/i,
  // A pinned-host-key failure against the configured host_keys. Deliberately NARROW: it matches an actual
  // key MISMATCH ("knownhosts: key mismatch" matches via `key mismatch`), not a bare mention of knownhosts
  // — a false MITM alarm on a benign line desensitizes users to a real one (anti-cry-wolf).
  hostKeyMismatch: /host key mismatch|key mismatch|host key .*(changed|does ?n[o']?t match)/i,
  // SFTP authentication refused — the ssh handshake got past host-key verification but auth failed (e.g. a
  // lapsed/rotated temp-cred): "ssh: unable to authenticate, attempted methods [none password] ...".
  authFailed: /unable to authenticate|no supported methods remain|permission denied \(publickey,?password/i,
  // An individual file rejected for path/name length (Windows and POSIX wordings).
  pathTooLong: /path too long|file ?name too long|filename or extension is too long|name too long/i,
  // A keep-both conflict rename (bisync's safe default): both copies preserved, neither overwritten.
  conflict: /\.conflict\d/i,
});

function haystack(stdout, stderr) { return String(stdout == null ? '' : stdout) + '\n' + String(stderr == null ? '' : stderr); }

/**
 * @param {{code:number, stdout?:string, stderr?:string, resync?:boolean}} o
 * @returns {{result:string, resyncRequired:(boolean|null), needsAttention:boolean}}
 *   resyncRequired is `true`/`false` when the outcome decides it, or `null` to mean "leave the prior
 *   value unchanged" (a connection-level block or a plain error does not establish or clear a baseline).
 */
function classifyBisyncOutcome(o) {
  const text = haystack(o.stdout, o.stderr);

  // Most serious first: an identity-change (MITM) signal and a data-safety abort outrank a plain error.
  if (SIG.hostKeyMismatch.test(text)) return { result: RESULT.HOST_KEY_MISMATCH, resyncRequired: null, needsAttention: true };
  // A connection-level auth failure (e.g. a credential that lapsed mid-run): surface it as its own state so
  // the status layer can prompt sign-in, and leave the resync baseline untouched. Fail-closed, never silent.
  if (SIG.authFailed.test(text)) return { result: RESULT.AUTH_FAILED, resyncRequired: null, needsAttention: true };
  if (SIG.excessiveDelete.test(text)) return { result: RESULT.ABORT_EXCESSIVE_DELETE, resyncRequired: true, needsAttention: true };
  // A different safety abort than the delete cap — all files on one side read as changed. Must NOT be labelled as
  // a large DELETE (its own honest status); still a fail-closed abort requiring a deliberate resync.
  if (SIG.allChanged.test(text)) return { result: RESULT.ABORT_ALL_CHANGED, resyncRequired: true, needsAttention: true };
  if (SIG.needsResync.test(text)) return { result: RESULT.NEEDS_RESYNC, resyncRequired: true, needsAttention: true };

  if (o.code !== 0) {
    // A non-zero exit with no recognized safety signature: name path-too-long distinctly if that is the
    // cause, else a generic error. Neither changes the resync block (no new baseline was established).
    if (SIG.pathTooLong.test(text)) return { result: RESULT.PATH_TOO_LONG, resyncRequired: null, needsAttention: true };
    return { result: RESULT.ERROR, resyncRequired: null, needsAttention: true };
  }

  // code === 0: the run completed and established/refreshed the baseline (clears the resync block), but
  // it may still carry a non-green attention state that must not read as "clean".
  if (SIG.pathTooLong.test(text)) return { result: RESULT.PATH_TOO_LONG, resyncRequired: false, needsAttention: true };
  if (SIG.conflict.test(text)) return { result: RESULT.CONFLICT_KEEP_BOTH, resyncRequired: false, needsAttention: true };
  return { result: o.resync ? RESULT.RESYNC_OK : RESULT.OK, resyncRequired: false, needsAttention: false };
}

module.exports = { classifyBisyncOutcome, RESULT, HOST_KEY_UNVERIFIED, SIG };

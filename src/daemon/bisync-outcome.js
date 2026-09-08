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
  CHANNEL_REFUSED: 'channel-refused',                // the door answered but refused the session channel (a spent credential, a limit, a busy server)
  CONNECT_FAILED: 'connect-failed',                  // the SFTP door could not be reached at all (refused / timed out / no such host)
  PATH_TOO_LONG: 'path-too-long',                    // a file skipped for OS path length — surface which one
  // The three ways a file can fail to LAND on the server, kept apart because the honest sentence differs and
  // only the first two are knowable from what the server said:
  FILE_TOO_LARGE: 'file-too-large',                  // the server refused a file for exceeding a size limit it named
  SERVER_NO_SPACE: 'server-no-space',                // the server said it had no room to receive the file
  UPLOAD_NOT_STORED: 'upload-not-stored',            // the bytes went up and the file was not there afterwards — cause not knowable here
  ERROR: 'error',                                    // any other non-zero exit
});

// Decided in the MAIN process, not here: an 'upload-not-stored'/'server-no-space' run whose vault record then
// proves the vault is over (or at) its own allowance is re-typed to this, so "out of space" is only ever said
// when the server's own numbers say so. Named here so the one vocabulary stays in one file.
const VAULT_FULL = 'vault-full';

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
  // The server ANSWERED and then refused the session channel — the door's other way of turning this computer
  // away: a spent single-use credential, a credential or attempt limit, or simply a server with no session slots
  // left. The Go ssh library prefixes every channel-open rejection with this one literal ("ssh: rejected:
  // administratively prohibited (open failed)" / "... resource shortage"), so the signature is exactly that
  // prefix. It is its OWN result, not an auth failure: the scheduler backs off from both alike, but only a real
  // auth failure may go on to ask for a sign-in — a busy server must never be answered with "sign in again".
  channelRefused: /ssh: rejected:/i,
  // The door could not be reached: "NewFs: couldn't connect SSH: dial tcp host:port: connectex: … actively refused
  // it." / "… i/o timeout" / "dial tcp: lookup host: no such host". Tested AFTER the mismatch and auth signatures:
  // rclone wraps both of those in the same "couldn't connect SSH" prefix, and each has its own honest state.
  connectFailed: /couldn't connect ssh|dial tcp|connection refused|actively refused|i\/o timeout|no such host|network is unreachable|no route to host|connection reset by peer/i,
  // An individual file rejected for path/name length (Windows and POSIX wordings).
  pathTooLong: /path too long|file ?name too long|filename or extension is too long|name too long/i,
  // A keep-both conflict rename (bisync's safe default): both copies preserved, neither overwritten.
  conflict: /\.conflict\d/i,
  // A file rejected for its SIZE by the SERVER. The vault's SFTP door refuses an over-limit upload in-stream
  // with a description stating the limit in whole MB ("file exceeds the N MB ... limit"), which the Go client
  // renders verbatim inside its own `sftp: "…" (SSH_FX_…)` wrapper. The remaining alternatives are the
  // protocol's own over-size wordings, and each is REQUIRED to carry that remote wrapper: the bare phrases are
  // also what the local filesystem says when a write fails on THIS computer (a file over the local
  // filesystem's own maximum), and blaming the server for the local disk is the wrong-cause answer this
  // classification exists to stop. NOTE the server's raw text also names the operator's own tuning settings —
  // it is a classification haystack ONLY and must never reach a person; the limit is re-stated from the
  // NUMBER extracted below, never by quoting the message.
  fileTooLarge: /exceeds the \d+\s*[kmgt]?b\b[^\n]{0,40}limit|SSH_FX_FILE_TOO_LARGE|(?:sftp:|SSH_FX_)[^\n]{0,120}?(?:file (?:is )?too large|exceeds (?:the )?maximum (?:file )?size)/i,
  // The SERVER said it had no ROOM: the vault door's full-staging-buffer refusal, or the protocol's own
  // out-of-space wordings — again only inside the remote wrapper, because "no space left on device" is
  // overwhelmingly the LOCAL disk filling up on a download, and telling someone their server is full while
  // their own disk is full would send them to the wrong place entirely. Distinct from a file being too big
  // for a stated limit (nothing about the file is wrong), and distinct from the VAULT's own allowance, which
  // this cannot tell apart and so never claims.
  serverNoSpace: /staging buffer is full|SSH_FX_QUOTA_EXCEEDED|SSH_FX_NO_SPACE_ON_FILESYSTEM|(?:sftp:|SSH_FX_)[^\n]{0,120}?(?:quota exceeded|no space left on device|disk (?:quota|full)|insufficient (?:disk )?space)/i,
  // The bytes were accepted and the file was NOT there afterwards. Observed against the real server: rclone
  // uploads to a temporary "<name>.<token>.partial" and renames it into place at the end, so when the vault's
  // door decides at close NOT to keep an upload (it is over the vault's allowance, or the deployment's) the
  // rename finds nothing — "partial file rename failed: Move Rename failed: file does not exist". The
  // object-not-found wording is the same event on the paths that upload in place: this server cannot store a
  // client mtime, so rclone's post-upload verification IS a stat, and it comes back empty.
  //
  // Deliberately NARROW. A bare "SetModTime failed" is NOT here: against a server that cannot store a client
  // mtime rclone logs that on runs which then succeed, and a green run must never be dressed up as a failure.
  // Neither is "corrupted on transfer"/"sizes differ": those are per-ATTEMPT diagnostics that a low-level
  // retry usually clears, not a terminal outcome.
  //
  // An SFTP close cannot report a failure, so this silence is the ONLY signal the client ever gets, and WHY
  // it happened (the vault's allowance, the deployment's, a permission lost mid-transfer) is not decidable
  // here — the main process asks the server's own numbers before anything specific is claimed.
  uploadNotStored: /partial file rename failed|rename failed: file does not exist|failed to copy: object not found|setmodtime stat failed: object not found/i,
});

// The remote-relative path rclone names on the line that FAILED. Only the file's own name is kept (never the
// folders above it), so what travels to the status layer is the one word a person needs to find the file.
const FAILED_FILE_LINE = /(?:^|\n)[^\n]{0,60}?\b(?:ERROR|NOTICE)\s*:\s*([^\n]+?)\s*:\s*(?:Failed to copy|Failed to transfer|Failed to update|Failed to set modification time|partial file rename failed|error reading)/i;
// rclone uploads to a temporary sibling — "<name>.<random token>.partial" — and renames it into place at
// the end, so the file it names on a rename failure is that temporary one. Show the name the person
// actually has in their folder, not rclone's working name for it (which would be an internal string).
const PARTIAL_SUFFIX = /\.[0-9a-z]{6,12}\.partial$/i;
// What a file name may contain to be SHOWN. Deliberately conservative: printable, no control characters, no
// path separators (the basename is taken first), no zero-width or direction-overriding characters (a name can
// come from the remote side of a shared vault, and one that reverses the text around it must not be handed to
// a menu), not a bare "." or "..", and bounded. Anything else is dropped and the copy falls back to its
// no-name wording rather than rendering whatever an error line happened to hold.
const SHOWABLE_NAME = /^(?!\.\.?$)[^\u0000-\u001f\u007f\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff\\/:*?"<>|]{1,80}$/;
const MB = 1024 * 1024;
const SIZE_UNIT = Object.freeze({ b: 1, k: 1024, m: MB, g: 1024 * MB, t: 1024 * 1024 * MB });

/**
 * The failing file's path RELATIVE to the sync root, as rclone named it, with its temporary upload suffix
 * removed — or null when the line names nothing usable. This is the engine's own lookup key (it joins it to
 * the local folder to learn the file's size) and it is NOT part of the detail: nothing downstream of the
 * engine ever sees it, so no folder structure travels with an outcome.
 *
 * Fail-closed on anything that is not a plain relative path: an absolute path, a drive letter, a URL rclone
 * logged, a traversal segment, or a control character yields null rather than a path that could be joined
 * somewhere unintended.
 */
function failedRelPath(text, sig) {
  const m = FAILED_FILE_LINE.exec(String((sig && decidingLine(text, sig)) || (text == null ? '' : text)));
  if (!m || !m[1]) return null;
  const raw = String(m[1]).replace(PARTIAL_SUFFIX, '');
  if (!raw || raw.length > 1024) return null;
  if (/[\u0000-\u001f\u007f]/.test(raw)) return null;
  if (/^[a-zA-Z]:|^[\\/]|^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(raw)) return null;
  const parts = raw.split(/[\\/]/);
  if (parts.some((seg) => seg === '' || seg === '.' || seg === '..')) return null;
  return parts.join('/');
}

/**
 * The file name from the first line rclone reported as failed, reduced to its basename and checked against
 * SHOWABLE_NAME. Returns null whenever there is any doubt — a caller that gets null says "a file", never a
 * raw fragment of an error message.
 */
function failedFileName(text) {
  const m = FAILED_FILE_LINE.exec(String(text == null ? '' : text));
  if (!m || !m[1]) return null;
  const leaf = String(m[1]).split(/[\\/]/).pop().replace(PARTIAL_SUFFIX, '');
  if (!leaf || !SHOWABLE_NAME.test(leaf)) return null;
  return leaf;
}

/**
 * The size limit the server NAMED, in bytes, from its own "exceeds the N MB limit" wording. Returns null when
 * no number was stated (or it is not a sane one) — the copy then says a file was too large WITHOUT inventing
 * a maximum. Only the number and its unit are taken; the rest of the server's sentence is never reused.
 */
function statedLimitBytes(text) {
  const m = /exceeds the (\d{1,7})\s*([kmgt])?b\b/i.exec(String(text == null ? '' : text));
  if (!m) return null;
  const n = Number(m[1]);
  if (!Number.isFinite(n) || n <= 0) return null;
  const unit = SIZE_UNIT[(m[2] || 'b').toLowerCase()] || 1;
  const bytes = n * unit;
  return Number.isSafeInteger(bytes) && bytes > 0 ? bytes : null;
}

/**
 * The first line of the run's output that matches `sig` — the signature that actually decided the outcome.
 *
 * Everything the detail says is then read from THAT ONE LINE. A run can fail on several files for several
 * reasons, and taking the name from the first failing line while taking the size from anywhere in the output
 * produces a confident, specific, WRONG sentence: one file's name beside another file's limit. Scoping both
 * to the deciding line makes that impossible by construction.
 */
function decidingLine(text, sig) {
  for (const line of String(text == null ? '' : text).split('\n')) {
    if (sig.test(line)) return line;
  }
  return null;
}

/**
 * The bounded DETAIL that travels with a file-level outcome: the failing file's name (basename only, or null)
 * and the maximum the server stated (bytes, or null) — both read from the line that decided the outcome, so
 * they always describe the same failure. Nothing else from the run's output is ever carried; the raw text
 * names the operator's own tuning settings and must not leave the helper.
 * @param {string} text  the run's output
 * @param {RegExp} [sig] the signature that classified it; without one the first failing line is used
 * @returns {{file:(string|null), maxBytes:(number|null)}|null} null when there is nothing worth carrying
 */
function outcomeDetail(text, sig) {
  const scope = (sig && decidingLine(text, sig)) || text;
  const file = failedFileName(scope);
  const maxBytes = statedLimitBytes(scope);
  return (file || maxBytes) ? { file, maxBytes } : null;
}

function haystack(stdout, stderr) { return String(stdout == null ? '' : stdout) + '\n' + String(stderr == null ? '' : stderr); }

/**
 * The connection-level verdict of ANY failed rclone process against the vault (not only bisync): a changed
 * server identity, an auth refusal, or an unreachable door — or null when the failure is something else. Used by
 * the zero-loss resync's first step, so a server that cannot be reached during a first sync gets the same typed
 * state (and the same stop on minting) as it does on a routine run.
 * @returns {string|null} a RESULT value, or null
 */
function classifyConnectionFailure(stdout, stderr) {
  const text = haystack(stdout, stderr);
  if (SIG.hostKeyMismatch.test(text)) return RESULT.HOST_KEY_MISMATCH;
  if (SIG.authFailed.test(text)) return RESULT.AUTH_FAILED;
  if (SIG.channelRefused.test(text)) return RESULT.CHANNEL_REFUSED;
  if (SIG.connectFailed.test(text)) return RESULT.CONNECT_FAILED;
  return null;
}

/**
 * @param {{code:number, stdout?:string, stderr?:string, resync?:boolean}} o
 * @returns {{result:string, resyncRequired:(boolean|null), needsAttention:boolean, detail?:object}}
 *   resyncRequired is `true`/`false` when the outcome decides it, or `null` to mean "leave the prior
 *   value unchanged" (a connection-level block or a plain error does not establish or clear a baseline).
 *   `detail` rides only on the file-level outcomes, and only ever carries the bounded pair outcomeDetail
 *   produces (a checked base file name, a stated maximum in bytes) — never a fragment of the raw output.
 */
function classifyBisyncOutcome(o) {
  const text = haystack(o.stdout, o.stderr);
  // What bisync said about the BASELINE, decided independently of which cause wins the result below. A file
  // the server refused is the honest cause of the run, but bisync may ALSO have aborted and owed a resync;
  // naming the real cause must never quietly drop that latch.
  const owesResync = SIG.needsResync.test(text) || SIG.excessiveDelete.test(text) || SIG.allChanged.test(text);
  const baseline = () => (owesResync ? true : (o.code === 0 ? false : null));

  // Most serious first: an identity-change (MITM) signal and a data-safety abort outrank a plain error.
  if (SIG.hostKeyMismatch.test(text)) return { result: RESULT.HOST_KEY_MISMATCH, resyncRequired: null, needsAttention: true };
  // A connection-level auth failure (e.g. a credential that lapsed mid-run): surface it as its own state so
  // the status layer can prompt sign-in, and leave the resync baseline untouched. Fail-closed, never silent.
  if (SIG.authFailed.test(text)) return { result: RESULT.AUTH_FAILED, resyncRequired: null, needsAttention: true };
  // The door answered and refused the channel — a refusal, but never an account matter: its own typed result.
  if (SIG.channelRefused.test(text)) return { result: RESULT.CHANNEL_REFUSED, resyncRequired: null, needsAttention: true };
  if (SIG.excessiveDelete.test(text)) return { result: RESULT.ABORT_EXCESSIVE_DELETE, resyncRequired: true, needsAttention: true };
  // A different safety abort than the delete cap — all files on one side read as changed. Must NOT be labelled as
  // a large DELETE (its own honest status); still a fail-closed abort requiring a deliberate resync.
  if (SIG.allChanged.test(text)) return { result: RESULT.ABORT_ALL_CHANGED, resyncRequired: true, needsAttention: true };

  // A DOOR that could not be reached outranks anything about a file. A connection dropping mid-transfer
  // leaves both kinds of trace in one log, and reading it as "the server refused your file" would be a
  // specific claim about the server's behaviour when the truth is that nothing reached it — and, worse, it
  // would tell the credential bounds that the server ANSWERED, re-opening the gate that stops this computer
  // minting a credential every tick against a door that is down. Tested after the safety aborts above (a
  // genuine abort whose output also mentions a transient network phrase keeps its latch) and, as before,
  // only on a non-zero exit, since the signature is deliberately narrow.
  if (o.code !== 0 && SIG.connectFailed.test(text)) return { result: RESULT.CONNECT_FAILED, resyncRequired: null, needsAttention: true };

  // A file the server would not take. Two orderings matter here.
  //
  // Tested BEFORE the needs-resync signature: bisync ends a run with a failed transfer by declaring a
  // critical error and owing a resync, so leaving these below it would launder every one of them into the
  // generic "this needs a repair" — the exact wrong-cause answer this classification exists to stop. The
  // resync latch bisync asked for is preserved (baseline()); only the NAME of the cause changes.
  //
  // And only on a NON-ZERO exit: rclone retries at a low level and logs a failed attempt that it then
  // recovers from, so a run that ultimately succeeded can carry these words in its output. A green run must
  // never be dressed up as a failure.
  //
  // Among themselves they run from the most specific thing the server said to the least: a size it stated, a
  // lack of room it stated, and last the case where it said nothing at all.
  if (o.code !== 0) {
    if (SIG.fileTooLarge.test(text)) return { result: RESULT.FILE_TOO_LARGE, resyncRequired: baseline(), needsAttention: true, detail: outcomeDetail(text, SIG.fileTooLarge), failedPath: failedRelPath(text, SIG.fileTooLarge) };
    if (SIG.serverNoSpace.test(text)) return { result: RESULT.SERVER_NO_SPACE, resyncRequired: baseline(), needsAttention: true, detail: outcomeDetail(text, SIG.serverNoSpace), failedPath: failedRelPath(text, SIG.serverNoSpace) };
    if (SIG.uploadNotStored.test(text)) return { result: RESULT.UPLOAD_NOT_STORED, resyncRequired: baseline(), needsAttention: true, detail: outcomeDetail(text, SIG.uploadNotStored), failedPath: failedRelPath(text, SIG.uploadNotStored) };
  }

  if (SIG.needsResync.test(text)) return { result: RESULT.NEEDS_RESYNC, resyncRequired: true, needsAttention: true };

  if (o.code !== 0) {
    // A non-zero exit with no recognized safety signature: name path-too-long distinctly if that is the
    // cause, else a generic error. Neither changes the resync block (no new baseline was established).
    if (SIG.pathTooLong.test(text)) return { result: RESULT.PATH_TOO_LONG, resyncRequired: null, needsAttention: true, detail: outcomeDetail(text) };
    return { result: RESULT.ERROR, resyncRequired: null, needsAttention: true };
  }

  // code === 0: the run completed and established/refreshed the baseline (clears the resync block), but
  // it may still carry a non-green attention state that must not read as "clean".
  if (SIG.pathTooLong.test(text)) return { result: RESULT.PATH_TOO_LONG, resyncRequired: false, needsAttention: true, detail: outcomeDetail(text) };
  if (SIG.conflict.test(text)) return { result: RESULT.CONFLICT_KEEP_BOTH, resyncRequired: false, needsAttention: true };
  return { result: o.resync ? RESULT.RESYNC_OK : RESULT.OK, resyncRequired: false, needsAttention: false };
}

module.exports = { classifyBisyncOutcome, classifyConnectionFailure, outcomeDetail, failedFileName, failedRelPath, statedLimitBytes, RESULT, VAULT_FULL, HOST_KEY_UNVERIFIED, SIG };

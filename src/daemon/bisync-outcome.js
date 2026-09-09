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

// Where the run's OWN voice begins on a line. rclone writes one message per line, and a message ABOUT THE RUN
// starts immediately after the log level — "ERROR : Safety abort: …". A message about a FILE puts the file's
// own name in that same slot: "ERROR : holiday/max delete list.md: Failed to copy: …". That difference is the
// only thing separating the run saying something from a file merely being named, so the structural signatures
// below are anchored to the slot instead of matching a bare phrase anywhere in the output.
//
// It matters because the names are not ours. In a shared vault they arrive from other members, and an
// unanchored phrase let a chosen name make this computer announce a changed server identity — which stops
// syncing for EVERY vault and needs a person to clear it — or demand a repair that was never owed.
// A line the LOGGER actually wrote: the start of a line, an optional timestamp, then a level and its colon.
// Requiring the level raises the bar without settling the matter, and it is worth being exact about which.
// It stops a name whose break is a carriage return or one of Unicode's own separators, because those are
// flattened before any of this is read and the name stays inside its own line. It does NOT stop a name
// containing a real newline: the half after the break starts a line, and the name's author writes all of
// it, level included. Nothing in a text log can tell that apart from a line the tool wrote — see the
// residual recorded in the tests, and the note on the log format that would end the question.
const LOG_LINE = String.raw`(?:^|[\r\n])[^\r\n]{0,32}?(?:ERROR|CRITICAL|NOTICE|INFO|DEBUG)\s*:\s*`;
// The run's OWN voice: immediately after the level, which is where a verdict about the run is written and
// where a file name never sits (a name is only ever printed as the subject of a message, after the level).
const LINE_LEAD = LOG_LINE;
// Somewhere inside a logged message, for phrases that legitimately appear mid-sentence (an ssh error arrives
// wrapped in several layers). Still pinned to a real logged line, so a name smuggling in a newline cannot
// manufacture one. The gap is generous because the text before the phrase can include a whole long path.
const IN_LOG_LINE = LOG_LINE + String.raw`[^\r\n]{0,500}?`;

// The subject of a per-file message is the file's NAME, and it must not be read as if the run had said it.
// Two rules decide when the name in front of a message is taken out, and a deny-list decides when neither may.
//
// The deny-list comes first and is the important one. Some of the run's OWN verdicts read exactly like a
// per-file message, because the tool wraps a file-level cause inside them - "Bisync critical error: failed to
// copy Path1 to Path2: ...". Stripping the front off one of those would throw away the very verdict this file
// exists to notice, and losing a baseline is far worse than naming a cause wrongly: the vault would go on
// running delete-capable syncs with no repair ever latched. So anything opening with the run's own words is
// left whole.
const VERDICT_OPENER = /^\s*(?:Bisync critical error|Bisync aborted|Safety abort|Fatal error|Failed to create file system|NewFs)\s*$/i;
// ...but a FILE may be named after one of those words, and then it is still just a file. What separates them
// is that the run's verdict is never a path: no folder in it, and no extension on the end.
//
// Judged on the FIRST token after the level — the subject as written, before the lazy match below grew it. A
// verdict's own text routinely contains a path further along ("Bisync critical error: open /var/x/v.lst: no
// such file"), and letting the grown subject decide meant those read as paths, voided the deny-list, and had
// the verdict stripped: the exact loss this deny-list exists to prevent.
const LOOKS_LIKE_A_PATH = /[\\\/]|\.[A-Za-z0-9]{1,8}$/;
const subjectAsWritten = (line, lead) => String(line).slice(String(lead).length).split(': ')[0];
// Then either rule may take the name out: the message after it is one the tool writes ABOUT A FILE, or the
// subject simply looks like a path. Two rules rather than one because neither is complete alone - the tool's
// per-file vocabulary is long and keeps growing, and not every name looks like a path.
//
// The subject is matched GREEDILY, which matters more than it looks. A name is free to contain the tool's own
// per-file wording, and a lazy match would stop at the FIRST one - leaving everything the name said after it
// sitting in the part that is kept. Taking the LAST split keeps the whole of the name on the name's side.
const FILE_MESSAGE = /^(.*?(?:ERROR|CRITICAL|NOTICE|INFO|DEBUG)\s*:\s*)(.+): ((?:Failed to \w+|Couldn't \w+|Can't \w+|Not \w+|partial file rename failed|corrupted on transfer|error read\w*|sizes differ|md5 differ|hash differ|Duplicate object|Skipped|Removing|Update|Post request)\b.*)$/i;
const FILE_SUBJECT = /^(.*?(?:ERROR|CRITICAL|NOTICE|INFO|DEBUG)\s*:\s*)([^\r\n]*?(?:[\\\/][^\r\n]*|\.[A-Za-z0-9]{1,8})): (.+)$/;

/**
 * The run's output with FILE NAMES taken out of the lines that are about a single file — the name replaced by a
 * fixed placeholder, the message it carried left untouched. Used as the haystack every signature reads, so what
 * a file is CALLED can never decide what the run is reported to have done. The raw text is still what the
 * detail extraction reads, because naming the file to a person is exactly its job.
 */
// The characters a NAME can carry that would otherwise end a line here. The tool writes names verbatim, and a
// lone carriage return, or one of Unicode's own line separators, splits a line for some readers and not for
// others — which is all an attacker needs: the half after the break looks like a fresh line and can be given
// any prefix, including the level the logger writes. They are flattened to a space before anything is read, so
// a message stays one line no matter what the name inside it contains. A real CRLF is left as its newline.
const NAME_BORNE_BREAKS = /\r(?!\n)|[\u2028\u2029\u0085\v\f]/g;

function maskFileNames(text) {
  return String(text == null ? '' : text)
    .replace(NAME_BORNE_BREAKS, ' ')
    .split('\n')
    .map((line) => {
      const m = line.match(FILE_MESSAGE) || line.match(FILE_SUBJECT);
      if (!m) return line;
      const head = subjectAsWritten(line, m[1]);
      if (VERDICT_OPENER.test(head) && !LOOKS_LIKE_A_PATH.test(head)) return line; // the run speaking about itself keeps every word
      return `${m[1]}<file>: ${m[3]}`;
    })
    .join('\n');
}

const SIG = Object.freeze({
  // "Safety abort: too many deletes (>50%, N of M) ... Run with --force if desired. Bisync aborted." NARROW to
  // the DELETE wording — the bare "safety abort" is shared with the all-changed guard below, a different abort.
  excessiveDelete: new RegExp(`(?:${LINE_LEAD}Safety abort:` + String.raw`[^\r\n]{0,60}?too many deletes` + `)|(?:${LINE_LEAD}` + String.raw`max delete limit` + `)`, 'i'),
  // "Safety abort: all files were changed on Path1/Path2 ... Run with --force". A DIFFERENT safety guard than the
  // delete cap: every file on one side read as changed (here, mtime drift under set_modtime=false), NOT deletions.
  allChanged: new RegExp(`${LINE_LEAD}Safety abort:` + String.raw`[^\r\n]{0,60}?all files (?:were )?changed`, 'i'),
  // "cannot find prior Path1 or Path2 listings ... Must run --resync to recover." / a bisync critical error.
  needsResync: new RegExp(`(?:${LINE_LEAD}Bisync critical error)|(?:${LINE_LEAD}` + String.raw`Bisync aborted\.[^\r\n]{0,60}?Must run --resync` + `)|(?:${IN_LOG_LINE}` + String.raw`cannot find prior Path\d` + `)`, 'i'),
  // NOT anchored to the start of a line, unlike the verdict signatures: this phrase is the ssh library's own
  // and turns up nowhere by accident, and a changed server identity is the one thing worth a false alarm over —
  // failing to NAME a real key change would leave a person staring at a generic error. Taking file names out of
  // the text (maskFileNames) is what stops a file called "knownhosts: key mismatch.txt" reaching it; a per-file
  // line whose message is not one this recognises would still get through, which is a known and narrow residual.
  // A pinned-host-key failure against the configured host_keys. Deliberately NARROW: it matches an actual
  // key MISMATCH ("knownhosts: key mismatch" matches via `key mismatch`), not a bare mention of knownhosts
  // — a false MITM alarm on a benign line desensitizes users to a real one (anti-cry-wolf).
  hostKeyMismatch: new RegExp(String.raw`knownhosts: key mismatch|ssh: handshake failed:[^\r\n]{0,120}?key mismatch` + `|${IN_LOG_LINE}` + String.raw`host key[^\r\n]{0,40}?(?:has changed|does ?n[o']?t match)`, 'i'),
  // SFTP authentication refused — the ssh handshake got past host-key verification but auth failed (e.g. a
  // lapsed/rotated temp-cred): "ssh: unable to authenticate, attempted methods [none password] ...".
  // The same key-mismatch test, but pinned to a line the logger wrote. Used ONLY when the output actually
  // contains logged lines, so a file name that smuggles in a newline cannot forge the alarm; when a caller
  // hands over a bare error string instead (the connection-level check does), the loose one above still
  // applies and a real mismatch is never missed for want of a prefix.
  hostKeyMismatchLogged: new RegExp(`${IN_LOG_LINE}` + String.raw`(?:handshake failed|couldn't connect ssh|NewFs)[^\r\n]{0,200}?(?:knownhosts: )?key mismatch` + `|${IN_LOG_LINE}` + String.raw`host key[^\r\n]{0,40}?(?:has changed|does ?n[o']?t match)`, 'i'),
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
  pathTooLong: new RegExp(`${IN_LOG_LINE}` + String.raw`(?:path too long|file ?name too long|filename or extension is too long|name too long|ENAMETOOLONG)`, 'i'),
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

/**
 * The RAW line that a signature decided on, found by matching against the MASKED text and then taking the line
 * at the same position. Masking never adds or removes lines, so the position carries across.
 *
 * Taking it by position is the point. Searching the raw text again would find whichever line matched FIRST
 * there — and a file NAME can arrange to be that line. A decoy called "partial file rename failed.txt" sitting
 * above the real failure would be named in its place, and then SIZED in its place: that size is what decides
 * whether a person is told their vault is out of room. A small decoy hides a real "out of space"; a large one
 * invents one. So the line that names the file is always the same line that decided the outcome.
 * @returns {string|null}
 */
function decidingRawLine(maskedText, rawText, sig) {
  const masked = String(maskedText == null ? '' : maskedText).split('\n');
  const raw = String(rawText == null ? '' : rawText).split('\n');
  for (let i = 0; i < masked.length; i += 1) {
    if (sig.test(masked[i])) return raw[i] == null ? masked[i] : raw[i];
  }
  return null;
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
  // stderr ONLY, and deliberately so. The caller's stdout here is the server's file listing — one name per
  // line, every one of them chosen by whoever can put a file in the vault. Reading a connection verdict out of
  // that let a member call a file "knownhosts: key mismatch" and have this computer announce a changed server
  // identity, which stops syncing for every vault until a person clears it. Errors are written to stderr; the
  // listing is data, and data never gets a vote on what happened to the connection.
  const text = haystack('', stderr);
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
  // Two different readings of the same run. `text` is what the SIGNATURES see, with the names of individual
  // files taken out, so nothing a file is called can decide what the run is reported to have done. `rawText`
  // still carries them, because naming the file to the person is exactly what the detail extraction is for.
  const rawText = haystack(o.stdout, o.stderr);
  const text = maskFileNames(rawText);
  // What bisync said about the BASELINE, decided independently of which cause wins the result below. A file
  // the server refused is the honest cause of the run, but bisync may ALSO have aborted and owed a resync;
  // naming the real cause must never quietly drop that latch.
  const owesResync = SIG.needsResync.test(text) || SIG.excessiveDelete.test(text) || SIG.allChanged.test(text);
  const baseline = () => (owesResync ? true : (o.code === 0 ? false : null));
  // What a CONNECTION verdict must carry through instead of a flat `null`. A data-safety abort — a >50% delete,
  // or every file on one side reading as changed — latches the vault until a person deliberately repairs it, and
  // no connection phrase in the same output may take the result and drop that latch with it.
  //
  // Deliberately NARROWER than baseline(): it does NOT latch on bisync's generic critical-error line. bisync
  // frames every failure that way, including an ordinary dropped connection, so latching on it would answer a
  // network blip with "this needs a repair" — the wrong-cause answer, and one that sends someone to do work that
  // will not help. A genuine lost baseline still surfaces: the next run meets the same missing listing and
  // classifies as needs-resync on its own, which latches honestly.
  // Only on a FAILED run: a run that exited green established its own baseline, and inventing a repair for it
  // would put a vault behind a manual Repair it never needed.
  const safetyLatch = () => ((o.code !== 0 && (SIG.excessiveDelete.test(text) || SIG.allChanged.test(text))) ? true : null);

  // Most serious first: a changed server identity is the one signal that outranks even a data-safety abort —
  // it says the machine on the other end may not be the vault at all, and it must be the loud answer whatever
  // else the run also said. It carries the baseline rather than discarding it, so a run that ALSO aborted on a
  // mass delete keeps the repair that abort owes (see below: no verdict here may quietly drop that latch).
  // Where the output carries logged lines at all, the alarm must come from one of them (see the two signatures).
  const logged = new RegExp(LOG_LINE).test(text);
  if ((logged ? SIG.hostKeyMismatchLogged : SIG.hostKeyMismatch).test(text)) return { result: RESULT.HOST_KEY_MISMATCH, resyncRequired: safetyLatch(), needsAttention: true };
  if (SIG.excessiveDelete.test(text)) return { result: RESULT.ABORT_EXCESSIVE_DELETE, resyncRequired: true, needsAttention: true };
  // A different safety abort than the delete cap — all files on one side read as changed. Must NOT be labelled as
  // a large DELETE (its own honest status); still a fail-closed abort requiring a deliberate resync.
  if (SIG.allChanged.test(text)) return { result: RESULT.ABORT_ALL_CHANGED, resyncRequired: true, needsAttention: true };

  // A DOOR that refused the credential, refused the connection, or could not be reached at all, outranks
  // anything about a file. A connection dropping mid-transfer leaves both kinds of trace in one log, and reading
  // that as "the server refused your file" would be a specific claim about the server's behaviour when the truth
  // is that nothing reached it — and, worse, it would tell the credential bounds that the server ANSWERED,
  // re-opening the gate that stops this computer minting a credential every tick against a door that is down.
  //
  // All THREE connection verdicts sit HERE, below the data-safety aborts and only on a non-zero exit, and for
  // one reason: a >50%-delete or all-files-changed abort carries a latch that holds the vault until a person
  // deliberately repairs it, and no connection phrase appearing in the same output may take the result and drop
  // that latch with it. rclone retries at a low level and keeps both a head and a rolling tail of the log, so an
  // early recovered connection error and the terminal abort line genuinely do arrive together. They run from the
  // narrowest claim to the widest: the credential itself was refused, then the session channel was refused (the
  // door answered either way), then the door could not be reached at all. Each signature is deliberately narrow,
  // and none may turn a run that ultimately exited green into a failure — hence the exit check on all three.
  //
  // They carry safetyLatch() rather than a flat null. Below this point the ordering has ALREADY settled it —
  // an abort would have returned above — so for these three it can only answer null today, and it is here as
  // belt-and-braces should that order ever be changed back. Where it genuinely does the work is the identity
  // check at the top, which must outrank even an abort to be the loud answer, and which without it would take
  // the verdict and drop the abort's repair with it.
  if (o.code !== 0 && SIG.authFailed.test(text)) return { result: RESULT.AUTH_FAILED, resyncRequired: safetyLatch(), needsAttention: true };
  if (o.code !== 0 && SIG.channelRefused.test(text)) return { result: RESULT.CHANNEL_REFUSED, resyncRequired: safetyLatch(), needsAttention: true };
  if (o.code !== 0 && SIG.connectFailed.test(text)) return { result: RESULT.CONNECT_FAILED, resyncRequired: safetyLatch(), needsAttention: true };

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
    if (SIG.fileTooLarge.test(text)) return { result: RESULT.FILE_TOO_LARGE, resyncRequired: baseline(), needsAttention: true, detail: outcomeDetail(decidingRawLine(text, rawText, SIG.fileTooLarge) || rawText), failedPath: failedRelPath(decidingRawLine(text, rawText, SIG.fileTooLarge) || rawText) };
    if (SIG.serverNoSpace.test(text)) return { result: RESULT.SERVER_NO_SPACE, resyncRequired: baseline(), needsAttention: true, detail: outcomeDetail(decidingRawLine(text, rawText, SIG.serverNoSpace) || rawText), failedPath: failedRelPath(decidingRawLine(text, rawText, SIG.serverNoSpace) || rawText) };
    if (SIG.uploadNotStored.test(text)) return { result: RESULT.UPLOAD_NOT_STORED, resyncRequired: baseline(), needsAttention: true, detail: outcomeDetail(decidingRawLine(text, rawText, SIG.uploadNotStored) || rawText), failedPath: failedRelPath(decidingRawLine(text, rawText, SIG.uploadNotStored) || rawText) };
  }

  if (SIG.needsResync.test(text)) return { result: RESULT.NEEDS_RESYNC, resyncRequired: true, needsAttention: true };

  if (o.code !== 0) {
    // A non-zero exit with no recognized safety signature: name path-too-long distinctly if that is the
    // cause, else a generic error. Neither changes the resync block (no new baseline was established).
    if (SIG.pathTooLong.test(text)) return { result: RESULT.PATH_TOO_LONG, resyncRequired: null, needsAttention: true, detail: outcomeDetail(decidingRawLine(text, rawText, SIG.pathTooLong) || rawText) };
    return { result: RESULT.ERROR, resyncRequired: null, needsAttention: true };
  }

  // code === 0: the run completed and established/refreshed the baseline (clears the resync block), but
  // it may still carry a non-green attention state that must not read as "clean".
  if (SIG.pathTooLong.test(text)) return { result: RESULT.PATH_TOO_LONG, resyncRequired: false, needsAttention: true, detail: outcomeDetail(decidingRawLine(text, rawText, SIG.pathTooLong) || rawText) };
  if (SIG.conflict.test(text)) return { result: RESULT.CONFLICT_KEEP_BOTH, resyncRequired: false, needsAttention: true };
  return { result: o.resync ? RESULT.RESYNC_OK : RESULT.OK, resyncRequired: false, needsAttention: false };
}

module.exports = { classifyBisyncOutcome, maskFileNames, classifyConnectionFailure, outcomeDetail, failedFileName, failedRelPath, statedLimitBytes, RESULT, VAULT_FULL, HOST_KEY_UNVERIFIED, SIG };

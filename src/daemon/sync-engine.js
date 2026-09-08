'use strict';

/*
 * Builds and runs the Standard-vault bidirectional sync as a ONE-SHOT `rclone bisync` child, with the
 * data-safety controls BAKED INTO the argv rather than left to caller discipline or an rclone default:
 *
 *   - `--force` and `--ignore-errors` can never appear (the runner refuses them by construction), so a
 *     local wipe or an errored listing can never override rclone's own safety aborts and propagate a
 *     mass deletion to the server.
 *   - `--max-delete` is pinned to an explicit percentage here, so bisync's excessive-delete guard is a
 *     property of THIS code, not of whatever default a bundled rclone happens to ship.
 *   - The bisync working directory (its prior-listing store) is a SHORT, per-vault, stable path under
 *     the app's own run dir. rclone's default workdir hashes the full remote path into a long name under
 *     the home directory, which trips Windows' path-length limit; a short controlled path avoids that and
 *     keeps the listings where the app can manage them.
 *   - First-run / blocked-vault gate: a vault that has never completed a clean run — or whose last run
 *     left it blocked — is FAIL-CLOSED to requiring a deliberate, user-initiated resync before any
 *     normal (delete-capable) bisync is allowed. A resync is never triggered automatically here.
 *
 * This path is zero-knowledge-disjoint: Standard-vault data is server-side encrypted, so no ZK key, DEK,
 * or the database key is read or passed here — only the run-state columns of the encrypted state DB.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { getRunState, recordRun } = require('../main/state-db');
const { classifyBisyncOutcome } = require('./bisync-outcome');

// The excessive-delete guard: bisync aborts the run if more than this percentage of files on either side
// would be deleted. (bisync interprets --max-delete as a PERCENTAGE, unlike plain `sync`, where it is a
// count.) It is FIXED here, never a caller-supplied argument — a caller must not be able to raise it to
// 100 (which means "abort only above 100%", i.e. never — the failsafe switched off) or otherwise weaken
// it. Tuning it, if ever warranted, is a deliberate edit here, not a runtime option: the guard is
// structural, not defaultal.
const MAX_DELETE_PERCENT = 50;
// The vault issues short-TTL, per-run scoped SFTP credentials and fail-closes an auth throttle, so a
// credential admits only a single concurrent SSH connection — bisync's default parallelism opens several
// at once and the extras are refused. Pin the transfer and check concurrency to one connection: robust
// against that limit and gentle on the server. It can be revisited upward only if throughput proves
// inadequate AND a higher concurrent-connection budget is confirmed.
const SFTP_CONNECTIONS = 1;
// bisync can legitimately run long over SFTP; bound it generously rather than leaving it unbounded.
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;
// A long transfer/scan is bounded by INACTIVITY, not a fixed wall clock: it is killed only after this long
// with NO output, so a large-but-progressing run survives while a hung one is caught. rclone is quiet by
// default, so the run is fed periodic stats to stderr at NOTICE level, which keep the idle timer alive AND
// carry the two aggregate {files,bytes} progress numbers the daemon extracts for the "Syncing…" glance.
// The stats period doubles as the "Syncing…" VISIBILITY THRESHOLD: a transfer only surfaces once a stats
// block reports it, so a transfer shorter than one period stays silent (quiet-by-default; motion means real
// work). 5s is a deliberate UX choice — responsive enough that an everyday few-files transfer is visible,
// tunable up to 10s if a rendered pass shows flicker — and it is DECOUPLED from the inactivity window below
// (a shorter period only widens the margin). The flags are fixed here — never caller/renderer-supplied.
const SYNC_STATS_ARGS = Object.freeze(['--stats', '5s', '--stats-log-level', 'NOTICE']);
// Bound the CONNECTION itself so a door that won't talk fails FAST with a definitive, classifiable error rather
// than hanging the run. rclone's defaults are generous (a 5-minute IO idle timeout, ten low-level retries), so a
// server that completes the SSH transport but then refuses or stalls the SFTP channel — exactly what the server's
// per-computer credential cap looks like at the door — can otherwise keep an operation alive for many minutes,
// and the periodic --stats heartbeat keeps the daemon's own inactivity watchdog from noticing (the heartbeat is
// output even while nothing moves). These make rclone give up in bounded time so the failure is caught and named
// (unreachable / can't-verify / connect-failed) instead of reading as an endless "syncing". A healthy transfer
// never idles 90s (data is flowing), so this never false-trips real work.
const CONNECT_BOUND_ARGS = Object.freeze(['--contimeout', '20s', '--timeout', '90s', '--low-level-retries', '3']);
// ONE SSH connection per rclone process, ever — and every transfer a single stream. The server issues SINGLE-USE
// credentials: the first SSH connection spends the credential, and any second connection the same process opens
// is refused at the door. rclone's SFTP backend keeps a connection POOL that grows on demand, and its default
// multi-thread download (files at or above --multi-thread-cutoff, 256 MiB) opens one extra connection per stream —
// so on the defaults a large file coming DOWN failed every run ("multi-thread copy: failed to open source: ...
// unable to authenticate"), and every retry minted another credential. Pinning the pool to one connection
// makes rclone WAIT for the connection instead of opening a doomed second one, and disabling multi-thread
// streams keeps a large file a single streamed read that never needs another. Both are fixed by construction
// here and travel with EVERY rclone operation against the remote (bisync, and the zero-loss resync's list /
// compare / preserve steps), never caller-supplied. A single stream is also what keeps the transfer's memory
// flat: rclone streams a file through a small fixed buffer whether it is 1 MB or 10 GB; it never holds a file
// whole, and neither does this daemon (nothing here reads file bytes; rclone's output is retained bounded).
// The last two flags keep that one connection QUIET: this server offers SFTP only — no shell, no remote hash
// commands — yet rclone's defaults probe for both on every process (a shell-type command, then six hash
// commands), each a channel the server refuses, and then WRITE the findings back into the config file it was
// handed (the per-run ephemeral config). Declaring "no shell" up front skips every probe and the write-back:
// one connection, one SFTP channel, nothing else on the wire, and the ephemeral config is never touched.
// The idle timeout is off because rclone otherwise CLOSES a pooled connection that sat idle for a minute (a long
// local scan between remote calls is enough) and dials a fresh one for the next call — with the spent credential.
// A stall on the one connection is still bounded: the daemon's inactivity watchdog kills a run that produces no
// output for SYNC_INACTIVITY_MS, and rclone's own --timeout ends an IO that stops moving (CONNECT_BOUND_ARGS).
const SINGLE_CONNECTION_ARGS = Object.freeze(['--sftp-connections', '1', '--sftp-idle-timeout', '0', '--multi-thread-streams', '0', '--sftp-shell-type', 'none', '--sftp-disable-hashcheck']);
// The folder's identity marker (main/folder-marker.js) lives in the synced folder's root and is LOCAL ONLY: it
// is excluded from every transfer, listing, and compare, so it is never uploaded to the vault, never deleted
// from the folder by a sync, and never counted as a difference. The name is fixed here, not caller-supplied.
const MARKER_NAME = '.dockvault-sync';
const MARKER_FILTER_ARGS = Object.freeze(['--exclude', `/${MARKER_NAME}`, '--exclude', `/${MARKER_NAME}.*.tmp`]);
// bisync's stdout is normally EMPTY (its log is stderr); this is the bounded retention for whatever does appear.
const BISYNC_MAX_STDOUT_BYTES = 256 * 1024;
const SYNC_INACTIVITY_MS = 120 * 1000;          // 24x the 5s stats period — ample margin against a false idle-trip
const SYNC_HARD_CEILING_MS = 6 * 60 * 60 * 1000; // absolute backstop, even if stats never stop

/**
 * A short, stable, filesystem-safe bisync workdir for one vault under `runDir`. The vault id (an
 * arbitrary/UUID string) is reduced to a short hash leaf so the path stays well under Windows' limit and
 * is identical across runs (bisync needs the prior listing to diff against).
 */
function bisyncWorkdir(runDir, vault) {
  const leaf = crypto.createHash('sha256').update(String(vault)).digest('hex').slice(0, 16);
  return path.join(runDir, 'bs', leaf);
}

/**
 * Assemble the bisync argv with the safety controls baked in. Pure (no I/O), so it is fully unit-tested.
 * `--force`/`--ignore-errors` are intentionally absent and cannot be added downstream (runner-refused);
 * the delete guard is the fixed MAX_DELETE_PERCENT, with no caller override to weaken or disable it.
 */
function buildBisyncArgs({ local, remote, workdir, resync = false }) {
  if (!local || !remote || !workdir) throw new Error('bisync needs local, remote, and workdir');
  const args = ['bisync', String(local), String(remote),
    '--workdir', String(workdir),
    '--max-delete', String(MAX_DELETE_PERCENT),
    // Compare by SIZE, not modtime. This server cannot store a client mtime (SETSTAT is unsupported; every file's
    // mtime is the server's own upload timestamp), so a modtime compare re-reads a different mtime than the
    // baseline recorded and reports EVERY file "changed" — tripping the all-changed safety abort on every run so
    // routine sync never progresses. Size is stable across re-listings. The safety guards are unchanged (a real
    // >50% name-absent delete still aborts; a real whole-side SIZE change still aborts). A same-size content
    // overwrite is the known blind spot of size-compare: a routine run does NOT detect it and does NOT self-heal
    // it — it is reconciled only by a DELIBERATE Repair (the zero-loss resync's byte-true `check --download`),
    // which runs on the first baseline or a user-initiated Repair, never automatically/periodically. Closing it
    // in routine sync needs a server that preserves a client mtime or exposes a hash (tracked cross-repo follow-up).
    '--compare', 'size',
    '--transfers', String(SFTP_CONNECTIONS), '--checkers', String(SFTP_CONNECTIONS),
    // Attempt the run ONCE. Each single-use credential authenticates one connection, so retrying the whole
    // operation would re-authenticate with a spent credential and, on a genuine auth failure, hammer the
    // server's per-source login limiter. It also means a safety abort (excessive delete) is never
    // re-attempted. A transient failure simply re-ticks on the next scheduled sweep.
    '--retries', '1',
    ...CONNECT_BOUND_ARGS, // a door that won't talk fails fast, never hangs the run
    ...SINGLE_CONNECTION_ARGS, // one SSH connection, single-stream transfers: a single-use credential is never re-presented
    ...MARKER_FILTER_ARGS, // the folder's own identity marker stays home
    ...SYNC_STATS_ARGS]; // periodic progress so the inactivity timeout can tell a long run from a hung one
  if (resync) args.push('--resync'); // a deliberate resync, or the one automatic empty-baseline refresh (see runBisync)
  return args;
}

// An empty baseline. bisync refuses a normal run whose PRIOR listing is empty on either side ("cannot sync to
// an empty directory") — its guard against a side that was wiped — and it judges the prior listing, not the
// folder as it is now. So a new vault synced into a new folder (both empty at the baseline) can never run
// normally again, not even after the first file arrives. The rule here: an empty prior listing means a FRESH
// BASELINE is due, and taking one loses nothing — a side that recorded nothing had nothing that could since have
// been deleted, so the union a resync makes only brings files across. How it is taken depends on the local side:
//   - the local folder holds nothing but its own identity marker -> a plain `--resync` right here (one process,
//     one credential): nothing local can be overwritten, the server's files simply come down;
//   - the local folder holds files -> the daemon routes the run through the zero-loss resync instead (keep-both
//     for any same-named, differing file), never a bare --resync that could let one side win.
// A folder that HAD files at the baseline and is now empty keeps rclone's guard; anything unreadable counts as
// not-empty (fail closed); no listing at all is the scheduler's never-run branch, not this rule.
function localHasNoFiles(local) {
  let entries;
  try { entries = fs.readdirSync(local, { withFileTypes: true }); } catch { return false; }
  for (const e of entries) {
    if (e.name === MARKER_NAME || (e.name.startsWith(`${MARKER_NAME}.`) && e.name.endsWith('.tmp'))) continue;
    if (e.isDirectory()) { if (!localHasNoFiles(path.join(local, e.name))) return false; continue; }
    return false;
  }
  return true;
}
function priorListingEmpty(workdir, local, remote) {
  let names;
  try { names = fs.readdirSync(workdir); } catch { return false; }
  // Only the listings of the pair this run is about (bisync keys them by both paths): a stale listing from
  // an earlier pairing in the same vault's workdir must not decide anything.
  const key = local ? `${canonicalPath(local)}..${remote ? canonicalPath(remote) : ''}` : '';
  const lists = names.filter((n) => n.startsWith(key) && (n.endsWith('.path1.lst') || n.endsWith('.path2.lst')));
  if (!lists.length) return false; // never baselined here: that is the scheduler's never-run branch, not this
  for (const n of lists) {
    let text;
    try { text = fs.readFileSync(path.join(workdir, n), 'utf8'); } catch { return false; }
    if (!text.split(/\r?\n/).some((line) => line.trim() && !line.startsWith('#'))) return true; // one empty side is enough
  }
  return false;
}
/** A fresh baseline is due (a prior listing is empty) and the local side holds files: the zero-loss path. */
function needsZeroLossBaseline({ local, remote, workdir }) {
  return priorListingEmpty(workdir, local, remote) && !localHasNoFiles(local);
}
/** A fresh baseline is due and the local side holds nothing: a plain resync right here loses nothing. */
function emptyPairBaseline({ local, remote, workdir }) {
  return priorListingEmpty(workdir, local, remote) && localHasNoFiles(local);
}

// bisync keys its prior listings by the two paths — "<local>..<remote>" in rclone's canonical form. Either side
// can change while nothing in the vault does: the synced folder is moved or renamed (the local key), or the
// vault's run switches between the account path (the vault's name) and this computer's own device path (its
// id form) — the same server directory under another name (the remote key). Either would otherwise read as "no
// prior listings" and demand a repair. When main reports the old side(s), the listing files are renamed to the
// new key first, so the run continues from the same baseline. The name is rclone's own canonical form of a
// path (whitespace, separators, ':', '?', '*' become '_'; leading/trailing separators dropped). The carried
// listing is the LIVE baseline (the folder was just followed, or the path just switched), so a listing already
// sitting under the new name — left by an earlier pairing — is stale and is set aside, never used; any mismatch
// simply leaves bisync to ask for its repair.
const NON_CANONICAL = /[\s\\/:?*]/g;
function canonicalPath(p) {
  return String(p).replace(/^[\\/]+|[\\/]+$/g, '').replace(NON_CANONICAL, '_');
}
// The listing-file prefix of one pair. A bare string is the local side alone (every remote of that local); a
// { local, remote } names one exact pair.
function pairKey(side) {
  if (side && typeof side === 'object') return `${canonicalPath(side.local)}..${side.remote != null ? canonicalPath(side.remote) : ''}`;
  return `${canonicalPath(side)}..`;
}
function carryListings(workdir, { from, to }) {
  const oldKey = pairKey(from);
  const newKey = pairKey(to);
  const named = (s) => (s && typeof s === 'object' ? !!s.local : !!s);
  if (!named(from) || !named(to) || oldKey === newKey) return 0;
  let names;
  try { names = fs.readdirSync(workdir); } catch { return 0; }
  let moved = 0;
  for (const n of names) {
    if (!n.startsWith(oldKey)) continue;
    const target = path.join(workdir, newKey + n.slice(oldKey.length));
    try {
      if (fs.existsSync(target)) fs.renameSync(target, `${target}.stale-${Date.now()}`); // the stale one is set aside, not read again
      fs.renameSync(path.join(workdir, n), target); moved += 1;
    } catch { /* leave it; bisync will ask for a repair */ }
  }
  return moved;
}

/**
 * Run one bisync for `vault`. Enforces the first-run/blocked resync gate against the state DB, runs the
 * one-shot child through the verified runner using the given ephemeral `config` path, and records the
 * run-state.
 *
 * @param {object} o
 * @param {object} o.runner    a ready RcloneRunner (its run() is checksum/version-gated)
 * @param {object|null} o.db   the encrypted state DB handle (run-state columns only), or null
 * @param {string} o.vault     vault id (run-state key)
 * @param {string} o.local     local folder (path1)
 * @param {string} o.remote    the configured remote + path, "<name>:<path>" (path2)
 * @param {string} o.workdir   the per-vault bisync workdir (see bisyncWorkdir)
 * @param {string} o.config    the ephemeral rclone config path for this run
 * @param {boolean} [o.resync] request a resync (the only thing that satisfies the blocked gate)
 * @param {() => number} [o.now]           injectable clock for the recorded timestamp
 * @param {number} [o.timeoutMs]
 * @returns {Promise<{ran:boolean, code?:number, result:string, resyncRequired:boolean, needsAttention?:boolean, detail?:object|null, stdout?:string, stderr?:string}>}
 */
// A per-step credential prepare (mint-fresh-per-process, resync path) that FAILED — no rclone ran. Surface the
// typed reason AS the run outcome so it reads the same as a dispatch-time failure: a changed identity stays the
// loud mismatch, an unverifiable server the calm cannot-verify, a lost session a sign-in; anything else is a
// retryable error. resyncRequired is carried through unchanged (nothing ran to clear or set it).
const CRED_REASON_RESULT = Object.freeze({
  'host-key-mismatch': 'host-key-mismatch',
  'host-key-unavailable': 'host-key-unverified',
  'no-session': 'auth-failed',
  // A code fault in the credential path (the provider threw, or an unclassified internal error) is a distinct
  // NON-retrying problem, never the generic retryable 'error'.
  'provider-error': 'sync-error',
  'internal-error': 'sync-error',
});
// A TRANSIENT authority refusal (a lock, or a lost connection, mid-resync) is not a failure: the run simply did
// not happen, and it must read as the SAME calm skip the pre-dispatch gate emits — never a "couldn't sync"
// problem. A NOT-RUN shape (result null + the reason) signals the caller to emit a skip that keeps the last
// state. An invariant violation ('not-in-flight' / 'cap-exceeded') is NOT transient — it stays a plain error.
const CRED_REASON_TRANSIENT = new Set(['paused-locked', 'waiting-to-reconnect']);
// A refusal the status layer already names on its own (the server's per-computer credential cap): carried as the
// same NOT-RUN shape so the caller surfaces THAT reason rather than a generic error. It is not transient (the
// cap frees only as credentials expire), so it is kept apart from CRED_REASON_TRANSIENT in name and intent.
const CRED_REASON_NAMED = new Set(['device-cred-cap']);
function credPrepareOutcome(reason, resyncRequired) {
  if (CRED_REASON_TRANSIENT.has(reason) || CRED_REASON_NAMED.has(reason)) {
    return { ran: false, result: null, reason, resyncRequired: !!resyncRequired, needsAttention: false, preserved: 0 };
  }
  const result = CRED_REASON_RESULT[reason] || 'error';
  const needsAttention = result === 'host-key-mismatch' || result === 'auth-failed';
  return { ran: false, result, resyncRequired: !!resyncRequired, needsAttention, preserved: 0 };
}

/**
 * Add the failing file's SIZE to an outcome's detail, read from the local copy.
 *
 * Why it is worth reading: "the server didn't keep this file" and "this vault has 1 MB free" are each true and
 * neither is an answer. Put the file's own size beside them and the answer becomes plain — the file is bigger
 * than the room left — which is what the main process needs before it may say a vault is out of space. The
 * local copy is untouched by a failed upload, so its size is exactly what was attempted.
 *
 * What travels onward is a NUMBER. The relative path is used here, inside the helper that was already given
 * the folder, and is discarded: only { file, maxBytes, bytes } goes on. Best-effort by design — a file moved
 * or renamed since the run simply yields no size, and every sentence downstream works without one.
 */
function withLocalSize(detail, relPath, localRoot) {
  if (!detail || !relPath || typeof localRoot !== 'string' || !localRoot) return detail || null;
  const full = path.resolve(localRoot, relPath);
  // Belt and braces over failedRelPath's own checks: whatever the join produced must still be INSIDE the
  // folder this run was given. Paired with the lstat below, that is what keeps this from reading a size
  // outside the folder the helper was pointed at.
  const root = path.resolve(localRoot);
  if (full !== root && !full.startsWith(root + path.sep)) return detail;
  let bytes = null;
  try {
    // lstat, not stat: stat follows a symlink, so a link inside the folder pointing anywhere on the machine
    // would return the size of its TARGET and the containment check above — which only ever saw the path —
    // would have proved nothing. A link is not the file that failed to upload, so it simply yields no size.
    const st = fs.lstatSync(full);
    if (st.isFile() && Number.isSafeInteger(st.size) && st.size > 0) bytes = st.size;
  } catch { /* gone, unreadable, or never local — the copy works without a size */ }
  return bytes == null ? detail : { ...detail, bytes };
}

async function runBisync(o) {
  const now = o.now || (() => Date.now());
  const state = o.db ? getRunState(o.db, o.vault) : { resyncRequired: true };

  // Fail-closed gate: never run a normal, delete-capable bisync while a resync is required. The caller
  // must surface this and let the user initiate the resync deliberately (nothing auto-resyncs here).
  if (state.resyncRequired && !o.resync) {
    return { ran: false, result: 'blocked-needs-resync', resyncRequired: true, needsAttention: true, stdout: '', stderr: '' };
  }

  // A fresh single-use credential for THIS rclone process, when a per-step provider is wired (the resync path,
  // whose several processes each burn a credential). On failure the TYPED reason becomes the run outcome, never
  // a generic error, so a mid-run host-key rotation stays the loud mismatch and a lost session a sign-in —
  // exactly as they read when the failure happens at dispatch. Nothing ran, so the resync block is untouched.
  if (o.prepareCred) {
    const p = await o.prepareCred();
    if (!p || !p.ok) return credPrepareOutcome(p && p.reason, state.resyncRequired);
  }

  fs.mkdirSync(o.workdir, { recursive: true });
  // The one automatic re-baseline: an empty pair (see emptyPairBaseline). Nothing local can be lost by it.
  const resync = !!o.resync || (!o.resync && emptyPairBaseline({ local: o.local, remote: o.remote, workdir: o.workdir }));
  const args = buildBisyncArgs({ local: o.local, remote: o.remote, workdir: o.workdir, resync });
  const { code, stdout, stderr } = await o.runner.run(args, {
    config: o.config,
    // bisync prints nothing to stdout in normal operation (its log goes to stderr); retain only a small
    // bounded amount for the outcome classifier's haystack so the run can never grow the daemon by its output.
    maxStdoutBytes: BISYNC_MAX_STDOUT_BYTES,
    inactivityMs: o.inactivityMs || SYNC_INACTIVITY_MS,
    hardCeilingMs: o.hardCeilingMs || SYNC_HARD_CEILING_MS,
    // Progress sink: the runner calls this with the two aggregate {files,bytes} integers as bytes move
    // (never a line, never a path). Optional; only wired for the ambient "Syncing…" glance.
    onProgress: o.onProgress,
  });

  // Classify into ONE typed result. A safety abort (excessive delete) and a critical/needs-resync outcome
  // SET the resync block; a completed run clears it; a connection-level block (host-key mismatch) or a
  // plain error leaves the prior block untouched (resyncRequired=null => keep the prior value). Nothing
  // here auto-forces, and nothing auto-clears a latched abort — the one automatic resync above runs only
  // for an empty baseline with an empty local side, where nothing can be lost.
  const outcome = classifyBisyncOutcome({ code, stdout, stderr, resync });
  const resyncRequired = outcome.resyncRequired === null ? state.resyncRequired : outcome.resyncRequired;
  if (o.db) recordRun(o.db, o.vault, { result: outcome.result, resyncRequired, atUtc: now() });
  // `detail` is the bounded pair the classifier built (a checked base file name, a stated maximum in bytes) and
  // NOTHING else from the run's output — it is what lets the status layer name the file and the limit instead of
  // a generic "couldn't sync". Absent for every outcome that has nothing to add.
  // The detail travels; the path its size was read from does NOT (see withLocalSize).
  const detail = withLocalSize(outcome.detail, outcome.failedPath, o.local);
  return { ran: true, code, result: outcome.result, resyncRequired, needsAttention: outcome.needsAttention, detail: detail || null, stdout, stderr };
}

module.exports = { CONNECT_BOUND_ARGS, SINGLE_CONNECTION_ARGS, BISYNC_MAX_STDOUT_BYTES, buildBisyncArgs, runBisync, credPrepareOutcome, bisyncWorkdir, emptyPairBaseline, needsZeroLossBaseline, localHasNoFiles, priorListingEmpty, canonicalPath, carryListings, pairKey, MAX_DELETE_PERCENT, DEFAULT_TIMEOUT_MS, SYNC_STATS_ARGS, SYNC_INACTIVITY_MS, SYNC_HARD_CEILING_MS, MARKER_NAME, MARKER_FILTER_ARGS };

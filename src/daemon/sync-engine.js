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
    ...SYNC_STATS_ARGS]; // periodic progress so the inactivity timeout can tell a long run from a hung one
  if (resync) args.push('--resync'); // only ever on an explicit, user-initiated resync
  return args;
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
 * @returns {Promise<{ran:boolean, code?:number, result:string, resyncRequired:boolean, needsAttention?:boolean, stdout?:string, stderr?:string}>}
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
function credPrepareOutcome(reason, resyncRequired) {
  if (CRED_REASON_TRANSIENT.has(reason)) {
    return { ran: false, result: null, reason, resyncRequired: !!resyncRequired, needsAttention: false, preserved: 0 };
  }
  const result = CRED_REASON_RESULT[reason] || 'error';
  const needsAttention = result === 'host-key-mismatch' || result === 'auth-failed';
  return { ran: false, result, resyncRequired: !!resyncRequired, needsAttention, preserved: 0 };
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
  const args = buildBisyncArgs({ local: o.local, remote: o.remote, workdir: o.workdir, resync: !!o.resync });
  const { code, stdout, stderr } = await o.runner.run(args, {
    config: o.config,
    inactivityMs: o.inactivityMs || SYNC_INACTIVITY_MS,
    hardCeilingMs: o.hardCeilingMs || SYNC_HARD_CEILING_MS,
    // Progress sink: the runner calls this with the two aggregate {files,bytes} integers as bytes move
    // (never a line, never a path). Optional; only wired for the ambient "Syncing…" glance.
    onProgress: o.onProgress,
  });

  // Classify into ONE typed result. A safety abort (excessive delete) and a critical/needs-resync outcome
  // SET the resync block; a completed run clears it; a connection-level block (host-key mismatch) or a
  // plain error leaves the prior block untouched (resyncRequired=null => keep the prior value). Nothing
  // here auto-resyncs or auto-forces — the abort is surfaced, and the server copy is left intact by rclone.
  const outcome = classifyBisyncOutcome({ code, stdout, stderr, resync: !!o.resync });
  const resyncRequired = outcome.resyncRequired === null ? state.resyncRequired : outcome.resyncRequired;
  if (o.db) recordRun(o.db, o.vault, { result: outcome.result, resyncRequired, atUtc: now() });
  return { ran: true, code, result: outcome.result, resyncRequired, needsAttention: outcome.needsAttention, stdout, stderr };
}

module.exports = { buildBisyncArgs, runBisync, credPrepareOutcome, bisyncWorkdir, MAX_DELETE_PERCENT, DEFAULT_TIMEOUT_MS, SYNC_STATS_ARGS, SYNC_INACTIVITY_MS, SYNC_HARD_CEILING_MS };

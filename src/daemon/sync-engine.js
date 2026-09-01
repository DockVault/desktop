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

// The excessive-delete guard: bisync aborts the run if more than this percentage of files on either side
// would be deleted. (bisync interprets --max-delete as a PERCENTAGE, unlike plain `sync`, where it is a
// count.) It is FIXED here, never a caller-supplied argument — a caller must not be able to raise it to
// 100 (which means "abort only above 100%", i.e. never — the failsafe switched off) or otherwise weaken
// it. Tuning it, if ever warranted, is a deliberate edit here, not a runtime option: the guard is
// structural, not defaultal.
const MAX_DELETE_PERCENT = 50;
// bisync can legitimately run long over SFTP; bound it generously rather than leaving it unbounded.
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

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
  const args = ['bisync', String(local), String(remote), '--workdir', String(workdir), '--max-delete', String(MAX_DELETE_PERCENT)];
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
 * @returns {Promise<{ran:boolean, code?:number, result:string, resyncRequired:boolean, stdout?:string, stderr?:string}>}
 */
async function runBisync(o) {
  const now = o.now || (() => Date.now());
  const state = o.db ? getRunState(o.db, o.vault) : { resyncRequired: true };

  // Fail-closed gate: never run a normal, delete-capable bisync while a resync is required. The caller
  // must surface this and let the user initiate the resync deliberately (nothing auto-resyncs here).
  if (state.resyncRequired && !o.resync) {
    return { ran: false, result: 'blocked-needs-resync', resyncRequired: true, stdout: '', stderr: '' };
  }

  fs.mkdirSync(o.workdir, { recursive: true });
  const args = buildBisyncArgs({ local: o.local, remote: o.remote, workdir: o.workdir, resync: !!o.resync });
  const { code, stdout, stderr } = await o.runner.run(args, { config: o.config, timeoutMs: o.timeoutMs || DEFAULT_TIMEOUT_MS });

  const ok = code === 0;
  // s1 coarse outcome: a clean run clears the resync block; a non-clean run leaves the block as it was
  // (a normal run that errored had no block to begin with, so it simply retries next time). The
  // excessive-delete safety abort — which must SET the block regardless — is classified in the next
  // slice; until then a failed run never silently clears the block.
  const result = ok ? (o.resync ? 'resync-ok' : 'ok') : 'error';
  const resyncRequired = ok ? false : state.resyncRequired;
  if (o.db) recordRun(o.db, o.vault, { result, resyncRequired, atUtc: now() });
  return { ran: true, code, result, resyncRequired, stdout, stderr };
}

module.exports = { buildBisyncArgs, runBisync, bisyncWorkdir, MAX_DELETE_PERCENT, DEFAULT_TIMEOUT_MS };

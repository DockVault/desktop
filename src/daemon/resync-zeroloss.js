'use strict';

/*
 * The zero-loss resync: a USER-INITIATED "repair" that re-establishes a clean bidirectional baseline
 * WITHOUT the data loss a bare `bisync --resync` would cause. A bare resync makes the server match local,
 * overwriting a differing server file and deleting a server-only one; here every version the resync would
 * destroy is first copied DOWN to local (so the resync propagates it back up and both survive).
 *
 * Flow: enumerate both sides -> diff (server-only + content-differing) -> preserve each losing version on
 * LOCAL under a keep-both/original name -> `bisync --resync`.
 *
 * Safety properties this module enforces:
 *  - FAIL-CLOSED enumeration (a resync is exempt from the --max-delete guard, so the pre-scan is the ONLY
 *    guard): if either side cannot be fully enumerated/compared, it THROWS and no resync runs. A missed
 *    file would be an unguarded overwrite/delete.
 *  - EXCLUSIVE-CREATE preservation writes (never clobber): each copy reserves its local path O_EXCL; a
 *    keep-both collision bumps the counter and retries, a server-only collision means the state changed
 *    under us and fails closed. A preservation copy that overwrote a real file would itself be the loss.
 *  - PATH-CONTAINED: a preserved copy can only land inside the local target dir (a name with a separator
 *    cannot escape it).
 *  - TRANSIENT-CONTENT hygiene: the content compare streams via `rclone check --download` (no persisted
 *    temp); the preserve copy writes the durable keep-both file directly (0600), no lingering plaintext.
 *  - It is never automatic: it is the deliberate repair action, and it is what CLEARS a resync-required
 *    block — it never weakens the "never auto-resync after a safety abort" invariant.
 */

const fs = require('node:fs');
const path = require('node:path');
const { planPreservation } = require('./resync-plan');
const { keepBothName } = require('./keepboth-name');
const { runBisync, credPrepareOutcome, SYNC_STATS_ARGS, SYNC_INACTIVITY_MS, SYNC_HARD_CEILING_MS } = require('./sync-engine');
const { RESULT } = require('./bisync-outcome');
const { recordRun } = require('../main/state-db');

// `rclone lsf -R --files-only` -> sorted rel paths (forward slashes, rclone's form).
function parseLsf(stdout) {
  return String(stdout == null ? '' : stdout).split(/\r?\n/).map((s) => s.trim()).filter(Boolean).sort();
}

/**
 * Parse `rclone check <local> <remote> --combined -` output for the ON-BOTH files:
 *   '=' equal, '*' differ, '!' could-not-check, '+'/'-' only-one-side (ignored — enumerated via lsf).
 * Returns { differing, covered } where `covered` is the set of on-both paths that got a verdict at all.
 * A '!' on an on-both path is a comparison failure the caller must treat as fail-closed.
 */
function parseCheckDiffering(stdout, onBoth) {
  const set = new Set(onBoth);
  const differing = [];
  const covered = new Set();
  let compareError = false;
  for (const line of String(stdout == null ? '' : stdout).split(/\r?\n/)) {
    const m = line.match(/^([=*+\-!])\s+(.*)$/);
    if (!m) continue;
    const mark = m[1];
    const p = m[2];
    if (!set.has(p)) continue;
    if (mark === '=' || mark === '*' || mark === '!') covered.add(p);
    if (mark === '*') differing.push(p);
    if (mark === '!') compareError = true;
  }
  return { differing: differing.sort(), covered, compareError };
}

// Walk a local dir into rclone-style rel paths (forward slashes), files only.
function walkLocal(root) {
  const out = [];
  const rec = (dir, prefix) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      const rel = prefix ? `${prefix}/${e.name}` : e.name;
      if (e.isDirectory()) rec(full, rel);
      else if (e.isFile()) out.push(rel);
    }
  };
  rec(root, '');
  return out.sort();
}

function dirOf(rel) { const i = rel.lastIndexOf('/'); return i < 0 ? '' : rel.slice(0, i + 1); }
function baseOf(rel) { const i = rel.lastIndexOf('/'); return i < 0 ? rel : rel.slice(i + 1); }

// Reserve `rel` under `localRoot` with O_EXCL (path-contained), bumping a keep-both counter on collision
// for a conflict copy, or failing closed for a server-only copy (its name existing means the state moved).
// Returns { full, rel } of the reserved (empty) file.
function reserveLocalPath(localRoot, action, source, at) {
  let rel = action.to;
  let counter = 1;
  for (;;) {
    const full = path.resolve(localRoot, rel);
    const rootResolved = path.resolve(localRoot);
    if (full !== rootResolved && !full.startsWith(rootResolved + path.sep)) {
      throw new Error(`preserve path escapes the target dir: ${rel}`);
    }
    fs.mkdirSync(path.dirname(full), { recursive: true });
    try { fs.closeSync(fs.openSync(full, 'wx', 0o600)); return { full, rel }; }
    catch (e) {
      if (e.code !== 'EEXIST') throw e;
      if (action.kind !== 'conflict-keep-both') throw new Error(`preserve target already exists (state changed): ${rel}`);
      counter += 1;
      rel = dirOf(action.to) + keepBothName(baseOf(action.from), { source, at, counter });
    }
  }
}

/**
 * @param {object} o
 * @param {object} o.runner   ready RcloneRunner
 * @param {object|null} o.db  encrypted state DB (run-state), or null
 * @param {string} o.vault    run-state key
 * @param {string} o.local    local folder (Path1) absolute path
 * @param {string} o.remote   configured remote + vault path ("vault:<name>")
 * @param {string} o.workdir  bisync workdir
 * @param {string} o.config   ephemeral rclone config path
 * @param {() => number} [o.now]
 * @param {string} [o.source] human origin label for preserved copies (default "the vault")
 * @param {number} [o.timeoutMs]
 * @returns {Promise<{ran:boolean, result:string, preserved:number, resyncRequired:boolean, needsAttention:boolean}>}
 */
async function zeroLossResync(o) {
  const now = o.now || (() => Date.now());
  const source = o.source || 'the vault';
  const at = now(); // one timestamp for the whole repair, so planned names + collision retries agree

  // Every sub-command below is bounded by INACTIVITY (like the bisync run), not a fixed wall clock, so a
  // large-but-progressing pre-scan of a big vault is not false-killed; each is fed periodic stats so a
  // quiet-but-working transfer keeps the timer alive. A generous hard ceiling still bounds a hung run.
  const scanOpts = { config: o.config, inactivityMs: o.inactivityMs || SYNC_INACTIVITY_MS, hardCeilingMs: o.hardCeilingMs || SYNC_HARD_CEILING_MS };

  // The server issues single-use credentials, so EACH rclone process below must authenticate with its own
  // fresh one. `prepareCred` (wired on the resync path) mints a fresh credential and rewrites the ephemeral
  // config in place before a step runs; on failure the typed reason becomes the run outcome (nothing ran, so
  // the resync stays required and is retried). Absent (it never is on this path) it is a no-op.
  const prepare = o.prepareCred || (async () => ({ ok: true }));

  // 1. FAIL-CLOSED enumeration of the server side.
  { const p = await prepare(); if (!p.ok) return { ...credPrepareOutcome(p.reason, true), preserved: 0 }; }
  const ls = await o.runner.run(['lsf', '-R', '--files-only', o.remote, ...SYNC_STATS_ARGS], scanOpts);
  if (ls.code !== 0) throw new Error('zero-loss resync: could not enumerate the server — refusing to resync');
  const serverList = parseLsf(ls.stdout);
  const localList = walkLocal(o.local);
  const localSet = new Set(localList);
  const serverOnly = serverList.filter((p) => !localSet.has(p));
  const onBoth = serverList.filter((p) => localSet.has(p));

  // 2. Content-diff the on-both files (checksum unsupported -> --download byte compare). FAIL-CLOSED if any
  //    on-both file could not be compared (a '!' verdict, or simply no verdict = the run died mid-scan).
  let differing = [];
  if (onBoth.length) {
    { const p = await prepare(); if (!p.ok) return { ...credPrepareOutcome(p.reason, true), preserved: 0 }; }
    const chk = await o.runner.run(['check', o.local, o.remote, '--download', '--combined', '-', ...SYNC_STATS_ARGS], scanOpts)
      .catch((e) => ({ code: -1, stdout: '', stderr: String(e) }));
    const parsed = parseCheckDiffering(chk.stdout, onBoth);
    if (parsed.compareError || parsed.covered.size !== onBoth.length) {
      throw new Error('zero-loss resync: could not compare every shared file — refusing to resync (fail-closed)');
    }
    differing = parsed.differing;
  }

  // 3. Plan + 4. preserve each losing version on LOCAL, exclusive-create, before the resync.
  const plan = planPreservation({ serverOnly, differing, localFiles: localList }, { source, at });
  let preserved = 0;
  for (const action of plan) {
    { const p = await prepare(); if (!p.ok) return { ...credPrepareOutcome(p.reason, true), preserved }; }
    const { full, rel } = reserveLocalPath(o.local, action, source, at);
    const cp = await o.runner.run(['copyto', `${o.remote}/${action.from}`, full, ...SYNC_STATS_ARGS], scanOpts)
      .catch((e) => ({ code: -1, stderr: String(e) }));
    if (cp.code !== 0) { try { fs.rmSync(full, { force: true }); } catch { /* best effort */ } throw new Error(`zero-loss resync: failed to preserve ${action.from} -> ${rel}`); }
    preserved += 1;
  }

  // 5. Establish the clean baseline. resync:true satisfies runBisync's gate and CLEARS a resync-required
  //    block; this is the deliberate user action, never an automatic response to an abort.
  const r = await runBisync({ runner: o.runner, db: o.db, vault: o.vault, local: o.local, remote: o.remote, workdir: o.workdir, config: o.config, resync: true, prepareCred: o.prepareCred, onProgress: o.onProgress, now, timeoutMs: o.timeoutMs });

  // A kept-both conflict is an UNRECONCILED state the user must resolve: even though the resync itself
  // succeeded and the data is safe, the outcome must NOT read as clean (the same anti-lie rule as a normal
  // keep-both run). Flip the result non-green + needsAttention, and record it so every surface agrees.
  // Preserving only server-only files is a clean recovery (nothing to reconcile) and stays green.
  const keptConflict = plan.some((a) => a.kind === 'conflict-keep-both');
  if (r.ran && keptConflict) {
    if (o.db) recordRun(o.db, o.vault, { result: RESULT.CONFLICT_KEEP_BOTH, resyncRequired: r.resyncRequired, atUtc: now() });
    return { ran: r.ran, result: RESULT.CONFLICT_KEEP_BOTH, preserved, resyncRequired: r.resyncRequired, needsAttention: true };
  }
  return { ran: r.ran, result: r.result, preserved, resyncRequired: r.resyncRequired, needsAttention: r.needsAttention };
}

module.exports = { zeroLossResync, parseLsf, parseCheckDiffering, walkLocal, reserveLocalPath };

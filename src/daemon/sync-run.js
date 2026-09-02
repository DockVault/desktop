'use strict';

/*
 * The single dispatch point for one vault run. It exists to make ONE safety rule a property of the code
 * rather than of caller discipline: a resync NEVER runs as a bare, destructive `bisync --resync`.
 *
 * A bare resync makes the server match local — it overwrites a differing server file and deletes a
 * server-only one. So a resync (the deliberate repair, and the initial baseline for a vault that has
 * never completed a run) is routed ONLY through the zero-loss resync, which first preserves every version
 * the resync would destroy (keep-both, on local) and only then establishes the baseline. A normal run is
 * a plain bidirectional bisync. Because every run is dispatched here, nothing else can reach a resync by
 * another route.
 *
 * The engines are injectable purely so the routing is unit-testable without a real rclone; the defaults
 * are the real ones.
 */

const { runBisync } = require('./sync-engine');
const { zeroLossResync } = require('./resync-zeroloss');

/**
 * @param {object} o  { runner, db, vault, local, remote, workdir, config, resync?, prepareCred?, now?, timeoutMs? }
 * @param {{ runBisync?: Function, zeroLossResync?: Function }} [engines]  test seam; defaults are the real engines
 * @returns {Promise<{ran:boolean, result:string, resyncRequired:boolean, needsAttention:boolean, code?:number, preserved?:number}>}
 */
async function runVaultSync(o, engines = {}) {
  const bisync = engines.runBisync || runBisync;
  const resync = engines.zeroLossResync || zeroLossResync;
  const base = {
    runner: o.runner, db: o.db, vault: o.vault, local: o.local, remote: o.remote,
    workdir: o.workdir, config: o.config, now: o.now, timeoutMs: o.timeoutMs,
    // A per-step fresh-credential provider (mint-fresh-per-process). Set only on the resync path, whose several
    // rclone processes each burn a single-use credential; a normal one-process bisync uses the dispatch cred.
    prepareCred: o.prepareCred,
  };
  // A resync — repair or initial baseline — goes ONLY through the keep-both path, never a bare --resync.
  if (o.resync) return resync(base);
  return bisync({ ...base, resync: false });
}

module.exports = { runVaultSync };

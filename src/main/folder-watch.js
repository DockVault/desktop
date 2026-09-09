'use strict';

/*
 * THE FILESYSTEM HALF OF NEAR-LIVE SYNC: one watcher per synced folder, feeding the gate.
 *
 * Every decision about whether a change is worth acting on lives in watch-gate.js. This module owns only the
 * plumbing — starting and stopping watchers as the configuration changes, turning raw events into gate
 * notices, and asking the scheduler when the gate says a vault is due.
 *
 * IT IS AN ACCELERATOR, NEVER A REQUIREMENT. The five-minute poll stays exactly as it was. Every failure
 * here — a platform without recursive watching, a folder on a filesystem that cannot be watched, a folder
 * that disappears, a watcher the OS drops — degrades to "the poll gets it in a few minutes", which is what
 * happens today. So nothing in here throws upward, and a folder that cannot be watched is recorded and
 * skipped rather than retried in a loop or surfaced as a fault. A sync feature that stops working because a
 * watcher could not start would be strictly worse than not watching at all.
 *
 * WHAT IT ASKS FOR, AND WHY THAT SHAPE. A due vault is asked for with the scheduler's ROUTINE request — the
 * same one the poll uses. Not the deliberate-press path: that exists for a person, and it reads and starts
 * the "Sync now" cooldown that bounds how often a person can spend a credential. A watcher borrowing it
 * would be a machine spending a person's allowance, and would defeat the very back-off that keeps a
 * refusing door from being knocked on repeatedly.
 */

const DEFAULT_TICK_MS = 1000;        // how often the gate is asked what has gone quiet
const DEFAULT_RECONCILE_MS = 30000;  // how often the watchers re-check which folders are synced

/**
 * @param {object} o
 * @param {object} o.fs           node:fs (or a fake): needs watch()
 * @param {object} o.gate         a WatchGate
 * @param {(vaultId: string) => void} o.onDue      ask the scheduler (routine request)
 * @param {(line: string) => void} [o.onLog]       a note for the log; never shown to a person
 * @param {number} [o.tickMs]
 * @param {() => Array} [o.readConfig]   re-read the synced folders, so the watchers keep themselves current
 * @param {number} [o.reconcileEveryMs]
 * @param {Function} [o.setIntervalFn] @param {Function} [o.clearIntervalFn]
 */
function createFolderWatch({ fs, gate, onDue, onLog = () => {}, tickMs = DEFAULT_TICK_MS, readConfig = null, reconcileEveryMs = DEFAULT_RECONCILE_MS, setIntervalFn = setInterval, clearIntervalFn = clearInterval }) {
  const watchers = new Map();   // vaultId -> { folder, handle }
  const unwatchable = new Map(); // vaultId -> folder we failed to watch, so it is not retried every reconcile
  const sawRunning = new Set();  // vaults whose 'running' we have seen, so only real runs end a run
  let timer = null;

  const log = (line) => { try { onLog(line); } catch { /* a log must never be the thing that breaks */ } };

  function stopOne(vaultId) {
    const w = watchers.get(vaultId);
    if (!w) return;
    try { if (w.handle && typeof w.handle.close === 'function') w.handle.close(); } catch { /* already gone */ }
    watchers.delete(vaultId);
  }

  function startOne(vaultId, folder) {
    try {
      // `recursive` is the whole point — a synced folder is a tree. Where the platform cannot do it, watch()
      // throws or reports only the top level; either way the poll remains the backstop.
      const handle = fs.watch(folder, { recursive: true, persistent: false }, (_eventType, filename) => {
        try { gate.noticed(vaultId, filename == null ? '' : String(filename)); } catch { /* never let an event throw */ }
      });
      // A watcher the OS drops (the folder was deleted, a network path went away) must not take anything
      // down with it, and must not be retried in a loop.
      if (handle && typeof handle.on === 'function') {
        handle.on('error', () => {
          stopOne(vaultId);
          unwatchable.set(vaultId, folder);
          log(`[watch] stopped watching a folder after an error; the poll still covers it`);
        });
      }
      watchers.set(vaultId, { folder, handle });
      unwatchable.delete(vaultId);
      return true;
    } catch {
      unwatchable.set(vaultId, folder);
      log(`[watch] could not watch a folder; the poll still covers it`);
      return false;
    }
  }

  /**
   * Bring the watchers in line with the configuration: watch every enabled vault with a folder, stop
   * watching anything else, and re-point a vault whose folder has moved.
   */
  function reconcile(entries) {
    const want = new Map();
    for (const e of Array.isArray(entries) ? entries : []) {
      if (!e || !e.vaultId || !e.localFolder) continue;
      if (e.enabled === false) continue;
      want.set(e.vaultId, e.localFolder);
    }
    // Gone, or switched off: stop, and let the gate forget it so nothing is left pending for a vault that
    // is no longer synced here.
    for (const vaultId of [...watchers.keys()]) {
      if (!want.has(vaultId)) { stopOne(vaultId); gate.forget(vaultId); sawRunning.delete(vaultId); }
    }
    for (const vaultId of [...unwatchable.keys()]) if (!want.has(vaultId)) unwatchable.delete(vaultId);

    for (const [vaultId, folder] of want) {
      const cur = watchers.get(vaultId);
      if (cur && cur.folder === folder) continue;                 // already watching the right place
      if (cur) stopOne(vaultId);                                  // the folder moved: re-point
      else if (unwatchable.get(vaultId) === folder) continue;     // already tried this exact folder and failed
      startOne(vaultId, folder);
    }
  }

  /**
   * The scheduler's own view of a run, which is what tells the gate when its writes are ours.
   *
   * Only a phase that FOLLOWS a 'running' ends a run. 'skipped' and 'paused' are emitted by routine ticks for
   * vaults that never started — treating those as a run ending would open a settle window on every poll and
   * quietly swallow real changes for as long as it lasted.
   */
  function noteEvent(vaultId, phase) {
    if (!vaultId || !phase) return;
    if (phase === 'running') { sawRunning.add(vaultId); gate.runStarted(vaultId); return; }
    if (phase === 'queued') return;
    if (sawRunning.delete(vaultId)) gate.runEnded(vaultId);
  }

  function start() {
    if (timer) return;
    // SELF-RECONCILING, rather than a hook at every place the configuration is written. There are eight of
    // those, and a missed one would leave a folder silently unwatched — which degrades to the poll, so it
    // would never announce itself as broken. Re-reading periodically cannot be forgotten by a future edit,
    // and the cost is one config read every half minute. A newly synced folder is watched within that, and
    // the poll covers it meanwhile.
    let ticksToReconcile = 0;
    timer = setIntervalFn(() => {
      if (typeof readConfig === 'function') {
        if (ticksToReconcile <= 0) {
          ticksToReconcile = Math.max(1, Math.ceil(reconcileEveryMs / Math.max(1, tickMs)));
          try { reconcile(readConfig()); } catch { /* a config that cannot be read changes nothing */ }
        }
        ticksToReconcile -= 1;
      }
      let due = [];
      try { due = gate.due(); } catch { due = []; }
      for (const vaultId of due) {
        try { onDue(vaultId); } catch { /* the scheduler's own answer is its business */ }
      }
    }, tickMs);
    if (timer && typeof timer.unref === 'function') timer.unref();
  }

  function stop() {
    if (timer) { try { clearIntervalFn(timer); } catch { /* ignore */ } timer = null; }
    for (const vaultId of [...watchers.keys()]) stopOne(vaultId);
    unwatchable.clear();
    sawRunning.clear();
  }

  return {
    reconcile,
    noteEvent,
    start,
    stop,
    // For tests and for an honest log line: what is actually being watched, and what could not be.
    watching: () => [...watchers.keys()].sort(),
    unwatched: () => [...unwatchable.keys()].sort(),
  };
}

module.exports = { createFolderWatch, DEFAULT_TICK_MS, DEFAULT_RECONCILE_MS };

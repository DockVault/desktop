'use strict';

/*
 * WHEN A CHANGE IN A SYNCED FOLDER SHOULD START A SYNC.
 *
 * A filesystem watcher is easy; a watcher that cannot hurt anything is the work. This is the decision half,
 * kept pure and clock-injected so every rule below is tested without touching a disk.
 *
 * THE LOOP IS THE DANGER, AND IT IS NOT HYPOTHETICAL. A sync writes files INTO the folder it is watching.
 * Left alone, that is a machine that runs forever: sync writes, watcher notices, watcher triggers a sync,
 * that sync writes. Every other rule here is about volume; this one is about the thing being self-powered.
 * So a change seen WHILE a run is in flight for that vault is not a change worth acting on, and neither is
 * one seen in the short settle window after it — filesystem events arrive late, and the last writes of a run
 * routinely land after the run has reported itself finished.
 *
 * THE OTHER THREE RULES ARE VOLUME:
 *   - QUIET PERIOD. Saving a file in most editors is several events; unzipping an archive is thousands. A
 *     change starts (or extends) a quiet timer, and only silence for `quietMs` makes a vault due. A burst of
 *     ten thousand events therefore costs exactly one sync, at the end.
 *   - MINIMUM INTERVAL. Somebody writing continuously — a log file, a video export — never goes quiet, and
 *     the quiet timer alone would then start a sync the moment it ever paused, repeatedly. A vault cannot
 *     become due more often than `minIntervalMs`, which puts a hard ceiling on how often watching can ask
 *     for anything, no matter what the disk does.
 *   - OUR OWN FILES. The hidden sync marker is written by us, and rclone's in-progress temporaries appear
 *     and vanish inside a run. Neither is a person changing anything.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO: it does not decide whether a sync may RUN. It asks the scheduler as a
 * routine request, the same as the poll, so every protection there — the settled-refusal holds, the per-vault
 * back-off after a refusing door, the endpoint gate — applies unchanged. Watching must not become a way to
 * knock on a door that is already refusing, which is exactly how a credential allowance gets spent.
 */

const path = require('node:path');

// A change to one of these is never a person's change.
const MARKER = '.dockvault-sync';
// rclone's working files inside a transfer: partials it renames on completion, and its own temp names.
const OURS = [/\.partial$/i, /\.rclone_chunk\.\d+$/i, /^\.rclone/i, /^~\$/];

/**
 * Is this path something we wrote, rather than something a person changed?
 * Matched on the FILE NAME and on every directory segment, so a change deep inside a folder of ours counts
 * as ours too.
 */
function isOurs(relPath) {
  const p = String(relPath || '');
  if (p === '') return false;
  const segments = p.split(/[\\/]+/).filter(Boolean);
  if (segments.length === 0) return false;
  for (const seg of segments) {
    if (seg === MARKER) return true;
    if (OURS.some((re) => re.test(seg))) return true;
  }
  return false;
}

const DEFAULTS = Object.freeze({
  quietMs: 2500,        // silence before a burst is considered over
  minIntervalMs: 30000, // the hard ceiling on how often watching may ask for a sync
  settleMs: 5000,       // after a run ends, how long its own trailing writes keep arriving
});

class WatchGate {
  /**
   * @param {object} [o]
   * @param {number} [o.quietMs]
   * @param {number} [o.minIntervalMs]
   * @param {number} [o.settleMs]
   * @param {() => number} [o.now]
   */
  constructor({ quietMs, minIntervalMs, settleMs, now } = {}) {
    this.quietMs = Number.isFinite(quietMs) && quietMs >= 0 ? quietMs : DEFAULTS.quietMs;
    this.minIntervalMs = Number.isFinite(minIntervalMs) && minIntervalMs >= 0 ? minIntervalMs : DEFAULTS.minIntervalMs;
    this.settleMs = Number.isFinite(settleMs) && settleMs >= 0 ? settleMs : DEFAULTS.settleMs;
    this._now = typeof now === 'function' ? now : () => Date.now();
    this._pending = new Map();   // vaultId -> when the last interesting change was seen
    this._lastAsked = new Map(); // vaultId -> when this vault was last made due
    this._running = new Set();   // vaults with a run in flight
    this._endedAt = new Map();   // vaultId -> when its last run ended
  }

  /** A run started for this vault: everything it writes from here is ours, not a person's. */
  runStarted(vaultId) { this._running.add(vaultId); this._pending.delete(vaultId); }

  /**
   * A run finished. The settle window starts now — its last writes are still arriving, and treating those as
   * a person's change is precisely the loop this gate exists to prevent.
   */
  runEnded(vaultId) { this._running.delete(vaultId); this._endedAt.set(vaultId, this._now()); this._pending.delete(vaultId); }

  /** True while a change in this vault's folder is more likely ours than a person's. */
  suppressed(vaultId) {
    if (this._running.has(vaultId)) return true;
    const ended = this._endedAt.get(vaultId);
    return ended != null && (this._now() - ended) < this.settleMs;
  }

  /**
   * Record a change. Returns whether it was taken as interesting — false for our own files and for anything
   * arriving inside the suppression window.
   */
  noticed(vaultId, relPath) {
    if (!vaultId) return false;
    if (isOurs(relPath)) return false;
    if (this.suppressed(vaultId)) return false;
    this._pending.set(vaultId, this._now());
    return true;
  }

  /**
   * The vaults whose burst has gone quiet and whose minimum interval allows another ask. Calling this MARKS
   * them as asked, so a caller polling every second does not produce a sync every second.
   */
  due() {
    const now = this._now();
    const out = [];
    for (const [vaultId, at] of [...this._pending]) {
      if (this.suppressed(vaultId)) { this._pending.delete(vaultId); continue; }
      if (now - at < this.quietMs) continue;                       // still inside the burst
      const last = this._lastAsked.get(vaultId);
      if (last != null && now - last < this.minIntervalMs) continue; // the ceiling; the change stays pending
      this._pending.delete(vaultId);
      this._lastAsked.set(vaultId, now);
      out.push(vaultId);
    }
    return out;
  }

  /** A vault that is no longer configured leaves nothing behind. */
  forget(vaultId) {
    this._pending.delete(vaultId);
    this._lastAsked.delete(vaultId);
    this._running.delete(vaultId);
    this._endedAt.delete(vaultId);
  }

  /** How many vaults are waiting on a quiet period — for a test, and for a log line worth having. */
  pendingCount() { return this._pending.size; }
}

module.exports = { WatchGate, isOurs, DEFAULTS, MARKER };

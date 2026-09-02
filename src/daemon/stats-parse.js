'use strict';

/*
 * Streaming parser for rclone's `--stats` blocks on the daemon side of a sync run.
 *
 * It exists for ONE job under a hard confidentiality constraint: pull out ONLY the two aggregate
 * progress numbers — files transferred and bytes transferred — and let NOTHING ELSE reach the surface.
 * rclone's stats block also lists the in-progress files BY PATH (a "Transferring:" header followed by
 * per-file " * <path>: <pct>" lines). Those path bytes must die HERE: never forwarded to the main
 * process, never rendered into "Syncing…", never logged. Progress is worth showing; a filename is not,
 * and a filename is exactly what an attacker (or a bug) would harvest from a progress feed.
 *
 * The design is leak-safe BY CONSTRUCTION, not by after-the-fact scrubbing:
 *   - Lines are assembled across chunk boundaries in a PRIVATE buffer that is never returned, forwarded,
 *     or logged while it holds an incomplete line. A "Transferring:" path line split across two reads is
 *     held only in that buffer until its newline arrives; the completed line is then classified and, as a
 *     stats/path line, DROPPED — no path substring is ever retained (this is the split-read case the
 *     leak gate tests).
 *   - Each COMPLETE line is classified: an aggregate "Transferred:" line updates the {files,bytes}
 *     counters (numbers only) and is then dropped; every other stats-block line (the "Transferring:"
 *     header, a " * path:" per-file line, Checks:/Deleted:/Elapsed/…) is DROPPED; anything that is NOT a
 *     stats-block line is KEPT as genuine non-stats stderr for the run's typed-outcome classification.
 *   - The only things that ever leave this module are two integers (counts()) and the KEPT non-stats
 *     stderr (stderr()) — which holds no stats/path line by construction, so it stays a safe input to the
 *     outcome classifier and bounded on a long run. The raw stats text and the incomplete-line buffer are
 *     never exposed.
 *
 * Pure and dependency-free so the whole thing is exercised by feeding fixture bytes through it (including
 * a path line split across a chunk boundary) and asserting on the actual output.
 */

// A leading rclone log prefix, e.g. "2026/09/03 02:00:05 NOTICE : ". Stripped only to TEST a line for a
// stats keyword; kept lines keep their original text.
const LOG_PREFIX = /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]+\s*:\s*/;

// The per-file progress line under "Transferring:" — rclone prints an INDENTED " * <name>: <progress>".
// Its first non-space token is a lone '*'. This is the leak-critical drop: this line carries the file PATH.
function isPerFileLine(body) { return /^\s*\*\s/.test(body); }

// Section/aggregate rows of a stats block (no path). Dropped after any counts are read — both to bound the
// kept buffer and to keep it path-free by construction. Anchored to the row LABEL (after any indent) so a
// genuine rclone error/notice message (which carries its text after an "ERROR :"/"NOTICE :" prefix, not as
// one of these labels) is never mistaken for a stats row and is kept for classification.
const STATS_SECTION = /^\s*(Transferred|Checks|Checking|Deleted|Renamed|Transferring|Elapsed time|Errors|Bytes|Server Side Copies|Server Side Moves):/;

function isStatsLine(body) { return isPerFileLine(body) || STATS_SECTION.test(body); }

// IEC (binary) unit factors rclone prints by default; SI variants tolerated as a fallback. A bare count
// (no unit) is the FILES line; a value with a unit is the BYTES line.
const UNIT = { B: 1, K: 1024, Ki: 1024, KiB: 1024, kB: 1000, M: 1024 ** 2, Mi: 1024 ** 2, MiB: 1024 ** 2, MB: 1000 ** 2, G: 1024 ** 3, Gi: 1024 ** 3, GiB: 1024 ** 3, GB: 1000 ** 3, T: 1024 ** 4, Ti: 1024 ** 4, TiB: 1024 ** 4, TB: 1000 ** 4, P: 1024 ** 5, Pi: 1024 ** 5, PiB: 1024 ** 5 };

function toBytes(num, unit) {
  const n = parseFloat(num);
  if (!Number.isFinite(n)) return null;
  if (!unit) return null; // no unit => this was the files line, not bytes
  const f = UNIT[unit];
  if (f == null) return null;
  return Math.round(n * f);
}

class StatsStderrParser {
  constructor() {
    this._buf = '';        // incomplete-line assembly buffer — NEVER returned/forwarded/logged while partial
    this._files = null;    // latest aggregate transferred FILE count (int) or null
    this._bytes = null;    // latest aggregate transferred BYTES (int) or null
    this._kept = '';       // NON-stats stderr only (for the typed-outcome classifier)
  }

  /**
   * Feed one raw stderr chunk. Only COMPLETE lines are classified; the trailing incomplete line stays in
   * the private buffer. Returns TRUE iff a {files,bytes} counter advanced — a boolean only, never any text,
   * so the caller can emit a progress event without ever touching a raw line.
   */
  push(chunk) {
    this._buf += String(chunk);
    let advanced = false;
    let nl;
    while ((nl = this._buf.indexOf('\n')) >= 0) {
      let line = this._buf.slice(0, nl);
      this._buf = this._buf.slice(nl + 1);
      if (line.endsWith('\r')) line = line.slice(0, -1);
      if (this._consume(line)) advanced = true;
    }
    return advanced; // the tail (an incomplete, possibly path-bearing line) remains unexposed in this._buf
  }

  /**
   * Flush at end of stream. A run that ends without a trailing newline leaves a final line in the buffer;
   * classify it too so a genuine last error line is not lost. A leftover INCOMPLETE stats/path line is
   * classified the same way — recognised as a stats/path line and dropped, so no path escapes at EOF.
   */
  end() {
    if (this._buf) {
      let line = this._buf;
      this._buf = '';
      if (line.endsWith('\r')) line = line.slice(0, -1);
      this._consume(line);
    }
    return this.counts();
  }

  _consume(line) {
    const body = line.replace(LOG_PREFIX, '');
    if (isStatsLine(body)) return this._readCounts(body); // stats/path line: read any counts, then DROP it
    if (body.trim() !== '') this._kept += line + '\n';     // genuine non-stats stderr: keep for classification
    return false;
  }

  // Read the aggregate transferred count from a "Transferred:" line. Bytes line ("4.521 MiB / …") carries a
  // unit; files line ("3 / 8, …") is a bare integer. Only these two numbers are ever taken from the block.
  _readCounts(body) {
    const m = body.match(/^\s*Transferred:\s*([\d.]+)\s*([A-Za-z]*)\s*\//);
    if (!m) return false;
    const unit = m[2] || '';
    if (unit) {
      const b = toBytes(m[1], unit);
      if (b != null && b !== this._bytes) { this._bytes = b; return true; }
      return false;
    }
    const f = parseInt(m[1], 10);
    if (Number.isFinite(f) && f !== this._files) { this._files = f; return true; }
    return false;
  }

  /** The two aggregate progress integers (null until first seen). The ONLY progress data that leaves here. */
  counts() { return { files: this._files, bytes: this._bytes }; }

  /**
   * The KEPT non-stats stderr, for the run's typed-outcome classifier. Holds no stats/path line by
   * construction, and never the incomplete-line buffer — an unterminated (possibly path-bearing) line is
   * never handed out.
   */
  stderr() { return this._kept; }
}

module.exports = { StatsStderrParser, isStatsLine, isPerFileLine, toBytes };

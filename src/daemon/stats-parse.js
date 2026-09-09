'use strict';

/*
 * Streaming parser for rclone's `--stats` blocks on the daemon side of a sync run.
 *
 * It exists for ONE job under a hard confidentiality constraint: pull out ONLY progress NUMBERS — files
 * and bytes transferred, their totals and percentage, and the percentage of each file in flight — and let
 * NOTHING ELSE reach the surface. rclone's stats block lists the in-progress files BY PATH (a
 * "Transferring:" header followed by per-file " * <path>: <pct> / <size>, <speed>, <eta>" lines). Those path
 * bytes must die HERE: never forwarded to the main process, never rendered into "Syncing…", never logged.
 * Progress is worth showing; a filename is not, and a filename is exactly what an attacker (or a bug) would
 * harvest from a progress feed. Of a per-file line, ONLY its percentage (an integer 0..100) is kept.
 *
 * TWO FORMATS, ONE JOB. The daemon asks the helper for its STRUCTURED log (see rclone-log.js), where each
 * line is an object: the run's own words in one field, the file a message is about in another, and the
 * progress block's numbers as actual numbers in a third. This parser tries that first, and it is strictly
 * better on both counts:
 *   - progress is READ FROM NUMBER FIELDS rather than parsed back out of a rendered block, so the
 *     integers-only promise stops depending on a regex holding its ground against a path;
 *   - the stats record's own message renders that block, per-file paths and all, and is DROPPED whole —
 *     the numbers come from beside it, never from it.
 * A line that is NOT structured takes the text path below, unchanged, so a helper that cannot produce the
 * format degrades to exactly today's behaviour rather than to silence.
 *
 * The design is leak-safe BY CONSTRUCTION, not by after-the-fact scrubbing:
 *   - Lines are assembled across chunk boundaries in a PRIVATE buffer that is never returned, forwarded,
 *     or logged while it holds an incomplete line. A "Transferring:" path line split across two reads is
 *     held only in that buffer until its newline arrives; the completed line is then classified and, as a
 *     stats/path line, DROPPED — no path substring is ever retained (this is the split-read case the
 *     leak gate tests).
 *   - Each COMPLETE line is classified: an aggregate "Transferred:" line updates the counters (numbers
 *     only) and is then dropped; a " * path:" per-file line yields ONE integer (its percentage) and is then
 *     dropped; every other stats-block line (the "Transferring:" header, Checks:/Deleted:/Elapsed/…) is
 *     DROPPED; anything that is NOT a stats-block line is KEPT as genuine non-stats stderr for the run's
 *     typed-outcome classification.
 *   - The only things that ever leave this module are integers (counts()), the KEPT structured records
 *     (records(), each already carrying its own file's name out of its message), and the KEPT non-structured
 *     stderr (stderr()). No STATS line is in either, by construction. A path can still be inside a record's
 *     message — the helper writes its own progress notices with the path in the sentence — which is why the
 *     classifier reads those under the rules in bisync-outcome.js rather than trusting this to be path-free;
 *     what this guarantees is that no path reaches the PROGRESS feed, which is the thing that travels. The
 *     raw stats text and the incomplete-line buffer are never exposed. The per-file list is bounded
 *     (MAX_FILE_PROGRESS entries) so a run with thousands of small files cannot balloon a progress message.
 *   - Both kinds of kept line share ONE retention budget, in arrival order, so adding the structured form
 *     did not add a second buffer to grow: what the daemon holds for a run is bounded exactly as before.
 *
 * Pure and dependency-free so the whole thing is exercised by feeding fixture bytes through it (including
 * a path line split across a chunk boundary) and asserting on the actual output.
 */

const { parseLogRecord, recordSize } = require('./rclone-log');

// A leading rclone log prefix, e.g. "2026/09/03 02:00:05 NOTICE : ". Stripped only to TEST a line for a
// stats keyword; kept lines keep their original text.
const LOG_PREFIX = /^\d{4}\/\d{2}\/\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]+\s*:\s*/;

// The per-file progress line under "Transferring:" — rclone prints an INDENTED " * <name>: <progress>".
// Its first non-space token is a lone '*'. This is the leak-critical drop: this line carries the file PATH.
function isPerFileLine(body) { return /^\s*\*\s/.test(body); }

// The percentage of one per-file line, read from its TAIL — " * <name>: 45% / 3 MiB, 572 KiB/s, 3s" (rclone
// prints "name:100% / 2 MiB" with no space at 100). Anchored at the end so a name containing a colon cannot
// shift it; only the integer is returned, never any part of the name. null when the tail is not in this shape
// (a checking line, or an unexpected format) — then nothing at all is taken from the line.
function perFilePercent(body) {
  const m = body.match(/:\s*(\d{1,3})%\s*\/\s*[\d.]+\s*[A-Za-z]*(?:,[^:]*)?$/);
  if (!m) return null;
  const n = parseInt(m[1], 10);
  return Number.isFinite(n) && n >= 0 && n <= 100 ? n : null;
}

// How many in-flight per-file percentages are carried at most; the COUNT of files in flight is still exact.
const MAX_FILE_PROGRESS = 8;
// Bounds on what the parser RETAINS, so a run that talks forever cannot grow the daemon: the kept non-stats
// stderr (for the outcome classifier) holds at most this many bytes — the FIRST half of the budget (where a
// run's first real error lands) and the LAST half (where rclone's final verdict lands), with the middle
// dropped and the drop flagged. An unterminated partial line longer than MAX_PARTIAL_LINE_BYTES is discarded
// rather than assembled (a real line is a short message or a path; megabytes without a newline are not).
const MAX_KEPT_STDERR_BYTES = 256 * 1024;
const MAX_PARTIAL_LINE_BYTES = 1024 * 1024;

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
    this._filesTotal = null; // ... of how many files rclone has queued so far (int) or null
    this._bytes = null;    // latest aggregate transferred BYTES (int) or null
    this._bytesTotal = null; // ... of how many bytes are queued so far (int) or null
    this._percent = null;  // rclone's own overall percentage (0..100) or null
    this._inFlight = [];   // the percentage of each file in flight in the CURRENT block (ints only, bounded)
    this._inFlightCount = 0; // how many files are in flight in the current block (exact, even past the bound)
    this._checks = null;   // how many files the run has compared, and of how many — watched ONLY so the
    this._checksTotal = null; // ... glance keeps moving through a long listing phase; never shown, never sent
    // What is KEPT for the typed-outcome classifier, in arrival order: the first half-budget of it ...
    this._keptHead = [];   // ... and a rolling window of the most recent within the second half-budget.
    this._keptHeadBytes = 0;
    this._keptTail = [];
    this._keptTailBytes = 0;
    this._headSealed = false; // once a line has gone to the tail, the head takes no more (keeps the kept text in order)
    this._skipLine = false;   // an over-long partial line was dropped: the rest of it (to its newline) goes too
    this._truncated = false; // something kept for the classifier was dropped to stay within the budget
    this._textTruncated = false; // ... and some of it was non-structured text (see _dropped)
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
      if (this._skipLine) { this._skipLine = false; continue; } // the rest of a dropped over-long line: gone too
      if (line.endsWith('\r')) line = line.slice(0, -1);
      if (this._consume(line)) advanced = true;
    }
    // A partial line that has outgrown any legitimate line is dropped WHOLE, not assembled without bound: what is
    // buffered goes now, and whatever remains of it up to its newline is skipped as it arrives.
    if (this._skipLine) this._buf = '';
    else if (this._buf.length > MAX_PARTIAL_LINE_BYTES) { this._buf = ''; this._skipLine = true; this._truncated = true; }
    return advanced; // the tail (an incomplete, possibly path-bearing line) remains unexposed in this._buf
  }

  /**
   * Flush at end of stream. A run that ends without a trailing newline leaves a final line in the buffer;
   * classify it too so a genuine last error line is not lost. A leftover INCOMPLETE stats/path line is
   * classified the same way — recognised as a stats/path line and dropped, so no path escapes at EOF.
   */
  end() {
    if (this._buf && !this._skipLine) {
      let line = this._buf;
      this._buf = '';
      if (line.endsWith('\r')) line = line.slice(0, -1);
      this._consume(line);
    }
    return this.counts();
  }

  _consume(line) {
    // The STRUCTURED form first. A file name cannot produce one of these: it lives inside a JSON string and
    // the encoder escapes whatever would end it, so nothing a name contains can close a record or open one.
    const rec = parseLogRecord(line);
    if (rec) return this._consumeRecord(rec);
    const body = line.replace(LOG_PREFIX, '');
    if (isPerFileLine(body)) return this._readPerFile(body);   // path line: keep ONE integer, then DROP it
    if (isStatsLine(body)) return this._readCounts(body); // stats line: read any counts, then DROP it
    if (body.trim() !== '') this._keep({ size: line.length + 1, text: line + '\n' }); // genuine non-stats stderr: keep (bounded)
    return false;
  }

  // One structured record. A stats record carries the progress NUMBERS in their own field and RENDERS the
  // stats block — per-file paths included — in its message: the numbers are read, the message is dropped
  // whole, and nothing of it is ever retained. Every other record is kept for the outcome classifier with
  // its own file's name already taken out of its message (see rclone-log.js).
  _consumeRecord(rec) {
    if (rec.stats) return this._readJsonStats(rec.stats);
    if (rec.msg.trim() === '') return false;
    this._keep({ size: recordSize(rec), rec });
    return false;
  }

  // Retain one kept item within the fixed budget: the head fills first (a run's first real error), then a
  // rolling tail keeps the most recent items (rclone's final verdict), evicting the oldest tail items.
  // Structured records and non-structured lines share this ONE budget, in arrival order.
  _keep(item) {
    const half = MAX_KEPT_STDERR_BYTES / 2;
    if (!this._headSealed && this._keptHeadBytes + item.size <= half) { this._keptHead.push(item); this._keptHeadBytes += item.size; return; }
    this._headSealed = true; // from here on everything goes to the tail, so head + tail stay in arrival order
    if (item.size > half) { this._dropped(item); return; } // a single item past the whole tail budget: drop it
    this._keptTail.push(item); this._keptTailBytes += item.size;
    while (this._keptTailBytes > half) { const gone = this._keptTail.shift(); this._keptTailBytes -= gone.size; this._dropped(gone); }
  }

  // Read the aggregate counts from a "Transferred:" line. The bytes line ("4.521 MiB / 10 MiB, 45%, …")
  // carries units; the files line ("3 / 8, 38%") is bare integers. Only numbers are ever taken from the block.
  // The bytes line opens a stats block, so it also starts a fresh in-flight list: a block with no
  // "Transferring:" section (the transfers are done) leaves the list empty rather than a stale one.
  _readCounts(body) {
    const m = body.match(/^\s*Transferred:\s*([\d.]+)\s*([A-Za-z]*)\s*\/\s*([\d.]+)\s*([A-Za-z]*)(?:,\s*(\d{1,3})%)?/);
    if (!m) return false;
    let advanced = false;
    const unit = m[2] || '';
    const pct = m[5] != null ? parseInt(m[5], 10) : null;
    if (unit) {
      if (this._inFlight.length || this._inFlightCount) { this._inFlight = []; this._inFlightCount = 0; advanced = true; }
      const b = toBytes(m[1], unit);
      const t = toBytes(m[3], m[4] || unit);
      if (b != null && b !== this._bytes) { this._bytes = b; advanced = true; }
      if (t != null && t !== this._bytesTotal) { this._bytesTotal = t; advanced = true; }
      if (pct != null && pct >= 0 && pct <= 100 && pct !== this._percent) { this._percent = pct; advanced = true; }
      return advanced;
    }
    const f = parseInt(m[1], 10);
    const ft = parseInt(m[3], 10);
    if (Number.isFinite(f) && f !== this._files) { this._files = f; advanced = true; }
    if (Number.isFinite(ft) && ft !== this._filesTotal) { this._filesTotal = ft; advanced = true; }
    return advanced;
  }

  /**
   * The progress numbers of one STRUCTURED stats record. Every value taken here is already a number in the
   * helper's own field — nothing is parsed out of rendered text, and no field that could hold a name or a
   * path (the in-flight entries also carry `name`, `srcFs`, `dstFs`) is read at all.
   *
   * The overall percentage is COMPUTED from the two byte counters rather than taken from the rendered
   * block, which is where the text path read it; rounding matches what the helper renders.
   */
  _readJsonStats(s) {
    const int = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.trunc(v) : null);
    let advanced = false;
    const bytes = int(s.bytes);
    const bytesTotal = int(s.totalBytes);
    const files = int(s.transfers);
    const filesTotal = int(s.totalTransfers);
    if (bytes != null && bytes !== this._bytes) { this._bytes = bytes; advanced = true; }
    if (bytesTotal != null && bytesTotal !== this._bytesTotal) { this._bytesTotal = bytesTotal; advanced = true; }
    if (files != null && files !== this._files) { this._files = files; advanced = true; }
    if (filesTotal != null && filesTotal !== this._filesTotal) { this._filesTotal = filesTotal; advanced = true; }
    const pct = (this._bytes != null && this._bytesTotal != null && this._bytesTotal > 0)
      ? Math.max(0, Math.min(100, Math.round((this._bytes * 100) / this._bytesTotal)))
      : null;
    if (pct != null && pct !== this._percent) { this._percent = pct; advanced = true; }
    // The files in flight: how MANY (exact), and the percentage of each (bounded, integers, in the
    // helper's order). Each entry also names the file and both ends of the transfer; none of that is read.
    // The run is also DOING something while it lists and compares, and that phase can run for minutes on a
    // large vault. The text format reported every block, so the glance kept moving; reading only the transfer
    // counters made those minutes look frozen. The check counters are watched for that reason alone — they
    // are integers like the rest, and nothing about them is shown.
    const checks = int(s.checks);
    const checksTotal = int(s.totalChecks);
    if (checks != null && checks !== this._checks) { this._checks = checks; advanced = true; }
    if (checksTotal != null && checksTotal !== this._checksTotal) { this._checksTotal = checksTotal; advanced = true; }
    const list = Array.isArray(s.transferring) ? s.transferring : [];
    const inFlight = [];
    for (let i = 0; i < list.length && inFlight.length < MAX_FILE_PROGRESS; i += 1) {
      const p = list[i] && int(list[i].percentage);
      if (p != null && p >= 0 && p <= 100) inFlight.push(p);
    }
    if (list.length !== this._inFlightCount || inFlight.join(',') !== this._inFlight.join(',')) {
      this._inFlightCount = list.length; this._inFlight = inFlight; advanced = true;
    }
    return advanced;
  }

  // One file in flight: count it, keep its percentage (bounded), and let the line die here.
  _readPerFile(body) {
    this._inFlightCount += 1;
    const pct = perFilePercent(body);
    if (pct != null && this._inFlight.length < MAX_FILE_PROGRESS) this._inFlight.push(pct);
    return true;
  }

  /**
   * The progress integers (null until first seen). The ONLY progress data that leaves here: aggregate files
   * and bytes moved, their totals and rclone's overall percentage, the number of files in flight, and the
   * percentage of each (bounded, in rclone's order — never a name).
   */
  counts() {
    return {
      files: this._files, filesTotal: this._filesTotal,
      bytes: this._bytes, bytesTotal: this._bytesTotal,
      percent: this._percent,
      transferring: this._inFlightCount,
      fileProgress: this._inFlight.slice(),
    };
  }

  // Something was dropped to stay inside the budget. Which KIND matters only for the marker below: it stands
  // in the text for lines that were dropped, and it would be a lie in either direction if it were written for
  // records instead — a run whose text was kept whole would claim it was trimmed, and one whose text was
  // trimmed would not say so once the tail held only records.
  _dropped(item) { this._truncated = true; if (item.text) this._textTruncated = true; }

  /**
   * The KEPT stderr that was NOT structured, for the run's typed-outcome classifier. Holds no stats/path
   * line by construction, and never the incomplete-line buffer — an unterminated (possibly path-bearing)
   * line is never handed out. Under the structured format this is normally empty and records() carries
   * the run; it is what a helper that cannot produce that format falls back to.
   */
  stderr() {
    const text = (items) => items.map((i) => i.text || '').join('');
    const head = text(this._keptHead);
    const tail = text(this._keptTail);
    if (!this._textTruncated) return head + tail;
    return `${head}[... stderr trimmed ...]\n${tail}`;
  }

  /**
   * The KEPT STRUCTURED records, in arrival order, for the run's typed-outcome classifier. Each carries
   * the tool's own words (colour stripped, line breaks flattened, the file's own name taken out of them),
   * the level the tool logged it at, and the file the message was about as its own field — so the
   * classifier reads a verdict from a message and never from a name. No stats record is ever among them.
   */
  records() { return [...this._keptHead, ...this._keptTail].filter((i) => i.rec).map((i) => i.rec); }

  // Whether anything kept for the classifier — a record or a non-structured line — was dropped to stay
  // within the retention budget. A run that says so did not necessarily lose a verdict, but it may have.
  truncated() { return this._truncated; }
}

module.exports = { StatsStderrParser, isStatsLine, isPerFileLine, perFilePercent, toBytes, MAX_FILE_PROGRESS, MAX_KEPT_STDERR_BYTES };

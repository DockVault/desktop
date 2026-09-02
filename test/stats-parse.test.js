'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { StatsStderrParser, isStatsLine, isPerFileLine, toBytes } = require('../src/daemon/stats-parse');

// A faithful rclone `--stats --stats-log-level NOTICE` block. The per-file "Transferring:" lines carry
// PATHS (with a distinctive marker so a leak is unmistakable in an assertion).
const BLOCK =
  '2026/09/03 02:00:05 NOTICE: \n' +
  'Transferred:   \t    4.521 MiB / 12.340 MiB, 37%, 1.234 MiB/s, ETA 6s\n' +
  'Transferred:            3 / 8, 38%\n' +
  'Checks:                 2 / 2, 100%\n' +
  'Deleted:                1 (files)\n' +
  'Elapsed time:         3.2s\n' +
  'Transferring:\n' +
  ' *      Documents/SECRET-report-Q3.pdf: 45% /2.100Mi, 512.3Ki/s, 3s\n' +
  ' *      Photos/SECRET-holiday.jpg:  0% /1.500Mi, 0/s, -\n';

const PATH_MARKER = /SECRET/;

test('extracts ONLY the two aggregate counts {files,bytes} from a stats block', () => {
  const p = new StatsStderrParser();
  p.push(BLOCK);
  p.end();
  const c = p.counts();
  assert.strictEqual(c.files, 3, 'files = the aggregate Transferred file count');
  assert.strictEqual(c.bytes, Math.round(4.521 * 1024 * 1024), 'bytes = the aggregate Transferred bytes (MiB -> bytes)');
});

test('LEAK GATE: no path from the "Transferring:" lines survives into stderr() or counts()', () => {
  const p = new StatsStderrParser();
  p.push(BLOCK);
  p.end();
  assert.doesNotMatch(p.stderr(), PATH_MARKER, 'the kept classification buffer holds NO file path');
  assert.strictEqual(JSON.stringify(p.counts()).match(PATH_MARKER), null, 'counts carry only numbers, never a path');
  // The whole stats block is stats/noise, so nothing at all is kept from it.
  assert.strictEqual(p.stderr(), '', 'a pure stats block leaves the classification buffer empty');
});

test('LEAK GATE (split read): a per-file PATH line split across two chunks never leaks', () => {
  const p = new StatsStderrParser();
  // Split right in the middle of the path — the classic streaming-parser leak.
  const line = ' *      Documents/SECRET-split-across-a-chunk.pdf: 45% /2.1Mi, 1/s, 3s\n';
  const cut = line.indexOf('SECRET') + 3; // mid-path
  p.push('Transferring:\n' + line.slice(0, cut)); // chunk 1 ends mid-path (no newline yet)
  // While the line is incomplete, nothing is kept and no fragment is exposed.
  assert.strictEqual(p.stderr(), '', 'no fragment kept while the path line is still incomplete');
  p.push(line.slice(cut)); // chunk 2 completes the line
  p.end();
  assert.doesNotMatch(p.stderr(), PATH_MARKER, 'the completed path line is dropped — no substring retained');
  assert.strictEqual(p.stderr(), '', 'the split path line leaves the buffer empty');
});

test('LEAK GATE (tick-emit boundary): a count advance that emits WHILE a path line is mid-buffer carries no path', () => {
  const p = new StatsStderrParser();
  // One read: a completed "Transferred:" count (advances -> the runner would fire onProgress here) FOLLOWED by
  // an incomplete path line still awaiting its newline — the tick-emit straddling the assembly buffer.
  const advanced = p.push('Transferred: 3 / 8, 38%\n *  /Users/me/SECRET-straddles-a-tick.pdf: 50% /1Mi');
  assert.strictEqual(advanced, true, 'the count advanced — the runner would emit onProgress at exactly this point');
  const emitted = p.counts(); // precisely what onProgress would carry at that emit
  assert.strictEqual(emitted.files, 3);
  assert.strictEqual(JSON.stringify(emitted).match(PATH_MARKER), null, 'the emitted counts carry no path fragment from the mid-buffer line');
  assert.doesNotMatch(p.stderr(), PATH_MARKER, 'the buffered incomplete path fragment is never kept');
  p.push('\n'); // complete the path line
  p.end();
  assert.doesNotMatch(p.stderr(), PATH_MARKER, 'the completed path line is dropped, no substring retained');
});

test('LEAK GATE (space + unicode path): a path with spaces/unicode is recognised and dropped, never extracted-from', () => {
  const p = new StatsStderrParser();
  p.push('Transferring:\n *  /Users/me/Rapport Financier Q3 — SECRET-CONFIDENTIEL.pdf: 12% /3Mi, 1/s, 5s\n');
  p.end();
  assert.doesNotMatch(p.stderr(), PATH_MARKER, 'a path with spaces and a unicode dash is dropped');
  assert.deepStrictEqual(p.counts(), { files: null, bytes: null }, 'no count is mistakenly extracted from a per-file path line');
});

test('KEEPS genuine non-stats stderr (error/notice lines) for the outcome classifier', () => {
  const p = new StatsStderrParser();
  p.push('2026/09/03 02:00:06 ERROR : something genuinely went wrong\n');
  p.push(BLOCK); // interleaved stats must not disturb the kept error line
  p.end();
  assert.match(p.stderr(), /something genuinely went wrong/, 'a real error line is kept');
  assert.doesNotMatch(p.stderr(), PATH_MARKER, 'still no path from the interleaved stats block');
});

test('data-safety signals SURVIVE the filter (delete abort / all-changed / mismatch still classifiable)', () => {
  const p = new StatsStderrParser();
  p.push('2026/09/03 02:00:07 ERROR : Safety abort: too many deletes (>50%, 5 of 7). Bisync aborted.\n');
  p.push('2026/09/03 02:00:07 ERROR : Safety abort: all files were changed on Path1. Bisync aborted.\n');
  p.push(BLOCK);
  p.end();
  assert.match(p.stderr(), /too many deletes/, 'the excessive-delete abort line is kept — delete-safety not masked');
  assert.match(p.stderr(), /all files were changed/, 'the all-changed abort line is kept');
});

test('push() returns true only when a counter advances — the progress trigger', () => {
  const p = new StatsStderrParser();
  assert.strictEqual(p.push('Checks: 2 / 2, 100%\n'), false, 'a non-Transferred stats line does not advance progress');
  assert.strictEqual(p.push('Transferred: 3 / 8, 38%\n'), true, 'first files count advances');
  assert.strictEqual(p.push('Transferred: 3 / 8, 38%\n'), false, 'an unchanged count does not advance');
  assert.strictEqual(p.push('Transferred: 5 / 8, 62%\n'), true, 'a changed count advances');
});

test('end() flush: a leftover INCOMPLETE path line at EOF is dropped, a real error line is kept', () => {
  const p1 = new StatsStderrParser();
  p1.push(' *      Documents/SECRET-truncated-at-eof.pdf: 45% /2.1Mi'); // no trailing newline (child killed mid-line)
  p1.end();
  assert.doesNotMatch(p1.stderr(), PATH_MARKER, 'an unterminated path line at EOF is recognised and dropped');

  const p2 = new StatsStderrParser();
  p2.push('2026/09/03 02:00:08 ERROR : final error without newline');
  p2.end();
  assert.match(p2.stderr(), /final error without newline/, 'a genuine last line without a newline is still kept');
});

test('classifiers: per-file path line and section rows are recognised; a real message is not', () => {
  assert.ok(isPerFileLine(' *  path/to/file: 1%'), 'indented " * path" is a per-file line');
  assert.ok(isStatsLine('Transferred:   3 / 8'), 'Transferred: is a stats row');
  assert.ok(isStatsLine('  Transferring:'), 'the (indented) Transferring: header is a stats row');
  assert.ok(!isStatsLine('Safety abort: too many deletes'), 'a Safety abort message is NOT a stats row');
  assert.ok(!isStatsLine('ok, done'), 'ordinary text is not a stats row');
});

test('toBytes converts IEC units and rejects a bare (files) value', () => {
  assert.strictEqual(toBytes('4.521', 'MiB'), Math.round(4.521 * 1024 * 1024));
  assert.strictEqual(toBytes('2', 'GiB'), 2 * 1024 ** 3);
  assert.strictEqual(toBytes('512', 'B'), 512);
  assert.strictEqual(toBytes('3', ''), null, 'no unit => not a byte value (it was the files line)');
});

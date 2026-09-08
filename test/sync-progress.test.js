'use strict';

// Progress surfacing: the honest "syncing" glance appears ONLY while a run is actually transferring, it
// carries the two aggregate counts (never a path, never a percentage), and it clears the moment the run ends.

const test = require('node:test');
const fs = require('node:fs');
const path = require('node:path');
const assert = require('node:assert');
const { SyncStatusHub } = require('../src/main/sync-status-hub');
const { STATE } = require('../src/main/sync-status-model');
const tray = require('../src/main/tray-presentation');

function hub1() { const h = new SyncStatusHub({ locked: false, online: true }); h.setVaults(['v1']); return h; }
const vof = (h) => h.current().vaults.find((v) => v.vault === 'v1');

test('hub.recordProgress: syncing shows only with a run in flight AND real bytes moving', () => {
  const h = hub1();
  h.recordProgress('v1', { files: 3, bytes: 1048576 });
  assert.notStrictEqual(vof(h).state, STATE.SYNCING, 'progress with no run in flight is ignored — never a phantom syncing');
  h.setRunning('v1', true);
  assert.notStrictEqual(vof(h).state, STATE.SYNCING, 'a dispatched run alone (scanning) is not syncing — quiet');
  h.recordProgress('v1', { files: 0, bytes: 0 });
  assert.notStrictEqual(vof(h).state, STATE.SYNCING, 'a zero report is not motion — stays quiet');
  h.recordProgress('v1', { files: 3, bytes: 1048576 });
  assert.strictEqual(vof(h).state, STATE.SYNCING, 'a positive count shows syncing');
  assert.deepStrictEqual(vof(h).progress, { files: 3, filesTotal: null, bytes: 1048576, bytesTotal: null, percent: null, transferring: 0, fileProgress: [] }, 'carrying the aggregate counts (totals unknown here)');
  h.recordOutcome('v1', { result: 'ok', resyncRequired: false });
  assert.strictEqual(vof(h).state, STATE.UP_TO_DATE);
  assert.strictEqual(vof(h).progress, null, 'progress cleared on completion');
});

test('hub: a fresh dispatch resets prior transfer motion (no stale "syncing" carried into a new run)', () => {
  const h = hub1();
  h.setRunning('v1', true); h.recordProgress('v1', { files: 2, bytes: 2048 });
  assert.strictEqual(vof(h).state, STATE.SYNCING);
  h.setRunning('v1', true); // a fresh dispatch
  assert.notStrictEqual(vof(h).state, STATE.SYNCING, 'the fresh run starts quiet — motion re-earned only on a new transfer');
  assert.strictEqual(vof(h).progress, null);
});

test('hub: a data-safety outcome preempts "syncing" even if a stale progress lingered', () => {
  const h = hub1();
  h.setRunning('v1', true); h.recordProgress('v1', { files: 1, bytes: 1024 });
  assert.strictEqual(vof(h).state, STATE.SYNCING);
  h.recordOutcome('v1', { result: 'abort-excessive-delete', resyncRequired: true });
  assert.strictEqual(vof(h).state, STATE.NEEDS_DECISION, 'the delete-abort decision wins; "syncing" is gone');
  assert.strictEqual(vof(h).progress, null);
});

test('tray tooltip: the honest count detail while syncing — no percentage, no path', () => {
  const model = { state: STATE.SYNCING, label: 'Syncing', reason: null, progress: { files: 3, bytes: 4404019 }, vaults: [], condition: null };
  const tip = tray.tooltip(model, null);
  assert.match(tip, /Syncing/);
  assert.match(tip, /3 files/);
  assert.match(tip, /4\.2 MB/, 'bytes rendered as a human size (4404019 -> 4.2 MB)');
  assert.doesNotMatch(tip, /%/, 'never a percentage');
});

test('tray formatBytes / progressDetail: counts only, singular/plural, omit what is missing', () => {
  assert.strictEqual(tray.formatBytes(0), null, 'zero omitted');
  assert.strictEqual(tray.formatBytes(512), '512 B');
  assert.strictEqual(tray.formatBytes(1048576), '1 MB');
  assert.strictEqual(tray.progressDetail({ files: 1, bytes: null }), '1 file', 'singular, bytes omitted');
  assert.strictEqual(tray.progressDetail({ files: 5, bytes: 2048 }), '5 files · 2 KB');
  assert.strictEqual(tray.progressDetail({ files: 0, bytes: 0 }), null, 'nothing moved yet => no detail');
  assert.strictEqual(tray.progressDetail(null), null);
  assert.strictEqual(tray.progressDetail({ percent: 45, files: 3, filesTotal: 8, bytes: 4404019, bytesTotal: 9542042 }), '45% · 3 of 8 files · 4.2 MB of 9.1 MB', 'the percentage leads, then what has moved of what is queued');
  assert.strictEqual(tray.progressDetail({ percent: 0, files: 0, filesTotal: 1, bytes: 0, bytesTotal: 1048576, transferring: 1 }), '0% · 0 of 1 file', 'a transfer that has just started still reads honestly');
  assert.strictEqual(tray.progressDetail({ percent: 101, files: 2, bytes: 10 }), '2 files · 10 B', 'an out-of-range percentage is not shown');
});

test('the manage page: the state chip carries an icon per face and the percentage on hover; a transfer strip only while bytes move', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'manage.js'), 'utf8');
  const html = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'manage.html'), 'utf8');
  assert.match(src, /icon: 'xfer'/, 'a transferring icon face');
  assert.match(src, /icon: 'ok'/, 'an idle (up to date) face');
  assert.match(src, /icon: 'bad'/, 'a problem face');
  assert.match(src, /st\.title = s\.title/, 'the hover text is set on the chip');
  assert.match(src, /\$\{pct\}%/, 'the percentage is part of the hover detail');
  assert.match(src, /setTransfer\(card, s\.transfer \|\| null\)/, 'the strip follows the state — removed when nothing moves');
  assert.match(html, /\.ico\.xfer[^}]*animation/, 'the transferring icon is animated');
  assert.match(html, /prefers-reduced-motion/, 'motion is respected');
  assert.doesNotMatch(src, /progress\.(name|path|file\b)/, 'the page never reads a name or path off the progress');
});


test('hub.recordProgress: totals, the percentage and the in-flight percentages ride along as integers; a file in flight alone is motion', () => {
  const h = hub1();
  h.setRunning('v1', true);
  h.recordProgress('v1', { files: 0, filesTotal: 2, bytes: 0, bytesTotal: 5242880, percent: 0, transferring: 1, fileProgress: [0] });
  assert.strictEqual(vof(h).state, STATE.SYNCING, 'a file in flight (even at 0%) is motion');
  h.recordProgress('v1', { files: 1, filesTotal: 2, bytes: 3145728, bytesTotal: 5242880, percent: 60, transferring: 1, fileProgress: [50] });
  assert.deepStrictEqual(vof(h).progress, { files: 1, filesTotal: 2, bytes: 3145728, bytesTotal: 5242880, percent: 60, transferring: 1, fileProgress: [50] });
  // Garbage never passes: strings, NaN, out-of-range or over-long per-file lists are dropped field by field.
  h.recordProgress('v1', { files: '3', filesTotal: NaN, bytes: 4, bytesTotal: 'x', percent: 101, transferring: 'many', fileProgress: [5, 'a', 200, -1, 7, 1, 2, 3, 4, 5, 6, 7] });
  assert.deepStrictEqual(vof(h).progress, { files: null, filesTotal: null, bytes: 4, bytesTotal: null, percent: 101, transferring: 0, fileProgress: [5, 7, 1, 2, 3, 4, 5, 6] }, 'numbers or null; the list bounded to 8 integers 0..100');
});

test('model: the transfer numbers ride along while bytes move whatever face the vault wears (a Repair under "needs your decision" shows its progress); they clear when nothing moves', () => {
  const { vaultState, STATE: S } = require('../src/main/sync-status-model');
  const progress = { files: 1, filesTotal: 3, bytes: 10, bytesTotal: 30, percent: 33, transferring: 1, fileProgress: [50] };
  const repairing = vaultState({ vault: 'v', running: true, transferring: true, progress, lastResult: 'needs-resync', resyncRequired: true });
  assert.strictEqual(repairing.state, S.NEEDS_DECISION, 'the latch keeps its face until the repair completes');
  assert.deepStrictEqual(repairing.progress, progress, 'but the transfer is shown');
  const scanning = vaultState({ vault: 'v', running: true, transferring: false, progress, lastResult: 'ok', resyncRequired: false });
  assert.strictEqual(scanning.progress, null, 'not transferring: no numbers');
  const idle = vaultState({ vault: 'v', running: false, transferring: true, progress, lastResult: 'ok', resyncRequired: false });
  assert.strictEqual(idle.progress, null, 'no run in flight: no numbers');
});

test('the manage page: a Repair that is transferring keeps its "Needs your decision" face and shows the strip (consistent with the tray), not a bare "Syncing"', () => {
  const fs = require('node:fs'); const path = require('node:path');
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'manage.js'), 'utf8');
  // The higher-ranked faces keep their identity while transferring.
  assert.match(src, /OUTRANKS_SYNCING = new Set\(\['paused', 'needs-decision', 'sync-problem', 'unavailable'\]\)/);
  assert.match(src, /OUTRANKS_SYNCING\.has\(local\.state\) \? faceOf\(local\.state\) : \{ text: 'Syncing'/, 'a higher face is kept; only an idle/syncing face becomes "Syncing"');
  // The pre-transfer scan reads "Checking…", not a near-duplicate "Syncing now".
  assert.match(src, /text: 'Checking…', tone: 'run', icon: 'busy'/);
  assert.doesNotMatch(src, /'Syncing now'/, 'the near-duplicate label is gone');
  // An unknown state never renders a raw token.
  assert.doesNotMatch(src, /String\(local\.state\)/, 'no raw state token in the chip');
});

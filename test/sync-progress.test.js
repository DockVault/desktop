'use strict';

// Progress surfacing: the honest "syncing" glance appears ONLY while a run is actually transferring, it
// carries the two aggregate counts (never a path, never a percentage), and it clears the moment the run ends.

const test = require('node:test');
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
  assert.deepStrictEqual(vof(h).progress, { files: 3, bytes: 1048576 }, 'carrying the two aggregate counts');
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
});

test('tray vaultRows: the transfer detail rides only on the actually-syncing vault', () => {
  const configured = [{ vaultId: 'v1', vaultName: 'Photos' }, { vaultId: 'v2', vaultName: 'Docs' }];
  const modelVaults = [
    { vault: 'v1', state: STATE.SYNCING, running: true, progress: { files: 2, bytes: 3145728 }, lastSyncedAt: null },
    { vault: 'v2', state: STATE.UP_TO_DATE, running: false, progress: null, lastSyncedAt: 1000 },
  ];
  const rows = tray.vaultRows(configured, modelVaults, 2000);
  assert.strictEqual(rows[0].syncingDetail, '2 files · 3 MB', 'the syncing vault shows the detail');
  assert.strictEqual(rows[1].syncingDetail, null, 'a non-syncing vault has no transfer detail');
});

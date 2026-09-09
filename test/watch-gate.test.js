'use strict';

// WHEN A CHANGE IN A SYNCED FOLDER SHOULD START A SYNC.
//
// The acceptance for near-live sync says the watcher must be "debounced/bounded so a burst of changes can't
// spin the scheduler or re-open the credential flood". Those are three separate failures and the tests below
// keep them separate:
//
//   1. THE LOOP. A sync writes into the folder it watches. Without suppression that is a perpetual motion
//      machine — and unlike the other two it does not need a burst, an unusual folder, or an impatient
//      person to happen. It happens on the first successful sync, every time.
//   2. THE BURST. Ten thousand events from unzipping an archive must cost one sync, not ten thousand.
//   3. THE CONTINUOUS WRITER. Something that never goes quiet must not be able to ask forever just because
//      it pauses for a moment now and then.

const test = require('node:test');
const assert = require('node:assert/strict');

const { WatchGate, isOurs } = require('../src/main/watch-gate');

// A clock the test drives, so every rule here is exact rather than timed.
function gate(over = {}) {
  let clock = 1000;
  const g = new WatchGate({ quietMs: 100, minIntervalMs: 1000, settleMs: 200, now: () => clock, ...over });
  return { g, tick: (ms) => { clock += ms; }, at: () => clock };
}

const V = 'vault-1';
const W = 'vault-2';

// ---------------------------------------------------------------------------------------------
// 1. The loop. This is the one that is self-powered.
// ---------------------------------------------------------------------------------------------

test('a sync\'s own writes never start another sync', () => {
  const { g, tick } = gate();
  g.runStarted(V);
  // Everything a run writes, while it writes it.
  for (let i = 0; i < 50; i += 1) { assert.equal(g.noticed(V, `file-${i}.txt`), false); tick(1); }
  assert.deepEqual(g.due(), [], 'nothing is due from a run\'s own output');
  g.runEnded(V);
  assert.deepEqual(g.due(), []);
});

test('the writes still landing after a run reports finished do not start another one', () => {
  const { g, tick } = gate();
  g.runStarted(V);
  g.runEnded(V);
  // Filesystem events arrive late; the last writes of a run routinely land after it says it is done.
  tick(50);
  assert.equal(g.noticed(V, 'late.txt'), false, 'inside the settle window this is still ours');
  tick(500);   // past settleMs
  assert.equal(g.noticed(V, 'now-a-person.txt'), true, 'and afterwards a real change is heard again');
});

test('suppression is per vault — one vault syncing does not deafen another', () => {
  const { g, tick } = gate();
  g.runStarted(V);
  assert.equal(g.noticed(V, 'a.txt'), false);
  assert.equal(g.noticed(W, 'b.txt'), true, 'a different vault is unaffected');
  tick(200);
  assert.deepEqual(g.due(), [W]);
});

test('a run starting discards changes already pending for that vault', () => {
  const { g, tick } = gate();
  assert.equal(g.noticed(V, 'a.txt'), true);
  g.runStarted(V);        // that run will carry the change anyway
  tick(500);
  assert.deepEqual(g.due(), [], 'the pending ask is not left to fire after the run that already covered it');
});

// ---------------------------------------------------------------------------------------------
// 2. The burst.
// ---------------------------------------------------------------------------------------------

test('ten thousand events in a burst cost exactly one sync, at the end', () => {
  const { g, tick } = gate();
  for (let i = 0; i < 10000; i += 1) { g.noticed(V, `unzipped/${i}.bin`); tick(1); }
  // Still inside the burst for as long as it keeps arriving.
  assert.deepEqual(g.due(), [], 'nothing fires while the burst is still going');
  tick(100);
  assert.deepEqual(g.due(), [V], 'one sync, once it goes quiet');
  assert.deepEqual(g.due(), [], 'and not a second one for the same burst');
});

test('polling due() every moment does not produce a sync every moment', () => {
  const { g, tick } = gate();
  g.noticed(V, 'a.txt');
  let fired = 0;
  for (let i = 0; i < 500; i += 1) { fired += g.due().length; tick(10); }
  assert.equal(fired, 1, `a single change asks once however often it is polled (got ${fired})`);
});

// ---------------------------------------------------------------------------------------------
// 3. The continuous writer, which never goes quiet and so never trips the debounce alone.
// ---------------------------------------------------------------------------------------------

test('something writing forever cannot ask more often than the ceiling', () => {
  const { g, tick } = gate();  // quiet 100ms, ceiling 1000ms
  let asks = 0;
  // Ten seconds of a file being appended to, pausing just long enough to go quiet each time.
  for (let i = 0; i < 100; i += 1) {
    g.noticed(V, 'export.mov');
    tick(100);
    asks += g.due().length;
  }
  assert.ok(asks <= 11, `ten seconds of continuous writing asked ${asks} times, ceiling allows ~10`);
  assert.ok(asks >= 8, `and it is not silenced altogether (${asks})`);
});

test('a change held back by the ceiling is not lost, it fires when the ceiling lifts', () => {
  const { g, tick } = gate();
  g.noticed(V, 'a.txt'); tick(200);
  assert.deepEqual(g.due(), [V]);
  // A second change immediately after: still inside the minimum interval.
  g.noticed(V, 'b.txt'); tick(200);
  assert.deepEqual(g.due(), [], 'the ceiling holds it');
  assert.equal(g.pendingCount(), 1, 'but it is still pending, not dropped');
  tick(1000);
  assert.deepEqual(g.due(), [V], 'and it fires once the interval has passed');
});

// ---------------------------------------------------------------------------------------------
// Our own files, and housekeeping.
// ---------------------------------------------------------------------------------------------

test('the sync marker and rclone\'s working files are never a person\'s change', () => {
  for (const ours of [
    '.dockvault-sync',
    'sub/.dockvault-sync',
    'big.mp4.partial',
    'deep/folder/big.mp4.partial',
    '.rclone_chunk.001',
    'x.rclone_chunk.12',
    '~$report.docx',
  ]) {
    assert.equal(isOurs(ours), true, ours);
  }
  for (const theirs of ['notes.txt', 'a/b/c.png', 'dockvault-sync.txt', 'partial.txt', 'my.partials', '']) {
    assert.equal(isOurs(theirs), false, theirs);
  }
  const { g, tick } = gate();
  assert.equal(g.noticed(V, '.dockvault-sync'), false, 'and the gate acts on that');
  tick(500);
  assert.deepEqual(g.due(), []);
});

test('a vault that is no longer configured leaves nothing behind', () => {
  const { g, tick } = gate();
  g.noticed(V, 'a.txt');
  g.forget(V);
  tick(500);
  assert.deepEqual(g.due(), []);
  assert.equal(g.pendingCount(), 0);
});

test('two vaults changing at once each ask once', () => {
  const { g, tick } = gate();
  g.noticed(V, 'a.txt');
  g.noticed(W, 'b.txt');
  tick(200);
  assert.deepEqual(g.due().sort(), [V, W]);
});

test('a change with no vault, or an empty path, is ignored rather than throwing', () => {
  const { g } = gate();
  assert.equal(g.noticed(null, 'a.txt'), false);
  assert.equal(g.noticed('', 'a.txt'), false);
  assert.equal(g.noticed(V, ''), true, 'an unnamed change in a watched folder is still a change');
  assert.equal(g.noticed(V, undefined), true);
});

// The defaults ship, so they are worth one assertion of their own: a quiet period long enough to cover an
// editor's save, a ceiling that keeps watching from ever being the reason a credential allowance is spent.
test('the shipped defaults are bounded and sane', () => {
  const { DEFAULTS } = require('../src/main/watch-gate');
  assert.ok(DEFAULTS.quietMs >= 1000, 'long enough that one save is one sync');
  assert.ok(DEFAULTS.minIntervalMs >= 15000, 'watching cannot ask more than a few times a minute');
  assert.ok(DEFAULTS.settleMs > 0, 'a run\'s trailing writes are always suppressed');
  assert.ok(DEFAULTS.quietMs < DEFAULTS.minIntervalMs, 'the ceiling is the outer bound, not the debounce');
});

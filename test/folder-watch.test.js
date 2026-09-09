'use strict';

// THE FILESYSTEM HALF OF NEAR-LIVE SYNC.
//
// Every decision about whether a change matters lives in the gate and is tested there. What is tested here
// is the plumbing, and the property that decides whether this feature is safe to ship at all:
//
//   IT IS AN ACCELERATOR, NEVER A REQUIREMENT.
//
// The five-minute poll already syncs everything. Watching only makes it sooner. So every failure — a
// platform that cannot watch recursively, a folder on a filesystem that refuses, a folder that is deleted,
// a watcher the OS drops — must degrade to "the poll gets it in a few minutes", which is exactly today's
// behaviour. A sync feature that broke because a watcher could not start would be strictly worse than not
// watching at all, and that is the shape of failure this file is mostly about.

const test = require('node:test');
const assert = require('node:assert/strict');

const { createFolderWatch } = require('../src/main/folder-watch');
const { WatchGate } = require('../src/main/watch-gate');

// A fake fs.watch: records what was asked for, hands back a handle a test can fire events through, and can
// be told to refuse particular folders.
function fakeFs({ refuse = () => false } = {}) {
  const opened = [];
  // ATTEMPTS, not just successes. Counting only the opens that worked made the retry test vacuous: a retry
  // of a folder that refuses throws before it is ever recorded, so the count looked identical either way.
  const attempts = [];
  const handles = new Map();     // folder -> { cb, closed, errorCb }
  return {
    opened,
    attempts,
    handles,
    fs: {
      watch(folder, opts, cb) {
        attempts.push(folder);
        if (refuse(folder)) throw new Error('EPERM');
        opened.push({ folder, opts });
        const h = {
          closed: false,
          close() { this.closed = true; },
          on(event, fn) { if (event === 'error') handles.get(folder).errorCb = fn; },
        };
        handles.set(folder, { cb, handle: h, errorCb: null });
        return h;
      },
    },
    fire(folder, filename) { const e = handles.get(folder); if (e) e.cb('change', filename); },
    breakIt(folder) { const e = handles.get(folder); if (e && e.errorCb) e.errorCb(new Error('gone')); },
  };
}

function harness(over = {}) {
  let clock = 1000;
  const asked = [];
  const logged = [];
  let ticker = null;
  const gate = new WatchGate({ quietMs: 100, minIntervalMs: 500, settleMs: 200, now: () => clock });
  const f = fakeFs(over.fsOpts || {});
  const w = createFolderWatch({
    fs: f.fs,
    gate,
    onDue: (v) => asked.push(v),
    onLog: (l) => logged.push(l),
    setIntervalFn: (fn) => { ticker = fn; return { unref() {} }; },
    clearIntervalFn: () => { ticker = null; },
    ...over.watch,
  });
  return {
    w, gate, f, asked, logged,
    tick: (ms) => { clock += ms; },
    pump: () => { if (ticker) ticker(); },
    running: () => ticker != null,
  };
}

const E = (vaultId, localFolder, enabled = true) => ({ vaultId, localFolder, enabled });

test('it watches every enabled synced folder, recursively', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a'), E('v2', '/b')]);
  assert.deepEqual(h.w.watching(), ['v1', 'v2']);
  for (const o of h.f.opened) assert.equal(o.opts.recursive, true, 'a synced folder is a tree');
  // It must not hold the process open on its own.
  for (const o of h.f.opened) assert.equal(o.opts.persistent, false);
});

test('a change becomes a routine sync request once the burst goes quiet', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.f.fire('/a', 'notes.txt');
  h.pump();
  assert.deepEqual(h.asked, [], 'not while the burst could still be going');
  h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v1']);
});

test('a folder that cannot be watched is skipped, not retried, and never throws', () => {
  const h = harness({ fsOpts: { refuse: (f) => f === '/bad' } });
  assert.doesNotThrow(() => h.w.reconcile([E('v1', '/bad'), E('v2', '/good')]));
  assert.deepEqual(h.w.watching(), ['v2'], 'the good one is still watched');
  assert.deepEqual(h.w.unwatched(), ['v1']);
  // Reconciling again must not hammer the same failing folder — the poll already covers it.
  const before = h.f.attempts.length;
  h.w.reconcile([E('v1', '/bad'), E('v2', '/good')]);
  assert.equal(h.f.attempts.length, before, 'the same failing folder is not even RETRIED on every reconcile');
});

test('a watcher the OS drops stops that folder and leaves everything else alone', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a'), E('v2', '/b')]);
  h.f.breakIt('/a');
  assert.deepEqual(h.w.watching(), ['v2'], 'the broken one is dropped');
  assert.deepEqual(h.w.unwatched(), ['v1']);
  // And the other folder keeps working.
  h.w.start();
  h.f.fire('/b', 'x.txt'); h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v2']);
});

test('stopping a sync, or removing a vault, stops watching it and leaves nothing pending', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a'), E('v2', '/b')]);
  h.w.start();
  h.f.fire('/a', 'notes.txt');           // a change is pending for v1
  h.w.reconcile([E('v2', '/b')]);         // v1 is no longer synced here
  assert.deepEqual(h.w.watching(), ['v2']);
  h.tick(500); h.pump();
  assert.deepEqual(h.asked, [], 'a vault that is gone does not get a sync asked for it');
  assert.equal(h.gate.pendingCount(), 0);
});

test('a vault whose sync is switched off is not watched', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a', false), E('v2', '/b')]);
  assert.deepEqual(h.w.watching(), ['v2']);
});

test('a folder that moved is re-pointed, not left watching the old place', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a')]);
  const first = h.f.handles.get('/a').handle;
  h.w.reconcile([E('v1', '/moved')]);
  assert.equal(first.closed, true, 'the old watcher is closed');
  assert.deepEqual(h.w.watching(), ['v1']);
  h.w.start();
  h.f.fire('/moved', 'x.txt'); h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v1'], 'and the new place is live');
});

// ---------------------------------------------------------------------------------------------
// The loop, at this layer: only a real run may open a settle window.
// ---------------------------------------------------------------------------------------------

test('a run\'s own writes do not become a sync request', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.w.noteEvent('v1', 'running');
  for (let i = 0; i < 20; i += 1) h.f.fire('/a', `out-${i}.bin`);
  h.tick(500); h.pump();
  assert.deepEqual(h.asked, [], 'everything a run writes is the run\'s, not a person\'s');
});

// 'skipped' and 'paused' are emitted by routine ticks for vaults that never started. If those counted as a
// run ENDING, every poll would open a settle window and quietly swallow real changes for its duration.
test('a phase that was never a run does not open a settle window', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.w.noteEvent('v1', 'skipped');       // no run ever started
  h.f.fire('/a', 'notes.txt');
  h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v1'], 'a real change right after a skipped tick is still heard');
});

test('a run that ends suppresses its trailing writes, then hears people again', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.w.noteEvent('v1', 'running');
  h.w.noteEvent('v1', 'done');
  h.f.fire('/a', 'late-from-the-run.bin');   // inside the settle window
  h.tick(150); h.pump();
  assert.deepEqual(h.asked, []);
  h.tick(200);                                // past it
  h.f.fire('/a', 'a-person.txt');
  h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v1']);
});

test('an ended run is only ended once, so a second terminal phase is harmless', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.w.noteEvent('v1', 'running');
  h.w.noteEvent('v1', 'done');
  h.tick(500);
  h.w.noteEvent('v1', 'skipped');   // a later routine tick, long after
  h.f.fire('/a', 'notes.txt');
  h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v1'], 'the stale terminal phase did not re-open a settle window');
});

// ---------------------------------------------------------------------------------------------
// Nothing here may take anything down.
// ---------------------------------------------------------------------------------------------

test('an event handler that throws, and a scheduler that throws, are both survivable', () => {
  const h = harness({ watch: { onDue: () => { throw new Error('scheduler said no'); } } });
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.f.fire('/a', 'notes.txt');
  h.tick(200);
  assert.doesNotThrow(() => h.pump(), 'a refusing scheduler is its own business, not a crash');
});

test('stop() closes every watcher and stops asking', () => {
  const h = harness();
  h.w.reconcile([E('v1', '/a'), E('v2', '/b')]);
  h.w.start();
  h.w.stop();
  assert.deepEqual(h.w.watching(), []);
  assert.equal(h.f.handles.get('/a').handle.closed, true);
  assert.equal(h.f.handles.get('/b').handle.closed, true);
  assert.equal(h.running(), false, 'and the tick is cancelled');
});

test('reconcile ignores malformed entries rather than throwing', () => {
  const h = harness();
  assert.doesNotThrow(() => h.w.reconcile([null, {}, { vaultId: 'v' }, { localFolder: '/x' }, E('v1', '/a')]));
  assert.deepEqual(h.w.watching(), ['v1']);
  assert.doesNotThrow(() => h.w.reconcile(null));
  assert.deepEqual(h.w.watching(), [], 'no configuration means nothing watched');
});

// ---------------------------------------------------------------------------------------------
// KEEPING ITSELF CURRENT. There are eight places the sync configuration is written; a hook at each is a
// hook one future edit forgets, and the symptom of forgetting is a folder that is silently unwatched —
// which degrades to the poll and so never announces itself as broken.
// ---------------------------------------------------------------------------------------------

test('a newly synced folder starts being watched without anyone telling the watcher', () => {
  let config = [E('v1', '/a')];
  const h = harness({ watch: { readConfig: () => config, reconcileEveryMs: 3000, tickMs: 1000 } });
  h.w.start();
  h.pump();
  assert.deepEqual(h.w.watching(), ['v1'], 'the first tick picks up what is configured');

  config = [E('v1', '/a'), E('v2', '/b')];
  for (let i = 0; i < 4; i += 1) h.pump();   // past the reconcile interval
  assert.deepEqual(h.w.watching(), ['v1', 'v2'], 'and a folder added later is picked up too');

  // And one that stops being synced is dropped again.
  config = [E('v2', '/b')];
  for (let i = 0; i < 4; i += 1) h.pump();
  assert.deepEqual(h.w.watching(), ['v2']);
});

test('it does not re-read the configuration on every single tick', () => {
  let reads = 0;
  const h = harness({ watch: { readConfig: () => { reads += 1; return [E('v1', '/a')]; }, reconcileEveryMs: 5000, tickMs: 1000 } });
  h.w.start();
  for (let i = 0; i < 10; i += 1) h.pump();
  assert.ok(reads <= 3, `ten ticks, at most a few config reads (got ${reads})`);
  assert.ok(reads >= 1, 'but it did read at least once');
});

test('a configuration that cannot be read leaves the watchers as they are', () => {
  let fail = false;
  const h = harness({ watch: { readConfig: () => { if (fail) throw new Error('unreadable'); return [E('v1', '/a')]; }, reconcileEveryMs: 1000, tickMs: 1000 } });
  h.w.start();
  h.pump();
  assert.deepEqual(h.w.watching(), ['v1']);
  fail = true;
  assert.doesNotThrow(() => { for (let i = 0; i < 3; i += 1) h.pump(); });
  assert.deepEqual(h.w.watching(), ['v1'], 'an unreadable config does not tear down what is working');
});

test('with no readConfig it simply does not self-reconcile, and still works', () => {
  const h = harness();     // no readConfig
  h.w.reconcile([E('v1', '/a')]);
  h.w.start();
  h.f.fire('/a', 'x.txt'); h.tick(200); h.pump();
  assert.deepEqual(h.asked, ['v1']);
});

// ---------------------------------------------------------------------------------------------
// THE WIRING. Source text for the part that runs inside the app and cannot be driven from here — aimed at
// the two properties that would cost something if they regressed.
// ---------------------------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const main = fs.readFileSync(path.join(path.resolve(__dirname, '..'), 'src', 'main', 'index.js'), 'utf8');

test('the watcher asks with the ROUTINE request, never the deliberate-press path', () => {
  const setup = main.slice(main.indexOf('folderWatch = createFolderWatch({'), main.indexOf('folderWatch.start();'));
  assert.ok(setup.length > 0, 'the watcher is created in the app');
  assert.ok(setup.includes('syncScheduler.requestSync(vaultId, { manual: false })'),
    `a machine must not spend a person's "Sync now" allowance: ${setup}`);
  // The press path is what reads and starts that cooldown; watching must never reach it.
  assert.ok(!/requestSync\([^)]*manual: true/.test(setup), 'never the manual path');
  assert.ok(!setup.includes('requestRepair'), 'and never a Repair, which is a confirmed human action');
});

test('run phases reach the watcher, or the first successful sync starts a loop', () => {
  assert.ok(main.includes('folderWatch.noteEvent(vaultId, ev.phase)'),
    'the scheduler\'s phases are what tell the watcher which writes are its own');
  // It must be inside the scheduler's event callback, not somewhere that never runs.
  const onEvent = main.indexOf('onEvent: (vaultId, ev) => {');
  assert.notEqual(onEvent, -1);
  const note = main.indexOf('folderWatch.noteEvent(', onEvent);
  assert.ok(note > onEvent && note - onEvent < 500, 'and it is wired at the top of that callback');
});

test('watching is optional; the poll is not', () => {
  const setup = main.slice(main.indexOf('const gate = new WatchGate();') - 200, main.indexOf('folderWatch.start();') + 200);
  assert.match(setup, /try \{/, 'a watcher that cannot be created must not stop sync starting');
  assert.match(setup, /catch \{ folderWatch = null;/);
});

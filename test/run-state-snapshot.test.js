'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { RunStateSnapshot } = require('../src/main/run-state-snapshot');

test('a successful refresh stores each entry; a missing vault reads as never-run (null)', async () => {
  const snap = new RunStateSnapshot({ fetch: async () => ({ ok: true, states: { a: { lastResult: 'ok', resyncRequired: false }, b: null } }) });
  assert.strictEqual(await snap.refresh(['a', 'b', 'c']), true);
  assert.strictEqual(snap.fresh(), true);
  assert.deepStrictEqual(snap.get('a'), { lastResult: 'ok', resyncRequired: false });
  assert.strictEqual(snap.get('b'), null, 'reported never-run');
  assert.strictEqual(snap.get('c'), null, 'in the refresh list but no row -> genuinely never-run');
});

test("an id the last refresh did NOT cover reads 'unknown', not null (never asked != never run)", async () => {
  // A vault just enabled and kicked before it was ever refreshed: the scheduler must skip it state-uncertain,
  // never treat "never asked about" as never-run and auto-resync a possibly-latched vault.
  const snap = new RunStateSnapshot({ fetch: async () => ({ ok: true, states: { a: { lastResult: 'ok', resyncRequired: false } } }) });
  await snap.refresh(['a']); // 'z' was never in any refresh id list
  assert.strictEqual(snap.fresh(), true);
  assert.strictEqual(snap.get('z'), 'unknown', 'an uncovered id is unknown, not never-run');
  assert.deepStrictEqual(snap.get('a'), { lastResult: 'ok', resyncRequired: false });
});

test("an 'unknown' entry rides through untouched (a fresh answer where a specific vault's state is not knowable)", async () => {
  // The daemon reports 'unknown' (not null) for a vault it cannot read (a throwing store / no-key session);
  // the query itself SUCCEEDED, so the snapshot is fresh, but that vault's entry is 'unknown', which the
  // scheduler then skips as state-uncertain rather than mistaking null for never-run.
  const snap = new RunStateSnapshot({ fetch: async () => ({ ok: true, states: { a: { lastResult: 'ok', resyncRequired: false }, b: 'unknown' } }) });
  await snap.refresh(['a', 'b']);
  assert.strictEqual(snap.fresh(), true);
  assert.deepStrictEqual(snap.get('a'), { lastResult: 'ok', resyncRequired: false });
  assert.strictEqual(snap.get('b'), 'unknown', "reported unknown, not coerced to null/never-run");
});

test('a FAILED refresh marks the snapshot not-fresh (the caller must fail closed, not read absent as never-run)', async () => {
  const snap = new RunStateSnapshot({ fetch: async () => ({ ok: false }) });
  assert.strictEqual(await snap.refresh(['a']), false);
  assert.strictEqual(snap.fresh(), false);
});

test('a throwing fetch is a failed refresh, never fresh', async () => {
  const snap = new RunStateSnapshot({ fetch: async () => { throw new Error('channel gone'); } });
  assert.strictEqual(await snap.refresh(['a']), false);
  assert.strictEqual(snap.fresh(), false);
});

test('a later failure does not silently turn a real blocked entry into never-run: fresh() goes false', async () => {
  let ok = true;
  const snap = new RunStateSnapshot({ fetch: async () => (ok ? { ok: true, states: { a: { lastResult: 'abort-excessive-delete', resyncRequired: true } } } : { ok: false }) });
  await snap.refresh(['a']);
  assert.strictEqual(snap.fresh(), true);
  assert.deepStrictEqual(snap.get('a'), { lastResult: 'abort-excessive-delete', resyncRequired: true });
  ok = false;
  await snap.refresh(['a']);
  assert.strictEqual(snap.fresh(), false, 'the caller now sees "uncertain" and holds off — never dispatches this blocked vault as never-run');
});

test('a successful refresh after a failure restores freshness with the current answer', async () => {
  let ok = false;
  const snap = new RunStateSnapshot({ fetch: async () => (ok ? { ok: true, states: { a: null } } : { ok: false }) });
  await snap.refresh(['a']);
  assert.strictEqual(snap.fresh(), false);
  ok = true;
  await snap.refresh(['a']);
  assert.strictEqual(snap.fresh(), true);
  assert.strictEqual(snap.get('a'), null);
});

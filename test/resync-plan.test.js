'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { planPreservation } = require('../src/daemon/resync-plan');

const AT = new Date(2026, 8, 1, 14, 14); // Sep 1 2026 2.14pm, local parts (tz-independent)

test('both loss modes are preserved: server-only kept by name, a differing file kept-both', () => {
  const plan = planPreservation({
    serverOnly: ['reports/old.txt'],
    differing: ['budget.xlsx'],
    localFiles: ['budget.xlsx'],
  }, { at: AT });
  // server-only -> copied down under its ORIGINAL name so the resync keeps it
  const so = plan.find((p) => p.kind === 'server-only');
  assert.deepStrictEqual([so.from, so.to], ['reports/old.txt', 'reports/old.txt']);
  // differing -> the SERVER's version copied down under a keep-both name (local original untouched)
  const cf = plan.find((p) => p.kind === 'conflict-keep-both');
  assert.strictEqual(cf.from, 'budget.xlsx');
  assert.strictEqual(cf.to, 'budget (conflicting copy from the vault, Sep 1 2026 2.14pm).xlsx');
  assert.notStrictEqual(cf.to, 'budget.xlsx', 'never overwrites the canonical local file');
});

test('every preserve copies FROM the server TO a local path (so the resync propagates it, not destroys it)', () => {
  const plan = planPreservation({ serverOnly: ['a.txt'], differing: ['b.txt'], localFiles: ['b.txt'] }, { at: AT });
  for (const p of plan) {
    assert.ok(typeof p.from === 'string' && typeof p.to === 'string');
    // the keep-both target is a plain local relative path (no remote: prefix)
    assert.ok(!/^[a-z]+:/.test(p.to), 'target is a local path, not a remote');
  }
});

test('a keep-both name that already exists locally bumps the collision counter (inside the marker)', () => {
  const existing = 'budget (conflicting copy from the vault, Sep 1 2026 2.14pm).xlsx';
  const plan = planPreservation({
    differing: ['budget.xlsx'],
    localFiles: ['budget.xlsx', existing], // the first keep-both name is taken
  }, { at: AT });
  const cf = plan[0];
  assert.strictEqual(cf.to, 'budget (conflicting copy from the vault, Sep 1 2026 2.14pm) (2).xlsx');
  assert.ok(cf.to.endsWith('.xlsx'), 'ext stays last through collision handling');
});

test('a differing file keeps its subdirectory (keep-both name is placed alongside the original)', () => {
  const plan = planPreservation({ differing: ['a/b/report.pdf'], localFiles: ['a/b/report.pdf'] }, { at: AT });
  assert.strictEqual(plan[0].to, 'a/b/report (conflicting copy from the vault, Sep 1 2026 2.14pm).pdf');
});

test('nothing to preserve -> empty plan (a clean resync needs no keep-both copies)', () => {
  assert.deepStrictEqual(planPreservation({ serverOnly: [], differing: [], localFiles: ['x'] }, { at: AT }), []);
  assert.deepStrictEqual(planPreservation({}, { at: AT }), []);
});

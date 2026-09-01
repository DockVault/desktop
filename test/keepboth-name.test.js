'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { keepBothName, friendlyDate, splitExt } = require('../src/daemon/keepboth-name');

// Sep 1 2026, 2:14pm, constructed from LOCAL calendar parts so the assertions are timezone-independent
// (friendlyDate reads the same local parts back).
const AT = new Date(2026, 8, 1, 14, 14);

test('the canonical form: base + human marker (source + friendly date) + ext LAST', () => {
  const n = keepBothName('Q3 Budget.xlsx', { source: 'the vault', at: AT });
  assert.strictEqual(n, 'Q3 Budget (conflicting copy from the vault, Sep 1 2026 2.14pm).xlsx');
  assert.ok(n.endsWith('.xlsx'), 'extension is last');
});

test('the extension is ALWAYS last — the marker never comes after .ext', () => {
  const n = keepBothName('report.pdf', { source: 'the vault', at: AT });
  assert.match(n, /\)\.pdf$/, 'the marker close-paren is immediately before the ext');
  assert.ok(!/\.pdf.+/.test(n), 'nothing follows the extension');
});

test('collision counter goes INSIDE the marker, before the ext (never after it)', () => {
  const n = keepBothName('report.pdf', { source: 'the vault', at: AT, counter: 2 });
  assert.ok(n.endsWith(') (2).pdf'), `counter before ext: ${n}`);
  assert.ok(!n.endsWith('.pdf (2)'), 'never after the ext');
  // counter 1 omits the suffix
  assert.ok(!keepBothName('report.pdf', { source: 'the vault', at: AT, counter: 1 }).includes(' (1)'));
});

test('filesystem-safe on all three OSes: no reserved chars, period (not colon) as the time separator', () => {
  const n = keepBothName('Q3 Budget.xlsx', { source: 'the vault', at: AT });
  assert.ok(!/[:/\\*?"<>|]/.test(n), 'no reserved characters');
  assert.ok(/2\.14pm/.test(n) && !/2:14pm/.test(n), 'time uses a period, not a colon');
});

test('source names the actual origin and is sanitized if it carries a reserved char', () => {
  assert.match(keepBothName('a.txt', { source: 'this computer', at: AT }), /from this computer,/);
  const n = keepBothName('a.txt', { source: 'a/b:c', at: AT }); // reserved chars -> spaces
  assert.ok(!/[:/\\*?"<>|]/.test(n));
});

test('dotfiles and multi-dot names keep the right extension boundary', () => {
  assert.deepStrictEqual(splitExt('.env'), ['.env', ''], 'leading dot is base, no ext');
  assert.ok(keepBothName('.env', { source: 'the vault', at: AT }).startsWith('.env (conflicting copy'));
  const n = keepBothName('archive.tar.gz', { source: 'the vault', at: AT });
  assert.ok(n.endsWith('.gz') && n.startsWith('archive.tar (conflicting copy'), n);
});

test('over-long names truncate only the BASE, keeping the marker + ext whole and within the limit', () => {
  const n = keepBothName('A'.repeat(300) + '.txt', { source: 'the vault', at: AT, maxLen: 90 });
  assert.ok(n.length <= 90, `within the limit: ${n.length}`);
  assert.ok(n.endsWith('.txt'), 'ext preserved');
  assert.ok(n.includes('(conflicting copy from the vault, Sep 1 2026 2.14pm)'), 'marker preserved whole');
});

test('friendlyDate: 12-hour clock with am/pm, padded minutes, midnight and noon edges', () => {
  assert.strictEqual(friendlyDate(new Date(2026, 0, 5, 0, 3)), 'Jan 5 2026 12.03am', 'midnight -> 12.xxam');
  assert.strictEqual(friendlyDate(new Date(2026, 11, 31, 12, 0)), 'Dec 31 2026 12.00pm', 'noon -> 12.00pm');
  assert.strictEqual(friendlyDate(new Date(2026, 8, 1, 9, 5)), 'Sep 1 2026 9.05am');
});

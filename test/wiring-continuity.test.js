'use strict';

/*
 * THE WIRE, NOT THE ENDS OF IT.
 *
 * Two features shipped dead in one night, and both had tests. Each end of the connection was asserted and
 * the connection itself never was:
 *
 *   - A troubleshoot check offered a "find the folder" button. The renderer called
 *     `api.relocateFolder(...)`; the main process registered `dockvault:troubleshoot.relocate` and gated it
 *     correctly. The PRELOAD never exposed it, so pressing the button threw. One test asserted the renderer
 *     end by source text, another asserted the main end by source text, and forty tests passed.
 *
 *   - The re-link consent read a folder's marker and asked before taking another vault's over. The flow
 *     skips the whole step when `io.readMarker` is absent — and the wizard, which is its only caller, builds
 *     that io as an explicit whitelist that never included it. So the step silently did not exist. The flow
 *     was tested with a rich io written by hand; nothing asserted what the real caller passes.
 *
 * These are the same mistake, and neither is caught by testing harder at either end. So this file asserts
 * CONTINUITY, structurally and for every case rather than for the two that bit:
 *
 *   1. Every channel a renderer calls through the preload is registered in main, and every channel main
 *      registers for a first-party page is reachable through the preload.
 *   2. Every member the enable flow reads off its io is supplied by the one caller that builds it.
 *
 * Both are derived from the source rather than listed here, so a NEW channel or a NEW io member is covered
 * the day it is written, by someone who has never read this file.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const read = (...p) => fs.readFileSync(path.join(root, ...p), 'utf8');

const preload = read('src', 'preload', 'index.js');
const main = read('src', 'main', 'index.js');

const RENDERERS = ['manage.js', 'sync-wizard.js', 'troubleshoot.js', 'status.js', 'server-setup.js'];

// ---------------------------------------------------------------------------------------------
// 1. The IPC wire
// ---------------------------------------------------------------------------------------------

const invoked = () => [...preload.matchAll(/ipcRenderer\.invoke\(\s*'(dockvault:[a-z.-]+)'/g)].map((m) => m[1]);
const handled = () => [...main.matchAll(/ipcMain\.handle\(\s*'(dockvault:[a-z.-]+)'/g)].map((m) => m[1]);

test('every channel the preload calls is registered in the main process', () => {
  const missing = [...new Set(invoked())].filter((c) => !handled().includes(c));
  assert.deepEqual(missing, [], `the preload calls channels nobody handles: ${missing.join(', ')}`);
});

test('every channel main registers is reachable through the preload', () => {
  // The reverse direction is the one that shipped broken: a handler with no bridge is a feature that looks
  // complete from the main process and throws in the page.
  const orphans = [...new Set(handled())].filter((c) => !invoked().includes(c));
  assert.deepEqual(orphans, [], `main handles channels no page can reach: ${orphans.join(', ')}`);
});

// The end that actually threw. A page calling something the preload does not expose is a TypeError at the
// moment a person presses the button, which is the worst time to find out.
test('every preload member a first-party page calls actually exists on the preload', () => {
  const surfaces = [...preload.matchAll(/^\s{2}([a-zA-Z]+): Object\.freeze\(\{/gm)].map((m) => m[1]);
  assert.ok(surfaces.length >= 5, `the preload's surfaces were found: ${surfaces.join(', ')}`);

  const membersOf = (surface) => {
    const start = preload.indexOf(`  ${surface}: Object.freeze({`);
    const end = preload.indexOf('\n  }),', start);
    const block = preload.slice(start, end);
    return new Set([...block.matchAll(/^\s{4}([a-zA-Z][a-zA-Z0-9]*):/gm)].map((m) => m[1]));
  };

  const problems = [];
  for (const file of RENDERERS) {
    let src;
    try { src = read('src', 'renderer', file); } catch { continue; }
    // WHICH surface each local name is bound to. A page binds one — `const api = window.dockvault.manage`
    // — and may bind others under different names. Checking a page's api.* calls against every surface it
    // merely mentions reports failures that are not real, which is what the first version of this did. A
    // test that fails for the wrong reason costs about as much as one that passes for the wrong reason.
    for (const b of src.matchAll(/const\s+(\w+)\s*=\s*\(?window\.dockvault\s*&&\s*window\.dockvault\.(\w+)\)?/g)) {
      const local = b[1];
      const surface = b[2];
      if (!surfaces.includes(surface)) continue;
      const have = membersOf(surface);
      for (const m of src.matchAll(new RegExp(`\\b${local}\\.([a-zA-Z][a-zA-Z0-9]*)\\s*\\(`, 'g'))) {
        if (!have.has(m[1])) problems.push(`${file}: ${local}.${m[1]}() — the ${surface} surface has: ${[...have].join(', ')}`);
      }
    }
  }
  assert.deepEqual(problems, [], problems.join('\n'));
});

// ---------------------------------------------------------------------------------------------
// 2. The enable flow's io
// ---------------------------------------------------------------------------------------------

test('the wizard supplies every io member the enable flow reads', () => {
  const flow = read('src', 'main', 'sync-enable.js');
  const wizard = read('src', 'main', 'sync-wizard.js');

  // What the flow reads off its io, taken from the flow itself so a new one is covered the day it is added.
  const wanted = new Set([...flow.matchAll(/\bio\.([a-zA-Z][a-zA-Z0-9]*)/g)].map((m) => m[1]));
  assert.ok(wanted.size > 10, `the flow's io members were found: ${[...wanted].join(', ')}`);

  // What the one caller actually builds. `enableIo()` is a whitelist, which is the right shape — this is
  // what makes forgetting an entry visible instead of silent.
  const start = wizard.indexOf('function enableIo(');
  assert.notEqual(start, -1, 'the wizard builds the flow io');
  const built = wizard.slice(start, wizard.indexOf('\n  }\n', start));
  const missing = [...wanted].filter((m) => !new RegExp(`\\b${m}:`).test(built));

  assert.deepEqual(missing, [], `the flow reads these and the wizard never supplies them: ${missing.join(', ')}`);
});

// A step the flow makes OPTIONAL is the dangerous kind: leaving it out does not fail, it turns the step off.
// So the members behind the re-link consent are named explicitly as well — belt and braces, because this is
// the exact pair that shipped dead.
test('the re-use consent is wired, not merely written', () => {
  const wizard = read('src', 'main', 'sync-wizard.js');
  for (const member of ['readMarker', 'confirmReuse', 'knownFolderFor', 'vaultNameFor']) {
    assert.match(wizard, new RegExp(`\\b${member}:`), `the wizard must supply ${member}, or the whole step is skipped`);
  }
  // And the page can render the question it asks.
  const page = read('src', 'renderer', 'sync-wizard.js');
  assert.match(page, /'confirm-reuse':/, 'a question nothing renders is a flow that hangs');
});

// The same trap, stated generally: any question the wizard asks must have a view, or the flow stops dead
// waiting for an answer nobody can give.
test('every question the wizard asks has something that draws it', () => {
  const wizard = read('src', 'main', 'sync-wizard.js');
  const page = read('src', 'renderer', 'sync-wizard.js');
  const asked = new Set([...wizard.matchAll(/\bask\(\s*'([a-z-]+)'/g)].map((m) => m[1]));
  assert.ok(asked.size >= 4, `the wizard's questions were found: ${[...asked].join(', ')}`);
  // View keys are written both quoted ('confirm-cloud', because of the hyphen) and bare (consent), so both
  // spellings count. Requiring quotes made this report two views that are perfectly well drawn.
  const undrawn = [...asked].filter((q) => !new RegExp(`(?:['"]${q}['"]|(?<![\\w-])${q})\\s*:\\s*\\(`).test(page));
  assert.deepEqual(undrawn, [], `asked but never drawn: ${undrawn.join(', ')}`);
});

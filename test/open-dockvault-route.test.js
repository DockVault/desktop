'use strict';

// WHERE A PERSON IS SENT WHEN A SYNC NEEDS THEM.
//
// The app told them "Open DockVault". To the person using it, DockVault IS the files app — so that sentence
// means the file browser, and the tray's own `Open DockVault` item took them there. Nothing in that window can
// repair a sync, name the folder that went missing, or stop syncing a vault. So "can't sync until its folder is
// fixed — Open DockVault to sort it out" delivered someone to a screen with no trace of the problem it had just
// described, and left them to discover the tray on their own.
//
// It was not only the words. Every must-act item without an action of its own FELL THROUGH to that same window,
// so the door matched the misleading sentence. Both halves are checked here, and the second one is why the
// routing decision was moved out of the shell into a function that can be asked: a fallthrough is not a
// statement, and no test over source text would have seen it.
//
// The rule: a sentence about a SYNC problem points at Computers & synced folders, and the item opens it. The
// exceptions are named individually below, each because the thing being asked for genuinely lives elsewhere.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const tray = require('../src/main/tray-presentation');
const { bodyForConditionReason } = require('../src/main/manual-sync-copy');
const { STATE } = require('../src/main/sync-status-model');

const root = path.resolve(__dirname, '..');
const NAME = 'Photos';

// Every reason the app can produce a must-act line for. Taken from the copy table itself rather than typed out
// here, so a reason added later is covered by these tests without anyone remembering to add it.
function everyReason() {
  const src = fs.readFileSync(path.join(root, 'src', 'main', 'tray-presentation.js'), 'utf8');
  const found = new Set();
  for (const m of src.matchAll(/case '([a-z0-9-]+)':/g)) found.add(m[1]);
  assert.ok(found.size > 25, `the reason table was found and is not empty (got ${found.size})`);
  return [...found];
}

// "DockVault" appears in plenty of honest sentences ("DockVault couldn't tell why"). What must not appear is an
// INSTRUCTION to open it, which is the phrase that names the wrong window.
const TELLS_YOU_TO_OPEN_THE_APP = /\bopen(ing)?\s+DockVault\b|\breopen(ing)?\s+DockVault\b/i;

// ---------------------------------------------------------------------------------------------
// The words
// ---------------------------------------------------------------------------------------------

test('no tray line tells a person to open the app they are already being shown a menu of', () => {
  for (const reason of everyReason()) {
    const item = tray.itemForVault({ vault: 'v1', state: STATE.ATTENTION, reason }, () => NAME, { now: Date.now() });
    if (!item || !item.label) continue;
    assert.ok(!TELLS_YOU_TO_OPEN_THE_APP.test(item.label),
      `${reason}: a tray item must not tell someone to open the app — they are in its menu. Got: ${item.label}`);
  }
});

test('a sync problem points at Computers & synced folders, by that exact name', () => {
  // The only lines that may still name the file browser, each with a reason that is about WHERE the thing
  // being asked for lives — not about which window is more familiar.
  const livesInTheFileBrowser = new Set([
    'conflict-keep-both',   // conflicting copies ARE files; the Computers view has no conflict surface at all
  ]);

  let routed = 0;
  for (const reason of everyReason()) {
    const line = bodyForConditionReason(reason, NAME);
    if (typeof line !== 'string' || line === '') continue;
    if (livesInTheFileBrowser.has(reason)) continue;
    if (!TELLS_YOU_TO_OPEN_THE_APP.test(line)) { routed += 1; continue; }
    assert.fail(`${reason}: sends a person to the file browser for a sync problem. Got: ${line}`);
  }
  assert.ok(routed > 20, `most reasons were actually exercised, not skipped into a vacuous pass (got ${routed})`);
});

// The whole shipped surface, not just the two tables above — because the phrase also lived in the setup-item
// list, in the Computers page, and in the sync wizard, where none of the per-reason tests reach. Several of
// those sentences meant "quit and start it again" after unlocking a keychain, which is a THIRD thing, and
// "reopening DockVault" reads as neither of the two windows it might mean.
test('no shipped sentence tells a person to open or reopen the app', () => {
  const files = [
    'src/main/index.js', 'src/main/tray-presentation.js', 'src/main/manual-sync-copy.js',
    'src/main/sync-status-hub.js', 'src/renderer/manage.js', 'src/renderer/sync-wizard.js',
    'src/renderer/server-setup.js',
  ];
  let scanned = 0;
  for (const rel of files) {
    const src = fs.readFileSync(path.join(root, rel), 'utf8');
    // Split on \r?\n, not '\n'. These files are CRLF, so splitting on '\n' leaves a \r at the end of every
    // line — and `$` in the comment stripper below then never matches, so nothing gets stripped and the
    // exclusions read as if they were working.
    src.split(/\r?\n/).forEach((line, i) => {
      // Comments are stripped, not skipped by prefix: these modules discuss the old phrase deliberately, and
      // some of that discussion sits at the end of a line of real code.
      const t = line
        .replace(/\/\*[\s\S]*?\*\//g, '')          // inline /* ... */
        .replace(/(^|[\s;{}])\/\/.*$/, '$1')       // trailing // ... (but not the // in a URL)
        .trim();
      if (t === '' || line.trim().startsWith('*')) return;
      scanned += 1;
      if (rel === 'src/main/manual-sync-copy.js' && /conflicting copies/.test(line)) return; // the documented exception
      // The tray's own "Open DockVault" ENTRY is not an instruction, it is the affordance — the one thing in
      // the menu whose job is to open the file browser, and the name people look for. What this test is about
      // is sentences that SEND someone there for something that is not done there.
      if (/template\.push\(\{ label: 'Open DockVault'/.test(t)) return;
      // "Open DockVault on <that computer> itself" is about a different MACHINE, not a different window —
      // the one case where naming the app without naming a window is exactly right, because the point is
      // that this computer cannot answer for that one.
      if (/on \$\{cmp\.label\} itself/.test(t)) return;
      // A BUTTON labelled "Open DockVault", like the tray entry, is the affordance rather than an instruction
      // — and the copy beside it no longer tells anyone to go and find a window, because the button is right
      // there. What must not survive is a sentence sending someone off to look for one.
      if (/button\('Open DockVault'/.test(t)) return;
      assert.ok(!TELLS_YOU_TO_OPEN_THE_APP.test(t),
        `${rel}:${i + 1} still sends a person to an unnamed window: ${t}`);
    });
  }
  assert.ok(scanned > 500, `the files were really read (scanned ${scanned} lines)`);
});

// A sentence that names a menu entry which does not exist is worse than a vague one: it sends someone looking
// for something that is not there. So the words in the copy are checked against the menu the app really builds.
test('the menu entries the copy names are the menu entries the app builds', () => {
  const main = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
  const labels = [...main.matchAll(/template\.push\(\{\s*label: '([^']+)'/g)].map((m) => m[1]);
  assert.ok(labels.length > 3, 'the tray menu labels were found');

  // Computers & synced folders — the destination for a sync problem.
  assert.ok(labels.some((l) => l.startsWith(tray.MANAGE_ITEM)),
    `the copy points at "${tray.MANAGE_ITEM}" and the menu must contain it; menu has: ${labels.join(' | ')}`);

  // Troubleshoot and Restart sync are named by copy too, so they get the same treatment.
  const named = ['Troubleshoot', 'Restart sync'];
  const everyLabel = labels.concat(['Restart sync']);   // Restart sync is a must-act item, not a fixed entry
  for (const n of named) {
    assert.ok(everyLabel.some((l) => l.startsWith(n)), `copy names "${n}" so the app must offer it`);
  }
});

// ---------------------------------------------------------------------------------------------
// The door. This is the half that source text could not see.
// ---------------------------------------------------------------------------------------------

test('a sync problem OPENS Computers & synced folders, it does not merely say so', () => {
  // Every kind the shell does not handle with an action of its own falls through to a window, and this is
  // which one. Before, all of them fell through to the file browser.
  for (const kind of ['open', 'repair', 'relocate-folder', 'troubleshoot', 'set-up-again']) {
    assert.equal(tray.destinationFor(kind), 'manage', `${kind} is a sync problem and belongs on the vault's card`);
  }
  // The genuine exceptions, each because what is being asked for is not on a vault card.
  for (const kind of ['review', 'sign-in', 'unlock', 'check-identity', 'reopen']) {
    assert.equal(tray.destinationFor(kind), 'window', `${kind} is done in the vault's own interface`);
  }
  // An unknown kind must not silently become the file browser again — the default is the safer door.
  assert.equal(tray.destinationFor(undefined), 'manage');
  assert.equal(tray.destinationFor('something-added-later'), 'manage');
});

test('the shell asks that function rather than deciding for itself', () => {
  const main = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
  const start = main.indexOf('function handleMustAct(');
  assert.notEqual(start, -1, 'the must-act dispatcher exists');
  const body = main.slice(start, main.indexOf('\n}', start));
  assert.match(body, /destinationFor\(/, 'the dispatcher routes through the shared decision');
  // And the fallback door is still reachable for the kinds that need it, so this did not simply
  // redirect everything.
  assert.match(body, /showOrCreateWindow\(\)/);
  assert.match(body, /openManageView\(\)/);
});

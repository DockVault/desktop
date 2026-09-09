'use strict';

// Sign in, open the tray's "Computers & synced folders" straight away, and be told to sign in.
//
// The owner hit this and watched it correct itself about half a minute later, which is the tell:
// whether anyone is signed in was answered from a snapshot that a THIRTY-SECOND poll keeps up to
// date. That is a reasonable way to answer a background question and the wrong way to answer a
// window someone just opened — the one moment the answer is certainly wrong is immediately after
// signing in, because they just did it.
//
// Two things were wrong and both are fixed here:
//   1. the poll's sign-IN branch wrote the session to disk but never updated the in-memory snapshot,
//      while its sign-OUT branch cleared that snapshot. Asymmetric, so every reader that consults the
//      snapshot first stayed stale until a disk round-trip;
//   2. nothing asked the page for the session at the moment a window that gates on it opened.
//
// These are source assertions, because the seam is inside an Electron main process that cannot be
// booted under `node --test`. They are written to fail if either half is removed — see the comments
// on each, and the mutation notes in the phase's DONE post.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');

// The body of a top-level `async function name() { ... }`, by brace depth, so "does this function do
// X" is asked of the function and not of the file.
function bodyOf(name) {
  const start = main.indexOf(`async function ${name}() {`);
  assert.notEqual(start, -1, `${name} exists`);
  let depth = 0;
  for (let i = main.indexOf('{', start); i < main.length; i += 1) {
    if (main[i] === '{') depth += 1;
    else if (main[i] === '}') { depth -= 1; if (depth === 0) return main.slice(start, i + 1); }
  }
  throw new Error(`${name} is not closed`);
}

test('signing in updates the snapshot, not only the file on disk', () => {
  const capture = bodyOf('captureSession');
  // The sign-in branch sets it...
  assert.match(capture, /if \(signedIn\) \{[\s\S]*?sessionBundle = bundle;[\s\S]*?\} else \{/,
    'the sign-in branch assigns the in-memory snapshot');
  // ...and the sign-out branch still clears it. The pair is the property; one without the other is
  // how this went wrong in the first place.
  assert.match(capture, /\} else \{[\s\S]*?sessionBundle = null;/, 'the sign-out branch still clears it');
  // Exactly one of each, so a later edit cannot leave two writers disagreeing.
  assert.equal((capture.match(/sessionBundle = bundle;/g) || []).length, 1);
  assert.equal((capture.match(/sessionBundle = null;/g) || []).length, 1);
  // And the assignment is on the SIGNED-IN side: if it moved below the else it would fire on sign-out.
  assert.ok(capture.indexOf('sessionBundle = bundle;') < capture.indexOf('sessionBundle = null;'));
});

test('a window that gates on the session asks for it before it opens, not up to 30s later', () => {
  // Both tray-opened windows decide "are you signed in?" as their first act, so both refresh first.
  // The wizard has the same failure as the Computers window — set up sync right after signing in and
  // it would have said the same thing — so fixing only the reported one would have been half a fix.
  for (const fn of ['openSyncWizard', 'openManageView']) {
    const body = bodyOf(fn);
    assert.match(body, /await refreshSessionBeforeOpening\(\);/, `${fn} refreshes first`);
    // BEFORE it looks at any existing window or builds anything - otherwise it would refresh after
    // the decision it exists to inform.
    const refresh = body.indexOf('await refreshSessionBeforeOpening();');
    const firstUse = body.indexOf('const existing =');
    assert.ok(refresh > 0 && refresh < firstUse, `${fn} refreshes before it does anything else`);
  }
  // The refresh is the same read the poll makes, and it cannot take a window down with it: a failure
  // to reach the page must leave the window opening on a stale answer rather than not opening.
  const helper = bodyOf('refreshSessionBeforeOpening');
  assert.match(helper, /await captureSession\(\)/);
  assert.match(helper, /catch/, 'best-effort: a window must still open if the page cannot be asked');
});

test('the poll is still there, because this replaces nothing', () => {
  // The on-demand read is an addition. The background poll still has to run, or a session that
  // changes while no window is being opened would never be noticed at all.
  assert.match(main, /setInterval\(\(\) => \{ void captureSession\(\); \}, 30000\)/);
});

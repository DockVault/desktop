'use strict';

// A build has to be able to say which build it is — and never to say it wrongly. These cover the
// three halves of that: what a stamp is read as, what a person is shown, and that the pipeline
// which produces the stamp and the code which reads it agree on the same two field names.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { readStamp, stampLine, stampNote, stampMetadata, aboutDialog, SHORT } = require('../src/main/build-stamp');

const root = path.resolve(__dirname, '..');
const FULL = '3d6bcc8f0e1d2c3b4a5968778695a4b3c2d1e0f9';

test('a stamped build names its commit, shortened, and its date', () => {
  const s = readStamp({ version: '0.1.0', buildCommit: FULL, buildDate: '2026-09-09' });
  assert.deepEqual(s, { version: '0.1.0', commit: FULL.slice(0, SHORT), date: '2026-09-09', stamped: true });
  assert.equal(stampLine(s), 'DockVault 0.1.0 · build 3d6bcc8 · 2026-09-09');
  // The short form is what `git show` takes, so the line can be used as it is read.
  assert.equal(s.commit.length, 7);
});

test('a commit written by a tool that upper-cases hex is still the same commit', () => {
  assert.equal(readStamp({ buildCommit: FULL.toUpperCase() }).commit, FULL.slice(0, SHORT));
  // And surrounding whitespace (a value that arrived through a file or a shell) does not hide it.
  assert.equal(readStamp({ buildCommit: `  ${FULL}\n` }).commit, FULL.slice(0, SHORT));
});

test('an unstamped build says so rather than showing a blank or a half line', () => {
  for (const meta of [undefined, null, {}, 'nonsense', { version: '0.1.0' }, { version: '0.1.0', buildDate: '2026-09-09' }]) {
    const s = readStamp(meta);
    assert.equal(s.stamped, false, JSON.stringify(meta));
    assert.equal(s.commit, null);
    const line = stampLine(s);
    assert.ok(line.startsWith('DockVault'), line);
    assert.ok(line.includes('not stamped'), line);
  }
  assert.equal(stampLine(readStamp({ version: '0.1.0' })), 'DockVault 0.1.0 · build not stamped');
});

// The stamp travels from a build environment into a string this app SHOWS a person. So what arrives
// is input, not a label: anything that is not the shape of a commit or of a real date is absent, and
// nothing a build environment supplies can put a sentence of its own on screen.
test('nothing that is not a commit is ever shown as one', () => {
  const notCommits = [
    '', '   ', 'abc123', 'g'.repeat(40), `${FULL}f`, `${FULL} ${FULL}`,
    'HEAD', 'main', '../../etc/passwd', '3d6bcc8; rm -rf /', '<b>3d6bcc8</b>',
    'Contact support at http://example.invalid', '3d6bcc8\nSomething else entirely',
    123, true, {}, [], () => {},
  ];
  for (const buildCommit of notCommits) {
    const s = readStamp({ version: '0.1.0', buildCommit });
    assert.equal(s.commit, null, JSON.stringify(String(buildCommit)));
    assert.equal(s.stamped, false);
    assert.equal(stampLine(s), 'DockVault 0.1.0 · build not stamped');
  }
});

test('a date that is not a real calendar day in ISO order is not shown', () => {
  for (const buildDate of ['', '2026-13-01', '2026-02-31', '2026-00-10', '2026-09-00', '09/09/2026', '9 Sep 2026', '2026-9-9', '2026-09-09T12:00:00Z', 'today', 20260909]) {
    const s = readStamp({ version: '0.1.0', buildCommit: FULL, buildDate });
    assert.equal(s.date, null, JSON.stringify(String(buildDate)));
    // The commit still identifies the build — a bad date costs the convenience, not the identity.
    assert.equal(s.stamped, true);
    assert.equal(stampLine(s), 'DockVault 0.1.0 · build 3d6bcc8');
  }
  // A leap day in a leap year is a real day.
  assert.equal(readStamp({ buildCommit: FULL, buildDate: '2028-02-29' }).date, '2028-02-29');
  assert.equal(readStamp({ buildCommit: FULL, buildDate: '2026-02-29' }).date, null);
});

// A version is shown to a person beside the commit, so it has to LOOK LIKE A VERSION, not merely be
// built from a version's characters — `1-800-555-0199` is every character a version may contain.
test('a version that is not the shape of a version is left out rather than printed', () => {
  for (const version of ['', ' ', '.1.0', 'v'.repeat(40), '0.1.0 (please call this number)', 0.1, null,
    '1-800-555-0199', '0.1.0-call-1-800-555-0100-now-now-now-now', 'call-1-800-555-0199', '1', '1.', '.', '1.2.3.4', '-1.0']) {
    assert.equal(readStamp({ version, buildCommit: FULL }).version, null, JSON.stringify(String(version)));
  }
  assert.equal(stampLine(readStamp({ buildCommit: FULL, buildDate: '2026-09-09' })), 'DockVault · build 3d6bcc8 · 2026-09-09');
  for (const version of ['0.1.0', '1.2.3-beta.4', '2.0.0+build.5']) {
    assert.equal(readStamp({ version }).version, version);
  }
});

test('the About box answers with the build, the platform, and something to paste', () => {
  const s = readStamp({ version: '0.1.0', buildCommit: FULL, buildDate: '2026-09-09' });
  const a = aboutDialog(s, { platform: 'win32', arch: 'x64', electron: '44.1.0' });
  assert.equal(a.detail.split('\n')[0], stampLine(s));
  assert.ok(a.detail.includes('Platform: win32 x64'));
  assert.ok(a.detail.includes('Electron: 44.1.0'));
  // Everything on screen is what the copy button puts on the clipboard — no more, and nothing less.
  assert.equal(a.copyText, a.detail);
  assert.equal(a.buttons[a.copyIndex], 'Copy details');
  assert.equal(a.buttons[a.closeIndex], 'Close');
  // Dismissing the box must not replace what was on the person's clipboard, so Close is the default
  // and copying takes a deliberate click.
  assert.equal(a.defaultIndex, a.closeIndex);
  // A stamped build is told nothing extra; there is nothing to explain.
  assert.equal(stampNote(readStamp({ version: '0.1.0', buildCommit: FULL })), null);
  assert.equal(a.detail.split('\n').length, 3);
});

// The app can see that a field is missing. It CANNOT see where a copy came from — so it says the
// first and never the second. A build made by the pipeline but somehow unstamped would otherwise be
// telling its owner, in the sentence they paste into a report, something the app cannot know.
test('an unstamped build says what it does not know, not where it came from', () => {
  const note = stampNote(readStamp({ version: '0.1.0' }));
  const a = aboutDialog(readStamp({ version: '0.1.0' }), { platform: 'linux', arch: 'x64', electron: '44.1.0' });
  assert.ok(a.detail.includes('not stamped'));
  assert.ok(a.detail.includes(note), 'the box says the same sentence the footer explains itself with');
  // It states the absence...
  assert.match(note, /does not record which commit it was built from/);
  // ...and never a verdict on this copy's origin.
  assert.ok(!/this (build|copy) was not produced/i.test(note), note);
  assert.ok(!/\bnot (produced|built) by\b/i.test(note), note);
});

// The line and the sentence beside it read the same stamp the same way. A surface saying "not
// stamped" while another explains nothing (or the reverse) would be two parts of one screen
// disagreeing about the same fact.
test('the line and its explanation never disagree about whether a build is stamped', () => {
  const metas = [{}, { version: '0.1.0' }, { buildCommit: FULL }, { version: '0.1.0', buildCommit: FULL, buildDate: '2026-09-09' }, { version: '0.1.0', buildDate: '2026-09-09' }, { buildCommit: 'nope' }];
  for (const meta of metas) {
    const s = readStamp(meta);
    const saysUnstamped = stampLine(s).includes('not stamped');
    assert.equal(saysUnstamped, stampNote(s) !== null, JSON.stringify(meta));
    assert.equal(saysUnstamped, !s.stamped, JSON.stringify(meta));
  }
  // Hand-built stamps too: the composers agree on any object, not only on readStamp's output.
  assert.ok(stampLine({ commit: 'abcdefg' }).includes('build abcdefg'));
  assert.equal(stampNote({ commit: 'abcdefg' }), null);
  assert.ok(stampLine({ stamped: true }).includes('not stamped'), 'a stamp with no commit names no build');
  assert.notEqual(stampNote({ stamped: true }), null);
});

test('the About box holds up when it is told nothing about the machine', () => {
  for (const env of [undefined, null, {}, 'x', { platform: 'darwin' }]) {
    const a = aboutDialog(readStamp({ buildCommit: FULL }), env);
    assert.ok(a.detail.startsWith('DockVault · build 3d6bcc8'), a.detail);
    assert.equal(typeof a.copyText, 'string');
    assert.ok(a.copyText.length > 0);
  }
});

// The stamp only works if the side that WRITES it and the side that READS it name the same fields.
// These two assert that agreement across the three files it spans, so renaming one of them breaks a
// test rather than quietly shipping installers that all say "not stamped" again.
test('the build configuration bakes the stamp in, from the environment, with the shapes checked', () => {
  const builderPath = path.join(root, 'electron-builder.js');
  const load = (env) => {
    for (const k of ['DOCKVAULT_BUILD_COMMIT', 'DOCKVAULT_BUILD_DATE']) delete process.env[k];
    Object.assign(process.env, env);
    delete require.cache[require.resolve(builderPath)];
    return require(builderPath).extraMetadata;
  };
  const saved = { DOCKVAULT_BUILD_COMMIT: process.env.DOCKVAULT_BUILD_COMMIT, DOCKVAULT_BUILD_DATE: process.env.DOCKVAULT_BUILD_DATE };
  try {
    // What the pipeline passes ends up in the metadata under the names the app reads back.
    const stamped = load({ DOCKVAULT_BUILD_COMMIT: FULL.toUpperCase(), DOCKVAULT_BUILD_DATE: '2026-09-09' });
    assert.deepEqual(stamped, { buildCommit: FULL, buildDate: '2026-09-09' });
    assert.equal(readStamp({ version: '0.1.0', ...stamped }).stamped, true);
    // A build given nothing ships no stamp fields at all — it does not invent one, and it does not
    // write an empty one that would have to be defended against at read time.
    assert.deepEqual(load({}), {});
    // A malformed value is dropped at the build, not carried into a shipped artifact's metadata.
    assert.deepEqual(load({ DOCKVAULT_BUILD_COMMIT: 'HEAD', DOCKVAULT_BUILD_DATE: 'yesterday' }), {});
    assert.deepEqual(load({ DOCKVAULT_BUILD_COMMIT: FULL, DOCKVAULT_BUILD_DATE: '' }), { buildCommit: FULL });
    // Including a date that passes the pattern and fails the calendar. The writer and the reader use
    // ONE validator, so an artifact can never carry a date the app would then refuse to show.
    assert.deepEqual(load({ DOCKVAULT_BUILD_COMMIT: FULL, DOCKVAULT_BUILD_DATE: '2026-02-31' }), { buildCommit: FULL });
    assert.equal(readStamp({ buildDate: '2026-02-31' }).date, null);
    // The build writes the WHOLE commit; only the display is shortened, so a longer one can still be
    // checked against it later.
    assert.equal(load({ DOCKVAULT_BUILD_COMMIT: FULL }).buildCommit.length, 40);
  } finally {
    for (const [k, v] of Object.entries(saved)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
    delete require.cache[require.resolve(builderPath)];
  }
});

test('the workflow that builds the installers supplies the stamp the build configuration reads', () => {
  const yml = fs.readFileSync(path.join(root, '.github', 'workflows', 'build-installers.yml'), 'utf8');
  const builder = fs.readFileSync(path.join(root, 'electron-builder.js'), 'utf8');
  for (const name of ['DOCKVAULT_BUILD_COMMIT', 'DOCKVAULT_BUILD_DATE']) {
    assert.ok(builder.includes(`process.env.${name}`), `the build reads ${name}`);
    assert.ok(new RegExp(`echo "${name}=\\$[A-Za-z_]+"`).test(yml), `the workflow exports ${name}`);
  }
  // The build config validates with the APP's own rule rather than a second copy of it.
  assert.match(builder, /require\('\.\/src\/main\/build-stamp'\)/);
  assert.match(builder, /stampMetadata\(\{ commit: process\.env\.DOCKVAULT_BUILD_COMMIT/);
  // The commit stamped is the one this job checked out, never a value from anywhere else.
  assert.match(yml, /COMMIT: \$\{\{ github\.sha \}\}/);
  // One date for the whole RUN, not each runner's own clock: three legs of one commit crossing
  // midnight UTC must not ship installers claiming two different days.
  assert.match(yml, /STARTED: \$\{\{ github\.run_started_at \}\}/);
  assert.ok(!/date -u/.test(yml), 'no per-leg clock read');
  // And it is exported BEFORE the build step that consumes it.
  assert.ok(yml.indexOf('DOCKVAULT_BUILD_COMMIT=') < yml.indexOf('- name: Build installers'), 'stamped before the build runs');
});

// A stamp that fails silently is the failure this whole phase exists to end: an installer named after
// a commit whose own About box says it carries none. So the pipeline refuses at both ends — it will
// not start a build it cannot stamp, and it will not hand on a build the stamp did not reach.
test('the workflow refuses to build without a stamp, and refuses a build the stamp did not reach', () => {
  const yml = fs.readFileSync(path.join(root, '.github', 'workflows', 'build-installers.yml'), 'utf8');
  // Before: the values must be a commit and a date, checked whole (which also keeps a newline out of
  // the $GITHUB_ENV writes, where one would define variables of its own).
  assert.match(yml, /if \[\[ ! "\$COMMIT" =~ \^\[0-9a-f\]\{7,40\}\$ \]\]; then/);
  assert.match(yml, /if \[\[ ! "\$built" =~ \^\[0-9\]\{4\}-\[0-9\]\{2\}-\[0-9\]\{2\}\$ \]\]; then/);
  assert.equal((yml.match(/refusing to build/g) || []).length, 2);
  // After: the packaged app must really carry it, and the check must run before the artifacts leave.
  const check = yml.indexOf('- name: Check the packaged app really carries the stamp');
  assert.ok(check > yml.indexOf('- name: Build installers'), 'checked after the build');
  assert.ok(check < yml.indexOf('upload-artifact'), 'checked before anything is uploaded');
  assert.match(yml, /grep -lF "\$DOCKVAULT_BUILD_COMMIT"/);
  // It compares the archives carrying this build's commit against every archive there is, so one
  // unstamped platform cannot hide behind a stamped one.
  assert.match(yml, /if \[ "\$named" -ne "\$total" \]; then/);
});

// This last one reads SOURCE TEXT, and that is a weak instrument: it can only see that something is
// written, never that it runs. So it asserts the CALL SITES — the line that fills the footer, and the
// item pushed into the menu the tray is actually given — because those are what a merge drops. What
// proves the two surfaces really carry the line is elsewhere and is run separately, since neither can
// run under `node --test`: test/manage-check.js scenario L drives the real page over the real preload
// in a real window, and the tray self-test (DOCKVAULT_TRAY_SELFTEST=1) reads the drawn menu, in a
// packaged build as well as from source. Deleting `void showBuild();` passes this file and fails those.
test('the app shows the build where a person can find it, in both places', () => {
  const html = fs.readFileSync(path.join(root, 'src', 'renderer', 'manage.html'), 'utf8');
  const js = fs.readFileSync(path.join(root, 'src', 'renderer', 'manage.js'), 'utf8');
  const main = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
  // The Computers window: a footer element, a function that fills it, and the CALL that runs it.
  assert.match(html, /<span class="build" id="build">/);
  assert.match(js, /getElementById\('build'\)/);
  assert.match(js, /info\.buildLine/);
  assert.match(js, /^\s*void showBuild\(\);\s*$/m, 'showBuild is actually called, not merely defined');
  // Main composes that line with this module, so the footer and the About box can never disagree.
  assert.match(main, /buildLine: buildStamp\.stampLine\(appStamp\(\)\)/);
  // The tray: the item is pushed into the menu template, wired to the handler, beside Quit.
  assert.match(main, /\{ label: 'About DockVault', click: \(\) => \{ void showAbout\(\); \} \},\r?\n\s*\{ label: 'Quit DockVault'/);
  // And the build's identity is behind the same gate every other page-facing capability uses, so the
  // interface the server supplies cannot read which build a computer runs.
  assert.match(main, /fromShellPage\(e\) \? \{ build: appStamp\(\)/);
  assert.match(main, /const fromShellPage = \(e\) => fromSetupPage\(e\) \|\| fromWizardPage\(e\) \|\| fromManagePage\(e\) \|\| fromTroubleshootPage\(e\);/);
});

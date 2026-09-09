'use strict';

// Installing over an existing DockVault replaces it where it is, and uninstalling keeps the app's
// data unless the person ticks a box to say otherwise.
//
// WHAT THESE CAN AND CANNOT SEE. build/installer.nsh is compiled into an installer by makensis and
// only proves itself when someone runs it, so most of what follows reads the file's TEXT. That limit
// bit hard once already and the shape of these tests is the answer to it: the first version of this
// feature put the deletion inside the checkbox's own section, where it was drawn, ticked, and
// silently ignored — a one-click uninstall section ends in Quit, so nothing declared after it ever
// runs. Every assertion then in this file passed. So these pin WHERE the work lives, not merely that
// it exists, and the last one reaches outside this repo to pin the template contract that "where"
// depends on — because the bug was never in our file, it was in our belief about theirs.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const nsh = fs.readFileSync(path.join(root, 'build', 'installer.nsh'), 'utf8');
const config = require(path.join(root, 'electron-builder.js'));

// The one wording the person actually reads at the moment of choosing.
const LABEL = "Also delete DockVault's settings and this computer's sync registration (your synced files are not touched)";

// The body of a !macro, so "where does this live" can be asked of the macro rather than the file.
// The name is matched to its line end: `customUnInstall` is a prefix of `customUnInstallSection`,
// and a prefix match would hand back the wrong body the day the two are declared in the other order
// — quietly turning the first assertion below into one that passes on the broken layout.
const macroOf = (name) => {
  const m = nsh.match(new RegExp(`^!macro ${name}\\s*$`, 'm'));
  assert.ok(m, `!macro ${name} exists`);
  const end = nsh.indexOf('!macroend', m.index);
  assert.notEqual(end, -1, `!macro ${name} is closed`);
  return nsh.slice(m.index, end);
};

// The text between a `${IfNot} ${isUpdated}` and its matching `${EndIf}`, for asking whether
// something is INSIDE the guard rather than merely somewhere after it.
const updateGuardedBlock = (body) => {
  const start = body.indexOf('${IfNot} ${isUpdated}');
  assert.notEqual(start, -1, 'there is an update guard');
  const lines = body.slice(start).split(/\r?\n/);
  let depth = 0;
  const out = [];
  for (const line of lines) {
    out.push(line);
    if (/\$\{(If|IfNot|Do|Select)\b/.test(line)) depth += 1;
    if (/\$\{(EndIf|endIf|Loop|EndSelect)\}/.test(line)) {
      depth -= 1;
      if (depth === 0) break;
    }
  }
  return out.join('\n');
};

test('the deletion lives where it will actually run, and the box is only read', () => {
  const removals = [...nsh.matchAll(/RMDir\s+(\/r\s+)?"\$APPDATA[^"]*"/g)].map((m) => m[0]);
  assert.equal(removals.length, 2, `the contents, then the emptied folder: ${JSON.stringify(removals)}`);
  // customUnInstall is inserted by the template INSIDE the uninstall section, before the Quit that
  // ends a one-click run. That is the only place in this file whose code is guaranteed to execute.
  const unInstall = macroOf('customUnInstall');
  for (const r of removals) assert.ok(unInstall.includes(r), `${r} is in customUnInstall`);
  // And NOT in the section, which is declared after that Quit and never runs. This is the assertion
  // that would have failed on the first version of this feature.
  assert.ok(!macroOf('customUnInstallSection').includes('RMDir'), 'the section body does no work');
  assert.ok(!macroOf('customUnInstallSection').includes('MessageBox'), 'and says nothing');
});

test('the box is unticked, and it is found by its label rather than by a position', () => {
  // `/o` is what makes it unticked. Without it the section is selected by default and uninstalling
  // would delete the data unless the person noticed and turned it off — the exact inversion.
  assert.match(nsh, /Section \/o "un\.\$\{DV_APPDATA_LABEL\}"/);
  const unInstall = macroOf('customUnInstall');
  // The sections are walked and matched by label. An index would work today and become decoration
  // the day anything is declared before the box, with nothing to say so.
  assert.match(unInstall, /SectionGetText \$R4 \$R6/);
  assert.match(unInstall, /\$\{If\} \$R6 == "\$\{DV_APPDATA_LABEL\}"/);
  assert.ok(!/DV_APPDATA_SECTION/.test(nsh), 'no fixed index survives');
  // An index past the last section leaves the output untouched, so it is cleared before each read;
  // without that the walk would match a section that is no longer there.
  assert.match(unInstall, /ClearErrors\s*\r?\n\s*StrCpy \$R6 ""\s*\r?\n\s*SectionGetText/);
  assert.match(unInstall, /\$\{If\} \$\{Errors\}\s*\r?\n\s*\$\{ExitDo\}/);
  // The flags are read ONLY for a section whose label matched, and are only believed if one did.
  assert.ok(unInstall.indexOf('SectionGetText') < unInstall.indexOf('SectionGetFlags'), 'matched, then read');
  assert.match(unInstall, /\$\{If\} \$R5 != ""/, 'nothing found means nothing deleted');
  assert.match(unInstall, /IntOp \$R5 \$R5 & \$\{SF_SELECTED\}/);
  // The walk is bounded, so a malformed uninstaller cannot spin in it.
  assert.match(unInstall, /\$\{If\} \$R4 > \$\{DV_MAX_SECTIONS\}/);
  // One label, one place: the section that declares it and the walk that finds it cannot drift.
  assert.equal((nsh.match(/!define DV_APPDATA_LABEL/g) || []).length, 1);
  // The label is all the person gets: the components page has no description pane, so what is
  // destroyed AND what is not have to be in the label itself.
  assert.ok(nsh.includes(`!define DV_APPDATA_LABEL "${LABEL}"`), 'the label is the agreed wording');
  assert.match(nsh, /sync registration/, 'it names the registration, not a vaguer "sync state"');
  assert.match(nsh, /synced files are not touched/, 'and says what is NOT deleted');
  // The page's own framing, too: left to MUI it calls this picking features off a list.
  assert.match(nsh, /!define MUI_UNTEXT_COMPONENTS_SUBTITLE/);
  assert.match(nsh, /!define MUI_UNINNERTEXT_COMPONENTS_TOP/);
});

test('an upgrade can never reach the deletion, twice over', () => {
  const unInstall = macroOf('customUnInstall');
  // INSIDE the guard, not merely somewhere after it — this file has another `${ifNot} ${isUpdated}`
  // block (the login item), and an assertion that only proved ordering would pass with the real
  // guard deleted.
  const guarded = updateGuardedBlock(unInstall);
  assert.ok(guarded.includes('SectionGetText'), 'the walk is inside the update guard');
  assert.ok(guarded.includes('RMDir'), 'and so is the deletion');
  // And separately: the uninstaller only becomes interactive — so the box can be seen and ticked at
  // all — for an uninstall a person started. An upgrade runs it with /S --updated and stays silent,
  // which leaves the box untouched.
  const unInit = macroOf('customUnInit');
  assert.match(unInit, /\$\{GetOptions\} \$R0 "\/S" \$R1/, 'it looks for a silent run');
  assert.match(unInit, /\$\{IfNot\}\s+\$\{isUpdated\}/, 'and for an update');
  assert.match(unInit, /SetSilent normal/);
  assert.equal((unInit.match(/SetSilent/g) || []).length, 1, 'silence is changed once, in this macro');
});

// The template has its own --delete-app-data handling, and it runs AFTER our hook. Left alone, an
// uninstall passed that flag without /S drew the box UNTICKED, was told by our note that the data was
// kept, and then had the template delete it anyway: the page and the sentence both false in one run.
// Passing the flag IS the choice the box exists to offer, so it counts as the box being ticked.
test('the flag that asks for the data to go counts as the box being ticked', () => {
  const unInstall = macroOf('customUnInstall');
  assert.match(unInstall, /\$\{GetOptions\} \$R2 "--delete-app-data" \$R1/);
  // It is OR'd with the box, not substituted for it, so either route deletes and both are described
  // by the same note.
  assert.match(unInstall, /\$\{If\} \$R5 == \$\{SF_SELECTED\}\s+\$\{OrIf\} \$R3 == "asked"/);
  // And it is inside the update guard like everything else here: an upgrade never deletes.
  assert.ok(updateGuardedBlock(unInstall).includes('--delete-app-data'), 'an upgrade still cannot reach it');
});

// The error flag is not ours to hand back set. SectionGetText raises it at the end of the walk and
// RMDir raises it on a locked file; nothing between here and the template's own ClearErrors reads it
// today, which is a fact about their code rather than a promise.
test('the hook leaves the error flag clear', () => {
  const unInstall = macroOf('customUnInstall');
  assert.match(unInstall, /ClearErrors\s*$/, 'the last thing it does is clear the error flag');
});

test('the default is still to keep the data, in the configuration as well as the hook', () => {
  // The build-time switch that would delete app data for everyone with no choice offered. It stays
  // off: the choice belongs to the person at uninstall time, which is what the box is for.
  assert.equal(config.nsis.deleteAppDataOnUninstall, false);
  // The installer stays one-click. That was a deliberate call — the assisted installer opens on an
  // "anyone who uses this computer / only me" page whose first option dead-ends without administrator
  // rights — and the box was built around it rather than trading it away. Note this setting is also
  // what makes the uninstall section end in Quit, which is why the deletion cannot live in a section.
  assert.equal(config.nsis.oneClick, true);
  assert.equal(config.nsis.perMachine, false);
  assert.equal(config.nsis.allowElevation, false);
});

// "Asked to delete" and "deleted" are not the same event: RMDir /r deletes what it can and does not
// fail loudly on a file something else has open. The realistic partial is the worst one to get wrong
// — the small files go first, so the identity is gone while one cache file keeps the folder alive —
// and read as two outcomes that lands in "kept", telling the person their registration is intact at
// the moment it stopped existing. So there are three, and none of them may say the wrong thing.
test('there are three outcomes, and each is told the truth about itself', () => {
  const unInstall = macroOf('customUnInstall');
  assert.equal((unInstall.match(/MessageBox/g) || []).length, 3, 'a message for each outcome');
  assert.match(unInstall, /StrCpy \$dvRemovedAppData "gone"/);
  assert.match(unInstall, /StrCpy \$dvRemovedAppData "partial"/);
  assert.match(unInstall, /IfSilent dvNoteDone/, 'and nothing is said during a silent run');
  // The emptied folder is removed before the check, so a directory that merely outlived its contents
  // is not mistaken for data that survived.
  assert.match(unInstall, /RMDir \/r "\$APPDATA[^"]*"[\s\S]{0,900}?RMDir "\$APPDATA[^"]*"/);
  // Nothing is claimed before it is checked.
  assert.ok(unInstall.indexOf('IfFileExists') < unInstall.indexOf('StrCpy $dvRemovedAppData "gone"'), 'checked, then claimed');

  // The wordings themselves. Sliced from the note's OWN branch points — an earlier version anchored
  // on the first `${Else}` in the macro, which belongs to the CLSID loop far above, so it matched the
  // deletion lines and asserted nothing: the two messages could have been swapped and stayed green.
  const noteStart = unInstall.indexOf('${If} $dvRemovedAppData == "gone"');
  assert.notEqual(noteStart, -1, 'the note branches on the outcome');
  const note = unInstall.slice(noteStart);
  const partialAt = note.indexOf('${ElseIf} $dvRemovedAppData == "partial"');
  const keptAt = note.indexOf('${Else}', partialAt);
  assert.ok(partialAt > 0 && keptAt > partialAt, 'three branches, in order');
  const gone = note.slice(0, partialAt);
  const partial = note.slice(partialAt, keptAt);
  const kept = note.slice(keptAt);

  // Removed: says the registration went with it, and never says anything was kept or reusable.
  assert.match(gone, /sync registration/);
  assert.match(gone, /set itself up from scratch/);
  assert.ok(!/stay in \$APPDATA|picks up where it left off/.test(gone), 'the removed branch promises nothing');
  // Partial: never reassures. It must say the registration is not to be relied on, and say where the
  // leftovers are. This is the branch that used to be the kept message.
  assert.match(partial, /could not be deleted/);
  assert.match(partial, /Treat this computer's sync registration as gone/);
  assert.match(partial, /\$APPDATA\\\$\{APP_PACKAGE_NAME\}/, 'and names what is left behind');
  assert.ok(!/picks up where it left off/.test(partial), 'the partial branch never reassures');
  // Kept: the only branch allowed to say the data is still there and still usable, and it must name
  // the folder or it is not useful.
  assert.match(kept, /picks up where it left off/);
  assert.match(kept, /\$APPDATA\\\$\{APP_PACKAGE_NAME\}/);
  assert.ok(!/could not be deleted|from scratch/.test(kept), 'the kept branch is not a removal message');
});

test('the install writes where it installed, so the installed-programs list can say', () => {
  const install = macroOf('customInstall');
  assert.match(install, /WriteRegStr SHELL_CONTEXT "\$\{UNINSTALL_REGISTRY_KEY\}" "InstallLocation" "\$INSTDIR"/);
  // The second uninstall key is written only if defined, and for this app it never is (the define
  // appears only when the app guid contains a backslash). The code keeps the branch because it costs
  // nothing; this does not assert it, because pinning a branch that can never compile here would be
  // pinning decoration.
});

test('the variable the note reads is declared only where it is used', () => {
  // This file is compiled into the installer as well as the uninstaller, and makensis runs with -WX,
  // where a variable nothing reads is a warning and a warning is a failed build.
  assert.match(nsh, /!ifdef BUILD_UNINSTALLER\s*\r?\n\s*Var \/GLOBAL dvRemovedAppData\s*\r?\n\s*!endif/);
  // SF_SELECTED is deliberately NOT defined here: this file is included ahead of Sections.nsh, which
  // defines it plainly, and defining it first makes that include fail outright.
  assert.ok(!/!define\s+(\/ifndef\s+)?SF_SELECTED/.test(nsh), 'SF_SELECTED is left to Sections.nsh');
});

test("the data folder always means the person's own, whatever install mode is in force", () => {
  const unInstall = macroOf('customUnInstall');
  // SetShellVarContext all remaps $APPDATA to ProgramData. Electron's user data is per-user always,
  // so the deletion and the note both have to run under the current-user context or they point at a
  // folder nobody has. Unreachable today, guarded anyway — the same way the template guards its own
  // copy of this deletion, and for the same reason.
  const guards = [...unInstall.matchAll(/\$\{if\} \$installMode == "all"\s*\r?\n\s*SetShellVarContext (current|all)/g)].map((m) => m[1]);
  assert.deepEqual(guards, ['current', 'all'], "switched to the person's context, and switched back");
  assert.ok(unInstall.indexOf('SetShellVarContext current') < unInstall.indexOf('RMDir'));
  assert.ok(unInstall.lastIndexOf('SetShellVarContext all') > unInstall.indexOf('dvNoteDone:'));
});

// The one assertion that reaches outside this repo, and the most important one here. Everything
// above rests on a fact about SOMEBODY ELSE'S file: that the template inserts customUnInstall INSIDE
// the uninstall section and BEFORE the Quit that ends a one-click run. That belief is what was wrong
// the first time, and nothing in our own file can notice if it stops being true. electron-builder is
// pinned to an exact version, so this can only change by a deliberate bump — and a bump that moved
// the hook would otherwise be green, with the box drawn, ticked, and silently ignored again.
test('the template still inserts our hook where we think it does', () => {
  const tpl = path.join(root, 'node_modules', 'app-builder-lib', 'templates', 'nsis', 'uninstaller.nsh');
  const src = fs.readFileSync(tpl, 'utf8');
  const sectionStart = src.indexOf('Section "un.${UNINSTALL_SECTION_NAME}"');
  assert.notEqual(sectionStart, -1, 'the uninstall section is where we expect');
  const sectionEnd = src.indexOf('SectionEnd', sectionStart);
  const hook = src.indexOf('!insertmacro customUnInstall', sectionStart);
  const quit = src.indexOf('!insertmacro quitSuccess', sectionStart);
  assert.ok(hook !== -1 && hook < sectionEnd, 'customUnInstall is inserted inside the uninstall section');
  assert.ok(quit !== -1 && quit < sectionEnd, 'and the one-click Quit is in there too');
  assert.ok(hook < quit, 'our hook runs BEFORE the Quit — the whole design rests on this');
  // The section that carries the box is inserted after that section, which is why its body is empty.
  const sectionHook = src.indexOf('!insertmacro customUnInstallSection');
  assert.ok(sectionHook > sectionEnd, 'and the box section is inserted after it, hence unreachable');

  // The box only WORKS because the hook runs. It is only SEEN because of two more facts in their
  // files, and a bump that broke either would leave it drawn, ticked and ignored — inert but green,
  // which is this phase's named worst outcome. Both are pinned here for the same reason as above.
  const nsi = fs.readFileSync(path.join(root, 'node_modules', 'app-builder-lib', 'templates', 'nsis', 'installer.nsi'), 'utf8');
  const guard = nsi.indexOf('!ifmacrodef customUnInstallSection');
  assert.notEqual(guard, -1, 'defining our section is still what asks for the page');
  const components = nsi.indexOf('MUI_UNPAGE_COMPONENTS', guard);
  assert.ok(components > guard && components - guard < 200, 'and that is still what emits the components page');
  // ...and our un-silencing still lands AFTER the one-click silencing it exists to undo. Were it to
  // move before, the template would silence us again and no page would draw at all.
  const initStart = src.indexOf('Function un.onInit');
  const initEnd = src.indexOf('FunctionEnd', initStart);
  const silence = src.indexOf('SetSilent silent', initStart);
  const ourHook = src.indexOf('!insertmacro customUnInit', initStart);
  assert.ok(silence !== -1 && silence < initEnd, 'un.onInit still silences a one-click uninstall');
  assert.ok(ourHook !== -1 && ourHook < initEnd, 'and still inserts customUnInit');
  assert.ok(silence < ourHook, 'ours runs after theirs, which is the only order that works');
});

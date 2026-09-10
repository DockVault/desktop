'use strict';

// WHETHER A RUN IS PORTABLE, asked in both directions, with the temp folder treated as an INPUT.
//
// This file exists because of one line that appeared in every test of this behaviour before it:
//
//     portableLaunch({ ..., tmpDir: os.tmpdir(), ... })
//
// Every direction-(a) test handed the check the real temp folder and then varied something else. That
// made the temp root a fixed, trustworthy backdrop — which is exactly what it is not. Node computes
// os.tmpdir() on Windows as TEMP || TMP || SystemRoot\temp, so it is a THIRD environment variable,
// sitting next to the two the check was refusing to trust. Setting TEMP to `C:\` made every installed
// location "inside temp", and an INSTALLED app could be pointed at a network share with one extra
// variable and no file on disk. No test could see it, because no test could move the backdrop.
//
// The same blind spot hid the opposite failure. The launcher and this process do not compute the temp
// folder by the same rule — Windows' GetTempPathW reads TMP, then TEMP, then USERPROFILE; Node reads
// TEMP, then TMP, then the Windows temp folder — so on a machine where those disagree, a GENUINE
// portable launch was running somewhere the check's idea of temp did not contain. It was demoted, in
// silence, and opened the installed profile.
//
// The decision no longer reads a temp folder AT ALL — that is the fix, and the last two tests here are
// what keep it that way. What the fixtures still do is build the two rules separately and launch from
// each, so that a future version which reaches for a temp folder again is caught from both sides:
// by the sweep, which moves every variable that has ever steered this, and by the structural check,
// which fails if the decision so much as mentions one.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { portableLaunch, chooseDataDir, applyDataDir, insideOrSame, PORTABLE_ENV, PORTABLE_FILE_ENV, PORTABLE_APP_ENV } = require('../src/main/portable');

const APP = 'dockvault-desktop';
const tmps = [];
const mk = (prefix) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); tmps.push(d); return d; };
test.after(() => { for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } } });

// The two rules, written out rather than assumed equal. This is the fixture's whole point.
const gettemppath = (env) => env.TMP || env.TEMP || env.USERPROFILE || 'C:\\WINDOWS';     // the launcher
const nodeTmpdir = (env) => env.TEMP || env.TMP || 'C:\\WINDOWS\\temp';                   // this process

// An INSTALLED program directory: the executable, and the uninstaller the installer writes beside it.
// A real one is not a path — it is a directory with that file in it, which is the whole discriminator.
function installedApp(uninstallerName = `Uninstall ${APP}.exe`) {
  const dir = mk('dv-installed-');
  const exe = path.join(dir, 'DockVault.exe');
  fs.writeFileSync(exe, 'x');
  fs.writeFileSync(path.join(dir, uninstallerName), 'x');
  return exe;
}

// A portable launch as the launcher really makes it: unpacked under ITS rule for temp, run from there.
function unpackedUnder(root) {
  const dir = fs.mkdtempSync(path.join(root, 'dv-unpack-'));
  tmps.push(dir);
  const exe = path.join(dir, 'DockVault.exe');
  fs.writeFileSync(exe, 'x');
  return exe;
}

function downloadedLauncher() {
  const dir = mk('dv-downloads-');
  const file = path.join(dir, 'DockVault-0.1.0-win-x64-portable.exe');
  fs.writeFileSync(file, 'x');
  return { dir, file };
}

// ---------------------------------------------------------------------------------------------
// DIRECTION (a) — an installed app must stay installed, whatever the environment says.
// ---------------------------------------------------------------------------------------------

test('an installed app stays installed even when the temp folder is the attacker\'s to name', () => {
  const installedExe = installedApp();
  const attackerDir = ['', '', 'attacker', 'share'].join(path.sep);  // a UNC share: no local file needed

  // Every one of these is a value that whoever sets PORTABLE_EXECUTABLE_DIR can also put in TEMP —
  // from HKCU\Environment, a shortcut, or a shell. No privilege, and nothing to create on disk.
  const forged = [
    ['the drive root, which contains everything', path.parse(installedExe).root],
    ['the folder the app is installed in', path.dirname(path.dirname(installedExe))],
    ['the app\'s own directory', path.dirname(installedExe)],
  ];

  for (const [what, temp] of forged) {
    const env = { [PORTABLE_ENV]: attackerDir, TEMP: temp };
    const r = portableLaunch({
      env, fs, execPath: installedExe, platform: 'win32',
      appName: APP,
    });
    assert.equal(r.portable, false, `${what}: an installed app must stay installed`);
    assert.equal(typeof r.why, 'string', `${what}: and must say which check refused it`);
  }
});

test('naming every variable the launcher sets does not buy an installed app portability', () => {
  const installedExe = installedApp();
  const { dir, file } = downloadedLauncher();
  const env = {
    [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP,
    TEMP: path.dirname(installedExe),   // the one addition that defeated the old anchor
  };
  const r = portableLaunch({ env, fs, execPath: installedExe, platform: 'win32', appName: APP });
  assert.equal(r.portable, false, 'a full set of forged variables is still not a portable launch');
});

// The point of naming the uninstaller by SHAPE: where the app was installed is not knowable, but that
// an installer put its uninstaller beside the program is true of every install it makes. An earlier
// attempt derived one known install location and missed every other, which this pins.
test('it recognises an install wherever it is and whatever the uninstaller is called', () => {
  for (const name of ['Uninstall DockVault.exe', 'uninstall dockvault-desktop.exe', 'Uninstall.exe', 'unins000.exe']) {
    const exe = installedApp(name);
    const env = { [PORTABLE_ENV]: mk('dv-elsewhere-'), TEMP: path.dirname(exe) };
    const r = portableLaunch({ env, fs, execPath: exe, platform: 'win32', appName: APP });
    assert.equal(r.portable, false, `${name}: an uninstaller beside the program means installed`);
    assert.match(r.why, /installed app/);
  }
});

// If the program cannot read its own directory it cannot establish that it is NOT the installed app,
// and this is the check the isolation rests on. Not knowing is not a licence to relocate a profile.
test('a program that cannot see where it is running from refuses rather than assumes', () => {
  const missing = path.join(mk('dv-gone-'), 'no-such-dir', 'DockVault.exe');
  const env = { [PORTABLE_ENV]: mk('dv-elsewhere-'), TEMP: path.dirname(path.dirname(missing)) };
  const r = portableLaunch({ env, fs, execPath: missing, platform: 'win32', appName: APP });
  assert.equal(r.portable, false, 'unknown fails closed, towards an ordinary run');
  assert.equal(typeof r.why, 'string');
});

// AN ATTACKER MUST NOT BE ABLE TO DECLINE A CHECK BY WITHHOLDING ITS INPUT. Both corroborating
// variables used to be checked only "if set", so setting one variable and omitting the other two skipped
// them — the whole forgery needed one variable and no file anywhere. The real launcher sets all three on
// every launch, so requiring them costs a genuine run nothing.
test('a launch that withholds the launcher\'s own corroboration is not a launch', () => {
  const runningExe = unpackedUnder(mk('dv-unpack-'));
  const { dir, file } = downloadedLauncher();
  const full = { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP };

  for (const missing of [PORTABLE_FILE_ENV, PORTABLE_APP_ENV]) {
    const env = { ...full };
    delete env[missing];
    const r = portableLaunch({ env, fs, execPath: runningExe, platform: 'win32', appName: APP });
    assert.equal(r.portable, false, `omitting ${missing} must not skip its check`);
    assert.equal(typeof r.why, 'string');
  }

  // The named executable has to actually be there, in the directory the other variable names.
  const elsewhere = downloadedLauncher();
  const r = portableLaunch({
    env: { ...full, [PORTABLE_FILE_ENV]: elsewhere.file },
    fs, execPath: runningExe, platform: 'win32', appName: APP,
  });
  assert.equal(r.portable, false, 'the named executable must be in the directory the launcher names');

  // And the complete, honest set still works, or the above would prove only that everything is refused.
  assert.equal(portableLaunch({ env: full, fs, execPath: runningExe, platform: 'win32', appName: APP }).portable, true);
});

// TWO GUARDS THAT SAT IN THE SECURITY PATH UNTESTED. Measured before this test existed: deleting either one
// left all three portable test files green (33 pass / 0 fail). A check nobody would notice the removal of is
// indistinguishable from a check that is not there.
test('the launcher directory must be an absolute path, and the executable it names a real file', () => {
  const runningExe = unpackedUnder(mk('dv-unpack-'));
  const { dir, file } = downloadedLauncher();

  // A RELATIVE directory. Everything downstream joins onto this, so a relative one resolves against whatever
  // the working directory happens to be at the time — which is not a location anyone chose.
  for (const relative of ['somewhere', './somewhere', '..', 'downloads/dockvault']) {
    const r = portableLaunch({
      env: { [PORTABLE_ENV]: relative, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
      fs, execPath: runningExe, platform: 'win32', appName: APP,
    });
    assert.equal(r.portable, false, `${relative}: a relative launcher directory is not a launch`);
    assert.match(r.why, /absolute/, `${relative}: refused for the reason it should be`);
  }

  // A DIRECTORY where the executable should be. `statSync` alone succeeds on a directory, so dropping the
  // isFile() check would let a folder named like an .exe stand in for the launcher's own executable.
  const asDir = portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: dir, [PORTABLE_APP_ENV]: APP },
    fs, execPath: runningExe, platform: 'win32', appName: APP,
  });
  assert.equal(asDir.portable, false, 'a directory is not the launcher executable');
  assert.match(asDir.why, /not a file/, 'and it is refused for being a directory, not for being absent');

  // The honest set still passes, so the two refusals above are not just "everything is refused".
  assert.equal(portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
    fs, execPath: runningExe, platform: 'win32', appName: APP,
  }).portable, true);
});

// A DEVICE IDENTITY AND AN ENCRYPTED SESSION DO NOT LEAVE THE MACHINE. This is a bound on the damage,
// not another attempt at the decision: the decision rests on a file in a directory the user can write
// to, so someone already running as the user can beat it. What they must not also get is the identity
// written to a share they control. A genuine portable run loses nothing that matters — it falls through
// to a local per-executable folder and still never touches the installed profile.
test('a portable run never writes its identity to a network location', () => {
  const { isRemote } = require('../src/main/portable');
  for (const remote of ['\\\\server\\share', '\\\\server\\share\\sub', '//server/share', '\\\\?\\UNC\\server\\share']) {
    assert.equal(isRemote(remote), true, `${remote} is not local`);
  }
  for (const local of ['C:\\Users\\someone', 'C:\\', '\\\\?\\C:\\Users\\someone', 'D:\\portable']) {
    assert.equal(isRemote(local), false, `${local} is local`);
  }

  // And the choice honours it: a launcher on a share falls through to the local folder, not the share.
  const local = mk('dv-local-');
  const installed = path.join(mk('dv-roaming-'), APP);
  const d = chooseDataDir({
    exeDir: '\\\\attacker\\share',
    exeFile: '\\\\attacker\\share\\DockVault-portable.exe',
    installedDir: installed, localAppData: local, fs, canWrite: () => true,
  });
  assert.equal(d.where, 'fallback', `a share must not receive the data: ${JSON.stringify(d)}`);
  assert.ok(!isRemote(d.dir), 'and what it falls back to is local');

  // If the only local root is itself remote there is nowhere safe, and it refuses rather than guessing.
  const nowhere = chooseDataDir({
    exeDir: '\\\\attacker\\share', exeFile: null,
    installedDir: installed, localAppData: '\\\\attacker\\other', fs, canWrite: () => true,
  });
  assert.equal(nowhere.dir, null);
  assert.equal(typeof nowhere.refused, 'string');
});

// The two cheap outer conditions, tested because both could be deleted with everything else green.
test('a development run and a non-Windows run are never portable, whatever the variables say', () => {
  const runningExe = unpackedUnder(mk('dv-anywhere-'));
  const { dir, file } = downloadedLauncher();
  const env = { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP };

  // A stray variable in a developer's shell must not move their own data.
  const dev = portableLaunch({ env, fs, execPath: runningExe, platform: 'win32', appName: APP, isPackaged: false });
  assert.equal(dev.portable, false, 'a development run is not a portable launch');
  assert.match(dev.why, /development run/);

  // The portable target is Windows-only; elsewhere the variable means nothing. It is REFUSED rather
  // than acted on, which is also what stops a stray variable halting the app on mac or Linux.
  for (const platform of ['darwin', 'linux']) {
    const r = portableLaunch({ env, fs, execPath: runningExe, platform, appName: APP });
    assert.equal(r.portable, false, `${platform}: portable builds are a Windows target`);
    assert.equal(typeof r.why, 'string');
  }

  // And the same inputs on packaged Windows still are portable, or the two above would prove nothing.
  assert.equal(portableLaunch({ env, fs, execPath: runningExe, platform: 'win32', appName: APP }).portable, true);
});

// ---------------------------------------------------------------------------------------------
// DIRECTION (b) — a genuine launch must not be demoted. A demotion is silent and opens the real profile.
// ---------------------------------------------------------------------------------------------

test('a real portable launch survives TMP and TEMP disagreeing', () => {
  const env = { TMP: mk('dv-launcher-temp-'), TEMP: mk('dv-node-temp-') };
  assert.notEqual(gettemppath(env), nodeTmpdir(env), 'the fixture really does put the two rules apart');

  const runningExe = unpackedUnder(gettemppath(env));   // where the launcher actually put it
  const { dir, file } = downloadedLauncher();
  const full = { ...env, [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP };

  const r = portableLaunch({
    env: full, fs, execPath: runningExe, platform: 'win32',
             // the app's view, which is NOT where it is running
    appName: APP,
  });
  assert.equal(r.portable, true, `a genuine launch must not be demoted: ${r.why}`);
  assert.equal(r.exeDir, dir);
});

test('a real portable launch survives TMP and TEMP both being absent', () => {
  // Services, stripped environments, some elevated shells. The launcher falls back to USERPROFILE and
  // this process falls back to the Windows temp folder, so the split is wider, not narrower.
  const env = { USERPROFILE: mk('dv-profile-') };
  assert.notEqual(gettemppath(env), nodeTmpdir(env), 'the two fallbacks really do differ');

  const runningExe = unpackedUnder(gettemppath(env));
  const { dir, file } = downloadedLauncher();
  const full = { ...env, [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP };

  const r = portableLaunch({ env: full, fs, execPath: runningExe, platform: 'win32', appName: APP });
  assert.equal(r.portable, true, `a genuine launch must not be demoted: ${r.why}`);
});

// THE GUARD THAT KEEPS DATA OUT OF THE INSTALLED PROFILE IS ONLY AS GOOD AS THE FOLDER IT IS TOLD TO
// AVOID, and that folder is DERIVED — `join(roamingDir, appName)` — inside applyDataDir. Every other
// test hands `installedDir` to `chooseDataDir` directly, so the derivation itself was never asked a
// question it could get wrong: mutating it left the whole suite green through two reviews.
//
// Here the launch really does run from inside the installed profile, so a wrong derivation nests the
// portable data exactly where an uninstall's "also delete settings" would take it with the rest.
test('the folder a portable run must avoid is derived correctly, not merely passed in', () => {
  const roaming = mk('dv-roaming-');
  const installedProfile = path.join(roaming, APP);
  fs.mkdirSync(installedProfile, { recursive: true });

  // The launcher is sitting INSIDE the installed profile — the shape the guard exists for.
  const launcherDir = path.join(installedProfile, 'downloaded-here');
  fs.mkdirSync(launcherDir, { recursive: true });
  const launcher = path.join(launcherDir, 'DockVault-0.1.0-win-x64-portable.exe');
  fs.writeFileSync(launcher, 'x');
  const runningExe = unpackedUnder(mk('dv-unpack-'));

  let set = null;
  const app = { setPath: (k, v) => { set = v; }, getPath: () => { throw new Error('must not be asked'); } };
  const local = mk('dv-local-');
  const r = applyDataDir(app, {
    env: { [PORTABLE_ENV]: launcherDir, [PORTABLE_FILE_ENV]: launcher, [PORTABLE_APP_ENV]: APP },
    fs, localAppData: local, appName: APP, roamingDir: roaming, platform: 'win32', execPath: runningExe,
  });

  assert.equal(r.portable, true, `this is a genuine launch: ${r.why}`);
  assert.equal(r.where, 'fallback', 'beside the launcher is inside the installed profile, so it is refused');
  assert.ok(set && !insideOrSame(set, installedProfile, fs),
    `the data must not land inside the installed profile: ${set}`);
  assert.ok(set.startsWith(local), 'it lands in the per-user local folder instead');
});

// A BUILD COUPLING THAT NOTHING ELSE HOLDS IN PLACE. The launcher sets
// PORTABLE_EXECUTABLE_APP_FILENAME from electron-builder's sanitized app name; the running app compares
// it against `app.getName()`, which Electron takes from package.json `productName` if present and `name`
// otherwise. They are equal today only because package.json has NO `productName` — while
// electron-builder.js sets one, to a DIFFERENT value. Adding `"productName": "DockVault"` to
// package.json is an entirely reasonable change that would make `app.getName()` return `DockVault`
// while the launcher still says `dockvault-desktop`, and EVERY genuine portable launch would be
// demoted, silently, into the installed profile. Both sides are hardcoded in the other tests, so
// nothing there would notice.
test('the name the launcher reports and the name the app answers to cannot drift apart', () => {
  const pkg = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8'));
  const electronName = pkg.productName || pkg.name;          // what app.getName() returns
  const launcherName = pkg.name;                             // what the portable launcher reports
  assert.equal(electronName, launcherName,
    'package.json productName would change app.getName() without changing what the launcher reports; '
    + 'if you add one, the portable app-name check must be updated in the same change');

  // And the check really is the thing that would break, so this test is not merely about two strings.
  const runningExe = unpackedUnder(mk('dv-unpack-'));
  const { dir, file } = downloadedLauncher();
  const drifted = portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: launcherName },
    fs, execPath: runningExe, platform: 'win32', appName: 'DockVault',   // as it would become
  });
  assert.equal(drifted.portable, false, 'drift demotes a genuine launch — which is why the two must match');
});

// THE PROGRAM DIRECTORY IS DESTROYED FAR MORE OFTEN THAN THE PROFILE, and the containment guard only knew
// about the profile. The uninstaller runs `RMDir /r $INSTDIR` on every uninstall AND on every in-place
// upgrade, unconditionally — whereas deleting the roaming profile is an unticked box someone has to choose.
// So a portable copy sitting in the install directory would have kept its data in the one folder that a
// routine upgrade wipes, with nobody having asked for anything to be deleted.
test('a portable copy inside the program directory does not keep its data there', () => {
  const programDir = mk('dv-program-');
  fs.writeFileSync(path.join(programDir, 'Uninstall DockVault.exe'), 'x');  // what makes it the program dir
  const exeFile = path.join(programDir, 'DockVault-0.1.0-portable.exe');
  fs.writeFileSync(exeFile, 'x');

  const local = mk('dv-local-');
  const installedProfile = path.join(mk('dv-roaming-'), APP);
  const d = chooseDataDir({ exeDir: programDir, exeFile, installedDir: installedProfile, localAppData: local, fs, canWrite: () => true });

  assert.equal(d.where, 'fallback', `beside the .exe here is inside $INSTDIR: ${JSON.stringify(d)}`);
  assert.ok(!insideOrSame(d.dir, programDir, fs), 'and what it falls back to is outside the program directory');
  assert.ok(d.dir.startsWith(local));

  // The very same layout WITHOUT an uninstaller is an ordinary Downloads folder, and must still work —
  // otherwise this guard would be refusing every normal portable run.
  const plainDir = mk('dv-downloads-plain-');
  const plainExe = path.join(plainDir, 'DockVault-0.1.0-portable.exe');
  fs.writeFileSync(plainExe, 'x');
  const ok = chooseDataDir({ exeDir: plainDir, exeFile: plainExe, installedDir: installedProfile, localAppData: local, fs, canWrite: () => true });
  assert.equal(ok.where, 'beside-exe', 'an ordinary folder still keeps its data beside the executable');
});

// ---------------------------------------------------------------------------------------------
// THE INVARIANT. This is the one that would have caught all three previous rounds.
//
// Each round failed the same way: the decision was anchored on a path the environment supplies, so
// whoever set the variables owned the anchor. Round one it was PORTABLE_EXECUTABLE_DIR; round three it
// was the temp folder, which is TEMP || TMP || SystemRoot\temp and therefore no better. Both were
// reasoned about carefully and both were wrong for the same reason, which is why the rule is now
// structural rather than a matter of judgement: THE DECISION MAY NOT READ A TEMP FOLDER AT ALL.
// ---------------------------------------------------------------------------------------------

test('the decision cannot be moved by any environment variable it does not already refuse', () => {
  const installedExe = installedApp();
  const { dir, file } = downloadedLauncher();
  const runningExe = unpackedUnder(mk('dv-anywhere-'));

  // Every environment name that has ever steered this decision, plus the two the launcher legitimately
  // sets. Swept to absurd values in both directions: the installed app must stay installed, and the
  // genuine launch must stay portable, no matter what any of these say.
  const hostile = [
    {}, { TEMP: 'C:\\' }, { TMP: 'C:\\' }, { TEMP: 'C:\\', TMP: 'C:\\' },
    { USERPROFILE: 'C:\\' }, { SystemRoot: 'C:\\' }, { LOCALAPPDATA: 'C:\\' }, { APPDATA: 'C:\\' },
    { TEMP: path.dirname(installedExe), TMP: path.dirname(installedExe) },
    { TEMP: '', TMP: '', USERPROFILE: '' },
    // LOWER CASE TOO. Windows resolves environment names case-insensitively, so code reading `env.temp`
    // works in production; fixtures that only ever spell it `TEMP` leave that spelling untested and a
    // regression using it invisible. This is not hypothetical — it is how the first version of this file
    // let round three back in.
    { temp: 'C:\\' }, { tmp: 'C:\\' }, { temp: 'C:\\', tmp: 'C:\\' },
    { temp: path.dirname(installedExe), tmp: path.dirname(installedExe) },
    { Temp: 'C:\\', Tmp: 'C:\\', UserProfile: 'C:\\' },
  ];
  for (const extra of hostile) {
    const label = JSON.stringify(extra);
    const asInstalled = portableLaunch({
      env: { ...extra, [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
      fs, execPath: installedExe, platform: 'win32', appName: APP,
    });
    assert.equal(asInstalled.portable, false, `${label}: an installed app stays installed`);

    const asPortable = portableLaunch({
      env: { ...extra, [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
      fs, execPath: runningExe, platform: 'win32', appName: APP,
    });
    assert.equal(asPortable.portable, true, `${label}: a genuine launch stays portable — ${asPortable.why}`);
  }
});

// The DOWNLOADS folder is not the unpack directory, and the check must never look at it. A person's
// Downloads folder routinely holds other programs' uninstallers; inspecting it there would demote every
// genuine launch that landed in a crowded folder — silently, into the installed profile.
//
// The code is right about this. Nothing pinned it: adding a second `looksInstalled` call against the
// launcher's directory left every other test in this file green, because the fixture only ever puts one
// file in that folder.
test('what the person downloaded sits beside other programs\' uninstallers, and that is not this app', () => {
  const { dir, file } = downloadedLauncher();
  for (const noise of ['unins000.exe', 'Uninstall Notepad++.exe', 'uninstall.exe', 'UNINSTALL.EXE']) {
    fs.writeFileSync(path.join(dir, noise), 'x');
  }
  const runningExe = unpackedUnder(mk('dv-unpack-root-'));
  const r = portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
    fs, execPath: runningExe, platform: 'win32', appName: APP,
  });
  assert.equal(r.portable, true, `a crowded Downloads folder is not an install: ${r.why}`);
});

// A WRONG ANSWER NOBODY CAN SEE is how both isolation defects survived two reviews: the app opened the
// installed profile and nothing was logged, shown, or recorded anywhere. `why` was computed for exactly
// this and nothing read it.
//
// Asked BEHAVIOURALLY where it can be. The earlier version of this test compared the positions of two
// strings in index.js, and that let the log be made permanently unreachable — guarding it on
// `portableRun.portable` is enough, since a demotion is by definition not portable — while the ordering
// it asserted still held. So the reachability question is put to the function that decides, and only the
// wiring is left to source text.
test('a run that was told it was portable and refused produces a reason to report', () => {
  const { notice } = require('../src/main/portable');
  const installedExe = installedApp();
  const { dir, file } = downloadedLauncher();

  // A demotion: the launcher variables were set, and the answer was no.
  const demoted = portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
    fs, execPath: installedExe, platform: 'win32', appName: APP,
  });
  assert.equal(demoted.portable, false);
  assert.equal(typeof notice(demoted), 'string', 'a demotion has something to say');
  assert.match(notice(demoted), /installed app/);

  // An ordinary run — no variable set — says nothing, or every launch would log.
  const ordinary = portableLaunch({ env: {}, fs, execPath: installedExe, platform: 'win32', appName: APP });
  assert.equal(notice(ordinary), null, 'an ordinary run is not remarkable');

  // A successful portable launch says nothing either.
  const good = portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
    fs, execPath: unpackedUnder(mk('dv-unpack-ok-')), platform: 'win32', appName: APP,
  });
  assert.equal(good.portable, true);
  assert.equal(notice(good), null);

  // AND IT IS ACTUALLY SAID. Asked, not read: the previous version of this checked that index.js mentioned
  // the reason somewhere, which passes just as well for a value computed and thrown away — and a report
  // nobody makes is precisely the silence that let two isolation defects through two reviews.
  const { reportDemotion } = require('../src/main/portable');
  const said = [];
  const sink = (line) => said.push(line);

  assert.equal(reportDemotion(demoted, sink), true, 'a demotion is reported');
  assert.equal(said.length, 1, 'exactly once');
  assert.match(said[0], /installed app/, 'and it carries the reason, not a bare "not portable"');

  assert.equal(reportDemotion(ordinary, sink), false, 'an ordinary run says nothing');
  assert.equal(reportDemotion(good, sink), false, 'a successful portable launch says nothing');
  assert.equal(said.length, 1, 'so nothing further was written');

  // A logger that throws must not take the launch down with it.
  assert.equal(reportDemotion(demoted, () => { throw new Error('no console here'); }), true);

  // The shell still has to call it. Source text for the wiring only — everything above is behaviour.
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  assert.match(main.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n'),
    /portable\.reportDemotion\(portableRun/, 'index.js hands the result to the reporter');
});

// And the structural half, because the sweep above can only test the names it thought of. The decision
// path must not MENTION a temp folder. A future edit that reaches for one fails here and has to argue
// with the comment rather than quietly reintroduce round three.
test('the decision path does not read a temp folder, by construction', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'portable.js'), 'utf8');
  const code = src.split('\n')
    .filter((l) => !l.trim().startsWith('//') && !l.trim().startsWith('*') && !l.trim().startsWith('/*'))
    .join('\n');
  // EVERY ONE OF THESE IS CASE-INSENSITIVE, and that is not stylistic. The first version of this test
  // was not, and on Windows `process.env` is: `process.env.temp` and `process.env.TEMP` are the same
  // value. So `env.temp || env.tmp` read the temp folder in production while being `undefined` in every
  // fixture below, all of which spell the keys in upper case — which meant round three could be put back
  // verbatim, in both directions, with the whole suite green. The test written to prevent the regression
  // was the thing that let it through.
  const forbidden = [
    /\btmpdir\b/i, /\btmpDir\b/i,
    /\bprocess\s*\.\s*env\s*\.\s*t(e)?mp\b/i,
    /\benv\s*\.\s*t(e)?mp\b/i,
    /\[\s*['"]t(e)?mp['"]\s*\]/i,
    /['"]USERPROFILE['"]/i,
    /\bos\s*\[/,                       // os['tmp'+'dir']() and friends
  ];
  for (const pattern of forbidden) {
    assert.ok(!pattern.test(code), `the decision must not read ${pattern} — see the note in portable.js`);
  }
  // The caller must not be quietly handing one over either.
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const call = main.slice(main.indexOf('portable.applyDataDir('), main.indexOf('});', main.indexOf('portable.applyDataDir(')));
  assert.ok(call.length > 0, 'the app applies a data dir');
  assert.ok(!/tmpDir/.test(call.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n')),
    'index.js must not pass a temp folder into the decision');
});

// The launch this whole feature is for, with nothing unusual about it, still works. Without this the
// two directions above could both be satisfied by a function that refuses everything.
test('an ordinary portable launch is still portable', () => {
  const env = { TMP: os.tmpdir(), TEMP: os.tmpdir() };
  const runningExe = unpackedUnder(os.tmpdir());
  const { dir, file } = downloadedLauncher();
  const full = { ...env, [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP };
  const r = portableLaunch({ env: full, fs, execPath: runningExe, platform: 'win32', appName: APP });
  assert.equal(r.portable, true, `the ordinary case must work: ${r.why}`);
});

// THE UNINSTALLER PATTERN, IN BOTH DIRECTIONS. It used to be `^unins`, which matched the default name and
// the Inno convention and missed `Un_DockVault.exe` — a shape NSIS builds really use. Widening it is not
// free, and the comment that once said it was has been corrected: a miss lets an installed app be talked
// into relocating its data, and a false match demotes a genuine portable launch into opening the installed
// profile. Both are the severe direction, so it is aimed rather than broadened.
test('it recognises the uninstaller names installers really write', () => {
  const { UNINSTALLER } = require('../src/main/portable');
  for (const name of [
    'Uninstall DockVault.exe',      // electron-builder's default
    'Uninstall.exe',
    'uninstall.exe',
    'UNINSTALL.EXE',
    'unins000.exe',                 // the Inno convention
    'Un_DockVault.exe',             // the shape the old pattern missed entirely
    'un-dockvault.exe',
  ]) {
    assert.ok(UNINSTALLER.test(name), `${name} is an uninstaller`);
  }
});

// The safety of that pattern rests on a fact about the BUILD, not a property of the regex: the only
// executables in a packaged payload are the app and Chromium's crash handler. Pinned here so that if the
// payload ever gains a matching name, this fails — rather than a portable launch silently opening a real
// profile because a payload file looked like an uninstaller.
test('nothing a packaged payload actually contains is read as an uninstaller', () => {
  const { UNINSTALLER } = require('../src/main/portable');
  for (const name of [
    'DockVault.exe',
    'chrome_crashpad_handler.exe',
    'ffmpeg.dll', 'd3dcompiler_47.dll', 'vk_swiftshader.dll', 'vulkan-1.dll', 'libEGL.dll',
    'resources.pak', 'chrome_100_percent.pak', 'icudtl.dat', 'snapshot_blob.bin',
    'v8_context_snapshot.bin', 'LICENSE.electron.txt', 'LICENSES.chromium.html',
    'locales', 'resources',
    // Near misses, to show the pattern is aimed rather than "anything beginning with un".
    'under.exe', 'universe.exe', 'unicode.dat', 'unrelated-tool.exe',
  ]) {
    assert.ok(!UNINSTALLER.test(name), `${name} is part of the app, not an uninstaller`);
  }
});

// THE DEMOTION, AS A PERSON WOULD MEET IT. Someone double-clicked a portable build and got the installed
// app's data instead — no window of its own, no error, nothing on screen. It was reported to console.warn,
// from a windowed program started by a silent stub, which is the same "nothing is attached to read it"
// argument this module already makes about the refusal dialog. A log line there is a line nobody ever sees.
test('a demoted run has something to SAY, not just something to log', () => {
  const { demotionMessage, notice } = require('../src/main/portable');
  const installedExe = installedApp();
  const { dir, file } = downloadedLauncher();
  const env = { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP };

  const demoted = portableLaunch({ env, fs, execPath: installedExe, platform: 'win32', appName: APP });
  assert.equal(demoted.portable, false);
  const say = demotionMessage(demoted);
  assert.ok(say && say.title && say.body, 'a demotion is worth a sentence');
  // It has to say what is being USED, because that is the question behind the surprise.
  assert.match(say.body, /installed/i);
  assert.match(say.title, /installed copy/i);
  // And it must not read as a failure: the run that follows is an ordinary, safe run of the installed app.
  assert.ok(!/error|failed|cannot|refus/i.test(`${say.title} ${say.body}`), `not an error: ${say.title} / ${say.body}`);
  // It never puts an internal reason string in front of a person.
  assert.ok(!say.body.includes(notice(demoted)), 'the log line is not the sentence');
});

test('an ordinary run and a successful portable launch say nothing at all', () => {
  const { demotionMessage } = require('../src/main/portable');
  const installedExe = installedApp();
  const { dir, file } = downloadedLauncher();

  // No launcher variable: this is simply the installed app starting. Announcing that would be noise on
  // every single launch.
  const ordinary = portableLaunch({ env: {}, fs, execPath: installedExe, platform: 'win32', appName: APP });
  assert.equal(demotionMessage(ordinary), null);

  // A portable launch that worked has nothing surprising to report either.
  const good = portableLaunch({
    env: { [PORTABLE_ENV]: dir, [PORTABLE_FILE_ENV]: file, [PORTABLE_APP_ENV]: APP },
    fs, execPath: unpackedUnder(mk('dv-unpack-ok-')), platform: 'win32', appName: APP,
  });
  assert.equal(good.portable, true);
  assert.equal(demotionMessage(good), null);
});

test('the app shows that message once it has something to show it with', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const code = main.split('\n').filter((l) => !l.trim().startsWith('//')).join('\n');
  assert.match(code, /const demotionToShow = portable\.demotionMessage\(portableRun\)/,
    'the message is composed where the decision is made');
  // It cannot be shown at that point — this runs before the app is ready — so it must be shown later.
  assert.match(code, /if \(demotionToShow\)/);
  assert.match(code, /new Notification\(\{ title: demotionToShow\.title, body: demotionToShow\.body \}\)/);
  const decide = code.indexOf('const demotionToShow');
  const show = code.indexOf('new Notification({ title: demotionToShow.title');
  assert.ok(decide < show, 'decided at startup, shown once there is a way to show it');
});

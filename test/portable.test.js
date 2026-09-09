'use strict';

// A portable build runs with nothing installed. It has two ways to go badly wrong, and both are the
// subject here.
//
//  1. SHARING. If it opened the INSTALLED app's data folder it would be running against a real device
//     identity, session and sync state, possibly while the installed app was running against them.
//  2. BEING TOLD. The thing that makes a run "portable" is an environment variable, and the INSTALLED
//     app runs the same code. A bare variable must not be enough to move an installed app's data.
//
// A note on how these are written, because an earlier version of this file got it wrong. The test
// that claimed "there is no way to make it choose the installed data folder" asserted the result with
// the SAME path comparison the implementation used, and varied `installedDir` — which the app fixes —
// rather than the environment, which is the only input anyone else controls. A reviewer showed it
// passing against an implementation that returned the installed folder outright, spelled `\\?\C:\…`.
// So: the cases below vary the ENVIRONMENT, use the PRODUCTION shape of the installed folder, and
// check the answer against what the filesystem says a path is rather than against how it is spelled.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { portableLaunch, chooseDataDir, applyDataDir, insideOrSame, canonical, PORTABLE_ENV, PORTABLE_FILE_ENV, PORTABLE_APP_ENV, DATA_DIR_NAME, besideDirName, fallbackDirName } = require('../src/main/portable');

// Real directories, because the module deliberately asks the filesystem what a path is, and a test
// over invented strings could not tell a working canonicaliser from a broken one.
const tmps = [];
const mk = (prefix) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); tmps.push(d); return d; };
test.after(() => { for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } } });

// A launch that really passes the check. NOTE WHAT THIS USED TO DO, because it is why a whole class
// of case was invisible to this file: it built the launcher directory and the unpack directory as
// SIBLINGS under the temp folder, so nothing here could stand where a real person stands — an .exe
// downloaded INTO the temp folder, or an attacker choosing the directory. Those cases live in
// portable-reachable.test.js now, and this helper takes the launcher directory as an argument so it
// can build them at all.
//
// What makes a launch genuine is that the RUNNING program is not the installed app — established by
// the absence of an uninstaller beside it, plus the launcher's own corroborating variables. It is NOT
// established by where the program is running from. Three versions of this check were anchored on a
// location, and each time the location turned out to be named by an environment variable that the same
// person setting the portable variables could also set.
function genuineLaunch(exeDirOverride) {
  const exeDir = exeDirOverride || mk('dv-exe-');
  const exe = path.join(exeDir, 'DockVault-portable.exe');
  fs.writeFileSync(exe, 'not really an exe');
  const unpack = mk('dv-unpack-');            // <temp>\<id>, as the stub makes it
  return {
    exeDir,
    env: { [PORTABLE_ENV]: exeDir, [PORTABLE_FILE_ENV]: exe, [PORTABLE_APP_ENV]: 'dockvault-desktop' },
    execPath: path.join(unpack, 'DockVault.exe'),
  };
}
// Everything a launch needs beyond the environment, so no call site can forget one and get a
// refusal it then reads as a finding.
const launchArgs = (real) => ({ env: real.env, fs, execPath: real.execPath, platform: 'win32', appName: 'dockvault-desktop' });

// ---------------------------------------------------------------------------------------------
// Being told

test('an ordinary run is left completely alone', () => {
  for (const env of [{}, { [PORTABLE_ENV]: '' }, { [PORTABLE_ENV]: '   ' }, { OTHER: 'x' }, null, undefined]) {
    const r = portableLaunch({ env, fs, execPath: 'C:/app/DockVault.exe', platform: 'win32', appName: 'dockvault-desktop' });
    assert.equal(r.portable, false, JSON.stringify(env));
    assert.equal(r.why, null, 'and it is not even reported as a failure - it simply is not portable');
  }
});

// The finding that mattered most: a bare environment variable must not be able to move an INSTALLED
// app's data. Anything that can set a variable - a shortcut, a shell, a value under HKCU\Environment -
// could otherwise point it at an empty profile (so it forgets who it is and asks to be set up again)
// or at a network share (so a device identity and an encrypted session are written somewhere they
// were never meant to go; Electron accepts a UNC path for that without complaint).
test('being told it is portable is not enough; the claim has to hold up', () => {
  const real = genuineLaunch();
  // The running program is a REAL directory that exists and holds no uninstaller — i.e. it has already
  // got past the check that decides. Previously this was the string 'C:/Program Files/DockVault/...',
  // a path that does not exist on any machine running these tests, so every case below was refused for
  // being unreadable before the check it is named after was ever reached. Five labelled assertions,
  // none of them testing what its label said.
  const runningExe = real.execPath;
  const refusals = [
    ['a bare directory variable', { [PORTABLE_ENV]: real.exeDir }],
    // A share nobody can reach: refused because the executable it names is not there. Running a
    // portable copy FROM a share is legitimate and is not refused here — what must never happen is the
    // data landing on one, and that is the data-directory choice's job, tested with `isRemote`.
    ['a share naming an executable that is not there', { [PORTABLE_ENV]: '\\\\attacker\\share', [PORTABLE_FILE_ENV]: '\\\\attacker\\share\\DockVault.exe', [PORTABLE_APP_ENV]: 'dockvault-desktop' }],
    ['a relative path', { [PORTABLE_ENV]: 'somewhere', [PORTABLE_FILE_ENV]: 'somewhere/DockVault.exe', [PORTABLE_APP_ENV]: 'dockvault-desktop' }],
    ['an executable that does not exist', { [PORTABLE_ENV]: real.exeDir, [PORTABLE_FILE_ENV]: path.join(real.exeDir, 'nope.exe'), [PORTABLE_APP_ENV]: 'dockvault-desktop' }],
    ['an executable that is a directory', { [PORTABLE_ENV]: real.exeDir, [PORTABLE_FILE_ENV]: real.exeDir, [PORTABLE_APP_ENV]: 'dockvault-desktop' }],
    ['a launcher naming a different program', { ...real.env, [PORTABLE_APP_ENV]: 'something-else' }],
  ];
  for (const [name, env] of refusals) {
    const r = portableLaunch({ env, fs, execPath: runningExe, platform: 'win32', appName: 'dockvault-desktop' });
    assert.equal(r.portable, false, name);
    assert.equal(typeof r.why, 'string', `${name}: and it says which check failed`);
  }
  // An executable that exists but lives somewhere other than the directory named.
  const elsewhere = mk('dv-other-');
  const strayExe = path.join(elsewhere, 'DockVault-portable.exe');
  fs.writeFileSync(strayExe, 'x');
  assert.equal(portableLaunch({ ...launchArgs(real), env: { [PORTABLE_ENV]: real.exeDir, [PORTABLE_FILE_ENV]: strayExe, [PORTABLE_APP_ENV]: 'dockvault-desktop' } }).portable, false);
  // And the INSTALLED app itself, handed a complete and truthful-looking set of variables. What gives
  // it away is the uninstaller the installer wrote beside it — a file the packaged payload never
  // contains and no variable can remove. (This comment used to say the giveaway was WHERE it runs from;
  // the code stopped looking at that, twice over, because every location it could be compared against
  // turned out to be named by an environment variable.)
  const installedDir = mk('dv-installed-');
  const installedExe = path.join(installedDir, 'DockVault.exe');
  fs.writeFileSync(installedExe, 'x');
  fs.writeFileSync(path.join(installedDir, 'Uninstall DockVault.exe'), 'x');
  const asInstalled = portableLaunch({ ...launchArgs(real), execPath: installedExe });
  assert.equal(asInstalled.portable, false);
  assert.match(asInstalled.why, /installed app/, 'refused for BEING INSTALLED, not for something earlier');
  // Only the real thing passes.
  assert.equal(portableLaunch({ ...launchArgs(real) }).portable, true);
});

// ---------------------------------------------------------------------------------------------
// Sharing

test('a genuine portable run keeps its data beside the executable it was launched from', () => {
  const real = genuineLaunch();
  const installed = path.join(mk('dv-roaming-'), 'dockvault-desktop');
  const d = chooseDataDir({ exeDir: real.exeDir, installedDir: installed, localAppData: mk('dv-local-'), fs });
  assert.equal(d.where, 'beside-exe');
  assert.equal(d.dir, path.join(real.exeDir, DATA_DIR_NAME));
  assert.equal(d.refused, null);
});

// This replaces the tautology. It varies the ENVIRONMENT, uses the production shape of the installed
// folder, and asks the filesystem - not the spelling - whether the answer landed inside it.
test('no environment can put a portable run inside the installed profile', () => {
  const roaming = mk('dv-roaming-');
  const installed = path.join(roaming, 'dockvault-desktop');   // the real shape: <roaming>\<package name>
  fs.mkdirSync(installed, { recursive: true });
  const nested = path.join(installed, 'sub'); fs.mkdirSync(nested, { recursive: true });

  const exeDirs = [
    ['the exe sits IN the installed profile', installed],
    ['the exe sits in a subfolder of it', nested],
    ['spelled with a trailing separator', installed + path.sep],
    ['spelled through a dot segment', path.join(installed, '.')],
    ['spelled through a parent segment', path.join(installed, 'x', '..')],
    ['spelled in the long-path form', `\\\\?\\${path.resolve(installed)}`],
    ['spelled in upper case', installed.toUpperCase()],
  ];
  for (const [name, exeDir] of exeDirs) {
    const d = chooseDataDir({ exeDir, installedDir: installed, localAppData: mk('dv-local-'), fs });
    // The real question, asked of the filesystem rather than of the string.
    if (d.dir !== null) assert.equal(insideOrSame(d.dir, installed, fs), false, `${name}: chose ${d.dir}`);
    assert.notEqual(d.where, 'beside-exe', `${name}: must not settle beside an exe inside the profile`);
  }
  // ...and it must not swallow the installed folder from the other direction either.
  const parent = path.dirname(installed);
  const fromParent = chooseDataDir({ exeDir: parent, installedDir: path.join(parent, DATA_DIR_NAME), localAppData: mk('dv-local-'), fs });
  if (fromParent.dir !== null) assert.notEqual(fromParent.where, 'beside-exe');
});

test('one directory, many spellings, and the module sees through them', () => {
  const real = mk('dv-canon-');
  // 8.3 short names are not a curiosity here: this machine's own temp path uses one.
  assert.equal(insideOrSame(real, real, fs), true);
  assert.equal(insideOrSame(path.join(real, 'a', 'b'), real, fs), true);
  assert.equal(insideOrSame(real, path.join(real, 'a'), fs), false);
  // A sibling whose name merely STARTS with the other's must not read as inside it.
  const sib = `${real}-other`;
  fs.mkdirSync(sib, { recursive: true }); tmps.push(sib);
  assert.equal(insideOrSame(sib, real, fs), false, 'prefix is not containment');
  // canonical() survives a path that does not exist yet, which is the normal case for a data folder.
  assert.equal(typeof canonical(path.join(real, 'not', 'made', 'yet'), fs), 'string');
});

test('when it cannot write beside the executable it goes somewhere else of its own', () => {
  const real = genuineLaunch();
  const installed = path.join(mk('dv-roaming-'), 'dockvault-desktop');
  const local = mk('dv-local-');
  const beside = path.join(real.exeDir, besideDirName(real.env[PORTABLE_FILE_ENV]));
  const d = chooseDataDir({ exeDir: real.exeDir, exeFile: real.env[PORTABLE_FILE_ENV], installedDir: installed, localAppData: local, fs, canWrite: (p) => p !== beside });
  assert.equal(d.where, 'fallback');
  // Per executable, not one folder for every copy. See portable-reachable.test.js for why that
  // difference is the difference between sharing settings and a second copy never opening at all.
  assert.equal(d.dir, path.join(local, fallbackDirName(real.env[PORTABLE_FILE_ENV], fs)));
  assert.equal(insideOrSame(d.dir, installed, fs), false);
});

test('with nowhere of its own to write, it refuses rather than sharing', () => {
  const real = genuineLaunch();
  const installed = path.join(mk('dv-roaming-'), 'dockvault-desktop');
  const none = chooseDataDir({ exeDir: real.exeDir, installedDir: installed, localAppData: mk('dv-local-'), fs, canWrite: () => false });
  assert.equal(none.dir, null, 'no folder is better than the wrong folder');
  assert.match(none.refused, /will not share/);
  // And with no installed folder known at all it refuses too, rather than guessing it is safe.
  assert.equal(chooseDataDir({ exeDir: real.exeDir, installedDir: '', localAppData: mk('dv-local-'), fs }).dir, null);
});

test('applying it sets the path, makes the folder, and reports a refusal instead of throwing', () => {
  const real = genuineLaunch();
  const roaming = mk('dv-roaming-');
  let set = null;
  const app = { setPath: (k, v) => { assert.equal(k, 'userData'); set = v; }, getPath: () => { throw new Error('must not be asked'); } };
  const r = applyDataDir(app, { env: real.env, fs, localAppData: mk('dv-local-'), appName: 'dockvault-desktop', roamingDir: roaming, platform: 'win32', appName: 'dockvault-desktop', execPath: real.execPath });
  assert.equal(r.applied, true);
  assert.equal(set, path.join(real.exeDir, besideDirName(real.env[PORTABLE_FILE_ENV])));
  assert.ok(fs.existsSync(set));
  // An ordinary run has nothing done to it at all - including not being asked for its data path,
  // because asking CREATES the folder and a portable build should leave nothing behind. The stub's
  // getPath throws, so any attempt to ask would fail this test loudly.
  let touched = false;
  const ordinary = applyDataDir({ setPath: () => { touched = true; }, getPath: () => { throw new Error('must not be asked'); } },
    { env: {}, fs, localAppData: 'C:\\local', appName: 'dockvault-desktop', roamingDir: roaming });
  assert.equal(touched, false);
  assert.equal(ordinary.portable, false);
  // A setPath that throws is reported, not raised, so the caller can refuse to start.
  const bad = applyDataDir({ setPath: () => { throw new Error('no'); }, getPath: () => '' },
    { env: real.env, fs, localAppData: mk('dv-local-'), appName: 'dockvault-desktop', roamingDir: roaming, platform: 'win32', appName: 'dockvault-desktop', execPath: real.execPath });
  assert.equal(bad.applied, false);
  assert.equal(bad.portable, true);
});

// ---------------------------------------------------------------------------------------------
// Everything outside the data folder

// The data folder was only half of "leaves nothing behind". Start-at-login is keyed on the
// application id - the same value name for every copy of DockVault - so a portable run would
// overwrite an INSTALLED app's entry and point it at its own executable, which lives in a temporary
// folder the launcher deletes when the run ends. The installed app then silently stops starting at
// login, aimed at a path that no longer exists. On a machine with no install the entry is left
// behind for good, because the only thing that removes it is an uninstaller that will never run.
test('a portable run does not register itself to start at login, or claim to be installed', () => {
  const { decideOnLaunch } = require('../src/main/login-item');
  for (const storedChoice of [null, true, false]) {
    assert.deepEqual(decideOnLaunch({ storedChoice, isPackaged: true, isPortable: true }),
      { register: false, notify: false, store: null }, `storedChoice=${storedChoice}`);
  }
  // An INSTALLED first run still does register, or this would have broken what it guards.
  assert.deepEqual(decideOnLaunch({ storedChoice: null, isPackaged: true }), { register: true, notify: true, store: true });
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  assert.match(main, /decideOnLaunch\(\{[^}]*isPortable: portableRun\.portable/);
});

// ---------------------------------------------------------------------------------------------
// Wiring, and the build

test('the app points itself at that folder before anything can read the old one', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const apply = main.indexOf('portable.applyDataDir(');
  const lock = main.indexOf('requestSingleInstanceLock');
  assert.ok(apply > 0 && lock > 0);
  assert.ok(apply < lock, 'applied BEFORE the lock, which is keyed on the folder being chosen');
  // It works the installed path out rather than asking Electron for it, which would create it.
  // Asked of Electron, not of the environment: %APPDATA% is not what Electron uses.
  assert.match(main, /roamingDir: \(\(\) => \{ try \{ return app\.getPath\('appData'\)/);
  assert.match(main, /appName: \(\(\) => \{ try \{ return app\.getName\(\)/);
  // A portable run that could not be isolated does not start, and says so where a person can see it.
  const refusal = main.slice(main.indexOf('portableRun.portable && !portableRun.applied'));
  assert.ok(refusal.slice(0, refusal.indexOf('app.exit(1)')).includes('dialog.showErrorBox'),
    'a console line is invisible from a windowed program launched by a silent stub');
});

test('the build produces a portable artifact, under a name that cannot collide with the installer', () => {
  const config = require(path.join(__dirname, '..', 'electron-builder.js'));
  // The ORDER is load-bearing, not cosmetic: both targets pack the same directory and the first one
  // there decides, which is the only reason the installer's refusal of the elevate helper holds for
  // both. electron-builder's schema rejects packElevateHelper as a portable option, so it cannot be
  // said twice.
  assert.deepEqual(config.win.target.map((t) => t.target), ['nsis', 'portable']);
  assert.equal(config.nsis.packElevateHelper, false);
  assert.equal(config.portable.packElevateHelper, undefined, 'the schema forbids it here');
  // Both targets emit a .exe; without its own name the second written would overwrite the first.
  assert.match(config.portable.artifactName, /portable/);
  assert.notEqual(config.portable.artifactName, config.win.artifactName);
  // A pinned unpack directory would be shared by every build, and the launcher clears that directory
  // before extracting into it - so running one portable build while another was open would delete the
  // files the running one is executing from.
  assert.equal(config.portable.unpackDirName, undefined);
});

test('the workflow uploads the portable build, and refuses a Windows leg missing either half', () => {
  const yml = fs.readFileSync(path.join(__dirname, '..', '.github', 'workflows', 'build-installers.yml'), 'utf8');
  assert.match(yml, /^\s*dist\/\*\.exe\s*$/m);
  const check = yml.indexOf('Check both Windows artifacts exist');
  assert.ok(check > 0 && check < yml.indexOf('upload-artifact'), 'checked before uploading');
  assert.match(yml, /-name '\*-portable\.exe'/);
  // The header has to describe what the leg actually produces, or the next person reads it and is wrong.
  assert.match(yml, /portable/i);
});

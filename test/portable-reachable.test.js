'use strict';

// The three cases the gate found, each written so it FAILS on the code as it stood.
//
// They are in their own file because they are not more coverage of what portable.test.js already
// covers — they are the cases that file could not see, and the reason it could not see them is worth
// keeping visible. Its helper always built the launcher directory and the unpack directory as
// SIBLINGS under the temp folder, so no test in it could ever stand where a real person stands: an
// .exe downloaded INTO the temp folder, or an attacker choosing the directory. A helper that can only
// construct the happy shape is a test file that can only confirm the happy shape.
//
// What was wrong underneath: the check asked "is the running program somewhere other than the
// launcher's directory?" — a subtractive question that is free to satisfy for any directory an
// attacker picks, and false for a genuine launch whose directory happens to contain the unpack
// folder. Both failures are the same line read in opposite directions.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { portableLaunch, PORTABLE_ENV, PORTABLE_FILE_ENV, PORTABLE_APP_ENV } = require('../src/main/portable');
const { createLoginItem } = require('../src/main/login-item');

const tmps = [];
const mk = (prefix) => { const d = fs.mkdtempSync(path.join(os.tmpdir(), prefix)); tmps.push(d); return d; };
test.after(() => { for (const d of tmps) { try { fs.rmSync(d, { recursive: true, force: true }); } catch { /* ignore */ } } });

// Where the portable stub really unpacks to: a direct child of the temp folder. The running program
// is that folder's DockVault.exe. Nothing else about a launch is under anyone's control but this.
function unpackedApp() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-unpack-'));
  tmps.push(dir);
  const exe = path.join(dir, 'DockVault.exe');
  fs.writeFileSync(exe, 'x');
  return exe;
}

// BLOCKER 1. Everything the old check asked for is arrangeable by whoever set the variables: a
// directory they own, containing any file at all. The one remaining condition — that the running
// program is not in that directory — is free, because no attacker would choose the directory the
// installed app runs from. So an INSTALLED app could be told it was portable and pointed at a folder
// of someone else's choosing, which is where its device identity and encrypted session would then go.
test('an installed app cannot be talked into being portable by whoever set the variables', () => {
  const attackerDir = mk('dv-attacker-');
  const bait = path.join(attackerDir, 'anything.txt');
  fs.writeFileSync(bait, 'any file at all');
  // A REAL installed directory: one that exists and holds the uninstaller the installer writes beside the
  // program. This used to be a fabricated 'C:\Users\someone\...' string, and because that path does not exist
  // on any machine running these tests, every case below was refused for being UNREADABLE - the check that
  // actually decides was never reached. Measured: with the discriminator deleted outright, this whole file
  // was 6 pass / 0 fail.
  const installedDir = mk('dv-installed-');
  const installedExe = path.join(installedDir, 'DockVault.exe');
  fs.writeFileSync(installedExe, 'x');
  fs.writeFileSync(path.join(installedDir, 'Uninstall DockVault.exe'), 'x');

  const forged = [
    ['a plain file as the named executable', { [PORTABLE_ENV]: attackerDir, [PORTABLE_FILE_ENV]: bait }],
    ['a file named like the real one', { [PORTABLE_ENV]: attackerDir, [PORTABLE_FILE_ENV]: (() => { const f = path.join(attackerDir, 'DockVault-0.1.0-win-x64-portable.exe'); fs.writeFileSync(f, 'x'); return f; })() }],
    ['every variable the launcher sets', { [PORTABLE_ENV]: attackerDir, [PORTABLE_FILE_ENV]: path.join(attackerDir, 'DockVault-0.1.0-win-x64-portable.exe'), [PORTABLE_APP_ENV]: 'dockvault-desktop' }],
  ];
  for (const [name, env] of forged) {
    const r = portableLaunch({ env, fs, execPath: installedExe, platform: 'win32', appName: 'dockvault-desktop' });
    assert.equal(r.portable, false, `${name}: an installed app must stay installed`);
    assert.match(r.why, /installed app/, `${name}: refused for BEING INSTALLED, not an earlier check it never got past`);
  }
});

// BLOCKER 2. The launcher unpacks into a child of the temp folder, so a launcher directory that
// CONTAINS the temp folder made the old check refuse a real portable launch. The temp folder is not
// an exotic place to run something from — it is where a browser or a mail client puts what you just
// downloaded and offers to open. A refusal there was silent (the app only speaks up when it knows it
// is portable and could not isolate itself), so the portable build simply opened the installed app's
// identity, session and database instead.
test('a real portable launch is not demoted because of where it was downloaded to', () => {
  const exe = unpackedApp();                    // <temp>\<id>\DockVault.exe, as the stub makes it
  const ancestors = [os.tmpdir(), path.dirname(os.tmpdir()), path.parse(os.tmpdir()).root];
  let checked = 0;
  for (const exeDir of ancestors) {
    const launcher = path.join(exeDir, 'DockVault-0.1.0-win-x64-portable.exe');
    try { fs.writeFileSync(launcher, 'x'); } catch { continue; }   // skip anywhere unwritable
    tmps.push(launcher);
    checked += 1;
    const r = portableLaunch({
      env: { [PORTABLE_ENV]: exeDir, [PORTABLE_FILE_ENV]: launcher, [PORTABLE_APP_ENV]: 'dockvault-desktop' },
      fs, execPath: exe, platform: 'win32', appName: 'dockvault-desktop',
    });
    assert.equal(r.portable, true, `launched from ${exeDir}: this is a genuine portable run`);
  }
  assert.ok(checked >= 2, 'at least the temp folder and its parent were reachable to test');
});

// BLOCKER 3. The guard went on the LAUNCH path — whether the app registers itself unasked — and the
// tray checkbox is a different path entirely. A person with DockVault installed runs the portable
// build, ticks "Start at login", and the installed app's entry is overwritten to point inside a
// folder the launcher deletes when the run ends: it stops starting at login, and its own switch then
// reads "off". The registry value name is the application id, the same for every copy, which is what
// makes one copy able to speak for another.
test('the start-at-login switch writes nothing in a portable run', () => {
  const calls = [];
  const app = { setLoginItemSettings: (o) => calls.push(o), getLoginItemSettings: () => ({ openAtLogin: false, executableWillLaunchAtLogin: false }) };
  const item = createLoginItem({
    app, platform: 'win32', fs, homeDir: mk('dv-home-'), env: {},
    execPath: path.join(os.tmpdir(), 'dv-unpack-x', 'DockVault.exe'), isPortable: true,
  });
  item.setEnabled(true);
  item.setEnabled(false);
  assert.deepEqual(calls, [], 'a portable run never touches the login item, on or off');
  assert.equal(item.isEnabled(), false, 'and it reports itself as not registered');
  // AND IT SAYS SO BEFORE BEING ASKED TO DO ANYTHING. Refusing setEnabled is not enough on its own: the
  // tray's toggle also records the person's choice in the app's data folder, and that write went through
  // regardless — leaving a login-item.json claiming a start-at-login the app had deliberately refused to
  // arrange. Callers ask this first, so the whole action is skipped rather than half-performed.
  assert.equal(item.canChange(), false, 'a portable run reports the switch as not its to change');
  // The same object without the portable flag still works, or the guard would have broken the feature
  // it guards rather than protecting it.
  const normal = createLoginItem({
    app, platform: 'win32', fs, homeDir: mk('dv-home-'), env: {},
    execPath: path.join('C:', 'Program Files', 'DockVault', 'DockVault.exe'),
  });
  normal.setEnabled(true);
  assert.equal(calls.length, 1, 'an installed app still registers');
  assert.equal(calls[0].openAtLogin, true);
  assert.equal(normal.canChange(), true, 'and an installed app may still change it');
});

// A guard nothing reaches is not a guard. The app builds its login item once and hands it to every
// caller, so the flag has to be set there or the tray switch never sees it.
test('the app actually hands the portable flag to the thing that writes the registry', () => {
  const main = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const start = main.indexOf('loginItemMod.createLoginItem({');
  assert.notEqual(start, -1, 'the login item is built in main');
  const body = main.slice(start, main.indexOf('})', start));
  assert.match(body, /isPortable: portableRun\.portable/, 'and is told whether this run is portable');
  // The tray switch goes through that same object, so there is one place to get this right.
  assert.match(main, /loginItem\(\)\.setEnabled\(/);

  // AND THE TOGGLE ASKS FIRST. Refusing setEnabled is not the whole action: the toggle also writes the
  // person's choice to disk, and that write is a separate statement the refusal never reached — so a
  // portable click left a stored start-at-login preference behind that nothing would ever honour.
  // Source text, because this wiring cannot be driven from here; the DECISION it consults is behaviour,
  // and is tested above.
  const toggle = main.slice(main.indexOf('function toggleLoginItem('), main.indexOf('\n}', main.indexOf('function toggleLoginItem(')));
  assert.ok(toggle.length > 0, 'the tray toggle exists');
  assert.match(toggle, /canChange\(\)/, 'the toggle asks whether this run may change the setting');
  // It has to ask BEFORE it records anything, or the guard is decoration.
  assert.ok(toggle.indexOf('canChange()') < toggle.indexOf('write('), 'and asks before it writes the choice');
});

// The fallback folder was one fixed name for every copy. That reads like a settings-sharing wrinkle
// and is worse than that: Electron keys its single-instance lock on the data folder, so the SECOND
// portable copy to fall back would find the lock held, hand over to the first, and never open at all.
// The person would be looking at build A believing it was build B — which is the exact confusion a
// portable build exists to remove, arriving by the back door.
test('two portable copies that fall back do not end up in the same folder', () => {
  const { fallbackDirName, chooseDataDir, FALLBACK_DIR_NAME } = require('../src/main/portable');
  const a = path.join(mk('dv-dl-'), 'DockVault-0.1.0-portable.exe');
  const b = path.join(mk('dv-dl-'), 'DockVault-0.2.0-portable.exe');
  fs.writeFileSync(a, 'x'); fs.writeFileSync(b, 'x');
  assert.notEqual(fallbackDirName(a, fs), fallbackDirName(b, fs), 'two copies, two folders');
  // ...and the same copy keeps the same folder across runs, or it would forget itself every launch.
  assert.equal(fallbackDirName(a, fs), fallbackDirName(a, fs));
  // The name still says what it is, so someone finding it can tell where it came from.
  assert.ok(fallbackDirName(a, fs).startsWith(FALLBACK_DIR_NAME));

  // And the choice actually uses it, rather than the bare shared name.
  const { besideDirName } = require('../src/main/portable');
  const installed = path.join(mk('dv-roaming-'), 'dockvault-desktop');
  const local = mk('dv-local-');
  const beside = path.join(path.dirname(a), besideDirName(a));
  const d = chooseDataDir({ exeDir: path.dirname(a), exeFile: a, installedDir: installed, localAppData: local, fs, canWrite: (p) => p !== beside });
  assert.equal(d.where, 'fallback');
  assert.equal(d.dir, path.join(local, fallbackDirName(a, fs)));
  assert.notEqual(d.dir, path.join(local, FALLBACK_DIR_NAME), 'not the one shared name');
});

// THE SAME ARGUMENT, APPLIED WHERE IT ACTUALLY BITES. Everything above is about the FALLBACK, which only
// happens when the folder beside the .exe cannot be written. The ordinary case — two builds downloaded into
// one Downloads folder, which is how anyone compares two builds — went to a fixed `DockVault-data` for both.
// That is not a shared-settings wrinkle: Electron keys its single-instance lock on the data folder, so the
// second build finds the lock held, hands over to the first, and never opens a window of its own. The person
// is then looking at build A believing it is build B.
//
// The test above could not see it, because it only ever exercised the path that is reached when `beside` is
// unwritable — and it built its two executables in DIFFERENT directories, the one arrangement where the bug
// cannot appear.
test('two portable builds in the SAME folder do not get the same data folder', () => {
  const { chooseDataDir, besideDirName } = require('../src/main/portable');
  const downloads = mk('dv-dl-same-');
  const a = path.join(downloads, 'DockVault-0.1.0-portable.exe');
  const b = path.join(downloads, 'DockVault-0.2.0-portable.exe');
  fs.writeFileSync(a, 'x'); fs.writeFileSync(b, 'x');

  const installed = path.join(mk('dv-roaming-'), 'dockvault-desktop');
  const local = mk('dv-local-');
  const pick = (exe) => chooseDataDir({ exeDir: downloads, exeFile: exe, installedDir: installed, localAppData: local, fs });

  const da = pick(a); const db = pick(b);
  assert.equal(da.where, 'beside-exe');
  assert.equal(db.where, 'beside-exe');
  assert.notEqual(da.dir, db.dir, 'two builds in one folder, two data folders — or the second never opens');
  // Each is named after the .exe that was launched, so the pairing is obvious in the folder listing.
  assert.equal(da.dir, path.join(downloads, besideDirName(a)));
  assert.equal(db.dir, path.join(downloads, besideDirName(b)));
  // And the same build keeps the same folder across runs, or it would forget itself every launch.
  assert.equal(pick(a).dir, da.dir);
});

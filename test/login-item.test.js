'use strict';

// Start-at-login is read from the platform's real registration every time and written under the one
// shared name; on Linux it is an XDG autostart entry that points at the AppImage when running from one.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { createLoginItem } = require('../src/main/login-item');
const { LOGIN_ITEM_NAME } = require('../src/main/app-identity');

function fakeApp({ windows = true } = {}) {
  const calls = [];
  let registered = null; // { openAtLogin, name, path }
  let approved = true; // the Windows "startup apps" switch (Task Manager)
  return {
    calls,
    getLoginItemSettings(opts) {
      calls.push(['get', opts]);
      // Electron finds the entry under the app id and compares the (quoted) command line it wrote.
      const openAtLogin = !!(registered && registered.openAtLogin && registered.name === LOGIN_ITEM_NAME && registered.path === opts.path);
      // Windows also lists the matching launch items with their "startup apps" state; macOS reports only openAtLogin.
      if (!windows) return { openAtLogin };
      const launchItems = openAtLogin ? [{ name: LOGIN_ITEM_NAME, path: opts.path, args: [], scope: 'user', enabled: approved }] : [];
      return { openAtLogin, executableWillLaunchAtLogin: launchItems.some((i) => i.enabled), launchItems };
    },
    setLoginItemSettings(opts) { calls.push(['set', opts]); registered = opts; if (opts.enabled === true) approved = true; },
    // Something else (an uninstaller, the person, another tool) changes the registration behind the app's back.
    _external(v) { registered = v; },
    _taskManagerDisable() { approved = false; },
  };
}

function fakeFs() {
  const files = new Map();
  const dirs = new Set();
  return {
    files, dirs,
    existsSync: (p) => files.has(p),
    readFileSync: (p) => { if (!files.has(p)) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; } return files.get(p).data; },
    mkdirSync: (p) => { dirs.add(p); },
    writeFileSync: (p, data, opts) => { files.set(p, { data, opts }); },
    unlinkSync: (p) => { if (!files.delete(p)) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; } },
  };
}

test('Windows and macOS: the state is whatever the platform reports right now, never a remembered value', () => {
  const app = fakeApp();
  const item = createLoginItem({ app, platform: 'win32', fs: fakeFs(), homeDir: 'H', execPath: 'C:/P/DockVault.exe' });
  assert.equal(item.isEnabled(), false);
  assert.equal(item.setEnabled(true), true);
  assert.deepEqual(app.calls.filter((c) => c[0] === 'set').pop()[1], { openAtLogin: true, enabled: true, name: LOGIN_ITEM_NAME, path: '"C:/P/DockVault.exe"' });
  assert.equal(item.isEnabled(), true);
  app._external(null); // removed behind the app's back
  assert.equal(item.isEnabled(), false, 'the checkbox must follow the real registration');
  assert.equal(item.setEnabled(false), false);
  assert.equal(app.calls.filter((c) => c[0] === 'set').pop()[1].openAtLogin, false);
});

test('Windows: an item switched off under "startup apps" reads as off, and turning it on re-enables it', () => {
  const app = fakeApp();
  const item = createLoginItem({ app, platform: 'win32', fs: fakeFs(), homeDir: 'H', execPath: 'C:/P/DockVault.exe' });
  item.setEnabled(true);
  assert.equal(item.isEnabled(), true);
  app._taskManagerDisable(); // registration still present, but Windows will not launch it
  assert.equal(item.isEnabled(), false, 'says what will actually happen, not what is registered');
  assert.equal(item.setEnabled(true), true, 'the toggle flips the startup-apps switch back on');
});

test('macOS: with no launch flag reported, the registration itself is the state', () => {
  const app = fakeApp({ windows: false });
  const item = createLoginItem({ app, platform: 'darwin', fs: fakeFs(), homeDir: 'H', execPath: '/A/DockVault' });
  assert.equal(item.isEnabled(), false);
  assert.equal(item.setEnabled(true), true);
  assert.equal(item.setEnabled(false), false);
});

test('Windows and macOS: a platform error reads as "not enabled" rather than throwing into the tray', () => {
  const app = { getLoginItemSettings() { throw new Error('no'); }, setLoginItemSettings() {} };
  const item = createLoginItem({ app, platform: 'darwin', fs: fakeFs(), homeDir: 'H', execPath: '/A/DockVault' });
  assert.equal(item.isEnabled(), false);
});

test('Linux: an XDG autostart entry under ~/.config/autostart is the registration', () => {
  const fs = fakeFs();
  const item = createLoginItem({ app: fakeApp(), platform: 'linux', fs, homeDir: '/home/u', execPath: '/opt/DockVault/dockvault' });
  assert.equal(item.autostartFile, path.join('/home/u', '.config', 'autostart', 'dockvault.desktop'));
  assert.equal(item.isEnabled(), false);
  assert.equal(item.setEnabled(true), true);
  assert.ok(fs.dirs.has(path.join('/home/u', '.config', 'autostart')));
  const entry = fs.files.get(item.autostartFile).data;
  assert.match(entry, /^\[Desktop Entry\]\n/);
  assert.match(entry, /\nExec="\/opt\/DockVault\/dockvault"\n/);
  assert.match(entry, /\nName=DockVault\n/);
  assert.match(entry, /\nType=Application\n/);
  assert.equal(item.setEnabled(false), false);
  assert.equal(fs.files.size, 0);
  assert.equal(item.setEnabled(false), false, 'removing an absent entry is not an error');
});

test('Linux: when running from an AppImage the entry launches the AppImage, not the mounted executable, and names no icon', () => {
  const fs = fakeFs();
  const env = { APPIMAGE: '/home/u/Apps/DockVault-0.1.0-linux-x86_64.AppImage' };
  const item = createLoginItem({ app: fakeApp(), platform: 'linux', fs, homeDir: '/home/u', env, execPath: '/tmp/.mount_DockVaXYZ/dockvault' });
  item.setEnabled(true);
  const entry = fs.files.get(item.autostartFile).data;
  assert.match(entry, /\nExec="\/home\/u\/Apps\/DockVault-0.1.0-linux-x86_64.AppImage"\n/);
  assert.doesNotMatch(entry, /^Icon=/m, 'an AppImage has no installed icon-theme entry to point at');
  assert.doesNotMatch(entry, /sync/i, 'the entry promises nothing about syncing');
  // A package install does have the themed icon.
  const fs2 = fakeFs();
  const pkg = createLoginItem({ app: fakeApp(), platform: 'linux', fs: fs2, homeDir: '/home/u', env: {}, execPath: '/opt/DockVault/dockvault' });
  pkg.setEnabled(true);
  assert.match(fs2.files.get(pkg.autostartFile).data, /\nIcon=dockvault\n/);
});

test('Linux: an entry the desktop disabled in place reads as off, even though the file is there', () => {
  const fs = fakeFs();
  const item = createLoginItem({ app: fakeApp(), platform: 'linux', fs, homeDir: '/home/u', execPath: '/opt/DockVault/dockvault' });
  item.setEnabled(true);
  assert.equal(item.isEnabled(), true);
  const written = fs.files.get(item.autostartFile).data;
  fs.files.set(item.autostartFile, { data: written + 'Hidden=true\n' });
  fs.readFileSync = (p) => fs.files.get(p).data;
  assert.equal(item.isEnabled(), false, 'Hidden=true (KDE) is off');
  fs.files.set(item.autostartFile, { data: written.replace('X-GNOME-Autostart-enabled=true', 'X-GNOME-Autostart-enabled=false') });
  assert.equal(item.isEnabled(), false, 'X-GNOME-Autostart-enabled=false (GNOME) is off');
  assert.equal(item.setEnabled(true), true, 'switching on rewrites a clean entry');
});

test('a platform that refuses to register without throwing is reported as off, so the notice cannot overclaim', () => {
  const app = { getLoginItemSettings() { return { openAtLogin: false, launchItems: [] }; }, setLoginItemSettings() { /* silently refused */ } };
  const item = createLoginItem({ app, platform: 'win32', fs: fakeFs(), homeDir: 'H', execPath: 'C:/P/DockVault.exe' });
  assert.equal(item.setEnabled(true), false, 'the read-back, not the intent');
});

const { createLoginChoiceStore, decideOnLaunch } = require('../src/main/login-item');

function choiceFs() {
  const files = new Map();
  return {
    files,
    readFileSync: (p) => { if (!files.has(p)) { const e = new Error('ENOENT'); e.code = 'ENOENT'; throw e; } return files.get(p); },
    writeFileSync: (p, data) => { files.set(p, data); },
    renameSync: (a, b) => { files.set(b, files.get(a)); files.delete(a); },
    mkdirSync: () => {},
  };
}

test('an installed app registers unasked only when no choice was ever stored', () => {
  assert.deepEqual(decideOnLaunch({ storedChoice: null, isPackaged: true }), { register: true, notify: true, store: true });
  assert.deepEqual(decideOnLaunch({ storedChoice: false, isPackaged: true }), { register: false, notify: false, store: null });
  // A stored "on" with the item removed by hand is NOT quietly put back either.
  assert.deepEqual(decideOnLaunch({ storedChoice: true, isPackaged: true }), { register: false, notify: false, store: null });
  // An unreadable choice is not an absent one: nothing is written unasked.
  assert.deepEqual(decideOnLaunch({ storedChoice: 'unreadable', isPackaged: true }), { register: false, notify: false, store: null });
  assert.deepEqual(decideOnLaunch({ storedChoice: undefined, isPackaged: true }), { register: false, notify: false, store: null });
  // A development run never registers anything.
  assert.deepEqual(decideOnLaunch({ storedChoice: null, isPackaged: false }), { register: false, notify: false, store: null });
});

test('the stored choice survives in the data folder and unreadable means "no choice yet"', () => {
  const fs = choiceFs();
  const store = createLoginChoiceStore({ fs, dir: path.join('D', 'dockvault-desktop') });
  assert.equal(store.read(), null);
  store.write(true);
  assert.equal(store.read(), true);
  assert.equal(fs.files.size, 1, 'written atomically through a temp file that is renamed away');
  store.write(false);
  assert.equal(store.read(), false);
  // Unreadable is not absent: a truncated or malformed file must never read as "no choice yet".
  fs.files.set(store.file, '{"startAtLogin": fa');
  assert.equal(store.read(), 'unreadable');
  assert.equal(decideOnLaunch({ storedChoice: store.read(), isPackaged: true }).register, false, 'a truncated file never registers unasked');
  fs.files.set(store.file, JSON.stringify({ startAtLogin: 'yes' }));
  assert.equal(store.read(), 'unreadable', 'only a real boolean counts as a choice');
  fs.files.delete(store.file);
  assert.equal(store.read(), null, 'only a missing file is "no choice yet"');
});

test('the scenario: turned off, login item deleted by hand, relaunch → still off, no notification', () => {
  const app = fakeApp();
  const fs = choiceFs();
  const item = createLoginItem({ app, platform: 'win32', fs: fakeFs(), homeDir: 'H', execPath: 'C:/P/DockVault.exe' });
  const store = createLoginChoiceStore({ fs, dir: 'D' });
  // First launch: no choice → register + notify.
  let d = decideOnLaunch({ storedChoice: store.read(), isPackaged: true });
  assert.equal(d.register, true);
  item.setEnabled(true); store.write(true);
  // The person turns it off from the tray.
  item.setEnabled(false); store.write(false);
  app._external(null);
  // Relaunch.
  d = decideOnLaunch({ storedChoice: store.read(), isPackaged: true });
  assert.deepEqual(d, { register: false, notify: false, store: null });
  assert.equal(item.isEnabled(), false);
});

test('the login item is registered under the app id, which is both what Electron reads back and what the uninstaller removes', () => {
  const app = fakeApp();
  createLoginItem({ app, platform: 'win32', fs: fakeFs(), homeDir: 'H', execPath: 'C:/P/DockVault.exe' }).setEnabled(true);
  const { APP_ID } = require('../src/main/app-identity');
  assert.equal(app.calls.find((c) => c[0] === 'set')[1].name, APP_ID);
  assert.equal(LOGIN_ITEM_NAME, APP_ID);
});

test('a path with spaces is handed to the platform quoted, on read and on write', () => {
  const app = fakeApp();
  const item = createLoginItem({ app, platform: 'win32', fs: fakeFs(), homeDir: 'H', execPath: 'C:/Users/A B/AppData/Local/Programs/DockVault/DockVault.exe' });
  item.setEnabled(true);
  assert.equal(app.calls.find((c) => c[0] === 'set')[1].path, '"C:/Users/A B/AppData/Local/Programs/DockVault/DockVault.exe"');
  assert.equal(item.isEnabled(), true);
  assert.equal(app.calls.filter((c) => c[0] === 'get').pop()[1].path, '"C:/Users/A B/AppData/Local/Programs/DockVault/DockVault.exe"');
});

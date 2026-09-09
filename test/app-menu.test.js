'use strict';

// THE APPLICATION MENU.
//
// Electron's default menubar is built for a document editor, and DockVault is a tray app whose main window
// hosts the vault's own web interface. Two things follow, and the tests below are mostly about not getting
// either of them wrong in the obvious way:
//
//   - Developer tools were offered, by default, on the one window holding a signed-in session. In a shipped
//     build that is a door nobody asked for. In a development run it is exactly what a developer needs.
//   - The tempting fix is to remove the menu entirely. That silently breaks Ctrl+C / Ctrl+V / Ctrl+A in
//     every text input, because on Windows and Linux those accelerators come from the Edit ROLES. The
//     server-address field would stop accepting a pasted address, which is the first thing anyone does
//     with it.

const test = require('node:test');
const assert = require('node:assert/strict');

const { buildMenuTemplate, labelsOf, rolesOf } = require('../src/main/app-menu');

const actions = () => {
  const called = [];
  return {
    called,
    actions: {
      status: () => called.push('status'),
      computers: () => called.push('computers'),
      troubleshoot: () => called.push('troubleshoot'),
      about: () => called.push('about'),
      quit: () => called.push('quit'),
    },
  };
};
const build = (over = {}) => buildMenuTemplate({ isPackaged: true, platform: 'win32', actions: actions().actions, ...over });

test('the clipboard roles survive, on every platform — they are what bind the shortcuts', () => {
  for (const platform of ['win32', 'darwin', 'linux']) {
    const roles = rolesOf(build({ platform }));
    for (const must of ['cut', 'copy', 'paste', 'selectAll', 'undo', 'redo']) {
      assert.ok(roles.includes(must), `${platform}: the ${must} role is what makes its accelerator work`);
    }
  }
});

test('a shipped build offers no developer tools and no reload', () => {
  const roles = rolesOf(build({ isPackaged: true }));
  for (const never of ['toggleDevTools', 'reload', 'forceReload']) {
    assert.ok(!roles.includes(never), `a packaged build must not offer ${never} on a signed-in window`);
  }
  assert.ok(!labelsOf(build({ isPackaged: true })).includes('&View'));
});

test('a development run keeps them, because that is who needs them', () => {
  const roles = rolesOf(build({ isPackaged: false }));
  for (const want of ['toggleDevTools', 'reload', 'forceReload']) assert.ok(roles.includes(want), want);
});

test('nothing points outside this app, and nothing survives from the default menu', () => {
  for (const isPackaged of [true, false]) {
    for (const platform of ['win32', 'darwin', 'linux']) {
      const labels = labelsOf(build({ isPackaged, platform })).join(' | ');
      // Electron's default Help menu links to electronjs.org, which is not this app's help.
      assert.ok(!/Learn More|Documentation|Community|Electron/i.test(labels), `${platform}/${isPackaged}: ${labels}`);
      // The document-editor leftovers.
      assert.ok(!/New Window|Open File|Save|Print|Close Window/i.test(labels), `${platform}/${isPackaged}: ${labels}`);
    }
  }
});

test('every door the menu offers is one the tray offers too, and each one works', () => {
  const { called, actions: a } = actions();
  const t = buildMenuTemplate({ isPackaged: true, platform: 'win32', actions: a });
  const labels = labelsOf(t);
  for (const door of ['Sync status…', 'Computers & synced folders…', 'Troubleshoot…', 'About DockVault']) {
    assert.ok(labels.includes(door), `${door} is offered`);
  }
  // Click every item that has a handler and confirm it reaches the action rather than being decoration.
  const clickAll = (items) => {
    for (const it of items || []) {
      if (it && typeof it.click === 'function' && it.label) it.click();
      if (it && Array.isArray(it.submenu)) clickAll(it.submenu);
    }
  };
  clickAll(t);
  for (const fired of ['status', 'computers', 'troubleshoot', 'about', 'quit']) {
    assert.ok(called.includes(fired), `${fired} is wired, not decoration`);
  }
});

// Quit must go through the app's own shutdown so a sync in flight is not cut off mid-write. On macOS the
// platform role is correct and expected; everywhere else it is this app's own handler.
test('Quit is the app\'s own on Windows and Linux, and the platform role on macOS', () => {
  for (const platform of ['win32', 'linux']) {
    const t = build({ platform });
    const roles = rolesOf(t);
    assert.ok(!roles.includes('quit'), `${platform}: not the bare role, which would bypass the shutdown`);
    const labels = labelsOf(t);
    assert.ok(labels.some((l) => /Quit/i.test(l)), `${platform}: but there is still a way to quit`);
  }
  assert.ok(rolesOf(build({ platform: 'darwin' })).includes('quit'), 'macOS expects the standard role');
});

test('the accelerator for Quit is stated, since dropping the default menu would take it away', () => {
  const t = build({ platform: 'win32' });
  const found = [];
  const walk = (items) => { for (const it of items || []) { if (it && it.accelerator) found.push(it.accelerator); if (it && Array.isArray(it.submenu)) walk(it.submenu); } };
  walk(t);
  assert.ok(found.includes('CmdOrCtrl+Q'), `Ctrl+Q still quits: ${found}`);
});

test('macOS puts About and Quit in the application menu, where that platform expects them', () => {
  const t = build({ platform: 'darwin', appName: 'DockVault' });
  assert.equal(t[0].label, 'DockVault', 'the app menu comes first');
  const first = labelsOf([t[0]]);
  assert.ok(first.includes('About DockVault'));
  assert.ok(rolesOf([t[0]]).includes('quit'));
  // And the doors are reachable there too, not stranded in a File menu macOS users would not look in.
  assert.ok(first.includes('Sync status…'));
});

test('a missing action never throws — a menu item that cannot act is inert, not a crash', () => {
  const t = buildMenuTemplate({ isPackaged: true, platform: 'win32', actions: {} });
  const clickAll = (items) => { for (const it of items || []) { if (it && typeof it.click === 'function') it.click(); if (it && Array.isArray(it.submenu)) clickAll(it.submenu); } };
  assert.doesNotThrow(() => clickAll(t));
});

// ---------------------------------------------------------------------------------------------
// THE WIRING. A template nobody installs is a definition, not a fix — and installing it late is worse than
// not installing it, because a window shown before it would carry Electron's default menu with the
// developer tools in it.
// ---------------------------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const main = fs.readFileSync(path.join(path.resolve(__dirname, '..'), 'src', 'main', 'index.js'), 'utf8');

test('the menu is installed, and installed before any window can exist', () => {
  assert.match(main, /Menu\.setApplicationMenu\(Menu\.buildFromTemplate\(appMenu\.buildMenuTemplate\(/,
    'the template is turned into the real application menu');

  const install = main.indexOf('installApplicationMenu();');
  assert.notEqual(install, -1, 'and it is actually called, not merely defined');

  // Before the session partition every window is built on — which is the first thing in boot that leads to
  // a window existing. A window created before this call would show the default menubar.
  const session = main.indexOf('uiSession = session.fromPartition(UI_PARTITION)');
  assert.notEqual(session, -1);
  assert.ok(install < session, 'the menu is in place before anything can open a window');
});

test('the real build is told whether it is packaged, so the shipped one drops the developer tools', () => {
  const call = main.slice(main.indexOf('appMenu.buildMenuTemplate('), main.indexOf('})));', main.indexOf('appMenu.buildMenuTemplate(')));
  assert.match(call, /isPackaged: app\.isPackaged/, 'not a hardcoded false, which would ship devtools');
  assert.match(call, /platform: process\.platform/);
});

test('every door the menu opens is a real function in the app', () => {
  const call = main.slice(main.indexOf('appMenu.buildMenuTemplate('), main.indexOf('})));', main.indexOf('appMenu.buildMenuTemplate(')));
  for (const [name, fn] of [['status', 'openStatusView'], ['computers', 'openManageView'], ['troubleshoot', 'openTroubleshoot'], ['about', 'showAbout']]) {
    // Plain string containment, not a built regex: the parens and braces here are regex metacharacters, and
    // an under-escaped pattern compiles into something that matches almost anything rather than failing.
    assert.ok(call.includes(`${name}: () => { void ${fn}(); }`), `${name} opens ${fn}: ${call}`);
    assert.ok(main.includes(`function ${fn}(`), `${fn} exists`);
  }
  // Quit goes through the app's own shutdown flag, not a bare app.quit(), so a run in flight is not cut off.
  assert.match(call, /quit: \(\) => \{ isQuitting = true; app\.quit\(\); \}/);
});

test('a menu that cannot be built does not stop the app starting', () => {
  const fn = main.slice(main.indexOf('function installApplicationMenu()'), main.indexOf('\n}', main.indexOf('function installApplicationMenu()')));
  assert.match(fn, /try \{/);
  assert.match(fn, /catch \{/);
});

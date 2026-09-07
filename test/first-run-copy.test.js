'use strict';

// The first-launch notification discloses the login item without promising a sync that is not set up,
// and the tray checkbox is a plain reflection of whatever it is handed.

const test = require('node:test');
const assert = require('node:assert/strict');

const { installedNotification, loginItemMenu } = require('../src/main/tray-presentation');

test('the first-launch notification names the platform sign-in and where to turn the login item off', () => {
  for (const [platform, phrase] of [['win32', 'sign in to Windows'], ['darwin', 'log in to your Mac'], ['linux', 'log in']]) {
    const n = installedNotification(platform);
    assert.equal(n.title, 'DockVault is installed and running in the tray');
    assert.equal(n.body, `It starts when you ${phrase}. You can turn that off in the tray menu.`);
    assert.doesNotMatch(n.body, /sync/i, 'no sync promise before anything is set up');
  }
});

test('when the platform refused the registration, the notice points at the switch instead of claiming it starts', () => {
  for (const [platform, phrase] of [['win32', 'sign in to Windows'], ['darwin', 'log in to your Mac'], ['linux', 'log in']]) {
    const n = installedNotification(platform, false);
    assert.equal(n.title, 'DockVault is installed and running in the tray');
    assert.equal(n.body, `Turn on Start at login in the tray menu if you want it to start when you ${phrase}.`);
    assert.doesNotMatch(n.body, /^It starts/);
  }
  assert.match(installedNotification('win32', true).body, /^It starts when you sign in to Windows\./);
  assert.match(installedNotification('win32', undefined).body, /^It starts/, 'the default is the registered wording');
});

test('the login-item checkbox shows exactly the state it is given, and only a true is checked', () => {
  assert.deepEqual(loginItemMenu(true), { label: 'Start at login', type: 'checkbox', checked: true });
  assert.deepEqual(loginItemMenu(false), { label: 'Start at login', type: 'checkbox', checked: false });
  assert.equal(loginItemMenu(undefined).checked, false);
  assert.equal(loginItemMenu('yes').checked, false);
});

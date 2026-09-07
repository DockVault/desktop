'use strict';

// The identity the running app reports and the identity the installers are built with are the same
// values, read from the same place; the installer hook removes exactly the login item the app creates.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const { APP_ID, LOGIN_ITEM_NAME } = require('../src/main/app-identity');

const root = path.resolve(__dirname, '..');

test('the build configuration uses the shared application id', () => {
  const config = require(path.join(root, 'electron-builder.js'));
  assert.equal(config.appId, APP_ID);
  assert.match(APP_ID, /^[a-z]+([.][a-z0-9-]+)+$/, 'reverse-domain form, as macOS and Windows expect');
});

test('the Windows uninstaller removes exactly the login item the app registers', () => {
  const nsh = fs.readFileSync(path.join(root, 'build', 'installer.nsh'), 'utf8');
  const runKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Run';
  const approvedKey = 'Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run';
  assert.ok(nsh.includes(`DeleteRegValue HKCU "${runKey}" "${LOGIN_ITEM_NAME}"`), 'Run value removed by the shared name');
  assert.ok(nsh.includes(`DeleteRegValue HKCU "${approvedKey}" "${LOGIN_ITEM_NAME}"`), 'startup-approval flag removed by the shared name');
  // No other value name is touched, so the hook cannot drift to a stale name.
  const names = [...nsh.matchAll(/DeleteRegValue HKCU "[^"]+" "([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual([...new Set(names)], [LOGIN_ITEM_NAME]);
  // An install over an existing one runs this same uninstaller with the updated flag first; the login item
  // must survive that, so both removals sit inside the not-updated guard and nowhere else.
  const guarded = nsh.match(/\$\{ifNot\} \$\{isUpdated\}([\s\S]*?)\$\{endIf\}/);
  assert.ok(guarded, 'the removals are wrapped in the not-updated guard');
  assert.equal((guarded[1].match(/DeleteRegValue/g) || []).length, 2, 'both removals are inside the guard');
  assert.equal((nsh.match(/DeleteRegValue/g) || []).length, 2, 'and there are no removals outside it');
});

test('the uninstaller names the real data folder, which follows the package name', () => {
  const nsh = fs.readFileSync(path.join(root, 'build', 'installer.nsh'), 'utf8');
  const { name } = require(path.join(root, 'package.json'));
  // Electron derives the user-data folder from the package name; the note must point at that folder.
  assert.ok(nsh.includes(`$APPDATA\\${name}`), `uninstall note names $APPDATA\\${name}`);
});

test('the login-item name is a plain registry value name, and it is the app id Electron reads it under', () => {
  assert.match(LOGIN_ITEM_NAME, /^[A-Za-z0-9. ]+$/);
  assert.equal(LOGIN_ITEM_NAME, APP_ID);
});

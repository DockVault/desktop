'use strict';

// The tray tells the truth about which server is in force, and a server change asks first in words
// that say what ends and what stays.

const test = require('node:test');
const assert = require('node:assert/strict');

const { serverMenuItems, changeServerConsent } = require('../src/main/tray-presentation');

test('a saved server silently overridden by the environment is named in the menu, and cannot be "changed" into a file the variable would ignore', () => {
  const items = serverMenuItems({ status: 'env', origin: 'https://env.example.com', envOrigin: 'https://env.example.com', fileOrigin: 'https://saved.example.com', envOverrides: true });
  assert.deepEqual(items.map((i) => i.kind), ['server-note']);
  assert.equal(items[0].label, 'Using DOCKVAULT_SERVER override');
  assert.equal(items[0].enabled, false);
});

test('an environment value equal to the saved one, or with nothing saved, needs no note and offers no change', () => {
  const same = serverMenuItems({ status: 'env', origin: 'https://a.example.com', envOrigin: 'https://a.example.com', fileOrigin: 'https://a.example.com', envOverrides: false });
  assert.deepEqual(same, []);
  const saved = serverMenuItems({ status: 'ok', origin: 'https://a.example.com', envOrigin: null, fileOrigin: 'https://a.example.com', envOverrides: false });
  assert.deepEqual(saved.map((i) => i.label), ['Change server…']);
});

test('with no server in force the tray offers the setup screen, never a blank state', () => {
  assert.deepEqual(serverMenuItems({ status: 'absent', origin: null, envOrigin: null, fileOrigin: null, envOverrides: false }), [{ kind: 'setup-server', label: 'Set up server…' }]);
  assert.deepEqual(serverMenuItems({ status: 'unreadable', origin: null, envOrigin: null, fileOrigin: null, envOverrides: false }), [{ kind: 'setup-server', label: 'Set up server…' }]);
  assert.deepEqual(serverMenuItems(null), []);
  const { tooltip } = require('../src/main/tray-presentation');
  const model = { state: 'idle', condition: 'not-configured' };
  assert.equal(tooltip(model, 'unlocked', null, { server: { origin: null } }), 'DockVault — Not connected');
  assert.equal(tooltip(model, 'unlocked', null, { server: { origin: 'https://a.example.com' } }), 'DockVault');
});

test('the change-server consent names the old server, what ends, and that files stay', () => {
  const c = changeServerConsent('vault.example.com');
  assert.equal(c.message, 'Switching servers signs you out and removes this computer from sync on vault.example.com. Files already synced stay in their folders.');
  assert.deepEqual(c.buttons, ['Cancel', 'Switch server']);
  assert.match(changeServerConsent('').message, /on the current server\./);
});

test('with no server in force the glance says so even while the app is locked — the lock cannot outrank a server that was never set', () => {
  const { tooltip } = require('../src/main/tray-presentation');
  const { STATE } = require('../src/main/sync-status-model');
  // A paused-locked model is the strongest competing glance; without a server nothing behind it can be
  // true, so "Not connected" wins. The two inputs are named, so neither can slide into the other's slot.
  const pausedLocked = { state: STATE.PAUSED, reason: 'locked', condition: null, online: true, label: 'Paused', vaults: [{ vault: 'v1', state: STATE.PAUSED, reason: 'locked' }] };
  assert.equal(tooltip(pausedLocked, null, null, { server: { origin: null }, lockReason: 'os-lock' }), 'DockVault — Not connected');
  // With a server in force the same model reads as the lock, so the precedence is a rule and not an accident.
  assert.equal(tooltip(pausedLocked, null, null, { server: { origin: 'https://a.example.com' }, lockReason: 'os-lock' }), 'DockVault — Locked');
  // The options are order-independent and each is optional.
  assert.equal(tooltip(pausedLocked, null, null, { lockReason: 'sleep' }), 'DockVault — Sync paused since sleep — Resume sync to continue');
});

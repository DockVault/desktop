'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { MODE, detectMode, hasSecureStore, isHardwareBacked } = require('../src/main/key-protection');

const ss = (available, backend) => ({
  isEncryptionAvailable: () => available,
  getSelectedStorageBackend: () => backend,
});

test('no OS encryption available -> Mode C (memory-only), on every platform', () => {
  for (const p of ['win32', 'darwin', 'linux']) {
    assert.strictEqual(detectMode(ss(false), p), MODE.NONE);
  }
  assert.strictEqual(detectMode(null, 'win32'), MODE.NONE);
  assert.strictEqual(detectMode({}, 'win32'), MODE.NONE);
});

test('Linux basic_text -> Mode C (memory-only); a real secret service -> Mode A', () => {
  assert.strictEqual(detectMode(ss(true, 'basic_text'), 'linux'), MODE.NONE);
  assert.strictEqual(detectMode(ss(true, 'gnome_libsecret'), 'linux'), MODE.SOFTWARE);
  assert.strictEqual(detectMode(ss(true, 'kwallet6'), 'linux'), MODE.SOFTWARE);
});

test('Linux never asserts hardware backing even with a positive probe', () => {
  assert.strictEqual(detectMode(ss(true, 'gnome_libsecret'), 'linux', () => true), MODE.SOFTWARE);
});

test('Windows / macOS with encryption -> Mode A when no hardware probe is wired', () => {
  assert.strictEqual(detectMode(ss(true), 'win32'), MODE.SOFTWARE);
  assert.strictEqual(detectMode(ss(true), 'darwin'), MODE.SOFTWARE);
});

test('Mode B is claimed only on a verified positive hardware probe (never over-claimed)', () => {
  assert.strictEqual(detectMode(ss(true), 'darwin', () => true), MODE.HARDWARE);
  assert.strictEqual(detectMode(ss(true), 'win32', () => false), MODE.SOFTWARE);
  assert.strictEqual(detectMode(ss(true), 'darwin', () => { throw new Error('probe blew up'); }), MODE.SOFTWARE);
});

test('secure-store + hardware helpers', () => {
  assert.ok(hasSecureStore(MODE.SOFTWARE) && hasSecureStore(MODE.HARDWARE), 'A/B have a real secret store');
  assert.ok(!hasSecureStore(MODE.NONE), 'Mode C has no secure store -> no persistence / no background sync');
  assert.ok(isHardwareBacked(MODE.HARDWARE));
  assert.ok(!isHardwareBacked(MODE.SOFTWARE) && !isHardwareBacked(MODE.NONE));
});

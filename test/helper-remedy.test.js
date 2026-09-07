'use strict';

// The helper-not-ready dialog's remedy follows the typed reason, because the honest fix differs: only a
// missing / altered / wrong-version bundled helper is a damaged installation. Nothing here ever names a path,
// a value, or a hash.

const test = require('node:test');
const assert = require('node:assert/strict');

const { helperDetail, helperRemedy, setPackaged, tooltip } = require('../src/main/tray-presentation');

test('once main marks the app as installed, the tooltip and every other caller speak the same way', () => {
  const model = { state: 'sync-problem', reason: 'helper-not-ready', sub: 'binary-missing', condition: 'ok' };
  try {
    setPackaged(true);
    assert.equal(helperDetail('binary-missing', null, null), 'The sync helper file is missing.');
    const t = tooltip(model, 'unlocked', '1.75.0');
    assert.match(t, /The sync helper isn't ready · The sync helper file is missing\.$/);
    assert.doesNotMatch(t, /Set it up again|check its setup/);
    assert.equal(helperDetail('obscure-failed', null, null), "The sync helper couldn't be started.");
  } finally {
    setPackaged(false);
  }
  assert.equal(helperDetail('binary-missing', null, null), 'The sync helper file is missing. Set it up again.');
  assert.match(tooltip(model, 'unlocked', '1.75.0'), /Set it up again\.$/);
});

const DAMAGED = ['version-mismatch', 'checksum-mismatch', 'binary-missing'];
const RAN_THEN_FAILED = ['obscure-failed', 'config-format-failed', 'prepare-failed', null, undefined, 'something-new'];

test('a damaged bundled helper is repaired only by reinstalling', () => {
  for (const sub of DAMAGED) {
    const r = helperRemedy(sub, 'win32');
    assert.match(r, /installation looks damaged/);
    assert.match(r, /Reinstall DockVault by running the installer again/);
    assert.match(r, /Your files and settings are not affected/);
  }
});

test('a helper blocked from starting is not called damaged; the remedy names the real blocker per platform', () => {
  const win = helperRemedy('spawn-failed', 'win32');
  assert.match(win, /SmartScreen or your antivirus/);
  assert.match(win, /restore it from quarantine/);
  const mac = helperRemedy('spawn-failed', 'darwin');
  assert.match(mac, /macOS blocked the sync helper/);
  assert.match(mac, /Privacy & Security/);
  const linux = helperRemedy('spawn-failed', 'linux');
  assert.match(linux, /security policy or a missing execute permission/);
  for (const r of [win, mac, linux]) {
    assert.doesNotMatch(r, /damaged|Reinstall/);
    assert.match(r, /then restart DockVault/);
    assert.match(r, /Your files and settings are not affected/);
  }
});

test('a helper that ran and then failed gets restart first, reinstall only if it persists', () => {
  for (const sub of RAN_THEN_FAILED) {
    const r = helperRemedy(sub, 'win32');
    assert.match(r, /^DockVault couldn't start its sync helper\. Restart DockVault; if this keeps happening, reinstall/);
    assert.doesNotMatch(r, /damaged/);
  }
});

test('no remedy ever shows a path, an environment variable, or a hash', () => {
  for (const sub of [...DAMAGED, 'spawn-failed', ...RAN_THEN_FAILED]) {
    for (const platform of ['win32', 'darwin', 'linux']) {
      const r = helperRemedy(sub, platform);
      assert.doesNotMatch(r, /DOCKVAULT_|[A-Za-z]:\\|\/usr\/|[0-9a-f]{40}|sha/i);
    }
  }
});

test('the detail line drops environment-era advice in a packaged app', () => {
  assert.equal(helperDetail('binary-missing', null, null, true), 'The sync helper file is missing.');
  assert.equal(helperDetail('binary-missing', null, null), 'The sync helper file is missing. Set it up again.');
  assert.equal(helperDetail('obscure-failed', null, null, true), "The sync helper couldn't be started.");
  assert.match(helperDetail('obscure-failed', null, null), /check its setup/);
  // Reason lines that were already environment-free are unchanged either way.
  assert.equal(helperDetail('spawn-failed', null, null, true), helperDetail('spawn-failed', null, null));
  assert.equal(helperDetail('version-mismatch', '1.0.0', '1.75.0', true), helperDetail('version-mismatch', '1.0.0', '1.75.0'));
});

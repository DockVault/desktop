'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { refuseMessage, cloudServiceName, cloudWarnMessage, consentMessage } = require('../src/main/enable-copy');

test('refuseMessage: every known reason has actionable non-blaming copy; unknown falls back', () => {
  for (const r of ['home-root-or-above', 'app-data-dir', 'system-location', 'overlaps-another-sync', 'not-absolute']) {
    const m = refuseMessage(r);
    assert.ok(m && m.length > 0 && !/you (idiot|should)/i.test(m), `${r} has copy`);
  }
  assert.match(refuseMessage('something-new'), /pick another folder/i);
});

test('cloudServiceName detects the major services and falls back generically', () => {
  assert.strictEqual(cloudServiceName('/Users/t/OneDrive/x'), 'OneDrive');
  assert.strictEqual(cloudServiceName('C:/Users/t/Dropbox/x'), 'Dropbox');
  assert.strictEqual(cloudServiceName('/Users/t/Google Drive/x'), 'Google Drive');
  assert.strictEqual(cloudServiceName('/Users/t/Library/Mobile Documents/com~apple~CloudDocs/x'), 'iCloud Drive');
  assert.strictEqual(cloudServiceName('/Users/t/Documents/x'), 'a cloud storage app');
});

test('cloudWarnMessage names the service; consentMessage is TWO-WAY + warns on a non-empty folder', () => {
  assert.match(cloudWarnMessage('OneDrive'), /inside OneDrive.*conflicts/s);
  const c = consentMessage('Marketing', '/Users/t/Vaults/M');
  assert.match(c, /Marketing/);
  assert.match(c, /\/Users\/t\/Vaults\/M/);
  assert.match(c, /both ways/i, 'states it is bidirectional');
  assert.match(c, /uploaded into the vault/i, 'states the upload direction, not only the download');
  // non-empty folder: the existing contents are called out as being uploaded
  const ne = consentMessage('Marketing', '/Users/t/Vaults/M', { nonEmpty: true });
  assert.match(ne, /already contains files/i);
  // empty folder: no such warning
  assert.doesNotMatch(consentMessage('Marketing', '/Users/t/Vaults/M', { nonEmpty: false }), /already contains files/i);
});

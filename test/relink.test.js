'use strict';

// RE-LINKING A FOLDER THAT HAS BEEN SYNCED BEFORE.
//
// Setting up sync read the picked folder's marker and acted on it without saying anything. It kept the sync
// id when the marker named the same vault, and in every other shape it OVERWROTE the marker — including when
// the marker belonged to ANOTHER vault, which is how that vault finds its folder again after a rename. That
// vault lost its folder identity and nobody was told.
//
// The other half is the sync BASELINE, and it is why these verdicts are a kind rather than a flag. rclone
// bisync diffs against a prior listing; the engine keys the workdir by VAULT and the listings inside it by
// the local+remote path PAIR. So the same vault re-linked to the SAME path finds its listings and genuinely
// resumes, while the same vault re-linked to a DIFFERENT path finds none and starts a fresh baseline. Saying
// "resetting the sync baseline" in the first case would be a lie, and saying nothing in the second leaves a
// person watching a long first run with no explanation — which is the failure this phase names.

const test = require('node:test');
const assert = require('node:assert/strict');

const { classifyPick, pickMessage, samePath } = require('../src/main/relink');

const VAULT = '11111111-1111-1111-1111-111111111111';
const OTHER = '22222222-2222-2222-2222-222222222222';
const marker = (over) => ({ kind: 'ok', vaultId: VAULT, syncId: 'sync-1', ...over });

test('a folder with no marker is an ordinary first setup, and says nothing', () => {
  for (const kind of ['absent', 'folder-missing', 'no-marker']) {
    const v = classifyPick({ marker: { kind }, vaultId: VAULT, folder: 'C:\\Users\\a\\Docs' });
    assert.equal(v.kind, 'fresh', kind);
    assert.equal(v.resetsBaseline, false);
    assert.equal(v.takesOverMarker, false);
    // Nothing to interrupt a first setup with.
    assert.equal(pickMessage(v, { vaultName: 'Photos' }), null, kind);
  }
});

test('the same vault, the same folder: it resumes, and does not claim to reset anything', () => {
  const folder = 'C:\\Users\\a\\Docs\\Photos';
  const v = classifyPick({ marker: marker(), vaultId: VAULT, folder, knownFolder: folder });
  assert.equal(v.kind, 'resume');
  assert.equal(v.resetsBaseline, false, 'the prior listings are keyed by this same path, so they are found');
  assert.equal(v.keepsSyncId, true);
  assert.equal(v.takesOverMarker, false);

  const say = pickMessage(v, { vaultName: 'Photos' });
  assert.match(say.detail, /carry on from where that left off/);
  assert.doesNotMatch(say.title, /resetting/i, 'this case must not say the baseline is reset — it is not');
  assert.match(say.detail, /nothing is deleted/i);
});

test('the same vault from a different place: it says the baseline is being reset', () => {
  const v = classifyPick({
    marker: marker(), vaultId: VAULT,
    folder: 'D:\\Moved\\Photos', knownFolder: 'C:\\Users\\a\\Docs\\Photos',
  });
  assert.equal(v.kind, 'moved');
  assert.equal(v.resetsBaseline, true, 'no listing exists for this path pair, so the first run rebuilds one');
  assert.equal(v.keepsSyncId, true, 'it is still the same folder identity');
  assert.equal(v.takesOverMarker, false);

  const say = pickMessage(v, { vaultName: 'Photos' });
  assert.match(say.title, /resetting the sync baseline/i, 'the exact thing the person is owed');
  // A reset baseline is not data loss and must not read as one.
  assert.match(say.detail, /nothing is deleted/i);
  assert.match(say.detail, /takes longer/i, 'and it explains the long first run, which is the visible symptom');
});

test("another vault's folder is never taken over silently, and the warning says what it costs", () => {
  const v = classifyPick({ marker: marker({ vaultId: OTHER }), vaultId: VAULT, folder: 'C:\\Users\\a\\Shared' });
  assert.equal(v.kind, 'other-vault');
  assert.equal(v.takesOverMarker, true);
  assert.equal(v.resetsBaseline, true);
  assert.equal(v.otherVaultId, OTHER, 'the caller can name the other vault instead of quoting an id');

  const named = pickMessage(v, { vaultName: 'Photos', otherVaultName: 'Invoices' });
  assert.match(named.title, /Invoices/);
  assert.match(named.detail, /no longer recognise this folder/i, 'the real cost to the other vault is stated');
  assert.match(named.detail, /nothing is deleted/i);

  // A vault that is no longer configured has no name to give, and the copy must not invent one.
  const unnamed = pickMessage(v, { vaultName: 'Photos' });
  assert.match(unnamed.title, /another vault/i);
  assert.doesNotMatch(unnamed.detail, new RegExp(OTHER), 'never a raw id in front of a person');
});

test('a marker that cannot be read is replaced, but never assumed to be ours', () => {
  const v = classifyPick({ marker: { kind: 'unreadable' }, vaultId: VAULT, folder: 'C:\\Users\\a\\Docs' });
  assert.equal(v.kind, 'unreadable');
  assert.equal(v.keepsSyncId, false, 'an unreadable marker is not evidence of an identity to keep');
  assert.equal(v.resetsBaseline, true);
  const say = pickMessage(v, { vaultName: 'Photos' });
  assert.match(say.title, /resetting the sync baseline/i);
  assert.match(say.detail, /can't be read/i);
  assert.match(say.detail, /nothing is deleted/i);
});

// Every sentence a person can be shown here is about their files, so the reassurance has to be in all of
// them — a "resetting the baseline" with no such line reads as "about to lose things".
test('every message says plainly that nothing is deleted, and none of them shows an id', () => {
  const shapes = [
    classifyPick({ marker: marker(), vaultId: VAULT, folder: 'C:\\a', knownFolder: 'C:\\a' }),
    classifyPick({ marker: marker(), vaultId: VAULT, folder: 'C:\\b', knownFolder: 'C:\\a' }),
    classifyPick({ marker: marker({ vaultId: OTHER }), vaultId: VAULT, folder: 'C:\\a' }),
    classifyPick({ marker: { kind: 'unreadable' }, vaultId: VAULT, folder: 'C:\\a' }),
  ];
  let seen = 0;
  for (const v of shapes) {
    const say = pickMessage(v, { vaultName: 'Photos' });
    assert.ok(say && say.title && say.detail, `${v.kind}: has something to say`);
    assert.match(say.detail, /nothing is deleted|nothing is re-uploaded and nothing is deleted/i, `${v.kind}: reassures`);
    assert.ok(!/[0-9a-f]{8}-[0-9a-f]{4}/i.test(`${say.title} ${say.detail}`), `${v.kind}: no raw id`);
    seen += 1;
  }
  assert.equal(seen, 4, 'all four talking shapes were exercised');
});

test('the same folder spelled differently is still the same folder', () => {
  assert.equal(samePath('C:\\Users\\a\\Docs', 'C:\\Users\\a\\Docs\\', true), true, 'a trailing separator');
  assert.equal(samePath('C:\\Users\\a\\Docs', 'c:\\users\\a\\docs', true), true, 'case, where the platform ignores it');
  assert.equal(samePath('C:\\Users\\a\\Docs', 'C:\\Users\\a\\Other', true), false);
  assert.equal(samePath('/home/a/docs', '/home/a/docs/', false), true);
  // Case matters where the platform says it does.
  assert.equal(samePath('/home/a/Docs', '/home/a/docs', false), false);
  for (const bad of [null, undefined, '', 42]) assert.equal(samePath(bad, 'C:\\a'), false, String(bad));

  // And it is what decides resume-vs-reset, so a spelling difference must not cause a needless full compare.
  const v = classifyPick({ marker: marker(), vaultId: VAULT, folder: 'C:\\Users\\a\\Docs\\', knownFolder: 'C:\\Users\\a\\Docs' });
  assert.equal(v.kind, 'resume', 'a trailing separator is not a move');
});

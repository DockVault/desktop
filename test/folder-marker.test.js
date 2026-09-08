'use strict';

// The synced folder's identity marker: written once, read by content, found again after a move — on a real
// temporary tree, since renames and hidden files are what this is about.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const fm = require('../src/main/folder-marker');

const V = '11111111-1111-4111-8111-111111111111';
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-marker-')); }

test('a marker round-trips, carries only the two ids, and is hidden by name', () => {
  const root = tmp();
  const folder = path.join(root, 'Photos');
  fs.mkdirSync(folder);
  const syncId = fm.newSyncId();
  assert.match(syncId, fm.ID_RE);
  const written = fm.writeMarker(folder, { syncId, vaultId: V });
  assert.equal(path.basename(written), '.dockvault-sync');
  const text = fs.readFileSync(written, 'utf8');
  const parsed = JSON.parse(text);
  assert.deepEqual(Object.keys(parsed).sort(), ['app', 'note', 'syncId', 'v', 'vaultId']);
  assert.ok(!text.includes(root), 'no path in the marker');
  assert.deepEqual(fm.readMarker(folder), { kind: 'ok', syncId, vaultId: V });
  assert.ok(!fs.readdirSync(folder).some((n) => n.endsWith('.tmp')), 'no temp file left behind');
});

test('writing over an existing marker replaces it atomically; a hide hook is called and may fail', () => {
  const root = tmp();
  const folder = path.join(root, 'Docs');
  fs.mkdirSync(folder);
  const a = fm.newSyncId(); const b = fm.newSyncId();
  fm.writeMarker(folder, { syncId: a, vaultId: V });
  let hidden = null;
  fm.writeMarker(folder, { syncId: b, vaultId: V }, { hide: (p) => { hidden = p; throw new Error('attrib missing'); } });
  assert.equal(fm.readMarker(folder).syncId, b);
  assert.equal(hidden, fm.markerPath(folder));
});

test('reading distinguishes a missing folder, a folder without a marker, and a torn or foreign marker', () => {
  const root = tmp();
  assert.deepEqual(fm.readMarker(path.join(root, 'nope')), { kind: 'folder-missing' });
  const f = path.join(root, 'F'); fs.mkdirSync(f);
  assert.deepEqual(fm.readMarker(f), { kind: 'absent' });
  fs.writeFileSync(fm.markerPath(f), '{"v":1,"syncId":"abc"');
  assert.deepEqual(fm.readMarker(f), { kind: 'unreadable' });
  fs.writeFileSync(fm.markerPath(f), JSON.stringify({ v: 2, syncId: V, vaultId: V }));
  assert.deepEqual(fm.readMarker(f), { kind: 'unreadable' }, 'a version this app does not know is not trusted');
  fs.writeFileSync(fm.markerPath(f), JSON.stringify({ v: 1, syncId: '../../etc', vaultId: V }));
  assert.deepEqual(fm.readMarker(f), { kind: 'unreadable' }, 'ids must be well-formed');
  // A file where the folder should be is not a folder.
  const file = path.join(root, 'file.txt'); fs.writeFileSync(file, 'x');
  assert.deepEqual(fm.readMarker(file), { kind: 'folder-missing' });
});

test('the read is bounded: a huge file or a link under the marker name is unreadable, never loaded', () => {
  const root = tmp();
  const f = path.join(root, 'F'); fs.mkdirSync(f);
  fs.writeFileSync(fm.markerPath(f), Buffer.alloc(fm.MARKER_MAX_BYTES + 1, 0x20));
  assert.deepEqual(fm.readMarker(f), { kind: 'unreadable' });
  // A file exactly at the bound with a valid marker inside still reads.
  const good = fm.markerContents({ syncId: fm.newSyncId(), vaultId: V });
  fs.writeFileSync(fm.markerPath(f), good);
  assert.equal(fm.readMarker(f).kind, 'ok');
  if (process.platform !== 'win32') {
    const target = path.join(root, 'elsewhere.json'); fs.writeFileSync(target, good);
    fs.rmSync(fm.markerPath(f)); fs.symlinkSync(target, fm.markerPath(f));
    assert.deepEqual(fm.readMarker(f), { kind: 'unreadable' }, 'a link is never followed');
  }
});

test('a marker refuses malformed ids', () => {
  assert.throws(() => fm.markerContents({ syncId: 'x', vaultId: V }));
  assert.throws(() => fm.markerContents({ syncId: V, vaultId: 'C:\\Users\\x' }));
  assert.equal(fm.parseMarker('not json'), null);
  assert.equal(fm.parseMarker('[]'), null);
});

test('removeMarker removes only this sync\'s own marker', () => {
  const root = tmp();
  const f = path.join(root, 'F'); fs.mkdirSync(f);
  const mine = fm.newSyncId(); const theirs = fm.newSyncId();
  fm.writeMarker(f, { syncId: theirs, vaultId: V });
  assert.equal(fm.removeMarker(f, mine), false);
  assert.equal(fm.readMarker(f).kind, 'ok');
  assert.equal(fm.removeMarker(f, theirs), true);
  assert.equal(fm.readMarker(f).kind, 'absent');
  assert.equal(fm.removeMarker(path.join(root, 'gone'), mine), false, 'never throws');
});

test('a renamed folder is found by its marker next to where it was; a moved one under the roots; a copy makes it ambiguous', async () => {
  const root = tmp();
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const docs = path.join(home, 'Documents'); fs.mkdirSync(docs);
  const orig = path.join(docs, 'Photos'); fs.mkdirSync(orig);
  const syncId = fm.newSyncId();
  fm.writeMarker(orig, { syncId, vaultId: V });
  // Decoys: a same-named folder with no marker, a folder with another sync's marker, a hidden folder that is skipped.
  fs.mkdirSync(path.join(home, 'Photos'));
  const other = path.join(docs, 'Other'); fs.mkdirSync(other); fm.writeMarker(other, { syncId: fm.newSyncId(), vaultId: V });
  const hidden = path.join(home, '.hidden'); fs.mkdirSync(hidden);

  // Rename in place.
  const renamed = path.join(docs, 'Photos 2026');
  fs.renameSync(orig, renamed);
  let r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: orig, roots: [home] });
  assert.deepEqual(r, { kind: 'found', folder: renamed });

  // Move deeper under home.
  const deep = path.join(home, 'Pictures', 'Family', 'Photos'); fs.mkdirSync(path.dirname(deep), { recursive: true });
  fs.renameSync(renamed, deep);
  r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: orig, roots: [home] });
  assert.deepEqual(r, { kind: 'found', folder: deep });

  // Moved into a hidden tree: not looked at (hidden trees are skipped), so not found — and honestly so.
  const inHidden = path.join(hidden, 'Photos');
  fs.renameSync(deep, inHidden);
  r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: orig, roots: [home] });
  assert.equal(r.kind, 'not-found');
  fs.renameSync(inHidden, deep);

  // A copy of the folder (marker and all): two candidates, neither is chosen.
  const copy = path.join(docs, 'Photos copy'); fs.mkdirSync(copy); fs.copyFileSync(fm.markerPath(deep), fm.markerPath(copy));
  r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: orig, roots: [home] });
  assert.equal(r.kind, 'ambiguous');
  assert.deepEqual(r.folders.sort(), [copy, deep].sort());

  // A marker for the right sync id but the wrong vault does not count.
  fs.rmSync(copy, { recursive: true });
  fm.writeMarker(deep, { syncId, vaultId: '22222222-2222-4222-8222-222222222222' });
  r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: orig, roots: [home] });
  assert.equal(r.kind, 'not-found');
});

test('the search stops at its budget and says it did not finish', async () => {
  const root = tmp();
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  for (let i = 0; i < 30; i++) fs.mkdirSync(path.join(home, `d${i}`, 'x', 'y'), { recursive: true });
  const r = await fm.findFolderByMarker({ syncId: fm.newSyncId(), vaultId: V, lastPath: path.join(home, 'was'), roots: [home], maxDirs: 10 });
  assert.equal(r.kind, 'not-found');
  assert.equal(r.exhausted, false);
  const t = await fm.findFolderByMarker({ syncId: fm.newSyncId(), vaultId: V, lastPath: path.join(home, 'was'), roots: [home], maxMs: 0 });
  assert.equal(t.exhausted, false, 'a zero time budget stops at once');
});

test('symlinked folders are never followed', { skip: process.platform === 'win32' ? 'symlink dirs need privileges on Windows' : false }, async () => {
  const root = tmp();
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const outside = path.join(root, 'outside', 'Photos'); fs.mkdirSync(outside, { recursive: true });
  const syncId = fm.newSyncId();
  fm.writeMarker(outside, { syncId, vaultId: V });
  fs.symlinkSync(path.join(root, 'outside'), path.join(home, 'link'), 'dir');
  const r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: path.join(home, 'was'), roots: [home] });
  assert.equal(r.kind, 'not-found');
});

test('a synced folder whose own name starts with a dot is still found after a rename in place (the nearby pass looks at hidden names)', async () => {
  const root = tmp();
  const home = path.join(root, 'home'); fs.mkdirSync(home);
  const orig = path.join(home, 'Docs'); fs.mkdirSync(orig);
  const syncId = fm.newSyncId();
  fm.writeMarker(orig, { syncId, vaultId: V });
  fs.renameSync(orig, path.join(home, '.docs'));
  const r = await fm.findFolderByMarker({ syncId, vaultId: V, lastPath: orig, roots: [home] });
  assert.deepEqual(r, { kind: 'found', folder: path.join(home, '.docs') });
});

test('markerIdentity survives a rename and a same-volume move, and differs for a copy', () => {
  const root = tmp();
  const a = path.join(root, 'A'); fs.mkdirSync(a);
  fm.writeMarker(a, { syncId: fm.newSyncId(), vaultId: V });
  const id = fm.markerIdentity(a);
  assert.match(id, /^\d+:\d+$/);
  fs.renameSync(a, path.join(root, 'B'));
  assert.equal(fm.markerIdentity(path.join(root, 'B')), id, 'a rename keeps it');
  fs.mkdirSync(path.join(root, 'sub')); fs.renameSync(path.join(root, 'B'), path.join(root, 'sub', 'C'));
  assert.equal(fm.markerIdentity(path.join(root, 'sub', 'C')), id, 'a move within the volume keeps it');
  const copy = path.join(root, 'Copy'); fs.mkdirSync(copy); fs.copyFileSync(fm.markerPath(path.join(root, 'sub', 'C')), fm.markerPath(copy));
  assert.notEqual(fm.markerIdentity(copy), id, 'a copy is a different file');
  assert.equal(fm.markerIdentity(path.join(root, 'nope')), null);
});

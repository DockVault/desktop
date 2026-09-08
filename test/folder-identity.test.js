'use strict';

// Resolving a synced folder by its marker before a run: follow a move, adopt an old config, pause on doubt,
// and accept a relocation only for the folder that really carries the sync's marker.

const test = require('node:test');
const assert = require('node:assert/strict');

const { resolveSyncFolder, checkRelocation, NO_FOLDER_REASONS } = require('../src/main/folder-identity');

const V = '11111111-1111-4111-8111-111111111111';
const S = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OLD = 'C:\\Users\\me\\Documents\\Photos';
const NEW = 'C:\\Users\\me\\Pictures\\Photos';

const ID = '7:4242';
function make({ markers = {}, identities = {}, find = async () => ({ kind: 'not-found', exhausted: true }), classify = () => ({ ok: true }), writeMarker = null, repoint = null } = {}) {
  const log = [];
  const io = {
    readMarker: (folder) => markers[folder] || { kind: 'folder-missing' },
    writeMarker: writeMarker || ((folder, ids) => { log.push(['write', folder, ids]); markers[folder] = { kind: 'ok', ...ids }; identities[folder] = identities[folder] || `9:${folder.length}`; }),
    markerIdentity: (folder) => (Object.prototype.hasOwnProperty.call(identities, folder) ? identities[folder] : null),
    find: async (q) => { log.push(['find', q]); return find(q); },
    classify: (folder, vaultId) => { log.push(['classify', folder, vaultId]); return classify(folder); },
    repoint: repoint || ((entry, change) => log.push(['repoint', entry.vaultId, change])),
  };
  return { io, log };
}
// An entry whose marker identity is known (the common case after set-up).
const ENTRY = { vaultId: V, localFolder: OLD, syncId: S, markerId: ID };

test('the marker at the remembered path matches: run there, nothing else touched', async () => {
  const { io, log } = make({ markers: { [OLD]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [OLD]: ID } });
  const r = await resolveSyncFolder(ENTRY, io);
  assert.deepEqual(r, { ok: true, folder: OLD, syncId: S });
  assert.deepEqual(log, []);
});

test('an entry that never recorded the marker\'s identity learns it once, in place', async () => {
  const { io, log } = make({ markers: { [OLD]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [OLD]: ID } });
  const r = await resolveSyncFolder({ vaultId: V, localFolder: OLD, syncId: S }, io);
  assert.deepEqual(r, { ok: true, folder: OLD, syncId: S });
  assert.deepEqual(log, [['repoint', V, { localFolder: OLD, syncId: S, markerId: ID }]]);
});

test('the folder moved (the same marker file): it is found, checked against the placement rules, and the config re-pointed', async () => {
  const { io, log } = make({ markers: { [NEW]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [NEW]: ID }, find: async () => ({ kind: 'found', folder: NEW }) });
  const r = await resolveSyncFolder(ENTRY, io);
  assert.deepEqual(r, { ok: true, folder: NEW, syncId: S, moved: { from: OLD, to: NEW } });
  assert.deepEqual(log[0], ['find', { syncId: S, vaultId: V, lastPath: OLD }]);
  assert.deepEqual(log[1], ['classify', NEW, V]);
  assert.deepEqual(log[2], ['repoint', V, { localFolder: NEW, syncId: S, markerId: ID, movedFrom: OLD }]);
});

test('a look-alike found once — a copy, a move across volumes, or an identity never recorded — is NOT followed: the person is asked', async () => {
  const cases = [
    [ENTRY, { [NEW]: '7:9999' }, 'a copy (a different file)'],
    [ENTRY, {}, 'the identity cannot be read now'],
    [{ vaultId: V, localFolder: OLD, syncId: S }, { [NEW]: ID }, 'the entry never recorded an identity'],
  ];
  for (const [entry, identities, why] of cases) {
    const { io, log } = make({ markers: { [NEW]: { kind: 'ok', syncId: S, vaultId: V } }, identities, find: async () => ({ kind: 'found', folder: NEW }) });
    const r = await resolveSyncFolder(entry, io);
    assert.deepEqual(r, { ok: false, reason: 'folder-found-elsewhere', folders: [NEW] }, why);
    assert.ok(!log.some((l) => l[0] === 'repoint' || l[0] === 'classify'), `nothing followed: ${why}`);
  }
});

test('a second move before a run completes keeps the FIRST old path, so the engine can still carry its listings', async () => {
  const third = 'C:\\Users\\me\\Desktop\\Photos';
  const { io, log } = make({ markers: { [third]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [third]: ID }, find: async () => ({ kind: 'found', folder: third }) });
  const r = await resolveSyncFolder({ ...ENTRY, localFolder: NEW, movedFrom: OLD }, io);
  assert.equal(r.ok, true);
  assert.deepEqual(log.find((l) => l[0] === 'repoint'), ['repoint', V, { localFolder: third, syncId: S, markerId: ID, movedFrom: OLD }]);
});

test('a marker that cannot be written, or a config that cannot be saved, is a typed pause — never a raw error', async () => {
  const cannotWrite = make({ markers: { [OLD]: { kind: 'absent' } }, writeMarker: () => { throw new Error('EROFS'); } });
  assert.deepEqual(await resolveSyncFolder({ vaultId: V, localFolder: OLD }, cannotWrite.io), { ok: false, reason: 'folder-marker-unwritable' });
  const cannotSave = make({ markers: { [NEW]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [NEW]: ID }, find: async () => ({ kind: 'found', folder: NEW }), repoint: () => { const e = new Error('unreadable'); e.code = 'CONFIG_UNREADABLE'; throw e; } });
  assert.deepEqual(await resolveSyncFolder(ENTRY, cannotSave.io), { ok: false, reason: 'config-unwritable' });
  for (const reason of ['folder-marker-unwritable', 'config-unwritable', 'folder-found-elsewhere']) assert.ok(NO_FOLDER_REASONS.has(reason));
});

test('moved somewhere the rules refuse: paused with the place named, the config NOT re-pointed', async () => {
  const { io, log } = make({ identities: { 'C:\\Windows\\Photos': ID }, find: async () => ({ kind: 'found', folder: 'C:\\Windows\\Photos' }), classify: () => ({ ok: false, reason: 'system-location' }) });
  const r = await resolveSyncFolder(ENTRY, io);
  assert.deepEqual(r, { ok: false, reason: 'folder-moved-rejected', folders: ['C:\\Windows\\Photos'], placement: 'system-location' });
  assert.ok(!log.some((l) => l[0] === 'repoint'));
  // A cloud-synced place is asked about at set-up; followed silently it would double-sync, so it is refused here.
  const cloud = make({ identities: { 'C:\\Users\\me\\OneDrive\\Photos': ID }, find: async () => ({ kind: 'found', folder: 'C:\\Users\\me\\OneDrive\\Photos' }), classify: () => ({ ok: true, warn: 'inside-cloud-sync' }) });
  assert.deepEqual(await resolveSyncFolder(ENTRY, cloud.io), { ok: false, reason: 'folder-moved-rejected', folders: ['C:\\Users\\me\\OneDrive\\Photos'], placement: 'inside-cloud-sync' });
  assert.ok(!cloud.log.some((l) => l[0] === 'repoint'));
});

test('not found: the reason says what sits at the old path — nothing, a strange folder, another sync, a torn marker', async () => {
  const cases = [
    [{}, 'folder-missing'],
    [{ [OLD]: { kind: 'absent' } }, 'folder-marker-missing'],
    [{ [OLD]: { kind: 'ok', syncId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', vaultId: V } }, 'folder-other-vault'],
    [{ [OLD]: { kind: 'ok', syncId: S, vaultId: '22222222-2222-4222-8222-222222222222' } }, 'folder-other-vault'],
    [{ [OLD]: { kind: 'unreadable' } }, 'folder-marker-unreadable'],
  ];
  for (const [markers, reason] of cases) {
    const { io, log } = make({ markers });
    const r = await resolveSyncFolder(ENTRY, io);
    assert.deepEqual(r, { ok: false, reason }, reason);
    assert.ok(NO_FOLDER_REASONS.has(reason));
    assert.ok(!log.some((l) => l[0] === 'write' || l[0] === 'repoint'), 'nothing written on doubt');
  }
});

test('two folders carry the marker: paused as ambiguous, with both named, nothing chosen', async () => {
  const { io, log } = make({ find: async () => ({ kind: 'ambiguous', folders: [NEW, OLD + ' copy'] }) });
  const r = await resolveSyncFolder(ENTRY, io);
  assert.deepEqual(r, { ok: false, reason: 'folder-ambiguous', folders: [NEW, OLD + ' copy'] });
  assert.ok(!log.some((l) => l[0] === 'repoint'));
});

test('a search that throws is a not-found, never a crash into the run', async () => {
  const { io } = make({ find: async () => { throw new Error('disk'); } });
  const r = await resolveSyncFolder(ENTRY, io);
  assert.deepEqual(r, { ok: false, reason: 'folder-missing' });
});

test('a config from before markers: the folder is given a marker now and the id recorded', async () => {
  const { io, log } = make({ markers: { [OLD]: { kind: 'absent' } } });
  const r = await resolveSyncFolder({ vaultId: V, localFolder: OLD }, io);
  assert.equal(r.ok, true); assert.equal(r.folder, OLD); assert.equal(r.adopted, true);
  assert.match(r.syncId, /^[0-9a-f-]{36}$/);
  assert.deepEqual(log[0].slice(0, 2), ['write', OLD]);
  assert.deepEqual(log[1], ['repoint', V, { localFolder: OLD, syncId: r.syncId, markerId: `9:${OLD.length}` }]);
});

test('a config from before markers whose folder already carries this vault\'s marker adopts that id; another vault\'s marker or a torn one pauses', async () => {
  const { io, log } = make({ markers: { [OLD]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [OLD]: ID } });
  const r = await resolveSyncFolder({ vaultId: V, localFolder: OLD }, io);
  assert.deepEqual(r, { ok: true, folder: OLD, syncId: S, adopted: true });
  assert.ok(!log.some((l) => l[0] === 'write'));
  assert.deepEqual(log[0], ['repoint', V, { localFolder: OLD, syncId: S, markerId: ID }]);
  assert.deepEqual(await resolveSyncFolder({ vaultId: V, localFolder: OLD }, make({ markers: { [OLD]: { kind: 'ok', syncId: S, vaultId: '22222222-2222-4222-8222-222222222222' } } }).io), { ok: false, reason: 'folder-other-vault' });
  assert.deepEqual(await resolveSyncFolder({ vaultId: V, localFolder: OLD }, make({ markers: { [OLD]: { kind: 'unreadable' } } }).io), { ok: false, reason: 'folder-marker-unreadable' });
  assert.deepEqual(await resolveSyncFolder({ vaultId: V, localFolder: OLD }, make().io), { ok: false, reason: 'folder-missing' });
});

test('ids compare case-insensitively (a marker written in lower case matches an upper-case config)', async () => {
  const { io } = make({ markers: { [OLD]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [OLD]: ID } });
  const r = await resolveSyncFolder({ ...ENTRY, vaultId: V.toUpperCase(), syncId: S.toUpperCase() }, io);
  assert.equal(r.ok, true);
});

test('a relocation is accepted only for the folder carrying this sync\'s marker, in an allowed place', () => {
  const entry = { vaultId: V, localFolder: OLD, syncId: S };
  const ok = make({ markers: { [NEW]: { kind: 'ok', syncId: S, vaultId: V } }, identities: { [NEW]: '7:1' } });
  assert.deepEqual(checkRelocation(entry, NEW, ok.io), { ok: true, markerId: '7:1' }, 'the confirmed folder\'s identity is handed back to be recorded');
  assert.deepEqual(checkRelocation(entry, NEW, make({ markers: { [NEW]: { kind: 'absent' } } }).io), { ok: false, reason: 'no-marker' });
  assert.deepEqual(checkRelocation(entry, NEW, make({ markers: { [NEW]: { kind: 'unreadable' } } }).io), { ok: false, reason: 'marker-unreadable' });
  assert.deepEqual(checkRelocation(entry, NEW, make().io), { ok: false, reason: 'folder-missing' });
  assert.deepEqual(checkRelocation(entry, NEW, make({ markers: { [NEW]: { kind: 'ok', syncId: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb', vaultId: V } } }).io), { ok: false, reason: 'other-sync' });
  assert.deepEqual(checkRelocation({ vaultId: V, localFolder: OLD }, NEW, ok.io), { ok: false, reason: 'other-sync' }, 'no sync id recorded: nothing can match');
  const refused = make({ markers: { [NEW]: { kind: 'ok', syncId: S, vaultId: V } }, classify: () => ({ ok: false, reason: 'overlaps-another-sync' }) });
  assert.deepEqual(checkRelocation(entry, NEW, refused.io), { ok: false, reason: 'overlaps-another-sync' });
});

test('a followed move records where the folder came from, so the engine can carry its listings over', async () => {
  const { io, log } = make({ identities: { [NEW]: ID }, find: async () => ({ kind: 'found', folder: NEW }) });
  await resolveSyncFolder(ENTRY, io);
  assert.deepEqual(log.find((l) => l[0] === 'repoint'), ['repoint', V, { localFolder: NEW, syncId: S, markerId: ID, movedFrom: OLD }]);
});

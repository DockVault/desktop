'use strict';

// The Computers view: what it shows for this computer versus the others, where each fact comes from, and
// what each confirmed action does — server first, local drop second, never on a refusal.

const test = require('node:test');
const assert = require('node:assert/strict');

const { createManageView } = require('../src/main/manage-view');

const ME = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OLD = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const V1 = '11111111-1111-4111-8111-111111111111';
const V2 = '22222222-2222-4222-8222-222222222222';
const V3 = '33333333-3333-4333-8333-333333333333';

function harness(over = {}) {
  const log = [];
  const io = {
    signedIn: () => true,
    listDevices: async () => ({ ok: true, devices: [
      { device_id: OTHER, label: 'Laptop', is_active: true, created_at: '2026-01-01T00:00:00Z', last_seen: '2026-02-01T00:00:00Z', expires_at: null },
      { device_id: ME, label: 'Desk', is_active: true, created_at: '2026-01-02T00:00:00Z', last_seen: '2026-02-02T00:00:00Z', expires_at: null },
      { device_id: OLD, label: 'Old', is_active: false, created_at: '2025-01-01T00:00:00Z', last_seen: null, expires_at: null },
    ] }),
    myIdentity: () => ({ status: 'ok', deviceId: ME }),
    myGrants: async () => ({ ok: true, grants: [{ vaultId: V1, grantedAt: '2026-01-03T00:00:00Z', name: 'Photos', metaKnown: true }, { vaultId: V3, grantedAt: null, name: null, metaKnown: false }] }),
    grantRecord: () => ({ status: 'ok', has: (id) => id === V1 }),
    reasonText: (live, name) => (live.reason ? `why: ${live.reason} (${name})` : null),
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: '/home/u/Photos', enabled: true }, { vaultId: V2, vaultName: 'Work', localFolder: '/home/u/Work', enabled: true }],
    liveStatus: () => ({ vaults: [{ vault: V1, state: 'up-to-date', reason: null, running: false, lastSyncedAt: 1700000000000, via: 'device' }, { vault: V2, state: 'paused', reason: 'no-session', running: false, lastSyncedAt: null, via: 'account' }] }),
    endpoint: () => ({ serverHost: 'vault.example.com', sftp: { host: 'files.example.com', port: 2200 } }),
    remotePathFor: (vaultId, via, name) => (via === 'device' ? `vault_${vaultId}` : name),
    revokeGrant: async (d, v) => { log.push(['revokeGrant', d, v]); return { ok: true }; },
    revokeDevice: async (d) => { log.push(['revokeDevice', d]); return { ok: true }; },
    deleteDevice: async (d) => { log.push(['deleteDevice', d]); return { ok: true }; },
    dropLocalVault: (v) => log.push(['dropLocalVault', v]),
    dropLocalIdentity: () => log.push(['dropLocalIdentity']),
    syncNow: (v) => log.push(['syncNow', v]),
    afterChange: () => log.push(['afterChange']),
    ...over,
  };
  return { io, log, view: createManageView(io) };
}

test('the model: this computer first with its vault cards (local side shown), other computers with metadata only, revoked ones last', async () => {
  const h = harness();
  const m = await h.view.model();
  assert.equal(m.kind, 'ok');
  assert.equal(m.serverHost, 'vault.example.com');
  assert.equal(m.remoteHost, 'files.example.com:2200');
  assert.deepEqual(m.computers.map((c) => [c.label, c.isThis, c.isActive]), [['Desk', true, true], ['Laptop', false, true], ['Old', false, false]]);
  const me = m.computers[0];
  assert.deepEqual(me.vaults.map((v) => [v.name, v.granted, !!v.local, v.standing]), [['Photos', true, true, 'device'], ['A vault', true, false, 'device'], ['Work', false, true, 'account']]);
  const photos = me.vaults[0];
  assert.equal(photos.remote, `files.example.com:2200/vault_${V1}`);
  assert.deepEqual(photos.local, { folder: '/home/u/Photos', enabled: true, state: 'up-to-date', reason: null, running: false, lastSyncedAt: 1700000000000, via: 'device', reasonText: null });
  const work = me.vaults[2];
  assert.equal(work.granted, false, 'configured but never recorded here: syncs through the sign-in');
  assert.equal(work.remote, 'files.example.com:2200/Work');
  assert.equal(work.local.via, 'account');
  assert.equal(work.local.reasonText, 'why: no-session (Work)', 'the live reason rides as a sentence');
  const other = m.computers[1];
  assert.equal(other.vaults, null, 'another computer: its vaults are not listable from here');
  assert.equal(other.vaultsUnavailable, 'not-listable');
  assert.equal(JSON.stringify(m).includes('/home/u/Work'), true, 'the local folder appears only under this computer');
  assert.equal(JSON.stringify(m.computers[1]).includes('/home/u'), false);
  assert.equal(m.local, null);
  assert.deepEqual(m.thisComputer, { deviceId: ME, status: 'ok', registered: true });
});

test('not set up as its own computer here: the configured vaults still show in a local block, each by its standing, and no computer is marked as this one', async () => {
  const h = harness({ myIdentity: () => ({ status: 'absent', deviceId: null }) });
  const m = await h.view.model();
  assert.equal(m.thisComputer.registered, false);
  assert.ok(m.computers.every((c) => !c.isThis));
  assert.equal(m.local.status, 'absent');
  // Photos was recorded here (granted once) and the identity is gone: removed, held. Work was never recorded: sign-in.
  assert.deepEqual(m.local.vaults.map((v) => [v.name, v.granted, v.standing]), [['Photos', false, 'removed'], ['Work', false, 'account']]);
});

test('a vault recorded here but no longer granted is "withdrawn" (held), never "syncs through the sign-in"; an identity problem holds every recorded vault', async () => {
  const h = harness({ myGrants: async () => ({ ok: true, grants: [] }) });
  const m = await h.view.model();
  assert.deepEqual(m.computers[0].vaults.map((v) => [v.name, v.standing]), [['Photos', 'withdrawn'], ['Work', 'account']]);
  // A retired/unreadable identity whose id is still known: the listed row is STILL this computer (marked, with the
  // status as a note), its configured vaults shown by standing; no separate local block.
  for (const status of ['stale', 'rechecking', 'unreadable']) {
    const p = harness({ myIdentity: () => ({ status, deviceId: ME }) });
    const pm = await p.view.model();
    assert.equal(pm.local, null, status);
    assert.equal(pm.computers[0].isThis, true); assert.equal(pm.computers[0].identityNote, status);
    assert.deepEqual(pm.computers[0].vaults.map((v) => v.standing), ['identity', 'account'], status);
  }
  // No id known (another server's identity, no secure store): nothing is marked; the local block explains.
  for (const status of ['absent-for-this-server', 'no-secure-store', 'unreadable']) {
    const p = harness({ myIdentity: () => ({ status, deviceId: null }) });
    const pm = await p.view.model();
    assert.equal(pm.local.status, status, status);
    assert.ok(pm.computers.every((c) => !c.isThis));
    assert.deepEqual(pm.local.vaults.map((v) => v.standing), ['identity', 'account'], status);
  }
});

test('an identity the server no longer lists: the local block says so and keeps the configured vaults reachable', async () => {
  const h = harness({ listDevices: async () => ({ ok: true, devices: [{ device_id: OTHER, label: 'Laptop', is_active: true }] }) });
  const m = await h.view.model();
  assert.equal(m.thisComputer.registered, false);
  assert.equal(m.local.status, 'not-listed');
  assert.deepEqual(m.local.vaults.map((v) => [v.name, v.granted]), [['Photos', true], ['A vault', true], ['Work', false]], 'the grant list still answered, so its cards are shown');
});

test('two model reads in flight share one build; two actions in flight refuse the second as busy', async () => {
  let builds = 0;
  const h = harness({ listDevices: async () => { builds++; await new Promise((r) => setTimeout(r, 20)); return { ok: true, devices: [] }; } });
  const [a, b] = await Promise.all([h.view.model(), h.view.model()]);
  assert.equal(builds, 1); assert.equal(a, b);
  let release;
  const slow = harness({ revokeDevice: () => new Promise((r) => { release = r; }) });
  const first = slow.view.act({ kind: 'revoke-computer', deviceId: OTHER });
  await new Promise((r) => setImmediate(r));
  assert.deepEqual(await slow.view.act({ kind: 'sync-now', vaultId: V1 }), { ok: false, reason: 'busy' });
  release({ ok: true });
  assert.deepEqual(await first, { ok: true });
});

test('device ids are the server\'s opaque strings, compared exactly; a stale identity with a matching id still counts as this computer for the local drop', async () => {
  const h = harness({ listDevices: async () => ({ ok: true, devices: [{ device_id: 'dev_01HXYZ.Q-7', label: 'Odd', is_active: true }] }), myIdentity: () => ({ status: 'ok', deviceId: 'dev_01HXYZ.Q-7' }) });
  const m = await h.view.model();
  assert.equal(m.computers[0].isThis, true);
  assert.deepEqual(await h.view.act({ kind: 'revoke-computer', deviceId: 'dev_01HXYZ.Q-7' }), { ok: true });
  assert.deepEqual(h.log, [['revokeDevice', 'dev_01HXYZ.Q-7'], ['dropLocalIdentity'], ['afterChange']]);
  for (const bad of ['a b', 'x/y', '', 'x'.repeat(129)]) assert.deepEqual(await h.view.act({ kind: 'revoke-computer', deviceId: bad }), { ok: false, reason: 'bad-request' });
  const stale = harness({ myIdentity: () => ({ status: 'stale', deviceId: ME }) });
  await stale.view.act({ kind: 'revoke-computer', deviceId: ME });
  assert.deepEqual(stale.log, [['revokeDevice', ME], ['dropLocalIdentity'], ['afterChange']]);
});

test('the gates: not signed in; a server without device routes; an unreadable device list; this computer\'s grant list refused', async () => {
  assert.deepEqual(await harness({ signedIn: () => false }).view.model(), { kind: 'sign-in' });
  assert.equal((await harness({ listDevices: async () => ({ ok: false, reason: 'too-old' }) }).view.model()).kind, 'unsupported');
  assert.equal((await harness({ listDevices: async () => ({ ok: false, reason: 'auth' }) }).view.model()).kind, 'sign-in');
  assert.equal((await harness({ listDevices: async () => ({ ok: false, reason: 'indeterminate' }) }).view.model()).kind, 'unavailable');
  const g = harness({ myGrants: async () => ({ ok: false, reason: 'device-suspended' }) });
  const m = await g.view.model();
  assert.equal(m.computers[0].vaults, null);
  assert.equal(m.computers[0].vaultsUnavailable, 'device-suspended');
});

test('revoke a grant: the server call first; for THIS computer the local pointer is dropped too; for another computer nothing local changes; a refusal changes nothing', async () => {
  const h = harness();
  assert.deepEqual(await h.view.act({ kind: 'revoke-grant', deviceId: ME, vaultId: V1 }), { ok: true });
  assert.deepEqual(h.log, [['revokeGrant', ME, V1], ['dropLocalVault', V1], ['afterChange']]);
  h.log.length = 0;
  assert.deepEqual(await h.view.act({ kind: 'revoke-grant', deviceId: OTHER, vaultId: V1 }), { ok: true });
  assert.deepEqual(h.log, [['revokeGrant', OTHER, V1], ['afterChange']]);
  const refused = harness();
  refused.io.revokeGrant = async (d, v) => { refused.log.push(['revokeGrant', d, v]); return { ok: false, reason: 'not-found' }; };
  assert.deepEqual(await refused.view.act({ kind: 'revoke-grant', deviceId: ME, vaultId: V1 }), { ok: false, reason: 'not-found' });
  assert.deepEqual(refused.log, [['revokeGrant', ME, V1]], 'no local drop on a refusal');
});

test('revoke / remove a computer: the server call first; this computer also clears its local identity; a refusal changes nothing', async () => {
  const h = harness();
  assert.deepEqual(await h.view.act({ kind: 'revoke-computer', deviceId: OTHER }), { ok: true });
  assert.deepEqual(h.log, [['revokeDevice', OTHER], ['afterChange']]);
  h.log.length = 0;
  assert.deepEqual(await h.view.act({ kind: 'revoke-computer', deviceId: ME }), { ok: true });
  assert.deepEqual(h.log, [['revokeDevice', ME], ['dropLocalIdentity'], ['afterChange']]);
  h.log.length = 0;
  assert.deepEqual(await h.view.act({ kind: 'remove-computer', deviceId: OLD }), { ok: true });
  assert.deepEqual(h.log, [['deleteDevice', OLD], ['afterChange']]);
  const refused = harness();
  refused.io.revokeDevice = async (d) => { refused.log.push(['revokeDevice', d]); return { ok: false, reason: 'refused' }; };
  assert.deepEqual(await refused.view.act({ kind: 'revoke-computer', deviceId: ME }), { ok: false, reason: 'refused' });
  assert.deepEqual(refused.log, [['revokeDevice', ME]], 'the local identity stays on a refusal');
});

test('stop-sync and sync-now act locally on this computer only; an unreadable config is its own reason', async () => {
  const h = harness();
  assert.deepEqual(await h.view.act({ kind: 'stop-sync', vaultId: V2 }), { ok: true });
  assert.deepEqual(await h.view.act({ kind: 'sync-now', vaultId: V1 }), { ok: true });
  assert.deepEqual(h.log, [['dropLocalVault', V2], ['afterChange'], ['syncNow', V1]]);
  const bad = harness({ dropLocalVault: () => { const e = new Error('refuse'); e.code = 'CONFIG_UNREADABLE'; throw e; } });
  assert.deepEqual(await bad.view.act({ kind: 'stop-sync', vaultId: V2 }), { ok: false, reason: 'config-unreadable' });
});

test('malformed ids and unknown kinds are refused before anything is called', async () => {
  const h = harness();
  for (const a of [{ kind: 'revoke-grant', deviceId: 'a b', vaultId: V1 }, { kind: 'revoke-grant', deviceId: ME, vaultId: '../x' }, { kind: 'revoke-grant', deviceId: 'a/b', vaultId: V1 }, { kind: 'revoke-computer', deviceId: { toString: () => ME } }, { kind: 'stop-sync', vaultId: 'Photos' }, { kind: 'nuke' }, null, 'revoke-computer']) {
    assert.deepEqual(await h.view.act(a), { ok: false, reason: 'bad-request' }, JSON.stringify(a));
  }
  assert.deepEqual(h.log, []);
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { decideMintPath, deviceRemotePath, MintPathSelector } = require('../src/main/mint-path');

const V = '3f2b1c0a-9d8e-4f7a-b6c5-d4e3f2a1b0c9';
const OTHER = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee';
const grant = (o = {}) => ({ vaultId: V, grantedAt: null, name: 'Payroll', vaultType: 'standard', hasPassword: true, metaKnown: true, ...o });
const ok = (grants) => ({ ok: true, grants });
const rec = (hasEntry, status = 'ok') => ({ status, hasEntry });

test('decide: an unreadable device secret PAUSES — never "not registered", never the account path', () => {
  for (const grants of [ok([grant()]), { ok: false, reason: 'device-revoked' }, null]) {
    assert.deepStrictEqual(decideMintPath({ secretStatus: 'unreadable', grants, record: rec(true), vaultId: V }), { ok: false, reason: 'device-secret-unreadable' });
  }
});

test('decide: a STALE identity (a lost rotation answer) refuses with the server literal — never the account path, never a mint', () => {
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'stale', grants: ok([grant()]), record: rec(true), vaultId: V }), { ok: false, reason: 'device-secret-stale' });
  // a rotation cut off mid-flight, not yet reconciled: a calm "being re-checked", distinct from the terminal retired 'stale'
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'rechecking', grants: ok([grant()]), record: rec(true), vaultId: V }), { ok: false, reason: 'device-being-rechecked' });
});

test('decide: no device identity here (no secure store / another server) -> the account path, and the grants are not consulted', () => {
  for (const s of ['no-secure-store', 'absent-for-this-server', undefined, null, 'weird']) {
    assert.deepStrictEqual(decideMintPath({ secretStatus: s, grants: null, record: null, vaultId: V }), { ok: true, via: 'account' });
  }
});

test('decide: an ABSENT identity keeps the account path only for a vault never recorded here; a vault this computer once synced on its own identity is device-removed (never a quiet account fallback); an unreadable record pauses', () => {
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'absent', grants: null, record: rec(false), vaultId: V }), { ok: true, via: 'account' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'absent', grants: null, record: rec(false, 'absent'), vaultId: V }), { ok: true, via: 'account' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'absent', grants: null, record: rec(true), vaultId: V }), { ok: false, reason: 'device-removed' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'absent', grants: null, record: rec(false, 'unreadable'), vaultId: V }), { ok: false, reason: 'device-state-unreadable' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'absent', grants: null, record: null, vaultId: V }), { ok: false, reason: 'device-state-unreadable' });
});

test('decide: a registered device whose grant list FAILED surfaces the typed device reason — never an account-path run', () => {
  for (const reason of ['device-revoked', 'device-expired', 'device-suspended', 'device-secret-stale', 'invalid-device-credential', 'account-inactive', 'network', 'grants-unreadable', 'device-request-refused']) {
    assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: { ok: false, reason }, record: rec(false), vaultId: V }), { ok: false, reason });
  }
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: null, record: rec(false), vaultId: V }), { ok: false, reason: 'device-request-refused' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: { ok: false }, record: rec(false), vaultId: V }), { ok: false, reason: 'device-request-refused' });
});

test('decide: an active grant for the vault with a recorded Standard tier -> the device path; unknown details WAIT (never the account path)', () => {
  const d = decideMintPath({ secretStatus: 'ok', grants: ok([grant({ vaultId: OTHER }), grant()]), record: rec(true), vaultId: V });
  assert.strictEqual(d.ok, true); assert.strictEqual(d.via, 'device'); assert.strictEqual(d.grant.vaultId, V);
  for (const record of [rec(false, 'unreadable'), rec(false), rec(true)]) {
    const unknown = decideMintPath({ secretStatus: 'ok', grants: ok([grant({ name: null, vaultType: null, hasPassword: null, metaKnown: false })]), record, vaultId: V });
    assert.deepStrictEqual(unknown, { ok: false, reason: 'grant-details-pending' });
  }
  // metaKnown must be an explicit true; a grant that claims a tier without metaKnown still waits
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: ok([grant({ metaKnown: undefined })]), record: rec(true), vaultId: V }), { ok: false, reason: 'grant-details-pending' });
});

test('decide: a KNOWN non-Standard tier refuses locally before any mint (exact "standard" only)', () => {
  for (const t of ['zero_knowledge', 'zero-knowledge', 'Standard', 'STANDARD', ' standard', '', null, undefined, 42]) {
    assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: ok([grant({ vaultType: t, metaKnown: true })]), record: rec(true), vaultId: V }), { ok: false, reason: 'vault-not-standard' }, `tier ${JSON.stringify(t)}`);
  }
});

test('decide: no grant for the vault -> withdrawn (no-grant) when recorded here, account path when never recorded, pause when the record is unreadable', () => {
  const none = ok([grant({ vaultId: OTHER })]);
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: none, record: rec(true), vaultId: V }), { ok: false, reason: 'no-grant' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: none, record: rec(false), vaultId: V }), { ok: true, via: 'account' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: none, record: rec(false, 'absent'), vaultId: V }), { ok: true, via: 'account' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: none, record: rec(false, 'unreadable'), vaultId: V }), { ok: false, reason: 'device-state-unreadable' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: none, record: null, vaultId: V }), { ok: false, reason: 'device-state-unreadable' });
  // a malformed grants field reads as no grants, never as a match
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: { ok: true, grants: 'nope' }, record: rec(true), vaultId: V }), { ok: false, reason: 'no-grant' });
  assert.deepStrictEqual(decideMintPath({ secretStatus: 'ok', grants: ok([null, 7, { vaultId: 42 }, { vaultId: null }]), record: rec(true), vaultId: V }), { ok: false, reason: 'no-grant' });
});

test('deviceRemotePath: the rename-proof machine form vault_<id>, lower-cased, one safe segment; anything else throws', () => {
  assert.strictEqual(deviceRemotePath(V), `vault_${V}`);
  assert.strictEqual(deviceRemotePath(V.toUpperCase()), `vault_${V}`);
  for (const bad of ['', 'Payroll', '../x', 'vault_' + V, V + '/x', `${V}\\`, 42, null, undefined, 'not-a-uuid-at-all-0000']) {
    assert.throws(() => deviceRemotePath(bad), Error, `id ${JSON.stringify(bad)}`);
  }
});

function selector(o = {}) {
  const calls = { grants: 0, record: 0, secret: 0 };
  const s = new MintPathSelector({
    readSecret: () => { calls.secret++; if (o.secretThrows) throw new Error('boom'); return { status: o.secret || 'ok' }; },
    listGrants: async () => { calls.grants++; if (o.grantsThrows) throw new Error('boom'); return o.grants || ok([grant()]); },
    readGrantRecord: () => { calls.record++; if (o.recordThrows) throw new Error('boom'); return o.record || { status: 'ok', meta: { [V]: {} } }; },
  });
  return { s, calls };
}

test('selector: begin decides + latches the device path with the id-keyed remote path and the recorded name; end clears it', async () => {
  const { s, calls } = selector();
  assert.strictEqual(s.current(V), null);
  assert.deepStrictEqual(await s.begin(V), { ok: true, via: 'device', remotePath: `vault_${V}`, vaultName: 'Payroll' });
  assert.strictEqual(s.current(V), 'device');
  assert.strictEqual(s.current(OTHER), null);
  assert.deepStrictEqual(calls, { secret: 1, grants: 1, record: 1 });
  s.end(V);
  assert.strictEqual(s.current(V), null);
});

test('selector: the account path latches too, without consulting the grants when there is no device identity', async () => {
  const { s, calls } = selector({ secret: 'absent', record: { status: 'absent', meta: {} } });
  assert.deepStrictEqual(await s.begin(V), { ok: true, via: 'account' });
  assert.strictEqual(s.current(V), 'account');
  assert.deepStrictEqual(calls, { secret: 1, grants: 0, record: 1 }, 'the grant record is read (was this vault ever synced on a device identity here?), the grants are not');
});

test('selector: a refusal latches NOTHING (a per-step mint then finds no path), and a fresh begin re-decides', async () => {
  const { s } = selector({ grants: { ok: false, reason: 'device-revoked' } });
  assert.deepStrictEqual(await s.begin(V), { ok: false, reason: 'device-revoked' });
  assert.strictEqual(s.current(V), null);
  const { s: sel2 } = selector({ secret: 'unreadable' });
  assert.deepStrictEqual(await sel2.begin(V), { ok: false, reason: 'device-secret-unreadable' });
  assert.strictEqual(sel2.current(V), null);
});

test('selector: throwing reads fail CLOSED on the device side (never the account path)', async () => {
  assert.deepStrictEqual(await selector({ secretThrows: true }).s.begin(V), { ok: false, reason: 'device-secret-unreadable' });
  assert.deepStrictEqual(await selector({ grantsThrows: true }).s.begin(V), { ok: false, reason: 'device-request-refused' });
  assert.deepStrictEqual(await selector({ grants: ok([grant({ vaultId: OTHER })]), recordThrows: true }).s.begin(V), { ok: false, reason: 'device-state-unreadable' });
  // a record that throws does not matter when the grant IS present — the server grant is the authority
  const d = await selector({ recordThrows: true }).s.begin(V);
  assert.strictEqual(d.via, 'device');
});

test('selector: an unreadable local record (any non-ok/absent status) with no server grant pauses; a readable one decides withdrawn vs not-moved-over', async () => {
  const none = ok([grant({ vaultId: OTHER })]);
  for (const status of ['undecryptable', 'unparseable', 'unreadable-io', 'weird']) {
    assert.deepStrictEqual(await selector({ grants: none, record: { status, meta: {} } }).s.begin(V), { ok: false, reason: 'device-state-unreadable' }, status);
  }
  assert.deepStrictEqual(await selector({ grants: none, record: { status: 'ok', meta: { [V]: {} } } }).s.begin(V), { ok: false, reason: 'no-grant' });
  assert.deepStrictEqual(await selector({ grants: none, record: { status: 'absent', meta: {} } }).s.begin(V), { ok: true, via: 'account' });
  assert.deepStrictEqual(await selector({ grants: none, record: { status: 'ok', meta: {} } }).s.begin(V), { ok: true, via: 'account' });
  // own-property only: a prototype member never reads as a recorded grant
  assert.deepStrictEqual(await selector({ grants: ok([grant({ vaultId: OTHER })]), record: { status: 'ok', meta: {} } }).s.begin('constructor'), { ok: true, via: 'account' });
});

test('selector: a grant with unknown details waits, is backfilled ONCE from an account session when one is offered, and then decides on the filled-in tier', async () => {
  const pending = ok([grant({ name: null, vaultType: null, hasPassword: null, metaKnown: false })]);
  // no backfill hook: waits
  const { s: sel0 } = selector({ grants: pending, record: { status: 'undecryptable', meta: {} } });
  assert.deepStrictEqual(await sel0.begin(V), { ok: false, reason: 'grant-details-pending' });
  assert.strictEqual(sel0.current(V), null);
  // a backfill that cannot help (no session / null / throws / no tier): still waits, still no latch
  for (const backfill of [async () => null, async () => { throw new Error('no session'); }, async () => ({ name: 'X' }), async () => 'junk']) {
    const { s } = selector({ grants: pending, record: { status: 'ok', meta: {} } });
    s._io.backfill = backfill;
    assert.deepStrictEqual(await s.begin(V), { ok: false, reason: 'grant-details-pending' });
    assert.strictEqual(s.current(V), null);
  }
  // a backfill that returns the details: the device path proceeds with the filled-in name, ONE call
  const { s: sel1 } = selector({ grants: pending, record: { status: 'ok', meta: {} } });
  let calls = 0;
  sel1._io.backfill = async (id) => { calls++; assert.strictEqual(id, V); return { name: 'Payroll', vaultType: 'standard', hasPassword: true }; };
  assert.deepStrictEqual(await sel1.begin(V), { ok: true, via: 'device', remotePath: `vault_${V}`, vaultName: 'Payroll' });
  assert.strictEqual(calls, 1);
  assert.strictEqual(sel1.current(V), 'device');
  // a backfill that reveals a non-Standard tier refuses locally
  const { s: sel2z } = selector({ grants: pending, record: { status: 'ok', meta: {} } });
  sel2z._io.backfill = async () => ({ name: 'Secret', vaultType: 'zero_knowledge', hasPassword: false });
  assert.deepStrictEqual(await sel2z.begin(V), { ok: false, reason: 'vault-not-standard' });
  // the backfill is never consulted when the details are already known
  const { s: sel3 } = selector();
  sel3._io.backfill = async () => { throw new Error('must not be called'); };
  assert.strictEqual((await sel3.begin(V)).via, 'device');
});

test('selector: a non-uuid vault id on the device path fails closed without a latch', async () => {
  const { s: sel2 } = selector({ grants: ok([grant({ vaultId: 'Payroll' })]) });
  assert.deepStrictEqual(await sel2.begin('Payroll'), { ok: false, reason: 'bad-vault-name' });
  assert.strictEqual(sel2.current('Payroll'), null);
});

test('selector: the latch is per vault and survives until end() — a second begin replaces it', async () => {
  const { s } = selector();
  await s.begin(V);
  const { s: acct } = selector({ secret: 'absent' });
  await acct.begin(OTHER);
  assert.strictEqual(s.current(V), 'device');
  assert.strictEqual(acct.current(OTHER), 'account');
  // the same selector, the same vault, a changed world: begin re-decides (a new run), current() follows
  s._io.readSecret = () => ({ status: 'absent' });
  s._io.readGrantRecord = () => ({ status: 'absent', meta: {} });
  assert.deepStrictEqual(await s.begin(V), { ok: true, via: 'account' });
  assert.strictEqual(s.current(V), 'account');
});

test('selector: after a revoke wiped the identity, a fresh selector refuses a recorded vault as device-removed with no account mint; an unrecorded vault keeps the account path', async () => {
  const { s: removed, calls } = selector({ secret: 'absent', record: { status: 'ok', meta: { [V]: { name: 'Payroll', vaultType: 'standard', hasPassword: true } } } });
  assert.deepStrictEqual(await removed.begin(V), { ok: false, reason: 'device-removed' });
  assert.strictEqual(removed.current(V), null, 'nothing is latched: no account path, no mint');
  assert.deepStrictEqual(calls, { secret: 1, grants: 0, record: 1 });
  const { s: fresh } = selector({ secret: 'absent', record: { status: 'absent', meta: {} } });
  assert.deepStrictEqual(await fresh.begin(V), { ok: true, via: 'account' });
  assert.strictEqual(fresh.current(V), 'account');
  // a vault id spelling a prototype member never reads as recorded
  const { s: proto } = selector({ secret: 'absent', record: { status: 'ok', meta: {} } });
  assert.deepStrictEqual(await proto.begin('constructor'), { ok: true, via: 'account' });
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { grantDeviceVault, listMyGrants, grantAndRecord } = require('../src/main/device-grant');
const { ROUTES } = require('../src/main/device-http');

const ORIGIN = 'https://vault.example';
const ACCOUNT = 'account-jwt-token-DO-NOT-LOG';
const DEVICE_ID = 'dev-11112222-3333-4444';
const VAULT_ID = 'vault-aaaa-bbbb';
const PASSWORD = 'vault-proof-DO-NOT-PERSIST-987';

function res(status, body) { return { ok: status >= 200 && status < 300, status, json: async () => body }; }
function mockFetch(handler) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url, init, method: (init && init.method) || 'GET' }); return handler({ url, init }); };
  fn.calls = calls;
  return fn;
}
const grantPath = `${ORIGIN}/devices/${DEVICE_ID}/grants`;

test('happy (password vault): account-Bearer POST carries the proof once; returns hasPassword + grantedAt', async () => {
  const fetchFn = mockFetch(() => res(200, { device_id: DEVICE_ID, vault_id: VAULT_ID, is_active: true, password_protected: true, granted_at: '2026-09-04T00:00:00Z' }));
  const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD }, { fetchFn });
  assert.deepStrictEqual(r, { ok: true, vaultId: VAULT_ID, hasPassword: true, grantedAt: '2026-09-04T00:00:00Z' });
  // Exactly one call, to the grant route, under the ACCOUNT Bearer, carrying the proof once.
  assert.strictEqual(fetchFn.calls.length, 1);
  const { url, init } = fetchFn.calls[0];
  assert.strictEqual(url, grantPath);
  assert.strictEqual(init.method, 'POST');
  assert.strictEqual(init.headers.Authorization, `Bearer ${ACCOUNT}`);
  assert.deepStrictEqual(JSON.parse(init.body), { vault_id: VAULT_ID, vault_password: PASSWORD });
});

test('no-password vault: the body carries no vault_password; hasPassword:false', async () => {
  const fetchFn = mockFetch(() => res(200, { password_protected: false, granted_at: null }));
  const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard' }, { fetchFn });
  assert.deepStrictEqual(r, { ok: true, vaultId: VAULT_ID, hasPassword: false, grantedAt: null });
  assert.deepStrictEqual(JSON.parse(fetchFn.calls[0].init.body), { vault_id: VAULT_ID });
});

test('grant sanitizes a non-string granted_at to null (the cache never stores a bogus timestamp)', async () => {
  const fetchFn = mockFetch(() => res(200, { password_protected: true, granted_at: 1700000000 }));
  const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD }, { fetchFn });
  assert.deepStrictEqual(r, { ok: true, vaultId: VAULT_ID, hasPassword: true, grantedAt: null });
});

test('the tier gate fails CLOSED: anything but an exact "standard" refuses LOCALLY, no POST, no password on the wire', async () => {
  // The most catastrophic gate defaults to refuse: a missing / null / mis-cased / future / ZK tier must
  // never put a zero-knowledge passphrase on the wire. Only an explicit 'standard' proceeds.
  for (const vaultType of ['zero_knowledge', 'zero-knowledge', 'ZERO_KNOWLEDGE', 'Standard', 'STANDARD', ' standard', 'standard ', undefined, null, '', 42, {}]) {
    const fetchFn = mockFetch(() => res(200, {}));
    const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType, vaultPassword: PASSWORD }, { fetchFn });
    assert.deepStrictEqual(r, { ok: false, reason: 'vault-not-standard' }, `vaultType ${JSON.stringify(vaultType)} must refuse locally`);
    assert.strictEqual(fetchFn.calls.length, 0, `vaultType ${JSON.stringify(vaultType)} never sends the password`);
  }
});

test('grant refusals map to fixed reasons without a body leak', async () => {
  const mk = (status) => grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD },
    { fetchFn: mockFetch(() => res(status, { detail: 'a human string' })) });
  assert.deepStrictEqual(await mk(400), { ok: false, reason: 'wrong-password' }); // ZK pre-filtered, so 400 = bad proof
  assert.deepStrictEqual(await mk(429), { ok: false, reason: 'rate-limited' });
  assert.deepStrictEqual(await mk(404), { ok: false, reason: 'vault-not-accessible' });
  assert.deepStrictEqual(await mk(401), { ok: false, reason: 'auth' });
  assert.deepStrictEqual(await mk(403), { ok: false, reason: 'auth' });
  assert.deepStrictEqual(await mk(500), { ok: false, reason: 'grant-failed' });
});

test('an empty deviceId or vaultId is refused LOCALLY (grant-failed) with no request and no password on the wire', async () => {
  for (const [deviceId, vaultId] of [['', VAULT_ID], [undefined, VAULT_ID], [null, VAULT_ID], [42, VAULT_ID], [DEVICE_ID, ''], [DEVICE_ID, undefined], [DEVICE_ID, null]]) {
    const fetchFn = mockFetch(() => res(200, { password_protected: true }));
    const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId, vaultId, vaultType: 'standard', vaultPassword: PASSWORD }, { fetchFn });
    assert.deepStrictEqual(r, { ok: false, reason: 'grant-failed' });
    assert.strictEqual(fetchFn.calls.length, 0, 'a malformed identity never reaches the network');
  }
});

test('a 2xx whose body cannot be read still counts as granted, with conservative metadata (hasPassword:false, grantedAt:null)', async () => {
  const fetchFn = mockFetch(() => ({ ok: true, status: 200, json: async () => { throw new Error(`bad json ${PASSWORD}`); } }));
  const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD }, { fetchFn });
  assert.deepStrictEqual(r, { ok: true, vaultId: VAULT_ID, hasPassword: false, grantedAt: null });
  assert.strictEqual(fetchFn.calls.length, 1);
});

test('a transport failure fails closed to reason "network"', async () => {
  const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD },
    { fetchFn: async () => { throw new Error(`connect failed with pw ${PASSWORD}`); } });
  assert.deepStrictEqual(r, { ok: false, reason: 'network' }); // the transport message (which embeds the pw here) is never surfaced
});

test('prove-once: the vault password is sent in exactly one request and never in a result', async () => {
  const fetchFn = mockFetch(() => res(200, { password_protected: true, granted_at: null }));
  const r = await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD }, { fetchFn });
  const carrying = fetchFn.calls.filter((c) => String(c.init && c.init.body || '').includes(PASSWORD));
  assert.strictEqual(carrying.length, 1, 'the password rides exactly one request');
  assert.ok(!JSON.stringify(r).includes(PASSWORD), 'no result carries the vault password');
});

test('NEVER-LOGGED: no grant path writes the vault password or account token to any log sink', async () => {
  const seen = [];
  const methods = ['log', 'info', 'warn', 'error', 'debug'];
  const oc = {}; for (const m of methods) { oc[m] = console[m]; console[m] = (...a) => { seen.push(a.map(String).join(' ')); }; }
  const so = process.stdout.write.bind(process.stdout);
  const se = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c) => { seen.push(String(c)); return true; };
  process.stderr.write = (c) => { seen.push(String(c)); return true; };
  let selfCheck = false;
  try {
    console.log('planted', PASSWORD);
    selfCheck = seen.some((l) => l.includes(PASSWORD));
    seen.length = 0;
    await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD },
      { fetchFn: mockFetch(() => res(200, { password_protected: true, granted_at: null })) });
    await grantDeviceVault({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultPassword: PASSWORD },
      { fetchFn: mockFetch(() => res(400, { detail: 'wrong' })) });
  } finally {
    for (const m of methods) console[m] = oc[m];
    process.stdout.write = so;
    process.stderr.write = se;
  }
  assert.ok(selfCheck, 'self-check: the capture catches a planted secret (non-vacuous)');
  const swept = seen.join('\n');
  const b64 = Buffer.from(PASSWORD, 'utf8').toString('base64');
  assert.ok(!swept.includes(PASSWORD) && !swept.includes(b64), 'no vault password in any log sink');
  assert.ok(!swept.includes(ACCOUNT), 'no account token in any log sink');
});

test('the grant module is fingerprint-blind, persists nothing, and stays out of the device-Bearer allowlist', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'device-grant.js'), 'utf8');
  // Fingerprint-blind: the client never COMPUTES or holds a fingerprint (the server owns it) — no
  // hashing and no touch of the server's fingerprint field. (The docstring may explain the property;
  // what matters is that no code computes one.)
  assert.ok(!/createHash|node:crypto|require\('crypto'\)|\.digest\(/.test(src), 'device-grant.js must not hash / compute a fingerprint');
  assert.ok(!/vault_password_fingerprint/.test(src), 'device-grant.js must not touch the server fingerprint field');
  // No persistence: it never writes the password anywhere. Targets actual USAGE (require statements and
  // write/encrypt calls), so the docstring may name these while the code uses none.
  for (const forbidden of ["require('node:fs')", "require('fs')", "require('./device-secret-store')", "require('./state-db')", 'writeFileSync', 'encryptString', 'safeStorage.']) {
    assert.ok(!src.includes(forbidden), `device-grant.js must not use ${forbidden} (the vault password is transient)`);
  }
  // Grant-CREATE is account-only (accountInit, never the device client). The device-Bearer client is
  // used ONLY for the READ-ONLY grants list — every deviceRequest call in this module names the 'grants'
  // route, never a write route (mint/refresh).
  assert.ok(src.includes('accountInit'), 'grant-create rides the account Bearer');
  const routeCalls = src.match(/route:\s*'[a-z]+'/g) || [];
  assert.ok(routeCalls.length > 0 && routeCalls.every((r) => /route:\s*'grants'/.test(r)),
    'the device client is used read-only (the grants list) only — never for mint/refresh/a write');
  // The device-Bearer allowlist has NO grant-create (write) route — grants is read-only GET.
  assert.deepStrictEqual(Object.keys(ROUTES).sort(), ['grants', 'mint', 'refresh']);
  assert.strictEqual(ROUTES.grants.method, 'GET', 'a device may only LIST grants, never create one');
});

// ---- listMyGrants: device-Bearer active grants JOINED with the local metadata cache -------------
// The store is read ONCE, status-aware: a double supplies readGrantMeta(safe,dir)->{status,meta} and
// isUnreadable(status)->bool, exactly the shape the real device-grant-store exports.
function metaStore(map, status) {
  return {
    readGrantMeta: () => ({ status: status || 'ok', meta: map || {} }),
    isUnreadable: (s) => s === 'undecryptable' || s === 'unparseable' || s === 'unreadable-io',
  };
}

test('listMyGrants joins the authoritative active grants with the local metadata (cache miss -> name-unknown)', async () => {
  const store = metaStore({ v1: { name: 'Payroll', vaultType: 'standard', hasPassword: true } });
  const fetchFn = mockFetch(() => res(200, { grants: [{ vault_id: 'v1', granted_at: 't1' }, { vault_id: 'v2', granted_at: 't2' }] }));
  const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} }, { fetchFn, store });
  assert.deepStrictEqual(r, {
    ok: true,
    grants: [
      { vaultId: 'v1', grantedAt: 't1', name: 'Payroll', vaultType: 'standard', hasPassword: true, metaKnown: true },
      { vaultId: 'v2', grantedAt: 't2', name: null, vaultType: null, hasPassword: null, metaKnown: false },
    ],
  });
});

test('listMyGrants fails closed with the device-Bearer typed reason on a device error', async () => {
  const fetchFn = mockFetch(() => res(401, { detail: { reason: 'device-revoked' } }));
  const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} }, { fetchFn, store: metaStore({}) });
  assert.deepStrictEqual(r, { ok: false, reason: 'device-revoked' });
});

test('listMyGrants returns an empty list when the device has no active grants', async () => {
  const fetchFn = mockFetch(() => res(200, { grants: [] }));
  const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} }, { fetchFn, store: metaStore({}) });
  assert.deepStrictEqual(r, { ok: true, grants: [] });
});

test('listMyGrants fails closed (grants-unreadable) when a 2xx body is not a grant array', async () => {
  for (const bad of [{}, { grants: null }, { grants: 'nope' }, { grants: { 0: 'x' } }]) {
    const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} },
      { fetchFn: mockFetch(() => res(200, bad)), store: metaStore({}) });
    assert.deepStrictEqual(r, { ok: false, reason: 'grants-unreadable' }, `a non-array grants (${JSON.stringify(bad)}) is unintelligible, not empty`);
  }
});

test('listMyGrants treats an unreadable cache as name-unknown, never as "no grant" (every metaKnown:false)', async () => {
  // A locked keyring / corrupt file must NOT masquerade as "this vault has no metadata"; it degrades to
  // name-unknown for all, backfilled from an account session later — never a fabricated name.
  const store = metaStore({ v1: { name: 'Payroll', vaultType: 'standard', hasPassword: true } }, 'undecryptable');
  const fetchFn = mockFetch(() => res(200, { grants: [{ vault_id: 'v1', granted_at: 't1' }] }));
  const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: true, grants: [{ vaultId: 'v1', grantedAt: 't1', name: null, vaultType: null, hasPassword: null, metaKnown: false }] });
});

test('listMyGrants never resolves a vault_id to an inherited Object.prototype member', async () => {
  // A server vault_id colliding with a prototype key ('constructor'/'__proto__'/'toString') must not
  // pick up an inherited value from a plain-object cache — own-property lookup only.
  const store = metaStore({}); // plain {} map: 'constructor' etc. are inherited, never own
  const fetchFn = mockFetch(() => res(200, { grants: [{ vault_id: 'constructor', granted_at: 't1' }, { vault_id: '__proto__', granted_at: 't2' }, { vault_id: 'toString', granted_at: 't3' }] }));
  const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} }, { fetchFn, store });
  for (const g of r.grants) assert.deepStrictEqual({ metaKnown: g.metaKnown, name: g.name }, { metaKnown: false, name: null }, `${g.vaultId} must not inherit metadata`);
});

test('listMyGrants sanitizes a non-string granted_at to null (never trusts the server field shape)', async () => {
  const store = metaStore({ v1: { name: 'P', vaultType: 'standard', hasPassword: false } });
  const fetchFn = mockFetch(() => res(200, { grants: [{ vault_id: 'v1', granted_at: 1700000000 }, { vault_id: 'v9' /* no granted_at */ }] }));
  const r = await listMyGrants({ serverOrigin: ORIGIN, deviceSecret: 'S', dir: '/x', safeStorage: {} }, { fetchFn, store });
  assert.strictEqual(r.grants[0].grantedAt, null, 'a numeric granted_at is not a timestamp string');
  assert.strictEqual(r.grants[1].grantedAt, null, 'a missing granted_at is null');
});

test('grantAndRecord: a grant that succeeded stands even when the local record cannot be written — recorded:false, never grant-failed, never a revoke', async () => {
  const calls = [];
  const fetchFn = mockFetch(({ url, init }) => { calls.push({ url, method: init && init.method }); return res(200, { password_protected: true, granted_at: '2026-09-05T10:00:00Z' }); });
  const throwing = { setGrantMeta: () => { const e = new Error('no secure store'); e.code = 'GRANT_META_NO_SECURE_STORE'; throw e; } };
  const r = await grantAndRecord({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultName: 'Payroll', vaultPassword: PASSWORD, dir: '/nowhere', safeStorage: null }, { fetchFn, store: throwing });
  assert.deepStrictEqual(r, { ok: true, vaultId: VAULT_ID, hasPassword: true, grantedAt: '2026-09-05T10:00:00Z', recorded: false });
  assert.deepStrictEqual(calls, [{ url: grantPath, method: 'POST' }], 'exactly the one grant-create call — no revoke, no retry');
  // an unreadable existing record refuses the write the same way; the grant still stands
  const unreadable = { setGrantMeta: () => { const e = new Error('unreadable'); e.code = 'GRANT_META_UNREADABLE'; throw e; } };
  const r2 = await grantAndRecord({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultName: 'Payroll', vaultPassword: PASSWORD, dir: '/nowhere', safeStorage: null }, { fetchFn, store: unreadable });
  assert.strictEqual(r2.ok, true); assert.strictEqual(r2.recorded, false);
});

test('grantAndRecord: on success the record holds exactly the three non-secret fields (tier fixed to standard, name from the caller, hasPassword from the server)', async () => {
  const written = [];
  const store = { setGrantMeta: (safe, dir, vaultId, meta) => { written.push({ dir, vaultId, meta }); return { encrypted: true }; } };
  const fetchFn = mockFetch(() => res(200, { password_protected: false, granted_at: null }));
  const r = await grantAndRecord({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'standard', vaultName: 'Payroll', dir: '/d', safeStorage: {} }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: true, vaultId: VAULT_ID, hasPassword: false, grantedAt: null, recorded: true });
  assert.deepStrictEqual(written, [{ dir: '/d', vaultId: VAULT_ID, meta: { name: 'Payroll', vaultType: 'standard', hasPassword: false } }]);
  assert.ok(!JSON.stringify(written).includes(PASSWORD) && !JSON.stringify(written).includes(ACCOUNT), 'nothing secret reaches the record');
  // a refused grant writes nothing and returns the refusal unchanged
  const w2 = [];
  const r2 = await grantAndRecord({ serverOrigin: ORIGIN, accountToken: ACCOUNT, deviceId: DEVICE_ID, vaultId: VAULT_ID, vaultType: 'zero_knowledge', vaultName: 'ZK', dir: '/d', safeStorage: {} }, { fetchFn, store: { setGrantMeta: () => w2.push(1) } });
  assert.deepStrictEqual(r2, { ok: false, reason: 'vault-not-standard' });
  assert.strictEqual(w2.length, 0);
});

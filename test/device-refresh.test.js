'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { refreshDeviceSecret, isRotationDue, identityIsStaleAfter, reconcileRotationMarker, ROTATE_AFTER_MS, NEVER_SENT_CODES } = require('../src/main/device-refresh');
const { ROUTES } = require('../src/main/device-http');
const realStore = require('../src/main/device-secret-store');
const { MintPathSelector } = require('../src/main/mint-path');
const { mintDeviceSftpAccess } = require('../src/main/device-mint');

const A = 'https://a.example';
const B = 'https://b.example';
const OLD = 'old-device-secret-DO-NOT-LOG-1111';
const NEW = 'new-device-secret-DO-NOT-LOG-2222';
const DEVICE_ID = 'dev-11112222-3333-4444';
const NOW = Date.parse('2026-09-05T12:00:00Z');

function res(status, body) { return { ok: status >= 200 && status < 300, status, json: async () => body }; }
function recordingFetch(handler) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url, init }); const r = handler({ url, init }); if (r instanceof Error) throw r; return r; };
  fn.calls = calls;
  return fn;
}
// A store double: `read` is what readDeviceSecret returns; `writes` records store calls; `storeFails` makes the write fail n times.
function storeDouble(read, { storeFails = 0, storeThrows = false } = {}) {
  const st = { writes: [], zeroized: [], fails: storeFails };
  st.store = {
    readDeviceSecret: () => ({ ...read }),
    markDeviceSecretRotating: () => { st.rotating = (st.rotating || 0) + 1; return true; },
    clearDeviceSecretRotating: () => { st.rotatingCleared = (st.rotatingCleared || 0) + 1; return true; },
    storeDeviceSecret: (safe, dir, payload) => {
      st.writes.push({ ...payload });
      if (storeThrows) throw new Error('keychain write failed');
      if (st.fails > 0) { st.fails--; return { stored: false, backend: 'basic_text' }; }
      return { stored: true, backend: 'gnome_libsecret' };
    },
    zeroizeSecret: (v) => st.zeroized.push(v),
  };
  return st;
}
const okRead = (o = {}) => ({ status: 'ok', deviceId: DEVICE_ID, secret: OLD, epoch: 3, serverOrigin: A, rotatedAt: '2026-09-04T00:00:00Z', ...o });

test('happy: one POST to the refresh route with the CURRENT secret and no body; the new secret is stored with the epoch from the answer, under the origin READ BACK from the blob', async () => {
  const fetchFn = recordingFetch(() => res(200, { device_id: DEVICE_ID, epoch: 4, secret: NEW }));
  const st = storeDouble(okRead());
  const r = await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {}, now: () => NOW }, { store: st.store, fetchFn });
  assert.deepStrictEqual(r, { ok: true, epoch: 4, rotatedAt: '2026-09-05T12:00:00.000Z' });
  assert.strictEqual(fetchFn.calls.length, 1);
  assert.strictEqual(fetchFn.calls[0].url, `${A}${ROUTES.refresh.path}`);
  assert.strictEqual(fetchFn.calls[0].init.method, 'POST');
  assert.strictEqual(fetchFn.calls[0].init.headers.Authorization, `Bearer ${OLD}`);
  assert.strictEqual(fetchFn.calls[0].init.body, undefined, 'the refresh carries no body');
  assert.deepStrictEqual(st.writes, [{ deviceId: DEVICE_ID, secret: NEW, epoch: 4, serverOrigin: A, rotatedAt: '2026-09-05T12:00:00.000Z' }]);
  assert.deepStrictEqual(st.zeroized, [OLD, NEW], 'both secrets are dropped once used');
});

test('A never becomes B: the stored binding comes from the blob, not from the caller; a blob bound elsewhere is never rotated at all', async () => {
  // the store double claims 'ok' with origin A even though the caller is configured for B — the write still binds A
  const fetchFn = recordingFetch(() => res(200, { epoch: 4, secret: NEW }));
  const st = storeDouble(okRead({ serverOrigin: A }));
  const r = await refreshDeviceSecret({ serverOrigin: B, dir: '/x', safeStorage: {}, now: () => NOW }, { store: st.store, fetchFn });
  assert.strictEqual(r.ok, true);
  assert.strictEqual(st.writes[0].serverOrigin, A, 'the binding travels from the blob');
  assert.notStrictEqual(st.writes[0].serverOrigin, B);
  // and with the REAL store: a blob bound to A read under B is absent-for-this-server -> no request, no write
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-refresh-'));
  const safe = mockSafe();
  realStore.storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: OLD, epoch: 1, serverOrigin: A });
  const before = fs.readFileSync(path.join(dir, 'device-secret.bin'));
  const f2 = recordingFetch(() => res(200, { epoch: 2, secret: NEW }));
  const r2 = await refreshDeviceSecret({ serverOrigin: B, dir, safeStorage: safe }, { fetchFn: f2 });
  assert.deepStrictEqual(r2, { ok: false, reason: 'absent-for-this-server' });
  assert.strictEqual(f2.calls.length, 0, 'no request with a secret that is not for this server');
  assert.ok(before.equals(fs.readFileSync(path.join(dir, 'device-secret.bin'))), 'the blob is untouched');
  // the same blob under A rotates, and the rotated blob still reads ok under A and not under B
  const f3 = recordingFetch(() => res(200, { epoch: 2, secret: NEW }));
  const r3 = await refreshDeviceSecret({ serverOrigin: A, dir, safeStorage: safe, now: () => NOW }, { fetchFn: f3 });
  assert.strictEqual(r3.ok, true);
  const after = realStore.readDeviceSecret(safe, dir, A);
  assert.deepStrictEqual([after.status, after.secret, after.epoch, after.serverOrigin, after.rotatedAt], ['ok', NEW, 2, A, '2026-09-05T12:00:00.000Z']);
  assert.strictEqual(realStore.readDeviceSecret(safe, dir, B).status, 'absent-for-this-server');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an identity that is not usable here is refused locally with the store status — no request, no write', async () => {
  for (const status of ['absent', 'unreadable', 'absent-for-this-server', 'no-secure-store']) {
    const fetchFn = recordingFetch(() => res(200, { epoch: 4, secret: NEW }));
    const st = storeDouble({ status, deviceId: null, secret: null, epoch: null });
    assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn }), { ok: false, reason: status });
    assert.strictEqual(fetchFn.calls.length, 0);
    assert.strictEqual(st.writes.length, 0);
  }
  const st = storeDouble(null); st.store.readDeviceSecret = () => { throw new Error('boom'); };
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => res(200, {})) }), { ok: false, reason: 'unreadable' });
});

test('a refusal keeps the device client\'s typed reason and writes nothing; the presented secret is dropped', async () => {
  for (const [status, reason] of [[401, 'device-secret-stale'], [401, 'device-revoked'], [401, 'device-suspended'], [401, 'device-expired'], [403, 'account-inactive']]) {
    const st = storeDouble(okRead());
    const r = await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => res(status, { detail: { reason } })) });
    assert.deepStrictEqual(r, { ok: false, reason }, reason);
    assert.strictEqual(st.writes.length, 0);
    assert.deepStrictEqual(st.zeroized, [OLD]);
  }
  const st = storeDouble(okRead());
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => Object.assign(new Error(`ECONNRESET ${OLD}`), { code: 'ECONNRESET' })) }), { ok: false, reason: 'network' }); // a CODED transport failure stays network
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: storeDouble(okRead()).store, fetchFn: recordingFetch(() => res(503, { detail: 'down' })) }), { ok: false, reason: 'server-error' });
});

test('a 2xx without a usable secret is refresh-malformed (nothing written); a store that fails after the server rotated reports rotated but not stored, after one retry', async () => {
  for (const body of [{}, { epoch: 4 }, { secret: '' }, { secret: 7 }, null]) {
    const st = storeDouble(okRead());
    assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => res(200, body)) }), { ok: false, reason: 'refresh-malformed' }, JSON.stringify(body));
    assert.strictEqual(st.writes.length, 0);
  }
  // one transient store failure is retried and succeeds, with the SAME payload both times
  let st = storeDouble(okRead(), { storeFails: 1 });
  assert.strictEqual((await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {}, now: () => NOW }, { store: st.store, fetchFn: recordingFetch(() => res(200, { epoch: 4, secret: NEW })) })).ok, true);
  assert.strictEqual(st.writes.length, 2);
  assert.deepStrictEqual(st.writes[1], st.writes[0]);
  assert.deepStrictEqual(st.writes[1], { deviceId: DEVICE_ID, secret: NEW, epoch: 4, serverOrigin: A, rotatedAt: '2026-09-05T12:00:00.000Z' });
  // two failures (or a throwing store) give up honestly: rotated on the server, not stored here
  st = storeDouble(okRead(), { storeFails: 2 });
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => res(200, { epoch: 4, secret: NEW })) }), { ok: false, reason: 'store-failed', rotated: true });
  st = storeDouble(okRead(), { storeThrows: true });
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => res(200, { epoch: 4, secret: NEW })) }), { ok: false, reason: 'store-failed', rotated: true });
  assert.deepStrictEqual(st.zeroized, [OLD, NEW], 'the new secret is dropped even when it could not be stored');
});

test('a missing epoch in the answer falls back to the stored epoch + 1', async () => {
  const st = storeDouble(okRead({ epoch: 7 }));
  const r = await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {}, now: () => NOW }, { store: st.store, fetchFn: recordingFetch(() => res(200, { secret: NEW })) });
  assert.strictEqual(r.epoch, 8);
  assert.strictEqual(st.writes[0].epoch, 8);
});

test('isRotationDue: only an ok identity is ever due; an unknown write time is due; otherwise due after the rotation interval', () => {
  const t0 = '2026-09-05T12:00:00Z';
  assert.strictEqual(isRotationDue({ status: 'ok', rotatedAt: t0 }, Date.parse(t0) + 1000), false);
  assert.strictEqual(isRotationDue({ status: 'ok', rotatedAt: t0 }, Date.parse(t0) + ROTATE_AFTER_MS - 1), false);
  assert.strictEqual(isRotationDue({ status: 'ok', rotatedAt: t0 }, Date.parse(t0) + ROTATE_AFTER_MS), true);
  assert.strictEqual(isRotationDue({ status: 'ok', rotatedAt: t0 }, Date.parse(t0) + 1000, 500), true, 'a caller-supplied interval is honoured');
  for (const bad of [null, undefined, '', 'not a date', 42]) assert.strictEqual(isRotationDue({ status: 'ok', rotatedAt: bad }, NOW), true, `unknown write time ${JSON.stringify(bad)} is due`);
  for (const status of ['absent', 'unreadable', 'absent-for-this-server', 'no-secure-store', 'stale']) assert.strictEqual(isRotationDue({ status, rotatedAt: '2000-01-01T00:00:00Z' }, NOW), false, status);
  assert.strictEqual(isRotationDue(null, NOW), false);
  assert.ok(ROTATE_AFTER_MS >= 60 * 60 * 1000, 'never rotates per mint or per tick');
});

test('NEVER-LOGGED: no refresh path writes either secret (plaintext or base64) to a log sink, a result, or an error', async () => {
  const sinks = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, out: process.stdout.write, err: process.stderr.write };
  const cap = (...a) => { sinks.push(a.map(String).join(' ')); };
  console.log = cap; console.error = cap; console.warn = cap;
  process.stdout.write = (s) => { sinks.push(String(s)); return true; };
  process.stderr.write = (s) => { sinks.push(String(s)); return true; };
  const results = [];
  try {
    console.log('planted ' + OLD);
    results.push(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: storeDouble(okRead()).store, fetchFn: recordingFetch(() => res(200, { epoch: 4, secret: NEW })) }));
    results.push(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: storeDouble(okRead()).store, fetchFn: recordingFetch(() => res(401, { detail: { reason: 'device-secret-stale', message: `was ${OLD}` } })) }));
    results.push(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: storeDouble(okRead()).store, fetchFn: recordingFetch(() => new Error(`dial failed Bearer ${OLD}`)) }));
    results.push(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: storeDouble(okRead(), { storeThrows: true }).store, fetchFn: recordingFetch(() => res(200, { epoch: 4, secret: NEW })) }));
  } finally {
    console.log = orig.log; console.error = orig.error; console.warn = orig.warn; process.stdout.write = orig.out; process.stderr.write = orig.err;
  }
  const b64 = (s) => Buffer.from(s).toString('base64');
  assert.ok(sinks.some((s) => s.includes('planted ' + OLD)), 'capture is live');
  const leaked = sinks.filter((s) => !s.startsWith('planted ') && [OLD, NEW, b64(OLD), b64(NEW)].some((v) => s.includes(v)));
  assert.deepStrictEqual(leaked, []);
  const text = JSON.stringify(results);
  assert.ok(!text.includes(OLD) && !text.includes(NEW), 'no result carries a secret');
});

function mockSafe() {
  const MAGIC = 'DVENC1:';
  return {
    isEncryptionAvailable: () => true,
    getSelectedStorageBackend: () => 'gnome_libsecret',
    encryptString: (s) => Buffer.from(MAGIC + Buffer.from(String(s), 'utf8').toString('base64'), 'utf8'),
    decryptString: (buf) => { const str = Buffer.from(buf).toString('utf8'); if (!str.startsWith(MAGIC)) throw new Error('bad framing'); return Buffer.from(str.slice(MAGIC.length), 'base64').toString('utf8'); },
  };
}

test('identityIsStaleAfter: a stale refusal, a lost answer (store failed) and a malformed 2xx all mean the held secret is retired; every other outcome does not', () => {
  for (const reason of ['device-secret-stale', 'store-failed', 'refresh-malformed']) assert.strictEqual(identityIsStaleAfter({ ok: false, reason }), true, reason);
  for (const reason of ['network', 'server-error', 'device-revoked', 'device-suspended', 'device-expired', 'account-inactive', 'absent', 'unreadable', 'absent-for-this-server', 'no-secure-store', 'device-request-refused']) {
    assert.strictEqual(identityIsStaleAfter({ ok: false, reason }), false, reason);
  }
  assert.strictEqual(identityIsStaleAfter({ ok: true, epoch: 2, rotatedAt: 'x' }), false);
  assert.strictEqual(identityIsStaleAfter(null), false);
});

test('the store preconditions are checked BEFORE the irreversible request: a read that lacks a usable bound origin or id is refused with no request', async () => {
  for (const read of [okRead({ serverOrigin: null }), okRead({ serverOrigin: 'garbage' }), okRead({ serverOrigin: undefined }), okRead({ deviceId: '' }), okRead({ deviceId: null })]) {
    const fetchFn = recordingFetch(() => res(200, { epoch: 4, secret: NEW }));
    const st = storeDouble(read);
    assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn }), { ok: false, reason: 'unreadable' });
    assert.strictEqual(fetchFn.calls.length, 0, 'nothing is presented to the server');
    assert.strictEqual(st.writes.length, 0);
    assert.deepStrictEqual(st.zeroized, [OLD], 'the read secret is still dropped');
  }
});

test('the answer object does not keep the new secret either', async () => {
  const body = { epoch: 4, secret: NEW };
  const st = storeDouble(okRead());
  await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn: recordingFetch(() => ({ ok: true, status: 200, json: async () => body })) });
  assert.strictEqual(body.secret, null);
});

test('after a restart, a stale mark still stops every presentation: a fresh selector and a fresh mint over the same directory refuse with device-secret-stale and make zero requests', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-stale-'));
  const safe = mockSafe();
  realStore.storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: OLD, epoch: 1, serverOrigin: A });
  // the lost rotation answer: the server rotated, the store here failed -> marked stale (as the glue does)
  assert.strictEqual(realStore.markDeviceSecretStale(dir), true);
  // "restart": brand-new objects over the same directory, no in-memory state
  const requests = [];
  const fetchFn = async (url, init) => { requests.push(url); return { ok: true, status: 200, json: async () => ({ grants: [] }) }; };
  const selector = new MintPathSelector({
    readSecret: () => { const r = realStore.readDeviceSecret(safe, dir, A); r.secret = null; return { status: r.status }; },
    listGrants: async () => { const r = realStore.readDeviceSecret(safe, dir, A); if (r.status !== 'ok') throw Object.assign(new Error('no identity'), { reason: 'device-secret-stale' }); return { ok: true, grants: [] }; },
    readGrantRecord: () => ({ status: 'absent', meta: {} }),
  });
  assert.deepStrictEqual(await selector.begin('3f2b1c0a-9d8e-4f7a-b6c5-d4e3f2a1b0c9'), { ok: false, reason: 'device-secret-stale' });
  assert.strictEqual(selector.current('3f2b1c0a-9d8e-4f7a-b6c5-d4e3f2a1b0c9'), null, 'no path is latched');
  // a direct mint attempt cannot even obtain the secret
  const read = realStore.readDeviceSecret(safe, dir, A);
  assert.strictEqual(read.status, 'stale'); assert.strictEqual(read.secret, null);
  await assert.rejects(() => mintDeviceSftpAccess({ serverOrigin: A, deviceSecret: read.secret, vaultId: '3f2b1c0a-9d8e-4f7a-b6c5-d4e3f2a1b0c9' }, fetchFn), (e) => e.reason === 'no-device-secret');
  // no rotation is due or attempted on a stale identity either
  assert.strictEqual(isRotationDue(read, Date.now()), false);
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir, safeStorage: safe }, { fetchFn }), { ok: false, reason: 'stale' });
  assert.deepStrictEqual(requests, [], 'zero requests carried the retired secret');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the request-to-store window is covered: a rotation cut off after the server answered leaves a survivor that a fresh launch reads as stale, with zero requests carrying the retired secret', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-rotating-'));
  const safe = mockSafe();
  realStore.storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: OLD, epoch: 1, serverOrigin: A });
  // the server rotates (the fetch resolves with a new secret) but this process dies before the store runs
  const killedStore = { ...realStore, storeDeviceSecret: () => { throw new Error('process killed before the store'); } };
  const fetchFn = recordingFetch(() => res(200, { epoch: 2, secret: NEW }));
  const r = await refreshDeviceSecret({ serverOrigin: A, dir, safeStorage: safe }, { store: killedStore, fetchFn });
  assert.strictEqual(r.ok, false);
  assert.ok(fs.existsSync(path.join(dir, 'device-secret.rotating')), 'the in-flight mark survives the cut-off');
  assert.ok(!fs.existsSync(path.join(dir, 'device-secret.stale')), 'no stale mark was written by anyone — the survivor alone must do the work');
  // "next launch": fresh objects over the same directory
  const read = realStore.readDeviceSecret(safe, dir, A);
  assert.strictEqual(read.status, 'stale'); assert.strictEqual(read.secret, null);
  const requests = [];
  const selector = new MintPathSelector({
    readSecret: () => ({ status: realStore.readDeviceSecret(safe, dir, A).status }),
    listGrants: async () => { requests.push('grants'); return { ok: true, grants: [] }; },
    readGrantRecord: () => ({ status: 'absent', meta: {} }),
  });
  assert.deepStrictEqual(await selector.begin('3f2b1c0a-9d8e-4f7a-b6c5-d4e3f2a1b0c9'), { ok: false, reason: 'device-secret-stale' });
  assert.strictEqual(isRotationDue(read, Date.now()), false);
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir, safeStorage: safe }, { fetchFn: recordingFetch(() => { requests.push('refresh'); return res(200, { epoch: 3, secret: 'x' }); }) }), { ok: false, reason: 'stale' });
  assert.deepStrictEqual(requests, []);
  // forget clears the survivor with the identity; a fresh registration then reads ok
  assert.deepStrictEqual(realStore.clearDeviceSecret(dir), { removed: true });
  assert.ok(!fs.existsSync(path.join(dir, 'device-secret.rotating')));
  realStore.storeDeviceSecret(safe, dir, { deviceId: 'dev-new', secret: NEW, epoch: 1, serverOrigin: A });
  assert.strictEqual(realStore.readDeviceSecret(safe, dir, A).status, 'ok');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('ETIMEDOUT stays OUT of NEVER_SENT_CODES, so a timeout keeps the rotation mark (guard against a future tidy-up that would silently start clearing it)', () => {
  assert.strictEqual(NEVER_SENT_CODES.has('ETIMEDOUT'), false, 'ETIMEDOUT must NOT be in NEVER_SENT_CODES: a timeout means the request may have landed, so it keeps the in-flight rotation mark — adding it would start clearing the mark on every timeout, a replay risk');
  for (const c of ['ECONNREFUSED', 'ENOTFOUND', 'ERR_CONNECTION_REFUSED']) assert.strictEqual(NEVER_SENT_CODES.has(c), true, `${c} is a connection-never-made code and DOES clear the mark`);
});

test('the in-flight mark is removed on success and on a typed refusal (the server answered without rotating), and kept on a transport or server failure (ambiguous)', async () => {
  const cases = [
    ['success', () => res(200, { epoch: 2, secret: NEW }), 'ok'],
    ['typed refusal', () => res(401, { detail: { reason: 'device-revoked' } }), 'ok'],
    ['stale refusal', () => res(401, { detail: { reason: 'device-secret-stale' } }), 'ok'], // the caller marks stale itself
    ['network: reset after connecting', () => Object.assign(new Error('socket hang up'), { code: 'ECONNRESET' }), 'stale'],
    ['network: timeout', () => new Error('request timed out'), 'stale'],
    ['network: never connected (refused)', () => Object.assign(new Error('connect ECONNREFUSED 127.0.0.1:8360'), { code: 'ECONNREFUSED' }), 'ok'],
    ['network: never connected (dns)', () => Object.assign(new Error('getaddrinfo ENOTFOUND vault.example'), { code: 'ENOTFOUND' }), 'ok'],
    ['network: unroutable', () => Object.assign(new Error('connect ENETUNREACH'), { code: 'ENETUNREACH' }), 'ok'],
    ['network: never connected (chromium refused)', () => new Error('net::ERR_CONNECTION_REFUSED'), 'ok'],
    ['network: never connected (chromium dns)', () => new Error('net::ERR_NAME_NOT_RESOLVED'), 'ok'],
    ['network: never connected (chromium network unreachable)', () => new Error('net::ERR_NETWORK_UNREACHABLE'), 'ok'],
    ['network: never connected (chromium offline)', () => new Error('net::ERR_INTERNET_DISCONNECTED'), 'ok'],
    // ambiguous — the bytes may have left: every one of these MUST keep the mark
    ['network: chromium reset after connecting', () => new Error('net::ERR_CONNECTION_RESET'), 'stale'],
    ['network: chromium timeout', () => new Error('net::ERR_TIMED_OUT'), 'stale'],
    ['network: chromium connection timeout', () => new Error('net::ERR_CONNECTION_TIMED_OUT'), 'stale'],
    ['network: chromium empty response', () => new Error('net::ERR_EMPTY_RESPONSE'), 'stale'],
    ['network: chromium connection closed', () => new Error('net::ERR_CONNECTION_CLOSED'), 'stale'],
    ['network: node timeout code', () => Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }), 'stale'],
    ['network: node pipe broken', () => Object.assign(new Error('write EPIPE'), { code: 'EPIPE' }), 'stale'],
    ['server error', () => res(503, { detail: 'down' }), 'stale'],
    ['unknown refusal', () => res(418, { detail: 'teapot' }), 'stale'],
  ];
  for (const [name, handler, expectRead] of cases) {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-rotating-'));
    const safe = mockSafe();
    realStore.storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: OLD, epoch: 1, serverOrigin: A });
    await refreshDeviceSecret({ serverOrigin: A, dir, safeStorage: safe }, { fetchFn: recordingFetch(handler) });
    assert.strictEqual(realStore.readDeviceSecret(safe, dir, A).status, expectRead, name);
    assert.strictEqual(fs.existsSync(path.join(dir, 'device-secret.rotating')), expectRead === 'stale', `${name}: in-flight mark`);
    fs.rmSync(dir, { recursive: true, force: true });
  }
  // and when the in-flight mark cannot be written, no rotation is attempted at all
  const st = storeDouble(okRead()); st.store.markDeviceSecretRotating = () => false;
  const fetchFn = recordingFetch(() => res(200, { epoch: 2, secret: NEW }));
  assert.deepStrictEqual(await refreshDeviceSecret({ serverOrigin: A, dir: '/x', safeStorage: {} }, { store: st.store, fetchFn }), { ok: false, reason: 'rotation-unprotected' });
  assert.strictEqual(fetchFn.calls.length, 0);
  assert.deepStrictEqual(st.zeroized, [OLD]);
  assert.strictEqual(identityIsStaleAfter({ ok: false, reason: 'rotation-unprotected' }), false, 'not stale — simply not rotated this time');
});

test('reconcileRotationMarker: only an exact epoch match LIFTS the marker; greater is stale, absent/inactive is revoked, doubt keeps', () => {
  // rotation never landed → clear (the held secret is still current)
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true, epoch: 4 }, 4), 'clear');
  // the server rotated and this side lost the answer → stale (never present the retired secret)
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true, epoch: 5 }, 4), 'stale');
  // the device row is gone / deactivated → revoked → set up again
  assert.strictEqual(reconcileRotationMarker({ found: false }, 4), 'revoked');
  assert.strictEqual(reconcileRotationMarker(null, 4), 'revoked');
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: false, epoch: 4 }, 4), 'revoked');
  // any doubt keeps the marker: a smaller server epoch (impossible-but-safe), a missing/non-integer epoch on either side
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true, epoch: 3 }, 4), 'keep');
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true }, 4), 'keep');
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true, epoch: 4.5 }, 4), 'keep');
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true, epoch: 4 }, null), 'keep');
  assert.strictEqual(reconcileRotationMarker({ found: true, isActive: true, epoch: '4' }, 4), 'keep');
});

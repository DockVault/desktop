'use strict';

const test = require('node:test');
const assert = require('node:assert');
const os = require('node:os');
const {
  registerDevice, forgetDevice, mayRegisterHere, checkDeviceSyncSupported, validateDeviceLabel, suggestDeviceLabel,
  decideEnableDeviceStep, nextUnreadableStreak,
} = require('../src/main/device-register');

const ORIGIN = 'https://vault.example';
const ACCOUNT = 'account-jwt-token-DO-NOT-LOG';
const SECRET = 'opaque-device-bearer-secret-xyz789';
const DEVICE_ID = 'dev-11112222-3333-4444';
const BENIGN = { hostname: 'unrelated-host', username: 'nobody' }; // injected identity so label checks are hermetic

function mockSafe(secure) {
  return {
    isEncryptionAvailable: () => secure,
    getSelectedStorageBackend: () => (secure ? 'gnome_libsecret' : 'basic_text'),
    encryptString: (s) => Buffer.from(String(s)),
    decryptString: (b) => Buffer.from(b).toString('utf8'),
  };
}
function jsonRes(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}
// A fetch double: dispatches on `${method} ${pathname}` to a handler, records every call.
function mockFetch(handlers) {
  const calls = [];
  const fn = async (url, init) => {
    const path = url.replace(ORIGIN, '');
    const key = `${(init && init.method) || 'GET'} ${path.split('/').slice(0, 3).join('/')}`;
    calls.push({ url, init, method: (init && init.method) || 'GET', path });
    const h = handlers[key] || handlers[`${(init && init.method) || 'GET'} ${path}`];
    if (!h) throw new Error('no handler'); // transport-style failure for an unmapped route
    return h({ url, init });
  };
  fn.calls = calls;
  return fn;
}
// A store double: control the store outcome; record zeroize + hint writes + the stored payload.
function mockStore({ storeResult, storeThrows } = {}) {
  const s = {
    stored: null, zeroized: [], hints: [],
    storeDeviceSecret(safe, dir, payload) { s.stored = payload; if (storeThrows) throw new TypeError('store boom'); return storeResult || { stored: true, backend: 'gnome_libsecret' }; },
    readDeviceSecret() { return { status: s.readStatus || 'absent', deviceId: null, secret: null, epoch: null }; },
    zeroizeSecret(x) { s.zeroized.push(x); },
    writeDeviceIdHint(dir, id) { s.hints.push(id); },
  };
  return s;
}

// ---- checkDeviceSyncSupported: capability probe, honest 4-way ------------------------------------
test('capability probe: 200 -> supported (with the device list)', async () => {
  const fetchFn = mockFetch({ 'GET /devices': () => jsonRes(200, { devices: [{ label: 'a' }] }) });
  assert.deepStrictEqual(await checkDeviceSyncSupported({ serverOrigin: ORIGIN, accountToken: ACCOUNT }, fetchFn),
    { supported: true, reason: 'ok', devices: [{ label: 'a' }] });
});
test('capability probe: 404 -> too-old; 401/403 -> auth; 2xx-non-200/5xx/network -> indeterminate (fail closed, honest)', async () => {
  const mk = (status) => checkDeviceSyncSupported({ serverOrigin: ORIGIN, accountToken: ACCOUNT },
    mockFetch({ 'GET /devices': () => jsonRes(status, {}) }));
  assert.deepStrictEqual(await mk(404), { supported: false, reason: 'too-old' });
  assert.deepStrictEqual(await mk(401), { supported: false, reason: 'auth' });
  assert.deepStrictEqual(await mk(403), { supported: false, reason: 'auth' });
  assert.deepStrictEqual(await mk(500), { supported: false, reason: 'indeterminate' });
  assert.deepStrictEqual(await mk(503), { supported: false, reason: 'indeterminate' });
  // A non-200 2xx (gateway 202/204/etc.) is ambiguous, not a confirmed device list -> never fail OPEN.
  assert.deepStrictEqual(await mk(204), { supported: false, reason: 'indeterminate' });
  assert.deepStrictEqual(await mk(202), { supported: false, reason: 'indeterminate' });
  // A 200 that is NOT a parseable {devices: array} (an HTML SPA / proxy / captive portal in front of an
  // OLD vault answers 200 too) is ambiguous -> indeterminate, never a false offer.
  const s200 = (body, throwing) => checkDeviceSyncSupported({ serverOrigin: ORIGIN, accountToken: ACCOUNT },
    mockFetch({ 'GET /devices': () => ({ ok: true, status: 200, json: async () => { if (throwing) throw new Error('html'); return body; } }) }));
  assert.deepStrictEqual(await s200({}), { supported: false, reason: 'indeterminate' });
  assert.deepStrictEqual(await s200({ devices: 'nope' }), { supported: false, reason: 'indeterminate' });
  assert.deepStrictEqual(await s200(null, true), { supported: false, reason: 'indeterminate' });
  const netFn = async () => { throw new Error('offline'); };
  assert.deepStrictEqual(await checkDeviceSyncSupported({ serverOrigin: ORIGIN, accountToken: ACCOUNT }, netFn),
    { supported: false, reason: 'indeterminate' });
});

// ---- registerDevice: the fail-safe order --------------------------------------------------------
test('happy path: pre-check ok -> POST -> store {deviceId,secret,epoch:1} -> {ok:true}; secret zeroized', async () => {
  const store = mockStore({ storeResult: { stored: true, backend: 'gnome_libsecret' } });
  const fetchFn = mockFetch({ 'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }) });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'My laptop', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store, identity: BENIGN });
  assert.deepStrictEqual(r, { ok: true, deviceId: DEVICE_ID });
  assert.deepStrictEqual(store.stored, { deviceId: DEVICE_ID, secret: SECRET, epoch: 1, serverOrigin: ORIGIN }, 'the stored identity is bound to the exact origin the register request went to');
  assert.ok(store.zeroized.includes(SECRET), 'the in-memory secret is zeroized after a successful store');
  assert.strictEqual(fetchFn.calls.filter((c) => c.method === 'DELETE').length, 0, 'no cleanup on success');
  // The POST is account-authenticated and carries the CLEANED label as its body.
  const post = fetchFn.calls.find((c) => c.method === 'POST');
  assert.strictEqual(post.url, `${ORIGIN}/devices`);
  assert.strictEqual(post.init.headers.Authorization, `Bearer ${ACCOUNT}`);
  assert.strictEqual(post.init.body, JSON.stringify({ label: 'My laptop' }));
});

test('fail-safe: pre-check non-secure -> abort, POST never called', async () => {
  const store = mockStore();
  const fetchFn = mockFetch({ 'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }) });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(false) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'no-secure-store' });
  assert.strictEqual(fetchFn.calls.length, 0, 'nothing is created server-side when there is no secure backend');
  assert.strictEqual(store.stored, null);
});

test('fail-safe: a throw after POST -> orphan-cleanup DELETE + zeroize + {store-failed, orphanCleaned:true}', async () => {
  const store = mockStore({ storeThrows: true });
  const del = [];
  const fetchFn = mockFetch({
    'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }),
    [`DELETE /devices/${DEVICE_ID}`]: ({ init }) => { del.push(init); return jsonRes(200, { message: 'deleted' }); },
  });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'store-failed', orphanCleaned: true });
  assert.strictEqual(del.length, 1, 'the just-created server row is deleted');
  assert.ok(store.zeroized.includes(SECRET));
  assert.strictEqual(store.hints.length, 0, 'a successful cleanup does not need the sidecar hint');
  // The orphan-cleanup DELETE is account-authenticated and carries no body.
  assert.strictEqual(del[0].headers.Authorization, `Bearer ${ACCOUNT}`);
  assert.ok(!('body' in del[0]), 'the DELETE carries no body');
});

test('fail-safe: {stored:false} after POST (backend flip) -> treated like a throw -> cleanup + no-secure-store', async () => {
  const store = mockStore({ storeResult: { stored: false, backend: 'basic_text' } }); // flipped after the pre-check
  const del = [];
  const fetchFn = mockFetch({
    'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }),
    [`DELETE /devices/${DEVICE_ID}`]: () => { del.push(1); return jsonRes(200, {}); },
  });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'no-secure-store', orphanCleaned: true });
  assert.strictEqual(del.length, 1, 'a store-step {stored:false} still cleans up the orphaned server row');
  assert.ok(store.zeroized.includes(SECRET));
});

test('#5 fail-safe: store fails AND the cleanup DELETE also fails -> retain the id in the sidecar + surface it', async () => {
  const store = mockStore({ storeThrows: true });
  const fetchFn = mockFetch({
    'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }),
    [`DELETE /devices/${DEVICE_ID}`]: () => jsonRes(500, {}), // cleanup itself fails
  });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'store-failed', orphanCleaned: false, orphanDeviceId: DEVICE_ID });
  assert.deepStrictEqual(store.hints, [DEVICE_ID], 'the deviceId is retained in the sidecar so a later reset can name the row');
  assert.ok(store.zeroized.includes(SECRET));
});

test('register refusals map to fixed reasons without a POST body leak', async () => {
  const mk = (status) => registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) },
    { fetchFn: mockFetch({ 'POST /devices': () => jsonRes(status, { detail: 'nope' }) }), store: mockStore() });
  assert.deepStrictEqual(await mk(409), { ok: false, reason: 'device-cap-reached' });
  assert.deepStrictEqual(await mk(401), { ok: false, reason: 'auth' });
  assert.deepStrictEqual(await mk(400), { ok: false, reason: 'invalid-label' });
  assert.deepStrictEqual(await mk(500), { ok: false, reason: 'register-refused' });
});

test('a transport failure on the POST -> network (no row created)', async () => {
  const store = mockStore();
  const fetchFn = async () => { throw new Error('offline'); };
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'network' });
  assert.strictEqual(store.stored, null);
});

test('a 2xx register with a usable id but no secret -> the REAL row is orphan-cleaned (register-malformed)', async () => {
  // The server created a row (id present) but we cannot store it (no usable secret) -> it is an orphan
  // and must be deleted, exactly like a store failure. Regression guard: it must NOT just return.
  const store = mockStore();
  const del = [];
  const fetchFn = mockFetch({
    'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID }), // id but no secret -> a real, unusable row
    [`DELETE /devices/${DEVICE_ID}`]: () => { del.push(1); return jsonRes(200, {}); },
  });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'register-malformed', orphanCleaned: true });
  assert.strictEqual(store.stored, null, 'nothing is stored locally');
  assert.strictEqual(del.length, 1, 'the real-but-unusable server row is deleted, never left orphaned');
});

test('a 2xx register with no usable id -> register-malformed, nothing to name/clean', async () => {
  const store = mockStore();
  const del = [];
  const fetchFn = mockFetch({
    'POST /devices': () => jsonRes(200, {}), // neither id nor secret -> no row we can name
    [`DELETE /devices/${DEVICE_ID}`]: () => { del.push(1); return jsonRes(200, {}); },
  });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'register-malformed' });
  assert.strictEqual(store.stored, null);
  assert.strictEqual(del.length, 0, 'no usable id -> no DELETE');
});

test('an identifying label is rejected locally -> invalid-label, POST never called', async () => {
  const store = mockStore();
  const fetchFn = mockFetch({ 'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }) });
  const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'user@host', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store });
  assert.deepStrictEqual(r, { ok: false, reason: 'invalid-label' });
  assert.strictEqual(fetchFn.calls.length, 0);
});

test('NEVER-LOGGED: neither the secret nor the account token appears in any register result', async () => {
  const results = [];
  const store = mockStore({ storeThrows: true });
  const fetchFn = mockFetch({
    'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }),
    [`DELETE /devices/${DEVICE_ID}`]: () => jsonRes(500, {}),
  });
  results.push(await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store }));
  results.push(await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(false) }, { fetchFn, store }));
  const blob = JSON.stringify(results);
  assert.ok(!blob.includes(SECRET), 'no result carries the device secret');
  assert.ok(!blob.includes(ACCOUNT), 'no result carries the account token');
});

test('NEVER-LOGGED (sweep): no register path writes the secret or account token to any log sink', async () => {
  const seen = [];
  const methods = ['log', 'info', 'warn', 'error', 'debug'];
  const oc = {};
  for (const m of methods) { oc[m] = console[m]; console[m] = (...a) => { seen.push(a.map(String).join(' ')); }; }
  const so = process.stdout.write.bind(process.stdout);
  const se = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c) => { seen.push(String(c)); return true; };
  process.stderr.write = (c) => { seen.push(String(c)); return true; };
  let selfCheck = false;
  try {
    console.log('planted', SECRET); // non-vacuity: prove the capture catches a logged secret
    selfCheck = seen.some((l) => l.includes(SECRET));
    seen.length = 0;
    // happy path
    await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) },
      { fetchFn: mockFetch({ 'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }) }), store: mockStore(), identity: BENIGN });
    // store throws AND the cleanup DELETE also fails (the orphan-retain path)
    await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) },
      { fetchFn: mockFetch({ 'POST /devices': () => jsonRes(200, { device_id: DEVICE_ID, secret: SECRET }), [`DELETE /devices/${DEVICE_ID}`]: () => jsonRes(500, {}) }), store: mockStore({ storeThrows: true }), identity: BENIGN });
  } finally {
    for (const m of methods) console[m] = oc[m];
    process.stdout.write = so;
    process.stderr.write = se;
  }
  assert.ok(selfCheck, 'self-check: the capture catches a planted secret (non-vacuous)');
  const swept = seen.join('\n');
  const b64 = Buffer.from(SECRET, 'utf8').toString('base64');
  const hex = Buffer.from(SECRET, 'utf8').toString('hex');
  assert.ok(!swept.includes(SECRET) && !swept.includes(b64) && !swept.includes(hex), 'no secret in any log sink');
  assert.ok(!swept.includes(ACCOUNT), 'no account token in any log sink');
});

// ---- label helpers ------------------------------------------------------------------------------
test('validateDeviceLabel: accepts a nickname, null for empty, rejects path/@/IPv4/over-long', () => {
  assert.strictEqual(validateDeviceLabel('My laptop', BENIGN), 'My laptop');
  assert.strictEqual(validateDeviceLabel('', BENIGN), null);
  assert.strictEqual(validateDeviceLabel(null, BENIGN), null);
  assert.strictEqual(validateDeviceLabel(undefined, BENIGN), null);
  for (const bad of ['/etc/x', 'a\\b', 'me@host', '10.0.0.1', 'x'.repeat(65)]) {
    assert.throws(() => validateDeviceLabel(bad, BENIGN), TypeError, `should reject ${JSON.stringify(bad)}`);
  }
  // A control character is stripped, not smuggled.
  assert.strictEqual(validateDeviceLabel('lap\x07top', BENIGN), 'laptop');
});

test('validateDeviceLabel: 3-arm identity-echo guard (whole-token / exact-collapse / collapsed-containment)', () => {
  // ARM 1 — whole-token (>= 3): a literal whole-word echo of the host or username.
  assert.throws(() => validateDeviceLabel('File Server', { hostname: 'server', username: 'x' }), TypeError);
  assert.throws(() => validateDeviceLabel('laptop', { hostname: 'laptop.corp.example.com', username: 'x' }), TypeError);
  // ARM 2 — exact full-collapse (no floor): the label IS the machine name.
  assert.throws(() => validateDeviceLabel('Johns MacBook Pro', { hostname: 'Johns-MacBook-Pro', username: 'x' }), TypeError);
  assert.throws(() => validateDeviceLabel('Desktop 4KJ9P2', { hostname: 'DESKTOP-4KJ9P2', username: 'x' }), TypeError);
  assert.throws(() => validateDeviceLabel('Lis iMac', { hostname: 'Lis-iMac', username: 'x' }), TypeError);
  assert.throws(() => validateDeviceLabel('PC 7', { hostname: 'pc-7', username: 'x' }), TypeError);
  // ARM 3 — collapsed containment (>= 8): a long identity embedded in a longer label.
  assert.throws(() => validateDeviceLabel('Johns MacBook Pro Work', { hostname: 'Johns-MacBook-Pro', username: 'x' }), TypeError);
  // ACCEPT: no whole-token, not an exact collapse, no >= 8 collapsed containment.
  assert.strictEqual(validateDeviceLabel('Samsung TV', { hostname: 'x', username: 'sam' }), 'Samsung TV');
  assert.strictEqual(validateDeviceLabel('Raspberry Pi', { hostname: 'x', username: 'pi' }), 'Raspberry Pi');
  assert.strictEqual(validateDeviceLabel('File Server', { hostname: 'fileserver01', username: 'x' }), 'File Server');
  assert.strictEqual(validateDeviceLabel('Work laptop', { hostname: 'other', username: 'ed' }), 'Work laptop');
  // A falsy/empty host or user is a clean NO-OP — never reject-all (collapse('')==='' would otherwise
  // make the containment arm match every label).
  assert.strictEqual(validateDeviceLabel('Anything At All', { hostname: '', username: '' }), 'Anything At All');
  assert.strictEqual(validateDeviceLabel('Kitchen iPad', { hostname: '', username: 'sam' }), 'Kitchen iPad');
  // The identity-echo refusal carries its own actionable message (distinct from the path/@/IPv4 one).
  try { validateDeviceLabel('laptop', { hostname: 'laptop', username: 'x' }); assert.fail('expected a throw'); }
  catch (e) { assert.match(e.message, /computer's name/); }
});

test('suggestDeviceLabel: generic + non-identifying, avoids collisions with a bounded suffix', () => {
  assert.strictEqual(suggestDeviceLabel([]), 'This computer');
  assert.strictEqual(suggestDeviceLabel(['This computer']), 'This computer 2');
  assert.strictEqual(suggestDeviceLabel(['This computer', 'This computer 2']), 'This computer 3');
  const host = (() => { try { return os.hostname(); } catch { return ''; } })();
  if (host) assert.ok(!suggestDeviceLabel([]).includes(host), 'the suggested label never contains the hostname');
});

// ---- forget: read the id -> revoke under the account session -> clear, on every branch --------------------

const DEL = `DELETE /devices/${DEVICE_ID}`;
function forgetStore(read, { hint = DEVICE_ID, clearRemoved = true, readThrows = false } = {}) {
  const st = { cleared: 0, zeroized: [], hints: [] };
  st.store = {
    readDeviceSecret: () => { if (readThrows) throw new Error('boom'); return read; },
    readDeviceIdHint: () => hint,
    writeDeviceIdHint: (dir, id) => st.hints.push(id),
    clearDeviceSecret: () => { st.cleared++; return { removed: clearRemoved }; },
    zeroizeSecret: (v) => st.zeroized.push(v),
  };
  return st;
}

test('forget (bound to this server): revokes by the blob id under the account session, then clears; the secret is never sent', async () => {
  const calls = [];
  const fetchFn = mockFetch({ [DEL]: ({ url, init }) => { calls.push({ url, init }); return jsonRes(204, null); } });
  const st = forgetStore({ status: 'ok', deviceId: DEVICE_ID, secret: SECRET, epoch: 3 });
  const r = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store: st.store });
  assert.deepStrictEqual(r, { cleared: true, revoked: true, deviceId: DEVICE_ID });
  assert.strictEqual(calls.length, 1);
  assert.strictEqual(calls[0].url, `${ORIGIN}/devices/${DEVICE_ID}`);
  assert.strictEqual(calls[0].init.method, 'DELETE');
  assert.strictEqual(calls[0].init.headers.Authorization, `Bearer ${ACCOUNT}`);
  assert.ok(!JSON.stringify(calls).includes(SECRET), 'the device secret never rides a forget request');
  assert.deepStrictEqual(st.zeroized, [SECRET]);
  assert.strictEqual(st.cleared, 1);
});

test('forget (bound to ANOTHER server): no revoke is attempted with this session; local files are cleared; the other server is named', async () => {
  const fetchFn = mockFetch({});
  const st = forgetStore({ status: 'absent-for-this-server', deviceId: null, secret: null, epoch: null, otherOrigin: 'https://other.example' });
  const r = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store: st.store });
  assert.deepStrictEqual(r, { cleared: true, revoked: false, deviceId: DEVICE_ID, otherOrigin: 'https://other.example' });
  assert.strictEqual(fetchFn.calls.length, 0, 'never a request to the wrong server, never with the wrong session');
  assert.strictEqual(st.cleared, 1);
});

test('forget (blob unreadable / absent): id-only best-effort revoke from the sidecar hint, account-scoped, then clear', async () => {
  for (const read of [{ status: 'unreadable', deviceId: null, secret: null, epoch: null }, { status: 'absent', deviceId: null, secret: null, epoch: null }, { status: 'no-secure-store', deviceId: null, secret: null, epoch: null }]) {
    const fetchFn = mockFetch({ [DEL]: () => jsonRes(204, null) });
    const st = forgetStore(read);
    const r = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store: st.store });
    assert.deepStrictEqual(r, { cleared: true, revoked: true, deviceId: DEVICE_ID }, read.status);
    assert.strictEqual(fetchFn.calls[0].method, 'DELETE');
    assert.strictEqual(fetchFn.calls[0].init.headers.Authorization, `Bearer ${ACCOUNT}`);
    assert.strictEqual(st.cleared, 1);
  }
  // a refused / failed / foreign-id delete reads not-revoked, and the clear still happens
  for (const handler of [() => jsonRes(404, { detail: 'not yours' }), () => jsonRes(401, {}), () => { throw new Error('offline'); }]) {
    const st = forgetStore({ status: 'unreadable', deviceId: null, secret: null, epoch: null });
    const r = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn: mockFetch({ [DEL]: handler }), store: st.store });
    assert.deepStrictEqual(r, { cleared: true, revoked: false, deviceId: DEVICE_ID, hintKept: true });
    assert.strictEqual(st.cleared, 1);
    assert.deepStrictEqual(st.hints, [DEVICE_ID], 'the id (never a secret) stays nameable for a later revoke');
  }
  // no hint and no session: nothing to revoke with, still cleared
  const st = forgetStore({ status: 'unreadable', deviceId: null, secret: null, epoch: null }, { hint: null });
  const fetchFn = mockFetch({ [DEL]: () => jsonRes(204, null) });
  assert.deepStrictEqual(await forgetDevice({ serverOrigin: ORIGIN, accountToken: null, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store: st.store }), { cleared: true, revoked: false, deviceId: null });
  assert.strictEqual(fetchFn.calls.length, 0);
});

test('forget never throws: a throwing read degrades to the id-only branch, and a clear that leaves files reports cleared:false', async () => {
  const st = forgetStore(null, { readThrows: true, clearRemoved: false });
  const fetchFn = mockFetch({ [DEL]: () => jsonRes(204, null) });
  const r = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store: st.store });
  assert.deepStrictEqual(r, { cleared: false, revoked: true, deviceId: DEVICE_ID });
});

test('forget: a successful revoke or an other-server identity keeps NO hint behind; a failed revoke on this server does', async () => {
  const okSt = forgetStore({ status: 'ok', deviceId: DEVICE_ID, secret: SECRET, epoch: 1 });
  await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn: mockFetch({ [DEL]: () => jsonRes(204, null) }), store: okSt.store });
  assert.deepStrictEqual(okSt.hints, []);
  const otherSt = forgetStore({ status: 'absent-for-this-server', deviceId: null, secret: null, epoch: null, otherOrigin: 'https://other.example' });
  const r = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn: mockFetch({}), store: otherSt.store });
  assert.deepStrictEqual(otherSt.hints, [], 'an id that belongs to another server is never kept as a hint for this one');
  assert.strictEqual(r.hintKept, undefined);
  const failSt = forgetStore({ status: 'ok', deviceId: DEVICE_ID, secret: SECRET, epoch: 1 });
  const r2 = await forgetDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, dir: '/x', safeStorage: mockSafe(true) }, { fetchFn: mockFetch({ [DEL]: () => { throw new Error('offline'); } }), store: failSt.store });
  assert.deepStrictEqual(r2, { cleared: true, revoked: false, deviceId: DEVICE_ID, hintKept: true });
  assert.deepStrictEqual(failSt.hints, [DEVICE_ID]);
  assert.deepStrictEqual(failSt.zeroized, [SECRET], 'the secret is still dropped');
});

test('a registration may start ONLY when the store is genuinely empty (absent) — never over an identity for another server, an unreadable blob, or no secure store', () => {
  assert.strictEqual(mayRegisterHere('absent'), true);
  for (const status of ['ok', 'absent-for-this-server', 'unreadable', 'no-secure-store', undefined, null, '', 'undecryptable', 'weird']) {
    assert.strictEqual(mayRegisterHere(status), false, `status ${JSON.stringify(status)} must not register`);
  }
});

test('registerDevice refuses to overwrite an existing identity: only an absent store registers; every other read status refuses BEFORE any request', async () => {
  for (const [readStatus, reason] of [['ok', 'already-registered'], ['absent-for-this-server', 'registered-elsewhere'], ['unreadable', 'identity-unreadable']]) {
    const store = mockStore(); store.readStatus = readStatus;
    const fetchFn = mockFetch({ 'POST /devices': () => jsonRes(201, { device_id: DEVICE_ID, secret: SECRET }) });
    const r = await registerDevice({ serverOrigin: ORIGIN, accountToken: ACCOUNT, label: 'x', dir: '/x', safeStorage: mockSafe(true) }, { fetchFn, store, identity: BENIGN });
    assert.deepStrictEqual(r, { ok: false, reason }, readStatus);
    assert.strictEqual(fetchFn.calls.length, 0, `${readStatus}: no server row is ever created over an existing identity`);
    assert.strictEqual(store.stored, null, 'nothing written');
  }
});

test('decideEnableDeviceStep: the probe gates first, then the stored identity decides the device action', () => {
  const d = (probeReason, secretStatus) => decideEnableDeviceStep({ probeReason, secretStatus });
  // The probe gates before the identity is even consulted.
  assert.deepStrictEqual(d('auth', 'absent'), { action: 'sign-in', reason: 'no-session' });
  assert.deepStrictEqual(d('too-old', 'absent'), { action: 'account-only', reason: 'server-too-old' });
  assert.deepStrictEqual(d('indeterminate', 'ok'), { action: 'account-only', reason: 'indeterminate' }, 'could not verify -> account path, never a device action');
  // Server supports device sync: the identity status decides.
  assert.deepStrictEqual(d('ok', 'absent'), { action: 'register', reason: null });
  assert.deepStrictEqual(d('ok', 'ok'), { action: 'grant-only', reason: null });
  assert.deepStrictEqual(d('ok', 'absent-for-this-server'), { action: 'forget-then-register', reason: 'registered-elsewhere' });
  assert.deepStrictEqual(d('ok', 'no-secure-store'), { action: 'account-only', reason: 'no-secure-store' });
  // A stale identity (rotation marker) is being re-checked, not unreadable — its own honest reason, account path meanwhile.
  assert.deepStrictEqual(d('ok', 'stale'), { action: 'account-only', reason: 'identity-stale' });
  // A transient / unreadable / unknown identity NEVER registers on top of a blob it could not read.
  assert.deepStrictEqual(d('ok', 'unreadable'), { action: 'account-only', reason: 'identity-unreadable' });
  assert.deepStrictEqual(d('ok', 'some-future-status'), { action: 'account-only', reason: 'identity-unreadable' });
});

test('nextUnreadableStreak: advances only on an unreadable read while UNLOCKED; a locked tick or any readable read resets it', () => {
  let s = 0;
  for (let i = 0; i < 3; i++) s = nextUnreadableStreak(s, { status: 'unreadable', appLocked: false });
  assert.strictEqual(s, 3, 'three unreadable-while-unlocked reads reach the threshold');
  assert.strictEqual(nextUnreadableStreak(3, { status: 'unreadable', appLocked: true }), 0, 'a locked unreadable tick does NOT count — a keyring locked with the screen must not trip a reset');
  for (const status of ['ok', 'stale', 'absent', 'no-secure-store', 'absent-for-this-server']) {
    assert.strictEqual(nextUnreadableStreak(9, { status, appLocked: false }), 0, `a readable '${status}' read resets the streak`);
  }
  assert.strictEqual(nextUnreadableStreak(undefined, { status: 'unreadable', appLocked: false }), 1, 'a missing prev counts as zero');
  assert.strictEqual(nextUnreadableStreak(-5, { status: 'unreadable', appLocked: false }), 1, 'a nonsense prev counts as zero');
});

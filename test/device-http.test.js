'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {
  deviceRequest, DeviceRequestError, ROUTES,
} = require('../src/main/device-http');

const ORIGIN = 'https://vault.example';
const SECRET = 'opaque-device-bearer-secret-xyz789';

// A recording fetch stand-in: captures the (url, init) it was called with, and returns a configurable
// response of the httpJson shape { ok, status, json }. `throws` simulates a transport error whose
// message deliberately embeds the secret + URL, to prove the client never re-surfaces them.
function recordingFetch(response, { throws = null } = {}) {
  const calls = [];
  const fn = async (url, init) => {
    calls.push({ url, init });
    if (throws) throw new Error(throws);
    return response;
  };
  fn.calls = calls;
  return fn;
}
function jsonRes(status, body) {
  return { ok: status >= 200 && status < 300, status, json: async () => body };
}

test('allowlist: an unknown route is refused LOCALLY (no network) with route-not-allowed', async () => {
  const fetchFn = recordingFetch(jsonRes(200, {}));
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'admin' }, fetchFn),
    (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'route-not-allowed',
  );
  assert.strictEqual(fetchFn.calls.length, 0, 'a disallowed route never reaches the network');
});

test('a missing/empty secret is refused LOCALLY (no network) with no-device-secret', async () => {
  const fetchFn = recordingFetch(jsonRes(200, {}));
  for (const bad of ['', undefined, null]) {
    await assert.rejects(
      () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: bad, route: 'grants' }, fetchFn),
      (e) => e instanceof DeviceRequestError && e.reason === 'no-device-secret',
    );
  }
  assert.strictEqual(fetchFn.calls.length, 0, 'no secret -> never reaches the network');
});

test('only the three device routes are reachable; each maps to its fixed method + path', () => {
  assert.deepStrictEqual(Object.keys(ROUTES).sort(), ['grants', 'mint', 'refresh']);
  assert.deepStrictEqual(ROUTES.mint, { method: 'POST', path: '/device/sync-credential' });
  assert.deepStrictEqual(ROUTES.refresh, { method: 'POST', path: '/device/refresh' });
  assert.deepStrictEqual(ROUTES.grants, { method: 'GET', path: '/device/grants' });
});

test('a GET route attaches the Bearer secret, hits the fixed path, and sends no body', async () => {
  const fetchFn = recordingFetch(jsonRes(200, { grants: [] }));
  const out = await deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants', body: { ignored: true } }, fetchFn);
  assert.deepStrictEqual(out, { grants: [] });
  const { url, init } = fetchFn.calls[0];
  assert.strictEqual(url, `${ORIGIN}/device/grants`);
  assert.strictEqual(init.method, 'GET');
  assert.strictEqual(init.headers.Authorization, `Bearer ${SECRET}`);
  assert.ok(!('body' in init), 'a GET route sends no body even if one is passed');
  assert.ok(!('Content-Type' in init.headers));
});

test('a POST route serializes the body and sets Content-Type, with the Bearer secret', async () => {
  const fetchFn = recordingFetch(jsonRes(200, { id: 'cred1' }));
  await deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'mint', body: { vault_id: 'v1' } }, fetchFn);
  const { url, init } = fetchFn.calls[0];
  assert.strictEqual(url, `${ORIGIN}/device/sync-credential`);
  assert.strictEqual(init.method, 'POST');
  assert.strictEqual(init.headers.Authorization, `Bearer ${SECRET}`);
  assert.strictEqual(init.headers['Content-Type'], 'application/json');
  assert.strictEqual(init.body, JSON.stringify({ vault_id: 'v1' }));
});

test('known server reasons map to their fixed literals; the status is preserved', async () => {
  const cases = [
    [401, 'device-revoked'], [401, 'device-secret-stale'], [409, 'device-cred-cap'],
    [503, 'host-key-unavailable'], [401, 'invalid-device-credential'], [400, 'grant-needs-reproof'],
  ];
  for (const [status, reason] of cases) {
    const fetchFn = recordingFetch(jsonRes(status, { detail: { reason, message: 'human text' } }));
    await assert.rejects(
      () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'mint', body: {} }, fetchFn),
      (e) => e.status === status && e.reason === reason,
    );
  }
});

test('an unknown or missing reason fails closed to device-request-refused (non-retrying default)', async () => {
  for (const body of [{ detail: { reason: 'a-brand-new-reason' } }, { detail: {} }, {}, null]) {
    const fetchFn = recordingFetch(jsonRes(400, body));
    await assert.rejects(
      () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'mint', body: {} }, fetchFn),
      (e) => e.reason === 'device-request-refused',
    );
  }
});

test('a codeless throw is our own internal-error, not a laundered retryable network reason', async () => {
  const fetchFn = recordingFetch(null, { throws: 'boom' }); // a bare Error: no platform code, no net::ERR_
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
    (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'internal-error' && e.code === null,
  );
});

test('the transport codes http-json actually produces (ETIMEDOUT, ERESPONSE_TOO_LARGE) classify as network — a timeout/size-cap is retryable, not our internal-error', async () => {
  for (const code of ['ETIMEDOUT', 'ERESPONSE_TOO_LARGE']) {
    const fetchFn = async () => { throw Object.assign(new Error('transport failed'), { code }); };
    await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
      (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'network' && e.code === code);
  }
});

test('a NON-transport throw (a bug in the injected fetchFn) surfaces as internal-error, never network', async () => {
  const buggy = async () => { const x = null; return x.nope; }; // a TypeError: no transport signature at all
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, buggy),
    (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'internal-error' && e.code === null,
  );
});

test('a CODED but NON-network throw (a Node programming error) is internal-error, never a laundered network reason', async () => {
  // The classify-by-shape bug (live-proof row d): a Node type error carries code ERR_INVALID_ARG_TYPE, which the
  // transportCode SHAPE extractor matches — but it is a bug in our path, not a transport failure, and must not be
  // retried forever as 'network'. The classifier is the allowlist (isTransportError), not the shape.
  const fetchFn = async () => { throw Object.assign(new TypeError('bad arg'), { code: 'ERR_INVALID_ARG_TYPE' }); };
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
    (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'internal-error' && e.code === null,
  );
});

test("a Chromium net::ERR_ message (no .code) classifies as network — refused/DNS over Electron net", async () => {
  const fetchFn = async () => { throw new Error('request failed: net::ERR_CONNECTION_REFUSED'); };
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
    (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'network' && e.code === 'ERR_CONNECTION_REFUSED',
  );
});

test('a 2xx with an unreadable body fails closed rather than returning garbage', async () => {
  const fetchFn = recordingFetch({ ok: true, status: 200, json: async () => { throw new Error('bad json'); } });
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
    (e) => e instanceof DeviceRequestError && e.reason === 'device-request-refused',
  );
});

test('NEVER-LOGGED: a thrown error carries neither the secret, the URL, nor the response body', async () => {
  const b64 = Buffer.from(SECRET, 'utf8').toString('base64');
  const carriesSecret = (e) => {
    const blob = `${e.message}\n${e.stack || ''}\n${JSON.stringify(e, Object.getOwnPropertyNames(e))}`;
    return blob.includes(SECRET) || blob.includes(b64);
  };
  // (a) transport error whose underlying message embeds the secret + URL — must not re-surface either.
  const netFetch = recordingFetch(null, { throws: `connect ECONNREFUSED ${ORIGIN}/device/grants header Bearer ${SECRET}` });
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, netFetch),
    (e) => !carriesSecret(e) && !e.message.includes('ECONNREFUSED') && !e.message.includes(ORIGIN),
  );
  // (b) a non-2xx whose response body echoes the secret — the error carries only the mapped reason.
  const bodyFetch = recordingFetch(jsonRes(401, { detail: { reason: 'device-revoked', message: `secret is ${SECRET}` } }));
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'mint', body: { p: SECRET } }, bodyFetch),
    (e) => e.reason === 'device-revoked' && !carriesSecret(e),
  );
});

test('inherited Object.prototype keys do NOT bypass the allowlist (own-property check; no network)', async () => {
  const fetchFn = recordingFetch(jsonRes(200, {}));
  for (const route of ['toString', 'constructor', 'hasOwnProperty', '__proto__', 'valueOf', 'isPrototypeOf']) {
    await assert.rejects(
      () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route }, fetchFn),
      (e) => e instanceof DeviceRequestError && e.reason === 'route-not-allowed',
    );
  }
  assert.strictEqual(fetchFn.calls.length, 0, 'a prototype-key route never reaches the network');
});

test('an unserializable body is refused LOCALLY as a DeviceRequestError, not a raw TypeError (no network)', async () => {
  const fetchFn = recordingFetch(jsonRes(200, {}));
  const circular = {}; circular.self = circular; // JSON.stringify would throw and enumerate property names
  await assert.rejects(
    () => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'mint', body: circular }, fetchFn),
    (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === 'device-request-refused',
  );
  assert.strictEqual(fetchFn.calls.length, 0, 'a bad body is caught before any network call');
});

test('a 5xx is the server failing, not refusing: it maps to the distinct retryable server-error, never a refusal literal', async () => {
  for (const status of [500, 502, 503, 504]) {
    const fetchFn = recordingFetch(jsonRes(status, { detail: 'internal error text' })); // no typed reason
    await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
      (e) => e instanceof DeviceRequestError && e.status === status && e.reason === 'server-error');
    await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, recordingFetch({ ok: false, status, json: async () => { throw new Error('html'); } })),
      (e) => e.reason === 'server-error', 'an unreadable 5xx body is still the server failing');
  }
  // a typed answer wins whatever the status (the server answers host-key-unavailable with a 503)
  await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'mint', body: {} }, recordingFetch(jsonRes(503, { detail: { reason: 'host-key-unavailable' } }))),
    (e) => e.status === 503 && e.reason === 'host-key-unavailable');
  // a 4xx keeps the fixed-literal mapping
  await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, recordingFetch(jsonRes(401, { detail: { reason: 'device-revoked' } }))),
    (e) => e.reason === 'device-revoked');
});

test('a coded transport failure is network (keeping only the bare code); a codeless throw is internal-error — neither leaks the message, URL, or secret', async () => {
  // A recognizable platform code → a genuine network failure keeping that token; an absent/invalid code → not
  // a transport failure at all → our own internal-error. Either way, never the message, URL, or the secret.
  for (const [code, expect] of [['ECONNREFUSED', 'ECONNREFUSED'], ['ENOTFOUND', 'ENOTFOUND'], ['ECONNRESET', 'ECONNRESET'], [undefined, null], ['weird code!', null], [42, null], ['x'.repeat(40), null]]) {
    const fetchFn = async () => { throw Object.assign(new Error(`dial failed for Bearer ${SECRET} at ${ORIGIN}`), code === undefined ? {} : { code }); };
    await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
      (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === (expect ? 'network' : 'internal-error') && e.code === expect
        && !String(e.message).includes(SECRET) && !String(e.stack).includes(SECRET) && !String(e.message).includes(ORIGIN));
  }
  // a Chromium-shaped transport failure names itself only in the message: the net::ERR_ token is lifted (network);
  // a message with no such token is not a transport failure → internal-error. Nothing but the token is ever kept.
  for (const [message, expect] of [[`net::ERR_CONNECTION_REFUSED at ${ORIGIN} Bearer ${SECRET}`, 'ERR_CONNECTION_REFUSED'], ['net::ERR_NAME_NOT_RESOLVED', 'ERR_NAME_NOT_RESOLVED'], ['Request was cancelled', null], [`net::err_lowercase ${SECRET}`, null]]) {
    const fetchFn = async () => { throw new Error(message); };
    await assert.rejects(() => deviceRequest({ serverOrigin: ORIGIN, deviceSecret: SECRET, route: 'grants' }, fetchFn),
      (e) => e instanceof DeviceRequestError && e.status === 0 && e.reason === (expect ? 'network' : 'internal-error') && e.code === expect
        && !String(e.message).includes(SECRET) && !String(e.stack).includes(SECRET) && !String(e.message).includes(ORIGIN));
  }
});

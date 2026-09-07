'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { mintDeviceSftpAccess, bundleFromMintResponse, DEVICE_MINT_VALIDITY_MINUTES } = require('../src/main/device-mint');
const { ROUTES } = require('../src/main/device-http');

const ORIGIN = 'https://vault.example:8443';
const SECRET = 'opaque-device-secret-DO-NOT-LOG-4477';
const VAULT_ID = '3f2b1c0a-9d8e-4f7a-b6c5-d4e3f2a1b0c9';
const KEY = 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGxvbmctZW5vdWdoLXRvLWxvb2stbGlrZS1hLWtleS1ibG9i';

function goodBody(extra) {
  return {
    id: 'cred-1', temp_username: 'tmp_abc', credential: 'cred-password-DO-NOT-LOG', created_at: '2026-09-05T10:00:00Z',
    deactivate_at: '2026-09-05T10:15:00Z', expires_at: '2026-09-05T11:00:00Z', validity_minutes: 15, total_lifetime_minutes: 60,
    vault_id: VAULT_ID, host_public_key: KEY, port: 2360, host: null, ...extra,
  };
}
function res(status, body) { return { ok: status >= 200 && status < 300, status, json: async () => body }; }
function recordingFetch(response, { throws = null } = {}) {
  const calls = [];
  const fn = async (url, init) => { calls.push({ url, init }); if (throws) throw new Error(throws); return response; };
  fn.calls = calls;
  return fn;
}
const mint = (fetchFn, args) => mintDeviceSftpAccess({ serverOrigin: ORIGIN, deviceSecret: SECRET, vaultId: VAULT_ID, ...args }, fetchFn);

test('happy: one POST to the mint route with the device Bearer; body is exactly {vault_id, validity_minutes:15}; bundle has the helper shape', async () => {
  const fetchFn = recordingFetch(res(200, goodBody()));
  const b = await mint(fetchFn);
  assert.strictEqual(fetchFn.calls.length, 1);
  const { url, init } = fetchFn.calls[0];
  assert.strictEqual(url, `${ORIGIN}${ROUTES.mint.path}`);
  assert.strictEqual(init.method, 'POST');
  assert.strictEqual(init.headers.Authorization, `Bearer ${SECRET}`);
  assert.deepStrictEqual(JSON.parse(init.body), { vault_id: VAULT_ID, validity_minutes: 15 });
  assert.strictEqual(DEVICE_MINT_VALIDITY_MINUTES, 15);
  assert.deepStrictEqual(b, { host: 'vault.example', port: 2360, user: 'tmp_abc', password: 'cred-password-DO-NOT-LOG', hostKeys: KEY, expiresAt: '2026-09-05T10:15:00Z' });
  assert.ok(!Object.values(b).some((v) => typeof v === 'string' && v.includes(SECRET)), 'the device secret never rides in the bundle');
});

test('the SFTP host: the API host by default; an advertised host when the server sets a well-formed one; a malformed one is refused', async () => {
  assert.strictEqual((await mint(recordingFetch(res(200, goodBody({ host: undefined }))))).host, 'vault.example');
  assert.strictEqual((await mint(recordingFetch(res(200, goodBody({ host: 'sftp.vault.example' }))))).host, 'sftp.vault.example');
  assert.strictEqual((await mint(recordingFetch(res(200, goodBody({ host: ' 10.0.0.7 ' }))))).host, '10.0.0.7');
  assert.strictEqual((await mint(recordingFetch(res(200, goodBody({ host: '2001:db8::1' }))))).host, '2001:db8::1');
  for (const bad of ['', 'host with space', 'sftp://x', 'a/b', 'evil.example:2222', 42, {}, '-bad.example', 'x'.repeat(300)]) {
    await assert.rejects(() => mint(recordingFetch(res(200, goodBody({ host: bad })))), (e) => e.reason === 'device-request-refused', `host ${JSON.stringify(bad)} must be refused`);
  }
});

test('the host key must be a full OpenSSH public-key line — a fingerprint, empty, missing or non-string key fails closed as cannot-verify (no trust-on-first-use)', async () => {
  for (const bad of ['SHA256:abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG', '', '   ', undefined, null, 42, { key: KEY }, 'ssh-ed25519']) {
    await assert.rejects(() => mint(recordingFetch(res(200, goodBody({ host_public_key: bad })))), (e) => e.reason === 'host-key-unavailable', `key ${JSON.stringify(bad)}`);
  }
  // Whitespace around a real key is tolerated; the pinned value is the trimmed line.
  assert.strictEqual((await mint(recordingFetch(res(200, goodBody({ host_public_key: `  ${KEY}\n` }))))).hostKeys, KEY);
  for (const algo of ['ssh-rsa AAAAB3NzaC1yc2E', 'ecdsa-sha2-nistp256 AAAAE2VjZHNh', 'sk-ssh-ed25519@openssh.com AAAAGnNr']) {
    assert.strictEqual((await mint(recordingFetch(res(200, goodBody({ host_public_key: algo }))))).hostKeys, algo);
  }
});

test('a malformed credential body is refused with the fixed non-retrying literal (never a partial bundle)', async () => {
  const cases = [
    goodBody({ port: undefined }), goodBody({ port: 0 }), goodBody({ port: 70000 }), goodBody({ port: '2360' }), goodBody({ port: 2360.5 }),
    goodBody({ temp_username: '' }), goodBody({ temp_username: undefined }), goodBody({ credential: '' }), goodBody({ credential: 7 }),
    null, 'a string', [], 42,
  ];
  for (const body of cases) {
    await assert.rejects(() => mint(recordingFetch(res(200, body))), (e) => e.reason === 'device-request-refused', `body ${JSON.stringify(body)}`);
  }
  assert.throws(() => bundleFromMintResponse(goodBody({ port: -1 }), 'h'), (e) => e.reason === 'device-request-refused');
});

test('a non-2xx propagates the device client\'s TYPED reason unchanged, so each refusal keeps its own state', async () => {
  const cases = [
    [403, 'grant-needs-reproof'], [401, 'device-revoked'], [401, 'device-expired'], [401, 'device-suspended'],
    [403, 'account-inactive'], [403, 'no-grant'], [403, 'vault-not-standard'], [409, 'device-cred-cap'], [503, 'host-key-unavailable'],
  ];
  for (const [status, reason] of cases) {
    await assert.rejects(() => mint(recordingFetch(res(status, { detail: { reason, message: 'refused' } }))), (e) => e.status === status && e.reason === reason);
  }
  await assert.rejects(() => mint(recordingFetch(res(500, { detail: 'boom' }))), (e) => e.reason === 'server-error'); // a failing server is retryable, not a refusal
  await assert.rejects(() => mint(recordingFetch(res(403, { detail: { reason: 'brand-new-reason' } }))), (e) => e.reason === 'device-request-refused');
  await assert.rejects(() => mint(async () => { throw Object.assign(new Error('down'), { code: 'ECONNREFUSED' }); }), (e) => e.status === 0 && e.reason === 'network'); // a CODED transport failure is network; a codeless throw is internal-error (device-http)
});

test('validity: a positive integer override is sent; anything else falls back to the default', async () => {
  const body = (f) => JSON.parse(f.calls[0].init.body);
  let f = recordingFetch(res(200, goodBody())); await mint(f, { validityMinutes: 5 }); assert.strictEqual(body(f).validity_minutes, 5);
  for (const v of [0, -3, 2.5, '5', null, undefined]) {
    f = recordingFetch(res(200, goodBody())); await mint(f, { validityMinutes: v }); assert.strictEqual(body(f).validity_minutes, 15, `override ${JSON.stringify(v)}`);
  }
});

test('a bad vault id, origin, or secret is refused LOCALLY — no request is made', async () => {
  for (const vaultId of ['', undefined, null, 42]) {
    const f = recordingFetch(res(200, goodBody()));
    await assert.rejects(() => mint(f, { vaultId }), (e) => e.reason === 'device-request-refused');
    assert.strictEqual(f.calls.length, 0);
  }
  let f = recordingFetch(res(200, goodBody()));
  await assert.rejects(() => mint(f, { serverOrigin: 'not a url' }), (e) => e.reason === 'device-request-refused');
  assert.strictEqual(f.calls.length, 0);
  f = recordingFetch(res(200, goodBody()));
  await assert.rejects(() => mint(f, { deviceSecret: '' }), (e) => e.reason === 'no-device-secret');
  assert.strictEqual(f.calls.length, 0);
});

test('NEVER-LOGGED: no mint path writes the device secret (plaintext or base64) or the credential to any log sink, error message, or stack', async () => {
  const sinks = [];
  const orig = { log: console.log, error: console.error, warn: console.warn, info: console.info, debug: console.debug, out: process.stdout.write, err: process.stderr.write };
  const cap = (...a) => { sinks.push(a.map(String).join(' ')); };
  console.log = cap; console.error = cap; console.warn = cap; console.info = cap; console.debug = cap;
  process.stdout.write = (s) => { sinks.push(String(s)); return true; };
  process.stderr.write = (s) => { sinks.push(String(s)); return true; };
  const errors = [];
  try {
    console.log('planted ' + SECRET); // non-vacuity: the capture sees what is logged
    await mint(recordingFetch(res(200, goodBody())));
    for (const run of [
      () => mint(recordingFetch(res(200, { echo: SECRET, temp_username: 'u', credential: 'c', host_public_key: 'SHA256:fp', port: 1 }))),
      () => mint(recordingFetch(res(401, { detail: { reason: 'device-revoked', message: `secret was ${SECRET}` } }))),
      () => mint(recordingFetch(null, { throws: `dial tcp failed for Bearer ${SECRET}` })),
      () => mint(recordingFetch(res(200, goodBody({ port: 'x', note: SECRET })))),
    ]) {
      try { await run(); assert.fail('expected a refusal'); } catch (e) { errors.push(e); }
    }
  } finally {
    console.log = orig.log; console.error = orig.error; console.warn = orig.warn; console.info = orig.info; console.debug = orig.debug;
    process.stdout.write = orig.out; process.stderr.write = orig.err;
  }
  const b64 = Buffer.from(SECRET).toString('base64');
  assert.ok(sinks.some((s) => s.includes('planted ' + SECRET)), 'the planted line was captured (non-vacuous)');
  const leaked = sinks.filter((s) => !s.startsWith('planted ') && (s.includes(SECRET) || s.includes(b64) || s.includes('cred-password')));
  assert.deepStrictEqual(leaked, [], 'no sink received the secret or credential');
  assert.strictEqual(errors.length, 4);
  for (const e of errors) {
    const text = String(e && e.message) + String(e && e.stack) + JSON.stringify(e);
    assert.ok(!text.includes(SECRET) && !text.includes(b64), 'no error carries the secret');
    assert.ok(typeof e.reason === 'string' && e.reason, 'every refusal is typed');
  }
});

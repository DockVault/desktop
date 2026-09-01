'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { buildSyncScope, mintTempCred, fetchHostKey, mintSftpAccess, SYNC_CAPS, SFTP_PORT } = require('../src/main/sftp-cred');

// A mock fetch recording each call; `routes` maps a path substring to a { status, body } response.
function mockFetch(routes) {
  const calls = [];
  const fn = async (url, opts = {}) => {
    calls.push({ url, opts, body: opts.body ? JSON.parse(opts.body) : undefined });
    const hit = Object.keys(routes).find((p) => url.includes(p));
    const r = hit ? routes[hit] : { status: 404, body: { detail: 'not found' } };
    return { ok: r.status >= 200 && r.status < 300, status: r.status, json: async () => r.body };
  };
  fn.calls = calls;
  return fn;
}

const ORIGIN = 'https://vault.example';
const TOKEN = 'ACCOUNT-SESSION-TOKEN-do-not-leak';

test('buildSyncScope is least-privilege: one vault with the sync file/folder caps, no pages, no temp caps', () => {
  const s = buildSyncScope('vault-1');
  assert.strictEqual(s.vault_access_mode, 'selected');
  // The caps sit BOTH on the entry and in vault_caps_default — the server applies per-vault caps from
  // vault_caps_default, so an empty one grants nothing (SFTP writes denied).
  assert.deepStrictEqual(s.selected_vaults, [{ vault_id: 'vault-1', caps: SYNC_CAPS }]);
  assert.deepStrictEqual(s.scope.vault_caps_default, SYNC_CAPS);
  // Only file/folder (and see-files) operations — never vault management, permissions, or temp-cred minting.
  for (const c of SYNC_CAPS) assert.match(c, /^(file\.|folder\.|vault\.see_files)/, `${c} is a file/folder op only`);
  assert.deepStrictEqual(s.scope.pages, [], 'no navigation pages');
  assert.deepStrictEqual(s.scope.caps, [], 'no global caps');
  assert.deepStrictEqual(s.scope.temp, {}, 'no temp-credential-management caps');
  assert.strictEqual(s.scope.v, 1);
});

test('buildSyncScope carries a vault-password proof only when one is provided', () => {
  assert.ok(!('password' in buildSyncScope('v').selected_vaults[0]));
  assert.strictEqual(buildSyncScope('v', 'vaultpw').selected_vaults[0].password, 'vaultpw');
});

test('mintTempCred POSTs the scoped body with the account Bearer, and returns only the temp cred', async () => {
  const fetchFn = mockFetch({ '/auth/temp-credentials': { status: 200, body: { temp_username: 'tc_x', credential: 'pw_y', expires_at: 'T+15' } } });
  const out = await mintTempCred({ serverOrigin: ORIGIN, sessionToken: TOKEN, vaultId: 'v1', validityMinutes: 15 }, fetchFn);
  assert.deepStrictEqual(out, { user: 'tc_x', password: 'pw_y', expiresAt: 'T+15' });
  const call = fetchFn.calls[0];
  assert.match(call.url, /\/auth\/temp-credentials$/);
  assert.strictEqual(call.opts.headers.Authorization, `Bearer ${TOKEN}`);
  assert.strictEqual(call.body.vault_access_mode, 'selected');
  assert.strictEqual(call.body.selected_vaults[0].vault_id, 'v1');
  assert.strictEqual(call.body.validity_minutes, 15);
});

test('mintTempCred fails on a non-2xx response and on a response missing credentials', async () => {
  await assert.rejects(() => mintTempCred({ serverOrigin: ORIGIN, sessionToken: TOKEN, vaultId: 'v1' }, mockFetch({ '/auth/temp-credentials': { status: 400, body: { detail: 'nope' } } })), /mint request failed: 400/);
  await assert.rejects(() => mintTempCred({ serverOrigin: ORIGIN, sessionToken: TOKEN, vaultId: 'v1' }, mockFetch({ '/auth/temp-credentials': { status: 200, body: { temp_username: 'x' } } })), /missing credentials/);
});

test('fetchHostKey returns a FULL public key to pin, and FAILS CLOSED otherwise (no TOFU)', async () => {
  // Full OpenSSH public-key lines are accepted (Option 1: the server exposes its full key).
  assert.strictEqual(await fetchHostKey({ serverOrigin: ORIGIN, sessionToken: TOKEN }, mockFetch({ '/sftp/host-key': { status: 200, body: { host_keys: ['ssh-ed25519 AAAABBB', 'ssh-rsa CCCDDD'] } } })), 'ssh-ed25519 AAAABBB,ssh-rsa CCCDDD');
  assert.strictEqual(await fetchHostKey({ serverOrigin: ORIGIN, sessionToken: TOKEN }, mockFetch({ '/sftp/host-key': { status: 200, body: { public_key: 'ssh-ed25519 EEEFFF' } } })), 'ssh-ed25519 EEEFFF');
  // Unavailable -> fail closed.
  await assert.rejects(() => fetchHostKey({ serverOrigin: ORIGIN, sessionToken: TOKEN }, mockFetch({ '/sftp/host-key': { status: 200, body: { available: false } } })), /host key unavailable/);
  // FINGERPRINT-ONLY (available, but only a fingerprint) -> fail closed: a fingerprint alone cannot pin.
  await assert.rejects(() => fetchHostKey({ serverOrigin: ORIGIN, sessionToken: TOKEN }, mockFetch({ '/sftp/host-key': { status: 200, body: { available: true, algorithm: 'ssh-ed25519', fingerprint_sha256: 'SHA256:EXAMPLE-not-a-real-fingerprint' } } })), /a fingerprint alone is insufficient/);
  // Nothing usable -> fail closed.
  await assert.rejects(() => fetchHostKey({ serverOrigin: ORIGIN, sessionToken: TOKEN }, mockFetch({ '/sftp/host-key': { status: 200, body: {} } })), /did not provide a full SFTP host public key/);
});

test('mintSftpAccess returns the per-run bundle and leaks neither the account token nor the vault password', async () => {
  const fetchFn = mockFetch({
    '/sftp/host-key': { status: 200, body: { host_keys: ['ssh-ed25519 HOSTKEY'] } },
    '/auth/temp-credentials': { status: 200, body: { temp_username: 'tc_z', credential: 'pw_z', expires_at: 'T+15' } },
  });
  const bundle = await mintSftpAccess({ serverOrigin: ORIGIN, sessionToken: TOKEN, vaultId: 'v1', validityMinutes: 15, vaultPassword: 'VAULTPW' }, fetchFn);
  assert.deepStrictEqual(bundle, { host: 'vault.example', port: SFTP_PORT, user: 'tc_z', password: 'pw_z', hostKeys: 'ssh-ed25519 HOSTKEY', expiresAt: 'T+15' });
  const serialized = JSON.stringify(bundle);
  assert.ok(!serialized.includes(TOKEN), 'the account session token never appears in the bundle');
  assert.ok(!serialized.includes('VAULTPW'), 'the vault-password proof never appears in the bundle');
});

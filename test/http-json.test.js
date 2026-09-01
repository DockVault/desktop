'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { httpJson } = require('../src/main/http-json');
const { fetchStandardVaults } = require('../src/main/sync-vaults');
const { mintTempCred } = require('../src/main/sftp-cred');

// Stand up a throwaway localhost server that records the request it receives (method, url, headers, and
// the full request body) and lets `handler` reply. `received` is filled in once a request arrives.
async function withServer(handler, run) {
  const received = {};
  const server = http.createServer((req, res) => {
    let body = '';
    req.on('data', (c) => { body += c; });
    req.on('end', () => {
      received.method = req.method;
      received.url = req.url;
      received.headers = req.headers;
      received.body = body;
      handler(req, res);
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  try { return await run(origin, received); } finally { await new Promise((r) => server.close(r)); }
}

test('the vault-list fetch actually sends Authorization: Bearer to the server (real request)', async () => {
  await withServer(
    (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('[]'); },
    async (origin, received) => {
      await fetchStandardVaults({ serverOrigin: origin, sessionToken: 'TESTTOKEN' }, httpJson);
      // The load-bearing observable consequence: the Authorization header ARRIVED at the server.
      assert.strictEqual(received.headers.authorization, 'Bearer TESTTOKEN', 'Authorization: Bearer reached the server');
      // And the fetch-style init object was NOT mistaken for the header map — no junk header names sent.
      assert.strictEqual(received.headers.method, undefined, 'no "method" header leaked from a mis-passed init');
      assert.strictEqual(received.headers.headers, undefined, 'no "headers" header leaked from a mis-passed init');
      assert.strictEqual(received.method, 'GET');
      assert.strictEqual(received.url, '/vaults');
    },
  );
});

test('a real response body is parsed and filtered to Standard vaults, with the excluded flag set', async () => {
  const list = [
    { id: 'v1', name: 'Docs', vault_type: 'standard' },
    { id: 'v2', name: 'Secrets', vault_type: 'zero_knowledge' },
    { id: 'v3', name: 'Photos', type: 'standard' },
  ];
  await withServer(
    (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify(list)); },
    async (origin) => {
      const { vaults, someExcluded } = await fetchStandardVaults({ serverOrigin: origin, sessionToken: 't' }, httpJson);
      assert.deepStrictEqual(vaults, [{ vaultId: 'v1', vaultName: 'Docs' }, { vaultId: 'v3', vaultName: 'Photos' }]);
      assert.strictEqual(someExcluded, true, 'the zero-knowledge vault is excluded and the note flag is set');
    },
  );
});

test('a non-OK status fails closed (throws), never returns a partial list', async () => {
  await withServer(
    (req, res) => { res.writeHead(401); res.end('nope'); },
    async (origin) => {
      await assert.rejects(
        () => fetchStandardVaults({ serverOrigin: origin, sessionToken: 't' }, httpJson),
        /status 401/,
      );
    },
  );
});

test('a POST body is actually written and length-declared, and the caller Content-Type is honoured', async () => {
  const payload = JSON.stringify({ hello: 'world' });
  await withServer(
    (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('{"ok":true}'); },
    async (origin, received) => {
      const res = await httpJson(`${origin}/echo`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', Authorization: 'Bearer T' },
        body: payload,
      });
      assert.strictEqual(received.method, 'POST');
      assert.deepStrictEqual(JSON.parse(received.body), { hello: 'world' }, 'the body arrived intact — not dropped');
      assert.strictEqual(received.headers['content-length'], String(Buffer.byteLength(payload)), 'Content-Length was declared');
      assert.strictEqual(received.headers['content-type'], 'application/json', 'the caller Content-Type is honoured, not overridden');
      assert.strictEqual(received.headers.authorization, 'Bearer T');
      assert.strictEqual((await res.json()).ok, true);
    },
  );
});

// The forward path: the cred mint POSTs a body. Driving the REAL mint through httpJson proves the body
// is carried end to end (the failure the vault-list bug was, in POST form) before any wiring depends on it.
test('the cred mint driven through httpJson sends its scoped body and returns the credentials', async () => {
  await withServer(
    (req, res) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end(JSON.stringify({ temp_username: 'tc_x', credential: 'obscured_form', expires_at: '2026-01-01T00:00:00Z' })); },
    async (origin, received) => {
      const cred = await mintTempCred({ serverOrigin: origin, sessionToken: 'SESS', vaultId: 'v9', validityMinutes: 15 }, httpJson);
      assert.strictEqual(received.method, 'POST');
      assert.strictEqual(received.url, '/auth/temp-credentials');
      assert.strictEqual(received.headers.authorization, 'Bearer SESS');
      assert.strictEqual(received.headers['content-type'], 'application/json');
      const body = JSON.parse(received.body); // the observable consequence: the request body reached the server
      assert.strictEqual(body.selected_vaults[0].vault_id, 'v9', 'the scoped vault id reached the server');
      assert.strictEqual(body.validity_minutes, 15);
      assert.deepStrictEqual(cred, { user: 'tc_x', password: 'obscured_form', expiresAt: '2026-01-01T00:00:00Z' });
    },
  );
});

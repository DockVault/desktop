'use strict';

const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const { httpJson } = require('../src/main/http-json');
const { fetchStandardVaults } = require('../src/main/sync-vaults');

// Stand up a throwaway localhost server that records the request it receives and replies with `body`.
// Returns { origin, received } where `received` is filled in once a request arrives.
async function withServer(handler, run) {
  const received = {};
  const server = http.createServer((req, res) => {
    received.method = req.method;
    received.url = req.url;
    received.headers = req.headers;
    handler(req, res);
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

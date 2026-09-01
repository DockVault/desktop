'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { vaultTier, isStandardVault, filterStandardVaults, fetchStandardVaults } = require('../src/main/sync-vaults');

test('vaultTier reads the server field (vault_type preferred, type accepted); non-string => null', () => {
  assert.strictEqual(vaultTier({ vault_type: 'standard' }), 'standard');
  assert.strictEqual(vaultTier({ type: 'zero_knowledge' }), 'zero_knowledge');
  assert.strictEqual(vaultTier({ vault_type: 'standard', type: 'zero_knowledge' }), 'standard'); // server field wins
  assert.strictEqual(vaultTier({}), null);
  assert.strictEqual(vaultTier({ vault_type: 42 }), null);
  assert.strictEqual(vaultTier(null), null);
});

test('only an explicit Standard vault is eligible (fail-closed on zk / unknown / missing)', () => {
  assert.strictEqual(isStandardVault({ vault_type: 'standard' }), true);
  assert.strictEqual(isStandardVault({ vault_type: 'zero_knowledge' }), false);
  assert.strictEqual(isStandardVault({ vault_type: 'STANDARD' }), false, 'exact match only, no case-fold');
  assert.strictEqual(isStandardVault({ vault_type: 'weird_future_tier' }), false);
  assert.strictEqual(isStandardVault({}), false, 'missing tier is excluded');
});

test('filterStandardVaults keeps only Standard and drops everything else', () => {
  const list = [
    { id: 'a', name: 'Marketing', vault_type: 'standard' },
    { id: 'b', name: 'Secrets', vault_type: 'zero_knowledge' },
    { id: 'c', name: 'Legacy', /* no tier */ },
    { id: 'd', name: 'Future', vault_type: 'quantum' },
    { id: 'e', name: 'Ops', type: 'standard' },
  ];
  assert.deepStrictEqual(filterStandardVaults(list).map((v) => v.id), ['a', 'e']);
  assert.deepStrictEqual(filterStandardVaults(null), []);
  assert.deepStrictEqual(filterStandardVaults(undefined), []);
});

test('fetchStandardVaults: GETs /vaults with the account bearer and returns only Standard { vaultId, vaultName }', async () => {
  let seen = null;
  const fetchFn = async (url, init) => {
    seen = { url, init };
    return {
      ok: true, status: 200,
      json: async () => [
        { id: 'a', name: 'Marketing', type: 'standard' },
        { id: 'b', name: 'Secrets', type: 'zero_knowledge' },
        { id: 'c', name: 'Ops', vault_type: 'standard' },
        { id: 'd', name: 'NoTier' },
        { id: 'e' /* no name */, type: 'standard' },
      ],
    };
  };
  const out = await fetchStandardVaults({ serverOrigin: 'https://vault.example/', sessionToken: 'tok' }, fetchFn);
  assert.strictEqual(seen.url, 'https://vault.example/vaults', 'trailing slash trimmed; /vaults path');
  assert.strictEqual(seen.init.headers.Authorization, 'Bearer tok');
  assert.deepStrictEqual(out.vaults, [{ vaultId: 'a', vaultName: 'Marketing' }, { vaultId: 'c', vaultName: 'Ops' }]);
  assert.strictEqual(out.someExcluded, true, 'a bare boolean: the account has non-eligible (zk/unknown) vaults');
});

test('fetchStandardVaults: someExcluded is false when every vault is eligible', async () => {
  const fetchFn = async () => ({ ok: true, status: 200, json: async () => [
    { id: 'a', name: 'A', type: 'standard' }, { id: 'b', name: 'B', vault_type: 'standard' },
  ] });
  const out = await fetchStandardVaults({ serverOrigin: 'https://v', sessionToken: 't' }, fetchFn);
  assert.deepStrictEqual(out, { vaults: [{ vaultId: 'a', vaultName: 'A' }, { vaultId: 'b', vaultName: 'B' }], someExcluded: false });
});

test('fetchStandardVaults: fails closed on a non-OK response and on missing inputs', async () => {
  await assert.rejects(() => fetchStandardVaults({ serverOrigin: 'https://v', sessionToken: 't' }, async () => ({ ok: false, status: 403, json: async () => ({}) })), /could not load the vault list/);
  await assert.rejects(() => fetchStandardVaults({ serverOrigin: '', sessionToken: 't' }, async () => ({ ok: true })), /server origin and an account session/);
  await assert.rejects(() => fetchStandardVaults({ serverOrigin: 'https://v', sessionToken: '' }, async () => ({ ok: true })), /server origin and an account session/);
});

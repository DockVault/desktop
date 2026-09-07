'use strict';

// The verify step behind the setup screen: two independent legs, the sync sentence, and the one rule
// for when connecting may proceed.

const test = require('node:test');
const assert = require('node:assert/strict');

const { verifySetup } = require('../src/main/setup-verify');

// An httpJson that answers the health route and the device route separately.
function server({ health = { status: 'healthy' }, devices = 401 } = {}) {
  const calls = [];
  const fn = async (url) => {
    calls.push(url);
    if (url.endsWith('/health')) return { ok: true, status: 200, json: async () => health };
    if (url.endsWith('/devices')) return { ok: devices < 300, status: devices, json: async () => ({ detail: 'x' }) };
    return { ok: false, status: 404, json: async () => ({}) };
  };
  fn.calls = calls;
  return fn;
}
const sftpOk = async (ep) => ({ kind: 'ok', host: ep.host, port: ep.port, hostKey: 'ssh-ed25519 AAAA', fingerprint: 'SHA256:abc', banner: 'SSH-2.0-X' });
const sftpDown = async (ep) => ({ kind: 'unreachable', host: ep.host, port: ep.port });

test('both legs green on a server that speaks sync: proceed, with the endpoint to save and the fingerprint (never the key line) to show', async () => {
  const httpJson = server();
  const r = await verifySetup({ input: 'vault.example.com', sftp: 'vault.example.com:2222' }, { httpJson, probeSftp: sftpOk });
  assert.deepEqual(r.api, { kind: 'ok', host: 'vault.example.com' }, 'the screen gets kind + host only');
  assert.equal(r.origin, 'https://vault.example.com', 'the normalised origin rides separately for the write');
  assert.deepEqual(r.sync, { kind: 'supported' });
  assert.deepEqual(r.sftp, { kind: 'ok', host: 'vault.example.com', port: 2222, fingerprint: 'SHA256:abc' });
  assert.equal(r.proceed, true);
  assert.deepEqual(r.endpoint, { host: 'vault.example.com', port: 2222 });
  assert.deepEqual(httpJson.calls, ['https://vault.example.com/health', 'https://vault.example.com/devices']);
});

test('the SFTP leg red on a server that speaks sync blocks connecting; the API leg stays green and says so', async () => {
  const r = await verifySetup({ input: 'vault.example.com', sftp: 'vault.example.com:1234' }, { httpJson: server(), probeSftp: sftpDown });
  assert.equal(r.api.kind, 'ok');
  assert.equal(r.sync.kind, 'supported');
  assert.deepEqual(r.sftp, { kind: 'unreachable', host: 'vault.example.com', port: 1234 });
  assert.equal(r.proceed, false);
  assert.equal(r.endpoint, null);
});

test('an empty or malformed SFTP address never reaches the network and blocks connecting', async () => {
  let probed = 0;
  const probeSftp = async () => { probed++; return { kind: 'ok' }; };
  const empty = await verifySetup({ input: 'vault.example.com', sftp: '' }, { httpJson: server(), probeSftp });
  assert.deepEqual(empty.sftp, { kind: 'empty', host: '', port: 0 });
  assert.equal(empty.proceed, false);
  const bad = await verifySetup({ input: 'vault.example.com', sftp: 'vault.example.com:99999' }, { httpJson: server(), probeSftp });
  assert.deepEqual(bad.sftp, { kind: 'malformed', host: '', port: 0 });
  assert.equal(bad.proceed, false);
  assert.equal(probed, 0);
});

test('a server that does NOT speak sync: the SFTP leg is set aside as not-needed and connecting proceeds on the API leg alone, saving no endpoint', async () => {
  const r = await verifySetup({ input: 'old.example.com', sftp: 'old.example.com:2222' }, { httpJson: server({ devices: 404 }), probeSftp: sftpDown });
  assert.equal(r.sync.kind, 'unsupported');
  assert.deepEqual(r.sftp, { kind: 'not-needed', host: 'old.example.com', port: 2222 });
  assert.equal(r.proceed, true);
  assert.equal(r.endpoint, null);
  // With an empty SFTP field too: nothing to type for a server that has no use for it.
  const e = await verifySetup({ input: 'old.example.com', sftp: '' }, { httpJson: server({ devices: 404 }), probeSftp: sftpDown });
  assert.equal(e.sftp.kind, 'not-needed');
  assert.equal(e.proceed, true);
  // A green SFTP leg on such a server is still reported green and its endpoint kept (harmless, and honest).
  const g = await verifySetup({ input: 'old.example.com', sftp: 'old.example.com:2222' }, { httpJson: server({ devices: 404 }), probeSftp: sftpOk });
  assert.equal(g.sftp.kind, 'ok');
  assert.deepEqual(g.endpoint, { host: 'old.example.com', port: 2222 });
});

test('when sync support cannot be told, the SFTP leg is required (fail closed on the unknown)', async () => {
  const down = await verifySetup({ input: 'v.example.com', sftp: 'v.example.com:2222' }, { httpJson: server({ devices: 503 }), probeSftp: sftpDown });
  assert.equal(down.sync.kind, 'unknown');
  assert.equal(down.sftp.kind, 'unreachable');
  assert.equal(down.proceed, false);
  const up = await verifySetup({ input: 'v.example.com', sftp: 'v.example.com:2222' }, { httpJson: server({ devices: 503 }), probeSftp: sftpOk });
  assert.equal(up.proceed, true);
});

test('the API leg red: sync is not checked, the SFTP leg still reports on its own, and nothing proceeds', async () => {
  const httpJson = async () => { throw Object.assign(new Error('refused'), { code: 'ECONNREFUSED' }); };
  const r = await verifySetup({ input: 'down.example.com', sftp: 'down.example.com:2222' }, { httpJson, probeSftp: sftpOk });
  assert.equal(r.api.kind, 'unreachable');
  assert.deepEqual(r.sync, { kind: 'not-checked' });
  assert.equal(r.sftp.kind, 'ok', 'the SFTP leg is independent');
  assert.equal(r.proceed, false);
  const typed = await verifySetup({ input: 'http://remote.example.com', sftp: 'x:22' }, { httpJson, probeSftp: sftpOk });
  assert.equal(typed.api.kind, 'http-refused');
  assert.equal(typed.proceed, false);
});

test('a degraded server counts as green for the API leg; a throwing probe reads as unreachable, never as a crash', async () => {
  const r = await verifySetup({ input: 'v.example.com', sftp: 'v.example.com:2222' }, { httpJson: server({ health: { status: 'degraded' } }), probeSftp: sftpOk });
  assert.equal(r.api.kind, 'degraded');
  assert.equal(r.proceed, true);
  const t = await verifySetup({ input: 'v.example.com', sftp: 'v.example.com:2222' }, { httpJson: server(), probeSftp: async () => { throw new Error('boom'); } });
  assert.deepEqual(t.sftp, { kind: 'unreachable', host: 'v.example.com', port: 2222 });
  assert.equal(t.proceed, false);
});

test('on a server without sync, a door that presented an unprovable host key stays red (never "not needed"), though it does not block', async () => {
  const bad = async (ep) => ({ kind: 'host-key-unverified', host: ep.host, port: ep.port });
  const r = await verifySetup({ input: 'old.example.com', sftp: 'old.example.com:2222' }, { httpJson: server({ devices: 404 }), probeSftp: bad });
  assert.deepEqual(r.sftp, { kind: 'host-key-unverified', host: 'old.example.com', port: 2222 });
  assert.equal(r.proceed, true);
  assert.equal(r.endpoint, null);
});

test('the API leg reaching the screen carries a redirect source but never the origin; a failed verify has its own kind', async () => {
  const real = 'https://real.example.com';
  const httpJson = async (url) => {
    if (url.endsWith('/health')) return { ok: true, status: 200, url: `${real}/health`, json: async () => ({ status: 'healthy' }) };
    return { ok: false, status: 401, json: async () => ({}) };
  };
  const r = await verifySetup({ input: 'front.example.com', sftp: 'real.example.com:2222' }, { httpJson, probeSftp: sftpOk });
  assert.deepEqual(r.api, { kind: 'ok', host: 'real.example.com', from: 'front.example.com' });
  assert.equal(r.origin, real);
  const { failedVerify } = require('../src/main/setup-verify');
  const f = failedVerify();
  assert.equal(f.api.kind, 'failed'); assert.equal(f.sftp.kind, 'failed'); assert.equal(f.proceed, false); assert.equal(f.endpoint, null);
});

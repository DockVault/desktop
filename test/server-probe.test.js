'use strict';

// The server check answers with one typed outcome per situation, degrades by the SHAPE of the health
// reply (never a version), never offers a way past an untrusted certificate, and leaks no error text.

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeInput, probeServer, TLS_CODES } = require('../src/main/server-probe');

const reply = (ok, status, body) => ({ ok, status, json: async () => { if (body === 'not json') throw new SyntaxError('x'); return body; } });
const fetchWith = (fn) => async (url, init) => fn(url, init);
const failWith = (code, message = 'boom') => async () => { const e = new Error(message); if (code) e.code = code; throw e; };

test('normalising: a bare host becomes https, a pasted URL keeps its port and drops its path', () => {
  assert.deepEqual(normalizeInput('vault.example.com'), { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com', isLoopback: false });
  assert.equal(normalizeInput('  vault.example.com:8443/some/path?x=1  ').origin, 'https://vault.example.com:8443');
  assert.equal(normalizeInput('https://vault.example.com/login').origin, 'https://vault.example.com');
  assert.equal(normalizeInput('HTTPS://Vault.Example.com').origin, 'https://vault.example.com');
  assert.deepEqual(normalizeInput(''), { kind: 'empty' });
  assert.deepEqual(normalizeInput(null), { kind: 'empty' });
});

test('normalising: plain http to a remote host is refused, loopback http is allowed, junk is malformed', () => {
  assert.deepEqual(normalizeInput('http://vault.example.com'), { kind: 'http-refused' });
  assert.equal(normalizeInput('http://localhost:8080').kind, 'ok');
  assert.equal(normalizeInput('http://localhost:8080').isLoopback, true);
  assert.deepEqual(normalizeInput('not a server'), { kind: 'malformed' });
  assert.deepEqual(normalizeInput('ftp://vault.example.com'), { kind: 'malformed' });
  assert.deepEqual(normalizeInput('https://'), { kind: 'malformed' });
});

test('a DockVault server answers ok, a degraded one answers degraded, and the request is GET /health', async () => {
  const calls = [];
  const httpJson = fetchWith((url, init) => { calls.push([url, init.method]); return reply(true, 200, { status: 'healthy', database: 'connected' }); });
  assert.deepEqual(await probeServer('vault.example.com', { httpJson }), { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com' });
  assert.deepEqual(calls, [['https://vault.example.com/health', 'GET']]);
  const degraded = fetchWith(() => reply(true, 200, { status: 'degraded', database: 'disconnected' }));
  assert.equal((await probeServer('vault.example.com', { httpJson: degraded })).kind, 'degraded');
});

test('something that answers but is not DockVault: non-2xx, no JSON, or a body without a health status', async () => {
  for (const r of [reply(false, 404, {}), reply(false, 500, { status: 'healthy' }), reply(true, 200, 'not json'), reply(true, 200, { hello: 'world' }), reply(true, 200, { status: 'up' }), reply(true, 200, null), reply(true, 200, 'text')]) {
    assert.equal((await probeServer('vault.example.com', { httpJson: fetchWith(() => r) })).kind, 'not-dockvault');
  }
});

test('an untrusted certificate is its own outcome, and there is no way to accept it', async () => {
  for (const code of ['DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'SELF_SIGNED_CERT_IN_CHAIN']) {
    assert.ok(TLS_CODES.has(code));
    const r = await probeServer('vault.example.com', { httpJson: failWith(code) });
    assert.equal(r.kind, 'tls-untrusted');
    assert.deepEqual(Object.keys(r).sort(), ['host', 'kind', 'origin'], 'no error detail rides along');
  }
  // A wrapped cause carries the same code.
  const wrapped = async () => { const e = new Error('fetch failed'); e.cause = { code: 'CERT_HAS_EXPIRED' }; throw e; };
  assert.equal((await probeServer('vault.example.com', { httpJson: wrapped })).kind, 'tls-untrusted');
  const src = require('node:fs').readFileSync(require.resolve('../src/main/server-probe'), 'utf8');
  assert.doesNotMatch(src, /rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|insecure|bypass/i, 'nothing in the module can weaken certificate checks');
});

test('cannot reach it: name not found, refused, unreachable, or timed out', async () => {
  for (const code of ['ENOTFOUND', 'ECONNREFUSED', 'EHOSTUNREACH', 'ETIMEDOUT', 'EAI_AGAIN']) {
    assert.equal((await probeServer('vault.example.com', { httpJson: failWith(code) })).kind, 'unreachable');
  }
  assert.equal((await probeServer('vault.example.com', { httpJson: failWith(null, 'request timed out') })).kind, 'unreachable');
  assert.equal((await probeServer('vault.example.com', { httpJson: failWith(null, 'something odd') })).kind, 'unreachable', 'an unknown failure still reads as unreachable, never as a raw error');
});

test('the health check follows a redirect (it carries no credential) and the FINAL origin is what gets saved', async () => {
  const calls = [];
  const landing = async (url, init) => { calls.push([url, init.redirect, init.headers]); return { ok: true, status: 200, url: 'https://vault.example.org/health', json: async () => ({ status: 'healthy' }) }; };
  const r = await probeServer('vault.example.com', { httpJson: landing });
  assert.deepEqual(r, { kind: 'ok', origin: 'https://vault.example.org', host: 'vault.example.org', from: 'vault.example.com' }, 'the typed host rides along only when the landing host differs');
  const sameHost = async () => ({ ok: true, status: 200, url: 'https://vault.example.com/health/', json: async () => ({ status: 'healthy' }) });
  assert.deepEqual(await probeServer('vault.example.com', { httpJson: sameHost }), { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com' });
  assert.equal(calls[0][1], 'follow', 'the probe opts in');
  assert.equal(Object.keys(calls[0][2]).some((k) => /authorization/i.test(k)), false, 'and carries no bearer');
  // A redirect onto a port or path keeps the origin rules: port kept, path dropped.
  const withPort = async () => ({ ok: true, status: 200, url: 'https://vault.example.com:8443/api/health', json: async () => ({ status: 'healthy' }) });
  assert.equal((await probeServer('vault.example.com', { httpJson: withPort })).origin, 'https://vault.example.com:8443');
  // A redirect onto plain http off loopback is refused like a typed http address.
  const toHttp = async () => ({ ok: true, status: 200, url: 'http://vault.example.com/health', json: async () => ({ status: 'healthy' }) });
  assert.equal((await probeServer('vault.example.com', { httpJson: toHttp })).kind, 'http-refused');
  // No url on the reply (a fake or an old transport): the typed origin stands.
  const noUrl = async () => ({ ok: true, status: 200, json: async () => ({ status: 'healthy' }) });
  assert.equal((await probeServer('vault.example.com', { httpJson: noUrl })).origin, 'https://vault.example.com');
});

test('a redirect that cannot be followed to a landing is its own outcome, and Chromium network names map like Node codes', async () => {
  const refused = async () => { throw new TypeError("Attempted to redirect, but redirect policy was 'error'"); };
  assert.equal((await probeServer('vault.example.com', { httpJson: refused })).kind, 'redirected');
  const loop = async () => { throw new Error('too many redirects'); };
  assert.equal((await probeServer('vault.example.com', { httpJson: loop })).kind, 'redirected');
  for (const [msg, kind] of [['net::ERR_CERT_AUTHORITY_INVALID', 'tls-untrusted'], ['net::ERR_CERT_DATE_INVALID', 'tls-untrusted'], ['net::ERR_SSL_PROTOCOL_ERROR', 'tls-untrusted'], ['net::ERR_NAME_NOT_RESOLVED', 'unreachable'], ['net::ERR_CONNECTION_REFUSED', 'unreachable'], ['net::ERR_CONNECTION_TIMED_OUT', 'unreachable'], ['net::ERR_INTERNET_DISCONNECTED', 'unreachable']]) {
    const r = await probeServer('vault.example.com', { httpJson: failWith(null, msg) });
    assert.equal(r.kind, kind, msg);
    assert.deepEqual(Object.keys(r).sort(), ['host', 'kind', 'origin'], 'no error text rides along');
  }
});

test('a refused or malformed address never reaches the network', async () => {
  let called = 0;
  const httpJson = fetchWith(() => { called++; return reply(true, 200, { status: 'healthy' }); });
  assert.equal((await probeServer('http://vault.example.com', { httpJson })).kind, 'http-refused');
  assert.equal((await probeServer('nope nope', { httpJson })).kind, 'malformed');
  assert.equal((await probeServer('', { httpJson })).kind, 'empty');
  assert.equal(called, 0);
});

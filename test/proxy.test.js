'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { proxyRequest, buildTargetUrl } = require('../src/main/proxy');

test('buildTargetUrl preserves path + query and strips a trailing slash on the origin', () => {
  assert.strictEqual(
    buildTargetUrl('dockvault://app/auth/login?x=1', 'https://vault.example.com'),
    'https://vault.example.com/auth/login?x=1');
  assert.strictEqual(
    buildTargetUrl('dockvault://app/branding', 'https://vault.example.com/'),
    'https://vault.example.com/branding');
});

test('proxyRequest forwards method + body, drops hop-by-hop headers, injects NO credential', async () => {
  let seen = null;
  const fakeNet = { fetch: async (target, init) => { seen = { target, init }; return new Response('ok', { status: 200 }); } };
  const req = {
    url: 'dockvault://app/vaults/1/files',
    method: 'POST',
    headers: new Headers({ authorization: 'Bearer abc', host: 'app', 'content-type': 'application/json' }),
    body: 'PAYLOAD',
  };
  const res = await proxyRequest(req, 'https://vault.example.com', fakeNet);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(seen.target, 'https://vault.example.com/vaults/1/files');
  assert.strictEqual(seen.init.method, 'POST');
  // The UI's own Authorization header is forwarded verbatim...
  assert.strictEqual(seen.init.headers.get('authorization'), 'Bearer abc');
  // ...the hop-by-hop Host is dropped...
  assert.strictEqual(seen.init.headers.get('host'), null);
  // ...and the proxy added nothing of its own (no extra auth header injected).
  const names = [...seen.init.headers.keys()].sort();
  assert.deepStrictEqual(names, ['authorization', 'content-type']);
  assert.strictEqual(seen.init.body, 'PAYLOAD');
});

test('a GET is forwarded without a body', async () => {
  let seen = null;
  const fakeNet = { fetch: async (target, init) => { seen = init; return new Response('{}', { status: 200 }); } };
  await proxyRequest({ url: 'dockvault://app/auth/policy', method: 'GET', headers: new Headers() }, 'https://v.example', fakeNet);
  assert.strictEqual(seen.body, undefined);
  assert.strictEqual(seen.method, 'GET');
});

test('an upstream transport failure surfaces as a 502, not a crash', async () => {
  const fakeNet = { fetch: async () => { throw new Error('ECONNREFUSED'); } };
  const res = await proxyRequest({ url: 'dockvault://app/x', method: 'GET', headers: new Headers() }, 'https://v.example', fakeNet);
  assert.strictEqual(res.status, 502);
});

// The host is fixed by the configured origin; a hostile renderer-supplied path must never reach a
// different host. The string concatenation (origin + pathname + search) is the secure form — a
// pathname always begins with '/', so the authority is closed and nothing in the path can reach the
// host. (Do NOT refactor to new URL(pathname, origin): '//evil.com/x' would resolve to evil.com.)
test('buildTargetUrl cannot be steered off the configured host by a hostile path', () => {
  for (const u of ['dockvault://app//evil.com/x', 'dockvault://app/@evil.com/x',
                   'dockvault://app/%2f%2fevil.com/x', 'dockvault://app/x?next=//evil.com']) {
    assert.strictEqual(new URL(buildTargetUrl(u, 'https://vault.example.com')).host, 'vault.example.com');
  }
});

// A cross-origin redirect from the server must not be auto-followed by the proxy (that would be an
// SSRF the renderer never sees). 'manual' keeps net.fetch from chasing it.
test('proxyRequest does not auto-follow redirects (anti-SSRF)', async () => {
  let seen;
  const fakeNet = { fetch: async (_t, init) => { seen = init; return new Response('', { status: 200 }); } };
  await proxyRequest({ url: 'dockvault://app/x', method: 'GET', headers: new Headers() }, 'https://v.example', fakeNet);
  assert.strictEqual(seen.redirect, 'manual');
});

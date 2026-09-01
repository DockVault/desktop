'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { buildCsp } = require('../src/main/csp');

test('the default policy locks script-src and connect-src to self, with no ws/wss wildcard', () => {
  const csp = buildCsp();
  assert.match(csp, /(^|; )script-src 'self'(;|$)/, "script-src must be 'self' only");
  assert.match(csp, /(^|; )connect-src 'self'(;|$)/, "connect-src must be 'self' only by default");
  assert.ok(!/\bws:/.test(csp), 'no bare ws: scheme wildcard');
  assert.ok(!/\bwss:/.test(csp), 'no bare wss: scheme wildcard');
  assert.ok(!/script-src[^;]*https?:/.test(csp), 'the remote server origin never appears in script-src');
  assert.match(csp, /(^|; )frame-ancestors 'none'/, 'clickjacking guard preserved');
  assert.match(csp, /(^|; )object-src 'self' blob:/, 'mirrors the hosted directive set');
});

test('a configured server is appended to connect-src only, never script-src', () => {
  const csp = buildCsp({ serverHttpsOrigin: 'https://vault.example.com', serverWssOrigin: 'wss://vault.example.com' });
  assert.match(csp, /connect-src 'self' https:\/\/vault\.example\.com wss:\/\/vault\.example\.com/);
  assert.match(csp, /(^|; )script-src 'self'(;|$)/, 'script-src stays self even with a server configured');
  assert.ok(!/script-src[^;]*vault\.example\.com/.test(csp), 'server never appears in script-src');
  assert.ok(!/\bws:\s/.test(csp) && !/\bwss:\s/.test(csp), 'still no bare scheme wildcard (explicit host only)');
});

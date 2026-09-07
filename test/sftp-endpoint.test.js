'use strict';

// The typed SFTP address: what parses, what does not, how it is shown back, and how a saved endpoint
// replaces the host and port a minted credential advertises.

const test = require('node:test');
const assert = require('node:assert/strict');

const { parseSftpEndpoint, formatSftpEndpoint, isSftpEndpoint, suggestSftpEndpoint, applySftpEndpoint, DEFAULT_SFTP_PORT } = require('../src/main/sftp-endpoint');

test('host:port, a bare host on the default port, IPv6 in brackets, and a pasted sftp:// URL all parse', () => {
  assert.deepEqual(parseSftpEndpoint('files.example.com:2200'), { kind: 'ok', host: 'files.example.com', port: 2200 });
  assert.deepEqual(parseSftpEndpoint('  files.example.com  '), { kind: 'ok', host: 'files.example.com', port: DEFAULT_SFTP_PORT });
  assert.deepEqual(parseSftpEndpoint('10.0.0.5:22'), { kind: 'ok', host: '10.0.0.5', port: 22 });
  assert.deepEqual(parseSftpEndpoint('[::1]:2222'), { kind: 'ok', host: '::1', port: 2222 });
  assert.deepEqual(parseSftpEndpoint('[fe80::1]'), { kind: 'ok', host: 'fe80::1', port: DEFAULT_SFTP_PORT });
  assert.deepEqual(parseSftpEndpoint('fe80::1'), { kind: 'ok', host: 'fe80::1', port: DEFAULT_SFTP_PORT });
  assert.deepEqual(parseSftpEndpoint('sftp://files.example.com:2222/'), { kind: 'ok', host: 'files.example.com', port: 2222 });
  assert.deepEqual(parseSftpEndpoint('localhost:2222'), { kind: 'ok', host: 'localhost', port: 2222 });
});

test('nothing, a path, a URL with a scheme other than sftp, spaces, or a bad port are refused as their own kinds', () => {
  assert.deepEqual(parseSftpEndpoint(''), { kind: 'empty' });
  assert.deepEqual(parseSftpEndpoint(null), { kind: 'empty' });
  for (const bad of ['files.example.com:0', 'files.example.com:65536', 'files.example.com:abc', 'files.example.com:22:33', 'https://files.example.com:2222', 'files.example.com/path', 'a b:22', '-bad.example.com', 'user@host:22', ':2222', '1.2.3.4:22:', 'abc:2222:', '[v6]:22', '[1.2.3.4]:22']) {
    assert.deepEqual(parseSftpEndpoint(bad), { kind: 'malformed' }, bad);
  }
});

test('an endpoint is shown back as host:port, an IPv6 host in brackets; a broken one shows as nothing', () => {
  assert.equal(formatSftpEndpoint({ host: 'files.example.com', port: 2222 }), 'files.example.com:2222');
  assert.equal(formatSftpEndpoint({ host: '::1', port: 22 }), '[::1]:22');
  assert.equal(formatSftpEndpoint({ host: '', port: 22 }), '');
  assert.equal(formatSftpEndpoint(null), '');
  assert.equal(isSftpEndpoint({ host: 'h', port: 1 }), true);
  assert.equal(isSftpEndpoint({ host: 'h', port: '1' }), false);
  assert.equal(isSftpEndpoint({ host: 'h' }), false);
});

test('the suggested endpoint for a server address is its hostname on the default SFTP port', () => {
  assert.deepEqual(suggestSftpEndpoint('https://vault.example.com:8443'), { host: 'vault.example.com', port: DEFAULT_SFTP_PORT });
  assert.deepEqual(suggestSftpEndpoint('https://[::1]:8443'), { host: '::1', port: DEFAULT_SFTP_PORT });
  assert.equal(suggestSftpEndpoint('not a url'), null);
});

test('a saved endpoint replaces the advertised host and port on a minted bundle IN PLACE (one object ever holds the credential); none saved leaves it as-is', () => {
  const make = () => ({ host: 'api.example.com', port: 2222, user: 'u', password: 'p', hostKeys: 'ssh-ed25519 AAAA', expiresAt: 'later' });
  const bundle = make();
  const r = applySftpEndpoint(bundle, { host: 'files.example.com', port: 2200 });
  assert.equal(r.bundle, bundle, 'the very same object, so the cache can blank the password it holds');
  assert.deepEqual(bundle, { ...make(), host: 'files.example.com', port: 2200 });
  assert.deepEqual(r.advertised, { host: 'api.example.com', port: 2222 });
  assert.equal(r.overridden, true);
  const same = applySftpEndpoint(make(), { host: 'api.example.com', port: 2222 });
  assert.equal(same.overridden, false);
  assert.deepEqual(same.bundle, make());
  for (const none of [null, undefined, {}, { host: 'x' }, { host: 'x', port: 0 }]) {
    const b = make();
    const n = applySftpEndpoint(b, none);
    assert.equal(n.bundle, b);
    assert.deepEqual(b, make(), 'untouched');
    assert.equal(n.overridden, false);
  }
  assert.throws(() => applySftpEndpoint(null, { host: 'h', port: 1 }), TypeError);
});

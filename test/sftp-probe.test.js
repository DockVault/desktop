'use strict';

// The SFTP host-key probe against a loopback fake that runs the SERVER side of the same key exchange with
// Node's own crypto: a genuine ed25519 signature over the exchange hash verifies; a forged one, a
// non-SSH answer, a closed port, an SSH server with no shared algorithm, and a server that stalls each
// come back as their own kind — and never as 'ok'.

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');

const probe = require('../src/main/sftp-probe');
const { probeSftp } = probe;
const { fakeSshServer, listenFake: listen, SERVER_VERSION } = require('./fake-ssh-server');

test('a genuine key exchange: the probe returns the host key line, its fingerprint, and the banner, and sends only a client id + KEXINIT + ECDH_INIT', async () => {
  const fake = fakeSshServer();
  const { port, close } = await listen(fake.handler);
  try {
    const r = await probeSftp({ host: '127.0.0.1', port });
    assert.equal(r.kind, 'ok');
    assert.equal(r.host, '127.0.0.1'); assert.equal(r.port, port);
    assert.equal(r.hostKey, `ssh-ed25519 ${fake.hostKeyBlob.toString('base64')}`);
    assert.equal(r.fingerprint, 'SHA256:' + crypto.createHash('sha256').update(fake.hostKeyBlob).digest('base64').replace(/=+$/, ''));
    assert.equal(r.banner, SERVER_VERSION);
    assert.equal(fake.seen.clientVersion, probe.CLIENT_VERSION);
    assert.deepEqual(fake.seen.kexInit.kex, [...probe.KEX_ALGORITHMS]);
    assert.deepEqual(fake.seen.kexInit.hostKey, [...probe.HOST_KEY_ALGORITHMS]);
    assert.equal(fake.seen.ecdhInit, true);
    assert.ok(!('secret' in r) && !('password' in r), 'the result carries no secret');
  } finally { await close(); }
});

test('the key line matches what the OpenSSH public-key format carries: the blob decodes back to the ed25519 key', async () => {
  const fake = fakeSshServer();
  const { port, close } = await listen(fake.handler);
  try {
    const r = await probeSftp({ host: '127.0.0.1', port });
    const [type, b64] = r.hostKey.split(' ');
    assert.equal(type, 'ssh-ed25519');
    const blob = Buffer.from(b64, 'base64');
    assert.equal(blob.readUInt32BE(0), 11);
    assert.equal(blob.subarray(4, 15).toString(), 'ssh-ed25519');
    assert.equal(blob.readUInt32BE(15), 32);
    assert.deepEqual(blob.subarray(19), fake.pubRaw);
  } finally { await close(); }
});

test('a signature by a key other than the one presented is refused as host-key-unverified — never ok', async () => {
  const forged = fakeSshServer({ tweak: { forgeSignature: true } });
  const corrupt = fakeSshServer({ tweak: { corruptSignature: true } });
  const a = await listen(forged.handler); const b = await listen(corrupt.handler);
  try {
    const r1 = await probeSftp({ host: '127.0.0.1', port: a.port });
    assert.equal(r1.kind, 'host-key-unverified');
    assert.ok(!r1.hostKey && !r1.fingerprint, 'an unverified key is not reported');
    assert.equal((await probeSftp({ host: '127.0.0.1', port: b.port })).kind, 'host-key-unverified');
  } finally { await a.close(); await b.close(); }
});

test('RSA and ECDSA host keys verify too (the same families the sync path can pin), and a forged signature under each is refused', async () => {
  for (const algorithm of ['rsa-sha2-256', 'rsa-sha2-512', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521']) {
    const fake = fakeSshServer({ algorithm });
    const a = await listen(fake.handler);
    try {
      const r = await probeSftp({ host: '127.0.0.1', port: a.port });
      assert.equal(r.kind, 'ok', algorithm);
      assert.equal(r.hostKey.split(' ')[0], algorithm.startsWith('rsa') ? 'ssh-rsa' : algorithm);
      assert.equal(r.hostKey.split(' ')[1], fake.hostKeyBlob.toString('base64'));
    } finally { await a.close(); }
    const forged = fakeSshServer({ algorithm, tweak: { forgeSignature: true } });
    const b = await listen(forged.handler);
    try { assert.equal((await probeSftp({ host: '127.0.0.1', port: b.port })).kind, 'host-key-unverified', `${algorithm} forged`); }
    finally { await b.close(); }
  }
  // A server that lists rsa-sha2-256 but sends an ed25519-typed key and signature is refused: the blob must match the negotiated algorithm.
  const mismatch = fakeSshServer({ algorithm: 'ssh-ed25519', tweak: { hostKeyAlgs: ['rsa-sha2-256'] } });
  const c = await listen(mismatch.handler);
  try { assert.equal((await probeSftp({ host: '127.0.0.1', port: c.port })).kind, 'host-key-unverified'); }
  finally { await c.close(); }
});

test('an SSH server without a shared key-exchange or host-key algorithm is ssh-unsupported (SHA-1 ssh-rsa and ssh-dss are not accepted)', async () => {
  const noKex = fakeSshServer({ tweak: { kex: ['diffie-hellman-group14-sha256'] } });
  const noHk = fakeSshServer({ tweak: { hostKeyAlgs: ['ssh-rsa', 'ssh-dss'] } });
  const a = await listen(noKex.handler); const b = await listen(noHk.handler);
  try {
    assert.equal((await probeSftp({ host: '127.0.0.1', port: a.port })).kind, 'ssh-unsupported');
    assert.equal((await probeSftp({ host: '127.0.0.1', port: b.port })).kind, 'ssh-unsupported');
    assert.equal(noKex.seen.ecdhInit, false, 'no exchange is attempted without a shared algorithm');
  } finally { await a.close(); await b.close(); }
});

test('something that answers but is not SSH (an HTTP-ish banner, or silence) is not-ssh; a closed port is unreachable', async () => {
  const http = fakeSshServer({ tweak: { banner: 'HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n' } });
  const silent = fakeSshServer({ tweak: { banner: '' } });
  const a = await listen(http.handler); const b = await listen(silent.handler);
  try {
    assert.equal((await probeSftp({ host: '127.0.0.1', port: a.port })).kind, 'not-ssh');
    assert.equal((await probeSftp({ host: '127.0.0.1', port: b.port }, { timeoutMs: 400 })).kind, 'not-ssh');
  } finally { await a.close(); await b.close(); }
  const closed = await listen(() => {});
  await closed.close();
  const r = await probeSftp({ host: '127.0.0.1', port: closed.port });
  assert.equal(r.kind, 'unreachable');
  assert.deepEqual(Object.keys(r).sort(), ['host', 'kind', 'port']);
});

test('a server that stalls mid-exchange answers within the timeout as ssh-unsupported; a bad endpoint is unreachable without a connection', async () => {
  const stall = fakeSshServer({ tweak: { stallAfterInit: true } });
  const a = await listen(stall.handler);
  try {
    const t0 = Date.now();
    assert.equal((await probeSftp({ host: '127.0.0.1', port: a.port }, { timeoutMs: 500 })).kind, 'ssh-unsupported');
    assert.ok(Date.now() - t0 < 3000);
  } finally { await a.close(); }
  let connects = 0;
  const connect = () => { connects++; throw new Error('must not be called'); };
  assert.equal((await probeSftp({ host: '', port: 22 }, { connect })).kind, 'unreachable');
  assert.equal((await probeSftp({ host: 'x', port: 0 }, { connect })).kind, 'unreachable');
  assert.equal((await probeSftp({ host: 'x', port: 70000 }, { connect })).kind, 'unreachable');
  assert.equal(connects, 0);
});

test('the SSH mpint encoding used in the exchange hash strips leading zeros and keeps the value positive', () => {
  assert.deepEqual(probe.mpint(Buffer.from([0, 0, 0x7f])), Buffer.from([0, 0, 0, 1, 0x7f]));
  assert.deepEqual(probe.mpint(Buffer.from([0x80, 1])), Buffer.from([0, 0, 0, 3, 0, 0x80, 1]));
  assert.deepEqual(probe.mpint(Buffer.from([0, 0])), Buffer.from([0, 0, 0, 0]));
});

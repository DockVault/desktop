'use strict';

// A loopback fake of the SERVER side of one SSH key exchange (curve25519 with an ed25519, RSA or ECDSA
// host key), built on Node's own crypto, for tests of the SFTP host-key probe. `tweak` breaks specific
// parts on purpose: the signature, the algorithm lists, the banner, or the exchange itself (a stall).
// Not a test file itself.

const net = require('node:net');
const crypto = require('node:crypto');

const { exchangeHash, packet, sshString, nameList, parseKexInit, MSG_KEXINIT, MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY } = require('../src/main/sftp-probe');

const SERVER_VERSION = 'SSH-2.0-FakeVault';

function takePacket(buf) {
  if (buf.length < 4) return null;
  const len = buf.readUInt32BE(0);
  if (buf.length < 4 + len) return null;
  const pad = buf[4];
  return [buf.subarray(5, 4 + len - pad), buf.subarray(4 + len)];
}

// An SSH mpint from a JWK base64url magnitude: a leading zero when the high bit is set.
function mpintOf(b64) {
  const m = Buffer.from(b64, 'base64url');
  return sshString(m[0] & 0x80 ? Buffer.concat([Buffer.from([0]), m]) : m);
}

// The host key material for one signature algorithm: the key pair, its SSH key blob, and a signer that
// produces the SSH signature blob for that algorithm.
function hostKeyFor(algorithm) {
  if (algorithm === 'ssh-ed25519') {
    const pair = crypto.generateKeyPairSync('ed25519');
    const pubRaw = Buffer.from(pair.publicKey.export({ format: 'jwk' }).x, 'base64url');
    return {
      pair, pubRaw, blob: Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(pubRaw)]),
      sign: (h, priv = pair.privateKey) => Buffer.concat([sshString(Buffer.from('ssh-ed25519')), sshString(crypto.sign(null, h, priv))]),
      fresh: () => crypto.generateKeyPairSync('ed25519').privateKey,
    };
  }
  if (algorithm === 'rsa-sha2-256' || algorithm === 'rsa-sha2-512') {
    const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = pair.publicKey.export({ format: 'jwk' });
    const hash = algorithm === 'rsa-sha2-256' ? 'sha256' : 'sha512';
    return {
      pair, blob: Buffer.concat([sshString(Buffer.from('ssh-rsa')), mpintOf(jwk.e), mpintOf(jwk.n)]),
      sign: (h, priv = pair.privateKey) => Buffer.concat([sshString(Buffer.from(algorithm)), sshString(crypto.sign(hash, h, { key: priv, padding: crypto.constants.RSA_PKCS1_PADDING }))]),
      fresh: () => crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey,
    };
  }
  const curveName = algorithm.slice('ecdsa-sha2-'.length);
  const curves = { nistp256: ['prime256v1', 'sha256', 32], nistp384: ['secp384r1', 'sha384', 48], nistp521: ['secp521r1', 'sha512', 66] };
  const [named, hash, size] = curves[curveName];
  const pair = crypto.generateKeyPairSync('ec', { namedCurve: named });
  const jwk = pair.publicKey.export({ format: 'jwk' });
  const point = Buffer.concat([Buffer.from([4]), Buffer.from(jwk.x, 'base64url'), Buffer.from(jwk.y, 'base64url')]);
  const mpintFixed = (buf) => { let i = 0; while (i < buf.length - 1 && buf[i] === 0) i++; const m = buf.subarray(i); return sshString(m[0] & 0x80 ? Buffer.concat([Buffer.from([0]), m]) : m); };
  return {
    pair, blob: Buffer.concat([sshString(Buffer.from(algorithm)), sshString(Buffer.from(curveName)), sshString(point)]),
    sign: (h, priv = pair.privateKey) => {
      const raw = crypto.sign(hash, h, { key: priv, dsaEncoding: 'ieee-p1363' });
      return Buffer.concat([sshString(Buffer.from(algorithm)), sshString(Buffer.concat([mpintFixed(raw.subarray(0, size)), mpintFixed(raw.subarray(size))]))]);
    },
    fresh: () => crypto.generateKeyPairSync('ec', { namedCurve: named }).privateKey,
  };
}

function fakeSshServer({ algorithm = 'ssh-ed25519', tweak = {} } = {}) {
  const material = hostKeyFor(algorithm);
  const hostKeyBlob = material.blob;
  const pubRaw = material.pubRaw || null;
  const seen = { clientVersion: null, kexInit: null, ecdhInit: false, connections: 0 };
  const handler = (sock) => {
    seen.connections++;
    let inbound = Buffer.alloc(0);
    let phase = 'banner';
    let clientKexInit = null;
    const serverKexInit = Buffer.concat([
      Buffer.from([MSG_KEXINIT]), crypto.randomBytes(16),
      nameList(tweak.kex || ['curve25519-sha256@libssh.org', 'ecdh-sha2-nistp256']),
      nameList(tweak.hostKeyAlgs || [algorithm]),
      nameList(['aes128-ctr']), nameList(['aes128-ctr']), nameList(['hmac-sha2-256']), nameList(['hmac-sha2-256']),
      nameList(['none']), nameList(['none']), nameList([]), nameList([]), Buffer.from([0]), Buffer.alloc(4),
    ]);
    if (tweak.banner !== undefined) sock.write(tweak.banner); else sock.write(`${SERVER_VERSION}\r\n`);
    if (tweak.banner === undefined) sock.write(packet(serverKexInit));
    sock.on('data', (chunk) => {
      inbound = Buffer.concat([inbound, chunk]);
      for (;;) {
        if (phase === 'banner') {
          const nl = inbound.indexOf(0x0a);
          if (nl < 0) return;
          seen.clientVersion = inbound.subarray(0, nl).toString('ascii').replace(/\r$/, '');
          inbound = inbound.subarray(nl + 1);
          phase = 'packets';
          continue;
        }
        const t = takePacket(inbound);
        if (!t) return;
        const [payload, rest] = t; inbound = rest;
        if (payload[0] === MSG_KEXINIT) { clientKexInit = Buffer.from(payload); seen.kexInit = parseKexInit(payload); continue; }
        if (payload[0] === MSG_KEX_ECDH_INIT) {
          seen.ecdhInit = true;
          if (tweak.stallAfterInit) return;
          const clientPublic = payload.subarray(5, 5 + payload.readUInt32BE(1));
          const eph = crypto.generateKeyPairSync('x25519');
          const serverPublic = Buffer.from(eph.publicKey.export({ format: 'jwk' }).x, 'base64url');
          const secret = crypto.diffieHellman({ privateKey: eph.privateKey, publicKey: crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: clientPublic.toString('base64url') }, format: 'jwk' }) });
          const h = exchangeHash({ clientVersion: seen.clientVersion, serverVersion: SERVER_VERSION, clientKexInit, serverKexInit, hostKeyBlob, clientPublic, serverPublic, secret });
          let sigBlob = material.sign(h);
          if (tweak.forgeSignature) sigBlob = material.sign(h, material.fresh()); // a key that is not the one presented
          if (tweak.corruptSignature) sigBlob[sigBlob.length - 3] ^= 0xff;
          sock.write(packet(Buffer.concat([Buffer.from([MSG_KEX_ECDH_REPLY]), sshString(hostKeyBlob), sshString(serverPublic), sshString(sigBlob)])));
          continue;
        }
        // A DISCONNECT (or anything else) ends the exchange.
        sock.end();
        return;
      }
    });
    sock.on('error', () => {});
  };
  return { handler, hostKeyBlob, seen, pubRaw };
}

/** Listen on a loopback port with a fake server's handler. Resolves { srv, port, close() }. */
function listenFake(handler) {
  return new Promise((resolve) => {
    const srv = net.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, port: srv.address().port, close: () => new Promise((r) => srv.close(r)) }));
  });
}

module.exports = { fakeSshServer, listenFake, SERVER_VERSION };

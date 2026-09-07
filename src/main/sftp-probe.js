'use strict';

/*
 * Reach the SFTP endpoint a person entered on the setup screen and obtain its host key — without any
 * credential and without an SSH library. It speaks just enough of the SSH transport (RFC 4253) to run
 * one key exchange: the version banners, KEXINIT, a curve25519 exchange, and the server's KEXDH reply,
 * which carries the host public key and a signature over the exchange hash. The signature is verified
 * with that key, so a green result means "an SSH server at this address holds the private half of this
 * host key" — which is what the setup screen wants to know before saving the address. It then
 * disconnects; nothing is authenticated, no session is opened, no data is transferred.
 *
 * What this is NOT: a trust decision. The key obtained here is shown (as a fingerprint) and returned,
 * but the connection that carries files is pinned to the key the vault hands over inside the
 * credential-minting reply on the authenticated HTTPS channel — that stays the trust anchor. This probe
 * only tells the person, at setup time, whether the address they typed is an SFTP server they can reach
 * and which key it presents, so a wrong host, a wrong port, or a stale address is caught here rather
 * than as a silent sync failure later.
 *
 * Outcomes (kind), each with the host and port that were tried:
 *   ok                   reachable, spoke SSH, key exchange verified. Carries hostKey (the OpenSSH public
 *                        key line), fingerprint (SHA256: form) and banner (the server's version string).
 *   unreachable          the connection could not be made (refused, name not found, timed out, ...)
 *   not-ssh              something answered, but not with an SSH version banner
 *   ssh-unsupported      an SSH server that does not share an algorithm with this probe (curve25519 key
 *                        exchange; an ed25519, ECDSA or RSA host key), or one that broke the protocol
 *                        mid-exchange
 *   host-key-unverified  the server presented a key but its signature over the exchange did not verify:
 *                        the key cannot be trusted — refused, never reported as reachable-and-fine
 *
 * The socket factory is injected so the exchange is testable against a loopback fake; the timeout
 * bounds every phase, so a server that accepts and then stalls still answers within a few seconds.
 */

const net = require('node:net');
const crypto = require('node:crypto');

const CLIENT_VERSION = 'SSH-2.0-DockVaultDesktop';
const PROBE_TIMEOUT_MS = 10000;
const MAX_INBOUND_BYTES = 64 * 1024; // a key exchange is a few KB; anything larger is not one

const KEX_ALGORITHMS = Object.freeze(['curve25519-sha256', 'curve25519-sha256@libssh.org']);
// The host-key algorithms this probe can verify — the same families the sync path's pin accepts (an
// OpenSSH public-key line of type ssh-*, ecdsa-*), so no deployment the sync path could connect to is
// refused here. In preference order; ssh-rsa (SHA-1) is deliberately absent.
const HOST_KEY_ALGORITHMS = Object.freeze(['ssh-ed25519', 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521', 'rsa-sha2-512', 'rsa-sha2-256']);
// The key-blob type each signature algorithm goes with (RSA signatures name a hash; the key does not).
const KEY_TYPE_FOR = Object.freeze({
  'ssh-ed25519': 'ssh-ed25519',
  'ecdsa-sha2-nistp256': 'ecdsa-sha2-nistp256', 'ecdsa-sha2-nistp384': 'ecdsa-sha2-nistp384', 'ecdsa-sha2-nistp521': 'ecdsa-sha2-nistp521',
  'rsa-sha2-256': 'ssh-rsa', 'rsa-sha2-512': 'ssh-rsa',
});
const ECDSA_CURVES = Object.freeze({ nistp256: { crv: 'P-256', hash: 'sha256', bytes: 32 }, nistp384: { crv: 'P-384', hash: 'sha384', bytes: 48 }, nistp521: { crv: 'P-521', hash: 'sha512', bytes: 66 } });
const CIPHERS = Object.freeze(['aes128-ctr', 'aes256-ctr', 'aes128-gcm@openssh.com', 'aes256-gcm@openssh.com']);
const MACS = Object.freeze(['hmac-sha2-256', 'hmac-sha2-512']);

const MSG_DISCONNECT = 1;
const MSG_IGNORE = 2;
const MSG_DEBUG = 4;
const MSG_KEXINIT = 20;
const MSG_KEX_ECDH_INIT = 30;
const MSG_KEX_ECDH_REPLY = 31;

// --- wire encoding -------------------------------------------------------------------------------

function sshString(buf) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(buf.length, 0);
  return Buffer.concat([len, buf]);
}
function nameList(names) { return sshString(Buffer.from(names.join(','), 'ascii')); }
// An SSH mpint: big-endian two's complement, minimal length, positive (a leading zero when the high bit is set).
function mpint(buf) {
  let i = 0;
  while (i < buf.length && buf[i] === 0) i++;
  let body = buf.subarray(i);
  if (body.length > 0 && (body[0] & 0x80)) body = Buffer.concat([Buffer.from([0]), body]);
  return sshString(body);
}

class Reader {
  constructor(buf) { this.buf = buf; this.off = 0; }
  byte() { if (this.off + 1 > this.buf.length) throw new Error('short'); return this.buf[this.off++]; }
  uint32() { if (this.off + 4 > this.buf.length) throw new Error('short'); const v = this.buf.readUInt32BE(this.off); this.off += 4; return v; }
  string() { const n = this.uint32(); if (this.off + n > this.buf.length) throw new Error('short'); const s = this.buf.subarray(this.off, this.off + n); this.off += n; return s; }
  names() { return this.string().toString('ascii').split(',').filter(Boolean); }
  skip(n) { if (this.off + n > this.buf.length) throw new Error('short'); this.off += n; }
}

// An unencrypted binary packet: uint32 length, byte padding_length, payload, padding (block size 8, at
// least 4 bytes of padding).
function packet(payload) {
  let pad = 8 - ((5 + payload.length) % 8);
  if (pad < 4) pad += 8;
  const len = Buffer.alloc(4);
  len.writeUInt32BE(1 + payload.length + pad, 0);
  return Buffer.concat([len, Buffer.from([pad]), payload, crypto.randomBytes(pad)]);
}

function buildKexInit() {
  return Buffer.concat([
    Buffer.from([MSG_KEXINIT]),
    crypto.randomBytes(16),
    nameList(KEX_ALGORITHMS),
    nameList(HOST_KEY_ALGORITHMS),
    nameList(CIPHERS), nameList(CIPHERS),
    nameList(MACS), nameList(MACS),
    nameList(['none']), nameList(['none']),
    nameList([]), nameList([]),
    Buffer.from([0]),   // first_kex_packet_follows: no
    Buffer.alloc(4),    // reserved
  ]);
}

function parseKexInit(payload) {
  const r = new Reader(payload);
  if (r.byte() !== MSG_KEXINIT) throw new Error('not kexinit');
  r.skip(16);
  const kex = r.names(); const hostKey = r.names();
  r.names(); r.names(); r.names(); r.names(); r.names(); r.names(); r.names(); r.names();
  const guess = r.byte() !== 0;
  return { kex, hostKey, guess };
}

function disconnectPacket() {
  return packet(Buffer.concat([
    Buffer.from([MSG_DISCONNECT]),
    Buffer.from([0, 0, 0, 11]), // SSH_DISCONNECT_BY_APPLICATION
    sshString(Buffer.from('host key check complete', 'ascii')),
    sshString(Buffer.alloc(0)),
  ]));
}

// --- the exchange hash and its verification -----------------------------------------------------

function b64url(buf) { return Buffer.from(buf).toString('base64url'); }

// Curve25519 shared secret from our private key and the server's raw 32-byte public value.
function sharedSecret(privateKey, serverPublicRaw) {
  const publicKey = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'X25519', x: b64url(serverPublicRaw) }, format: 'jwk' });
  return crypto.diffieHellman({ privateKey, publicKey });
}

// Strip an mpint's leading zero (the sign byte) for a JWK field; refuse a negative or empty value.
function unsignedMagnitude(mp) {
  if (mp.length === 0 || (mp[0] & 0x80)) return null;
  let i = 0;
  while (i < mp.length - 1 && mp[i] === 0) i++;
  return mp.subarray(i);
}

/**
 * The public key inside a host-key blob, as a KeyObject, for the negotiated host-key algorithm — or null
 * when the blob is not a well-formed key of exactly that type (any trailing byte refuses it). Exported for
 * the unit tests.
 */
function publicKeyFromBlob(blob, algorithm) {
  try {
    const r = new Reader(blob);
    const type = r.string().toString('ascii');
    if (type !== KEY_TYPE_FOR[algorithm]) return null;
    let key;
    if (type === 'ssh-ed25519') {
      const raw = r.string();
      if (raw.length !== 32) return null;
      key = crypto.createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: b64url(raw) }, format: 'jwk' });
    } else if (type === 'ssh-rsa') {
      const e = unsignedMagnitude(r.string());
      const n = unsignedMagnitude(r.string());
      if (!e || !n || n.length < 256) return null; // at least a 2048-bit modulus
      key = crypto.createPublicKey({ key: { kty: 'RSA', n: b64url(n), e: b64url(e) }, format: 'jwk' });
    } else {
      const curveName = r.string().toString('ascii');
      const curve = ECDSA_CURVES[curveName];
      if (!curve || type !== `ecdsa-sha2-${curveName}`) return null;
      const point = r.string();
      if (point.length !== 1 + 2 * curve.bytes || point[0] !== 0x04) return null; // uncompressed only
      key = crypto.createPublicKey({ key: { kty: 'EC', crv: curve.crv, x: b64url(point.subarray(1, 1 + curve.bytes)), y: b64url(point.subarray(1 + curve.bytes)) }, format: 'jwk' });
    }
    return r.off === blob.length ? key : null;
  } catch { return null; }
}

/**
 * Verify an SSH signature blob over `data` with `key` for the negotiated algorithm. The blob must name
 * exactly that algorithm. ed25519 signatures are raw 64 bytes; RSA are PKCS#1 v1.5 over the named hash;
 * ECDSA carry r and s as two mpints, verified in fixed-width form. Returns false on any malformation.
 */
function verifySignatureBlob(algorithm, key, data, blob) {
  try {
    const r = new Reader(blob);
    if (r.string().toString('ascii') !== algorithm) return false;
    const sig = r.string();
    if (r.off !== blob.length) return false;
    if (algorithm === 'ssh-ed25519') return sig.length === 64 && crypto.verify(null, data, key, sig);
    if (algorithm === 'rsa-sha2-256' || algorithm === 'rsa-sha2-512') {
      return crypto.verify(algorithm === 'rsa-sha2-256' ? 'sha256' : 'sha512', data, { key, padding: crypto.constants.RSA_PKCS1_PADDING }, sig);
    }
    const curve = ECDSA_CURVES[algorithm.slice('ecdsa-sha2-'.length)];
    if (!curve) return false;
    const inner = new Reader(sig);
    const rr = unsignedMagnitude(inner.string()); const ss = unsignedMagnitude(inner.string());
    if (!rr || !ss || inner.off !== sig.length || rr.length > curve.bytes || ss.length > curve.bytes) return false;
    const fixed = Buffer.alloc(2 * curve.bytes);
    rr.copy(fixed, curve.bytes - rr.length); ss.copy(fixed, 2 * curve.bytes - ss.length);
    return crypto.verify(curve.hash, data, { key, dsaEncoding: 'ieee-p1363' }, fixed);
  } catch { return false; }
}

/**
 * H = SHA-256(V_C, V_S, I_C, I_S, K_S, Q_C, Q_S, K) — strings and one mpint, exactly as RFC 5656 / the
 * curve25519-sha256 draft lay it out. Exported so a test's fake server computes the same hash.
 */
function exchangeHash({ clientVersion, serverVersion, clientKexInit, serverKexInit, hostKeyBlob, clientPublic, serverPublic, secret }) {
  return crypto.createHash('sha256').update(Buffer.concat([
    sshString(Buffer.from(clientVersion, 'ascii')),
    sshString(Buffer.from(serverVersion, 'ascii')),
    sshString(clientKexInit),
    sshString(serverKexInit),
    sshString(hostKeyBlob),
    sshString(clientPublic),
    sshString(serverPublic),
    mpint(secret),
  ])).digest();
}

function fingerprintOf(blob) {
  return 'SHA256:' + crypto.createHash('sha256').update(blob).digest('base64').replace(/=+$/, '');
}

/** The OpenSSH public-key line for a host-key blob: "<type> <base64>". */
function hostKeyLine(blob) {
  const type = new Reader(blob).string().toString('ascii');
  return `${type} ${blob.toString('base64')}`;
}

// --- the probe ------------------------------------------------------------------------------------

/**
 * @param {{ host: string, port: number }} endpoint
 * @param {{ connect?: typeof net.connect, timeoutMs?: number }} [deps]
 * @returns {Promise<{ kind: string, host: string, port: number, hostKey?: string, fingerprint?: string, banner?: string }>}
 */
function probeSftp(endpoint, { connect = net.connect, timeoutMs = PROBE_TIMEOUT_MS } = {}) {
  const host = endpoint && typeof endpoint.host === 'string' ? endpoint.host : '';
  const port = endpoint && Number.isInteger(endpoint.port) ? endpoint.port : 0;
  const at = { host, port };
  if (!host || port < 1 || port > 65535) return Promise.resolve({ kind: 'unreachable', ...at });

  return new Promise((resolve) => {
    let settled = false;
    let socket = null;
    let connected = false;
    let phase = 'banner'; // 'banner' -> 'kexinit' -> 'reply' -> 'done'
    let inbound = Buffer.alloc(0);
    let discardNext = false;

    const clientKexInit = buildKexInit();
    const ecdh = crypto.generateKeyPairSync('x25519');
    const clientPublic = Buffer.from(ecdh.publicKey.export({ format: 'jwk' }).x, 'base64url');
    let serverVersion = '';
    let serverKexInit = null;
    let hostKeyAlgorithm = null; // the negotiated one: the first of ours the server also lists

    const finish = (result) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (socket) { try { socket.destroy(); } catch { /* gone */ } }
      resolve({ ...result, ...at });
    };
    const fail = (kind) => finish({ kind });
    // What a broken-off connection means depends on how far it got: never connected -> unreachable; connected
    // but no SSH banner yet -> not an SSH server; mid-exchange -> an SSH server this probe cannot talk to.
    const brokenOff = () => (connected ? (phase === 'banner' ? 'not-ssh' : 'ssh-unsupported') : 'unreachable');
    const timer = setTimeout(() => fail(brokenOff()), timeoutMs);
    if (timer.unref) timer.unref();

    const send = (buf) => { try { socket.write(buf); } catch { fail('ssh-unsupported'); } };

    const onPacket = (payload) => {
      if (payload.length === 0) return fail('ssh-unsupported');
      const type = payload[0];
      if (type === MSG_IGNORE || type === MSG_DEBUG) return null; // may appear anywhere, even before a guessed packet
      if (discardNext) { discardNext = false; return null; }      // the server's wrong first-kex guess
      if (type === MSG_DISCONNECT) return fail('ssh-unsupported');
      if (phase === 'kexinit') {
        if (type !== MSG_KEXINIT) return fail('ssh-unsupported');
        let parsed;
        try { parsed = parseKexInit(payload); } catch { return fail('ssh-unsupported'); }
        // Negotiation as RFC 4253 §7.1 has it: the first algorithm on the CLIENT's list that the server also supports.
        const kex = KEX_ALGORITHMS.find((a) => parsed.kex.includes(a));
        const hk = HOST_KEY_ALGORITHMS.find((a) => parsed.hostKey.includes(a));
        if (!kex || !hk) return fail('ssh-unsupported');
        hostKeyAlgorithm = hk;
        // A guessed first packet is only right when both first choices coincide; otherwise it is dropped.
        if (parsed.guess && (parsed.kex[0] !== KEX_ALGORITHMS[0] || parsed.hostKey[0] !== HOST_KEY_ALGORITHMS[0])) discardNext = true;
        serverKexInit = Buffer.from(payload);
        phase = 'reply';
        send(packet(Buffer.concat([Buffer.from([MSG_KEX_ECDH_INIT]), sshString(clientPublic)])));
        return null;
      }
      if (phase === 'reply') {
        if (type !== MSG_KEX_ECDH_REPLY) return fail('ssh-unsupported');
        let hostKeyBlob; let serverPublic; let sigBlob;
        try {
          const r = new Reader(payload); r.byte();
          hostKeyBlob = r.string(); serverPublic = r.string(); sigBlob = r.string();
        } catch { return fail('ssh-unsupported'); }
        const key = publicKeyFromBlob(hostKeyBlob, hostKeyAlgorithm);
        if (!key || serverPublic.length !== 32) return fail('host-key-unverified');
        let secret;
        try { secret = sharedSecret(ecdh.privateKey, serverPublic); } catch { return fail('host-key-unverified'); }
        const h = exchangeHash({ clientVersion: CLIENT_VERSION, serverVersion, clientKexInit, serverKexInit, hostKeyBlob, clientPublic, serverPublic, secret });
        if (!verifySignatureBlob(hostKeyAlgorithm, key, h, sigBlob)) return fail('host-key-unverified');
        phase = 'done';
        send(disconnectPacket());
        return finish({ kind: 'ok', hostKey: hostKeyLine(hostKeyBlob), fingerprint: fingerprintOf(hostKeyBlob), banner: serverVersion });
      }
      return fail('ssh-unsupported');
    };

    const consume = () => {
      for (;;) {
        if (settled) return;
        if (phase === 'banner') {
          const nl = inbound.indexOf(0x0a);
          if (nl < 0) { if (inbound.length > 4096) fail('not-ssh'); return; }
          const line = inbound.subarray(0, nl).toString('latin1').replace(/\r$/, '');
          inbound = inbound.subarray(nl + 1);
          if (!line.startsWith('SSH-')) { if (inbound.length > 4096) return fail('not-ssh'); continue; } // pre-banner text lines are allowed
          if (!line.startsWith('SSH-2.0-')) return fail('not-ssh');
          serverVersion = line;
          phase = 'kexinit';
          continue;
        }
        if (inbound.length < 4) return;
        const len = inbound.readUInt32BE(0);
        if (len < 5 || len > 35000) return fail('ssh-unsupported');
        if (inbound.length < 4 + len) return;
        const pad = inbound[4];
        if (pad + 1 > len) return fail('ssh-unsupported');
        const payload = inbound.subarray(5, 4 + len - pad);
        inbound = inbound.subarray(4 + len);
        onPacket(payload);
      }
    };

    try { socket = connect({ host, port }); } catch { return fail('unreachable'); }
    socket.on('connect', () => {
      connected = true;
      send(Buffer.from(`${CLIENT_VERSION}\r\n`, 'ascii'));
      send(packet(clientKexInit));
    });
    socket.on('data', (chunk) => {
      inbound = Buffer.concat([inbound, chunk]);
      if (inbound.length > MAX_INBOUND_BYTES) return fail(phase === 'banner' ? 'not-ssh' : 'ssh-unsupported');
      try { consume(); } catch { fail('ssh-unsupported'); }
    });
    socket.on('error', () => fail(brokenOff()));
    socket.on('close', () => { if (!settled) fail(brokenOff()); });
  });
}

module.exports = {
  probeSftp, exchangeHash, buildKexInit, parseKexInit, packet, sshString, nameList, mpint, hostKeyLine, fingerprintOf,
  publicKeyFromBlob, verifySignatureBlob,
  CLIENT_VERSION, PROBE_TIMEOUT_MS, KEX_ALGORITHMS, HOST_KEY_ALGORITHMS, MSG_KEXINIT, MSG_KEX_ECDH_INIT, MSG_KEX_ECDH_REPLY,
};

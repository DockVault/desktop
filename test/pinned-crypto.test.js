'use strict';

/*
 * THE PINNED CRYPTO READS WHAT EVERY SUPPORTED VAULT WRITES.
 *
 * The main window's zero-knowledge encryption is the bundled interface's own ecc_crypto.js. A vault page
 * before 0.31.0 writes version-1 key wraps and content; from 0.31.0 every page writes version 2. Moving
 * the pin may change either side, so these tests read the pinned file itself:
 *   - its reader must read both formats from the vault's frozen vectors, which are bytes a real writer
 *     produced, not bytes this copy produced for itself (a copy whose writer and reader drifted together
 *     would still pass a round trip);
 *   - its writers must produce the formats it names, and read them back, through the same choice the
 *     interface makes between them.
 * A pin that turns a writer off or on fails the first test below on purpose: what the app writes must be
 * readable by every server release the app supports, so that change needs a decision, not a pin bump.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');

const VAULT = path.resolve(__dirname, '..', 'vendor', 'vault');
const VECTORS = path.join(VAULT, 'tests', 'fixtures', 'crypto');
const subtle = nodeCrypto.webcrypto.subtle;

// The library takes Web Crypto from window, as it does in the page.
global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.join(VAULT, 'static', 'js', 'ecc_crypto.js'));

const vector = (dir, name) => JSON.parse(fs.readFileSync(path.join(VECTORS, dir, name), 'utf8'));
const fromB64 = (s) => new Uint8Array(Buffer.from(s, 'base64'));
const hex = (bytes) => Buffer.from(bytes).toString('hex');
const DVZ2 = [0x44, 0x56, 0x5a, 0x32];

// A quiet library: its diagnostics are for the page's console, not for test output.
function lib() {
  const l = new ECCCryptoLibrary();
  l.DEBUG = false;
  return l;
}

function scalarBytes(scalarHex) {
  const raw = Buffer.from(scalarHex.length % 2 ? `0${scalarHex}` : scalarHex, 'hex');
  return Buffer.concat([Buffer.alloc(48 - raw.length), raw]);
}

// The P-384 private key of a public test scalar.
async function privateKeyOf(scalarHex) {
  const ecdh = nodeCrypto.createECDH('secp384r1');
  const d = scalarBytes(scalarHex);
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey(undefined, 'uncompressed');
  const jwk = {
    kty: 'EC', crv: 'P-384', x: Buffer.from(pub.subarray(1, 49)).toString('base64url'),
    y: Buffer.from(pub.subarray(49, 97)).toString('base64url'), d: d.toString('base64url'), ext: true,
  };
  return subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits', 'deriveKey']);
}

const importDek = (dekHex) => subtle.importKey('raw', Buffer.from(dekHex, 'hex'), 'AES-GCM', true, ['encrypt', 'decrypt']);
const rawOf = async (key) => hex(new Uint8Array(await subtle.exportKey('raw', key)));

// The stream reader the interface uses for a download, fed in slices that do not line up with records.
async function readStream(l, bytes, dek, ctx) {
  let at = 0;
  const stream = new ReadableStream({
    pull(c) {
      if (at >= bytes.length) { c.close(); return; }
      const end = Math.min(at + 1000, bytes.length);
      c.enqueue(bytes.slice(at, end));
      at = end;
    },
  });
  const parts = [];
  await l.decryptStreamV2(stream, bytes.length, dek, ctx, (p) => parts.push(Buffer.from(p)));
  return Buffer.concat(parts);
}

test('the pinned interface writes version 2 for key wraps and for content', () => {
  const l = lib();
  assert.equal(l.ZK_WRAP_WRITE_V2, true, 'key wraps');
  assert.equal(l.ZK_CONTENT_WRITE_V2, true, 'content');
  const app = fs.readFileSync(path.join(VAULT, 'static', 'js', 'app.js'), 'utf8');
  // The interface decides in its own functions; the choice must still be these two flags.
  assert.match(app, /return lib\.ZK_WRAP_WRITE_V2\s*\?\s*lib\.wrapVaultDEKV2\(/, 'the direct wrap follows the flag');
  assert.match(app, /return lib\.ZK_WRAP_WRITE_V2\s*\?\s*lib\.wrapTeamDEKV2\(/, 'the team wrap follows the flag');
  assert.match(app, /if \(lib\.ZK_CONTENT_WRITE_V2\) \{/, 'content follows the flag');
});

test('the pinned reader reads version-1 content and key wraps a real writer produced', async () => {
  const l = lib();
  const content = vector('v0.10.0', 'zk-content-unversioned.json');
  const plain = await l.decryptFile(fromB64(content.encoded_b64), await importDek(content.inputs.dek_hex));
  assert.equal(Buffer.from(plain).toString('base64'), content.expected.plaintext_b64);

  const wrap = vector('v0.10.0', 'zk-direct-dek-wrap-legacy.json');
  assert.equal(fromB64(wrap.expected.wrapped_dek_b64).length, 40, 'a version-1 wrap is 40 bytes');
  const dek = await l.unwrapVaultDEK(wrap.expected.wrapped_dek_b64, wrap.expected.ephemeral_public_key_b64,
    await privateKeyOf(wrap.inputs.recipient_private_scalar_hex));
  assert.equal(await rawOf(dek), wrap.inputs.dek_hex);
});

test('the pinned reader reads version-2 content, whole and as a stream, from a real writer', async () => {
  const names = ['zk-content-v2-empty.json', 'zk-content-v2-one-partial-chunk.json',
    'zk-content-v2-exact-multiple.json', 'zk-content-v2-multi-chunk-partial-tail.json'];
  for (const name of names) {
    const v = vector('zk-content-v2', name);
    const i = v.inputs;
    const bytes = fromB64(v.encoded_b64);
    assert.deepEqual([...bytes.subarray(0, 4)], DVZ2, `${name} starts with the version-2 magic`);
    const ctx = { vaultId: i.vault_id, objectId: i.object_id, dekEpoch: i.dek_epoch };
    const dek = await importDek(i.dek_hex);
    const whole = await lib().decryptFile(bytes, dek, ctx);
    assert.equal(Buffer.from(whole).toString('base64'), v.expected.plaintext_b64, `${name}, whole`);
    const streamed = await readStream(lib(), bytes, dek, ctx);
    assert.equal(streamed.toString('base64'), v.expected.plaintext_b64, `${name}, as a stream`);
  }
});

test('the pinned reader reads version-2 direct and team key wraps from a real writer', async () => {
  for (const name of ['direct-wrap-v2-baseline.json', 'direct-wrap-v2-high-epoch.json']) {
    const v = vector('direct-wrap-v2', name);
    const i = v.inputs;
    const dek = await lib().unwrapVaultDEK(v.expected.wrapped_dek_b64, v.expected.ephemeral_public_key_b64,
      await privateKeyOf(i.recipient_private_scalar_hex),
      { vaultId: i.vault_id, recipientUserId: i.recipient_user_id, dekEpoch: i.dek_epoch });
    assert.equal(await rawOf(dek), i.dek_hex, name);
  }
  const t = vector('team-wrap-v2', 'team-dek-v2-epoch-1.json');
  const dek = await lib().unwrapVaultDEK(t.expected.wrapped_dek_b64, t.expected.ephemeral_public_key_b64,
    await privateKeyOf(t.inputs.team_private_scalar_hex),
    { vaultId: t.inputs.vault_id, dekEpoch: t.inputs.dek_epoch, teamMode: true });
  assert.equal(await rawOf(dek), t.inputs.dek_hex, 'team DEK wrap');
});

test('what the pinned writers produce is the format they name, and reads back', async () => {
  const l = lib();
  const recipient = await l.generateKeypair();
  const dek = await l.generateVaultDEK();
  const ctx = { vaultId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301', recipientUserId: '9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d', dekEpoch: 2 };

  // Key wrap, through the interface's choice.
  const wrapped = l.ZK_WRAP_WRITE_V2
    ? await l.wrapVaultDEKV2(dek, recipient.publicKey, ctx) : await l.wrapVaultDEK(dek, recipient.publicKey);
  const wrapBytes = fromB64(wrapped.wrappedDEK);
  assert.equal(wrapBytes.length, 68, 'a version-2 wrap is 68 bytes');
  assert.deepEqual([...wrapBytes.subarray(0, 6)], [...DVZ2, 0x02, 0x01], 'magic, version 2, direct-wrap purpose');
  const back = await lib().unwrapVaultDEK(wrapped.wrappedDEK, wrapped.ephemeralPublicKey, recipient.privateKey, ctx);
  assert.equal(await rawOf(back), await rawOf(dek));

  // Content, through the interface's choice, read whole and as a stream.
  const plain = nodeCrypto.randomBytes(9000);
  const cctx = { vaultId: ctx.vaultId, objectId: '22222222-2222-4222-8222-222222222222', dekEpoch: 2 };
  assert.equal(l.ZK_CONTENT_WRITE_V2, true);
  const sealed = (await l.encryptFileV2(plain, dek, cctx)).bytes;
  assert.deepEqual([...sealed.subarray(0, 6)], [...DVZ2, 0x02, 0x04], 'magic, version 2, content purpose');
  assert.ok(Buffer.from(await lib().decryptFile(sealed, dek, cctx)).equals(plain), 'read whole');
  assert.ok((await readStream(lib(), sealed, dek, cctx)).equals(plain), 'read as a stream');

  // The version-1 writers the interface falls back to still produce what the reader reads.
  const v1wrap = await l.wrapVaultDEK(dek, recipient.publicKey);
  assert.equal(fromB64(v1wrap.wrappedDEK).length, 40);
  assert.equal(await rawOf(await lib().unwrapVaultDEK(v1wrap.wrappedDEK, v1wrap.ephemeralPublicKey, recipient.privateKey, ctx)), await rawOf(dek));
  const v1 = new Uint8Array(await l.encryptFile(plain, dek));
  assert.notDeepEqual([...v1.subarray(0, 4)], DVZ2);
  assert.ok(Buffer.from(await lib().decryptFile(v1, dek, cctx)).equals(plain), 'version-1 content reads back');
});

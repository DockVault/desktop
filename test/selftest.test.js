'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { webcrypto } = require('node:crypto');
const { runKatWith, KAT } = require('../src/main/selftest');

test('boot KAT passes on the Node engine', async () => {
  const r = await runKatWith(webcrypto.subtle);
  assert.strictEqual(r.ok, true, `${r.code} ${r.detail || ''}`);
});

test('missing subtle fails closed with SUBTLE_MISSING', async () => {
  const r = await runKatWith(null);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'SUBTLE_MISSING');
});

test('KAT detects a wrong ciphertext (engine substitution/backdoor)', async () => {
  const real = webcrypto.subtle;
  // A "wrong" engine that flips one output byte on encrypt must be caught by the known-answer check.
  const tampered = {
    importKey: (...a) => real.importKey(...a),
    decrypt: (...a) => real.decrypt(...a),
    generateKey: (...a) => real.generateKey(...a),
    encrypt: async (...a) => { const b = new Uint8Array(await real.encrypt(...a)); b[0] ^= 0xff; return b.buffer; },
  };
  const r = await runKatWith(tampered);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'KAT_ENCRYPT_MISMATCH');
});

test('KAT detects a wrong decryption result', async () => {
  const real = webcrypto.subtle;
  const tampered = {
    importKey: (...a) => real.importKey(...a),
    encrypt: (...a) => real.encrypt(...a),
    generateKey: (...a) => real.generateKey(...a),
    decrypt: async () => new TextEncoder().encode('not the expected plaintext').buffer,
  };
  const r = await runKatWith(tampered);
  assert.strictEqual(r.ok, false);
  assert.strictEqual(r.code, 'KAT_DECRYPT_MISMATCH');
});

test('KAT vector has the exact AES-GCM length for a 31-byte plaintext (31 + 16 tag = 47 bytes)', () => {
  assert.strictEqual(KAT.cipherHex.length, 94); // 47 bytes * 2 hex chars
  assert.strictEqual(KAT.plaintext.length, 31);
});

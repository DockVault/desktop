'use strict';

/*
 * Boot crypto self-test: a known-answer test that gates the UI, run before any vault content is
 * shown.
 *
 * It is a known-answer test, not just a liveness check: a fixed AES-256-GCM (key, iv, plaintext)
 * must decrypt to the plaintext and the ciphertext must equal a precomputed constant. That catches
 * a broken, substituted, or subtly wrong WebCrypto engine — the failure a plain "is subtle defined?"
 * check misses. It also confirms P-384 ECDH key generation, the curve the client crypto uses.
 *
 * The same vector runs in two engines: Node's WebCrypto in the main process (here) and Chromium's
 * WebCrypto in the renderer (see rendererProbeExpression). Both must pass before any vault UI is
 * shown; either failing is fail-closed. The vector is public, deterministic test material.
 */

const KAT = Object.freeze({
  keyHex: '0b121920272e353c434a51585f666d747b828990979ea5acb3bac1c8cfd6dde4',
  ivHex: '03101d2a3744515e6b788592',
  plaintext: 'DockVault boot self-test KAT v1',
  cipherHex: '0dc394df8b4e1cb8a375247c7f1a87a67a71da13fdebfbadd42addb6f04c19559852dbe19ad33482ebcdb6b896404b',
});

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
  return out;
}
function bytesToHex(buf) {
  const b = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < b.length; i++) s += b[i].toString(16).padStart(2, '0');
  return s;
}
function constantTimeHexEqual(a, b) {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return d === 0;
}

/**
 * Run the known-answer test against a given SubtleCrypto, so identical logic runs under Node and
 * Chromium. Returns { ok, code, detail }. Never throws.
 */
async function runKatWith(subtle) {
  try {
    if (!subtle || typeof subtle.decrypt !== 'function' || typeof subtle.encrypt !== 'function') {
      return { ok: false, code: 'SUBTLE_MISSING', detail: 'crypto.subtle unavailable' };
    }
    const key = await subtle.importKey('raw', hexToBytes(KAT.keyHex), { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
    const iv = hexToBytes(KAT.ivHex);

    const dec = await subtle.decrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, hexToBytes(KAT.cipherHex));
    if (new TextDecoder().decode(dec) !== KAT.plaintext) return { ok: false, code: 'KAT_DECRYPT_MISMATCH', detail: 'plaintext mismatch' };

    const enc = await subtle.encrypt({ name: 'AES-GCM', iv, tagLength: 128 }, key, new TextEncoder().encode(KAT.plaintext));
    if (!constantTimeHexEqual(bytesToHex(enc), KAT.cipherHex)) {
      return { ok: false, code: 'KAT_ENCRYPT_MISMATCH', detail: 'ciphertext mismatch' };
    }

    const kp = await subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, false, ['deriveBits']);
    if (!kp || !kp.publicKey) return { ok: false, code: 'ECDH_P384_FAILED', detail: 'P-384 keygen failed' };

    return { ok: true, code: 'OK', detail: 'AES-GCM KAT + P-384 ECDH pass' };
  } catch (e) {
    return { ok: false, code: 'SELFTEST_THREW', detail: String((e && e.message) || e) };
  }
}

/** Main-process (Node WebCrypto) boot gate. */
async function runInMain() {
  const { webcrypto } = require('node:crypto');
  return runKatWith(webcrypto && webcrypto.subtle);
}

/**
 * The renderer (Chromium WebCrypto) leg, returned as a self-contained expression string for
 * webContents.executeJavaScript. It also reports isSecureContext, so a non-secure origin fails
 * closed here rather than surfacing later as a mysterious crypto error.
 */
function rendererProbeExpression() {
  return `(async () => {
    const KAT = ${JSON.stringify(KAT)};
    const hexToBytes = (h) => { const o = new Uint8Array(h.length/2); for (let i=0;i<o.length;i++) o[i]=parseInt(h.substr(i*2,2),16); return o; };
    const bytesToHex = (b) => { const u=new Uint8Array(b); let s=''; for (let i=0;i<u.length;i++) s+=u[i].toString(16).padStart(2,'0'); return s; };
    const out = { isSecureContext: window.isSecureContext, ok: false, code: 'INIT' };
    try {
      if (!(window.crypto && crypto.subtle)) { out.code='SUBTLE_MISSING'; return out; }
      const key = await crypto.subtle.importKey('raw', hexToBytes(KAT.keyHex), {name:'AES-GCM'}, false, ['encrypt','decrypt']);
      const iv = hexToBytes(KAT.ivHex);
      const dec = new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM', iv, tagLength:128}, key, hexToBytes(KAT.cipherHex)));
      if (dec !== KAT.plaintext) { out.code='KAT_DECRYPT_MISMATCH'; return out; }
      const enc = await crypto.subtle.encrypt({name:'AES-GCM', iv, tagLength:128}, key, new TextEncoder().encode(KAT.plaintext));
      if (bytesToHex(enc) !== KAT.cipherHex) { out.code='KAT_ENCRYPT_MISMATCH'; return out; }
      const kp = await crypto.subtle.generateKey({name:'ECDH', namedCurve:'P-384'}, false, ['deriveBits']);
      if (!(kp && kp.publicKey)) { out.code='ECDH_P384_FAILED'; return out; }
      out.ok = true; out.code = 'OK'; return out;
    } catch (e) { out.code='SELFTEST_THREW'; out.detail=String((e&&e.message)||e); return out; }
  })()`;
}

module.exports = { KAT, runKatWith, runInMain, rendererProbeExpression };

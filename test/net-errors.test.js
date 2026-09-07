'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { isTransportError, transportCode } = require('../src/main/net-errors');

test('isTransportError: an HTTP status is a transport failure (retryable)', () => {
  assert.strictEqual(isTransportError({ status: 503 }), true);
  assert.strictEqual(isTransportError({ status: 500 }), true);
});

test('isTransportError: a known network error code is a transport failure (direct or on a wrapped cause)', () => {
  assert.strictEqual(isTransportError({ code: 'ECONNREFUSED' }), true);
  assert.strictEqual(isTransportError({ code: 'ETIMEDOUT' }), true);
  assert.strictEqual(isTransportError({ cause: { code: 'ENOTFOUND' } }), true);
});

test('isTransportError: a code fault (no status, no known code) is NOT a transport failure', () => {
  assert.strictEqual(isTransportError(new TypeError('x is not a function')), false);
  assert.strictEqual(isTransportError({ code: 'EOOPS' }), false);
  assert.strictEqual(isTransportError(null), false);
  assert.strictEqual(isTransportError(undefined), false);
});

test('isTransportError: the JSON helper oversize code is transport (agrees with device-http transportCode)', () => {
  // http-json.js throws ERESPONSE_TOO_LARGE on a capped response; device-http's transportCode already reads it as
  // a transport failure, so net-errors must too — else the two classifiers disagree and an oversize /vaults body
  // reads as our-side 'internal-error' on one path and retryable network on the other.
  assert.strictEqual(isTransportError({ code: 'ERESPONSE_TOO_LARGE' }), true);
});

test('isTransportError: a net::ERR_ token in the message is transport (Electron net: refused / DNS carry no code)', () => {
  // Chromium's network stack names its failures net::ERR_* in the message with NO .code — the only signal for a
  // refused connection or a DNS failure over Electron net. Without reading the message these read as internal-error.
  assert.strictEqual(isTransportError(new Error('net::ERR_CONNECTION_REFUSED')), true);
  assert.strictEqual(isTransportError(new Error('load failed: net::ERR_NAME_NOT_RESOLVED')), true);
  assert.strictEqual(isTransportError({ cause: new Error('net::ERR_INTERNET_DISCONNECTED') }), true, 'on a wrapped cause too');
});

test('isTransportError: a Node PROGRAMMING error is NOT transport, even though its code has the ERR_ shape', () => {
  // THE row that distinguishes the correct property from `status || transportCode(e) !== null`: a bad-argument
  // TypeError carries code 'ERR_INVALID_ARG_TYPE', which matches transportCode's [A-Z][A-Z0-9_]+ SHAPE — but it is
  // a bug in our own path, not a network failure, and must NOT enter the retry lane. Keep this test: if a future
  // tidy-up simplifies isTransportError back to transportCode-non-null, this is the only case that fails.
  assert.strictEqual(isTransportError({ code: 'ERR_INVALID_ARG_TYPE' }), false);
  assert.strictEqual(isTransportError({ code: 'ERR_SOMETHING_UNKNOWN' }), false, 'an ERR_ code not in the vocabulary and with no net:: token is not transport');
});

test('transportCode: names a transport failure (platform code or the net::ERR_ token), else null', () => {
  // Exported from net-errors now (device-http imports it). It is a SHAPE match for NAMING a known-transport
  // failure — not a classifier — so a programming code passes it; that is why classification uses isTransportError.
  assert.strictEqual(transportCode({ code: 'ECONNREFUSED' }), 'ECONNREFUSED');
  assert.strictEqual(transportCode(new Error('boom net::ERR_TIMED_OUT here')), 'ERR_TIMED_OUT');
  assert.strictEqual(transportCode(new Error('plain error, no token')), null);
  assert.strictEqual(transportCode({ code: 'ERR_INVALID_ARG_TYPE' }), 'ERR_INVALID_ARG_TYPE', 'names by shape (why naming != classifying)');
});

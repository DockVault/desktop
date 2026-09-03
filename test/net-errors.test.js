'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { isTransportError } = require('../src/main/net-errors');

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

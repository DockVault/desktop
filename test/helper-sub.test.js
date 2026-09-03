'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { deriveCredSub } = require('../src/daemon/helper-sub');

// The daemon's credential-ack failure path names ONE bounded sub-reason and NEVER the raw error. This is the
// pure derivation behind it (src/daemon/index.js onSftpCred). It must: pass a runner-tagged subReason through
// verbatim, turn ONLY a malformed-config throw into the fixed 'config-format-failed' (by testing the message,
// not surfacing it), and collapse everything else — including a raw error that happens to carry sensitive text
// — to the generic 'prepare-failed'.
test('deriveCredSub: a runner-tagged failure keeps its typed subReason verbatim', () => {
  for (const s of ['checksum-mismatch', 'binary-missing', 'spawn-failed', 'version-mismatch', 'obscure-failed']) {
    assert.strictEqual(deriveCredSub(Object.assign(new Error('any raw detail here'), { subReason: s })), s);
  }
});

test('deriveCredSub: a malformed-config throw becomes the FIXED config-format-failed enum (message tested, never returned)', () => {
  assert.strictEqual(deriveCredSub(new Error('invalid sftp config value for host')), 'config-format-failed');
  assert.strictEqual(deriveCredSub(new Error('invalid sftp config value for user')), 'config-format-failed');
  assert.strictEqual(deriveCredSub(new Error('invalid remote name')), 'config-format-failed');
  // the RETURN is the fixed enum, not any slice of the offending message
  assert.strictEqual(deriveCredSub(new Error('invalid remote name: bad name]')), 'config-format-failed');
});

test('deriveCredSub: an untagged / unknown error is the generic prepare-failed — the raw message never leaks', () => {
  const raw = new Error('ECONNRESET raw-host raw-user would-be-secret-detail');
  assert.strictEqual(deriveCredSub(raw), 'prepare-failed');
  assert.strictEqual(deriveCredSub(new Error('')), 'prepare-failed');
  assert.strictEqual(deriveCredSub(null), 'prepare-failed');
  assert.strictEqual(deriveCredSub(undefined), 'prepare-failed');
  assert.strictEqual(deriveCredSub({}), 'prepare-failed');
  // a non-string subReason is not trusted as the tag — it falls through to the generic reason
  assert.strictEqual(deriveCredSub({ subReason: 42, message: 'nope' }), 'prepare-failed');
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { classifyBisyncOutcome, RESULT } = require('../src/daemon/bisync-outcome');

// Representative rclone bisync output (the real emitted phrasings these key on).
const ABORT = 'ERROR : Safety abort: too many deletes (>50%, 3 of 4). Run with --force if desired. Bisync aborted.';
const NEEDS = 'ERROR : cannot find prior Path1 or Path2 listings, likely due to critical error during last run.\nMust run --resync to recover.';
const MISMATCH = "ERROR : couldn't connect SSH: ssh: handshake failed: knownhosts: key mismatch";
const TOOLONG = 'ERROR : dir/file: Failed to copy: mkdir: The filename or extension is too long.';
const CONFLICT = 'NOTICE: report.txt.conflict1: renamed from report.txt\nNOTICE: report.txt.conflict2: copied (new)';
const CLEAN = 'INFO  : Bisync successful';

test('excessive-delete safety abort -> typed abort result + resync required', () => {
  const o = classifyBisyncOutcome({ code: 2, stderr: ABORT });
  assert.strictEqual(o.result, RESULT.ABORT_EXCESSIVE_DELETE);
  assert.strictEqual(o.resyncRequired, true, 'the abort blocks until a deliberate resync');
  assert.strictEqual(o.needsAttention, true);
});

test('missing prior listing / critical error -> needs-resync (resync required)', () => {
  const o = classifyBisyncOutcome({ code: 2, stderr: NEEDS });
  assert.strictEqual(o.result, RESULT.NEEDS_RESYNC);
  assert.strictEqual(o.resyncRequired, true);
});

test('host-key mismatch -> its own block result; the prior resync block is left untouched (null)', () => {
  const o = classifyBisyncOutcome({ code: 1, stderr: MISMATCH });
  assert.strictEqual(o.result, RESULT.HOST_KEY_MISMATCH);
  assert.strictEqual(o.resyncRequired, null, 'a connection-level block does not touch the resync baseline');
  assert.strictEqual(o.needsAttention, true);
});

test('the MITM signal outranks a generic error when both appear (severity order)', () => {
  const o = classifyBisyncOutcome({ code: 1, stderr: MISMATCH + '\nERROR : and some other failure' });
  assert.strictEqual(o.result, RESULT.HOST_KEY_MISMATCH);
});

test('anti-cry-wolf: a bare knownhosts mention on a clean run is NOT flagged as a mismatch', () => {
  // A benign line that merely names the knownhosts mechanism must not raise a false MITM alarm.
  const benign = classifyBisyncOutcome({ code: 0, stdout: 'INFO  : SFTP: using knownhosts pin for the server\nINFO  : Bisync successful' });
  assert.strictEqual(benign.result, RESULT.OK);
  assert.strictEqual(benign.needsAttention, false);
  // A real mismatch — the exact rclone phrasing — is still caught (via "key mismatch").
  const real = classifyBisyncOutcome({ code: 1, stderr: 'ssh: handshake failed: knownhosts: key mismatch' });
  assert.strictEqual(real.result, RESULT.HOST_KEY_MISMATCH);
});

test('an individual path-too-long -> its own surfaced result, not a generic error', () => {
  const o = classifyBisyncOutcome({ code: 1, stderr: TOOLONG });
  assert.strictEqual(o.result, RESULT.PATH_TOO_LONG);
  assert.strictEqual(o.needsAttention, true);
});

test('a completed run with a keep-both conflict -> non-green conflict result, block cleared', () => {
  const o = classifyBisyncOutcome({ code: 0, stdout: CONFLICT });
  assert.strictEqual(o.result, RESULT.CONFLICT_KEEP_BOTH, 'a keep-both run never reads as clean');
  assert.strictEqual(o.resyncRequired, false);
  assert.strictEqual(o.needsAttention, true);
});

test('a clean run -> ok / resync-ok (green), block cleared, no attention', () => {
  const ok = classifyBisyncOutcome({ code: 0, stdout: CLEAN });
  assert.deepStrictEqual([ok.result, ok.resyncRequired, ok.needsAttention], [RESULT.OK, false, false]);
  const rs = classifyBisyncOutcome({ code: 0, stdout: CLEAN, resync: true });
  assert.strictEqual(rs.result, RESULT.RESYNC_OK);
});

test('a generic non-zero exit with no known signature -> error, prior block untouched (null)', () => {
  const o = classifyBisyncOutcome({ code: 1, stderr: 'ERROR : a transient network failure' });
  assert.strictEqual(o.result, RESULT.ERROR);
  assert.strictEqual(o.resyncRequired, null);
  assert.strictEqual(o.needsAttention, true);
});

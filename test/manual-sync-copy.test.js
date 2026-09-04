'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { manualCompletionBody } = require('../src/main/manual-sync-copy');

const NAME = 'Photos';

// One completion answer per phase/reason. The table is walked so every case a "Sync now" press can end in has
// exactly one honest line — and so the toast never contradicts the tray glance (both read conditionForReason).
test('manual completion: a run that finished up to date reassures', () => {
  assert.deepStrictEqual(manualCompletionBody({ phase: 'done', outcome: { result: 'ok' } }, NAME),
    { body: 'Photos is up to date — safe to work offline.' });
  assert.deepStrictEqual(manualCompletionBody({ phase: 'done', outcome: { result: 'resync-ok' } }, NAME),
    { body: 'Photos is up to date — safe to work offline.' });
});

// A run that HAPPENED but did not simply succeed is classified through OUTCOME_STATE, the SAME table the sink
// uses — so these lines are actually reachable (they were dead code while 'done' collapsed to a generic line),
// and the toast matches the tray glance for the same outcome.
test('manual completion: a completed run with conflicting copies names the conflict', () => {
  const msg = manualCompletionBody({ phase: 'done', outcome: { result: 'conflict-keep-both' } }, NAME);
  assert.ok(/conflicting copies/i.test(msg.body), msg.body);
  assert.ok(!/needs your attention/i.test(msg.body), `must not collapse to the generic line, got: ${msg.body}`);
});

test('manual completion: completed-run outcomes each get their own line via OUTCOME_STATE', () => {
  assert.ok(/repair/i.test(manualCompletionBody({ phase: 'done', outcome: { result: 'abort-excessive-delete' } }, NAME).body));
  assert.ok(/repair/i.test(manualCompletionBody({ phase: 'done', outcome: { result: 'needs-resync' } }, NAME).body));
  assert.ok(/shorter path/i.test(manualCompletionBody({ phase: 'done', outcome: { result: 'path-too-long' } }, NAME).body));
  assert.ok(/sign in/i.test(manualCompletionBody({ phase: 'done', outcome: { result: 'auth-failed' } }, NAME).body));
  assert.ok(/can't verify/i.test(manualCompletionBody({ phase: 'done', outcome: { result: 'host-key-unverified' } }, NAME).body));
});

test('manual completion: a completed run with no typed result falls back to the generic attention line', () => {
  assert.deepStrictEqual(manualCompletionBody({ phase: 'done', outcome: {} }, NAME),
    { body: 'Photos finished, but it needs your attention. Open DockVault to review.' });
});

// The severe case: a changed server identity must be the LOUD must-act on a manual press, never the vague
// "couldn't sync" — because the exactly-one-toast window suppresses the hub's own identity alarm for that press.
// It can arrive as an errored run, a completed run reporting it, or a pre-dispatch cred-cache catch.
test('manual completion: a host-key mismatch renders the identity alert, never the generic line', () => {
  for (const ev of [
    { phase: 'error', reason: 'host-key-mismatch' },
    { phase: 'done', outcome: { result: 'host-key-mismatch' } },
    { phase: 'paused', reason: 'host-key-mismatch' },
  ]) {
    const msg = manualCompletionBody(ev, NAME);
    assert.ok(/identity has changed/i.test(msg.body), `${JSON.stringify(ev)} -> ${msg.body}`);
    assert.ok(!/couldn't sync\. Open DockVault to see why/i.test(msg.body), `must not be the vague error line: ${msg.body}`);
  }
});

// An unready sync helper is a NON-retrying must-act, so a manual "Sync now" press that hits it must say so —
// NEVER the calm "try again in a moment" that would tell a different story than the tray. Both the gate-refused
// and cred-paused paths carry reason 'helper-not-ready'; the toast points at the tray's how-to-fix affordance.
test('manual completion: an unready helper is a must-act (points at the fix), never the calm retry line', () => {
  for (const ev of [
    { phase: 'refused', reason: 'helper-not-ready', sub: 'version-mismatch' },
    { phase: 'paused', reason: 'helper-not-ready', sub: 'binary-missing' },
  ]) {
    const msg = manualCompletionBody(ev, NAME);
    assert.match(msg.body, /sync helper isn't ready/i, `${JSON.stringify(ev)} -> ${msg.body}`);
    assert.match(msg.body, /how to fix it/i, `points at the fix: ${msg.body}`);
    assert.doesNotMatch(msg.body, /try again in a moment/i, `never the false transient-retry line: ${msg.body}`);
  }
});

// A DOWN helper (daemon crash/restart, reason 'helper-unavailable') is DISTINCT from a misconfigured one: it
// self-recovers, so the manual press earns a calm can't-reach line — NEVER the "how to fix it" setup pointer
// (which would tell the person to edit env vars for a helper that is actually fine), and never "misconfigured".
test('manual completion: a down helper (helper-unavailable) is a calm can\'t-reach line, never the how-to-fix setup pointer', () => {
  const msg = manualCompletionBody({ phase: 'paused', reason: 'helper-unavailable' }, NAME);
  assert.match(msg.body, /can't reach the sync helper/i, msg.body);
  assert.doesNotMatch(msg.body, /how to fix|isn't ready|set it up|misconfigured/i, `a down helper is never the misconfigured setup line: ${msg.body}`);
});

// The defect this replaces: a fingerprint-only / unverifiable server is REACHABLE, so a cannot-verify pause
// must NOT borrow the offline "can't reach the server" line. It reads as a verification pause, and promises no
// specific remedy (the state also covers an absent endpoint or a failed fetch, not only a too-old server).
test('manual completion: cannot-verify reads as a verification pause, never "offline"', () => {
  const msg = manualCompletionBody({ phase: 'paused', reason: 'host-key-unavailable' }, NAME);
  assert.ok(/can't verify/i.test(msg.body), `expected a verification line, got: ${msg.body}`);
  assert.ok(!/can't reach|offline|back online/i.test(msg.body), `must not claim offline, got: ${msg.body}`);
  assert.ok(!/updated|update the server/i.test(msg.body), `must not over-promise a remedy, got: ${msg.body}`);
});

test('manual completion: offline reads as "can\'t reach the server", back-online', () => {
  const msg = manualCompletionBody({ phase: 'paused', reason: 'waiting-to-reconnect' }, NAME);
  assert.ok(/can't reach the server/i.test(msg.body) && /back online/i.test(msg.body), msg.body);
});

test('manual completion: a cred-refresh hiccup is a calm retry, not offline', () => {
  const msg = manualCompletionBody({ phase: 'paused', reason: 'cred-refresh-failed' }, NAME);
  assert.ok(/try again/i.test(msg.body), msg.body);
  assert.ok(!/back online/i.test(msg.body), `a refresh hiccup is not an offline claim, got: ${msg.body}`);
});

test('manual completion: a declined upload earns no toast (silent)', () => {
  assert.deepStrictEqual(manualCompletionBody({ phase: 'skipped', reason: 'consent-declined' }, NAME), { silent: true });
});

test('manual completion: sign-in owed, locked, and blocked each get their own line', () => {
  assert.ok(/sign in/i.test(manualCompletionBody({ phase: 'skipped', reason: 'no-session' }, NAME).body));
  assert.ok(/unlock/i.test(manualCompletionBody({ phase: 'skipped', reason: 'paused-locked' }, NAME).body));
  assert.ok(/repair/i.test(manualCompletionBody({ phase: 'blocked', reason: 'needs-repair' }, NAME).body));
});

test('manual completion: a refused folder and an ineligible vault get honest lines', () => {
  assert.ok(/folder/i.test(manualCompletionBody({ phase: 'refused', reason: 'folder-insecure' }, NAME).body));
  assert.ok(/folder/i.test(manualCompletionBody({ phase: 'refused', reason: 'folder-problem' }, NAME).body));
  assert.ok(/can't be synced any more/i.test(manualCompletionBody({ phase: 'refused', reason: 'not-standard-or-removed' }, NAME).body));
  assert.ok(/can't be synced any more/i.test(manualCompletionBody({ phase: 'refused', reason: 'ineligible' }, NAME).body));
});

test('manual completion: an errored run points at the app', () => {
  assert.ok(/couldn't sync/i.test(manualCompletionBody({ phase: 'error', reason: 'run-failed' }, NAME).body));
});

test('manual completion: an unknown refusal is a calm retry, never silent', () => {
  const msg = manualCompletionBody({ phase: 'refused', reason: 'something-new' }, NAME);
  assert.ok(msg.body && /try again/i.test(msg.body), JSON.stringify(msg));
});

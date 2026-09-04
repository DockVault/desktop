'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { CredCache } = require('../src/main/cred-cache');

const NOW = 1_700_000_000_000;
const iso = (ms) => new Date(ms).toISOString();
const FRESH = iso(NOW + 15 * 60 * 1000);
const HOST = 'sync.example';

// A mint that hands out a DISTINCT bundle each call (single-use creds are minted fresh every time), so
// mint-per-dispatch and pin behaviour are observable. Every bundle is for the same server HOST unless
// overridden (the host key is per server, not per vault). `returned` keeps the actual objects the cache
// received, so the post-send zeroize is observable.
function mintSeq(bundles) {
  let i = 0;
  const calls = [];
  const returned = [];
  return {
    calls,
    returned,
    mint: async (vaultId) => { calls.push(vaultId); const o = { host: HOST, ...bundles[Math.min(i++, bundles.length - 1)] }; returned.push(o); return o; },
  };
}
// Record a COPY at send time, mirroring the real structured-clone across the parent<->child port (so a
// post-send zeroize of the main-side object does not rewrite what the helper was handed).
function sendRec() {
  const sent = [];
  return { sent, send: async (bundle) => { sent.push({ ...bundle }); return { ok: true }; } };
}

test('ensureSent mints a fresh single-use credential and sends it (pinned host key + plaintext password)', async () => {
  const m = mintSeq([{ user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH }]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: true });
  assert.deepStrictEqual(m.calls, ['v1']);
  assert.strictEqual(s.sent.length, 1);
  assert.strictEqual(s.sent[0].hostKeys, 'PIN1');
  assert.strictEqual(s.sent[0].password, 'p1');
});

test('ensureSent classifies a mint code-fault as a non-retryable internal-error, a transport failure as retryable mint-failed', async () => {
  const s = sendRec();
  // A bug in our own mint path (no status, no network code) must surface at once as a non-retryable problem,
  // never be retried forever behind the generic 'mint-failed'.
  const codeFault = new CredCache({ mint: async () => { throw new TypeError('bad call'); }, send: s.send, now: () => NOW });
  assert.deepStrictEqual(await codeFault.ensureSent('v1'), { ok: false, reason: 'internal-error' });
  // A genuine transport failure IS a retryable hiccup.
  const transport = new CredCache({ mint: async () => { const e = new Error('down'); e.status = 503; throw e; }, send: s.send, now: () => NOW });
  assert.deepStrictEqual(await transport.ensureSent('v1'), { ok: false, reason: 'mint-failed' });
});

test('ensureSent maps a typed helper sub to the single non-retrying helper-not-ready (carrying sub + installed); a plain failure to cred-send-failed', async () => {
  const bundle = () => [{ user: 'u', password: 'p', hostKeys: 'PIN1', expiresAt: FRESH }];
  const mk = (sub, installed) => new CredCache({ mint: mintSeq(bundle()).mint, send: async () => ({ ok: false, sub, installed }), now: () => NOW });
  // A typed helper readiness/prepare failure: the ack's sub + the daemon-detected installed version.
  assert.deepStrictEqual(await mk('version-mismatch', '1.60.0').ensureSent('v1'), { ok: false, reason: 'helper-not-ready', sub: 'version-mismatch', installed: '1.60.0' });
  // An UNKNOWN sub still maps to helper-not-ready (fail-safe) — never a calm reason.
  assert.deepStrictEqual(await mk('a-new-sub', null).ensureSent('v1'), { ok: false, reason: 'helper-not-ready', sub: 'a-new-sub', installed: null });
  // A plain send failure (NO sub) stays the genuine transient cred-send-failed.
  const plain = new CredCache({ mint: mintSeq(bundle()).mint, send: async () => ({ ok: false }), now: () => NOW });
  assert.deepStrictEqual(await plain.ensureSent('v1'), { ok: false, reason: 'cred-send-failed' });
});

// The consequence-2 regression: the server BURNS a temp credential on first use, so a second dispatch must
// present a FRESH credential — never re-send the spent one. (The reverse — re-send-until-near-expiry — made
// the second routine tick fail 'auth-failed' with a latched false "sign in" on a healthy server.)
test('every dispatch mints a FRESH credential and never re-sends a spent one', async () => {
  const m = mintSeq([
    { user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH },
    { user: 'u2', password: 'p2', hostKeys: 'PIN1', expiresAt: FRESH },
    { user: 'u3', password: 'p3', hostKeys: 'PIN1', expiresAt: FRESH },
  ]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  await cc.ensureSent('v1');
  await cc.ensureSent('v1');
  await cc.ensureSent('v1');
  assert.strictEqual(m.calls.length, 3, 'a fresh mint on every dispatch — single-use is never reused');
  assert.deepStrictEqual(s.sent.map((b) => b.password), ['p1', 'p2', 'p3'], 'three distinct credentials sent, never a repeat');
});

test('every mint carries the SESSION pin unchanged while the credential itself rotates', async () => {
  const m = mintSeq([
    { user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH },   // first mint pins PIN1
    { user: 'u2', password: 'p2', hostKeys: 'PIN1', expiresAt: FRESH },   // same server key, new cred
  ]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  await cc.ensureSent('v1');
  await cc.ensureSent('v1');
  assert.strictEqual(s.sent[1].hostKeys, 'PIN1', 'the session pin is carried');
  assert.strictEqual(s.sent[1].password, 'p2', 'the credential itself rotates');
});

test('the plaintext password is zeroized once the helper holds the bundle', async () => {
  const m = mintSeq([{ user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH }]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  await cc.ensureSent('v1');
  assert.strictEqual(m.returned[0].password, '', 'the main-side plaintext reference is dropped after send');
  assert.strictEqual(s.sent[0].password, 'p1', 'but the helper was handed the real credential');
});

test('a re-fetch that returns a DIFFERENT host key fails closed as a mismatch (never silently re-pinned)', async () => {
  const m = mintSeq([
    { user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH },
    { user: 'u2', password: 'p2', hostKeys: 'PIN2', expiresAt: FRESH },  // server key CHANGED mid-session
  ]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  await cc.ensureSent('v1');                          // pins PIN1
  const r = await cc.ensureSent('v1');                // next mint returns PIN2 -> mismatch
  assert.deepStrictEqual(r, { ok: false, reason: 'host-key-mismatch' });
  assert.strictEqual(s.sent.length, 1, 'the changed key is never sent');
});

test('the SESSION pin survives a lock: after clear(), a changed key is still a mismatch (no re-TOFU on unlock)', async () => {
  const m = mintSeq([
    { user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH },
    { user: 'u2', password: 'p2', hostKeys: 'PIN2', expiresAt: FRESH },  // a fresh fetch after unlock, different key
  ]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  await cc.ensureSent('v1');   // pins PIN1
  cc.clear();                  // lock: no cached credential to drop, but the pin persists...
  const r = await cc.ensureSent('v1'); // ...so a different key still mismatches
  assert.deepStrictEqual(r, { ok: false, reason: 'host-key-mismatch' }, 'the lock/unlock cycle is not a re-accept window');
});

test('two vaults on the same server share the one session pin; each gets its own fresh credential', async () => {
  const m = { calls: [], mint: async (v) => { m.calls.push(v); return { host: HOST, user: v, password: 'p-' + v + '-' + m.calls.length, hostKeys: 'PIN', expiresAt: FRESH }; } };
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  await cc.ensureSent('a');
  await cc.ensureSent('b');
  await cc.ensureSent('a'); // back to a: a fresh mint again (single-use), not a re-send
  assert.deepStrictEqual(m.calls, ['a', 'b', 'a'], 'every dispatch mints, including the repeat vault');
  assert.deepStrictEqual(s.sent.map((b) => b.password), ['p-a-1', 'p-b-2', 'p-a-3'], 'each dispatch sends a distinct fresh credential');
  assert.ok(s.sent.every((b) => b.hostKeys === 'PIN'), 'all carry the one server pin');
});

test('a first mint without a host key fails closed and never sends', async () => {
  const m = mintSeq([{ user: 'u1', password: 'p1', hostKeys: null, expiresAt: FRESH }]);
  const s = sendRec();
  const cc = new CredCache({ mint: m.mint, send: s.send, now: () => NOW });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: false, reason: 'host-key-unavailable' });
  assert.strictEqual(s.sent.length, 0);
});

test('a mint failure fails closed; the next dispatch mints again', async () => {
  let calls = 0;
  const cc = new CredCache({
    mint: async () => { calls += 1; if (calls === 1) { const e = new Error('401'); e.reason = 'no-session'; throw e; } return { host: HOST, user: 'u', password: 'p', hostKeys: 'PIN', expiresAt: FRESH }; },
    send: async () => ({ ok: true }), now: () => NOW,
  });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: false, reason: 'no-session' });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: true });
  assert.strictEqual(calls, 2, 'the next dispatch mints again — nothing stale is reused');
});

test('a send failure fails closed; the next dispatch mints a fresh credential (never re-sends the failed one)', async () => {
  const m = mintSeq([
    { user: 'u1', password: 'p1', hostKeys: 'PIN1', expiresAt: FRESH },
    { user: 'u2', password: 'p2', hostKeys: 'PIN1', expiresAt: FRESH },
  ]);
  let ok = false; const sent = [];
  const cc = new CredCache({ mint: m.mint, send: async (b) => { sent.push({ ...b }); return { ok }; }, now: () => NOW });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: false, reason: 'cred-send-failed' });
  ok = true;
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: true });
  assert.strictEqual(m.calls.length, 2, 'a fresh mint on the retry — the single-use cred is never re-sent');
  assert.deepStrictEqual(sent.map((b) => b.password), ['p1', 'p2']);
});

test('clear / sweepExpired / has hold no credential state under mint-per-dispatch', async () => {
  const m = mintSeq([{ user: 'u', password: 'p', hostKeys: 'PIN', expiresAt: FRESH }]);
  const cc = new CredCache({ mint: m.mint, send: async () => ({ ok: true }), now: () => NOW });
  await cc.ensureSent('v1');
  assert.strictEqual(cc.has('v1'), false, 'nothing is cached to be re-sent');
  assert.strictEqual(cc.sweepExpired(NOW + 60 * 60 * 1000), 0, 'no cached credential to sweep');
  cc.clear();       // must not throw
  cc.clear('v1');   // must not throw
});

test('a 401 at mint time is classified as a sign-in need, not a generic retry', async () => {
  const cc = new CredCache({ mint: async () => { const e = new Error('mint request failed: 401'); e.status = 401; throw e; }, send: async () => ({ ok: true }), now: () => NOW });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: false, reason: 'no-session' });
});

test('a 400/429 at mint time is a NON-retrying needs-unlock — never a retry that would burn the shared vault rate limit', async () => {
  for (const status of [400, 429]) {
    const cc = new CredCache({ mint: async () => { const e = new Error(`mint refused: ${status}`); e.status = status; throw e; }, send: async () => ({ ok: true }), now: () => NOW });
    assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: false, reason: 'needs-unlock' }, `${status} -> needs-unlock (not the retryable mint-failed)`);
  }
});

test('an unverifiable host key is classified as host-key-unavailable (a calm cannot-verify-yet upstream)', async () => {
  const cc = new CredCache({ mint: async () => { const e = new Error('host key unavailable'); e.reason = 'host-key-unverified'; throw e; }, send: async () => ({ ok: true }), now: () => NOW });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: false, reason: 'host-key-unavailable' });
});

// Credential-to-child binding: a temp credential is minted for the child that is current at mint time. If a
// RESTART replaces that child during the (network) mint, the send must REFUSE — never hand the fresh child a
// credential minted for a child that is gone (a misdelivery / phantom-cred hazard). The epoch is sampled BEFORE
// the mint and passed to send; a mismatch zeroizes the bundle and returns without delivering.
test('ensureSent binds the cred to the mint-time child epoch: a restart mid-mint refuses delivery, zeroized, never sent to the replacement', async () => {
  let epoch = 5;
  let delivered = null; let attempted = null;
  const cc = new CredCache({
    mint: async () => ({ user: 'u', password: 'topsecret', hostKeys: 'k', host: HOST, expiresAt: FRESH }),
    epoch: () => epoch,
    send: async (bundle, boundEpoch) => {
      attempted = bundle;
      if (boundEpoch != null && boundEpoch !== epoch) { if (bundle && typeof bundle.password === 'string') bundle.password = ''; return { ok: false, reason: 'daemon-exited' }; }
      delivered = { ...bundle }; return { ok: true };
    },
    now: () => NOW,
  });
  // A restart happens DURING the mint: the child epoch moves on after the sample but before the send.
  const realMint = cc._mint;
  cc._mint = async (v) => { const r = await realMint(v); epoch = 6; return r; };
  const res = await cc.ensureSent('v1');
  assert.strictEqual(res.ok, false, 'the send was refused — no cred delivered to the replacement child');
  assert.strictEqual(delivered, null, 'the credential was NOT delivered');
  assert.strictEqual(attempted.password, '', 'the undelivered credential was zeroized');
});

test('ensureSent with a STABLE epoch (no restart) delivers normally — the binding never causes a false refusal', async () => {
  let delivered = null;
  const cc = new CredCache({
    mint: async () => ({ user: 'u', password: 'p', hostKeys: 'k', host: HOST, expiresAt: FRESH }),
    epoch: () => 9,
    send: async (bundle, boundEpoch) => { if (boundEpoch != null && boundEpoch !== 9) return { ok: false, reason: 'daemon-exited' }; delivered = { ...bundle }; return { ok: true }; },
    now: () => NOW,
  });
  assert.deepStrictEqual(await cc.ensureSent('v1'), { ok: true });
  assert.ok(delivered && delivered.user === 'u', 'a stable epoch delivers the credential');
});

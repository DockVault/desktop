'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { credNeedsRefresh, refreshSftpCredIfNeeded, DEFAULT_MARGIN_MS } = require('../src/main/cred-refresh');

const NOW = 1_000_000_000_000;
const iso = (ms) => new Date(ms).toISOString();

test('credNeedsRefresh: valid-with-headroom = false; expired / within-margin / unknown = true', () => {
  assert.strictEqual(credNeedsRefresh(iso(NOW + 10 * 60 * 1000), NOW), false, 'plenty of validity left');
  assert.strictEqual(credNeedsRefresh(iso(NOW - 1000), NOW), true, 'already expired');
  assert.strictEqual(credNeedsRefresh(iso(NOW + 60 * 1000), NOW), true, 'within the default ~2min margin');
  assert.strictEqual(credNeedsRefresh(null, NOW), true, 'missing expiry -> refresh (fail-safe)');
  assert.strictEqual(credNeedsRefresh('not-a-date', NOW), true, 'unparseable expiry -> refresh');
  // exact margin boundary refreshes
  assert.strictEqual(credNeedsRefresh(iso(NOW + DEFAULT_MARGIN_MS), NOW), true, 'at the margin edge');
  assert.strictEqual(credNeedsRefresh(iso(NOW + DEFAULT_MARGIN_MS + 1), NOW), false, 'just past the margin');
});

test('refreshSftpCredIfNeeded: skips the re-mint when the cred has headroom', async () => {
  let minted = 0;
  const r = await refreshSftpCredIfNeeded({
    expiresAt: iso(NOW + 10 * 60 * 1000), now: NOW,
    mint: async () => { minted += 1; return { expiresAt: iso(NOW + 15 * 60 * 1000) }; },
    send: async () => ({ ok: true }),
  });
  assert.deepStrictEqual(r, { refreshed: false, expiresAt: iso(NOW + 10 * 60 * 1000) });
  assert.strictEqual(minted, 0, 'no re-mint when not near expiry');
});

test('refreshSftpCredIfNeeded: re-mints + re-sends near expiry, returns the new expiry', async () => {
  const calls = { mint: 0, sent: null };
  const fresh = { host: 'h', port: 2222, user: 'temp_new', password: 'p', hostKeys: 'ssh-ed25519 K', expiresAt: iso(NOW + 15 * 60 * 1000) };
  const r = await refreshSftpCredIfNeeded({
    expiresAt: iso(NOW + 30 * 1000), now: () => NOW, pinnedHostKeys: 'ssh-ed25519 K', // ~30s left -> within margin
    mint: async () => { calls.mint += 1; return fresh; },
    send: async (access) => { calls.sent = access; return { ok: true }; },
  });
  assert.strictEqual(r.refreshed, true);
  assert.strictEqual(r.expiresAt, fresh.expiresAt);
  assert.strictEqual(calls.mint, 1);
  assert.strictEqual(calls.sent.user, fresh.user, 'the daemon is sent the NEW per-run cred (token boundary intact)');
  assert.strictEqual(calls.sent.hostKeys, 'ssh-ed25519 K', 'carrying the pinned host key');
});

test('refreshSftpCredIfNeeded: a refresh CARRIES OVER the pinned host key (rotates only the cred, never re-pins)', async () => {
  const pinned = 'ssh-ed25519 ORIGINAL';
  let sentBundle = null;
  // even if the re-mint re-fetched a DIFFERENT host key, the bundle handed to the daemon carries the PINNED
  // one — the host identity is never re-pinned at a refresh (a genuine change is caught at connection time).
  const r = await refreshSftpCredIfNeeded({
    expiresAt: null, now: NOW, pinnedHostKeys: pinned,
    mint: async () => ({ user: 'u', password: 'p', hostKeys: 'ssh-ed25519 REFETCHED-DIFFERENT', expiresAt: iso(NOW + 15 * 60 * 1000) }),
    send: async (b) => { sentBundle = b; return { ok: true }; },
  });
  assert.strictEqual(r.refreshed, true);
  assert.strictEqual(sentBundle.hostKeys, pinned, 'the daemon receives the ORIGINAL pinned key, not the re-fetched one');
  assert.strictEqual(sentBundle.user, 'u', 'only the credential (user/password/expiry) rotated');
});

test('refreshSftpCredIfNeeded: FAILS CLOSED when the refresh cannot reach the daemon', async () => {
  await assert.rejects(() => refreshSftpCredIfNeeded({
    expiresAt: null, now: NOW, pinnedHostKeys: 'ssh-ed25519 K', // unknown expiry -> must refresh
    mint: async () => ({ expiresAt: iso(NOW + 15 * 60 * 1000) }),
    send: async () => ({ ok: false, error: 'daemon exited' }),
  }), /could not be delivered to the daemon: daemon exited/);
});

test('refreshSftpCredIfNeeded: pinnedHostKeys is NON-BYPASSABLE — a needed refresh without it fails, pre-mint', async () => {
  let minted = false;
  await assert.rejects(() => refreshSftpCredIfNeeded({
    expiresAt: null, now: NOW, // refresh needed, but no pinnedHostKeys supplied
    mint: async () => { minted = true; return { expiresAt: iso(NOW + 15 * 60 * 1000) }; },
    send: async () => ({ ok: true }),
  }), /requires the pinned host key/);
  assert.strictEqual(minted, false, 'refuses BEFORE re-minting — carry-over cannot be bypassed');
  // when NOT refreshing (headroom), the absence of pinnedHostKeys is harmless (nothing to carry)
  const r = await refreshSftpCredIfNeeded({ expiresAt: iso(NOW + 10 * 60 * 1000), now: NOW, mint: async () => ({}), send: async () => ({ ok: true }) });
  assert.strictEqual(r.refreshed, false);
});

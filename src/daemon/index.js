'use strict';

/*
 * The background sync daemon — a forked Node utility child of the main process.
 *
 * It has NO Electron APIs (no keychain): the main process unwraps the database key with the OS
 * keychain and hands it in ONCE at startup over the private parent↔child channel, which is not a
 * listening port and is not reachable by any other local process. This child owns the encrypted
 * state database; the filesystem watcher, the rclone lifecycle, and the sync engine are added in
 * later phases.
 *
 * Control protocol (messages over process.parentPort):
 *   parent -> child : { type: 'init', dir, dbk?: Uint8Array, rclone?: { bin, version, sha256 } }
 *                      dbk absent => run without an encrypted store (fail-closed: no zero-knowledge
 *                      metadata is persisted); rclone present => standard-vault sync is available
 *                     { type: 'ping', t }        { type: 'sync-status', id }        { type: 'shutdown' }
 *   child  -> parent : { type: 'hello' }          sent once the child is up, before init
 *                     { type: 'ready', encrypted, reason? }
 *                     { type: 'pong', t }         { type: 'sync-status', id, ok, version?, error? }
 *                     { type: 'bye' }             { type: 'error', op, message }
 *
 * The key is used only to open the database and is then zeroized in this process; it is never logged.
 */

const path = require('node:path');
const stateDb = require(path.join(__dirname, '..', 'main', 'state-db'));
const { RcloneRunner } = require('./rclone-runner');

let db = null;
let rclone = null;      // the standard-vault sync runner (one-shot rclone children), if configured
let syncReady = null;   // cached rclone readiness (verified once: pinned binary + version)

function reply(msg) {
  try { process.parentPort.postMessage(msg); } catch { /* parent gone; nothing to do */ }
}

function onInit(m) {
  // Standard-vault sync needs no zero-knowledge/DB key (server-side encrypted), so the runner is set up
  // independently of the DB key. The binary path + pin come from the parent's config.
  if (m.rclone && m.rclone.bin) {
    rclone = new RcloneRunner({ rcloneBin: m.rclone.bin, expectVersion: m.rclone.version || null, expectSha256: m.rclone.sha256 || null });
  }
  if (!m.dbk) {
    // Fail-closed: with no key (e.g. a non-secure keychain) the encrypted store is not created and no
    // zero-knowledge metadata is persisted; background ZK sync stays disabled until a key is available.
    reply({ type: 'ready', encrypted: false, reason: 'no-key' });
    return;
  }
  const dbk = Buffer.from(m.dbk); // a private copy we control + can zeroize
  try {
    db = stateDb.openStateDb(m.dir, dbk);
    reply({ type: 'ready', encrypted: true });
  } finally {
    dbk.fill(0);                          // zeroize our copy
    try { if (m.dbk.fill) m.dbk.fill(0); } catch { /* the transferred view too */ }
  }
}

// Standard-vault sync health: verify the pinned rclone once (checksum + version) and report its
// version. This is the daemon supervising rclone through a one-shot child — no listener, no key material.
async function onSyncStatus(m) {
  if (!rclone) { reply({ type: 'sync-status', id: m.id, ok: false, error: 'rclone not configured' }); return; }
  try {
    if (!syncReady) syncReady = await rclone.ready();
    reply({ type: 'sync-status', id: m.id, ok: true, version: syncReady.version });
  } catch (err) {
    reply({ type: 'sync-status', id: m.id, ok: false, error: String((err && err.message) || err) });
  }
}

process.parentPort.on('message', (event) => {
  const m = (event && event.data) || {};
  try {
    switch (m.type) {
      case 'init': onInit(m); break;
      case 'ping': reply({ type: 'pong', t: m.t }); break;
      case 'sync-status': void onSyncStatus(m); break;
      case 'zk-lock':
        // Drop the daemon's in-memory ZK sync key as part of the atomic lock purge, then ACK so the
        // purge is observable (request->ack; the id correlates the reply). No such key exists until
        // the sync engine is added, so this is a wired hook today that acks immediately. (Later: a
        // true zeroize of the daemon's ZK key + per-vault DEKs — Node Buffers, explicit .fill(0) —
        // happens BEFORE this ack, so the ack only fires once the bytes are gone.)
        reply({ type: 'zk-locked', id: m.id });
        break;
      case 'shutdown':
        try { if (db) db.close(); } catch { /* best effort */ }
        db = null;
        reply({ type: 'bye' });
        break;
      default: reply({ type: 'error', op: String(m.type), message: 'unknown message' });
    }
  } catch (err) {
    reply({ type: 'error', op: String(m && m.type), message: String((err && err.message) || err) });
  }
});

reply({ type: 'hello' });

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
 *                     { type: 'sftp-cred', id, bundle }   a per-run scoped SFTP cred (over this private,
 *                        in-memory channel ONLY — never disk/argv/env); the child obscures the password
 *                        just-in-time and holds only the prepared config
 *                     { type: 'sftp-cred-clear', id }      drop the prepared config from memory (on lock /
 *                        session end); acked, so the clear is observable
 *                     { type: 'run-state', id, vaults }    query each vault's run-state (operational
 *                        metadata only — last result + resync-owed; never a credential)
 *                     { type: 'sync-run', id, spec }       run one bisync; spec = { vault, local,
 *                        remotePath, resync? }. Uses the prepared config from the last sftp-cred.
 *   child  -> parent : { type: 'hello' }          sent once the child is up, before init
 *                     { type: 'ready', encrypted, reason? }
 *                     { type: 'pong', t }         { type: 'sync-status', id, ok, version?, error? }
 *                     { type: 'sftp-cred-ack', id, ok, error? }   (never echoes the cred or the config)
 *                     { type: 'run-state-result', id, states }    per-vault { lastResult, resyncRequired }, null
 *                       (a real missing row = never-run), or 'unknown' (unreadable / no state DB — not never-run)
 *                     { type: 'sync-run-result', id, ok, ran?, result?, resyncRequired?, needsAttention?,
 *                        code?, error? }  (a summarized, typed outcome only — never raw output or the cred)
 *                     { type: 'bye' }             { type: 'error', op, message }
 *
 * The key is used only to open the database and is then zeroized in this process; it is never logged.
 */

const path = require('node:path');
const stateDb = require(path.join(__dirname, '..', 'main', 'state-db'));
const { RcloneRunner } = require('./rclone-runner');
const ephemeralConfig = require('./ephemeral-config');
const syncEngine = require('./sync-engine');
const { runVaultSync } = require('./sync-run');

let db = null;
let rclone = null;      // the standard-vault sync runner (one-shot rclone children), if configured
let rcloneRunDir = null; // where per-run ephemeral rclone configs live (under userData)
let syncReady = null;   // cached rclone readiness (verified once: pinned binary + version)
let sftpConfig = null;  // the prepared rclone remote config (obscured cred) held in memory for a run
let syncInFlight = false; // one bisync at a time in the helper: a second request is refused, never run concurrently
let credGen = 0;        // bumped on every fresh sftp-cred prepared — lets a per-step request confirm a NEW cred arrived
let needCredSeq = 0;    // id source for helper-initiated 'need-sftp-cred' requests
const needCredPending = new Map(); // request id -> { resolve, timer }

function reply(msg) {
  try { process.parentPort.postMessage(msg); } catch { /* parent gone; nothing to do */ }
}

// Ask MAIN to mint+send a fresh single-use credential for `vault` (the server burns one on first use, so each
// rclone process of a resync needs its own). Main authorises or refuses; the credential itself arrives on the
// sftp-cred path (onSftpCred), never in this reply. Fail-closed on timeout — the step then does not run.
function requestFreshCred(vault, timeoutMs = 20000) {
  return new Promise((resolve) => {
    const id = 'nc' + (++needCredSeq);
    const timer = setTimeout(() => { if (needCredPending.delete(id)) resolve({ ok: false, reason: 'cred-request-timeout' }); }, timeoutMs);
    if (timer.unref) timer.unref();
    needCredPending.set(id, { resolve, timer });
    reply({ type: 'need-sftp-cred', id, vault });
  });
}

// A per-step credential provider for the resync engines: request a fresh single-use credential from main, and
// only if a NEW one actually arrived (credGen advanced — never proceed on a stale slot even if main said ok),
// rewrite the run's ephemeral config atomically so the next rclone process authenticates with it. Returns the
// typed reason on any failure, so it becomes the step's honest outcome.
async function prepareFreshCred(vault, cfgPath) {
  const before = credGen;
  const r = await requestFreshCred(vault);
  if (!r || !r.ok) return { ok: false, reason: (r && r.reason) || 'cred-request-failed' };
  if (credGen === before || !sftpConfig) return { ok: false, reason: 'cred-request-failed' }; // ok, but no fresh cred landed
  try { ephemeralConfig.rewriteEphemeralConfig(cfgPath, sftpConfig); }
  catch { return { ok: false, reason: 'cred-config-write-failed' }; }
  return { ok: true };
}

function onInit(m) {
  // Standard-vault sync needs no zero-knowledge/DB key (server-side encrypted), so the runner is set up
  // independently of the DB key. The binary path + pin come from the parent's config.
  if (m.rclone && m.rclone.bin) {
    rclone = new RcloneRunner({ rcloneBin: m.rclone.bin, expectVersion: m.rclone.version || null, expectSha256: m.rclone.sha256 || null });
    rcloneRunDir = path.join(m.dir, 'rclone');
    // Crash-sweep: remove any per-run cred config orphaned by a prior crash before sync resumes.
    // Fail-closed — a lingering cred file is surfaced, never left silently.
    try { ephemeralConfig.sweepStaleConfigs(rcloneRunDir); }
    catch (err) { reply({ type: 'error', op: 'sweep-stale-configs', message: String((err && err.message) || err) }); }
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

// Receive a per-run scoped SFTP credential over the private channel and prepare the rclone config in
// memory. The plaintext password is obscured into rclone's config form immediately (JIT) and only the
// prepared config text is retained; the plaintext is not written anywhere and not echoed back. The ack
// reports readiness only — never the credential or the config.
async function onSftpCred(m) {
  const b = (m && m.bundle) || {};
  if (!rclone) { reply({ type: 'sftp-cred-ack', id: m.id, ok: false, error: 'rclone not configured' }); return; }
  try {
    if (!syncReady) syncReady = await rclone.ready();
    const obscuredPass = await rclone.obscure(b.password);
    sftpConfig = ephemeralConfig.formatSftpRemote('vault', {
      host: b.host, port: b.port, user: b.user, obscuredPass, hostKeys: b.hostKeys,
    });
    credGen += 1; // a fresh credential is now prepared — a pending per-step request can confirm it arrived
    reply({ type: 'sftp-cred-ack', id: m.id, ok: true });
  } catch (err) {
    sftpConfig = null;
    reply({ type: 'sftp-cred-ack', id: m.id, ok: false, error: String((err && err.message) || err) });
  }
}

// Drop the prepared SFTP config from memory — on app lock, and when the account session ends. Until a
// fresh credential is sent, the next run fails closed with 'no sftp cred prepared'. Acked so the clear is
// observable to the caller (the lock flow can confirm the daemon holds nothing before it reports Locked).
function onSftpCredClear(m) {
  sftpConfig = null;
  reply({ type: 'sftp-cred-ack', id: m.id, ok: true });
}

// Report each requested vault's run-state so the scheduler (in main) can tell a never-run vault from a
// blocked one without opening the state DB itself (the daemon stays its single owner). This is OPERATIONAL
// METADATA ONLY — the two run-state columns (last typed result, resync-owed) — never a credential or any
// zero-knowledge material. A vault with NO row is reported as null (never-run) — the ONE source of truth
// for the never-run vs blocked distinction, so main never double-defaults it. A read that CANNOT be made
// (a throwing read, or no state DB this session) is reported 'unknown', NEVER null, so main skips it as
// state-uncertain instead of mistaking it for never-run and dispatching a spurious initial resync.
function onRunState(m) {
  const vaults = Array.isArray(m && m.vaults) ? m.vaults : [];
  const states = {};
  // No state DB this session (no key yet) — we CANNOT know any vault's run-state. Report every vault as
  // 'unknown', NEVER null: null is reserved for a real MISSING row (a genuinely never-run vault). Conflating
  // "can't tell" with "never run" would dispatch a spurious INITIAL RESYNC — and with no DB nothing is ever
  // recorded, so it would recur every tick (a resync loop → mass keep-both duplication). Fail-closed.
  if (!db) {
    for (const v of vaults) states[String(v)] = 'unknown';
    reply({ type: 'run-state-result', id: m.id, states });
    return;
  }
  for (const v of vaults) {
    try {
      const st = stateDb.getRunState(db, v);
      // getRunState synthesises lastResult:null only for a MISSING row (a real row always has a result),
      // so a null result IS the never-run signal — report it as null rather than a synthesised default.
      states[String(v)] = st.lastResult == null ? null : { lastResult: st.lastResult, resyncRequired: !!st.resyncRequired };
    } catch { states[String(v)] = 'unknown'; } // a locked / corrupt / closed read is UNKNOWN, never never-run
  }
  reply({ type: 'run-state-result', id: m.id, states });
}

// Run one vault sync using the config prepared by the last sftp-cred. Delete-safety, the first-run/blocked
// resync gate, and the rule that a resync goes ONLY through the zero-loss (keep-both) path live in the
// engine + its router; this handler just supplies the ephemeral config + workdir and relays a SUMMARIZED
// outcome (never raw rclone output, never the cred/config). The remote name matches the one
// formatSftpRemote used ('vault'); the caller supplies only the path within it.
async function onSyncRun(m) {
  const b = (m && m.spec) || {};
  if (!rclone) { reply({ type: 'sync-run-result', id: m.id, ok: false, error: 'rclone not configured' }); return; }
  if (!sftpConfig) { reply({ type: 'sync-run-result', id: m.id, ok: false, error: 'no sftp cred prepared' }); return; }
  if (!b.vault || !b.local || typeof b.remotePath !== 'string') {
    reply({ type: 'sync-run-result', id: m.id, ok: false, error: 'sync-run needs vault, local, remotePath' });
    return;
  }
  // One bisync at a time in the helper. The caller's global mutex already serialises runs, but if the
  // caller ever gives up early (its own timeout) while a long run is still going here, this refuses the
  // second request rather than starting two rclone children on the same vault. ran:false, so the caller
  // records nothing — the still-running first run remains the source of truth.
  // A TYPED refusal, not a bare error: this fires exactly when a healthy long run is still going, so the
  // caller must be able to tell it apart from a real failure (and never count it as one, or as a run that
  // completed). ran:false + refused:'already-running'; no error prose to be mistaken for a fault.
  if (syncInFlight) { reply({ type: 'sync-run-result', id: m.id, ok: false, ran: false, refused: 'already-running' }); return; }
  syncInFlight = true;
  try {
    if (!syncReady) syncReady = await rclone.ready();
    const workdir = syncEngine.bisyncWorkdir(rcloneRunDir, b.vault);
    const remote = 'vault:' + b.remotePath;
    // A resync runs several rclone processes, each of which burns a single-use credential — so each gets its
    // own fresh one via prepareFreshCred (main authorises + sends; this rewrites the ephemeral config). A
    // normal one-process bisync needs no provider: it uses the dispatch credential already prepared.
    const r = await ephemeralConfig.withEphemeralConfig(rcloneRunDir, sftpConfig, (cfgPath) =>
      runVaultSync({
        runner: rclone, db, vault: b.vault, local: b.local, remote, workdir, config: cfgPath, resync: !!b.resync,
        prepareCred: b.resync ? (() => prepareFreshCred(b.vault, cfgPath)) : undefined,
      }));
    reply({ type: 'sync-run-result', id: m.id, ok: true, ran: r.ran, result: r.result, reason: r.reason, resyncRequired: r.resyncRequired, needsAttention: r.needsAttention, code: r.code, preserved: r.preserved });
  } catch (err) {
    reply({ type: 'sync-run-result', id: m.id, ok: false, error: String((err && err.message) || err) });
  } finally {
    syncInFlight = false;
    sftpConfig = null; // a single-use credential is spent after its run — never leave one held between runs
  }
}

process.parentPort.on('message', (event) => {
  const m = (event && event.data) || {};
  try {
    switch (m.type) {
      case 'init': onInit(m); break;
      case 'ping': reply({ type: 'pong', t: m.t }); break;
      case 'sync-status': void onSyncStatus(m); break;
      case 'sftp-cred': void onSftpCred(m); break;
      case 'sftp-cred-clear': onSftpCredClear(m); break;
      case 'need-sftp-cred-result': {
        const e = needCredPending.get(m.id);
        if (e) { needCredPending.delete(m.id); clearTimeout(e.timer); e.resolve({ ok: !!m.ok, reason: m.reason || null }); }
        break;
      }
      case 'run-state': onRunState(m); break;
      case 'sync-run': void onSyncRun(m); break;
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

'use strict';

/*
 * Supervises the forked sync daemon from the main process.
 *
 * The daemon runs as a Node utility child (crash-isolated from the window and from the main process's
 * event loop). The main process is the only holder of the OS keychain, so it unwraps the database key
 * and hands it to the daemon ONCE, at startup, over the private parent↔child channel — not a listening
 * port, not reachable by other local processes — then zeroizes its own copy. The key is never logged
 * and never placed in the child's arguments or environment.
 *
 * The supervisor restarts the daemon with capped exponential backoff if it exits unexpectedly, so a
 * crash never leaves sync silently dead, and stops it cleanly on app quit.
 */

const { utilityProcess, safeStorage } = require('electron');
const path = require('node:path');
const stateDb = require('./state-db');

const DAEMON_ENTRY = path.join(__dirname, '..', 'daemon', 'index.js');
const MAX_BACKOFF_MS = 30000;
// Crash-loop ceiling: after this many unexpected exits inside the window, the supervisor stops
// restarting and reports a stuck helper rather than churning forever. A helper that cannot stay up
// is surfaced as a sync problem the person must act on, never retried silently to exhaustion.
const MAX_RESTARTS = 5;
const CRASH_WINDOW_MS = 3 * 60 * 1000;
// A single resync run's per-process credential requests are bounded: enumerate + compare + one preserve per
// conflicting file + the baseline. This ceiling covers a large conflict set with generous slack while still
// stopping a looping helper from minting without bound (each mint is a server credential row + an audit line).
const MAX_CRED_REQUESTS_PER_RUN = 512;

class DaemonManager {
  constructor(userDataDir, rcloneConfig = null, opts = {}) {
    this.dir = userDataDir;
    this.rcloneConfig = rcloneConfig; // { bin, version, sha256 } for standard-vault sync, or null
    this.child = null;
    this.stopping = false;
    this.restarts = 0;
    this.status = 'stopped';
    this._listeners = [];
    this._restartTimer = null;
    // Crash-loop ceiling state (clock injectable for tests).
    this._now = typeof opts.now === 'function' ? opts.now : () => Date.now();
    this._maxRestarts = opts.maxRestarts || MAX_RESTARTS;
    this._crashWindowMs = opts.crashWindowMs || CRASH_WINDOW_MS;
    this._restartTimes = [];
    this.crashLoopLatched = false; // true once the ceiling is hit; cleared only by a deliberate resume()
    this._pingSeq = 0;
    this._pending = new Map(); // ping id -> resolve
    this._lockSeq = 0;
    this._lockPending = new Map(); // zk-lock id -> resolve
    this._statusSeq = 0;
    this._statusPending = new Map(); // sync-status id -> { resolve, timer }
    this._credSeq = 0;
    this._credPending = new Map(); // sftp-cred id -> { resolve, timer }
    this._syncSeq = 0;
    this._syncPending = new Map(); // sync-run id -> { resolve, timer }
    this._runStateSeq = 0;
    this._runStatePending = new Map(); // run-state id -> { resolve, timer }
    // The helper may REQUEST a fresh single-use credential per rclone process of a resync (the daemon->main
    // 'need-sftp-cred' direction). Main AUTHORISES each such request — it never executes it: an injected
    // provider applies the in-flight-vault + unlock + account checks and mints, and a per-run counter bounds
    // how many a single run may ask for, so a looping helper cannot mint without bound.
    this._credProvider = null;
    this._credRequestsThisRun = 0;
  }

  /**
   * Wire the authoriser for a helper-initiated per-step credential request. `fn(vault)` must itself enforce
   * the in-flight-vault, unlock and account checks and then mint+send (it returns { ok, reason }). The per-run
   * COUNT bound is enforced here, in main, independently of anything the helper says.
   */
  setCredProvider(fn) { this._credProvider = fn; }

  start() { if (!this.child) this._spawn(); return this; }

  _spawn() {
    this.status = 'starting';
    const child = utilityProcess.fork(DAEMON_ENTRY, [], { serviceName: 'dockvault-sync' });
    this.child = child;
    child.on('message', (m) => this._onMessage(m || {}));
    child.on('exit', (code) => this._onExit(code));
  }

  _onMessage(m) {
    switch (m.type) {
      case 'hello': this._sendInit(); break;
      case 'ready':
        this.status = m.encrypted ? 'ready' : 'ready-no-store';
        // A clean start breaks any crash loop: forget the recent-exit history and the backoff.
        this.restarts = 0;
        this._restartTimes = [];
        this.crashLoopLatched = false;
        this._emit('ready', m);
        break;
      case 'pong': {
        const r = this._pending.get(m.t); if (r) { this._pending.delete(m.t); r(true); }
        break;
      }
      case 'zk-locked': {
        const e = this._lockPending.get(m.id);
        if (e) { this._lockPending.delete(m.id); clearTimeout(e.timer); e.resolve(true); }
        break;
      }
      case 'sync-status': {
        const e = this._statusPending.get(m.id);
        if (e) { this._statusPending.delete(m.id); clearTimeout(e.timer); e.resolve({ ok: !!m.ok, version: m.version || null, sub: m.sub || null, installed: m.installed || null, pinned: m.pinned || null }); }
        break;
      }
      case 'sftp-cred-ack': {
        const e = this._credPending.get(m.id);
        // Carry the typed reason enum (`sub`) plus the non-secret version strings (installed/pinned, for the
        // "update the sync helper X→Y" remedy) — NEVER a free-text error (which could carry a host or path).
        if (e) { this._credPending.delete(m.id); clearTimeout(e.timer); e.resolve({ ok: !!m.ok, sub: m.sub || null, installed: m.installed || null, pinned: m.pinned || null }); }
        break;
      }
      case 'sync-run-result': {
        const e = this._syncPending.get(m.id);
        if (e) {
          this._syncPending.delete(m.id); clearTimeout(e.timer);
          e.resolve({ ok: !!m.ok, ran: !!m.ran, result: m.result || null, reason: m.reason || null, resyncRequired: !!m.resyncRequired, needsAttention: !!m.needsAttention, code: typeof m.code === 'number' ? m.code : null, preserved: typeof m.preserved === 'number' ? m.preserved : null, refused: m.refused || null });
        }
        break;
      }
      // Unsolicited in-flight progress: the two aggregate integers only (files, bytes) for a vault. Emitted as
      // an event for the status hub. It is not a reply (no id) and carries no path — the numbers are re-coerced
      // here so nothing but a number or null can pass on, whatever the helper sent.
      case 'sync-progress': this._emit('sync-progress', { vault: m.vault, files: typeof m.files === 'number' ? m.files : null, bytes: typeof m.bytes === 'number' ? m.bytes : null }); break;
      // The helper asks main to mint+send a fresh single-use credential for the CURRENT resync's next process.
      case 'need-sftp-cred': void this._onNeedSftpCred(m); break;
      case 'run-state-result': {
        const e = this._runStatePending.get(m.id);
        if (e) { this._runStatePending.delete(m.id); clearTimeout(e.timer); e.resolve({ ok: true, states: (m.states && typeof m.states === 'object') ? m.states : {} }); }
        break;
      }
      case 'error':
        // Surface the FACT of a daemon-side error for diagnosis — the op only, never the message (which can
        // carry a path or host). Init failures no longer arrive here (they come back as a typed ready reply);
        // this catches the rest so none is silently dropped.
        try { console.error('[sync] daemon error op=' + ((m && m.op) || 'unknown')); } catch { /* ignore */ }
        this._emit('error', m);
        break;
      default: break;
    }
  }

  // Unwrap the DB key with the keychain and hand it in once. Fail-closed: a null key tells the daemon
  // to run without an encrypted store. The main-side copies are zeroized immediately after sending.
  _sendInit() {
    let dbk = null;
    let keyReason = null; // a bounded reason when a wrapped key exists but could not be unwrapped
    try { dbk = stateDb.loadOrMintDBK(safeStorage, this.dir); }
    catch (e) {
      // A wrapped key exists on disk but did not unwrap (a transient keychain error, or a corrupt/rotated
      // key). loadOrMintDBK deliberately did NOT overwrite it — the existing database is intact but locked.
      // Start the daemon WITHOUT a key and carry the typed reason so it reports an honest, non-retrying
      // problem, rather than silently minting a fresh key (which would orphan the database).
      keyReason = (e && e.reason) || 'db-key-unreadable';
    }
    const view = dbk ? new Uint8Array(dbk) : null;
    try { this.child.postMessage({ type: 'init', dir: this.dir, dbk: view, keyReason, rclone: this.rcloneConfig }); }
    finally {
      if (dbk) dbk.fill(0);
      if (view) view.fill(0);
    }
  }

  _onExit(code) {
    this.child = null;
    for (const r of this._pending.values()) r(false);
    this._pending.clear();
    // A daemon that has exited holds no key in memory — its process is gone. Resolve any in-flight
    // zk-lock ack as confirmed-clean so a crash mid-purge does not hang the lock (fail-closed still
    // holds: the caller only reports "locked" once this resolves, and a dead process has no key).
    for (const e of this._lockPending.values()) { clearTimeout(e.timer); e.resolve(true); }
    this._lockPending.clear();
    // A dead daemon can't answer a status request — resolve any in-flight one as not-ok, never hang.
    for (const e of this._statusPending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, version: null, reason: 'daemon-exited' }); }
    this._statusPending.clear();
    for (const e of this._credPending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, reason: 'daemon-exited' }); }
    this._credPending.clear();
    // A dead daemon can't finish a bisync — resolve any in-flight run as not-ok (never hang). It stays
    // fail-closed: the caller sees a failed run and the resync block (if any) is untouched on disk.
    for (const e of this._syncPending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, ran: false, reason: 'daemon-exited' }); }
    this._syncPending.clear();
    // A dead daemon can't answer a run-state query — resolve any in-flight one as a FAILURE (ok:false),
    // distinct from a successful-but-empty snapshot, so the caller fails closed (never reads it as
    // "every vault never-run") and never hangs.
    for (const e of this._runStatePending.values()) { clearTimeout(e.timer); e.resolve({ ok: false }); }
    this._runStatePending.clear();
    if (this.stopping) { this.status = 'stopped'; return; }
    // Record this exit and keep only those inside the window. Once too many land in the window the
    // ceiling is hit: stop restarting, latch the stuck state, and surface it — never a silent storm.
    const now = this._now();
    this._restartTimes.push(now);
    this._restartTimes = this._restartTimes.filter((t) => now - t < this._crashWindowMs);
    if (this._restartTimes.length >= this._maxRestarts) {
      this.crashLoopLatched = true;
      this.status = 'crash-looped';
      this._emit('crash-loop', { code, restarts: this._restartTimes.length });
      return; // no restart scheduled: a deliberate resume() is required to try again
    }
    this.status = 'crashed';
    const backoff = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.restarts);
    this.restarts += 1;
    this._emit('exit', { code, backoff });
    this._restartTimer = setTimeout(() => { if (!this.stopping) this._spawn(); }, backoff);
    if (this._restartTimer.unref) this._restartTimer.unref();
  }

  /**
   * The deliberate "restart sync" action after the crash-loop ceiling was hit. Clears the latch and
   * the recent-exit history and starts the helper again. A no-op (returns false) when not latched, so
   * it can only ever RESUME from the stuck state, never force a second concurrent helper.
   */
  resume() {
    if (!this.crashLoopLatched) return false;
    this.crashLoopLatched = false;
    this.restarts = 0;
    this._restartTimes = [];
    this.stopping = false;
    this._emit('resume', {});
    this._spawn();
    return true;
  }

  /** Health check: resolves true on a matching pong, false on timeout or a dead child. */
  ping(timeoutMs = 2000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve(false);
      const t = ++this._pingSeq;
      this._pending.set(t, resolve);
      try { this.child.postMessage({ type: 'ping', t }); } catch { this._pending.delete(t); return resolve(false); }
      const timer = setTimeout(() => { if (this._pending.delete(t)) resolve(false); }, timeoutMs);
      if (timer.unref) timer.unref();
    });
  }

  /**
   * Tell the daemon to drop its in-memory ZK sync key (part of the atomic lock purge) and AWAIT its
   * ack (request->ack, bounded timeout). Resolves true once the daemon confirms the key is gone, or
   * true when there is no running daemon (a non-existent process holds no key). Resolves false only
   * on a send failure or an ack timeout while the daemon is alive — the caller treats that as
   * NOT-confirmed and fails closed (never reports "locked" while a key might still live).
   */
  zkLock(timeoutMs = 2000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve(true); // no daemon => no daemon-side key to purge
      const id = ++this._lockSeq;
      // The timeout stays ref'd for its bounded window: a lock purge is a foreground security
      // operation we actively wait on. It is cleared the instant an ack (or exit) settles the purge.
      const timer = setTimeout(() => { if (this._lockPending.delete(id)) resolve(false); }, timeoutMs);
      this._lockPending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'zk-lock', id }); }
      catch { this._lockPending.delete(id); clearTimeout(timer); return resolve(false); }
    });
  }

  /**
   * Ask the daemon to verify + report the standard-vault sync runner (pinned rclone binary + version)
   * and round-trip its version. Resolves { ok, version, error }: ok=false when rclone is unconfigured,
   * the daemon is dead, verification fails closed, or the request times out.
   */
  syncStatus(timeoutMs = 12000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve({ ok: false, version: null, error: 'no daemon' });
      const id = ++this._statusSeq;
      const timer = setTimeout(() => { if (this._statusPending.delete(id)) resolve({ ok: false, version: null, error: 'timeout' }); }, timeoutMs);
      if (timer.unref) timer.unref();
      this._statusPending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'sync-status', id }); }
      catch { this._statusPending.delete(id); clearTimeout(timer); return resolve({ ok: false, version: null, error: 'send failed' }); }
    });
  }

  /**
   * Hand the daemon a per-run scoped SFTP credential bundle over the PRIVATE parent<->child channel
   * (in-memory, like the DB key) — never disk, argv, or environment. The daemon obscures the password
   * just-in-time and holds only the prepared config; the ack reports readiness, never the credential.
   * Resolves { ok, error } — ok=false when unconfigured, dead, prepare failed, or the request timed out.
   */
  sendSftpCred(bundle, timeoutMs = 12000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve({ ok: false, error: 'no daemon' });
      const id = ++this._credSeq;
      const timer = setTimeout(() => { if (this._credPending.delete(id)) resolve({ ok: false, error: 'timeout' }); }, timeoutMs);
      if (timer.unref) timer.unref();
      this._credPending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'sftp-cred', id, bundle }); }
      catch { this._credPending.delete(id); clearTimeout(timer); return resolve({ ok: false, error: 'send failed' }); }
    });
  }

  /**
   * Tell the daemon to drop its prepared SFTP config (on app lock / session end). Resolves { ok } — and
   * ok=true when there is no daemon, since "no daemon holds no credential" already satisfies the caller's
   * goal (nothing to clear). Acked so the lock flow can confirm the daemon holds nothing.
   */
  clearSftpCred(timeoutMs = 12000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve({ ok: true }); // no daemon => nothing is held; the clear is vacuously done
      const id = ++this._credSeq;
      const timer = setTimeout(() => { if (this._credPending.delete(id)) resolve({ ok: false, error: 'timeout' }); }, timeoutMs);
      if (timer.unref) timer.unref();
      this._credPending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'sftp-cred-clear', id }); }
      catch { this._credPending.delete(id); clearTimeout(timer); return resolve({ ok: false, error: 'send failed' }); }
    });
  }

  /**
   * Ask the daemon to run one bisync for a vault, using the config prepared by the last sendSftpCred().
   * The daemon enforces delete-safety + the first-run/blocked resync gate; this only relays a summarized
   * outcome. `spec` = { vault, local, remotePath, resync? }. Resolves { ok, ran, result, resyncRequired,
   * code, error }: ok=false when unconfigured, no cred is prepared, the daemon is dead, or it timed out.
   * The daemon self-bounds a run by inactivity plus its own generous hard ceiling, so this timeout sits
   * ABOVE that ceiling — it is only a backstop for a wedged daemon, never a shorter cap that would give up
   * on a long-but-live run and release the run mutex while the daemon is still working (which could then
   * start a second run on the same vault).
   */
  runSync(spec, timeoutMs = 6 * 60 * 60 * 1000 + 10 * 60 * 1000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve({ ok: false, ran: false, error: 'no daemon' });
      this._credRequestsThisRun = 0; // a fresh per-run budget for this run's per-step credential requests
      const id = ++this._syncSeq;
      const timer = setTimeout(() => { if (this._syncPending.delete(id)) resolve({ ok: false, ran: false, error: 'timeout' }); }, timeoutMs);
      if (timer.unref) timer.unref();
      this._syncPending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'sync-run', id, spec }); }
      catch { this._syncPending.delete(id); clearTimeout(timer); return resolve({ ok: false, ran: false, error: 'send failed' }); }
    });
  }

  // Authorise (never blindly execute) a helper-initiated request to mint+send a fresh single-use credential
  // for the current resync's next process. Main holds the say: the per-run COUNT is bounded here, and the
  // injected provider re-checks that `vault` is the in-flight one and that the app is unlocked with a live
  // account before it mints. The reply carries NO credential — only { ok, reason }; the credential itself
  // travels on the existing sftp-cred -> sftp-cred-ack path, which the helper confirms arrived before it uses it.
  async _onNeedSftpCred(m) {
    const id = m && m.id;
    const vault = m && typeof m.vault === 'string' && m.vault ? m.vault : null;
    const done = (ok, reason) => { try { if (this.child) this.child.postMessage({ type: 'need-sftp-cred-result', id, ok: !!ok, reason: reason || null }); } catch { /* child gone */ } };
    if (id == null || !vault) return done(false, 'bad-request');
    this._credRequestsThisRun += 1;
    if (this._credRequestsThisRun > MAX_CRED_REQUESTS_PER_RUN) return done(false, 'cap-exceeded');
    if (!this._credProvider) return done(false, 'no-provider');
    let r;
    try { r = await this._credProvider(vault); }
    catch (e) {
      // The provider itself threw (a code error, not a mint/network failure). Do NOT swallow it as the
      // generic retryable 'mint-failed' — that hid a real bug behind an endless per-tick retry. Surface a
      // DISTINCT typed reason and note the error class only (leak-safe: class/code, never a message/path).
      try { console.error('[sync] credential provider error:', (e && e.name) || 'Error', (e && e.code) || ''); } catch { /* ignore */ }
      r = { ok: false, reason: 'provider-error' };
    }
    return done(!!(r && r.ok), r && r.reason);
  }

  /**
   * Query the daemon for each vault's run-state (operational metadata only — no credential). Resolves
   * `{ ok:true, states }` on a real answer — states = { vaultId: { lastResult, resyncRequired } | null |
   * 'unknown' }, null for a genuinely never-run vault (a real missing row), 'unknown' for a vault whose state
   * could NOT be read (a throwing store, or no state DB this session) so the caller skips it as
   * state-uncertain, and an EMPTY states means every vault is genuinely never-run. Resolves `{ ok:false }` on
   * no daemon, a timeout, or a send failure — DISTINCT from an empty success, so the caller can fail closed
   * (a failed query, or an unknown per-vault state, must never read as "every vault never-run") and never hangs.
   * @param {string[]} vaults
   */
  runStates(vaults, timeoutMs = 5000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve({ ok: false });
      const id = ++this._runStateSeq;
      const timer = setTimeout(() => { if (this._runStatePending.delete(id)) resolve({ ok: false }); }, timeoutMs);
      if (timer.unref) timer.unref();
      this._runStatePending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'run-state', id, vaults: Array.isArray(vaults) ? vaults : [] }); }
      catch { this._runStatePending.delete(id); clearTimeout(timer); return resolve({ ok: false }); }
    });
  }

  stop() {
    this.stopping = true;
    if (this._restartTimer) clearTimeout(this._restartTimer);
    if (this.child) {
      try { this.child.postMessage({ type: 'shutdown' }); } catch { /* ignore */ }
      try { this.child.kill(); } catch { /* ignore */ }
      this.child = null;
    }
    this.status = 'stopped';
  }

  on(event, cb) { this._listeners.push([event, cb]); return this; }
  _emit(event, data) { for (const [e, cb] of this._listeners) if (e === event) { try { cb(data); } catch { /* listener error is not ours */ } } }
}

module.exports = { DaemonManager, DAEMON_ENTRY };

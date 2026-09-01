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

class DaemonManager {
  constructor(userDataDir, rcloneConfig = null) {
    this.dir = userDataDir;
    this.rcloneConfig = rcloneConfig; // { bin, version, sha256 } for standard-vault sync, or null
    this.child = null;
    this.stopping = false;
    this.restarts = 0;
    this.status = 'stopped';
    this._listeners = [];
    this._restartTimer = null;
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
  }

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
        this.restarts = 0;
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
        if (e) { this._statusPending.delete(m.id); clearTimeout(e.timer); e.resolve({ ok: !!m.ok, version: m.version || null, error: m.error || null }); }
        break;
      }
      case 'sftp-cred-ack': {
        const e = this._credPending.get(m.id);
        if (e) { this._credPending.delete(m.id); clearTimeout(e.timer); e.resolve({ ok: !!m.ok, error: m.error || null }); }
        break;
      }
      case 'sync-run-result': {
        const e = this._syncPending.get(m.id);
        if (e) {
          this._syncPending.delete(m.id); clearTimeout(e.timer);
          e.resolve({ ok: !!m.ok, ran: !!m.ran, result: m.result || null, resyncRequired: !!m.resyncRequired, needsAttention: !!m.needsAttention, code: typeof m.code === 'number' ? m.code : null, error: m.error || null });
        }
        break;
      }
      case 'error': this._emit('error', m); break;
      default: break;
    }
  }

  // Unwrap the DB key with the keychain and hand it in once. Fail-closed: a null key tells the daemon
  // to run without an encrypted store. The main-side copies are zeroized immediately after sending.
  _sendInit() {
    const dbk = stateDb.loadOrMintDBK(safeStorage, this.dir);
    const view = dbk ? new Uint8Array(dbk) : null;
    try { this.child.postMessage({ type: 'init', dir: this.dir, dbk: view, rclone: this.rcloneConfig }); }
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
    for (const e of this._statusPending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, version: null, error: 'daemon exited' }); }
    this._statusPending.clear();
    for (const e of this._credPending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, error: 'daemon exited' }); }
    this._credPending.clear();
    // A dead daemon can't finish a bisync — resolve any in-flight run as not-ok (never hang). It stays
    // fail-closed: the caller sees a failed run and the resync block (if any) is untouched on disk.
    for (const e of this._syncPending.values()) { clearTimeout(e.timer); e.resolve({ ok: false, ran: false, error: 'daemon exited' }); }
    this._syncPending.clear();
    if (this.stopping) { this.status = 'stopped'; return; }
    this.status = 'crashed';
    const backoff = Math.min(MAX_BACKOFF_MS, 500 * 2 ** this.restarts);
    this.restarts += 1;
    this._emit('exit', { code, backoff });
    this._restartTimer = setTimeout(() => { if (!this.stopping) this._spawn(); }, backoff);
    if (this._restartTimer.unref) this._restartTimer.unref();
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
   * Ask the daemon to run one bisync for a vault, using the config prepared by the last sendSftpCred().
   * The daemon enforces delete-safety + the first-run/blocked resync gate; this only relays a summarized
   * outcome. `spec` = { vault, local, remotePath, resync? }. Resolves { ok, ran, result, resyncRequired,
   * code, error }: ok=false when unconfigured, no cred is prepared, the daemon is dead, or it timed out.
   * The timeout exceeds the daemon-side bisync timeout so a long-but-live run is not cut short here.
   */
  runSync(spec, timeoutMs = 15 * 60 * 1000) {
    return new Promise((resolve) => {
      if (!this.child) return resolve({ ok: false, ran: false, error: 'no daemon' });
      const id = ++this._syncSeq;
      const timer = setTimeout(() => { if (this._syncPending.delete(id)) resolve({ ok: false, ran: false, error: 'timeout' }); }, timeoutMs);
      if (timer.unref) timer.unref();
      this._syncPending.set(id, { resolve, timer });
      try { this.child.postMessage({ type: 'sync-run', id, spec }); }
      catch { this._syncPending.delete(id); clearTimeout(timer); return resolve({ ok: false, ran: false, error: 'send failed' }); }
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

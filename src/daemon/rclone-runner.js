'use strict';

/*
 * Runs rclone as ONE-SHOT child processes for Standard-vault sync, supervised by the sync daemon.
 *
 * There is deliberately NO resident rclone and NO remote-control server: no listening socket, no TCP
 * port, no control token — the smallest possible local surface. Each operation is a fresh child whose
 * output and exit the daemon captures. (Standard-vault sync is SERVER-SIDE encrypted; NO zero-knowledge
 * key or key material flows through this module — it imports none of that surface.)
 *
 * Data-safety invariant: this runner REFUSES to pass rclone `--force`, so a corrupted or emptied local
 * folder can never override rclone's own safety aborts (e.g. its >50%-delete guard) to wipe the server
 * copy. No rclone.conf is ever read or written (--config "").
 *
 * Supply-chain: the rclone binary is pinned by expected version + SHA-256 and verified before first
 * use; a mismatch fails closed (rclone is a native executable the daemon runs — a swapped binary is a
 * daemon-privileged RCE).
 */

const { spawn } = require('node:child_process');
const crypto = require('node:crypto');
const fs = require('node:fs');

// Flags the daemon must never hand rclone, enforced by construction (not by caller discipline):
//   --force                             overrides rclone's own data-safety aborts, so a local wipe could
//                                       then propagate a mass deletion to the server.
//   --ignore-errors                     would let a run that hit transfer/listing errors be treated as a
//                                       clean completion — so a partial or mis-listed bisync could delete
//                                       against an incomplete picture. A run with errors must fail, never
//                                       "succeed" quietly.
//   --rc / --rc-addr / --rc-web-gui /   would start a remote-control server (a listening endpoint) — the
//   --rc-no-auth                        one-shot design exists precisely to have NO listener.
const FORBIDDEN_FLAGS = ['--force', '--ignore-errors', '--rc', '--rc-addr', '--rc-web-gui', '--rc-no-auth'];
// Subcommands that stand up a server/listener; never run as the first argument.
const FORBIDDEN_SUBCOMMANDS = ['rcd', 'serve'];

// A flag matches either exactly or in its `--flag=value` form; a subcommand matches the first argument.
function forbiddenIn(args) {
  const list = args || [];
  if (FORBIDDEN_SUBCOMMANDS.includes(String(list[0]))) return String(list[0]);
  for (const a of list) {
    const s = String(a);
    for (const f of FORBIDDEN_FLAGS) { if (s === f || s.startsWith(f + '=')) return s; }
  }
  return null;
}

class RcloneRunner {
  /**
   * @param {object} opts
   * @param {string} opts.rcloneBin        absolute path to the (pinned, bundled) rclone executable
   * @param {string} [opts.expectVersion]  pinned version, e.g. '1.75.0' (asserted at ready())
   * @param {string} [opts.expectSha256]   pinned binary SHA-256 (verified before first use)
   * @param {Function} [opts.spawnFn]      injectable spawn (tests)
   * @param {Function} [opts.readFileFn]   injectable file read for the checksum (tests)
   */
  constructor(opts) {
    this.bin = opts.rcloneBin;
    this.expectVersion = opts.expectVersion || null;
    this.expectSha256 = opts.expectSha256 || null;
    this._spawn = opts.spawnFn || spawn;
    this._readFile = opts.readFileFn || fs.readFileSync;
    this._binaryVerified = false; // the SHA-256 gate passed (or dev: no pin) — required before any spawn
    this._verified = false;       // full readiness: checksum AND version confirmed — required for run()
  }

  // Supply-chain gate: the binary's SHA-256 must match the pin before it is ever executed. Fail-closed.
  // Reads and hashes the file only — it does NOT spawn — so it can gate every spawn that follows.
  verifyBinary() {
    if (!this.expectSha256) { this._binaryVerified = true; return null; } // dev: no pin (production always pins)
    const got = crypto.createHash('sha256').update(this._readFile(this.bin)).digest('hex').toLowerCase();
    if (got !== this.expectSha256.toLowerCase()) throw new Error('rclone binary checksum mismatch: refusing to run');
    this._binaryVerified = true;
    return got;
  }

  // The single spawn chokepoint. NOTHING spawns rclone unless the binary's checksum has been verified
  // (so a tampered binary is never run), and no forbidden flag/subcommand (--force, any rc server) reaches it.
  _launch(args, { timeoutMs = 30000, inactivityMs = null, hardCeilingMs = null, onLine, input, config } = {}) {
    if (!this._binaryVerified) return Promise.reject(new Error('rclone binary not verified; call ready() first'));
    const bad = forbiddenIn(args);
    if (bad) return Promise.reject(new Error(`refusing to run rclone with ${bad}`));
    // `--config` points at the per-run ephemeral config when a path is given (a sync run using the
    // temp-cred remote), else the empty string so no rclone.conf is read or written.
    const full = [...(args || []), '--config', config != null ? config : ''];
    return new Promise((resolve, reject) => {
      let child;
      // `input`, when given, is written to the child's stdin (an in-memory pipe) — used to hand a
      // secret to rclone WITHOUT placing it on argv or in the environment.
      const stdin = input != null ? 'pipe' : 'ignore';
      try { child = this._spawn(this.bin, full, { stdio: [stdin, 'pipe', 'pipe'], windowsHide: true }); }
      catch (e) { return reject(e); }
      if (input != null && child.stdin) { try { child.stdin.end(input); } catch { /* child gone */ } }
      let stdout = '';
      let stderr = '';
      let done = false;
      let idleTimer = null;
      let ceilingTimer = null;
      const clearTimers = () => { if (idleTimer) clearTimeout(idleTimer); if (ceilingTimer) clearTimeout(ceilingTimer); };
      const finish = (fn, arg) => { if (done) return; done = true; clearTimers(); fn(arg); };
      const killWith = (msg) => { try { child.kill(); } catch { /* already gone */ } finish(reject, new Error(msg)); };
      // Two timeout shapes. Utility commands use a FIXED wall-clock timeout (small; fail fast). A long
      // transfer/scan uses an INACTIVITY timeout that resets on ANY output from EITHER stream, so a
      // long-but-progressing run survives while a truly silent/hung one is killed; a generous fixed hard
      // ceiling still bounds a run that emits forever. Output is fed periodic stats (on stderr) by the
      // caller's flags so a quiet-but-working transfer keeps the timer alive.
      const resetIdle = () => {
        if (done) return;
        if (idleTimer) clearTimeout(idleTimer);
        idleTimer = setTimeout(() => killWith(inactivityMs ? 'rclone inactivity timeout' : 'rclone timeout'), inactivityMs || timeoutMs);
        if (idleTimer.unref) idleTimer.unref();
      };
      resetIdle();
      if (inactivityMs) {
        ceilingTimer = setTimeout(() => killWith('rclone hard-ceiling timeout'), hardCeilingMs || inactivityMs * 30);
        if (ceilingTimer.unref) ceilingTimer.unref();
      }
      // stdout feeds onLine (the line relay) AND, for a transfer, resets the idle timer. stderr ONLY
      // accumulates (for the typed-outcome classification) and resets the idle timer — it is NEVER relayed
      // to onLine, because stats/progress lines carry file paths that must not be logged or sent onward.
      if (child.stdout) child.stdout.on('data', (c) => { stdout += c; if (inactivityMs) resetIdle(); if (onLine) String(c).split(/\r?\n/).forEach((l) => { if (l) onLine(l); }); });
      if (child.stderr) child.stderr.on('data', (c) => { stderr += c; if (inactivityMs) resetIdle(); });
      child.on('error', (e) => finish(reject, e));
      child.on('exit', (code) => finish(resolve, { code, stdout, stderr }));
    });
  }

  // A one-shot rclone operation. Public entry: requires FULL readiness (checksum + version confirmed),
  // so no operation runs until ready() has passed — the pinned-binary checksum can never be bypassed.
  run(args, opts) {
    if (!this._verified) return Promise.reject(new Error('rclone not verified; call ready() first'));
    return this._launch(args, opts);
  }

  // Encode a password into rclone's "obscure" config form. The plaintext is fed on STDIN (an in-memory
  // pipe), NEVER on argv, so it is not exposed in the process table. Note: obscure is REVERSIBLE
  // obfuscation, not encryption — this is a config-FORMAT step only; the credential's protection comes
  // from its short-lived scope and the 0600 ephemeral file, never from being "obscured".
  async obscure(plaintext) {
    const { code, stdout } = await this.run(['obscure', '-'], { input: String(plaintext), timeoutMs: 10000 });
    const out = (stdout || '').trim();
    if (code !== 0 || !out) throw new Error('rclone obscure failed');
    return out;
  }

  // The version probe runs during ready() (after the checksum gate, before full readiness), so it uses
  // the chokepoint directly rather than the readiness-gated run().
  async version() {
    const { stdout } = await this._launch(['version'], { timeoutMs: 10000 });
    const m = stdout.match(/rclone\s+v([0-9][0-9.]*)/i);
    return { version: m ? m[1] : null, raw: (stdout.split(/\r?\n/)[0] || '').trim() };
  }

  // One-time readiness before the daemon uses rclone: verify the pinned binary, then the pinned
  // version. Either mismatch fails closed.
  async ready() {
    this.verifyBinary();
    const v = await this.version();
    if (this.expectVersion && v.version !== this.expectVersion) {
      throw new Error(`rclone version ${v.version} does not match the pinned ${this.expectVersion}`);
    }
    this._verified = true;
    return v;
  }
}

module.exports = { RcloneRunner, FORBIDDEN_FLAGS };

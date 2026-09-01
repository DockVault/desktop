'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the main process forks the sync
 * daemon, brokers the database key once over the private channel, the daemon opens the encrypted
 * state DB and reports ready, a health ping round-trips, and the DB exists encrypted at rest.
 * Writes .local/daemon-check.json (no key material).
 *
 *   node_modules/electron/dist/electron.exe test/daemon-check.js
 */

const { app } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');

const RESULT = path.join(__dirname, '..', '.local', 'daemon-check.json');
const out = {};
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 30000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

// Resolve a real rclone binary + its pin so the daemon can verify it (mirrors the bundled-binary config).
function rcloneConfig() {
  try {
    const finder = process.platform === 'win32' ? ['where', ['rclone']] : ['which', ['rclone']];
    let bin = execFileSync(finder[0], finder[1]).toString().split(/\r?\n/).find(Boolean).trim();
    try { bin = fs.realpathSync(bin); } catch { /* not a symlink */ }
    const sha256 = crypto.createHash('sha256').update(fs.readFileSync(bin)).digest('hex');
    const raw = execFileSync(bin, ['version']).toString();
    const version = (raw.match(/rclone\s+v([0-9][0-9.]*)/i) || [])[1] || null;
    return { bin, version, sha256 };
  } catch { return null; }
}

app.whenReady().then(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-daemon-'));
  const { DaemonManager } = require('../src/main/daemon-manager');
  const rc = rcloneConfig();
  const mgr = new DaemonManager(dir, rc);

  const ready = new Promise((resolve) => mgr.on('ready', resolve));
  mgr.start();
  out.ready = await Promise.race([ready, new Promise((r) => setTimeout(() => r({ type: 'timeout' }), 8000))]);
  out.pong = await mgr.ping(3000);
  out.zkLockAck = await mgr.zkLock(3000); // the atomic dual-key purge hook acks over the private channel

  // The daemon supervises rclone (one-shot child) and round-trips its verified version over the channel.
  out.rcloneConfigured = !!(rc && rc.bin);
  out.syncStatus = await mgr.syncStatus(12000);

  // Hand the daemon a (fake) per-run SFTP cred over the PRIVATE channel; it obscures the password JIT
  // and prepares the config in memory, acking readiness only (never echoing the cred/config).
  out.sftpCredAck = rc
    ? await mgr.sendSftpCred({ host: 'h.invalid', port: 2222, user: 'tc_test', password: 'fake-temp-pass', hostKeys: 'ssh-ed25519 AAAATESTKEY' }, 12000)
    : { ok: true, error: null };
  out.credAckLeaksNothing = !JSON.stringify(out.sftpCredAck || {}).includes('fake-temp-pass');

  const dbFile = path.join(dir, 'state.db');
  out.dbExists = fs.existsSync(dbFile);
  if (out.dbExists) {
    const raw = fs.readFileSync(dbFile);
    out.dbEncrypted = !raw.subarray(0, 16).toString('latin1').startsWith('SQLite format 3');
  }
  const dbkExists = fs.existsSync(path.join(dir, 'state-dbk.bin'));

  mgr.stop();
  await new Promise((r) => setTimeout(r, 400));

  // If rclone is available on this machine, the daemon must verify it and report the version; if it is
  // not installed, sync being unconfigured is acceptable (not a failure of the daemon itself).
  const syncOk = out.rcloneConfigured ? !!(out.syncStatus && out.syncStatus.ok && out.syncStatus.version) : true;
  const credOk = out.rcloneConfigured ? !!(out.sftpCredAck && out.sftpCredAck.ok && out.credAckLeaksNothing) : true;

  out.ok = !!(out.ready && out.ready.type === 'ready' && out.ready.encrypted === true
    && out.pong === true && out.zkLockAck === true && syncOk && credOk && out.dbExists && out.dbEncrypted && dbkExists);
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch {}
  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

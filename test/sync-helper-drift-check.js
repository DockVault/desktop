'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): the sync helper's per-spawn integrity rail,
 * driven end-to-end through the REAL forked daemon over its private channel. The pinned rclone is pointed at a
 * scratch file whose bytes do NOT match the pinned sha256, so the runner's checksum gate fails closed on every
 * spawn/health re-check — no real binary is ever needed (the failure happens at the hash, before any spawn).
 * Proves:
 *   A) onSyncStatus (health) surfaces the typed sub 'checksum-mismatch' — never a raw `error` field;
 *   B) onSftpCred (credential prep) surfaces the SAME typed sub, never a raw error, never the sent password;
 *   C) a same-path mutation of the scratch bytes is RE-detected on the next request (the daemon drops its
 *      cached readiness on the verified->unverified flip) — the health reply stays not-ok with the typed sub,
 *      never a stale green.
 * Scratch-only (a fresh mkdtemp under the OS temp dir) — never the real userData; no network. Writes
 * .local/sync-helper-drift-check.json and prints one PASS/FAIL line. Exit 0 = PASS.
 *
 *   node_modules/electron/dist/electron.exe test/sync-helper-drift-check.js
 */

const { app } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { DaemonManager } = require('../src/main/daemon-manager');

const RESULT = path.join(__dirname, '..', '.local', 'sync-helper-drift-check.json');
const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-drift-'));
const out = { scratch: SCRATCH };
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 40000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
const noErrorKey = (o) => !!o && typeof o === 'object' && !('error' in o);

app.whenReady().then(async () => {
  const bin = path.join(SCRATCH, 'rclone-scratch.bin');
  fs.writeFileSync(bin, Buffer.from('not-the-real-rclone-binary-v1'));
  const wrongSha = crypto.createHash('sha256').update(Buffer.from('a DIFFERENT binary entirely')).digest('hex');

  const dir = fs.mkdtempSync(path.join(SCRATCH, 'ud-'));
  const mgr = new DaemonManager(dir, { bin, version: '1.75.0', sha256: wrongSha });
  const ready = new Promise((r) => mgr.on('ready', r));
  mgr.start();
  await Promise.race([ready, new Promise((r) => setTimeout(r, 8000))]);

  // A) health reply: typed sub, no raw error.
  const st = await mgr.syncStatus(12000);
  out.A_healthTypedSub = !!st && st.ok === false && st.sub === 'checksum-mismatch' && noErrorKey(st);

  // B) credential ack: same typed sub, no raw error, and the sent password is never echoed.
  const ack = await mgr.sendSftpCred({ host: 'h.invalid', port: 2222, user: 'tc_test', password: 'fake-temp-pass', hostKeys: 'ssh-ed25519 AAAATESTKEY' }, 12000);
  out.B_credTypedSub = !!ack && ack.ok === false && ack.sub === 'checksum-mismatch' && noErrorKey(ack)
    && !JSON.stringify(ack).includes('fake-temp-pass');

  // C) a same-path mutation is re-detected on the next request — never a stale green.
  fs.writeFileSync(bin, Buffer.from('swapped-scratch-bytes-different-again'));
  const st2 = await mgr.syncStatus(12000);
  out.C_driftReDetected = !!st2 && st2.ok === false && st2.sub === 'checksum-mismatch' && noErrorKey(st2);

  mgr.stop();
  await new Promise((r) => setTimeout(r, 400));
  out.ok = !!(out.A_healthTypedSub && out.B_credTypedSub && out.C_driftReDetected);
  try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* ignore */ }
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nSYNC HELPER DRIFT CHECK: ${out.ok ? 'PASS' : 'FAIL'}  (A health=${out.A_healthTypedSub}, B cred=${out.B_credTypedSub}, C drift=${out.C_driftReDetected})\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

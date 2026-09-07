'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the BUNDLED sync helper reaches full readiness
 * through the REAL forked daemon, resolved exactly the way the app resolves it (rclone-bundle.js reading the
 * committed manifest, the binary scripts/fetch-rclone.js placed under build/rclone/<target>/). Proves:
 *   A) the resolved config carries the manifest's version + hash and points into build/rclone/<target>/;
 *   B) the daemon's health reply is ok with the pinned version — checksum AND version confirmed on the real binary;
 *   C) the same binary with one byte appended is refused with the typed sub 'checksum-mismatch' — the pin holds.
 * Scratch-only user data (a fresh mkdtemp under the OS temp dir) — never the real userData; the binary is copied to
 * scratch for C so the fetched one is never altered; no network. Writes .local/bundled-helper-check.json and
 * prints one PASS/FAIL line. Exit 0 = PASS. Run `node scripts/fetch-rclone.js` first.
 *
 *   node_modules/electron/dist/electron.exe test/bundled-helper-check.js
 */
const { app } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { DaemonManager } = require('../src/main/daemon-manager');
const { resolveBundledRclone, DEV_ROOT } = require('../src/main/rclone-bundle');
const RESULT = path.join(__dirname, '..', '.local', 'bundled-helper-check.json');
const SCRATCH = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-bundled-'));
const out = { scratch: SCRATCH };
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 60000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }

async function health(cfg) {
  const dir = fs.mkdtempSync(path.join(SCRATCH, 'ud-'));
  const mgr = new DaemonManager(dir, cfg);
  const ready = new Promise((r) => mgr.on('ready', r));
  mgr.start();
  await Promise.race([ready, new Promise((r) => setTimeout(r, 8000))]);
  const st = await mgr.syncStatus(20000);
  mgr.stop();
  await new Promise((r) => setTimeout(r, 400));
  return st;
}

app.whenReady().then(async () => {
  // Resolved as the app resolves it in a development checkout, with the environment override removed so the
  // check always exercises the bundled path.
  const cfg = resolveBundledRclone({ isPackaged: false, platform: process.platform, arch: process.arch, env: {} });
  out.A_resolved = !!cfg && typeof cfg.version === 'string' && /^[0-9a-f]{64}$/.test(cfg.sha256 || '')
    && path.resolve(cfg.bin).startsWith(path.resolve(DEV_ROOT) + path.sep) && fs.existsSync(cfg.bin);
  out.version = cfg && cfg.version;

  const st = out.A_resolved ? await health(cfg) : null;
  out.B_healthOk = !!st && st.ok === true && st.version === cfg.version && !('error' in st);
  out.B_reply = st && { ok: st.ok, version: st.version, sub: st.sub, reason: st.reason };

  // A tampered copy: same version string inside, one extra byte — the hash check must refuse it.
  let st2 = null;
  if (out.A_resolved) {
    const tampered = path.join(SCRATCH, path.basename(cfg.bin));
    fs.copyFileSync(cfg.bin, tampered);
    fs.appendFileSync(tampered, Buffer.from([0]));
    st2 = await health({ ...cfg, bin: tampered });
  }
  out.C_tamperRefused = !!st2 && st2.ok === false && st2.sub === 'checksum-mismatch' && !('error' in st2);

  out.ok = !!(out.A_resolved && out.B_healthOk && out.C_tamperRefused);
  try { fs.rmSync(SCRATCH, { recursive: true, force: true }); } catch { /* ignore */ }
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nBUNDLED HELPER CHECK: ${out.ok ? 'PASS' : 'FAIL'}  (A resolved=${out.A_resolved}, B health=${out.B_healthOk} version=${out.version}, C tamper=${out.C_tamperRefused})\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

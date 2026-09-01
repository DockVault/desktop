'use strict';

/*
 * Functional check (run under node, not part of `npm test`): drives the REAL rclone as one-shot
 * children and proves the Standard-vault sync control plane end-to-end —
 *   - the pinned SHA-256 verifies (and a wrong pin fails closed),
 *   - a `rclone version` round-trips and matches the pinned version,
 *   - no rclone.conf is written (--config ""),
 *   - a `--force` invocation is refused (data-safety invariant),
 *   - no listener / port is ever opened (inherent: one-shot, no rc server).
 * Writes .local/rclone-runner-check.json.
 *
 *   node test/rclone-runner-check.js
 */

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { execFileSync } = require('node:child_process');
const { RcloneRunner } = require('../src/daemon/rclone-runner');

const RESULT = path.join(__dirname, '..', '.local', 'rclone-runner-check.json');
const out = {};

function resolveRclone() {
  // Resolve a real rclone executable path (follow a symlink shim, if any, so the checksum can read it).
  const finder = process.platform === 'win32' ? ['where', ['rclone']] : ['which', ['rclone']];
  const first = execFileSync(finder[0], finder[1]).toString().split(/\r?\n/).find(Boolean).trim();
  try { return fs.realpathSync(first); } catch { return first; }
}

(async () => {
  const bin = resolveRclone();
  out.bin = bin;
  const sha = crypto.createHash('sha256').update(fs.readFileSync(bin)).digest('hex');
  out.sha256 = sha;

  const cwd0 = process.cwd();
  const workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-rr-'));
  try {
    // 1. Pinned binary + version verify (real).
    const r = new RcloneRunner({ rcloneBin: bin, expectSha256: sha, expectVersion: null });
    const v = await r.ready();
    out.version = v.version;
    out.readyOk = !!v.version;

    // 2. Pinned-version match + mismatch fails closed.
    const rPinOk = new RcloneRunner({ rcloneBin: bin, expectSha256: sha, expectVersion: v.version });
    await rPinOk.ready();
    out.versionPinMatch = true;
    const rPinBad = new RcloneRunner({ rcloneBin: bin, expectSha256: sha, expectVersion: '0.0.0' });
    let vRej = false; try { await rPinBad.ready(); } catch { vRej = true; }
    out.versionPinFailsClosed = vRej;

    // 3. Wrong checksum fails closed.
    const rShaBad = new RcloneRunner({ rcloneBin: bin, expectSha256: 'deadbeef' });
    let sRej = false; try { rShaBad.verifyBinary(); } catch { sRej = true; }
    out.checksumFailsClosed = sRej;

    // 4. --force is refused.
    let fRej = false; try { await r.run(['version', '--force']); } catch { fRej = true; }
    out.forceRefused = fRej;

    // 5. --config "" writes no rclone.conf in the run's working dir.
    process.chdir(workdir);
    await r.run(['version']);
    out.noConfInWorkdir = !fs.existsSync(path.join(workdir, 'rclone.conf'));
  } catch (e) {
    out.fatal = String((e && e.stack) || e);
  } finally {
    process.chdir(cwd0);
    try { fs.rmSync(workdir, { recursive: true, force: true }); } catch { /* ignore */ }
  }

  out.ok = !!(out.readyOk && out.versionPinMatch && out.versionPinFailsClosed && out.checksumFailsClosed && out.forceRefused && out.noConfInWorkdir);
  fs.mkdirSync(path.dirname(RESULT), { recursive: true });
  fs.writeFileSync(RESULT, JSON.stringify(out, null, 2));
  process.exit(out.ok ? 0 : 1);
})();

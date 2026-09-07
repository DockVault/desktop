'use strict';

/*
 * Where the sync helper (rclone) lives, and what it is pinned to.
 *
 * The installer bundles the helper beside the app archive (resources/rclone/<binary>). Its pinned
 * version and SHA-256 come from build/rclone.json, which travels INSIDE the integrity-checked app
 * archive — never from a file next to the binary, so nothing beside the helper can vouch for it. The
 * running app hands that hash to the helper runner, which re-checks the binary before every launch.
 *
 * A development checkout uses the same manifest with the binary that scripts/fetch-rclone.js placed
 * under build/rclone/<target>/, and may point DOCKVAULT_RCLONE (+ _VERSION, _SHA256) at another
 * binary. A packaged app ignores those variables and never looks anywhere else: there is no PATH
 * lookup and no fallback.
 *
 * Returns { bin, version, sha256 }, or null when the manifest has no usable entry for this platform
 * (the daemon then simply offers no standard sync — never fatal). A binary that is missing or altered
 * is NOT null here: the runner reports it as not ready, so it surfaces as a damaged installation.
 */

const path = require('node:path');

const MANIFEST = path.join(__dirname, '..', '..', 'build', 'rclone.json');
const DEV_ROOT = path.join(__dirname, '..', '..', 'build', 'rclone');

function readManifest(file) {
  try { return require(file); } catch { return null; }
}

function resolveBundledRclone({ isPackaged, resourcesPath, platform, arch, env = {}, manifestPath = MANIFEST, devRoot = DEV_ROOT } = {}) {
  if (!isPackaged && env.DOCKVAULT_RCLONE) {
    return { bin: env.DOCKVAULT_RCLONE, version: env.DOCKVAULT_RCLONE_VERSION || null, sha256: env.DOCKVAULT_RCLONE_SHA256 || null };
  }
  const manifest = readManifest(manifestPath);
  const target = `${platform}-${arch}`;
  const t = manifest && manifest.targets && manifest.targets[target];
  if (!t || typeof t.binary !== 'string' || typeof t.binarySha256 !== 'string' || typeof manifest.version !== 'string') return null;
  if (t.binary.includes('/') || t.binary.includes('\\') || t.binary.includes('..')) return null; // a bare file name, nothing else
  const bin = isPackaged ? path.join(resourcesPath, 'rclone', t.binary) : path.join(devRoot, target, t.binary);
  return { bin, version: manifest.version, sha256: t.binarySha256 };
}

module.exports = { resolveBundledRclone, MANIFEST, DEV_ROOT };

'use strict';

/*
 * electron-builder hook, run before the app is packaged: refuses to continue unless the pinned
 * rclone binary for the target being built is present under build/rclone/<target>/ and matches
 * build/rclone.json. Without this a forgotten download would quietly produce an installer with no
 * sync helper in it, which the app could only report as a damaged installation.
 */

const { Arch } = require('electron-builder');
const { loadManifest, installedBinaryOk } = require('./fetch-rclone');

async function checkBundledRclone(context) {
  const target = `${context.electronPlatformName}-${Arch[context.arch]}`;
  const manifest = loadManifest();
  if (!manifest.targets[target]) throw new Error(`no rclone is pinned for ${target} in build/rclone.json`);
  if (!installedBinaryOk(target, manifest)) {
    throw new Error(`the bundled rclone for ${target} is missing or does not match build/rclone.json; run: node scripts/fetch-rclone.js ${target}`);
  }
}

module.exports = checkBundledRclone;
module.exports.default = checkBundledRclone;

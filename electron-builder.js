'use strict';

/*
 * electron-builder configuration for the DockVault desktop app.
 *
 * One application, one process tree: the tray-resident Electron app carries the sync helper as a
 * utility child. There is no separate daemon to package. Installers are produced per platform from
 * this file; `npm run dist` builds for the host platform, the dist:* scripts pick a target.
 *
 * The version and the exact electron-builder release are pinned in package.json / package-lock.json
 * so a clean clone reproduces the same artifact. This is a JS file rather than YAML because the
 * per-platform sections REPLACE (not extend) the top-level file list, and the one shared allowlist
 * below is easier to keep honest than three copies of it.
 */

const SQLITE = 'node_modules/better-sqlite3-multiple-ciphers';

// What ships inside the app archive. Production dependencies are always included; the patterns
// below add the app sources and the vendored web UI, and drop everything that only matters for
// development: tests, the icon generator, the native module's C++ sources, and the musl prebuilds
// (the installers target glibc Linux). `forPlatform` then trims the remaining prebuilt binaries to
// the one the target actually loads.
const files = [
  'src/**/*',
  'vendor/vault/static/**/*',
  'build/icon.png',
  'build/rclone.json',
  'package.json',
  'LICENSE',
  '!**/*.test.js',
  `!${SQLITE}/{deps,src,build}/**`,
  `!${SQLITE}/binding.gyp`,
  `!${SQLITE}/prebuilds/linuxmusl-*.node`,
  // Only needed to compile the native module, which never happens here.
  '!node_modules/node-addon-api/**',
];
const PREBUILDS = ['darwin-arm64', 'darwin-x64', 'linux-arm64', 'linux-x64', 'win32-arm64', 'win32-x64'];
const forPlatform = (...keep) => files.concat(PREBUILDS.filter((p) => !keep.includes(p)).map((p) => `!${SQLITE}/prebuilds/${p}.node`));

// The sync helper (rclone) ships INSIDE the installer, next to the app archive as resources/rclone/:
// the binary that scripts/fetch-rclone.js downloaded and verified for this exact target (on Windows
// electron-builder signs executables copied into extra resources with the app's certificate; on
// macOS the helper is listed under mac.binaries for the same reason). The
// manifest with its pinned version and SHA-256 (build/rclone.json, in `files` above) travels inside
// the integrity-checked app archive, not beside the binary, and the app re-checks the binary against
// it before every launch of the helper. The pre-pack hook refuses to build when the verified binary
// is not there, so an installer can never quietly ship without its helper. `target` may use the
// ${arch} macro.
const rcloneResources = (target, binary) => [
  { from: `build/rclone/${target}/`, to: 'rclone', filter: [binary] },
];

module.exports = {
  appId: 'io.dockvault.desktop',
  productName: 'DockVault',
  copyright: 'AGPL-3.0-only, see LICENSE',
  directories: { output: 'dist', buildResources: 'build' },
  files,
  beforePack: 'scripts/check-bundled-rclone.js',

  // The state database module ships as an N-API prebuilt for every target, so nothing is compiled
  // or rebuilt at package time (no node-gyp, no toolchain). Native code cannot be loaded from inside
  // the archive, so the prebuilt binary is unpacked next to it. Note that the archive integrity
  // check (fuse below) covers app.asar only; unpacked files and the bundled helper are read straight
  // from disk and are protected by the platform code signature (and, for the helper, by the app's
  // own hash check), not by the archive hash.
  asar: true,
  asarUnpack: [`${SQLITE}/prebuilds/**`],
  npmRebuild: false,
  nodeGypRebuild: false,
  buildDependenciesFromSource: false,

  // Runtime switches baked into the Electron binary. The sync helper runs as a utility process, so
  // turning the run-as-node mode off costs nothing and removes the "act as plain Node" escape hatch;
  // the app serves its UI over its own scheme, so the file: protocol gets no extra privileges.
  electronFuses: {
    runAsNode: false,
    enableCookieEncryption: true,
    enableNodeOptionsEnvironmentVariable: false,
    enableNodeCliInspectArguments: false,
    enableEmbeddedAsarIntegrityValidation: true,
    onlyLoadAppFromAsar: true,
    grantFileProtocolExtraPrivileges: false,
    resetAdHocDarwinSignature: true,
  },

  // No update feed in this release: installers only.
  publish: null,

  // macOS: one .dmg per architecture. Hardened runtime with the smallest entitlement set Electron
  // needs (JIT for V8). Signing and notarization credentials come only from the environment of the
  // build (CI secrets); with none present the build is produced unsigned for local testing. The
  // bundled helper is listed explicitly so it is signed (hardened runtime, timestamped) with the app;
  // notarization rejects a bundle carrying an unsigned executable.
  mac: {
    category: 'public.app-category.utilities',
    target: [{ target: 'dmg', arch: ['arm64', 'x64'] }],
    hardenedRuntime: true,
    gatekeeperAssess: false,
    entitlements: 'build/entitlements.mac.plist',
    entitlementsInherit: 'build/entitlements.mac.plist',
    notarize: true,
    // Relative entries resolve against the .app bundle root, hence the Contents/ prefix.
    binaries: ['Contents/Resources/rclone/rclone'],
    artifactName: '${productName}-${version}-mac-${arch}.${ext}',
    files: forPlatform('darwin-arm64', 'darwin-x64'),
    extraResources: rcloneResources('darwin-${arch}', 'rclone'),
  },
  dmg: { sign: false },

  // Windows: a one-click NSIS installer that installs for the current user only and never asks for
  // elevation. One-click deliberately: the assisted installer would show an "anyone who uses this
  // computer / only me" page whose first choice dead-ends without administrator rights, and a
  // tray app has no reason to ask where it lives. Uninstalling keeps the app's data (the encrypted
  // session and sync state) and removes the start-at-login entry; see build/installer.nsh.
  win: {
    target: [{ target: 'nsis', arch: ['x64'] }],
    artifactName: '${productName}-${version}-win-${arch}.${ext}',
    files: forPlatform('win32-x64'),
    extraResources: rcloneResources('win32-x64', 'rclone.exe'),
  },
  nsis: {
    oneClick: true,
    perMachine: false,
    allowElevation: false,
    packElevateHelper: false,
    allowToChangeInstallationDirectory: false,
    createDesktopShortcut: true,
    createStartMenuShortcut: true,
    shortcutName: 'DockVault',
    uninstallDisplayName: 'DockVault',
    runAfterFinish: true,
    deleteAppDataOnUninstall: false,
    include: 'build/installer.nsh',
  },

  // Linux: a portable AppImage and a .deb. The tray needs a status-notifier host on some desktops,
  // hence the appindicator recommendation (a recommendation, not a hard dependency, so the package
  // installs on desktops that ship a tray natively).
  linux: {
    category: 'Utility',
    executableName: 'dockvault',
    // Keep the .desktop file name equal to the app id Electron reports as WM_CLASS (desktopName in
    // package.json), so desktops associate the running window with its launcher entry.
    syncDesktopName: true,
    synopsis: 'Desktop client for DockVault, the self-hosted encrypted file vault',
    target: [{ target: 'AppImage', arch: ['x64'] }, { target: 'deb', arch: ['x64'] }],
    artifactName: '${productName}-${version}-linux-${arch}.${ext}',
    files: forPlatform('linux-x64'),
    extraResources: rcloneResources('linux-x64', 'rclone'),
  },
  deb: { recommends: ['libayatana-appindicator3-1 | libappindicator3-1'] },
};

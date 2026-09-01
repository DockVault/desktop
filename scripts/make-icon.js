'use strict';

/*
 * Generates the app icon (build/icon.png, 512x512) from the reused brand mark. Run under Electron so
 * nativeImage does the image work with no extra dependency:
 *
 *   node_modules/electron/dist/electron.exe scripts/make-icon.js
 *
 * Source is the square-ish mark (logo-small.png) from the pinned vault assets; it is cropped to a
 * centred square first so the icon is not distorted, then resized to 512x512 (electron-builder's
 * preferred source size, from which the packaged .ico / .icns are generated at build time). The output
 * is committed so the running and packaged app both show the DockVault icon rather than the default.
 */

const { app, nativeImage } = require('electron');
const fs = require('node:fs');
const path = require('node:path');

const SRC = path.resolve(__dirname, '..', 'vendor', 'vault', 'static', 'assets', 'logo-small.png');
const OUT = path.resolve(__dirname, '..', 'build', 'icon.png');
const SIZE = 512;

app.disableHardwareAcceleration();
app.whenReady().then(() => {
  const img = nativeImage.createFromPath(SRC);
  if (img.isEmpty()) { console.error('source mark not found or empty:', SRC); app.exit(1); return; }
  const { width, height } = img.getSize();
  const side = Math.min(width, height);
  const square = img.crop({ x: Math.floor((width - side) / 2), y: Math.floor((height - side) / 2), width: side, height: side });
  const icon = square.resize({ width: SIZE, height: SIZE, quality: 'best' });
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, icon.toPNG());
  const out = nativeImage.createFromPath(OUT).getSize();
  console.log('wrote', OUT, JSON.stringify(out));
  app.quit();
}).catch((e) => { console.error(String((e && e.stack) || e)); app.exit(2); });

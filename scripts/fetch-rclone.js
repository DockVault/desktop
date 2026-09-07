'use strict';

/*
 * Fetches the pinned rclone release for one or more targets and places the binary where packaging
 * expects it (build/rclone/<target>/), so the installer carries its own sync helper and a person
 * never has to install rclone themselves.
 *
 * Every byte is checked against build/rclone.json before it is used: the downloaded archive must
 * match its pinned SHA-256, and the binary extracted from it must match its own pinned SHA-256. A
 * mismatch aborts without writing anything. The binary hash is the same one the running app checks
 * before every helper launch, so the manifest is the single source of truth for the helper.
 *
 *   node scripts/fetch-rclone.js                    # the target for this machine
 *   node scripts/fetch-rclone.js darwin-arm64 darwin-x64
 *
 * Targets are <platform>-<arch> in Node's naming: win32-x64, darwin-arm64, darwin-x64, linux-x64.
 * No dependencies: the release archives are plain zip files, read by the small reader below.
 */

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const zlib = require('node:zlib');
const https = require('node:https');

const MANIFEST_PATH = path.resolve(__dirname, '..', 'build', 'rclone.json');
const OUT_ROOT = path.resolve(__dirname, '..', 'build', 'rclone');
const MAX_ARCHIVE_BYTES = 256 * 1024 * 1024;
const HEX64 = /^[0-9a-f]{64}$/;

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }

function hostTarget() { return `${process.platform}-${process.arch}`; }

// Reads and validates the manifest. A malformed manifest is a build error, never a silent default.
function loadManifest(file = MANIFEST_PATH) {
  const m = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (typeof m.version !== 'string' || !/^[0-9]+[.][0-9]+[.][0-9]+$/.test(m.version)) throw new Error('rclone manifest: version must be x.y.z');
  if (typeof m.baseUrl !== 'string' || !m.baseUrl.startsWith('https://')) throw new Error('rclone manifest: baseUrl must be https');
  if (!m.targets || typeof m.targets !== 'object') throw new Error('rclone manifest: targets missing');
  for (const [target, t] of Object.entries(m.targets)) {
    if (!/^(win32|darwin|linux)-(x64|arm64)$/.test(target)) throw new Error(`rclone manifest: unknown target ${target}`);
    if (typeof t.archive !== 'string' || !t.archive.endsWith('.zip') || !t.archive.includes(m.version)) throw new Error(`rclone manifest: ${target} archive must be a zip of version ${m.version}`);
    if (t.binary !== (target.startsWith('win32') ? 'rclone.exe' : 'rclone')) throw new Error(`rclone manifest: ${target} binary name`);
    if (!HEX64.test(t.archiveSha256) || !HEX64.test(t.binarySha256)) throw new Error(`rclone manifest: ${target} hashes must be 64 lowercase hex characters`);
  }
  return m;
}

// Only https is ever fetched, including after a redirect: a plain-http hop would let anyone on the
// path substitute the archive (the hash check would still catch it, but there is no reason to try).
function assertHttps(url) {
  const u = new URL(url);
  if (u.protocol !== 'https:') throw new Error(`refusing to fetch ${url}: only https is allowed`);
  return u.href;
}

function download(url, redirects = 0) {
  return new Promise((resolve, reject) => {
    let target;
    try { target = assertHttps(url); } catch (e) { return reject(e); }
    const req = https.get(target, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location) {
        res.resume();
        if (redirects >= 5) return reject(new Error(`too many redirects for ${url}`));
        return resolve(download(new URL(res.headers.location, target).href, redirects + 1));
      }
      if (res.statusCode !== 200) { res.resume(); return reject(new Error(`${url}: HTTP ${res.statusCode}`)); }
      const chunks = [];
      let size = 0;
      res.on('data', (c) => {
        size += c.length;
        if (size > MAX_ARCHIVE_BYTES) { req.destroy(new Error(`${url}: larger than ${MAX_ARCHIVE_BYTES} bytes`)); return; }
        chunks.push(c);
      });
      res.on('end', () => resolve(Buffer.concat(chunks)));
      res.on('error', reject);
    });
    // A stalled connection fails the build rather than hanging it.
    req.setTimeout(60000, () => req.destroy(new Error(`${url}: no data for 60 seconds`)));
    req.on('error', reject);
  });
}

// Minimal zip reader: enough for a release archive (stored or deflated entries; no zip64, no encryption).
const SIG_EOCD = 0x06054b50;
const SIG_CENTRAL = 0x02014b50;
const SIG_LOCAL = 0x04034b50;

function zipEntries(buf) {
  let eocd = -1;
  for (let i = buf.length - 22; i >= Math.max(0, buf.length - 22 - 65535); i--) {
    if (buf.readUInt32LE(i) === SIG_EOCD) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('zip: end of central directory not found');
  const count = buf.readUInt16LE(eocd + 10);
  const cdSize = buf.readUInt32LE(eocd + 12);
  const cdOffset = buf.readUInt32LE(eocd + 16);
  if (count === 0xffff || cdSize === 0xffffffff || cdOffset === 0xffffffff) throw new Error('zip: zip64 archives are not supported');
  const entries = [];
  let p = cdOffset;
  for (let n = 0; n < count; n++) {
    if (p + 46 > buf.length || buf.readUInt32LE(p) !== SIG_CENTRAL) throw new Error('zip: bad central directory entry');
    const method = buf.readUInt16LE(p + 10);
    const compressedSize = buf.readUInt32LE(p + 20);
    const size = buf.readUInt32LE(p + 24);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    entries.push({ name, method, compressedSize, size, localOffset });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return entries;
}

function zipRead(buf, entry) {
  const p = entry.localOffset;
  if (p + 30 > buf.length || buf.readUInt32LE(p) !== SIG_LOCAL) throw new Error('zip: bad local header');
  const nameLen = buf.readUInt16LE(p + 26);
  const extraLen = buf.readUInt16LE(p + 28);
  const start = p + 30 + nameLen + extraLen;
  if (start + entry.compressedSize > buf.length) throw new Error(`zip: ${entry.name} runs past the end of the archive`);
  const data = buf.subarray(start, start + entry.compressedSize);
  let out;
  if (entry.method === 0) out = data;
  else if (entry.method === 8) out = zlib.inflateRawSync(data);
  else throw new Error(`zip: unsupported compression method ${entry.method}`);
  if (out.length !== entry.size) throw new Error(`zip: ${entry.name} size mismatch`);
  return Buffer.from(out);
}

// The one file named `binary` anywhere in the archive; none or more than one is refused.
function extractBinary(zipBuf, binary) {
  const matches = zipEntries(zipBuf).filter((e) => !e.name.endsWith('/') && e.name.split('/').pop() === binary);
  if (matches.length !== 1) throw new Error(`zip: expected exactly one ${binary}, found ${matches.length}`);
  return zipRead(zipBuf, matches[0]);
}

function binaryPath(target, manifest, outRoot = OUT_ROOT) {
  return path.join(outRoot, target, manifest.targets[target].binary);
}

// True only when the binary for `target` is on disk AND matches its pinned hash.
function installedBinaryOk(target, manifest, outRoot = OUT_ROOT) {
  const t = manifest.targets[target];
  if (!t) return false;
  try { return sha256(fs.readFileSync(binaryPath(target, manifest, outRoot))) === t.binarySha256; } catch { return false; }
}

async function fetchTarget(target, manifest, { log = console.log, fetch = download, outRoot = OUT_ROOT } = {}) {
  const t = manifest.targets[target];
  if (!t) throw new Error(`no rclone ${manifest.version} is pinned for ${target} in build/rclone.json`);
  const outFile = binaryPath(target, manifest, outRoot);
  if (installedBinaryOk(target, manifest, outRoot)) { log(`rclone ${manifest.version} for ${target}: already present and verified`); return outFile; }
  const url = `${manifest.baseUrl}/v${manifest.version}/${t.archive}`;
  log(`rclone ${manifest.version} for ${target}: downloading ${url}`);
  const archive = await fetch(url);
  const archiveHash = sha256(archive);
  if (archiveHash !== t.archiveSha256) throw new Error(`${t.archive}: SHA-256 ${archiveHash} does not match the pinned ${t.archiveSha256}; nothing written`);
  const bin = extractBinary(archive, t.binary);
  const binHash = sha256(bin);
  if (binHash !== t.binarySha256) throw new Error(`${t.binary} from ${t.archive}: SHA-256 ${binHash} does not match the pinned ${t.binarySha256}; nothing written`);
  fs.mkdirSync(path.dirname(outFile), { recursive: true });
  const partial = `${outFile}.part`;
  fs.writeFileSync(partial, bin, { mode: 0o755 });
  fs.renameSync(partial, outFile);
  log(`rclone ${manifest.version} for ${target}: verified, written to ${path.relative(process.cwd(), outFile)}`);
  return outFile;
}

async function main(argv) {
  const manifest = loadManifest();
  const targets = argv.length ? argv : [hostTarget()];
  for (const target of targets) await fetchTarget(target, manifest);
}

module.exports = { MANIFEST_PATH, OUT_ROOT, sha256, hostTarget, loadManifest, assertHttps, zipEntries, zipRead, extractBinary, binaryPath, installedBinaryOk, fetchTarget };

if (require.main === module) {
  main(process.argv.slice(2)).catch((e) => { console.error(String((e && e.message) || e)); process.exit(1); });
}

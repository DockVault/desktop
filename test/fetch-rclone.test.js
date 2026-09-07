'use strict';

// The bundled-helper fetcher: the manifest pins are well-formed, the zip reader extracts exactly the
// pinned binary, and a hash mismatch anywhere refuses to write. No network is touched here.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const zlib = require('node:zlib');

const fetcher = require('../scripts/fetch-rclone');

// A tiny zip writer for fixtures: stored or deflated entries, laid out the way a release archive is.
function makeZip(files) {
  const locals = [];
  const centrals = [];
  let offset = 0;
  for (const f of files) {
    const data = f.deflate ? zlib.deflateRawSync(f.data) : f.data;
    const method = f.deflate ? 8 : 0;
    const name = Buffer.from(f.name);
    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(data.length, 18);
    local.writeUInt32LE(f.data.length, 22);
    local.writeUInt16LE(name.length, 26);
    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(data.length, 20);
    central.writeUInt32LE(f.data.length, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    locals.push(local, name, data);
    centrals.push(central, name);
    offset += local.length + name.length + data.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(files.length, 8);
  eocd.writeUInt16LE(files.length, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

const BIN = Buffer.from('#!/bin/sh\necho pretend rclone\n');

test('the committed manifest is well-formed and pins every installer target', () => {
  const m = fetcher.loadManifest();
  assert.deepEqual(Object.keys(m.targets).sort(), ['darwin-arm64', 'darwin-x64', 'linux-x64', 'win32-x64']);
  for (const t of Object.values(m.targets)) {
    assert.notEqual(t.archiveSha256, t.binarySha256, 'archive and binary are different bytes, so different hashes');
  }
});

test('a manifest with a malformed hash or a wrong binary name is refused', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'rclone-manifest-'));
  const good = fetcher.loadManifest();
  const write = (mutate) => {
    const m = JSON.parse(JSON.stringify(good));
    mutate(m);
    const file = path.join(dir, 'rclone.json');
    fs.writeFileSync(file, JSON.stringify(m));
    return file;
  };
  assert.throws(() => fetcher.loadManifest(write((m) => { m.targets['linux-x64'].binarySha256 = 'abc'; })), /64 lowercase hex/);
  assert.throws(() => fetcher.loadManifest(write((m) => { m.targets['linux-x64'].binary = 'rclone.exe'; })), /binary name/);
  assert.throws(() => fetcher.loadManifest(write((m) => { m.baseUrl = 'http://downloads.rclone.org'; })), /https/);
  assert.throws(() => fetcher.loadManifest(write((m) => { m.targets['linux-x64'].archive = 'rclone-v9.9.9-linux-amd64.zip'; })), /version/);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the zip reader extracts the one pinned binary, stored or deflated, from inside its folder', () => {
  const stored = makeZip([
    { name: 'rclone-v1.0.0-linux-amd64/', data: Buffer.alloc(0) },
    { name: 'rclone-v1.0.0-linux-amd64/README.txt', data: Buffer.from('docs'), deflate: true },
    { name: 'rclone-v1.0.0-linux-amd64/rclone', data: BIN },
  ]);
  assert.deepEqual(fetcher.extractBinary(stored, 'rclone'), BIN);
  const deflated = makeZip([{ name: 'rclone-v1.0.0-windows-amd64/rclone.exe', data: BIN, deflate: true }]);
  assert.deepEqual(fetcher.extractBinary(deflated, 'rclone.exe'), BIN);
});

test('the zip reader refuses an archive with no binary, or with two of them', () => {
  const none = makeZip([{ name: 'x/README.txt', data: Buffer.from('docs') }]);
  assert.throws(() => fetcher.extractBinary(none, 'rclone'), /expected exactly one rclone, found 0/);
  const two = makeZip([{ name: 'a/rclone', data: BIN }, { name: 'b/rclone', data: BIN }]);
  assert.throws(() => fetcher.extractBinary(two, 'rclone'), /found 2/);
  assert.throws(() => fetcher.zipEntries(Buffer.from('not a zip at all')), /end of central directory/);
});

function manifestFor(archive, bin, overrides = {}) {
  return {
    version: '1.0.0',
    baseUrl: 'https://example.invalid',
    targets: {
      'linux-x64': {
        archive: 'rclone-v1.0.0-linux-amd64.zip',
        archiveSha256: fetcher.sha256(archive),
        binary: 'rclone',
        binarySha256: fetcher.sha256(bin),
        ...overrides,
      },
    },
  };
}

test('fetching writes the verified binary and reports it present afterwards', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rclone-out-'));
  const archive = makeZip([{ name: 'rclone-v1.0.0-linux-amd64/rclone', data: BIN, deflate: true }]);
  const manifest = manifestFor(archive, BIN);
  const urls = [];
  const logs = [];
  const fetch = async (url) => { urls.push(url); return archive; };
  assert.equal(fetcher.installedBinaryOk('linux-x64', manifest, outRoot), false);
  const file = await fetcher.fetchTarget('linux-x64', manifest, { fetch, outRoot, log: (l) => logs.push(l) });
  assert.deepEqual(urls, ['https://example.invalid/v1.0.0/rclone-v1.0.0-linux-amd64.zip']);
  assert.deepEqual(fs.readFileSync(file), BIN);
  assert.equal(fetcher.installedBinaryOk('linux-x64', manifest, outRoot), true);
  assert.equal(fs.existsSync(`${file}.part`), false, 'no partial file left behind');
  // A second run does not download again.
  await fetcher.fetchTarget('linux-x64', manifest, { fetch, outRoot, log: (l) => logs.push(l) });
  assert.equal(urls.length, 1);
  assert.match(logs[logs.length - 1], /already present and verified/);
  fs.rmSync(outRoot, { recursive: true, force: true });
});

test('an archive or binary whose hash does not match the pin is refused and nothing is written', async () => {
  const outRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'rclone-out-'));
  const archive = makeZip([{ name: 'rclone-v1.0.0-linux-amd64/rclone', data: BIN }]);
  const fetch = async () => archive;
  const badArchive = manifestFor(archive, BIN, { archiveSha256: 'a'.repeat(64) });
  await assert.rejects(fetcher.fetchTarget('linux-x64', badArchive, { fetch, outRoot, log() {} }), /does not match the pinned/);
  const badBinary = manifestFor(archive, BIN, { binarySha256: 'b'.repeat(64) });
  await assert.rejects(fetcher.fetchTarget('linux-x64', badBinary, { fetch, outRoot, log() {} }), /rclone from .* does not match the pinned/);
  assert.deepEqual(fs.readdirSync(outRoot), [], 'nothing written on a mismatch');
  // A binary already on disk that no longer matches the pin is not "present".
  fs.mkdirSync(path.join(outRoot, 'linux-x64'), { recursive: true });
  fs.writeFileSync(path.join(outRoot, 'linux-x64', 'rclone'), Buffer.from('tampered'));
  assert.equal(fetcher.installedBinaryOk('linux-x64', manifestFor(archive, BIN), outRoot), false);
  fs.rmSync(outRoot, { recursive: true, force: true });
});

test('only https URLs are ever fetched, so a redirect to plain http is refused', () => {
  assert.equal(fetcher.assertHttps('https://downloads.rclone.org/v1.0.0/x.zip'), 'https://downloads.rclone.org/v1.0.0/x.zip');
  assert.throws(() => fetcher.assertHttps('http://downloads.rclone.org/v1.0.0/x.zip'), /only https/);
  assert.throws(() => fetcher.assertHttps('ftp://example.invalid/x.zip'), /only https/);
});

test('a target that is not pinned is refused', async () => {
  const archive = makeZip([{ name: 'a/rclone', data: BIN }]);
  await assert.rejects(fetcher.fetchTarget('linux-arm64', manifestFor(archive, BIN), { fetch: async () => archive, log() {} }), /no rclone 1.0.0 is pinned for linux-arm64/);
});

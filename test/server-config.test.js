'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizeServer, readServerOrigin, writeServerOrigin } = require('../src/main/server-config');
const serverConfig = require('../src/main/server-config');

test('normalizeServer accepts an https remote and derives the wss origin', () => {
  const r = normalizeServer('https://vault.example.com/some/path');
  assert.strictEqual(r.origin, 'https://vault.example.com');
  assert.strictEqual(r.wssOrigin, 'wss://vault.example.com');
  assert.strictEqual(r.isLoopback, false);
});

test('normalizeServer allows http only for loopback', () => {
  const r = normalizeServer('http://localhost:7777');
  assert.strictEqual(r.origin, 'http://localhost:7777');
  assert.strictEqual(r.wssOrigin, 'ws://localhost:7777');
  assert.strictEqual(r.isLoopback, true);
  assert.throws(() => normalizeServer('http://vault.example.com'), /https/);
});

test('normalizeServer rejects a non-http(s) scheme and a malformed URL', () => {
  assert.throws(() => normalizeServer('ftp://vault.example.com'), /http/);
  assert.throws(() => normalizeServer('not a url'));
});

test('write/read round-trips a normalized origin in a temp userData dir', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-cfg-'));
  delete process.env.DOCKVAULT_SERVER;
  assert.strictEqual(readServerOrigin(dir), null, 'unconfigured -> null');
  const origin = writeServerOrigin(dir, 'https://vault.example.com/ignored/path');
  assert.strictEqual(origin, 'https://vault.example.com');
  assert.strictEqual(readServerOrigin(dir), 'https://vault.example.com');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the DOCKVAULT_SERVER env override wins over stored config', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-cfg-'));
  writeServerOrigin(dir, 'https://stored.example.com');
  process.env.DOCKVAULT_SERVER = 'http://localhost:7777';
  try {
    assert.strictEqual(readServerOrigin(dir), 'http://localhost:7777');
  } finally {
    delete process.env.DOCKVAULT_SERVER;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('the saved setting reads as absent, ok, or unreadable — never unreadable-as-absent', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-state-'));
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'absent' });
  serverConfig.writeServerOrigin(dir, 'https://vault.example.com/some/path');
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'ok', origin: 'https://vault.example.com', sftp: null });
  fs.writeFileSync(serverConfig.configFile(dir), '{"origin": "https://vau');
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'unreadable' }, 'a truncated file');
  fs.writeFileSync(serverConfig.configFile(dir), JSON.stringify({ origin: 'http://remote.example.com' }));
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'unreadable' }, 'a saved value that would not be accepted');
  fs.writeFileSync(serverConfig.configFile(dir), JSON.stringify({ other: 1 }));
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'unreadable' }, 'a file without an origin');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the config state says which server is in force and whether the environment overrides a saved one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-state-'));
  assert.deepEqual(serverConfig.readServerConfigState(dir, {}), { status: 'absent', origin: null, envOrigin: null, fileOrigin: null, envOverrides: false, sftp: null });
  serverConfig.writeServerOrigin(dir, 'https://saved.example.com');
  assert.deepEqual(serverConfig.readServerConfigState(dir, {}), { status: 'ok', origin: 'https://saved.example.com', envOrigin: null, fileOrigin: 'https://saved.example.com', envOverrides: false, sftp: null });
  const same = serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://saved.example.com' });
  assert.equal(same.status, 'env');
  assert.equal(same.envOverrides, false, 'env equal to the saved value overrides nothing');
  const differs = serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://other.example.com' });
  assert.deepEqual(differs, { status: 'env', origin: 'https://other.example.com', envOrigin: 'https://other.example.com', fileOrigin: 'https://saved.example.com', envOverrides: true, sftp: null });
  // An env value that does not normalise is ignored, so the saved setting is used.
  assert.equal(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'http://remote.example.com' }).status, 'ok');
  // Unreadable saved file + env: env in force, and the tray must still say so.
  fs.writeFileSync(serverConfig.configFile(dir), '{');
  const un = serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://other.example.com' });
  assert.equal(un.status, 'env');
  assert.equal(un.envOverrides, true);
  assert.equal(serverConfig.readServerConfigState(dir, {}).status, 'unreadable');
  assert.equal(serverConfig.readServerOrigin(dir), null, 'the plain read stays null when nothing usable is configured');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the write is atomic: no partial file is left, and the file holds only the origin', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-state-'));
  serverConfig.writeServerOrigin(dir, 'https://vault.example.com:8443/x?y');
  assert.deepEqual(fs.readdirSync(dir), ['server-config.json']);
  assert.deepEqual(JSON.parse(fs.readFileSync(serverConfig.configFile(dir), 'utf8')), { origin: 'https://vault.example.com:8443' });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('forgetting the saved server removes the file, and forgetting twice is not an error', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-state-'));
  serverConfig.writeServerOrigin(dir, 'https://old.example.com');
  serverConfig.removeServerOrigin(dir);
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'absent' });
  assert.deepEqual(fs.readdirSync(dir), []);
  serverConfig.removeServerOrigin(dir);
  assert.deepEqual(serverConfig.readServerConfigState(dir, {}).status, 'absent');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an installed app ignores the environment variable entirely; only development runs honour it', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-state-'));
  serverConfig.writeServerOrigin(dir, 'https://saved.example.com');
  try {
    serverConfig.setEnvOverrideAllowed(false);
    const s = serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://env.example.com' });
    assert.deepEqual(s, { status: 'ok', origin: 'https://saved.example.com', envOrigin: null, fileOrigin: 'https://saved.example.com', envOverrides: false, sftp: null });
    serverConfig.setEnvOverrideAllowed('yes');
    assert.equal(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://env.example.com' }).status, 'ok', 'only a real true switches it on');
  } finally {
    serverConfig.setEnvOverrideAllowed(true);
  }
  assert.equal(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://env.example.com' }).status, 'env');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the SFTP endpoint verified at setup is saved beside the origin, read back whole, and refused when torn', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-config-'));
  try {
    serverConfig.writeServerOrigin(dir, 'https://vault.example.com', { host: 'files.example.com', port: 2200 });
    assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'ok', origin: 'https://vault.example.com', sftp: { host: 'files.example.com', port: 2200 } });
    assert.deepEqual(serverConfig.readSftpEndpoint(dir), { host: 'files.example.com', port: 2200 });
    // A setting saved before the endpoint existed still reads (no endpoint), so nothing is re-asked or broken.
    fs.writeFileSync(serverConfig.configFile(dir), JSON.stringify({ origin: 'https://vault.example.com' }));
    assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'ok', origin: 'https://vault.example.com', sftp: null });
    assert.equal(serverConfig.readSftpEndpoint(dir), null);
    // A present-but-broken endpoint is a torn file, never "no endpoint": a half host or a port out of range
    // would aim every sync at an unverified place.
    for (const bad of [{ host: 'files.example.com' }, { host: '', port: 2200 }, { host: 'files.example.com', port: 70000 }, { host: 'a b', port: 22 }, 'files:2200']) {
      fs.writeFileSync(serverConfig.configFile(dir), JSON.stringify({ origin: 'https://vault.example.com', sftp: bad }));
      assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'unreadable' }, JSON.stringify(bad));
    }
    // A malformed endpoint is refused before anything is written.
    fs.writeFileSync(serverConfig.configFile(dir), JSON.stringify({ origin: 'https://keep.example.com' }));
    assert.throws(() => serverConfig.writeServerOrigin(dir, 'https://vault.example.com', { host: 'x', port: 0 }));
    assert.equal(serverConfig.readSavedServer(dir).origin, 'https://keep.example.com');
    // Under an environment override pointing at a DIFFERENT server the saved endpoint does not apply.
    serverConfig.writeServerOrigin(dir, 'https://vault.example.com', { host: 'files.example.com', port: 2200 });
    assert.equal(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://other.example.com' }).sftp, null);
    assert.deepEqual(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://vault.example.com' }).sftp, { host: 'files.example.com', port: 2200 });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('an SFTP endpoint can be added to a saved setting later, keeping its origin; never onto nothing or onto an unreadable file', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-server-config-'));
  try {
    assert.throws(() => serverConfig.writeSftpEndpoint(dir, { host: 'files.example.com', port: 2200 }), /no readable server/);
    assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'absent' });
    serverConfig.writeServerOrigin(dir, 'https://vault.example.com');
    serverConfig.writeSftpEndpoint(dir, { host: 'files.example.com', port: 2200 });
    assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'ok', origin: 'https://vault.example.com', sftp: { host: 'files.example.com', port: 2200 } });
    assert.throws(() => serverConfig.writeSftpEndpoint(dir, { host: 'x', port: 0 }));
    // Verified against another server than the saved one (an environment override in force): refused.
    assert.throws(() => serverConfig.writeSftpEndpoint(dir, { host: 'other.example.com', port: 22 }, 'https://other.example.com'), /different server/);
    serverConfig.writeSftpEndpoint(dir, { host: 'files.example.com', port: 2201 }, 'https://vault.example.com/');
    assert.equal(serverConfig.readSavedServer(dir).sftp.port, 2201);
    fs.writeFileSync(serverConfig.configFile(dir), '{"origin": "https://old.exa');
    assert.throws(() => serverConfig.writeSftpEndpoint(dir, { host: 'files.example.com', port: 2200 }), /no readable server/);
    assert.equal(serverConfig.readSavedServer(dir).status, 'unreadable', 'left as it was');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

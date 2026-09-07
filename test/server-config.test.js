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
  assert.deepEqual(serverConfig.readSavedServer(dir), { status: 'ok', origin: 'https://vault.example.com' });
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
  assert.deepEqual(serverConfig.readServerConfigState(dir, {}), { status: 'absent', origin: null, envOrigin: null, fileOrigin: null, envOverrides: false });
  serverConfig.writeServerOrigin(dir, 'https://saved.example.com');
  assert.deepEqual(serverConfig.readServerConfigState(dir, {}), { status: 'ok', origin: 'https://saved.example.com', envOrigin: null, fileOrigin: 'https://saved.example.com', envOverrides: false });
  const same = serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://saved.example.com' });
  assert.equal(same.status, 'env');
  assert.equal(same.envOverrides, false, 'env equal to the saved value overrides nothing');
  const differs = serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://other.example.com' });
  assert.deepEqual(differs, { status: 'env', origin: 'https://other.example.com', envOrigin: 'https://other.example.com', fileOrigin: 'https://saved.example.com', envOverrides: true });
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
    assert.deepEqual(s, { status: 'ok', origin: 'https://saved.example.com', envOrigin: null, fileOrigin: 'https://saved.example.com', envOverrides: false });
    serverConfig.setEnvOverrideAllowed('yes');
    assert.equal(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://env.example.com' }).status, 'ok', 'only a real true switches it on');
  } finally {
    serverConfig.setEnvOverrideAllowed(true);
  }
  assert.equal(serverConfig.readServerConfigState(dir, { DOCKVAULT_SERVER: 'https://env.example.com' }).status, 'env');
  fs.rmSync(dir, { recursive: true, force: true });
});

'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizeServer, readServerOrigin, writeServerOrigin } = require('../src/main/server-config');

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

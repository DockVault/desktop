'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

// The daemon wires itself to process.parentPort at require time and replies through it. We provide a mock
// parentPort BEFORE requiring, capture the registered message handler once, and drive a single 'init'
// message per test — no Electron, no real utilityProcess. This exercises onInit's honest-failure handling
// directly: the fix for a total silent sync outage, where an openStateDb throw used to escape onInit as a
// {type:'error'} that main dropped, leaving the supervisor stuck 'starting' forever.
let daemonHandler = null;
const port = { postMessage: () => {}, on: (e, cb) => { if (e === 'message') daemonHandler = cb; } };
Object.defineProperty(process, 'parentPort', { value: port, configurable: true, writable: true });
require('../src/daemon/index');

const stateDb = require('../src/main/state-db');

// Drive one message through the daemon's real handler and collect everything it replied.
function drive(msg) {
  const captured = [];
  port.postMessage = (m) => captured.push(m);
  try { daemonHandler({ data: msg }); } finally { port.postMessage = () => {}; }
  return captured;
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-dae-')); }

test('the daemon registered a message handler at require time', () => {
  assert.strictEqual(typeof daemonHandler, 'function');
});

test("onInit: an openStateDb failure replies a typed ready(db-unreadable), never a dropped error", () => {
  const orig = stateDb.openStateDb;
  stateDb.openStateDb = () => { throw new Error('cannot open (wrong key / corrupt DB)'); };
  const dir = tmp();
  try {
    // A key WAS handed in (32 bytes) but the database will not open. onInit must CATCH and reply a typed,
    // bounded ready reason — never let the throw escape and be dropped, which stuck sync silently.
    const out = drive({ type: 'init', dir, dbk: new Uint8Array(32) });
    const ready = out.find((x) => x && x.type === 'ready');
    assert.ok(ready, 'onInit replied ready instead of letting the throw escape');
    assert.strictEqual(ready.encrypted, false);
    assert.strictEqual(ready.reason, 'db-unreadable');
    assert.ok(!out.some((x) => x && x.type === 'error'), 'no dropped {type:error} reply');
  } finally {
    stateDb.openStateDb = orig;
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("onInit: no key + a db-key-unreadable reason replies ready(db-key-unreadable), distinct from no-secure-store", () => {
  const dir = tmp();
  try {
    // main handed no key (loadOrMintDBK threw on an existing-but-undecryptable key) but a distinct reason.
    // The daemon must surface THAT (case 3 — the saved state is present but locked), never collapse it to
    // the insecure-backend 'no-secure-store' (case 2), because only case 3 is offered a reset.
    const out = drive({ type: 'init', dir, dbk: null, keyReason: 'db-key-unreadable' });
    const ready = out.find((x) => x && x.type === 'ready');
    assert.ok(ready);
    assert.strictEqual(ready.encrypted, false);
    assert.strictEqual(ready.reason, 'db-key-unreadable');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("onInit: no key and no reason is the benign insecure-backend case (no-secure-store)", () => {
  const dir = tmp();
  try {
    const out = drive({ type: 'init', dir, dbk: null });
    const ready = out.find((x) => x && x.type === 'ready');
    assert.ok(ready);
    assert.strictEqual(ready.encrypted, false);
    assert.strictEqual(ready.reason, 'no-secure-store');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

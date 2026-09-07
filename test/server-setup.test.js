'use strict';

// The setup screen's main-process half: what the screen may know, what gets written and when, and the
// rule that a saved setting nobody can read is never overwritten without the person's say-so.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createServerSetup, DEGRADED_HOLD_MS } = require('../src/main/server-setup');
const serverConfig = require('../src/main/server-config');

const healthy = async () => ({ ok: true, status: 200, json: async () => ({ status: 'healthy' }) });
const degraded = async () => ({ ok: true, status: 200, json: async () => ({ status: 'degraded' }) });
const notDv = async () => ({ ok: true, status: 200, json: async () => ({ hello: 1 }) });

function harness(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-setup-'));
  const saved = [];
  const scheduled = [];
  const setup = createServerSetup({
    dir, httpJson: opts.httpJson || healthy, mode: opts.mode || (() => null),
    onSaved: (o) => saved.push(o), schedule: (fn, ms) => { scheduled.push(ms); fn(); },
  });
  return { dir, setup, saved, scheduled, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('the screen learns only mode, status, and host', () => {
  const h = harness();
  assert.deepEqual(h.setup.state(), { mode: 'first-run', status: 'absent', host: null });
  serverConfig.writeServerOrigin(h.dir, 'https://vault.example.com:8443/p');
  assert.deepEqual(h.setup.state(), { mode: 'first-run', status: 'ok', host: 'vault.example.com:8443' });
  const change = harness({ mode: () => 'change' });
  assert.equal(change.setup.state().mode, 'change');
  h.cleanup(); change.cleanup();
});

test('a DockVault answer is saved atomically and the caller is told to open the sign-in page', async () => {
  const h = harness();
  const out = await h.setup.connect({ input: 'vault.example.com' });
  assert.deepEqual(out, { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com' });
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://vault.example.com' });
  assert.deepEqual(fs.readdirSync(h.dir), ['server-config.json'], 'no partial file');
  assert.deepEqual(h.saved, [out]);
  assert.deepEqual(h.scheduled, [0], 'the sign-in page follows at once');
  h.cleanup();
});

test('a degraded server is still saved, but the sign-in page waits so the sentence can be read', async () => {
  const h = harness({ httpJson: degraded });
  const out = await h.setup.connect({ input: 'vault.example.com' });
  assert.equal(out.kind, 'degraded');
  assert.equal(serverConfig.readSavedServer(h.dir).status, 'ok');
  assert.deepEqual(h.scheduled, [DEGRADED_HOLD_MS]);
  h.cleanup();
});

test('anything that is not a DockVault answer writes nothing and opens nothing', async () => {
  for (const [httpJson, input] of [[notDv, 'vault.example.com'], [healthy, 'http://vault.example.com'], [healthy, 'nope nope'], [healthy, '']]) {
    const h = harness({ httpJson });
    const out = await h.setup.connect({ input });
    assert.notEqual(out.kind, 'ok');
    assert.equal(serverConfig.readSavedServer(h.dir).status, 'absent');
    assert.deepEqual(h.saved, []);
    h.cleanup();
  }
});

test('an unreadable saved setting is never overwritten without the explicit confirmation', async () => {
  const h = harness();
  fs.writeFileSync(serverConfig.configFile(h.dir), '{"origin": "https://old.exa');
  assert.equal(h.setup.state().status, 'unreadable');
  const first = await h.setup.connect({ input: 'vault.example.com' });
  assert.deepEqual(first, { kind: 'needs-confirm', host: 'vault.example.com' });
  assert.equal(serverConfig.readSavedServer(h.dir).status, 'unreadable', 'still untouched');
  assert.deepEqual(h.saved, []);
  const second = await h.setup.connect({ input: 'vault.example.com', replaceUnreadable: true });
  assert.equal(second.kind, 'ok');
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://vault.example.com' });
  // The flag must be exactly true; a truthy string from a page does not count.
  const h2 = harness();
  fs.writeFileSync(serverConfig.configFile(h2.dir), '{');
  assert.equal((await h2.setup.connect({ input: 'vault.example.com', replaceUnreadable: 'yes' })).kind, 'needs-confirm');
  h.cleanup(); h2.cleanup();
});

test('only the exact setup page URL passes; a prefix, a suffix, a query or another origin does not', () => {
  const { isSetupPageUrl } = require('../src/main/server-setup');
  const page = '/__dv_shell__/server-setup.html';
  assert.equal(isSetupPageUrl('dockvault://app/__dv_shell__/server-setup.html', 'dockvault://app', page), true);
  for (const bad of ['dockvault://app/__dv_shell__/server-setup.html?x=1', 'dockvault://app/__dv_shell__/server-setup.html#top', 'dockvault://app/', 'dockvault://app/index.html', 'dockvault://app/__dv_shell__/server-setup.htmlx', 'dockvault://app/__dv_shell__/server-setup.html/../index.html', 'https://vault.example.com/__dv_shell__/server-setup.html', 'file:///C:/x/server-setup.html', '', null, undefined]) {
    assert.equal(isSetupPageUrl(bad, 'dockvault://app', page), false, String(bad));
  }
});

test('the sender check needs all three legs: the main window, its main frame, and the exact setup URL', () => {
  const { isTrustedSetupSender } = require('../src/main/server-setup');
  const appOrigin = 'dockvault://app';
  const pagePath = '/__dv_shell__/server-setup.html';
  const main = {}; main.mainFrame = { url: appOrigin + pagePath };
  const other = {}; other.mainFrame = { url: appOrigin + pagePath };
  const ok = { sender: main, senderFrame: main.mainFrame };
  assert.equal(isTrustedSetupSender(ok, { webContents: main, appOrigin, pagePath }), true);
  // Another window's page, even at the right URL.
  assert.equal(isTrustedSetupSender({ sender: other, senderFrame: other.mainFrame }, { webContents: main, appOrigin, pagePath }), false);
  // A subframe of the main window, even at the right URL.
  assert.equal(isTrustedSetupSender({ sender: main, senderFrame: { url: appOrigin + pagePath } }, { webContents: main, appOrigin, pagePath }), false);
  // The main frame, but at the interface's URL.
  const atRoot = {}; atRoot.mainFrame = { url: appOrigin + '/' };
  assert.equal(isTrustedSetupSender({ sender: atRoot, senderFrame: atRoot.mainFrame }, { webContents: atRoot, appOrigin, pagePath }), false);
  // No window yet, or a malformed event.
  assert.equal(isTrustedSetupSender(ok, { webContents: null, appOrigin, pagePath }), false);
  assert.equal(isTrustedSetupSender(null, { webContents: main, appOrigin, pagePath }), false);
  assert.equal(isTrustedSetupSender({ sender: main }, { webContents: main, appOrigin, pagePath }), false);
});

test('a saved, readable server is never re-pointed from the screen: only a switch asked for in the tray may', async () => {
  const h = harness();
  serverConfig.writeServerOrigin(h.dir, 'https://saved.example.com');
  const out = await h.setup.connect({ input: 'attacker.example.com' });
  assert.deepEqual(out, { kind: 'not-allowed', host: 'attacker.example.com' });
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://saved.example.com' });
  assert.deepEqual(h.saved, []);
  // The same request during a switch (the old server already forgotten by the consent flow) is allowed.
  const sw = harness({ mode: () => 'change' });
  serverConfig.writeServerOrigin(sw.dir, 'https://saved.example.com');
  assert.equal((await sw.setup.connect({ input: 'new.example.com' })).kind, 'ok');
  assert.equal(serverConfig.readSavedServer(sw.dir).origin, 'https://new.example.com');
  h.cleanup(); sw.cleanup();
});

test('while switching servers the old host is pre-filled from memory, since the saved setting is already gone', () => {
  let host = 'old.example.com';
  const h = harness({ mode: () => 'change' });
  h.setup = createServerSetup({ dir: h.dir, httpJson: healthy, mode: () => 'change', changeHost: () => host, onSaved: () => {}, schedule: (fn) => fn() });
  assert.deepEqual(h.setup.state(), { mode: 'change', status: 'absent', host: 'old.example.com' });
  host = null;
  assert.equal(h.setup.state().host, null);
  // Outside a switch the memory is never consulted.
  const plain = createServerSetup({ dir: h.dir, httpJson: healthy, mode: () => null, changeHost: () => 'stale.example.com' });
  assert.equal(plain.state().host, null);
  h.cleanup();
});

test('a write that fails is reported as save-failed, nothing else', async () => {
  // The data "folder" is a plain file, so nothing can be created inside it.
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-setup-'));
  const dir = path.join(parent, 'not-a-folder');
  fs.writeFileSync(dir, 'x');
  const saved = [];
  const setup = createServerSetup({ dir, httpJson: healthy, onSaved: (o) => saved.push(o), schedule: (fn) => fn() });
  const out = await setup.connect({ input: 'vault.example.com' });
  assert.equal(out.kind, 'save-failed');
  assert.equal(out.host, 'vault.example.com');
  assert.deepEqual(saved, []);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('malformed arguments from the page are treated as an empty address, never as a crash', async () => {
  const h = harness();
  for (const args of [null, undefined, {}, { input: 42 }, 'string']) {
    assert.equal((await h.setup.connect(args)).kind, 'empty');
  }
  h.cleanup();
});

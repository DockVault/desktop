'use strict';

// The setup screen's main-process half: what the screen may know, what gets written and when, and the
// rule that a saved setting nobody can read is never overwritten without the person's say-so. The two
// probes behind the verify step are faked here; their own behaviour has its own tests.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { createServerSetup, DEGRADED_HOLD_MS } = require('../src/main/server-setup');
const serverConfig = require('../src/main/server-config');

// One httpJson that serves the health route AND the device route (the sync-capability signal).
const vault = (health, devicesStatus = 401) => async (url) => {
  if (url.endsWith('/devices')) return { ok: false, status: devicesStatus, json: async () => ({ detail: 'x' }) };
  return { ok: true, status: 200, json: async () => health };
};
const healthy = vault({ status: 'healthy' });
const degraded = vault({ status: 'degraded' });
const notDv = vault({ hello: 1 });
const oldVault = vault({ status: 'healthy' }, 404);

const sftpOk = async (ep) => ({ kind: 'ok', host: ep.host, port: ep.port, hostKey: 'ssh-ed25519 AAAA', fingerprint: 'SHA256:fp', banner: 'SSH-2.0-X' });
const sftpDown = async (ep) => ({ kind: 'unreachable', host: ep.host, port: ep.port });

const SFTP = 'vault.example.com:2222';
const ENDPOINT = { host: 'vault.example.com', port: 2222 };

function harness(opts = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-setup-'));
  const saved = [];
  const scheduled = [];
  const setup = createServerSetup({
    dir, httpJson: opts.httpJson || healthy, probeSftp: opts.probeSftp || sftpOk, mode: opts.mode || (() => null),
    changeHost: opts.changeHost, changeSftp: opts.changeSftp,
    onSaved: (o) => saved.push(o), schedule: (fn, ms) => { scheduled.push(ms); fn(); },
  });
  return { dir, setup, saved, scheduled, cleanup: () => fs.rmSync(dir, { recursive: true, force: true }) };
}

test('the screen learns only mode, status, host, and the saved SFTP address', () => {
  const h = harness();
  assert.deepEqual(h.setup.state(), { mode: 'first-run', status: 'absent', host: null, sftp: null });
  serverConfig.writeServerOrigin(h.dir, 'https://vault.example.com:8443/p', { host: 'files.example.com', port: 2200 });
  assert.deepEqual(h.setup.state(), { mode: 'first-run', status: 'ok', host: 'vault.example.com:8443', sftp: 'files.example.com:2200' });
  serverConfig.writeServerOrigin(h.dir, 'https://vault.example.com:8443/p');
  assert.equal(h.setup.state().sftp, null, 'a setting saved without an endpoint shows none');
  const change = harness({ mode: () => 'change' });
  assert.equal(change.setup.state().mode, 'change');
  h.cleanup(); change.cleanup();
});

test('check runs both legs and writes nothing', async () => {
  const h = harness();
  const v = await h.setup.check({ input: 'vault.example.com', sftp: SFTP });
  assert.equal(v.api.kind, 'ok');
  assert.equal(v.sync.kind, 'supported');
  assert.deepEqual(v.sftp, { kind: 'ok', host: 'vault.example.com', port: 2222, fingerprint: 'SHA256:fp' });
  assert.equal(v.proceed, true);
  assert.equal(serverConfig.readSavedServer(h.dir).status, 'absent');
  assert.deepEqual(h.saved, []);
  h.cleanup();
});

test('a DockVault answer with a verified SFTP door is saved atomically — origin and endpoint — and the caller is told to open the sign-in page', async () => {
  const h = harness();
  const out = await h.setup.connect({ input: 'vault.example.com', sftp: SFTP });
  assert.equal(out.kind, 'ok');
  assert.equal(out.origin, 'https://vault.example.com');
  assert.equal(out.host, 'vault.example.com');
  assert.equal(out.verify.proceed, true);
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://vault.example.com', sftp: ENDPOINT });
  assert.deepEqual(fs.readdirSync(h.dir), ['server-config.json'], 'no partial file');
  assert.deepEqual(h.saved, [out]);
  assert.deepEqual(h.scheduled, [0], 'the sign-in page follows at once');
  h.cleanup();
});

test('connect never trusts the page: an SFTP door that does not verify is refused as not-verified and nothing is written, even if the page claimed green', async () => {
  const h = harness({ probeSftp: sftpDown });
  const out = await h.setup.connect({ input: 'vault.example.com', sftp: 'vault.example.com:1234', verified: true, proceed: true });
  assert.equal(out.kind, 'not-verified');
  assert.equal(out.host, 'vault.example.com');
  assert.equal(out.verify.sftp.kind, 'unreachable');
  assert.equal(serverConfig.readSavedServer(h.dir).status, 'absent');
  assert.deepEqual(h.saved, []);
  // An empty SFTP field on a server that speaks sync is the same refusal.
  const e = await h.setup.connect({ input: 'vault.example.com', sftp: '' });
  assert.equal(e.kind, 'not-verified');
  assert.equal(e.verify.sftp.kind, 'empty');
  h.cleanup();
});

test('a server that does not speak sync connects on the API leg alone, says so, and saves no endpoint', async () => {
  const h = harness({ httpJson: oldVault, probeSftp: sftpDown });
  const out = await h.setup.connect({ input: 'old.example.com', sftp: 'old.example.com:2222' });
  assert.equal(out.kind, 'ok');
  assert.equal(out.verify.sync.kind, 'unsupported');
  assert.equal(out.verify.sftp.kind, 'not-needed');
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://old.example.com', sftp: null });
  assert.equal(h.saved.length, 1);
  h.cleanup();
});

test('a degraded server is still saved, but the sign-in page waits so the sentence can be read', async () => {
  const h = harness({ httpJson: degraded });
  const out = await h.setup.connect({ input: 'vault.example.com', sftp: SFTP });
  assert.equal(out.kind, 'degraded');
  assert.equal(serverConfig.readSavedServer(h.dir).status, 'ok');
  assert.deepEqual(h.scheduled, [DEGRADED_HOLD_MS]);
  h.cleanup();
});

test('anything that is not a DockVault answer writes nothing and opens nothing, and carries the verify for the lights', async () => {
  for (const [httpJson, input] of [[notDv, 'vault.example.com'], [healthy, 'http://vault.example.com'], [healthy, 'nope nope'], [healthy, '']]) {
    const h = harness({ httpJson });
    const out = await h.setup.connect({ input, sftp: SFTP });
    assert.notEqual(out.kind, 'ok');
    assert.ok(out.verify && out.verify.api && out.verify.api.kind === out.kind, `verify attached for ${input}`);
    assert.equal(serverConfig.readSavedServer(h.dir).status, 'absent');
    assert.deepEqual(h.saved, []);
    h.cleanup();
  }
});

test('an unreadable saved setting is never overwritten without the explicit confirmation', async () => {
  const h = harness();
  fs.writeFileSync(serverConfig.configFile(h.dir), '{"origin": "https://old.exa');
  assert.equal(h.setup.state().status, 'unreadable');
  const first = await h.setup.connect({ input: 'vault.example.com', sftp: SFTP });
  assert.equal(first.kind, 'needs-confirm');
  assert.equal(first.host, 'vault.example.com');
  assert.equal(serverConfig.readSavedServer(h.dir).status, 'unreadable', 'still untouched');
  assert.deepEqual(h.saved, []);
  const second = await h.setup.connect({ input: 'vault.example.com', sftp: SFTP, replaceUnreadable: true });
  assert.equal(second.kind, 'ok');
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://vault.example.com', sftp: ENDPOINT });
  // The flag must be exactly true; a truthy string from a page does not count.
  const h2 = harness();
  fs.writeFileSync(serverConfig.configFile(h2.dir), '{');
  assert.equal((await h2.setup.connect({ input: 'vault.example.com', sftp: SFTP, replaceUnreadable: 'yes' })).kind, 'needs-confirm');
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
  const out = await h.setup.connect({ input: 'attacker.example.com', sftp: 'attacker.example.com:2222' });
  assert.equal(out.kind, 'not-allowed');
  assert.equal(out.host, 'attacker.example.com');
  assert.deepEqual(serverConfig.readSavedServer(h.dir), { status: 'ok', origin: 'https://saved.example.com', sftp: null });
  assert.deepEqual(h.saved, []);
  // The same request during a switch (the old server already forgotten by the consent flow) is allowed.
  const sw = harness({ mode: () => 'change' });
  serverConfig.writeServerOrigin(sw.dir, 'https://saved.example.com');
  assert.equal((await sw.setup.connect({ input: 'new.example.com', sftp: 'new.example.com:2222' })).kind, 'ok');
  assert.deepEqual(serverConfig.readSavedServer(sw.dir), { status: 'ok', origin: 'https://new.example.com', sftp: { host: 'new.example.com', port: 2222 } });
  h.cleanup(); sw.cleanup();
});

test('while switching servers the old host and SFTP address are pre-filled from memory, since the saved setting is already gone', () => {
  let host = 'old.example.com';
  let sftp = 'old.example.com:2200';
  const h = harness({ mode: () => 'change', changeHost: () => host, changeSftp: () => sftp });
  assert.deepEqual(h.setup.state(), { mode: 'change', status: 'absent', host: 'old.example.com', sftp: 'old.example.com:2200' });
  host = null; sftp = null;
  assert.deepEqual(h.setup.state(), { mode: 'change', status: 'absent', host: null, sftp: null });
  h.cleanup();
});

test('connecting saves the server and nothing else: no sync set-up is started from here', async () => {
  const h = harness();
  const out = await h.setup.connect({ input: 'vault.example.com', sftp: SFTP });
  assert.equal(out.kind, 'ok');
  // The only things written are the origin and the SFTP endpoint; the sync config store, the device
  // identity, and any grant record are not touched (their files do not appear).
  assert.deepEqual(fs.readdirSync(h.dir), ['server-config.json']);
  assert.deepEqual(Object.keys(JSON.parse(fs.readFileSync(serverConfig.configFile(h.dir), 'utf8'))).sort(), ['origin', 'sftp']);
  h.cleanup();
});

'use strict';

/*
 * The setup screen, from the page's real source: its words for a server that answers without HTTPS, which are
 * never the untrusted-certificate sentence, and for a server on this computer reached over plain http.
 *
 * The page runs in a small DOM that keeps each element's value and listeners — enough to type into a field and
 * press Check; the full screen is exercised under Electron by test/server-setup-check.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const SRC = fs.readFileSync(path.join(__dirname, '..', 'src', 'renderer', 'server-setup.js'), 'utf8');

function element() {
  const listeners = {};
  return {
    value: '', textContent: '', hidden: false, disabled: false, checked: false, dataset: {},
    setAttribute() {}, removeAttribute() {}, focus() {}, select() {},
    addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    fire(type) { for (const fn of listeners[type] || []) fn({ preventDefault() {} }); },
  };
}

// The screen's words for an API outcome: press Check with a canned verify and read the server light.
async function apiLightFor(api) {
  const nodes = new Map();
  const document = { getElementById: (id) => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); } };
  const verify = { api, sync: { kind: 'not-checked' }, sftp: { kind: 'unreachable', host: 'localhost', port: 2322 }, proceed: false };
  const server = { state: async () => ({ mode: 'first-run', status: 'absent', host: null, sftp: null }), check: async () => verify, connect: async () => null };
  vm.runInContext(SRC, vm.createContext({ document, window: { dockvault: { server } }, URL, setTimeout, clearTimeout, Date, console }), { filename: 'server-setup.js' });
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
  document.getElementById('server').value = api.host || 'x';
  document.getElementById('form').fire('submit');
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r));
  return document.getElementById('api-what').textContent;
}

test('a server that answers without HTTPS gets its own words — never the certificate sentence — for this computer and for another one', async () => {
  const local = await apiLightFor({ kind: 'tls-not-offered', host: 'localhost:8290', loopback: true });
  assert.equal(local, "localhost:8290 answered, but not over HTTPS. If it's a test server on this computer that uses plain HTTP, enter http://localhost:8290.");
  const remote = await apiLightFor({ kind: 'tls-not-offered', host: 'vault.example.com:8290' });
  assert.equal(remote, 'vault.example.com:8290 answered, but not over HTTPS. A server on another computer must offer HTTPS — check the address and port with whoever runs it.');
  for (const text of [local, remote]) assert.doesNotMatch(text, /certificate/i);
  // A real certificate problem keeps its sentence.
  assert.match(await apiLightFor({ kind: 'tls-untrusted', host: 'vault.example.com' }), /^This server's certificate isn't trusted by this computer/);
});

test('when plain http was used for a server on this computer, the green light says so', async () => {
  assert.equal(await apiLightFor({ kind: 'ok', host: 'localhost:8290', plainHttp: true }), "localhost:8290 is a DockVault server. It doesn't offer HTTPS, so DockVault uses plain HTTP — allowed only for a server on this computer.");
  assert.equal(await apiLightFor({ kind: 'ok', host: 'localhost:8290' }), 'localhost:8290 is a DockVault server.');
  assert.equal(await apiLightFor({ kind: 'ok', host: 'τεστ' }), 'τεστ is a DockVault server.');
});

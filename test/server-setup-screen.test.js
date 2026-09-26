'use strict';

/*
 * The setup screen, from the page's real source: its words for a server that answers without HTTPS, which are
 * never the untrusted-certificate sentence, and for a server on this computer reached over plain http. And its
 * SFTP suggestion: typing a server fills the file transfer field with that server's host on the default port.
 * A name in another script is shown the way it was typed (trimmed, lower-cased), not as the "xn--" form the URL
 * parser turns it into, and main's parse of the suggestion always lands on the same ASCII host main uses for
 * the server address itself.
 *
 * The page runs in a small DOM that keeps each element's value and listeners — enough to type into a field and
 * press Check; the full screen is exercised under Electron by test/server-setup-check.js.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const { parseSftpEndpoint, DEFAULT_SFTP_PORT } = require('../src/main/sftp-endpoint');
const { normalizeInput } = require('../src/main/server-probe');

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

async function openScreen() {
  const nodes = new Map();
  const document = { getElementById: (id) => { if (!nodes.has(id)) nodes.set(id, element()); return nodes.get(id); } };
  const server = { state: async () => ({ mode: 'first-run', status: 'absent', host: null, sftp: null }), check: async () => null, connect: async () => null };
  const sandbox = { document, window: { dockvault: { server } }, URL, setTimeout, clearTimeout, Date, console };
  vm.runInContext(SRC, vm.createContext(sandbox), { filename: 'server-setup.js' });
  for (let i = 0; i < 5; i += 1) await new Promise((r) => setImmediate(r)); // start() has read the state
  const type = (text) => { document.getElementById('server').value = text; document.getElementById('server').fire('input'); return document.getElementById('sftp').value; };
  return { type, sftp: document.getElementById('sftp') };
}

// The ASCII host main connects to for a typed server address, without brackets (as an SFTP host carries it).
const serverHostAscii = (typed) => new URL(normalizeInput(typed).origin).hostname.replace(/^\[|\]$/g, '');

test('the suggestion shows a name in another script as typed, lower-cased, on port 2322', async () => {
  const screen = await openScreen();
  const cases = [
    ['τεστ', 'τεστ:2322'],                                   // the reported case: not "xn--qxa2abc:2322"
    ['  ΤΕΣΤ  ', 'τεστ:2322'],                               // trimmed and lower-cased
    ['Τεστ.Example.COM:8443/login', 'τεστ.example.com:2322'], // a port and a path are not part of the host
    ['https://bücher.example', 'bücher.example:2322'],
    ['localhost:8290', 'localhost:2322'],
    ['Vault.Example.com', 'vault.example.com:2322'],         // a plain ASCII name, exactly as before
    ['[::1]:8290', '[::1]:2322'],                            // an IPv6 literal keeps its brackets
    ['xn--qxa2abc', 'xn--qxa2abc:2322'],                     // the ASCII form, typed as such, is left as typed
  ];
  for (const [typed, expected] of cases) {
    const suggested = await screen.type(typed);
    assert.equal(suggested, expected, typed);
    const parsed = parseSftpEndpoint(suggested);
    assert.equal(parsed.kind, 'ok', typed);
    assert.equal(parsed.port, DEFAULT_SFTP_PORT);
    assert.equal(parsed.host, serverHostAscii(typed), `${typed}: the SFTP host is the server's own host where it is connected to`);
  }
});

test('a name whose lower-cased spelling would be a different host is shown exactly as typed', async () => {
  // A final capital sigma lower-cases to "ς", which is a different host name than the "σ" host names fold it
  // to; shown lower-cased, the suggestion would point somewhere else.
  const screen = await openScreen();
  const suggested = await screen.type('ΤΕΣ');
  assert.equal(suggested, 'ΤΕΣ:2322');
  assert.equal(parseSftpEndpoint(suggested).host, serverHostAscii('ΤΕΣ'));
});

test('the suggestion never holds 2332 or any port but the default for a host typed without one', async () => {
  const screen = await openScreen();
  for (const typed of ['vault.example.com', 'τεστ', 'localhost:8290', '10.0.0.5:443']) {
    assert.match(await screen.type(typed), /:2322$/, typed);
  }
  assert.doesNotMatch(SRC, /2332/);
});

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

'use strict';

// A server name in another script: shown the way it was typed, connected to and saved in its ASCII form, and
// the two never drift apart — through the SFTP address, the setup verify, the saved setting, the troubleshoot
// view, and the sync engine's configuration. A setting saved in the ASCII form by an earlier version keeps
// working unchanged.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const { toAsciiHost, toDisplayHost, toDisplayAddress } = require('../src/main/host-name');
const { parseSftpEndpoint, formatSftpEndpoint, displaySftpEndpoint, suggestSftpEndpoint, applySftpEndpoint, DEFAULT_SFTP_PORT } = require('../src/main/sftp-endpoint');
const { verifySetup } = require('../src/main/setup-verify');
const { createServerSetup } = require('../src/main/server-setup');
const { createTroubleshoot } = require('../src/main/troubleshoot');
const { formatSftpRemote } = require('../src/daemon/ephemeral-config');
const serverConfig = require('../src/main/server-config');

// "τεστ" is the reported example; its ASCII form is what the URL parser (and an address bar) produces.
const GREEK = 'τεστ';
const GREEK_ASCII = 'xn--qxa2abc';

test('the ASCII form: a Greek name is converted, a mixed-case one is lower-cased first, an IP or an ASCII name passes through', () => {
  assert.equal(toAsciiHost(GREEK), GREEK_ASCII);
  assert.equal(toAsciiHost('  ΤΕΣΤ  '), GREEK_ASCII, 'trimmed, and upper case names the same host');
  assert.equal(toAsciiHost('Τεστ.Example.COM'), `${GREEK_ASCII}.example.com`);
  assert.equal(toAsciiHost('Vault.Example.COM'), 'vault.example.com');
  assert.equal(toAsciiHost('bücher.de'), 'xn--bcher-kva.de');
  assert.equal(toAsciiHost(GREEK_ASCII), GREEK_ASCII, 'an ASCII (punycode) name typed or saved earlier is kept as it is');
  assert.equal(toAsciiHost('10.0.0.5'), '10.0.0.5');
  assert.equal(toAsciiHost('FE80::1'), 'fe80::1');
  assert.equal(toAsciiHost('::1'), '::1');
  for (const bad of ['', null, undefined, '   ', 'τεστ.1', 'τε στ']) assert.equal(toAsciiHost(bad), '', String(bad));
});

test('the readable form: only for an encoded name that converts back to exactly the same ASCII name', () => {
  assert.equal(toDisplayHost(GREEK_ASCII), GREEK);
  assert.equal(toDisplayHost(`${GREEK_ASCII}.example.com`), `${GREEK}.example.com`);
  assert.equal(toDisplayHost('XN--QXA2ABC'), GREEK, 'an upper-case ASCII form still names the same host');
  assert.equal(toDisplayHost('vault.example.com'), 'vault.example.com');
  assert.equal(toDisplayHost('::1'), '::1');
  assert.equal(toDisplayHost('xn--zz'), 'xn--zz', 'a label that does not decode is shown as it is');
  // Every readable form converts back to the very name it came from.
  for (const ascii of [GREEK_ASCII, 'xn--bcher-kva.de', 'xn--jxalpdlp', 'vault.example.com']) assert.equal(toAsciiHost(toDisplayHost(ascii)), ascii);
  // host:port, and an IPv6 literal with its port, which has no name to decode.
  assert.equal(toDisplayAddress(`${GREEK_ASCII}:8290`), `${GREEK}:8290`);
  assert.equal(toDisplayAddress(GREEK_ASCII), GREEK);
  assert.equal(toDisplayAddress('[::1]:8290'), '[::1]:8290');
  assert.equal(toDisplayAddress('localhost:8290'), 'localhost:8290');
  assert.equal(toDisplayAddress(''), '');
});

test('the SFTP address: a name typed in another script is parsed to the ASCII host that is probed and saved; its display form reads as typed', () => {
  assert.deepEqual(parseSftpEndpoint(`${GREEK}:2322`), { kind: 'ok', host: GREEK_ASCII, port: 2322 });
  assert.deepEqual(parseSftpEndpoint('ΤΕΣΤ'), { kind: 'ok', host: GREEK_ASCII, port: DEFAULT_SFTP_PORT });
  assert.deepEqual(parseSftpEndpoint(`sftp://Τεστ.Example.com:2200/`), { kind: 'ok', host: `${GREEK_ASCII}.example.com`, port: 2200 });
  assert.deepEqual(parseSftpEndpoint(`${GREEK_ASCII}:2322`), { kind: 'ok', host: GREEK_ASCII, port: 2322 }, 'the ASCII form typed directly');
  assert.deepEqual(parseSftpEndpoint('Files.Example.COM:2200'), { kind: 'ok', host: 'files.example.com', port: 2200 });
  assert.deepEqual(parseSftpEndpoint('[FE80::1]:2322'), { kind: 'ok', host: 'fe80::1', port: 2322 });
  assert.deepEqual(parseSftpEndpoint('τεστ.1:2322'), { kind: 'malformed' });
  const ep = { host: GREEK_ASCII, port: 2322 };
  assert.equal(formatSftpEndpoint(ep), `${GREEK_ASCII}:2322`, 'the connectable form');
  assert.equal(displaySftpEndpoint(ep), `${GREEK}:2322`, 'the readable form');
  assert.equal(displaySftpEndpoint({ host: '::1', port: 2322 }), '[::1]:2322');
  assert.equal(displaySftpEndpoint(null), '');
  // The suggestion for a saved server is its ASCII host on the default port; shown readable.
  assert.equal(displaySftpEndpoint(suggestSftpEndpoint(`https://${GREEK_ASCII}:8443`)), `${GREEK}:2322`);
});

// A fake DockVault server and SFTP door that record what they were asked for.
function fakes() {
  const asked = { http: [], sftp: [] };
  const httpJson = async (url) => {
    asked.http.push(url);
    if (url.endsWith('/devices')) return { ok: false, status: 401, json: async () => ({}) };
    return { ok: true, status: 200, json: async () => ({ status: 'healthy' }) };
  };
  const probeSftp = async (ep) => { asked.sftp.push(ep); return { kind: 'ok', host: ep.host, port: ep.port, hostKey: 'ssh-ed25519 AAAA', fingerprint: 'SHA256:fp' }; };
  return { asked, httpJson, probeSftp };
}

test('the setup verify: every connection uses the ASCII host, every sentence gets the readable one, the endpoint to save is ASCII', async () => {
  const { asked, httpJson, probeSftp } = fakes();
  const v = await verifySetup({ input: 'ΤΕΣΤ:8290', sftp: `${GREEK}:2322` }, { httpJson, probeSftp });
  assert.deepEqual(asked.http, [`https://${GREEK_ASCII}:8290/health`, `https://${GREEK_ASCII}:8290/devices`]);
  assert.deepEqual(asked.sftp, [{ host: GREEK_ASCII, port: 2322 }]);
  assert.deepEqual(v.api, { kind: 'ok', host: `${GREEK}:8290` });
  assert.deepEqual(v.sftp, { kind: 'ok', host: GREEK, port: 2322, fingerprint: 'SHA256:fp' });
  assert.deepEqual(v.endpoint, { host: GREEK_ASCII, port: 2322 });
  assert.equal(v.origin, `https://${GREEK_ASCII}:8290`);
});

test('a redirect onto a name the person did not type is shown in its ASCII form, so a look-alike cannot pass for the typed one', async () => {
  // "vаult" with a Cyrillic "а": reads the same as the typed name, is a different host.
  const lookalike = new URL('https://vаult.example.com').hostname;
  assert.ok(lookalike.startsWith('xn--'));
  const httpJson = async (url) => (url.endsWith('/health')
    ? { ok: true, status: 200, url: `https://${lookalike}/health`, json: async () => ({ status: 'healthy' }) }
    : { ok: false, status: 401, json: async () => ({}) });
  const v = await verifySetup({ input: 'vault.example.com', sftp: '' }, { httpJson, probeSftp: fakes().probeSftp });
  assert.deepEqual(v.api, { kind: 'ok', host: lookalike, from: 'vault.example.com' });
});

test('the saved setting, the setup screen and a connect: a Greek name is saved in the ASCII form and shown readable again', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-idn-'));
  try {
    const { httpJson, probeSftp } = fakes();
    const setup = createServerSetup({ dir, httpJson, probeSftp, schedule: (fn) => fn() });
    const out = await setup.connect({ input: GREEK, sftp: `${GREEK}:2322` });
    assert.equal(out.kind, 'ok');
    assert.equal(out.host, GREEK, 'the screen says what was typed');
    assert.deepEqual(JSON.parse(fs.readFileSync(serverConfig.configFile(dir), 'utf8')), { origin: `https://${GREEK_ASCII}`, sftp: { host: GREEK_ASCII, port: 2322 } }, 'the file holds the ASCII form only');
    assert.deepEqual(setup.state(), { mode: 'first-run', status: 'ok', host: GREEK, sftp: `${GREEK}:2322` });
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a setting saved in the ASCII form by an earlier version keeps working: read, shown, verified and synced to the same host', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-idn-old-'));
  try {
    fs.writeFileSync(serverConfig.configFile(dir), JSON.stringify({ origin: `https://${GREEK_ASCII}:8443`, sftp: { host: GREEK_ASCII, port: 2322 } }) + '\n');
    const saved = serverConfig.readSavedServer(dir);
    assert.deepEqual(saved, { status: 'ok', origin: `https://${GREEK_ASCII}:8443`, sftp: { host: GREEK_ASCII, port: 2322 } });
    // The setup screen (change mode pre-fills) shows it readable.
    const { asked, httpJson, probeSftp } = fakes();
    const setup = createServerSetup({ dir, httpJson, probeSftp });
    assert.deepEqual(setup.state(), { mode: 'first-run', status: 'ok', host: `${GREEK}:8443`, sftp: `${GREEK}:2322` });
    // The troubleshoot view passes the saved addresses to the verify, which reaches the very same hosts.
    const view = createTroubleshoot({ serverState: () => ({ status: 'ok', origin: saved.origin, sftp: saved.sftp }), verify: (fields) => verifySetup(fields, { httpJson, probeSftp }) });
    const facts = view.describe('server-connection').facts;
    assert.equal(facts[0].value, `${GREEK}:8443 (${GREEK_ASCII})`, 'readable, with the ASCII form beside it for comparison');
    assert.equal(facts[1].value, `${GREEK}:2322 (${GREEK_ASCII}:2322)`);
    const r = await view.probe('server-connection');
    assert.equal(asked.http[0], `https://${GREEK_ASCII}:8443/health`);
    assert.deepEqual(asked.sftp, [{ host: GREEK_ASCII, port: 2322 }]);
    assert.match(r.legs[0].text, new RegExp(`^${GREEK}:8443 answered as a DockVault server`));
    assert.match(r.legs[1].text, new RegExp(`^${GREEK}:2322 answered as an SFTP server`));
    // The sync engine: the saved endpoint replaces the minted host, and rclone is configured with the ASCII host.
    const bundle = { host: GREEK_ASCII, port: 2222, user: 'u', password: 'p', hostKeys: 'ssh-ed25519 AAAA' };
    applySftpEndpoint(bundle, serverConfig.readSftpEndpoint(dir));
    assert.deepEqual([bundle.host, bundle.port], [GREEK_ASCII, 2322]);
    const conf = formatSftpRemote('dv', { host: bundle.host, port: bundle.port, user: 'u', obscuredPass: 'x', hostKeys: bundle.hostKeys });
    assert.match(conf, new RegExp(`^host = ${GREEK_ASCII}$`, 'm'));
    assert.doesNotMatch(conf, /[^\x00-\x7f]/, 'nothing but ASCII reaches the rclone configuration');
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

test('a Greek SFTP address typed on the setup screen is saved in the ASCII form, and an ASCII endpoint on disk is never rewritten into the readable one', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-idn-ep-'));
  try {
    serverConfig.writeServerOrigin(dir, `https://${GREEK_ASCII}`);
    const parsed = parseSftpEndpoint(`${GREEK}:2322`);
    serverConfig.writeSftpEndpoint(dir, { host: parsed.host, port: parsed.port }, `https://${GREEK}`);
    assert.deepEqual(serverConfig.readSftpEndpoint(dir), { host: GREEK_ASCII, port: 2322 });
    // The sync wizard's conversation carries the readable host; turning it back gives the very host probed.
    assert.equal(toAsciiHost(toDisplayHost(parsed.host)), parsed.host);
    // A readable host can never be saved as-is: the endpoint shape accepts ASCII names only.
    assert.throws(() => serverConfig.writeSftpEndpoint(dir, { host: GREEK, port: 2322 }));
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

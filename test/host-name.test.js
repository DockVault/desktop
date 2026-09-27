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

const { toAsciiHost, toDisplayHost, toDisplayAddress, addressWithAscii, isReadableLabel } = require('../src/main/host-name');
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

// The look-alike names: each reads as another host on screen, and each IS another host on the network.
const LOOKALIKES = {
  // A division slash (U+2215) inside a label: reads as "paypal.com" and a path, is a host under evil.io.
  slash: { readable: 'paypal.com∕login.evil.io', ascii: 'paypal.xn--comlogin-0f7d.evil.io' },
  // Latin "vault" with one Cyrillic "а": two scripts in one label.
  mixed: { readable: 'vauаlt.com', ascii: 'xn--vault-6ve.com' },
  // All Cyrillic, yet it reads as "apple": one script, so only the ASCII form beside it exposes it.
  wholeScript: { readable: 'аррӏе.com', ascii: 'xn--80ak6aa92e.com' },
};

test('the readable form is offered only for a name written plainly in one script per label', () => {
  for (const { readable, ascii } of Object.values(LOOKALIKES)) assert.equal(toAsciiHost(readable), ascii, 'the fixtures name the hosts they claim to');
  // A slash or a dot look-alike, or a label that mixes scripts: shown in the ASCII form only.
  assert.equal(toDisplayHost(LOOKALIKES.slash.ascii), LOOKALIKES.slash.ascii);
  assert.equal(toDisplayHost(LOOKALIKES.mixed.ascii), LOOKALIKES.mixed.ascii);
  assert.equal(toDisplayAddress(`${LOOKALIKES.slash.ascii}:443`), `${LOOKALIKES.slash.ascii}:443`);
  for (const readable of ['exa․mple.com', 'a⁄b.com', 'e̸x.com', 'abテスト.jp', 'テストт.jp', 'pаypal.com']) {
    const ascii = toAsciiHost(readable);
    if (!ascii) continue; // a name IDNA refuses outright never reaches the screen at all
    assert.equal(toDisplayHost(ascii), ascii, `${JSON.stringify(readable)} is shown as ${ascii}`);
  }
  // Names written plainly in one script, or in one of the mixes a language needs, read as they are.
  const plain = [
    'τεστ', // Greek
    'δοκιμή-2.gr', // Greek with an ASCII hyphen and digit
    'пример.рф', // Cyrillic only, in a Cyrillic top-level domain
    'тест.example.com', // Cyrillic beside Latin labels
    'コーヒー.jp', // Katakana with the prolonged sound mark both kana share
    '例え.テスト', // Japanese: Han and Hiragana in one label
    '日本語.jp', // Han
    '한국.kr', // Korean
    '韓國한국.kr', // Korean: Han and Hangul in one label
    'bücher.de', 'việt.vn', 'हिन्दी.in', 'مثال.eg',
  ];
  for (const readable of plain) assert.equal(toDisplayHost(toAsciiHost(readable)), readable, readable);
  // The whole-script look-alike is one script, so it reads as it is; addressWithAscii is what exposes it.
  assert.equal(toDisplayHost(LOOKALIKES.wholeScript.ascii), LOOKALIKES.wholeScript.readable);
  // The label rule on its own.
  for (const ok of ['τεστ', 'vault', 'v2-a', '例え', '韓國한국', 'コーヒー']) assert.equal(isReadableLabel(ok), true, ok);
  for (const bad of ['', 'com∕login', 'vauаlt', 'a_b', 'a b', 'abテ', 'τт', '例え한']) assert.equal(isReadableLabel(bad), false, JSON.stringify(bad));
});

test('where a person confirms which server this is, the ASCII form is shown beside a readable one', () => {
  assert.equal(addressWithAscii(GREEK_ASCII), `${GREEK} (${GREEK_ASCII})`);
  assert.equal(addressWithAscii(`${GREEK_ASCII}:8290`), `${GREEK}:8290 (${GREEK_ASCII}:8290)`, 'the port in both spellings');
  assert.equal(addressWithAscii(LOOKALIKES.wholeScript.ascii), `${LOOKALIKES.wholeScript.readable} (${LOOKALIKES.wholeScript.ascii})`);
  // A look-alike that is not shown readable, and a plain name, have one spelling: no brackets.
  assert.equal(addressWithAscii(LOOKALIKES.slash.ascii), LOOKALIKES.slash.ascii);
  assert.equal(addressWithAscii(`${LOOKALIKES.mixed.ascii}:443`), `${LOOKALIKES.mixed.ascii}:443`);
  for (const plain of ['vault.example.com', 'localhost:8290', '[::1]:8290', '10.0.0.5', '']) assert.equal(addressWithAscii(plain), plain);
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

test('the setup verify: every connection uses the ASCII host, every sentence gets the readable one with the ASCII one beside it, the endpoint to save is ASCII', async () => {
  const { asked, httpJson, probeSftp } = fakes();
  const v = await verifySetup({ input: 'ΤΕΣΤ:8290', sftp: `${GREEK}:2322` }, { httpJson, probeSftp });
  assert.deepEqual(asked.http, [`https://${GREEK_ASCII}:8290/health`, `https://${GREEK_ASCII}:8290/devices`]);
  assert.deepEqual(asked.sftp, [{ host: GREEK_ASCII, port: 2322 }]);
  assert.deepEqual(v.api, { kind: 'ok', host: `${GREEK}:8290 (${GREEK_ASCII}:8290)` });
  assert.deepEqual(v.sftp, { kind: 'ok', host: GREEK, ascii: GREEK_ASCII, port: 2322, fingerprint: 'SHA256:fp' });
  assert.deepEqual(v.endpoint, { host: GREEK_ASCII, port: 2322 });
  assert.equal(v.origin, `https://${GREEK_ASCII}:8290`);
});

test('the setup verify on a look-alike name: the server light never shows it without its ASCII form', async () => {
  for (const { readable, ascii } of Object.values(LOOKALIKES)) {
    const { httpJson, probeSftp } = fakes();
    const v = await verifySetup({ input: readable, sftp: `${readable}:2322` }, { httpJson, probeSftp });
    assert.equal(v.origin, `https://${ascii}`, 'connected to the host the name really is');
    assert.ok(v.api.host.includes(ascii), `${v.api.host}: the ASCII form is on the server light`);
    assert.ok(v.sftp.host === ascii || v.sftp.ascii === ascii, 'and on the SFTP light');
  }
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
  // A landing written wholly in one script (it would have a readable form) is still shown in the ASCII form alone,
  // while the name the person typed keeps its readable form with the ASCII one beside it.
  const cyrillic = async (url) => (url.endsWith('/health')
    ? { ok: true, status: 200, url: `https://${LOOKALIKES.wholeScript.ascii}/health`, json: async () => ({ status: 'healthy' }) }
    : { ok: false, status: 401, json: async () => ({}) });
  const w = await verifySetup({ input: GREEK, sftp: '' }, { httpJson: cyrillic, probeSftp: fakes().probeSftp });
  assert.deepEqual(w.api, { kind: 'ok', host: LOOKALIKES.wholeScript.ascii, from: `${GREEK} (${GREEK_ASCII})` });
});

test('the saved setting, the setup screen and a connect: a Greek name is saved in the ASCII form and shown readable again', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-idn-'));
  try {
    const { httpJson, probeSftp } = fakes();
    const setup = createServerSetup({ dir, httpJson, probeSftp, schedule: (fn) => fn() });
    const out = await setup.connect({ input: GREEK, sftp: `${GREEK}:2322` });
    assert.equal(out.kind, 'ok');
    assert.equal(out.host, `${GREEK} (${GREEK_ASCII})`, 'the Connected line says what was typed, and the name the network uses');
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
    assert.equal(facts[0].value, `${GREEK}:8443 (${GREEK_ASCII}:8443)`, 'readable, with the ASCII form and its port beside it for comparison');
    assert.equal(facts[1].value, `${GREEK}:2322 (${GREEK_ASCII}:2322)`);
    const r = await view.probe('server-connection');
    assert.equal(asked.http[0], `https://${GREEK_ASCII}:8443/health`);
    assert.deepEqual(asked.sftp, [{ host: GREEK_ASCII, port: 2322 }]);
    assert.ok(r.legs[0].text.startsWith(`${GREEK}:8443 (${GREEK_ASCII}:8443) answered as a DockVault server`), r.legs[0].text);
    assert.ok(r.legs[1].text.startsWith(`${GREEK}:2322 (${GREEK_ASCII}:2322) answered as an SFTP server`), r.legs[1].text);
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
    // A look-alike SFTP host, shown in the walk-through in its ASCII form, turns back into that very host.
    for (const { ascii } of Object.values(LOOKALIKES)) assert.equal(toAsciiHost(toDisplayHost(ascii)), ascii);
  } finally { fs.rmSync(dir, { recursive: true, force: true }); }
});

// The wiring in main that no module test reaches: the switch-server prompt and the walk-through's other server
// name the server with its ASCII form beside a readable one; the setup screen's pre-fill (a field, which holds an
// address, not a note) is the readable form alone; the Computers page gets the ASCII forms and makes the display
// itself (manage-view.js, tested there).
test('main names the server with its ASCII form beside it on the switch-server prompt and in the walk-through', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'main', 'index.js'), 'utf8');
  const once = (anchor) => {
    const i = src.indexOf(anchor);
    assert.ok(i >= 0, `found: ${anchor}`);
    assert.equal(src.indexOf(anchor, i + 1), -1, `exactly once: ${anchor}`);
    return i;
  };
  const between = (from, to) => { const i = once(from); const j = src.indexOf(to, i + from.length); assert.ok(j > i, `${from} ... ${to}`); return src.slice(i, j); };
  const change = between('async function changeServer(', '\nasync function ');
  assert.match(change, /changeServerConsent\(hostName\.addressWithAscii\(asciiHost\)\)/);
  assert.match(change, /changeHost = hostName\.toDisplayAddress\(asciiHost\) \|\| null;/);
  assert.doesNotMatch(change, /changeServerConsent\((?!hostName\.addressWithAscii\()/, 'the prompt is given nothing else');
  const gather = between('    gather: async () => {', '\n    verifySftp:');
  assert.match(gather, /otherServerHost = hostName\.addressWithAscii\(serverProbe\.hostOf\(read\.otherOrigin\)\);/);
  assert.doesNotMatch(gather, /otherServerHost = hostName\.toDisplay/);
  const endpoint = between('    endpoint: () => ({', '\n    remotePathFor:');
  assert.doesNotMatch(endpoint, /toDisplay|WithAscii/, 'the Computers page is handed the ASCII forms');
});

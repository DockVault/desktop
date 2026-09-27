'use strict';

// The server check answers with one typed outcome per situation, degrades by the SHAPE of the health
// reply (never a version), never offers a way past an untrusted certificate, and leaks no error text.

const test = require('node:test');
const assert = require('node:assert/strict');

const { normalizeInput, probeServer, failureKind, plainHttpOrigin, plainHttpAddress, TLS_CODES, NO_TLS_CODES } = require('../src/main/server-probe');

const reply = (ok, status, body) => ({ ok, status, json: async () => { if (body === 'not json') throw new SyntaxError('x'); return body; } });
const fetchWith = (fn) => async (url, init) => fn(url, init);
const failWith = (code, message = 'boom') => async () => { const e = new Error(message); if (code) e.code = code; throw e; };

test('normalising: a bare host becomes https, a pasted URL keeps its port and drops its path', () => {
  assert.deepEqual(normalizeInput('vault.example.com'), { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com', isLoopback: false, schemeTyped: false });
  assert.equal(normalizeInput('  vault.example.com:8443/some/path?x=1  ').origin, 'https://vault.example.com:8443');
  assert.equal(normalizeInput('https://vault.example.com/login').origin, 'https://vault.example.com');
  assert.equal(normalizeInput('https://vault.example.com/login').schemeTyped, true, 'whether the person chose the scheme is kept');
  assert.equal(normalizeInput('HTTPS://Vault.Example.com').origin, 'https://vault.example.com');
  assert.deepEqual(normalizeInput(''), { kind: 'empty' });
  assert.deepEqual(normalizeInput(null), { kind: 'empty' });
});

test('normalising: plain http to a remote host is refused, loopback http is allowed, junk is malformed', () => {
  assert.deepEqual(normalizeInput('http://vault.example.com'), { kind: 'http-refused' });
  assert.equal(normalizeInput('http://localhost:8080').kind, 'ok');
  assert.equal(normalizeInput('http://localhost:8080').isLoopback, true);
  assert.deepEqual(normalizeInput('not a server'), { kind: 'malformed' });
  assert.deepEqual(normalizeInput('ftp://vault.example.com'), { kind: 'malformed' });
  assert.deepEqual(normalizeInput('https://'), { kind: 'malformed' });
});

test('a DockVault server answers ok, a degraded one answers degraded, and the request is GET /health', async () => {
  const calls = [];
  const httpJson = fetchWith((url, init) => { calls.push([url, init.method]); return reply(true, 200, { status: 'healthy', database: 'connected' }); });
  assert.deepEqual(await probeServer('vault.example.com', { httpJson }), { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com' });
  assert.deepEqual(calls, [['https://vault.example.com/health', 'GET']]);
  const degraded = fetchWith(() => reply(true, 200, { status: 'degraded', database: 'disconnected' }));
  assert.equal((await probeServer('vault.example.com', { httpJson: degraded })).kind, 'degraded');
});

test('something that answers but is not DockVault: non-2xx, no JSON, or a body without a health status', async () => {
  for (const r of [reply(false, 404, {}), reply(false, 500, { status: 'healthy' }), reply(true, 200, 'not json'), reply(true, 200, { hello: 'world' }), reply(true, 200, { status: 'up' }), reply(true, 200, null), reply(true, 200, 'text')]) {
    assert.equal((await probeServer('vault.example.com', { httpJson: fetchWith(() => r) })).kind, 'not-dockvault');
  }
});

test('an untrusted certificate is its own outcome, and there is no way to accept it', async () => {
  for (const code of ['DEPTH_ZERO_SELF_SIGNED_CERT', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'CERT_HAS_EXPIRED', 'ERR_TLS_CERT_ALTNAME_INVALID', 'SELF_SIGNED_CERT_IN_CHAIN']) {
    assert.ok(TLS_CODES.has(code));
    const r = await probeServer('vault.example.com', { httpJson: failWith(code) });
    assert.equal(r.kind, 'tls-untrusted');
    assert.deepEqual(Object.keys(r).sort(), ['host', 'kind', 'origin'], 'no error detail rides along');
  }
  // A wrapped cause carries the same code.
  const wrapped = async () => { const e = new Error('fetch failed'); e.cause = { code: 'CERT_HAS_EXPIRED' }; throw e; };
  assert.equal((await probeServer('vault.example.com', { httpJson: wrapped })).kind, 'tls-untrusted');
  const src = require('node:fs').readFileSync(require.resolve('../src/main/server-probe'), 'utf8');
  assert.doesNotMatch(src, /rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|insecure|bypass/i, 'nothing in the module can weaken certificate checks');
});

test('cannot reach it: name not found, refused, unreachable, or timed out', async () => {
  for (const code of ['ENOTFOUND', 'ECONNREFUSED', 'EHOSTUNREACH', 'ETIMEDOUT', 'EAI_AGAIN']) {
    assert.equal((await probeServer('vault.example.com', { httpJson: failWith(code) })).kind, 'unreachable');
  }
  assert.equal((await probeServer('vault.example.com', { httpJson: failWith(null, 'request timed out') })).kind, 'unreachable');
  assert.equal((await probeServer('vault.example.com', { httpJson: failWith(null, 'something odd') })).kind, 'unreachable', 'an unknown failure still reads as unreachable, never as a raw error');
});

test('the health check follows a redirect (it carries no credential) and the FINAL origin is what gets saved', async () => {
  const calls = [];
  const landing = async (url, init) => { calls.push([url, init.redirect, init.headers]); return { ok: true, status: 200, url: 'https://vault.example.org/health', json: async () => ({ status: 'healthy' }) }; };
  const r = await probeServer('vault.example.com', { httpJson: landing });
  assert.deepEqual(r, { kind: 'ok', origin: 'https://vault.example.org', host: 'vault.example.org', from: 'vault.example.com' }, 'the typed host rides along only when the landing host differs');
  const sameHost = async () => ({ ok: true, status: 200, url: 'https://vault.example.com/health/', json: async () => ({ status: 'healthy' }) });
  assert.deepEqual(await probeServer('vault.example.com', { httpJson: sameHost }), { kind: 'ok', origin: 'https://vault.example.com', host: 'vault.example.com' });
  assert.equal(calls[0][1], 'follow', 'the probe opts in');
  assert.equal(Object.keys(calls[0][2]).some((k) => /authorization/i.test(k)), false, 'and carries no bearer');
  // A redirect onto a port or path keeps the origin rules: port kept, path dropped.
  const withPort = async () => ({ ok: true, status: 200, url: 'https://vault.example.com:8443/api/health', json: async () => ({ status: 'healthy' }) });
  assert.equal((await probeServer('vault.example.com', { httpJson: withPort })).origin, 'https://vault.example.com:8443');
  // A redirect onto plain http off loopback is refused like a typed http address.
  const toHttp = async () => ({ ok: true, status: 200, url: 'http://vault.example.com/health', json: async () => ({ status: 'healthy' }) });
  assert.equal((await probeServer('vault.example.com', { httpJson: toHttp })).kind, 'http-refused');
  // No url on the reply (a fake or an old transport): the typed origin stands.
  const noUrl = async () => ({ ok: true, status: 200, json: async () => ({ status: 'healthy' }) });
  assert.equal((await probeServer('vault.example.com', { httpJson: noUrl })).origin, 'https://vault.example.com');
});

test('a redirect that cannot be followed to a landing is its own outcome, and Chromium network names map like Node codes', async () => {
  const refused = async () => { throw new TypeError("Attempted to redirect, but redirect policy was 'error'"); };
  assert.equal((await probeServer('vault.example.com', { httpJson: refused })).kind, 'redirected');
  const loop = async () => { throw new Error('too many redirects'); };
  assert.equal((await probeServer('vault.example.com', { httpJson: loop })).kind, 'redirected');
  for (const [msg, kind] of [['net::ERR_CERT_AUTHORITY_INVALID', 'tls-untrusted'], ['net::ERR_CERT_DATE_INVALID', 'tls-untrusted'], ['net::ERR_SSL_PROTOCOL_ERROR', 'tls-not-offered'], ['net::ERR_NAME_NOT_RESOLVED', 'unreachable'], ['net::ERR_CONNECTION_REFUSED', 'unreachable'], ['net::ERR_CONNECTION_TIMED_OUT', 'unreachable'], ['net::ERR_INTERNET_DISCONNECTED', 'unreachable']]) {
    const r = await probeServer('vault.example.com', { httpJson: failWith(null, msg) });
    assert.equal(r.kind, kind, msg);
    // A no-TLS answer also says whether the address is on this computer (it decides the sentence); nothing else rides along.
    assert.deepEqual(Object.keys(r).sort(), kind === 'tls-not-offered' ? ['host', 'kind', 'loopback', 'origin'] : ['host', 'kind', 'origin'], 'no error text rides along');
  }
});

// --- A server that answers without TLS is not a certificate problem ------------------------------------------

// Errors in the exact shapes the two transports produce. Node (fetch/undici) puts the OpenSSL code on the
// cause; node:https surfaces the same answer through a socket write as EPROTO with the reason only in the
// message; which reason depends on the OpenSSL version. Chromium (Electron's net, which the app uses) names
// every failure in the message as net::ERR_*.
const nodeFetchError = (code, reason) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(`C03B0000:error:0A0000C6:SSL routines:tls_get_more_records:${reason}:ssl/record/methods/tls_common.c:661:`), { code }) });
const nodeWriteError = (reason) => Object.assign(new Error(`write EPROTO 140:error:1408F10B:SSL routines:ssl3_get_record:${reason}:ssl/record/ssl3_record.c:332:`), { code: 'EPROTO' });
const nodeCertError = (code, message) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(message), { code }) });
const chromiumError = (name) => new Error(`net::${name}`);

test('the classifier: a plain-http answer is tls-not-offered in both Node and Chromium spellings, never tls-untrusted', () => {
  const noTls = [
    nodeFetchError('ERR_SSL_PACKET_LENGTH_TOO_LONG', 'packet length too long'), // OpenSSL 3.x, what Node 22 reports
    nodeFetchError('ERR_SSL_WRONG_VERSION_NUMBER', 'wrong version number'),     // OpenSSL 1.1 / 3.0
    nodeWriteError('wrong version number'),                                    // node:https, code EPROTO
    nodeWriteError('packet length too long'),
    // Node inside Electron, over BoringSSL: the same code, and the reason in capitals when only the message has it.
    nodeFetchError('ERR_SSL_WRONG_VERSION_NUMBER', 'WRONG_VERSION_NUMBER'),
    Object.assign(new Error('write EPROTO C0:error:100000f7:SSL routines:OPENSSL_internal:WRONG_VERSION_NUMBER:ssl/tls_record.cc:242:'), { code: 'EPROTO' }),
    chromiumError('ERR_SSL_PROTOCOL_ERROR'),                                   // Electron net.request / net.fetch
  ];
  for (const e of noTls) assert.equal(failureKind(e), 'tls-not-offered', e.message);
  // Without the reason, EPROTO stays what it always was: a transport failure.
  assert.equal(failureKind(Object.assign(new Error('write EPROTO'), { code: 'EPROTO' })), 'unreachable');
});

test('the classifier: each not-TLS code decides on its own, with no reason anywhere in the message', () => {
  // Written out rather than read from NO_TLS_CODES, so dropping a code from the set is caught here.
  for (const code of ['ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_PACKET_LENGTH_TOO_LONG', 'ERR_SSL_UNKNOWN_PROTOCOL']) {
    assert.equal(failureKind(Object.assign(new Error('boom'), { code })), 'tls-not-offered', `${code} on the error`);
    assert.equal(failureKind(Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error('boom'), { code }) })), 'tls-not-offered', `${code} on the cause`);
  }
});

test('the classifier: a server that DID speak TLS and then failed the handshake is never "not over HTTPS"', () => {
  // An alert or a refused protocol version comes from a TLS server: no retry over http may follow it.
  const nodeTlsFailure = (code, reason) => Object.assign(new TypeError('fetch failed'), { cause: Object.assign(new Error(`C03B0000:error:0A000410:SSL routines:ssl3_read_bytes:${reason}:ssl/record/rec_layer_s3.c:907:SSL alert number 40`), { code }) });
  const failures = [
    nodeTlsFailure('ERR_SSL_SSLV3_ALERT_HANDSHAKE_FAILURE', 'sslv3 alert handshake failure'),
    nodeTlsFailure('ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', 'tlsv1 alert protocol version'),
    nodeTlsFailure('ERR_SSL_TLSV1_ALERT_INTERNAL_ERROR', 'tlsv1 alert internal error'),
    nodeTlsFailure('ERR_SSL_UNSUPPORTED_PROTOCOL', 'unsupported protocol'),
    nodeTlsFailure('ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'no protocols available'),
    Object.assign(new Error('write EPROTO C0:error:0A000410:SSL routines:ssl3_read_bytes:sslv3 alert handshake failure:ssl/record/rec_layer_s3.c:907:'), { code: 'EPROTO' }),
    Object.assign(new Error('write EPROTO C0:error:10000410:SSL routines:OPENSSL_internal:SSLV3_ALERT_HANDSHAKE_FAILURE:ssl/tls_record.cc:592:'), { code: 'EPROTO' }),
    chromiumError('ERR_SSL_VERSION_OR_CIPHER_MISMATCH'),
    chromiumError('ERR_SSL_CLIENT_AUTH_CERT_NEEDED'),
    chromiumError('ERR_BAD_SSL_CLIENT_AUTH_CERT'),
  ];
  for (const e of failures) assert.notEqual(failureKind(e), 'tls-not-offered', (e.cause || e).message);
});

test('the classifier: a Chromium certificate name wins over the not-TLS name, wherever each appears', () => {
  const both = [
    Object.assign(chromiumError('ERR_SSL_PROTOCOL_ERROR'), { cause: chromiumError('ERR_CERT_AUTHORITY_INVALID') }),
    Object.assign(chromiumError('ERR_CERT_DATE_INVALID'), { cause: chromiumError('ERR_SSL_PROTOCOL_ERROR') }),
    new Error('net::ERR_SSL_PROTOCOL_ERROR after net::ERR_CERT_COMMON_NAME_INVALID'),
    // A not-TLS code or reason beside a certificate name: the certificate still decides.
    Object.assign(new Error('net::ERR_CERT_AUTHORITY_INVALID'), { code: 'ERR_SSL_WRONG_VERSION_NUMBER' }),
    Object.assign(new Error('write EPROTO SSL routines::wrong version number net::ERR_CERT_INVALID'), { code: 'EPROTO' }),
  ];
  for (const e of both) assert.equal(failureKind(e), 'tls-untrusted', e.message);
});

test('the classifier: every certificate problem is still tls-untrusted, in both spellings, and a certificate code wins', () => {
  const certs = [
    nodeCertError('DEPTH_ZERO_SELF_SIGNED_CERT', 'self-signed certificate'),
    nodeCertError('SELF_SIGNED_CERT_IN_CHAIN', 'self-signed certificate in certificate chain'),
    nodeCertError('UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'unable to verify the first certificate'),
    nodeCertError('CERT_HAS_EXPIRED', 'certificate has expired'),
    nodeCertError('ERR_TLS_CERT_ALTNAME_INVALID', "Hostname/IP does not match certificate's altnames"),
    chromiumError('ERR_CERT_AUTHORITY_INVALID'),   // self-signed or an unknown authority
    chromiumError('ERR_CERT_DATE_INVALID'),        // expired or not yet valid
    chromiumError('ERR_CERT_COMMON_NAME_INVALID'), // wrong name
    chromiumError('ERR_CERT_REVOKED'),
  ];
  for (const e of certs) assert.equal(failureKind(e), 'tls-untrusted', e.message || e.cause.message);
  // A certificate code decides even when a message also mentions a record problem.
  assert.equal(failureKind(nodeCertError('CERT_HAS_EXPIRED', 'SSL routines::wrong version number')), 'tls-untrusted');
  // A server that DID speak TLS but could not agree on it keeps its old outcome; only the not-TLS answer moved.
  assert.equal(failureKind(chromiumError('ERR_SSL_VERSION_OR_CIPHER_MISMATCH')), 'tls-untrusted');
  for (const code of NO_TLS_CODES) assert.equal(TLS_CODES.has(code), false, `${code} is not a certificate code`);
});

// A fake server: `https` decides what the https attempt does (a function that throws, or a health body), `http`
// likewise for plain http. Every URL asked is recorded.
function twoDoors({ https, http }) {
  const calls = [];
  const answer = (spec) => (typeof spec === 'function' ? spec() : { ok: true, status: 200, json: async () => spec });
  const httpJson = async (url) => {
    calls.push(url);
    return answer(url.startsWith('https:') ? https : http);
  };
  return { httpJson, calls };
}
const noTls = () => { throw chromiumError('ERR_SSL_PROTOCOL_ERROR'); };
const HEALTHY = { status: 'healthy' };

test('a server on this computer typed without a scheme that answers without TLS is asked once more over http on the same port, and saved as http', async () => {
  for (const [typed, https, http] of [
    ['localhost:8290', 'https://localhost:8290/health', 'http://localhost:8290/health'],
    ['127.0.0.1:8290', 'https://127.0.0.1:8290/health', 'http://127.0.0.1:8290/health'],
    ['[::1]:8290', 'https://[::1]:8290/health', 'http://[::1]:8290/health'],
    ['LocalHost:8290/some/path', 'https://localhost:8290/health', 'http://localhost:8290/health'],
    // No port typed: the server that answered on 443 is the one asked again, not whatever is on port 80.
    ['localhost', 'https://localhost/health', 'http://localhost:443/health'],
  ]) {
    const { httpJson, calls } = twoDoors({ https: noTls, http: HEALTHY });
    const r = await probeServer(typed, { httpJson });
    assert.deepEqual(calls, [https, http], typed);
    assert.equal(r.kind, 'ok', typed);
    assert.equal(r.origin, new URL(http).origin, typed);
    assert.equal(r.plainHttp, true, 'the screen is told plain http was used');
    assert.equal(r.from, undefined, 'the same server over http is not a redirect');
  }
  // Node's spelling of the same answer takes the same path.
  const node = twoDoors({ https: () => { throw nodeFetchError('ERR_SSL_PACKET_LENGTH_TOO_LONG', 'packet length too long'); }, http: { status: 'degraded' } });
  const d = await probeServer('127.0.0.1:8290', { httpJson: node.httpJson });
  assert.deepEqual([d.kind, d.origin, d.plainHttp], ['degraded', 'http://127.0.0.1:8290', true]);
});

test('the http retry is never taken for a remote address, nor for an address typed with a scheme, nor for any other failure', async () => {
  const neverRetried = [
    'vault.example.com:8290', 'vault.example.com', 'https://vault.example.com:8290', '192.168.1.20:8290', 'localhost.example.com:8290',
    // Names built to read as this computer while naming another one, or to slip a second host past the parser.
    'localhost.evil.example', '127.0.0.1.nip.io', 'localhost.:8290', 'localhost..:8290', 'localhost@evil.example:8290',
    'localhost:8290@evil.example', 'localhost%2eevil.example', '[::ffff:127.0.0.1]', '127.0.0.2', 'http:/localhost:8290',
  ];
  for (const typed of neverRetried) {
    const { httpJson, calls } = twoDoors({ https: noTls, http: HEALTHY });
    const r = await probeServer(typed, { httpJson });
    assert.equal(calls.length, 1, `${typed}: one request, over https only`);
    assert.ok(calls[0].startsWith('https://'), typed);
    assert.deepEqual([r.kind, r.loopback], ['tls-not-offered', false], typed);
    assert.ok(r.origin.startsWith('https://'), typed);
    assert.equal('plainHttpAddress' in r, false, `${typed}: no plain-http suggestion for another computer`);
  }
  // Spellings that ARE this computer are retried, and the retry only ever goes to this computer.
  const LOOPBACK_HTTP = /^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\]):\d+\/health$/;
  const thisComputer = ['LOCALHOST', 'evil.example@localhost', '[0:0:0:0:0:0:0:1]', '127.1', '2130706433', '0x7f000001',
    'ｌｏｃａｌｈｏｓｔ', 'ⓛⓞⓒⓐⓛⓗⓞⓢⓣ', 'local\thost'];
  for (const typed of thisComputer) {
    const { httpJson, calls } = twoDoors({ https: noTls, http: HEALTHY });
    const r = await probeServer(typed, { httpJson });
    assert.equal(calls.length, 2, JSON.stringify(typed));
    assert.match(calls[1], LOOPBACK_HTTP, JSON.stringify(typed));
    assert.deepEqual([r.kind, r.plainHttp], ['ok', true], JSON.stringify(typed));
  }
  // A scheme the person typed is kept, on this computer too.
  for (const typed of ['https://localhost:8290', 'https://127.0.0.1:8290', 'https://[::1]:8290']) {
    const { httpJson, calls } = twoDoors({ https: noTls, http: HEALTHY });
    const r = await probeServer(typed, { httpJson });
    assert.equal(calls.length, 1, typed);
    assert.deepEqual([r.kind, r.loopback], ['tls-not-offered', true], typed);
    assert.ok(r.origin.startsWith('https://'), 'nothing is saved over http that the person did not choose');
  }
  // On this computer, a certificate problem or a closed port is not a reason to drop to http.
  for (const fail of [() => { throw chromiumError('ERR_CERT_AUTHORITY_INVALID'); }, () => { throw nodeCertError('DEPTH_ZERO_SELF_SIGNED_CERT', 'self-signed certificate'); }, () => { throw chromiumError('ERR_CONNECTION_REFUSED'); }, () => { throw Object.assign(new Error('connect ECONNREFUSED'), { code: 'ECONNREFUSED' }); }]) {
    const { httpJson, calls } = twoDoors({ https: fail, http: HEALTHY });
    const r = await probeServer('localhost:8290', { httpJson });
    assert.equal(calls.length, 1);
    assert.notEqual(r.kind, 'ok');
    assert.ok(r.origin.startsWith('https://'));
  }
});

test('the http retry: only a DockVault answer is taken; anything else keeps the https outcome and its plain-http suggestion', async () => {
  const TYPED_OUTCOME = { kind: 'tls-not-offered', origin: 'https://localhost:8290', host: 'localhost:8290', loopback: true, plainHttpAddress: 'http://localhost:8290' };
  const redirectTo = (landing) => () => ({ ok: true, status: 200, url: landing, json: async () => HEALTHY });
  const answers = {
    'nothing on http': () => { throw chromiumError('ERR_CONNECTION_REFUSED'); },
    'no TLS on http either': noTls,
    'not DockVault': () => ({ ok: true, status: 200, json: async () => ({ hello: 'world' }) }),
    'an error status': () => ({ ok: false, status: 400, json: async () => ({}) }),
    // A redirect onto plain http on another computer: never "Change http:// to https://" for an address the
    // person typed without http://.
    'a redirect onto remote http': redirectTo('http://vault.example.com/health'),
    'a redirect onto something that is not an address': redirectTo('ftp://localhost/health'),
    'a redirect that cannot be followed': () => { throw new TypeError('fetch failed: redirect count exceeded'); },
    'a redirect onto https with a certificate problem': () => { throw chromiumError('ERR_CERT_AUTHORITY_INVALID'); },
    'a timeout': () => { throw Object.assign(new Error('The operation was aborted due to timeout'), { name: 'TimeoutError' }); },
  };
  for (const [what, http] of Object.entries(answers)) {
    const { httpJson, calls } = twoDoors({ https: noTls, http });
    const r = await probeServer('localhost:8290', { httpJson });
    assert.deepEqual(calls, ['https://localhost:8290/health', 'http://localhost:8290/health'], what);
    assert.deepEqual(r, TYPED_OUTCOME, what);
  }
  // A local http server that redirects to another local http origin: said against what the person typed.
  const moved = async (url) => {
    if (url.startsWith('https:')) noTls();
    return { ok: true, status: 200, url: 'http://127.0.0.1:9000/health', json: async () => HEALTHY };
  };
  const c = await probeServer('localhost:8290', { httpJson: moved });
  assert.deepEqual(c, { kind: 'ok', origin: 'http://127.0.0.1:9000', host: '127.0.0.1:9000', from: 'localhost:8290', plainHttp: true });
  // A local http server that sends the check on to https: saved over https, and plain http is not mentioned.
  const upgraded = async (url) => {
    if (url.startsWith('https://localhost:8290')) noTls();
    return { ok: true, status: 200, url: 'https://localhost:9443/health', json: async () => ({ status: 'degraded' }) };
  };
  const u = await probeServer('localhost:8290', { httpJson: upgraded });
  assert.deepEqual(u, { kind: 'degraded', origin: 'https://localhost:9443', host: 'localhost:9443', from: 'localhost:8290' });
  assert.equal('plainHttp' in u, false, 'an https landing never carries plainHttp');
});

test('the plain-http suggestion names the server that answered: the same host, over http, with its port written out', async () => {
  assert.equal(plainHttpAddress('https://localhost'), 'http://localhost:443', 'a typed "localhost" answered on 443, not 80');
  assert.equal(plainHttpAddress('https://localhost:8290'), 'http://localhost:8290');
  assert.equal(plainHttpAddress('https://127.0.0.1:80'), 'http://127.0.0.1:80', 'the port is written out even where http would imply it');
  assert.equal(plainHttpAddress('https://[::1]'), 'http://[::1]:443');
  for (const remote of ['https://vault.example.com', 'https://192.168.1.20:8290', 'http://localhost:8290', 'not a url', '']) {
    assert.equal(plainHttpAddress(remote), null, remote);
  }
  // Through the probe: typed without a port and without a scheme, the retry found nothing; the suggestion is 443.
  const { httpJson } = twoDoors({ https: noTls, http: () => { throw chromiumError('ERR_CONNECTION_REFUSED'); } });
  assert.equal((await probeServer('localhost', { httpJson })).plainHttpAddress, 'http://localhost:443');
  // Typed with https:// there is no retry, and the suggestion keeps the port that was typed.
  const typed = twoDoors({ https: noTls, http: HEALTHY });
  assert.equal((await probeServer('https://127.0.0.1:8290', { httpJson: typed.httpJson })).plainHttpAddress, 'http://127.0.0.1:8290');
  // A remote address gets no plain-http suggestion at all.
  const remote = twoDoors({ https: noTls, http: HEALTHY });
  assert.equal('plainHttpAddress' in (await probeServer('vault.example.com:8290', { httpJson: remote.httpJson })), false);
});

test('the plain-http address is only ever built for this computer', () => {
  assert.equal(plainHttpOrigin('https://localhost:8290'), 'http://localhost:8290');
  assert.equal(plainHttpOrigin('https://[::1]'), 'http://[::1]:443');
  for (const remote of ['https://vault.example.com', 'https://192.168.1.20:8290', 'http://localhost:8290', 'not a url', '']) {
    assert.equal(plainHttpOrigin(remote), null, remote);
  }
});

test('a refused or malformed address never reaches the network', async () => {
  let called = 0;
  const httpJson = fetchWith(() => { called++; return reply(true, 200, { status: 'healthy' }); });
  assert.equal((await probeServer('http://vault.example.com', { httpJson })).kind, 'http-refused');
  assert.equal((await probeServer('nope nope', { httpJson })).kind, 'malformed');
  assert.equal((await probeServer('', { httpJson })).kind, 'empty');
  assert.equal(called, 0);
});

test('a REMOTE address whose health check redirects onto a loopback http origin is refused as redirected; a typed loopback address may still land on loopback http', async () => {
  const { probeServer } = require('../src/main/server-probe');
  const landing = async (url) => ({ ok: true, status: 200, url: 'http://127.0.0.1:8080/health', json: async () => ({ status: 'healthy' }) });
  const remote = await probeServer('https://front.example.com', { httpJson: landing });
  assert.deepEqual(remote, { kind: 'redirected', origin: 'https://front.example.com', host: 'front.example.com' });
  const local = await probeServer('http://localhost:9000', { httpJson: landing });
  assert.equal(local.kind, 'ok');
  assert.equal(local.origin, 'http://127.0.0.1:8080');
});

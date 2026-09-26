'use strict';

/*
 * Verifies a server address before it is saved: normalise what the person typed, ask the server's
 * unauthenticated health route, and answer with ONE typed outcome the setup screen renders. Pure:
 * the request function is injected (main passes its JSON helper, which carries the 15-second timeout
 * and the response-size cap), so every branch is testable without a network.
 *
 * Outcomes (kind):
 *   empty           nothing typed
 *   http-refused    a remote address over plain http — DockVault connects over https only (loopback
 *                   http stays allowed for local testing, as server-config already permits)
 *   malformed       not a server address at all
 *   unreachable     name not found, connection refused, host unreachable, or the request timed out
 *   tls-untrusted   the certificate is not trusted by this computer — there is deliberately NO way to
 *                   accept it here; the answer is to install the certificate on this computer
 *   tls-not-offered something answered on that port, but not over TLS (a plain-http server asked for
 *                   https). No certificate was presented, so this is never reported as an untrusted one.
 *                   For an address on this computer typed WITHOUT a scheme, the check is retried once over
 *                   plain http on the same port (loopback http is allowed, as server-config permits); a
 *                   remote address is never retried over http, and neither is one typed with a scheme.
 *                   `loopback` rides along so the screen can say which of the two applies
 *   redirected      the address answers but points elsewhere and the landing could not be reached (the
 *                   check follows a redirect to find the real address; only a chain that never lands,
 *                   or a transport that refuses, ends here), or a REMOTE address redirected onto a
 *                   loopback http origin — the plain-http allowance is for an address the person typed
 *                   for a local server, never for where a remote server chose to send them
 *   not-dockvault   something answered, but not with the DockVault health object
 *   degraded        a DockVault server that reports a problem — still reachable, so the person proceeds
 *   ok              a DockVault server
 * An ok or degraded answer reached through that one http retry carries `plainHttp`, so the screen can say
 * plain http is in use: the person did not choose it.
 *
 * The check degrades by SHAPE (is the health object there, what does its status say), never by a
 * version: the health route carries none, and the version requirement is checked after sign-in
 * where it already lives. No error text, path, or certificate detail ever leaves this module —
 * only the kind, the normalised origin, and its host for the copy.
 *
 * Host names travel in their ASCII form (a name typed in another script is converted by the URL parser, as
 * an address bar converts it); the readable form is made for the screen only, in setup-verify.js.
 */

const { normalizeServer } = require('./server-config');
const { KNOWN_NETWORK_CODES } = require('./net-errors');

// The certificate-trust failures Node reports for a server this computer does not trust.
const TLS_CODES = new Set([
  'DEPTH_ZERO_SELF_SIGNED_CERT', 'SELF_SIGNED_CERT_IN_CHAIN', 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY', 'UNABLE_TO_GET_ISSUER_CERT', 'CERT_HAS_EXPIRED', 'CERT_NOT_YET_VALID',
  'ERR_TLS_CERT_ALTNAME_INVALID', 'CERT_UNTRUSTED', 'CERT_REVOKED',
]);

const HEALTH_STATUSES = new Set(['healthy', 'degraded']);

function hostOf(origin) {
  try { return new URL(origin).host; } catch { return origin; }
}

// What the person typed, as the origin that will be used: a bare host gets https:// in front, a pasted
// URL keeps its port and loses its path. Returns { kind: 'ok', origin, host, isLoopback, schemeTyped } or a
// typed refusal. `schemeTyped` records whether the person chose the scheme: only when they did not may an
// address on this computer fall back to plain http.
function normalizeInput(input) {
  const typed = String(input == null ? '' : input).trim();
  if (!typed) return { kind: 'empty' };
  const hasScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(typed);
  const candidate = hasScheme ? typed : `https://${typed}`;
  let normalized;
  try { normalized = normalizeServer(candidate); } catch (e) {
    // Only the "remote server over plain http" refusal is the person's fixable mistake; an unknown
    // scheme or an unparsable value is simply not an address.
    return { kind: /remote server must use https/.test(String(e && e.message)) ? 'http-refused' : 'malformed' };
  }
  return { kind: 'ok', origin: normalized.origin, host: hostOf(normalized.origin), isLoopback: normalized.isLoopback, schemeTyped: hasScheme };
}

// The same address over plain http, on the SAME port the https attempt used (443 when none was typed): the
// server that answered without TLS is the one asked again, not whatever listens on port 80. Built only for
// a loopback origin — and normalizeServer refuses plain http anywhere else, so nothing built here can
// reach off this computer.
function plainHttpOrigin(httpsOrigin) {
  try {
    const u = new URL(httpsOrigin);
    if (u.protocol !== 'https:') return null;
    const n = normalizeServer(`http://${u.hostname}:${u.port || '443'}`);
    return n.isLoopback ? n.origin : null;
  } catch { return null; }
}

function errorCode(e) {
  if (!e) return null;
  if (typeof e.code === 'string') return e.code;
  if (e.cause && typeof e.cause.code === 'string') return e.cause.code;
  return null;
}

// An answer that was not TLS at all: the first bytes back were not a TLS record, which is what a plain-http
// server sends when it is asked for https (its "400 Bad Request" reads as a record with a wrong version or
// an impossible length). OpenSSL, under Node, names it by a code on the error or its cause (which code
// depends on the OpenSSL version) or, when it surfaces through a socket write, only in the message, under
// EPROTO; the BoringSSL inside Electron's own Node writes the reason in capitals with underscores. None of
// these is a certificate problem: no certificate was ever presented.
const NO_TLS_CODES = new Set(['ERR_SSL_WRONG_VERSION_NUMBER', 'ERR_SSL_PACKET_LENGTH_TOO_LONG', 'ERR_SSL_UNKNOWN_PROTOCOL']);
const NO_TLS_MESSAGE = /SSL routines:[^\n]*(?:wrong[ _]version[ _]number|packet[ _]length[ _]too[ _]long|unknown[ _]protocol)/i;

// Chromium's network layer (Electron's net, which trusts the operating system's certificate store like
// the rest of the app) reports failures as `net::ERR_*` names in the error message rather than codes.
// It folds the not-TLS answer into ERR_SSL_PROTOCOL_ERROR, its name for a TLS record it cannot parse. Its
// certificate failures are all ERR_CERT_* and never that name, so taking it out of the certificate bucket
// cannot hide a certificate problem. The other ERR_SSL_* names (a version or cipher mismatch, a demand for
// a client certificate, a pinning failure) come from a server that did speak TLS and stay where they were.
const CHROMIUM_NO_TLS = /ERR_SSL_PROTOCOL_ERROR/;
const CHROMIUM_TLS = /ERR_CERT_|ERR_SSL_|CERT_/;
const CHROMIUM_UNREACHABLE = /ERR_NAME_NOT_RESOLVED|ERR_CONNECTION_REFUSED|ERR_CONNECTION_TIMED_OUT|ERR_CONNECTION_RESET|ERR_CONNECTION_CLOSED|ERR_ADDRESS_UNREACHABLE|ERR_INTERNET_DISCONNECTED|ERR_NETWORK_CHANGED|ERR_TIMED_OUT|ERR_CONNECTION_ABORTED|ERR_NAME_RESOLUTION_FAILED|ERR_EMPTY_RESPONSE/;

// One typed word for any failure to reach the health route, from Node codes or Chromium names. A
// certificate code is checked first and wins over everything else.
function failureKind(e) {
  const code = errorCode(e);
  if (code && TLS_CODES.has(code)) return 'tls-untrusted';
  if (code && NO_TLS_CODES.has(code)) return 'tls-not-offered';
  const text = String((e && e.message) || '') + ' ' + String((e && e.cause && e.cause.message) || '');
  // Before the network codes: Node reports the same answer as EPROTO, which alone reads as a transport failure.
  if (NO_TLS_MESSAGE.test(text)) return 'tls-not-offered';
  if (code && KNOWN_NETWORK_CODES.has(code)) return 'unreachable';
  if (CHROMIUM_NO_TLS.test(text)) return 'tls-not-offered';
  if (CHROMIUM_TLS.test(text)) return 'tls-untrusted';
  if (CHROMIUM_UNREACHABLE.test(text)) return 'unreachable';
  if (/timed out|TimeoutError|aborted/i.test(text) || (e && e.name === 'TimeoutError')) return 'unreachable';
  // The health check follows a redirect to find where the server really is; one that cannot be followed
  // to a landing (too many hops, or a transport that refuses) is reported as such, not as "unreachable":
  // the address answered, it just points elsewhere.
  if (/redirect/i.test(text)) return 'redirected';
  // Anything else is still "we could not reach it" to the person; the copy never shows the reason.
  return 'unreachable';
}

/**
 * @param {string} input          what the person typed
 * @param {{ httpJson: (url: string, init?: object) => Promise<{ ok: boolean, status: number, json: () => Promise<any> }> }} deps
 * @returns {Promise<{ kind: string, origin?: string, host?: string, from?: string, loopback?: boolean }>}
 */
async function probeServer(input, { httpJson }) {
  const n = normalizeInput(input);
  if (n.kind !== 'ok') return n;
  const first = await probeOrigin(n, { httpJson });
  if (first.kind !== 'tls-not-offered') return first;
  // The server answered without TLS. On this computer, for an address typed without a scheme, that is a
  // local server on plain http: it is asked once more over http on the same port. Its answer is taken when
  // something answered at all (a DockVault server, or one that says what did answer); otherwise the https
  // outcome stands. A remote address, or one typed with a scheme, is never retried.
  const plain = n.isLoopback && !n.schemeTyped ? plainHttpOrigin(n.origin) : null;
  if (!plain) return { ...first, loopback: n.isLoopback === true };
  const second = await probeOrigin({ origin: plain, host: hostOf(plain), isLoopback: true }, { httpJson });
  if (second.kind === 'unreachable' || second.kind === 'tls-not-offered') return { ...first, loopback: true };
  // A redirect is said against what the person typed, not against the http spelling of it: a portless
  // "localhost" asked again on its port is the same server, not a redirect.
  delete second.from;
  if (second.host !== n.host && second.origin !== plain) second.from = n.host;
  // The person did not choose plain http; the screen says it was used.
  if ((second.kind === 'ok' || second.kind === 'degraded') && /^http:/i.test(second.origin)) second.plainHttp = true;
  return second;
}

// One health check against one normalised origin: `n` carries the origin, its host, and whether the address
// is on this computer (which decides whether a landing on plain http is accepted).
async function probeOrigin(n, { httpJson }) {
  let { origin, host } = n;
  let res;
  try {
    // The health check carries no credential, so it may follow a redirect (a front that sends /health
    // elsewhere, a host that redirects to its canonical name); the FINAL origin is what gets saved, so
    // every later, credential-bearing call goes there directly and never meets the redirect itself.
    res = await httpJson(`${origin}/health`, { method: 'GET', headers: { Accept: 'application/json' }, redirect: 'follow' });
  } catch (e) {
    return { kind: failureKind(e), origin, host };
  }
  if (res && typeof res.url === 'string' && res.url) {
    let landed;
    try { landed = normalizeServer(new URL(res.url).origin); } catch (e) {
      // A redirect onto plain http (off loopback) is refused like a typed http address would be.
      return { kind: /remote server must use https/.test(String(e && e.message)) ? 'http-refused' : 'malformed', origin, host };
    }
    // A remote https address that sends the check to a loopback http origin is refused: the loopback
    // allowance exists for a local server the person typed, not for a landing a remote server chose.
    if (landed.origin !== origin && /^http:/i.test(landed.origin) && !n.isLoopback) return { kind: 'redirected', origin, host };
    origin = landed.origin;
    host = hostOf(origin);
  }
  if (!res || res.ok !== true) return { kind: 'not-dockvault', origin, host };
  let body;
  try { body = await res.json(); } catch { return { kind: 'not-dockvault', origin, host }; }
  if (!body || typeof body !== 'object' || !HEALTH_STATUSES.has(body.status)) return { kind: 'not-dockvault', origin, host };
  const outcome = { kind: body.status === 'degraded' ? 'degraded' : 'ok', origin, host };
  // When a redirect changed the host, say where the person was sent: the change must be unmissable.
  if (host !== n.host) outcome.from = n.host;
  return outcome;
}

module.exports = { normalizeInput, probeServer, failureKind, plainHttpOrigin, TLS_CODES, NO_TLS_CODES, hostOf };

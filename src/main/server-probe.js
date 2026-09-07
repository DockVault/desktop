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
 *   redirected      the address answers but points elsewhere and the landing could not be reached (the
 *                   check follows a redirect to find the real address; only a chain that never lands,
 *                   or a transport that refuses, ends here)
 *   not-dockvault   something answered, but not with the DockVault health object
 *   degraded        a DockVault server that reports a problem — still reachable, so the person proceeds
 *   ok              a DockVault server
 *
 * The check degrades by SHAPE (is the health object there, what does its status say), never by a
 * version: the health route carries none, and the version requirement is checked after sign-in
 * where it already lives. No error text, path, or certificate detail ever leaves this module —
 * only the kind, the normalised origin, and its host for the copy.
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
// URL keeps its port and loses its path. Returns { kind: 'ok', origin, host } or a typed refusal.
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
  return { kind: 'ok', origin: normalized.origin, host: hostOf(normalized.origin), isLoopback: normalized.isLoopback };
}

function errorCode(e) {
  if (!e) return null;
  if (typeof e.code === 'string') return e.code;
  if (e.cause && typeof e.cause.code === 'string') return e.cause.code;
  return null;
}

// Chromium's network layer (Electron's net, which trusts the operating system's certificate store like
// the rest of the app) reports failures as `net::ERR_*` names in the error message rather than codes.
const CHROMIUM_TLS = /ERR_CERT_|ERR_SSL_|CERT_/;
const CHROMIUM_UNREACHABLE = /ERR_NAME_NOT_RESOLVED|ERR_CONNECTION_REFUSED|ERR_CONNECTION_TIMED_OUT|ERR_CONNECTION_RESET|ERR_CONNECTION_CLOSED|ERR_ADDRESS_UNREACHABLE|ERR_INTERNET_DISCONNECTED|ERR_NETWORK_CHANGED|ERR_TIMED_OUT|ERR_CONNECTION_ABORTED|ERR_NAME_RESOLUTION_FAILED|ERR_EMPTY_RESPONSE/;

// One typed word for any failure to reach the health route, from Node codes or Chromium names.
function failureKind(e) {
  const code = errorCode(e);
  if (code && TLS_CODES.has(code)) return 'tls-untrusted';
  if (code && KNOWN_NETWORK_CODES.has(code)) return 'unreachable';
  const text = String((e && e.message) || '') + ' ' + String((e && e.cause && e.cause.message) || '');
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
 * @returns {Promise<{ kind: string, origin?: string, host?: string }>}
 */
async function probeServer(input, { httpJson }) {
  const n = normalizeInput(input);
  if (n.kind !== 'ok') return n;
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

module.exports = { normalizeInput, probeServer, TLS_CODES, hostOf };

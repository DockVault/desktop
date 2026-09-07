'use strict';

/*
 * The device-Bearer HTTP client for the DEVICE sync routes.
 *
 * A registered device authenticates to the vault's device routes with its opaque secret as an HTTP
 * Bearer — a DISTINCT credential domain from the account JWT the web/account session uses. This client
 * attaches ONLY the device secret and reaches ONLY the three device routes; it is the transport the
 * mint, refresh, and grant-listing slices build on.
 *
 * Two guardrails beyond the transport:
 *   - a fixed ROUTE ALLOWLIST: a caller names a LOGICAL route ('mint' | 'refresh' | 'grants'); the
 *     method + path are fixed here and never caller-supplied, and any other name is refused LOCALLY
 *     before any network call — client-side enforcement of the negative space, defence in depth over the
 *     server's own route boundary. The client can never be aimed at an account/admin/arbitrary URL.
 *   - NEVER-LOGGED: the device secret rides in the Authorization header, so no request header, request
 *     body, or response text is ever placed in a thrown error or a log line. A failure carries only the
 *     HTTP status and, when the server sent one, a reason mapped to a FIXED LITERAL — never the raw body,
 *     never the header, never the secret.
 */

const { transportCode, isTransportError } = require('./net-errors'); // the one transport classifier owns both

// The ONLY device routes this client may reach. Method + path are fixed here; the caller supplies only a
// logical name, so the client cannot construct an arbitrary path.
const ROUTES = Object.freeze({
  mint: Object.freeze({ method: 'POST', path: '/device/sync-credential' }),
  refresh: Object.freeze({ method: 'POST', path: '/device/refresh' }),
  grants: Object.freeze({ method: 'GET', path: '/device/grants' }),
});

// Known server refusal reasons (detail.reason on a device route). Anything absent from this set (a new
// or unexpected reason, or none at all) becomes UNKNOWN_REFUSAL — an unknown reason is NEVER guessed
// retryable. This only CLASSIFIES to a fixed literal; retryability is the caller's decision per literal,
// so e.g. a 409 cap and a 503 host-key never collapse into a single retryable "failed".
const KNOWN_REASONS = Object.freeze([
  'invalid-device-credential', 'device-revoked', 'device-suspended', 'device-expired',
  'device-secret-stale', 'account-inactive', 'no-grant', 'vault-not-standard',
  'grant-needs-reproof', 'device-cred-cap', 'host-key-unavailable',
]);
const UNKNOWN_REFUSAL = 'device-request-refused'; // fail-closed default: the caller treats it as non-retrying
const SERVER_ERROR = 'server-error';              // a 5xx: the server (or a proxy in front of it) failed, not a refusal — retryable
const NETWORK_FAILURE = 'network';                // a transport error (offline / DNS / TLS / timeout); status 0
const ROUTE_NOT_ALLOWED = 'route-not-allowed';    // a local allowlist refusal (a caller bug); no network happened
const NO_DEVICE_SECRET = 'no-device-secret';      // a local refusal: nothing to present; no network happened
const INTERNAL_ERROR = 'internal-error';          // a NON-transport throw inside the injected fetchFn (a bug / broken contract): status 0, our own fault — never a retryable network reason

class DeviceRequestError extends Error {
  constructor(status, reason, code) {
    // The message carries ONLY the status and the mapped reason literal — never a header, body, URL, or
    // the secret — so a device request failure can never leak the Bearer secret into a log or a stack.
    super(`device request failed: status=${status} reason=${reason}`);
    this.name = 'DeviceRequestError';
    this.status = status; // HTTP status, or 0 for a local/transport failure
    this.reason = reason; // a fixed literal (a KNOWN_REASONS value, or one of the sentinels above)
    // For a transport failure only: the platform's error code (ECONNREFUSED, ENOTFOUND, ...), a bare
    // upper-case token that names how the connection failed and nothing else — it lets a caller tell a
    // request that never left this machine from one whose answer was lost. Never the message.
    this.code = typeof code === 'string' && /^[A-Z][A-Z0-9_]{1,31}$/.test(code) ? code : null;
  }
}

// transportCode (the transport-error NAMING extractor) now lives in net-errors.js — the one classifier module —
// and is imported above, so device-http's naming and net-errors' classification can never diverge.

// Map a non-2xx response to a fixed reason literal WITHOUT surfacing the body text: read ONLY
// detail.reason, and fail closed to UNKNOWN_REFUSAL for anything unrecognised, missing, or unreadable.
async function reasonFor(res) {
  let reason;
  try { const body = await res.json(); reason = body && body.detail && body.detail.reason; }
  catch { /* a non-JSON / unreadable body yields no reason */ }
  if (typeof reason === 'string' && KNOWN_REASONS.includes(reason)) return reason; // a typed answer wins, whatever the status
  // A 5xx carrying no typed reason is not the server refusing this device — it is the server (or a proxy in
  // front of it) failing to answer. Keep it apart from the refusal literals so the caller retries it calmly
  // instead of holding the vault; every other unrecognised answer stays the fail-closed unknown refusal.
  if (res && typeof res.status === 'number' && res.status >= 500) return SERVER_ERROR;
  return UNKNOWN_REFUSAL;
}

/**
 * Perform a device-authenticated request to ONE allowlisted device route. Returns the parsed JSON body
 * on a 2xx. Throws a DeviceRequestError (status + fixed reason literal; never the secret/body/header) on
 * a non-2xx or a transport failure, and throws LOCALLY (before any network) for a route not on the
 * allowlist or a missing secret.
 * @param {{serverOrigin:string, deviceSecret:string, route:'mint'|'refresh'|'grants', body?:object}} args
 * @param {(url:string, init:object)=>Promise<{ok:boolean,status:number,json:()=>Promise<any>}>} [fetchFn]
 * @returns {Promise<any>} the parsed 2xx response body
 */
async function deviceRequest({ serverOrigin, deviceSecret, route, body } = {}, fetchFn) {
  // OWN-property check: a bracket lookup would also resolve inherited Object.prototype members
  // ('toString', 'constructor', '__proto__', ...), which are truthy and would slip past a `!spec` guard
  // and fire an authenticated request at a bogus URL. Only a real allowlisted route may proceed, and
  // belt-and-suspenders its method/path must be strings.
  const spec = Object.prototype.hasOwnProperty.call(ROUTES, route) ? ROUTES[route] : undefined;
  if (!spec || typeof spec.method !== 'string' || typeof spec.path !== 'string') {
    throw new DeviceRequestError(0, ROUTE_NOT_ALLOWED);                           // local refusal, no network
  }
  if (typeof deviceSecret !== 'string' || deviceSecret.length === 0) {
    throw new DeviceRequestError(0, NO_DEVICE_SECRET);                            // local refusal, no network
  }
  const init = { method: spec.method, headers: { Authorization: `Bearer ${deviceSecret}` } };
  if (spec.method !== 'GET' && body !== undefined) {
    init.headers['Content-Type'] = 'application/json';
    // Serialize inside a guard so an exotic caller body (a circular reference, a BigInt) becomes a
    // local, network-free DeviceRequestError with no body text — never a raw TypeError that would both
    // break the "only DeviceRequestError" contract and enumerate request-body property names.
    try { init.body = JSON.stringify(body); }
    catch { throw new DeviceRequestError(0, UNKNOWN_REFUSAL); }
  }
  let res;
  try {
    res = await fetchFn(`${serverOrigin}${spec.path}`, init);
  } catch (e) {
    // Never propagate the transport error's message: it can carry the URL, and must never carry the
    // header/secret. A genuine transport failure NAMES itself — a platform code (ECONNREFUSED, ETIMEDOUT, ...)
    // or Chromium's net::ERR_ in the message — so keep ONLY that bare code and fail closed to the status-0
    // network reason (the token lets a caller tell "never connected" from "answer lost"). A throw with NO such
    // name is NOT the transport failing but a fault inside the injected fetchFn (a bug, a broken contract):
    // surface it as its own 'internal-error' rather than laundering it into a retryable network reason that
    // would send the person hunting a connection for a fault only we can fix. (The real transport helper names
    // every transport failure with a code, so a codeless throw here is never a genuine transport error.)
    // CLASSIFY with the allowlist (isTransportError), NAME with the shape (transportCode). transportCode is a
    // shape match — a Node programming error carries an ERR_* code of the same shape (e.g. ERR_INVALID_ARG_TYPE)
    // — so classifying on it alone would launder a code bug into a retryable 'network' failure that is retried
    // forever. Only a genuine transport failure (a status, a net::ERR_ token, or an allowlisted code) becomes
    // NETWORK_FAILURE, carrying its bare code; anything else — including a coded programming fault inside the
    // injected fetchFn — is our-side 'internal-error'.
    const code = transportCode(e);
    if (code && isTransportError(e)) throw new DeviceRequestError(0, NETWORK_FAILURE, code);
    throw new DeviceRequestError(0, INTERNAL_ERROR);
  }
  if (res && res.ok) {
    try { return await res.json(); }
    catch { throw new DeviceRequestError(res.status || 0, UNKNOWN_REFUSAL); }     // 2xx but unreadable body
  }
  throw new DeviceRequestError((res && res.status) || 0, await reasonFor(res));
}

module.exports = {
  deviceRequest, DeviceRequestError, ROUTES, KNOWN_REASONS,
  UNKNOWN_REFUSAL, NETWORK_FAILURE, ROUTE_NOT_ALLOWED, NO_DEVICE_SECRET, SERVER_ERROR, INTERNAL_ERROR,
};

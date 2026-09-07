'use strict';

/*
 * Tell a genuine transport/HTTP failure (worth retrying) apart from a CODE error in our own path — a bug
 * such as a bad call or a type error — which must NOT be retried forever. A transport failure carries an
 * HTTP status or a recognizable network error code; a code error carries neither, and the callers classify
 * it as a non-retryable internal error (surfaced honestly and logged) instead of an endless retry.
 */

const KNOWN_NETWORK_CODES = new Set([
  'ECONNREFUSED', 'ECONNRESET', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH',
  'ENETUNREACH', 'ENETDOWN', 'EHOSTDOWN', 'EPIPE', 'ECONNABORTED', 'EADDRNOTAVAIL', 'EPROTO', 'UND_ERR_CONNECT_TIMEOUT',
  'EAI_FAIL',
  // The main-process JSON helper's own transport throws (http-json.js): a request timeout (ETIMEDOUT, above) and a
  // response that exceeded the size cap. Both mean the request left and the answer was lost or unusable — a
  // retryable transport condition, NOT our-side code error. This keeps net-errors in agreement with device-http's
  // transportCode, which already reads a capped response as a transport failure; the two classifiers must not
  // disagree on the same oversize error.
  'ERESPONSE_TOO_LARGE',
  // Chromium (Electron net) network names, for the rare bare-code arrival; the usual runtime form is a net::ERR_
  // token in the MESSAGE, matched by NET_ERR_MESSAGE below. These are network names only — never a programming
  // code like ERR_INVALID_ARG_TYPE, which must stay a non-retryable internal error.
  'ERR_CONNECTION_REFUSED', 'ERR_CONNECTION_RESET', 'ERR_CONNECTION_CLOSED', 'ERR_CONNECTION_ABORTED',
  'ERR_CONNECTION_TIMED_OUT', 'ERR_TIMED_OUT', 'ERR_NAME_NOT_RESOLVED', 'ERR_NAME_RESOLUTION_FAILED',
  'ERR_ADDRESS_UNREACHABLE', 'ERR_NETWORK_UNREACHABLE', 'ERR_INTERNET_DISCONNECTED', 'ERR_NETWORK_CHANGED', 'ERR_EMPTY_RESPONSE',
]);

// Chromium/Electron's network stack names its failures net::ERR_* in the error MESSAGE (with no .code). That
// token form comes ONLY from the network layer, so its presence is itself a transport signal — this is what
// lets a refused connection or a DNS failure over Electron net read as transport rather than an internal bug.
const NET_ERR_MESSAGE = /\bnet::ERR_[A-Z0-9_]+/;

// True when `e` looks like a network/HTTP transport failure — retryable. An HTTP status; a net::ERR_ token in
// the message (directly or on a wrapped cause); or a recognizable network code (directly or on a cause).
// Everything else — no status, no net:: token, and a code not in the set (a Node programming error's ERR_*
// shape included, e.g. ERR_INVALID_ARG_TYPE) — is treated by the callers as a non-retryable internal error.
function isTransportError(e) {
  if (!e) return false;
  if (typeof e.status === 'number') return true;
  if (typeof e.message === 'string' && NET_ERR_MESSAGE.test(e.message)) return true;
  if (e.cause && typeof e.cause.message === 'string' && NET_ERR_MESSAGE.test(e.cause.message)) return true;
  if (e.code && KNOWN_NETWORK_CODES.has(e.code)) return true;
  if (e.cause && e.cause.code && KNOWN_NETWORK_CODES.has(e.cause.code)) return true;
  return false;
}

// The bare failure token of a transport error, for NAMING one ALREADY known to be transport (device-http's
// catch, which runs only on a thrown request): the platform code when the transport sets one, else the
// net::ERR_ name a Chromium transport puts in its message. Anything else is null. This is a SHAPE match (any
// [A-Z][A-Z0-9_]+ code passes), so it is ONLY for naming a known-transport failure — never for CLASSIFYING one
// (use isTransportError for that; a programming error's ERR_* code passes this shape but is not transport).
function transportCode(e) {
  if (e && typeof e.code === 'string' && /^[A-Z][A-Z0-9_]{1,31}$/.test(e.code)) return e.code;
  const m = e && typeof e.message === 'string' ? /\bnet::(ERR_[A-Z0-9_]{1,40})\b/.exec(e.message) : null;
  return m ? m[1].slice(0, 32) : null;
}

module.exports = { isTransportError, transportCode, KNOWN_NETWORK_CODES };

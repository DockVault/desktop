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
]);

// True when `e` looks like a network/HTTP transport failure: it carries an HTTP status, or a recognizable
// network error code (directly or on a wrapped `cause`). Retryable. Anything else — no status, no known
// code — is treated by the callers as a non-retryable internal (code) error.
function isTransportError(e) {
  if (!e) return false;
  if (typeof e.status === 'number') return true;
  if (e.code && KNOWN_NETWORK_CODES.has(e.code)) return true;
  if (e.cause && e.cause.code && KNOWN_NETWORK_CODES.has(e.cause.code)) return true;
  return false;
}

module.exports = { isTransportError, KNOWN_NETWORK_CODES };

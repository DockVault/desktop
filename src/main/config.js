'use strict';

/*
 * Static, non-secret configuration shared across the main process.
 *
 * The web UI is served from a shell-controlled custom privileged secure scheme: a secure context so
 * `crypto.subtle` is defined, with no TLS certificate and nothing added to the OS trust store, and
 * no listening TCP port. The origin the renderer sees is `dockvault://app`; `'self'` in the policy
 * therefore means the locally bundled UI and crypto, never the remote server (which is reached only
 * through a pinned connect-src, wired when the session/auth layer is added).
 */

const APP_SCHEME = 'dockvault';
const APP_HOST = 'app';
const APP_ORIGIN = `${APP_SCHEME}://${APP_HOST}`;

module.exports = { APP_SCHEME, APP_HOST, APP_ORIGIN };

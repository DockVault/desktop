'use strict';

/*
 * The Content-Security-Policy the shell emits for the web-UI document.
 *
 * The bundled index.html carries no <meta> policy by design — in the hosted product the server sends
 * the header on every HTML response. When the shell serves the UI from its own origin there is no
 * such server, so the shell emits the policy itself. It mirrors the hosted directive set (so the
 * bundled UI still renders its styles, fonts, images, and blob previews) but tightens two things:
 *
 *   - script-src is 'self' only. 'self' is the shell origin (the locally bundled UI and crypto). The
 *     remote server is a different origin and never appears in script-src, so a server that returns
 *     JavaScript can never have it executed in the renderer.
 *   - connect-src is pinned, never a bare `ws:`/`wss:` scheme wildcard (which script running in the
 *     page could use to open a socket to any host). With no server configured yet it is 'self' only;
 *     once a server is configured, its exact https and wss origins are appended — nothing wider.
 */

function buildCsp(opts) {
  const o = opts || {};
  const connect = ["'self'"];
  if (o.serverHttpsOrigin) connect.push(o.serverHttpsOrigin);   // e.g. https://vault.example.com
  if (o.serverWssOrigin) connect.push(o.serverWssOrigin);       // e.g. wss://vault.example.com
  return [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "media-src 'self' blob:",
    "frame-src 'self' blob:",
    "object-src 'self' blob:",
    "font-src 'self'",
    `connect-src ${connect.join(' ')}`,
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "form-action 'self'",
  ].join('; ');
}

module.exports = { buildCsp };

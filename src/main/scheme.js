'use strict';

/*
 * The custom privileged secure scheme that serves the reused web UI and forwards its API calls.
 *
 * registerPrivileged() must run before the app 'ready' event (an Electron requirement).
 * installHandler() wires the responder afterwards. The responder routes by path:
 *   - asset paths ('/', '/index.html', '/static/...') are served from the pinned vendored tree,
 *     contained to the static root (no path traversal), with the shell's own tightened policy header
 *     injected on the HTML document;
 *   - every other path is forwarded to the configured server through the transparent proxy (the UI
 *     computes its API base from its own origin, so its API/auth calls arrive here). With no server
 *     configured yet, those paths return a clean 404.
 * Asset serving and forwarding are kept strictly separate, and neither path handles deep links.
 */

const { protocol, net } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_SCHEME } = require('./config');
const proxy = require('./proxy');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.webp': 'image/webp',
  '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
};
function contentType(p) { return MIME[path.extname(p).toLowerCase()] || 'application/octet-stream'; }

function isAssetPath(p) { return p === '/' || p === '/index.html' || p.startsWith('/static/'); }

// Reserved same-origin path serving a minimal blank page, used by the main process to pre-seed the
// origin's storage with a restored session before loading the real UI.
const SEED_PATH = '/__dv_session_seed__';

function registerPrivileged() {
  protocol.registerSchemesAsPrivileged([{
    scheme: APP_SCHEME,
    privileges: {
      standard: true,        // real origin semantics (needed for same-origin and module scripts)
      secure: true,          // treated as a secure context, so crypto.subtle is defined
      supportFetchAPI: true, // the UI's fetch() resolves against this scheme
      corsEnabled: true,
      stream: true,
    },
  }]);
}

/**
 * @param {string} staticRoot absolute path to the bundled web-UI root
 * @param {string} cspHeader  the policy string from buildCsp()
 * @param {() => (string|null)} [resolveServerOrigin] returns the configured server origin, or null
 * @param {Electron.Session} [ses] register on this session's protocol (e.g. the in-memory UI
 *   partition); defaults to the app-level protocol (the default session)
 */
function installHandler(staticRoot, cspHeader, resolveServerOrigin, ses) {
  const target = (ses && ses.protocol) ? ses.protocol : protocol;
  const ROOT = path.resolve(staticRoot);

  function resolveFile(urlPath) {
    let p = decodeURIComponent(urlPath.split('?')[0]);
    if (p === '/' || p === '') p = '/index.html';
    if (p.startsWith('/static/')) p = p.slice('/static'.length); // /static/js/x -> /js/x under ROOT
    const file = path.normalize(path.join(ROOT, p));
    if (file !== ROOT && !file.startsWith(ROOT + path.sep)) return null; // traversal guard
    return file;
  }

  function serveAsset(pathname) {
    const file = resolveFile(pathname);
    if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    const type = contentType(file);
    const headers = { 'content-type': type };
    // The shell owns the policy for the UI document (the bundled UI ships none of its own).
    if (type.startsWith('text/html')) headers['Content-Security-Policy'] = cspHeader;
    return new Response(fs.readFileSync(file), { headers });
  }

  target.handle(APP_SCHEME, (request) => {
    let pathname;
    try {
      pathname = new URL(request.url).pathname;
    } catch {
      return new Response('bad request', { status: 400 });
    }
    // A minimal, script-free page on the app origin. The main process loads this first when it has a
    // stored session, seeds the session into the origin's storage, then loads the real UI — so the
    // storage is populated before the UI's own boot script reads it (same origin, so it carries over).
    if (pathname === SEED_PATH) {
      return new Response('<!doctype html><meta charset="utf-8"><title>DockVault</title>',
        { headers: { 'content-type': 'text/html; charset=utf-8', 'Content-Security-Policy': cspHeader } });
    }
    if (isAssetPath(pathname)) return serveAsset(pathname);

    const origin = resolveServerOrigin ? resolveServerOrigin() : null;
    if (origin) return proxy.proxyRequest(request, origin, net);
    return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  });
}

module.exports = { registerPrivileged, installHandler, contentType, isAssetPath, SEED_PATH };

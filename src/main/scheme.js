'use strict';

/*
 * The custom privileged secure scheme that serves the reused web UI.
 *
 * registerPrivileged() must run before the app 'ready' event (an Electron requirement).
 * installHandler() wires the responder afterwards. The responder:
 *   - serves the bundled UI from the pinned vendored tree,
 *   - injects the shell's own tightened policy header on the HTML document,
 *   - contains itself to the static root (no path traversal),
 *   - returns clean 404s for anything else. Proxying the UI's API/auth calls to the configured
 *     server is added with the session layer; until then those calls fail as network errors, which
 *     is the expected state for a shell that only has to prove it can load and gate the UI.
 */

const { protocol } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_SCHEME } = require('./config');

const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8', '.png': 'image/png', '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml', '.webp': 'image/webp',
  '.ico': 'image/x-icon', '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf',
  '.map': 'application/json; charset=utf-8', '.txt': 'text/plain; charset=utf-8',
};
function contentType(p) { return MIME[path.extname(p).toLowerCase()] || 'application/octet-stream'; }

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
 */
function installHandler(staticRoot, cspHeader) {
  const ROOT = path.resolve(staticRoot);

  function resolveFile(urlPath) {
    let p = decodeURIComponent(urlPath.split('?')[0]);
    if (p === '/' || p === '') p = '/index.html';
    if (p.startsWith('/static/')) p = p.slice('/static'.length); // /static/js/x -> /js/x under ROOT
    const file = path.normalize(path.join(ROOT, p));
    if (file !== ROOT && !file.startsWith(ROOT + path.sep)) return null; // traversal guard
    return file;
  }

  protocol.handle(APP_SCHEME, (request) => {
    let file;
    try {
      file = resolveFile(new URL(request.url).pathname);
    } catch {
      return new Response('bad request', { status: 400 });
    }
    if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    const type = contentType(file);
    const headers = { 'content-type': type };
    // The shell owns the policy for the UI document (the bundled UI ships none of its own).
    if (type.startsWith('text/html')) headers['Content-Security-Policy'] = cspHeader;
    return new Response(fs.readFileSync(file), { headers });
  });
}

module.exports = { registerPrivileged, installHandler, contentType };

'use strict';

/*
 * The custom privileged secure scheme that serves the reused web UI and forwards its API calls.
 *
 * registerPrivileged() must run before the app 'ready' event (an Electron requirement).
 * installHandler() wires the responder afterwards. The responder routes by path:
 *   - asset paths ('/', '/index.html', '/static/...') are served from the pinned vendored tree,
 *     contained to the static root (no path traversal), with the shell's own tightened policy header
 *     injected on the HTML document;
 *   - the interface's download worker ('/download-sw.js') is served from the same pinned tree, never
 *     forwarded, and it is the only service worker script the scheme ever answers (see below);
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

// The streaming-download worker of the bundled interface, at the address the interface registers it
// under (the server serves it from its root for the same reason: a worker's scope cannot be wider
// than where its script lives without a header). The interface streams a large download through it,
// and without it refuses any download larger than it is willing to hold in memory. A service worker
// controls every page of the origin it is registered on, so this one is served from the pinned tree
// and nothing else is ever answered as a worker script: a script the server supplied would otherwise
// sit between the app's pages and everything they load.
const DOWNLOAD_WORKER_PATH = '/download-sw.js';
const DOWNLOAD_WORKER_FILE = ['js', 'download-sw.js'];
// Chromium marks the fetch of a service worker's script (and of every update check) with this header.
function isWorkerScriptRequest(request) {
  try { return request.headers.has('service-worker'); } catch { return false; }
}

// Reserved same-origin path serving a minimal blank page, used by the main process to pre-seed the
// origin's storage with a restored session before loading the real UI.
const SEED_PATH = '/__dv_session_seed__';

// Reserved same-origin prefix for the shell's OWN pages (the server setup screen, the self-test
// failure page), served from src/renderer. They must come over the app scheme rather than file:,
// because a packaged app keeps them inside its archive, which the file protocol cannot read, and
// because the same origin gives them the same policy header and the same typed preload.
const SHELL_PATH = '/__dv_shell__/';
const SHELL_ROOT = path.resolve(__dirname, '..', 'renderer');
function shellPageUrl(origin, name) { return origin + SHELL_PATH + name; }

// The file for a shell page path, or null: one flat directory, no traversal, no dotfiles.
function resolveShellFile(pathname, root = SHELL_ROOT) {
  if (!pathname.startsWith(SHELL_PATH)) return null;
  let name;
  try { name = decodeURIComponent(pathname.slice(SHELL_PATH.length).split('?')[0]); } catch { return null; }
  if (!/^[a-z0-9-]+\.(html|js)$/i.test(name)) return null;
  const file = path.normalize(path.join(root, name));
  if (!file.startsWith(path.resolve(root) + path.sep)) return null;
  return file;
}

function registerPrivileged() {
  protocol.registerSchemesAsPrivileged([{
    scheme: APP_SCHEME,
    privileges: {
      standard: true,        // real origin semantics (needed for same-origin and module scripts)
      secure: true,          // treated as a secure context, so crypto.subtle is defined
      supportFetchAPI: true, // the UI's fetch() resolves against this scheme
      corsEnabled: true,
      stream: true,
      allowServiceWorkers: true, // the interface's download worker; only the bundled script is served as one
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

  function serveDownloadWorker() {
    const file = path.join(ROOT, ...DOWNLOAD_WORKER_FILE);
    if (!fs.existsSync(file) || !fs.statSync(file).isFile()) {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    return new Response(fs.readFileSync(file), {
      headers: {
        'content-type': 'text/javascript; charset=utf-8',
        // The same two headers the server sends with it: its scope is the whole origin, and every
        // registration checks it again instead of keeping a stale copy.
        'Service-Worker-Allowed': '/',
        'Cache-Control': 'no-cache',
      },
    });
  }

  target.handle(APP_SCHEME, (request) => {
    let pathname;
    try {
      pathname = new URL(request.url).pathname;
    } catch {
      return new Response('bad request', { status: 400 });
    }
    if (pathname === DOWNLOAD_WORKER_PATH) return serveDownloadWorker();
    // No other script may become a service worker of this origin, whoever asks for it.
    if (isWorkerScriptRequest(request)) {
      return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
    }
    // A minimal, script-free page on the app origin. The main process loads this first when it has a
    // stored session, seeds the session into the origin's storage, then loads the real UI — so the
    // storage is populated before the UI's own boot script reads it (same origin, so it carries over).
    if (pathname === SEED_PATH) {
      return new Response('<!doctype html><meta charset="utf-8"><title>DockVault</title>',
        { headers: { 'content-type': 'text/html; charset=utf-8', 'Content-Security-Policy': cspHeader } });
    }
    if (isAssetPath(pathname)) return serveAsset(pathname);
    if (pathname.startsWith(SHELL_PATH)) {
      const file = resolveShellFile(pathname);
      if (!file || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
        return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
      }
      const type = contentType(file);
      const headers = { 'content-type': type };
      if (type.startsWith('text/html')) headers['Content-Security-Policy'] = cspHeader;
      return new Response(fs.readFileSync(file), { headers });
    }

    const origin = resolveServerOrigin ? resolveServerOrigin() : null;
    if (origin) return proxy.proxyRequest(request, origin, net);
    return new Response('not found', { status: 404, headers: { 'content-type': 'text/plain; charset=utf-8' } });
  });
}

module.exports = { registerPrivileged, installHandler, contentType, isAssetPath, resolveShellFile, shellPageUrl, SEED_PATH, SHELL_PATH, DOWNLOAD_WORKER_PATH };

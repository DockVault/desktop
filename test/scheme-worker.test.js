'use strict';

/*
 * THE DOWNLOAD WORKER COMES FROM THE BUNDLE, AND NOTHING ELSE CAN BECOME A WORKER.
 *
 * The bundled interface streams a large download through a service worker it registers at
 * /download-sw.js, and refuses a download it would have to hold whole in memory above its limit. The
 * scheme therefore has to allow service workers and answer that one path itself. A service worker
 * controls every page of its origin, so the scheme must never forward that path to the server, and
 * must refuse any other worker script, so that nothing the server supplies can ever take that place.
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// scheme.js takes protocol and net from Electron; a stand-in records what it is given.
const captured = { privileged: null };
require.cache[require.resolve('electron')] = {
  id: 'electron', filename: 'electron', loaded: true,
  exports: { protocol: { registerSchemesAsPrivileged: (list) => { captured.privileged = list; } }, net: {} },
};
const proxy = require('../src/main/proxy');
const scheme = require('../src/main/scheme');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
// The app's copy of the pinned worker, with the slot fix (test/download-worker.test.js ties the two).
const WORKER_SRC = fs.readFileSync(path.resolve(__dirname, '..', 'src', 'web-ui', 'download-sw.js'));

// The handler as installed on a session, with every forward to the server recorded instead of sent.
function handler() {
  let fn = null;
  scheme.installHandler(STATIC_ROOT, "default-src 'self'", () => 'https://vault.example.com',
    { protocol: { handle: (_scheme, h) => { fn = h; } } });
  return fn;
}
const forwarded = [];
const realProxy = proxy.proxyRequest;
test.beforeEach(() => {
  forwarded.length = 0;
  proxy.proxyRequest = async (req) => { forwarded.push(new URL(req.url).pathname); return new Response('from server'); };
});
test.after(() => { proxy.proxyRequest = realProxy; });

const asWorker = { 'service-worker': 'script' };

test('the scheme is registered to allow service workers', () => {
  scheme.registerPrivileged();
  const entry = captured.privileged.find((s) => s.scheme === 'dockvault');
  assert.ok(entry, 'the app scheme is registered');
  assert.equal(entry.privileges.allowServiceWorkers, true);
  assert.equal(entry.privileges.secure, true, 'and stays a secure context');
});

test('/download-sw.js is the app\'s worker, with the headers the server sends, and never forwarded', async () => {
  const h = handler();
  for (const headers of [asWorker, {}]) {
    const res = await h(new Request('dockvault://app/download-sw.js', { headers }));
    assert.equal(res.status, 200);
    assert.ok(Buffer.from(await res.arrayBuffer()).equals(WORKER_SRC), 'the bytes of the app\'s copy');
    assert.equal(res.headers.get('content-type'), 'text/javascript; charset=utf-8');
    assert.equal(res.headers.get('service-worker-allowed'), '/');
    assert.equal(res.headers.get('cache-control'), 'no-cache');
  }
  const withQuery = await h(new Request('dockvault://app/download-sw.js?v=2', { headers: asWorker }));
  assert.equal(withQuery.status, 200);
  assert.deepEqual(forwarded, [], 'the server is never asked for it');
});

test('no other script is ever answered as a service worker, and none is forwarded', async () => {
  const h = handler();
  for (const p of ['/evil-sw.js', '/api/download-sw.js', '/static/js/app.js', '/static/js/download-sw.js',
    '/', '/__dv_session_seed__', '/__dv_shell__/server-setup.js', '/download-sw.js/']) {
    const res = await h(new Request(`dockvault://app${p}`, { headers: asWorker }));
    assert.equal(res.status, 404, `${p} is refused as a worker script`);
  }
  assert.deepEqual(forwarded, [], 'none of them reached the server');
});

test('the same paths without the worker mark behave as before', async () => {
  const h = handler();
  assert.equal((await h(new Request('dockvault://app/api/vaults'))).status, 200);
  assert.deepEqual(forwarded, ['/api/vaults'], 'an API call is still forwarded');
  const app = await h(new Request('dockvault://app/static/js/app.js'));
  assert.equal(app.status, 200);
  assert.equal(app.headers.get('content-type'), 'text/javascript; charset=utf-8');
});

test('the pinned interface registers its worker at exactly the path the scheme serves, for the whole origin', () => {
  const app = fs.readFileSync(path.join(STATIC_ROOT, 'js', 'app.js'), 'utf8');
  const calls = [...app.matchAll(/serviceWorker\.register\(\s*([^)]*)\)/g)].map((m) => m[1].replace(/\s+/g, ' '));
  assert.deepEqual(calls, [`'${scheme.DOWNLOAD_WORKER_PATH}', { scope: '/' }`],
    'one registration, of the worker the scheme answers');
});

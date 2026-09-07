'use strict';

// The probe through the REAL main-process HTTP helper against a loopback stub: the wire shape of the
// health reply decides the outcome, and a closed port is "unreachable" within the helper's timeout.

const test = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');

const { probeServer } = require('../src/main/server-probe');
const httpJson = require('../src/main/http-json').createHttpJson({ fetch: globalThis.fetch });

function serve(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, '127.0.0.1', () => resolve({ srv, origin: `http://127.0.0.1:${srv.address().port}` }));
  });
}

test('a loopback DockVault stub answers ok or degraded from the health object, and asks GET /health with Accept json', async () => {
  const seen = [];
  const { srv, origin } = await serve((req, res) => {
    seen.push([req.method, req.url, req.headers.accept]);
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ status: req.url.includes('x') ? 'degraded' : 'healthy', database: 'connected', schema: 'complete' }));
  });
  try {
    const ok = await probeServer(origin, { httpJson });
    assert.deepEqual(ok, { kind: 'ok', origin, host: new URL(origin).host });
    assert.deepEqual(seen[0], ['GET', '/health', 'application/json']);
  } finally { srv.close(); }
});

test('a loopback server that is not DockVault: HTML, a 404, or JSON without a health status', async () => {
  let mode = 'html';
  const { srv, origin } = await serve((req, res) => {
    if (mode === 'html') { res.setHeader('Content-Type', 'text/html'); res.end('<html>hello</html>'); return; }
    if (mode === '404') { res.statusCode = 404; res.end('nope'); return; }
    res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ version: '1.2.3' }));
  });
  try {
    for (const m of ['html', '404', 'json']) {
      mode = m;
      assert.equal((await probeServer(origin, { httpJson })).kind, 'not-dockvault', m);
    }
  } finally { srv.close(); }
});

test('a closed loopback port is unreachable, and the address that was tried is reported by host only', async () => {
  const { srv, origin } = await serve((_req, res) => res.end());
  await new Promise((r) => srv.close(r));
  const r = await probeServer(origin, { httpJson });
  assert.equal(r.kind, 'unreachable');
  assert.equal(r.host, new URL(origin).host);
  assert.deepEqual(Object.keys(r).sort(), ['host', 'kind', 'origin']);
});

test('a front that redirects the health route to another loopback origin: the probe follows and saves where it landed', async () => {
  const real = await serve((_req, res) => { res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify({ status: 'healthy' })); });
  const front = await serve((_req, res) => { res.statusCode = 302; res.setHeader('Location', `${real.origin}/health`); res.end(); });
  try {
    const r = await probeServer(front.origin, { httpJson });
    assert.deepEqual(r, { kind: 'ok', origin: real.origin, host: new URL(real.origin).host, from: new URL(front.origin).host });
  } finally { front.srv.close(); real.srv.close(); }
});

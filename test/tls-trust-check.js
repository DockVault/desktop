'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the main-process request helper trusts
 * the OPERATING SYSTEM's certificate store, exactly as the interface does. It starts a loopback https
 * server whose certificate chains to a throwaway authority (DV_TLS_DIR holds ca.crt, leaf.crt, leaf.key,
 * made with openssl) and then, through the app's own helper (Electron net):
 *   - probes it the way the setup screen does (server-probe → /health),
 *   - lists vaults the way sync does (sync-vaults.fetchStandardVaults → /vaults with a bearer).
 * Run it three times from a driver: before the authority is installed in the user's certificate store
 * (expect tls-untrusted and a failed list), after installing it (expect ok and a list), and after removing
 * it again (expect tls-untrusted). Prints one JSON line; the driver decides PASS/FAIL. No network beyond
 * 127.0.0.1; nothing is written to the app's data folder.
 *
 *   DV_TLS_DIR=<dir> node_modules/electron/dist/electron.exe test/tls-trust-check.js
 */
const { app, net } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const { createHttpJson } = require('../src/main/http-json');
const { probeServer } = require('../src/main/server-probe');
const { fetchStandardVaults } = require('../src/main/sync-vaults');

const dir = process.env.DV_TLS_DIR;
const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; finish(3); }, 60000);
function finish(code) { clearTimeout(watchdog); process.stdout.write(`TLS TRUST CHECK ${JSON.stringify(out)}\n`); app.exit(code); }

app.whenReady().then(async () => {
  if (!dir) { out.fatal = 'DV_TLS_DIR not set'; return finish(2); }
  const srv = https.createServer({ cert: fs.readFileSync(path.join(dir, 'leaf.crt')), key: fs.readFileSync(path.join(dir, 'leaf.key')) }, (req, res) => {
    res.setHeader('Content-Type', 'application/json');
    if (req.url === '/health') return res.end(JSON.stringify({ status: 'healthy', database: 'connected' }));
    if (req.url === '/vaults') {
      if (req.headers.authorization !== 'Bearer check-token') { res.statusCode = 401; return res.end('{}'); }
      return res.end(JSON.stringify([{ id: 'v1', name: 'Docs', vault_type: 'standard' }]));
    }
    res.statusCode = 404; res.end('{}');
  });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  const origin = `https://127.0.0.1:${srv.address().port}`;
  const httpJson = createHttpJson(net);
  try {
    out.probe = (await probeServer(origin, { httpJson })).kind;
  } catch (e) { out.probe = 'threw:' + String(e && e.message).slice(0, 80); }
  try {
    const r = await fetchStandardVaults({ serverOrigin: origin, sessionToken: 'check-token' }, httpJson);
    out.vaults = Array.isArray(r && r.vaults) ? r.vaults.length : 'shape:' + JSON.stringify(r).slice(0, 60);
  } catch (e) {
    const m = String((e && e.message) || e);
    out.vaults = /ERR_CERT|CERT_|ERR_SSL/.test(m) ? 'refused-cert' : 'failed:' + m.slice(0, 80);
  }
  srv.close();
  finish(0);
}).catch((e) => { out.fatal = String((e && e.stack) || e).slice(0, 300); finish(2); });

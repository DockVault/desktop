'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): confirm the reused UI's real login
 * flow works over the custom scheme via the transparent proxy, against a live instance. This is the
 * central question for the session layer — does verbatim-UI auth survive serving the UI from the
 * shell's own origin.
 *
 *   DOCKVAULT_SERVER=http://localhost:PORT DV_USER=<u> DV_PASS=<p> \
 *     node_modules/electron/dist/electron.exe test/login-check.js
 *
 * Credentials are read from the environment in the main process and injected into the renderer for
 * one login POST; the result records only statuses and booleans — never the token, never the
 * credentials. Nothing sensitive is written to disk. The result file is under the gitignored .local/.
 */

const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const serverConfig = require('../src/main/server-config');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'login-check.json');
const out = { server: process.env.DOCKVAULT_SERVER || null, consoleErrors: [], wsSeen: [] };

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});

const watchdog = setTimeout(() => { dump(); app.exit(3); }, 45000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => serverConfig.readServerOrigin(app.getPath('userData')));
  const win = new BrowserWindow({
    show: false, width: 1200, height: 800,
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true },
  });
  win.webContents.on('console-message', (...a) => {
    const msg = String(a[2] || '');
    if (/websocket|ws:\/\/|wss:\/\//i.test(msg)) out.wsSeen.push(msg.slice(0, 200));
    else if ((a[1] || 0) >= 2) out.consoleErrors.push(msg.slice(0, 160));
  });

  await win.loadURL(`${APP_ORIGIN}/`);
  await new Promise((r) => setTimeout(r, 1500));

  const user = process.env.DV_USER || '';
  const pass = process.env.DV_PASS || '';
  // The login POST and the credentialed follow-ups all run through the same-origin proxy. The result
  // object deliberately carries no token and no credentials — only outcomes.
  out.login = await win.webContents.executeJavaScript(`(async (u, p) => {
    const o = { credsProvided: !!(u && p) };
    try {
      const r = await fetch('/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: u, password: p }) });
      o.loginStatus = r.status;
      const d = await r.json().catch(() => ({}));
      o.secondFactorRequired = !!d.second_factor_required;
      o.hasAccessToken = !!d.access_token;
      if (d.access_token) {
        const auth = { 'Authorization': 'Bearer ' + d.access_token };
        const me = await fetch('/users/me', { headers: auth });
        o.usersMeStatus = me.status;
        const sess = await fetch('/auth/session', { headers: auth });
        o.authSessionStatus = sess.status;
        // A ZK endpoint round-trip through the proxy (own public key): proves crypto endpoints proxy.
        const eccpk = await fetch('/ecc/users/me/public-key', { headers: auth });
        o.eccPublicKeyStatus = eccpk.status;
      }
    } catch (e) { o.error = String(e && e.message || e); }
    return o;
  })(${JSON.stringify(user)}, ${JSON.stringify(pass)})`, true);

  out.ok = !!(out.login && (out.login.hasAccessToken || out.login.secondFactorRequired) && out.login.loginStatus && out.login.loginStatus < 500);
  clearTimeout(watchdog);
  dump();
  win.destroy();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

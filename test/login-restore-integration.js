'use strict';

/*
 * Functional integration check (run under Electron, not part of `npm test`): prove the full
 * login -> capture -> "restart" -> restore -> server re-validation cycle against a live instance.
 * Run in two phases sharing a data dir (safeStorage is user-scoped, so the second process decrypts
 * what the first wrote). Credentials come from the environment (login only, no data changes); the
 * result records statuses/booleans, never the token.
 *
 *   DV_PHASE=1 DV_DATADIR=<dir> DOCKVAULT_SERVER=<url> DV_USER=<u> DV_PASS=<p> electron test/login-restore-integration.js
 *   DV_PHASE=2 DV_DATADIR=<dir> DOCKVAULT_SERVER=<url>                          electron test/login-restore-integration.js
 */

const { app, BrowserWindow, session, safeStorage } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const serverConfig = require('../src/main/server-config');
const tokenStore = require('../src/main/token-store');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PHASE = process.env.DV_PHASE || '1';
const DATADIR = process.env.DV_DATADIR;
const RESULT = path.join(__dirname, '..', '.local', `login-restore-p${PHASE}.json`);
const SESSION_KEYS = ['authToken', 'currentUser', 'userPermissions', 'isScopedTemp'];
const out = { phase: PHASE };

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { dump(); app.exit(3); }, 45000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

function makeWin(partition) {
  return new BrowserWindow({ show: false, webPreferences: { partition, contextIsolation: true, sandbox: true, nodeIntegration: false } });
}

app.whenReady().then(async () => {
  const resolveServer = () => serverConfig.readServerOrigin(DATADIR || app.getPath('userData'));
  const ses = session.fromPartition(`lri-${PHASE}`);
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), resolveServer, ses);
  out.server = resolveServer();

  if (PHASE === '1') {
    // Launch 1: log in through the proxy, capture the session, persist it to the encrypted store.
    const w = makeWin(`lri-1`);
    await w.loadURL(`${APP_ORIGIN}/`);
    const login = await w.webContents.executeJavaScript(`(async (u,p) => {
      const r = await fetch('/auth/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ username:u, password:p }) });
      const d = await r.json().catch(()=>({}));
      const o = { status: r.status, hasToken: !!d.access_token, secondFactor: !!d.second_factor_required };
      if (d.access_token) { localStorage.setItem('authToken', d.access_token); localStorage.setItem('currentUser', JSON.stringify({ username: u })); }
      return o;
    })(${JSON.stringify(process.env.DV_USER || '')}, ${JSON.stringify(process.env.DV_PASS || '')})`, true);
    out.login = login;
    const bundle = await w.webContents.executeJavaScript(
      `(() => { const k=${JSON.stringify(SESSION_KEYS)},o={}; for (const key of k){const v=localStorage.getItem(key); if(v!=null)o[key]=v;} return o; })()`, true);
    if (bundle && bundle.authToken) out.persist = tokenStore.persistSession(safeStorage, DATADIR, bundle);
    out.captured = !!(bundle && bundle.authToken);
    out.ok = !!(login.hasToken && out.persist && out.persist.persisted);
    w.destroy();
  } else {
    // Launch 2 ("restart"): load the persisted session, seed a fresh window, let the UI re-validate.
    const bundle = tokenStore.loadSession(safeStorage, DATADIR);
    out.loadedHasToken = !!(bundle && bundle.authToken);
    const w = makeWin(`lri-2`);
    if (bundle && bundle.authToken) {
      await w.loadURL(`${APP_ORIGIN}${schemeMod.SEED_PATH}`);
      const seed = {}; for (const k of SESSION_KEYS) if (typeof bundle[k] === 'string') seed[k] = bundle[k];
      await w.webContents.executeJavaScript(
        `(() => { const s=${JSON.stringify(seed)}; for (const k of Object.keys(s)) localStorage.setItem(k, s[k]); return true; })()`, true);
    }
    await w.loadURL(`${APP_ORIGIN}/`);
    await new Promise((r) => setTimeout(r, 4000)); // let the UI's boot /users/me re-validation run
    out.afterRevalidate = await w.webContents.executeJavaScript(`({
      authTokenKept: !!localStorage.getItem('authToken'),
      dataAuth: document.documentElement.getAttribute('data-auth'),
      loginScreenVisible: (() => { const el = document.getElementById('login-screen'); return !!(el && el.offsetParent !== null); })(),
    })`, true);
    // Logged-in after restore = the token survived re-validation (the UI clears it on a 401).
    out.ok = out.loadedHasToken && out.afterRevalidate.authTokenKept && out.afterRevalidate.loginScreenVisible === false;
    w.destroy();
  }

  clearTimeout(watchdog);
  dump();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

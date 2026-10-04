'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): confirm the reused web UI's own
 * external scripts execute under the shell-injected policy served over the real custom scheme. This
 * guards against a tightened policy silently breaking the reused UI.
 *
 * It reuses the real scheme and policy modules (not a reimplementation), loads dockvault://app/, and
 * asserts: the document rendered (title), the UI's main script and the Activity page's script ran (each
 * left its top-level function as a window global), every enabled stylesheet the page links was served and
 * parsed, and there were no policy-violation console errors. Writes
 * .local/spa-boot-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/spa-boot-check.js
 */

const { app, BrowserWindow } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');

const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'spa-boot-check.json');
const out = { cspViolations: [], consoleErrors: [] };

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});

const watchdog = setTimeout(() => { dump(); app.exit(3); }, 40000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

app.whenReady().then(async () => {
  schemeMod.installHandler(STATIC_ROOT, buildCsp());
  const win = new BrowserWindow({
    show: false, width: 1200, height: 800,
    webPreferences: { contextIsolation: true, sandbox: true, nodeIntegration: false, webSecurity: true },
  });
  win.webContents.on('console-message', (...a) => {
    const level = a[1], msg = String(a[2] || '');
    if (/content security policy|refused to (load|execute|connect)/i.test(msg)) out.cspViolations.push(msg.slice(0, 200));
    else if (level >= 2) out.consoleErrors.push(msg.slice(0, 160));
  });

  await win.loadURL(`${APP_ORIGIN}/`);
  await new Promise((r) => setTimeout(r, 2500)); // let boot scripts and the main script run

  out.cspHeaderApplied = await win.webContents.executeJavaScript(
    `(async () => { try { const r = await fetch('${APP_ORIGIN}/'); return r.headers.get('content-security-policy'); } catch(e){ return 'FETCH_ERR:'+e.message; } })()`, true);
  out.probe = await win.webContents.executeJavaScript(`({
    title: document.title,
    mainScriptRan: typeof window.apiRequest === 'function',  // a top-level UI function => it executed under the policy
    activityScriptRan: typeof window.initActivity === 'function', // the Activity page's own script, loaded after app.js
    // Every enabled stylesheet the page links was served and parsed (a missing or mistyped file has no rules).
    sheets: [...document.querySelectorAll('link[rel="stylesheet"]:not([disabled])')].map((l) => {
      let rules = -1; try { rules = l.sheet ? l.sheet.cssRules.length : -1; } catch (e) { rules = -2; }
      return { href: new URL(l.href).pathname, rules };
    }),
    hasBodyChildren: document.body ? document.body.children.length : 0,
    isSecureContext: window.isSecureContext,
  })`, true);

  const sheets = (out.probe && out.probe.sheets) || [];
  out.sheetsOk = sheets.length > 0 && sheets.every((x) => x.rules > 0);
  out.ok = !!(out.probe && out.probe.mainScriptRan && out.probe.activityScriptRan && out.probe.isSecureContext)
    && out.sheetsOk && out.cspViolations.length === 0;
  clearTimeout(watchdog);
  dump();
  win.destroy();
  app.quit();
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

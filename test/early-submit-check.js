'use strict';

/*
 * Functional check (run under Electron, not part of `npm test`): a sign-in sent before the bundled
 * interface's main script has bound its handlers never leaves the page, so the typed password never
 * reaches an address.
 *
 * The bundled interface binds its forms in app.js, at the end of the page. Until then the sign-in form is
 * on screen, and pressing Enter in it made the browser send the form itself, as a GET with the username
 * and password in the address. The interface now stops that from its <head>, and every form says
 * method="post". This check serves the pinned tree over the real scheme and policy, with the main script
 * withheld (the window before it binds), types a username and password, sends the form the way Enter does,
 * and asserts that the page did not navigate and no address carries the password.
 *
 * It also runs a control, so a pass means something: the same page with the guard taken out and the form's
 * method removed (the shape before the fix) must navigate with the password in the address. If the control
 * does not show the defect, the check fails, because it could not have seen it either.
 * Writes .local/early-submit-check.json.
 *
 *   node_modules/electron/dist/electron.exe test/early-submit-check.js
 */

const { app, BrowserWindow, session } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { APP_ORIGIN } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');

const PINNED_STATIC = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const RESULT = path.join(__dirname, '..', '.local', 'early-submit-check.json');
const PASSWORD = 'Typed-Pa55word-7f3c';
const out = {};

app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const watchdog = setTimeout(() => { out.fatal = 'timeout'; dump(); app.exit(3); }, 60000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch {} }

// A copy of the pinned tree in which the main scripts have not run: they are served empty.
function withheldTree(dir) {
  fs.cpSync(PINNED_STATIC, dir, { recursive: true });
  for (const f of ['app.js', 'activity.js']) fs.writeFileSync(path.join(dir, 'js', f), '');
  return dir;
}

// The control: the same tree with the guard removed and the sign-in form back to the browser's default
// method. Each edit must apply exactly once, or the control is not the page it claims to be.
function controlTree(dir) {
  withheldTree(dir);
  const bootFile = path.join(dir, 'js', 'auth-boot.js');
  const boot = fs.readFileSync(bootFile, 'utf8');
  const guard = "document.addEventListener('submit', function (e) { e.preventDefault(); }, true);";
  if (boot.split(guard).length !== 2) throw new Error('control: the guard line was not found exactly once');
  fs.writeFileSync(bootFile, boot.replace(guard, ''));
  const htmlFile = path.join(dir, 'index.html');
  const html = fs.readFileSync(htmlFile, 'utf8');
  const form = '<form id="login-form" method="post">';
  if (html.split(form).length !== 2) throw new Error('control: the sign-in form tag was not found exactly once');
  fs.writeFileSync(htmlFile, html.replace(form, '<form id="login-form">'));
  return dir;
}

async function trySignIn(name, root) {
  const ses = session.fromPartition(`early-submit-${name}`);
  schemeMod.installHandler(root, buildCsp(), () => null, ses);
  const win = new BrowserWindow({ show: false, webPreferences: { partition: `early-submit-${name}`, contextIsolation: true, sandbox: true } });
  await win.loadURL(`${APP_ORIGIN}/`);
  const navigations = [];
  win.webContents.on('did-start-navigation', (details, url) => {
    navigations.push(String((details && details.url) || url));
  });
  win.webContents.on('will-navigate', (_e, url) => navigations.push(String(url)));
  const sent = await win.webContents.executeJavaScript(`(() => {
    const u = document.getElementById('username'), p = document.getElementById('password');
    if (!u || !p || !p.form) return 'no-form';
    u.value = 'someone'; p.value = ${JSON.stringify(PASSWORD)};
    p.form.requestSubmit();   // what Enter in the password field does
    return 'sent';
  })()`, true);
  await new Promise((r) => setTimeout(r, 2000));
  let href = null;
  try { href = await win.webContents.executeJavaScript('location.href', true); } catch (e) { href = `unreadable: ${e.message}`; }
  win.destroy();
  const leaked = navigations.concat(href || '').some((u) => u.includes(PASSWORD));
  return { sent, navigations: navigations.map((u) => u.replace(PASSWORD, '<password>')), href: String(href).replace(PASSWORD, '<password>'), leaked };
}

app.whenReady().then(async () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-early-submit-'));
  try {
    out.bundle = await trySignIn('bundle', withheldTree(path.join(tmp, 'bundle')));
    out.control = await trySignIn('control', controlTree(path.join(tmp, 'control')));
  } finally {
    try { fs.rmSync(tmp, { recursive: true, force: true }); } catch {}
  }
  out.bundleStayed = out.bundle.sent === 'sent' && out.bundle.navigations.length === 0 && out.bundle.href === `${APP_ORIGIN}/` && !out.bundle.leaked;
  out.controlShowsDefect = out.control.sent === 'sent' && out.control.leaked;
  out.ok = out.bundleStayed && out.controlShowsDefect;
  clearTimeout(watchdog);
  dump();
  console.log(JSON.stringify({ ok: out.ok, bundleStayed: out.bundleStayed, controlShowsDefect: out.controlShowsDefect }));
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

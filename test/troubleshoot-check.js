'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the Troubleshoot view end to end — the real
 * page (src/renderer/troubleshoot.html), the real typed preload, the real check module (troubleshoot.js) — over
 * a recording, stubbed verify, in a hidden window, driven the way a person would use it. Proves:
 *   A) the first check is listed and selected, its facts show the saved server host, port, and SFTP address,
 *      the probe runs on arrival against exactly the saved setting, both lights turn green with their sentences
 *      and the fingerprint, the verdict is green, and Change server… is offered;
 *   B) a server that does not answer: both lights red, the verdict says nothing else can work;
 *   C) a server up with its SFTP door closed: green + red, a partial verdict;
 *   D) no server saved: no probe, a plain note, and Set up server…;
 *   E) Run again probes anew; while it runs the lights pulse and the button is disabled;
 *   F) Change server… asks main to open the server setup;
 *   G) the sender gate: a page at the interface root can list, describe, probe, or open nothing;
 *   H) a second check slots in: it is listed, opening it runs its own probe while the first is still running,
 *      each pane shows its own state, and coming back shows the first check's outcome once it lands;
 *   I) Run again keeps the keyboard on the button, and the verdict box is a live region.
 * Writes .local/troubleshoot-check.json and prints one PASS/FAIL line. Exit 0 = PASS.
 *
 *   node_modules/electron/dist/electron.exe test/troubleshoot-check.js
 */
const { app, BrowserWindow, ipcMain, session } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { createTroubleshoot, CHECKS } = require('../src/main/troubleshoot');
const { isTrustedSetupSender } = require('../src/main/server-setup');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const { APP_ORIGIN } = require('../src/main/config');

const RESULT = path.join(__dirname, '..', '.local', 'troubleshoot-check.json');
const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PAGE_NAME = 'troubleshoot.html';
const PAGE = schemeMod.shellPageUrl(APP_ORIGIN, PAGE_NAME);
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
schemeMod.registerPrivileged();
const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 120000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const SAVED = { status: 'ok', origin: 'https://vault.example.com', envOrigin: null, fileOrigin: 'https://vault.example.com', envOverrides: false, sftp: { host: 'vault.example.com', port: 2200 } };
const GREEN = { api: { kind: 'ok', host: 'vault.example.com' }, sync: { kind: 'supported' }, sftp: { kind: 'ok', host: 'vault.example.com', port: 2200, fingerprint: 'SHA256:abcdef' }, proceed: true };
const DOWN = { api: { kind: 'unreachable', host: 'vault.example.com' }, sync: { kind: 'not-checked' }, sftp: { kind: 'unreachable', host: 'vault.example.com', port: 2200 }, proceed: false };
const HALF = { ...GREEN, sftp: { kind: 'unreachable', host: 'vault.example.com', port: 2200 }, proceed: false };

function makeIo({ state = SAVED, verify = async () => GREEN } = {}) {
  const log = [];
  const io = { serverState: () => state, verify: async (fields) => { log.push(['verify', fields]); return verify(fields); } };
  return { io, log };
}

let theWindow = null;
function sharedWindow() {
  if (!theWindow || theWindow.isDestroyed()) {
    theWindow = new BrowserWindow({ show: false, webPreferences: { preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false } });
  }
  return theWindow;
}

const snap = `({
  checks: [...document.querySelectorAll('#checks button')].map(b => ({ title: b.textContent, current: b.getAttribute('aria-current') })),
  heading: (document.querySelector('#pane h2') || {}).textContent || '',
  facts: [...document.querySelectorAll('.facts .k')].map((k, i) => [k.textContent, document.querySelectorAll('.facts .v')[i].textContent]),
  lights: [...document.querySelectorAll('.light')].map(l => ({ leg: l.dataset.leg, state: l.dataset.state, name: l.querySelector('.name').textContent, what: l.querySelector('.what').textContent, detail: (l.querySelector('.detail') || {}).textContent || '' })),
  notes: [...document.querySelectorAll('#pane .note')].map(n => n.textContent),
  verdict: document.querySelector('.verdict') ? { state: document.querySelector('.verdict').dataset.state, text: document.querySelector('.verdict').textContent } : null,
  box: (document.querySelector('#pane .box') || {}).textContent || '',
  buttons: [...document.querySelectorAll('#pane button')].map(b => ({ label: b.textContent, disabled: b.disabled })),
  text: document.getElementById('pane').innerText,
})`;
// Wait until no light is still checking and the pane has left "Loading…".
const settle = `(async () => { for (let i = 0; i < 100; i++) { const t = document.getElementById('pane').innerText; const checking = document.querySelector('.light[data-state="checking"]'); if (!t.startsWith('Loading') && !checking && !t.includes('Checking…')) break; await new Promise(r => setTimeout(r, 50)); } await new Promise(r => setTimeout(r, 100)); return ${snap}; })()`;
const clickCheck = (title) => `(async () => { const b = [...document.querySelectorAll('#checks button')].find(x => x.textContent === ${JSON.stringify(title)}); if (!b) return 'no-check'; b.click(); await new Promise(r => setTimeout(r, 150)); return ${snap}; })()`;
const click = (label) => `(async () => { const b = [...document.querySelectorAll('#pane button')].find(x => x.textContent === ${JSON.stringify(label)}); if (!b) return 'no-button'; b.click(); await new Promise(r => setTimeout(r, 120)); return 'clicked'; })()`;

async function scenario(name, { ioSpec, drive, pageUrl = null, checks = undefined }) {
  const { io, log } = makeIo(ioSpec);
  const win = sharedWindow();
  const trusted = (e) => isTrustedSetupSender(e, { webContents: win.webContents, appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + PAGE_NAME });
  const view = createTroubleshoot(io, checks ? { checks } : {});
  let closes = 0; let setups = 0;
  for (const ch of ['dockvault:troubleshoot.checks', 'dockvault:troubleshoot.describe', 'dockvault:troubleshoot.probe', 'dockvault:troubleshoot.open-server-setup', 'dockvault:troubleshoot.close']) ipcMain.removeHandler(ch);
  ipcMain.handle('dockvault:troubleshoot.checks', (e) => (trusted(e) ? view.checks() : []));
  ipcMain.handle('dockvault:troubleshoot.describe', (e, a) => (trusted(e) ? view.describe(a && a.id) : null));
  ipcMain.handle('dockvault:troubleshoot.probe', (e, a) => (trusted(e) ? view.probe(a && a.id) : null));
  ipcMain.handle('dockvault:troubleshoot.open-server-setup', (e) => { if (trusted(e)) setups++; return null; });
  ipcMain.handle('dockvault:troubleshoot.close', (e) => { if (trusted(e)) closes++; return null; });
  await win.loadURL(pageUrl || PAGE);
  await sleep(150);
  const r = await drive(win, { log, io, closes: () => closes, setups: () => setups });
  out[name] = r;
  return r;
}

app.whenReady().then(async () => {
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, session.defaultSession);
  const ev = (win, expr) => win.webContents.executeJavaScript(expr, true);

  // A) listed, selected, facts, live probe on arrival, green lights, verdict, Change server
  {
    const r = await scenario('A_render', { ioSpec: {}, drive: async (win, ctx) => ({ ...(await ev(win, settle)), log: ctx.log }) });
    const [api, sftp] = r.lights;
    out.A_pass = r.checks.length === 1 && r.checks[0].title === 'Cannot connect to the server' && r.checks[0].current === 'true'
      && r.heading === 'Cannot connect to the server'
      && JSON.stringify(r.facts) === JSON.stringify([['Server address', 'vault.example.com:443'], ['File transfer address', 'vault.example.com:2200']])
      && r.log.length === 1 && JSON.stringify(r.log[0][1]) === JSON.stringify({ input: 'https://vault.example.com', sftp: 'vault.example.com:2200' })
      && api.leg === 'api' && api.state === 'ok' && api.name === 'Server' && api.what.includes('answered as a DockVault server')
      && sftp.leg === 'sftp' && sftp.state === 'ok' && sftp.name === 'File transfer (SFTP)' && sftp.what.includes('proved it is who it says it is') && sftp.detail === 'Host key fingerprint SHA256:abcdef'
      && r.notes.length === 1 && r.notes[0].includes('can sync folders')
      && r.verdict && r.verdict.state === 'ok' && r.verdict.text.includes('Both doors answered')
      && r.buttons.map((b) => b.label).join(',') === 'Run again,Change server…';
  }
  // B) server down
  {
    const r = await scenario('B_down', { ioSpec: { verify: async () => DOWN }, drive: async (win) => ev(win, settle) });
    out.B_pass = r.lights.map((l) => l.state).join(',') === 'bad,bad' && r.lights[0].what.includes('Nothing answered at vault.example.com')
      && r.notes.length === 0 && r.verdict && r.verdict.state === 'bad' && r.verdict.text.includes("can't be reached from this computer right now");
  }
  // C) SFTP door closed
  {
    const r = await scenario('C_half', { ioSpec: { verify: async () => HALF }, drive: async (win) => ev(win, settle) });
    out.C_pass = r.lights.map((l) => l.state).join(',') === 'ok,bad' && r.lights[1].what.includes('file transfer port may be closed')
      && r.verdict && r.verdict.state === 'partial' && r.verdict.text.includes("folders can't sync") && r.verdict.text.includes('should work');
  }
  // D) no server saved
  {
    const r = await scenario('D_absent', { ioSpec: { state: { status: 'absent', origin: null, sftp: null } }, drive: async (win, ctx) => ({ ...(await ev(win, settle)), log: ctx.log }) });
    out.D_pass = r.log.length === 0 && r.lights.length === 0 && r.facts.length === 0 && r.box.includes('No server is set up')
      && r.buttons.map((b) => b.label).join(',') === 'Set up server…';
  }
  // E) Run again: probes anew; pulsing lights + disabled button while it runs
  {
    const r = await scenario('E_again', { ioSpec: { verify: () => new Promise((res) => setTimeout(() => res(GREEN), 700)) }, drive: async (win, ctx) => {
      await ev(win, settle);
      const before = ctx.log.length;
      await ev(win, click('Run again'));
      const mid = await ev(win, snap);
      const after = await ev(win, settle);
      return { before, mid, afterLog: ctx.log.length, after };
    } });
    out.E_pass = r.before === 1 && r.afterLog === 2 && r.mid.lights.every((l) => l.state === 'checking')
      && r.mid.buttons[0].label === 'Checking…' && r.mid.buttons[0].disabled === true && r.mid.verdict && r.mid.verdict.state === 'checking'
      && r.after.lights.every((l) => l.state === 'ok') && r.after.buttons[0].label === 'Run again' && r.after.buttons[0].disabled === false;
  }
  // F) Change server… asks main
  {
    const r = await scenario('F_change', { ioSpec: {}, drive: async (win, ctx) => { await ev(win, settle); await ev(win, click('Change server…')); return { setups: ctx.setups() }; } });
    out.F_pass = r.setups === 1;
  }
  // G) sender gate
  {
    const r = await scenario('G_gate', { ioSpec: {}, pageUrl: `${APP_ORIGIN}/`, drive: async (win, ctx) => {
      const fromRoot = await ev(win, `(async () => { const t = window.dockvault.troubleshoot; const c = await t.checks(); const d = await t.describe('server-connection'); const p = await t.probe('server-connection'); await t.openServerSetup(); await t.close(); return { c, d, p, url: location.href }; })()`);
      return { fromRoot, log: ctx.log, closes: ctx.closes(), setups: ctx.setups() };
    } });
    out.G_pass = r.fromRoot.url === `${APP_ORIGIN}/` && Array.isArray(r.fromRoot.c) && r.fromRoot.c.length === 0 && r.fromRoot.d === null && r.fromRoot.p === null
      && r.log.length === 0 && r.closes === 0 && r.setups === 0;
  }

  // H) a second check slots in; each check probes on its own
  {
    let releaseFirst = null;
    const second = {
      id: 'folder-missing', title: 'A synced folder is missing',
      describe: () => ({ id: 'folder-missing', title: 'A synced folder is missing', intro: 'Looks for each synced folder where it was last seen.', facts: [{ label: 'Folders', value: '2', mono: false }], legs: [{ id: 'f', label: 'Folders' }], canProbe: true, note: '', action: null }),
      probe: async () => ({ id: 'folder-missing', ran: true, legs: [{ id: 'f', label: 'Folders', state: 'ok', text: 'Both folders are where they were.' }], notes: [], verdict: { state: 'ok', text: 'All synced folders are present.' } }),
    };
    const r = await scenario('H_second', { checks: [...CHECKS, second], ioSpec: { verify: () => new Promise((res) => { releaseFirst = () => res(GREEN); }) }, drive: async (win, ctx) => {
      await sleep(400); // the first check is now probing and stuck until released
      const first = await ev(win, snap);
      const switched = await ev(win, clickCheck('A synced folder is missing'));
      await sleep(300);
      const secondSettled = await ev(win, snap);
      const back = await ev(win, clickCheck('Cannot connect to the server'));
      releaseFirst();
      const landed = await ev(win, settle);
      return { first, switched, secondSettled, back, landed, log: ctx.log.length };
    } });
    out.H_pass = r.first.checks.length === 2 && r.first.checks[0].current === 'true' && r.first.lights.every((l) => l.state === 'checking')
      && r.switched.checks[1].current === 'true' && r.switched.checks[0].current === null && r.switched.heading === 'A synced folder is missing'
      && r.secondSettled.lights.length === 1 && r.secondSettled.lights[0].state === 'ok' && r.secondSettled.verdict && r.secondSettled.verdict.state === 'ok' && r.secondSettled.buttons[0].label === 'Run again' && r.secondSettled.buttons[0].disabled === false
      && r.back.heading === 'Cannot connect to the server' && r.back.lights.every((l) => l.state === 'checking') && r.back.buttons[0].disabled === true
      && r.landed.lights.every((l) => l.state === 'ok') && r.landed.verdict && r.landed.verdict.state === 'ok' && r.log === 1;
  }
  // I) Run again keeps focus on the button; the verdict is a live region
  {
    const r = await scenario('I_focus', { ioSpec: {}, drive: async (win) => {
      await ev(win, settle);
      const focused = await ev(win, `(async () => { const b = [...document.querySelectorAll('#pane button')].find(x => x.textContent === 'Run again'); b.focus(); b.click(); await new Promise(r => setTimeout(r, 400)); const v = document.querySelector('.verdict'); return { active: document.activeElement && document.activeElement.textContent, live: v && v.getAttribute('aria-live'), role: v && v.getAttribute('role') }; })()`);
      return focused;
    } });
    out.I_pass = r.active === 'Run again' && r.live === 'polite' && r.role === 'status';
  }

  const KEYS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I'];
  out.ok = KEYS.every((k) => out[`${k}_pass`] === true);
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nTROUBLESHOOT CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${KEYS.map((k) => `${k}=${out[`${k}_pass`]}`).join(' ')}\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the sync setup wizard end to end — the real
 * page (src/renderer/sync-wizard.html), the real typed preload, the real conversation module (sync-wizard.js) —
 * over a recording, stubbed io, in a hidden window, driven the way a person would use it (read the screen, click
 * a button, pick a vault). The OS folder picker is the one thing stubbed away (it cannot be clicked headlessly);
 * the enable flow's own checks (sync-enable.js, sync-config.js) run for real against scratch folders. Proves:
 *   A) the happy path: set this computer up -> pick a vault -> choose a folder -> consent -> done; the config entry
 *      is saved with the vault-derived remote, the grant runs before the first run is kicked, the page shows
 *      the done statement with the folder and the outcome sentence;
 *   B) not signed in -> the sign-in statement, nothing asked, nothing saved;
 *   C) a server that does not speak sync -> the plain statement;
 *   D) no file-transfer address saved -> the address step, a wrong answer re-asks with the verdict, a right one is
 *      saved before anything else;
 *   E) Cancel at the vault step -> the flow ends cancelled, nothing saved, no further question;
 *   F) a refused folder (a system root) re-asks with the reason; the next pick proceeds;
 *   G) vaults already syncing through the sign-in -> the move offer; accepting grants each (a password vault defers);
 *   H) the sender gate: a page at the interface root cannot read or answer the wizard.
 * Writes .local/sync-wizard-check.json and prints one PASS/FAIL line. Exit 0 = PASS.
 *
 *   node_modules/electron/dist/electron.exe test/sync-wizard-check.js
 */
const { app, BrowserWindow, ipcMain, session } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createSyncWizard } = require('../src/main/sync-wizard');
const { isTrustedSetupSender } = require('../src/main/server-setup');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const { APP_ORIGIN } = require('../src/main/config');
const syncConfig = require('../src/main/sync-config');

const RESULT = path.join(__dirname, '..', '.local', 'sync-wizard-check.json');
const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const WIZARD_PAGE = 'sync-wizard.html';
const PAGE = schemeMod.shellPageUrl(APP_ORIGIN, WIZARD_PAGE);
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
schemeMod.registerPrivileged();
const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 120000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const VAULTS = [
  { vaultId: '11111111-1111-4111-8111-111111111111', vaultName: 'Photos', hasPassword: false },
  { vaultId: '22222222-2222-4222-8222-222222222222', vaultName: 'Work', hasPassword: true },
];

let theWindow = null;
function sharedWindow() {
  if (!theWindow || theWindow.isDestroyed()) {
    theWindow = new BrowserWindow({ show: false, webPreferences: { preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false } });
  }
  return theWindow;
}

// A recording io over scratch folders. `facts` overrides gather(); `folders` is the sequence the stubbed OS picker returns.
function makeIo(root, { facts = {}, folders = [], overrides = {} } = {}) {
  const log = [];
  const saved = [];
  const home = root;
  const io = {
    gather: async () => ({ signedIn: true, support: 'ok', deviceStatus: 'ok', otherServerHost: null, sftpSaved: true, sftpSuggestion: 'vault.example.com:2222', configUnreadable: false, label: 'Blue Heron', existing: [], ...facts }),
    verifySftp: async (text) => { log.push(['verifySftp', text]); return text === 'files.example.com:2200' ? { kind: 'ok', host: 'files.example.com', port: 2200, fingerprint: 'SHA256:x' } : { kind: 'unreachable', host: 'nowhere.example.com', port: 2222 }; },
    saveSftp: (ep) => log.push(['saveSftp', ep]),
    registration: { probe: async () => ({ reason: 'ok' }), readStatus: () => 'absent', forget: async () => log.push(['forget']), register: async (label) => { log.push(['register', label]); return { ok: true, deviceId: 'd1' }; } },
    grantVault: async (v) => { log.push(['grant', v.vaultId, v.hasPassword]); return v.hasPassword ? { granted: false, deferred: true } : { granted: true }; },
    addPending: (id) => log.push(['pending', id]),
    enable: {
      listVaults: async () => VAULTS,
      someExcluded: () => false,
      configuredFolder: () => null,
      vaultHasPassword: (id) => VAULTS.find((v) => v.vaultId === id).hasPassword,
      resolveReal: (p) => { try { return fs.realpathSync.native(p); } catch { return path.resolve(p); } },
      classifyCtx: () => ({ home, userData: path.join(root, 'ud'), refuseRoots: syncConfig.platformRefuseRoots(process.platform, process.env), existingFolders: [], caseInsensitive: true }),
      inspectFolderSharing: async () => ({ shares: [], denies: [] }),
      makePrivate: async () => ({ ok: true }),
      isNonEmptyDir: (p) => { try { return fs.readdirSync(p).length > 0; } catch { return false; } },
      ensureFolder: (p) => { fs.mkdirSync(p, { recursive: true }); log.push(['ensureFolder']); },
      save: (entry) => { saved.push(entry); log.push(['save', entry.vaultId]); },
    },
    pickFolderNative: async () => { const f = folders.shift(); log.push(['pick', f || null]); return f || null; },
    consentNotes: () => ({ priorFolder: null, outsideProfile: false }),
    cloudServiceName: () => 'Dropbox',
    copy: {
      refuse: (reason) => `Refused because: ${reason}.`,
      cloud: (service) => `Cloud warning for ${service}.`,
      consent: (name, folder, o) => `Consent for ${name} into ${folder}${o.nonEmpty ? ' (non-empty)' : ''}.`,
      deviceOutcome: (r, ctx) => `Outcome ${r.outcome} for ${ctx.vaultName}.`,
    },
    afterSave: (entry) => log.push(['afterSave', entry.vaultId]),
    onIdentityChanged: () => log.push(['identity']),
    ...overrides,
  };
  return { io, log, saved };
}

const snapshot = `({ title: document.getElementById('title').textContent, body: document.getElementById('body').innerText, buttons: [...document.querySelectorAll('footer button')].map(b => ({ label: b.textContent, disabled: b.disabled })), steps: [...document.querySelectorAll('.steps li')].map(li => li.dataset.state || ''), vaults: [...document.querySelectorAll('.vault .name')].map(n => n.textContent) })`;

async function scenario(name, { ioSpec, drive, pageUrl = null }) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-wizard-check-'));
  const { io, log, saved } = makeIo(root, ioSpec);
  const win = sharedWindow();
  const trusted = (e) => isTrustedSetupSender(e, { webContents: win.webContents, appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + WIZARD_PAGE });
  const questions = [];
  const wizard = createSyncWizard(io, (q) => { questions.push(q); try { if (!win.isDestroyed()) win.webContents.send('dockvault:evt:wizard', q); } catch { /* ignore */ } });
  let closed = 0;
  let opened = 0;
  for (const ch of ['dockvault:wizard.state', 'dockvault:wizard.answer', 'dockvault:wizard.close', 'dockvault:wizard.open-app']) ipcMain.removeHandler(ch);
  ipcMain.handle('dockvault:wizard.state', (e) => (trusted(e) ? wizard.currentQuestion() : null));
  ipcMain.handle('dockvault:wizard.answer', (e, a) => (trusted(e) ? wizard.answer(a.id, a.value) : false));
  ipcMain.handle('dockvault:wizard.close', (e) => { if (trusted(e)) { closed++; wizard.cancel(); } return null; });
  ipcMain.handle('dockvault:wizard.open-app', (e) => { if (trusted(e)) opened++; return null; });
  await win.loadURL(pageUrl || PAGE);
  await sleep(150);
  const run = wizard.run();
  await sleep(150);
  const r = await drive(win, { run, log, saved, questions, root, closes: () => closed, opens: () => opened });
  out[name] = r;
  try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
  return r;
}

// Wait until the page shows a different title than `prev` (a new question landed), then snapshot.
const waitNew = (prev) => `(async () => { for (let i = 0; i < 100; i++) { const t = document.getElementById('title').textContent; if (t && t !== ${JSON.stringify(prev)}) break; await new Promise(r => setTimeout(r, 50)); } await new Promise(r => setTimeout(r, 80)); return ${snapshot}; })()`;
const click = (label) => `(() => { const b = [...document.querySelectorAll('footer button')].find(x => x.textContent === ${JSON.stringify(label)}); if (!b || b.disabled) return false; b.click(); return true; })()`;
const pickVault = (name) => `(() => { const v = [...document.querySelectorAll('.vault')].find(b => b.querySelector('.name').textContent === ${JSON.stringify(name)}); if (!v) return false; v.click(); return true; })()`;

app.whenReady().then(async () => {
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, session.defaultSession);
  const ev = (win, expr) => win.webContents.executeJavaScript(expr, true);

  // A) happy path
  {
    const r = await scenario('A_happy', { ioSpec: { facts: { deviceStatus: 'absent' }, folders: ['__ROOT__/Sync/Photos'] }, drive: async (win, ctx) => {
      // The picker's answer needs the scratch root: patch it in now that we know it.
      const s1 = await ev(win, waitNew(''));
      const okSetup = await ev(win, click('Set up this computer'));
      const s2 = await ev(win, waitNew(s1.title));
      const picked = await ev(win, pickVault('Photos'));
      const okCont = await ev(win, click('Continue'));
      const s3 = await ev(win, waitNew(s2.title));
      return { s1, okSetup, s2, picked, okCont, s3 };
    } });
    // The folder pick + consent + done run in a second pass with a real scratch folder (below).
    out.A_pass1 = r.s1.title === 'Set this computer up to sync' && r.s1.body.includes('"Blue Heron"') && r.s1.steps[0] === 'current' && r.okSetup
      && r.s2.title === 'Which vault do you want to sync to this computer?' && r.s2.vaults.join(',') === 'Photos,Work' && r.s2.steps.join(',') === 'done,current,' && r.s2.buttons.find((b) => b.label === 'Continue').disabled === true
      && r.picked && r.okCont && r.s3.title === 'Choose a folder for Photos' && r.s3.steps.join(',') === 'done,done,current';
  }
  {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-wizard-folder-'));
    const folder = path.join(scratch, 'Photos');
    const r = await scenario('A_happy2', { ioSpec: { folders: [folder] }, drive: async (win, ctx) => {
      const s1 = await ev(win, waitNew(''));               // pick-vault (computer already set up: no step 1)
      await ev(win, pickVault('Photos')); await ev(win, click('Continue'));
      const s2 = await ev(win, waitNew(s1.title));         // pick-folder
      const savedBefore = ctx.saved.length;
      await ev(win, click('Choose folder…'));
      const s3 = await ev(win, waitNew(s2.title));         // consent
      const savedAtConsent = ctx.saved.length;
      await ev(win, click('Sync this vault'));
      const s4 = await ev(win, waitNew(s3.title));         // done
      const result = await ctx.run;
      await ev(win, click('Done'));
      await sleep(100);
      return { s1, s2, s3, savedBefore, savedAtConsent, s4, result, saved: ctx.saved, log: ctx.log, closes: ctx.closes(), folder };
    } });
    const logKinds = r.log.map((l) => l[0]);
    out.A_pass2 = r.s1.title === 'Which vault do you want to sync to this computer?' && r.s1.steps[0] === 'done'
      && r.s2.title === 'Choose a folder for Photos' && r.savedBefore === 0
      && r.s3.title === 'Sync Photos to this computer?' && r.s3.body.includes(folder) && r.s3.body.includes('Consent for Photos into') && r.savedAtConsent === 0
      && r.s3.buttons.map((b) => b.label).join(',') === 'Cancel setup,Choose a different folder,Sync this vault'
      && r.s4.title === 'Photos is set up to sync' && r.s4.body.includes('Outcome granted for Photos.') && r.s4.steps.join(',') === 'done,done,done'
      && r.result.kind === 'done' && r.saved.length === 1 && r.saved[0].vaultId === VAULTS[0].vaultId && r.saved[0].remotePath === 'Photos' && r.saved[0].consented === true && [path.resolve(folder).toLowerCase(), fs.realpathSync.native(folder).toLowerCase()].includes(r.saved[0].localFolder.toLowerCase())
      && JSON.stringify(logKinds) === JSON.stringify(['pick', 'ensureFolder', 'save', 'grant', 'afterSave', 'identity'])
      && r.closes === 1;
    out.A_pass = out.A_pass1 === true && out.A_pass2 === true;
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  // B) not signed in
  {
    const r = await scenario('B_signIn', { ioSpec: { facts: { signedIn: false } }, drive: async (win, ctx) => {
      const s = await ev(win, waitNew(''));
      await ev(win, click('Open DockVault'));
      await sleep(100);
      return { s, result: await ctx.run, opens: ctx.opens(), closes: ctx.closes(), saved: ctx.saved.length, questions: ctx.questions.map((q) => q.kind) };
    } });
    out.B_pass = r.s.title === 'Sign in first' && r.s.buttons.map((b) => b.label).join(',') === 'Close,Open DockVault' && r.result.kind === 'sign-in' && r.opens === 1 && r.closes === 1 && r.saved === 0 && r.questions.join(',') === 'sign-in';
  }
  // C) a server that does not speak sync
  {
    const r = await scenario('C_noSync', { ioSpec: { facts: { support: 'too-old' } }, drive: async (win, ctx) => ({ s: await ev(win, waitNew('')), result: await ctx.run, saved: ctx.saved.length }) });
    out.C_pass = r.s.title === "This server doesn't support syncing folders from this computer" && r.s.body.includes('You can still sign in') && r.result.kind === 'unsupported' && r.saved === 0;
  }
  // D) the file-transfer address step
  {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-wizard-folder-'));
    const r = await scenario('D_sftp', { ioSpec: { facts: { sftpSaved: false }, folders: [path.join(scratch, 'Photos')] }, drive: async (win, ctx) => {
      const s1 = await ev(win, waitNew(''));
      const prefilled = await ev(win, `document.getElementById('sftp').value`);
      await ev(win, `(() => { const f = document.getElementById('sftp'); f.value = 'nowhere.example.com:2222'; f.dispatchEvent(new Event('input', { bubbles: true })); })()`);
      await ev(win, click('Check and continue'));
      await sleep(300);
      const s2 = await ev(win, `(async () => { for (let i = 0; i < 100; i++) { if (document.querySelector('.box.bad')) break; await new Promise(r => setTimeout(r, 50)); } return ${snapshot}; })()`);
      const kept = await ev(win, `document.getElementById('sftp').value`);
      out.D_kept = kept === 'nowhere.example.com:2222';
      await ev(win, `(() => { const f = document.getElementById('sftp'); f.value = 'files.example.com:2200'; f.dispatchEvent(new Event('input', { bubbles: true })); })()`);
      await ev(win, click('Check and continue'));
      const s3 = await ev(win, waitNew(s2.title));
      ctx.log.push(['MARK']);
      return { s1, prefilled, s2, s3, log: ctx.log, questions: ctx.questions.map((q) => q.kind) };
    } });
    out.D_pass = r.s1.title === 'One more thing about your server' && r.prefilled === 'vault.example.com:2222'
      && r.s2.body.includes("Couldn't reach nowhere.example.com:2222") && r.s2.title === 'One more thing about your server' && r.s3.title === 'Which vault do you want to sync to this computer?'
      && JSON.stringify(r.log.filter((l) => l[0] === 'saveSftp')) === JSON.stringify([['saveSftp', { host: 'files.example.com', port: 2200 }]])
      && r.questions.slice(0, 3).join(',') === 'sftp-address,sftp-address,pick-vault' && out.D_kept === true;
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  // E) cancel at the vault step
  {
    const r = await scenario('E_cancel', { ioSpec: {}, drive: async (win, ctx) => {
      const s1 = await ev(win, waitNew(''));
      await ev(win, click('Cancel'));
      const result = await ctx.run;
      await sleep(100);
      return { s1, result, saved: ctx.saved.length, questions: ctx.questions.map((q) => q.kind) };
    } });
    out.E_pass = r.s1.title === 'Which vault do you want to sync to this computer?' && r.result.kind === 'cancelled' && r.saved === 0 && r.questions.join(',') === 'pick-vault';
  }
  // F) a refused folder re-asks with the reason
  {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-wizard-folder-'));
    const refused = process.platform === 'win32' ? (process.env.SystemRoot || 'C:\\Windows') : '/etc';
    const r = await scenario('F_refused', { ioSpec: { folders: [refused, path.join(scratch, 'Photos')] }, drive: async (win, ctx) => {
      const s1 = await ev(win, waitNew(''));
      await ev(win, pickVault('Photos')); await ev(win, click('Continue'));
      const s2 = await ev(win, waitNew(s1.title));
      await ev(win, click('Choose folder…'));
      const s3 = await ev(win, `(async () => { for (let i = 0; i < 100; i++) { if (document.querySelector('.box.bad')) break; await new Promise(r => setTimeout(r, 50)); } return ${snapshot}; })()`);
      await ev(win, click('Choose folder…'));
      const s4 = await ev(win, waitNew(s3.title));
      return { s2, s3, s4, saved: ctx.saved.length };
    } });
    out.F_pass = r.s2.title === 'Choose a folder for Photos' && r.s3.title === 'Choose a folder for Photos' && r.s3.body.includes('Refused because:')
      && r.s4.title === 'Sync Photos to this computer?' && r.saved === 0;
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  // G) vaults already syncing through the sign-in: the move offer
  {
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-wizard-folder-'));
    const existing = [{ vaultId: VAULTS[0].vaultId, vaultName: 'Photos', hasPassword: false }, { vaultId: VAULTS[1].vaultId, vaultName: 'Work', hasPassword: true }];
    const r = await scenario('G_move', { ioSpec: { facts: { existing }, folders: [path.join(scratch, 'Photos')] }, drive: async (win, ctx) => {
      const s1 = await ev(win, waitNew(''));
      await ev(win, click('Set them up here'));
      const s2 = await ev(win, waitNew(s1.title));
      await ev(win, click('Sync another vault'));
      const s3 = await ev(win, waitNew(s2.title));
      return { s1, s2, s3, log: ctx.log };
    } });
    out.G_pass = r.s1.title === '2 vaults already sync here through your sign-in' && r.s1.body.includes('Photos') && r.s1.body.includes('Work')
      && r.s1.body.includes('password-protected vault') && r.s1.buttons[0].label === 'Skip'
      && r.s2.title === 'Here is where those vaults stand' && r.s2.body.includes('Outcome granted for Photos.') && r.s2.body.includes('Outcome grant-deferred for Work.')
      && r.s3.title === 'Which vault do you want to sync to this computer?'
      && JSON.stringify(r.log.filter((l) => l[0] === 'grant' || l[0] === 'pending')) === JSON.stringify([['grant', VAULTS[0].vaultId, false], ['grant', VAULTS[1].vaultId, true], ['pending', VAULTS[1].vaultId]]);
    try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* ignore */ }
  }
  // H) the sender gate
  {
    const r = await scenario('H_gate', { ioSpec: {}, pageUrl: `${APP_ORIGIN}/`, drive: async (win, ctx) => {
      const fromRoot = await ev(win, `(async () => { const s = await window.dockvault.wizard.state(); const a = await window.dockvault.wizard.answer(1, ${JSON.stringify(VAULTS[0].vaultId)}); await window.dockvault.wizard.close(); await window.dockvault.wizard.openApp(); return { state: s, answer: a, url: location.href }; })()`);
      const pendingKind = ctx.questions.length ? ctx.questions[ctx.questions.length - 1].kind : null;
      return { fromRoot, pendingKind, closes: ctx.closes(), opens: ctx.opens(), saved: ctx.saved.length };
    } });
    out.H_pass = r.fromRoot.url === `${APP_ORIGIN}/` && r.fromRoot.state === null && r.fromRoot.answer === false && r.closes === 0 && r.opens === 0 && r.pendingKind === 'pick-vault' && r.saved === 0;
  }

  const KEYS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
  out.ok = KEYS.every((k) => out[`${k}_pass`] === true);
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nSYNC WIZARD CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${KEYS.map((k) => `${k}=${out[`${k}_pass`]}`).join(' ')}\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

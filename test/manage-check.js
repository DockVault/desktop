'use strict';
/*
 * Functional check (run under Electron, not part of `npm test`): the Computers view end to end — the real page
 * (src/renderer/manage.html), the real typed preload, the real view module (manage-view.js) — over a recording,
 * stubbed io, in a hidden window, driven the way a person would use it. Proves:
 *   A) the model renders: this computer first with its vault cards (remote, local folder, state, granted), the
 *      other computer with metadata and "managed on that computer", a revoked computer last; the local folder
 *      appears under this computer only;
 *   B) Revoke on a vault card opens an inline confirmation naming the vault and computer; Cancel does nothing;
 *      confirming asks main for exactly { kind: 'revoke-grant', deviceId, vaultId } and the view reloads;
 *   C) Revoke computer on this computer confirms and asks main; a server refusal is shown inline, nothing reloads;
 *   D) Remove from list on a revoked computer;
 *   E) Stop syncing here and Sync now on this computer's card;
 *   F) the sign-in gate renders its statement, nothing else;
 *   G) the sender gate: a page at the interface root cannot read the model or act;
 *   H) a pushed sync status refreshes a card's state without reloading the model;
 *   I) a folder that cannot be found: the card says so and its "Find the folder…" asks main for the relocate offer.
 *   J) a "Sync now" the scheduler turns away (its cooldown, or a server that is refusing this computer's sync
 *      credentials) says so inline with the wait, restores the button, and leaves the card's real state alone.
 * Writes .local/manage-check.json and prints one PASS/FAIL line. Exit 0 = PASS.
 *
 *   node_modules/electron/dist/electron.exe test/manage-check.js
 */
const { app, BrowserWindow, ipcMain, session } = require('electron');
const fs = require('node:fs');
const path = require('node:path');
const { createManageView } = require('../src/main/manage-view');
const { isTrustedSetupSender } = require('../src/main/server-setup');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');
const { APP_ORIGIN } = require('../src/main/config');

const RESULT = path.join(__dirname, '..', '.local', 'manage-check.json');
const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PAGE_NAME = 'manage.html';
const PAGE = schemeMod.shellPageUrl(APP_ORIGIN, PAGE_NAME);
const PRELOAD = path.join(__dirname, '..', 'src', 'preload', 'index.js');
schemeMod.registerPrivileged();
const out = {};
const watchdog = setTimeout(() => { out.fatal = 'watchdog-timeout'; dump(); app.exit(3); }, 120000);
function dump() { try { fs.mkdirSync(path.dirname(RESULT), { recursive: true }); fs.writeFileSync(RESULT, JSON.stringify(out, null, 2)); } catch { /* ignore */ } }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const ME = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa';
const OTHER = 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb';
const OLD = 'cccccccc-cccc-4ccc-8ccc-cccccccccccc';
const V1 = '11111111-1111-4111-8111-111111111111';
const FOLDER = path.join('C:', 'Users', 'someone', 'Photos');
const relocated = [];

function makeIo(over = {}) {
  const log = [];
  const io = {
    signedIn: () => true,
    listDevices: async () => { log.push(['listDevices']); return { ok: true, devices: [
      { device_id: OTHER, label: 'Laptop', is_active: true, created_at: '2026-01-01T00:00:00Z', last_seen: '2026-02-01T00:00:00Z', expires_at: null },
      { device_id: ME, label: 'Desk', is_active: true, created_at: '2026-01-02T00:00:00Z', last_seen: '2026-02-02T00:00:00Z', expires_at: null },
      { device_id: OLD, label: 'Old', is_active: false, created_at: '2025-01-01T00:00:00Z', last_seen: null, expires_at: null },
    ] }; },
    myIdentity: () => ({ status: 'ok', deviceId: ME }),
    myGrants: async () => ({ ok: true, grants: [{ vaultId: V1, grantedAt: '2026-01-03T00:00:00Z', name: 'Photos', metaKnown: true }] }),
    grantRecord: () => ({ status: 'ok', has: (id) => id === V1 }),
    reasonText: () => null,
    configured: () => [{ vaultId: V1, vaultName: 'Photos', localFolder: FOLDER, enabled: true }],
    liveStatus: () => ({ vaults: [{ vault: V1, state: 'up-to-date', reason: null, running: false, lastSyncedAt: 1700000000000, via: 'device' }] }),
    endpoint: () => ({ serverHost: 'vault.example.com', sftp: { host: 'files.example.com', port: 2200 } }),
    remotePathFor: (vaultId, via, name) => (via === 'device' ? `vault_${vaultId}` : name),
    revokeGrant: async (d, v) => { log.push(['revokeGrant', d, v]); return { ok: true }; },
    revokeDevice: async (d) => { log.push(['revokeDevice', d]); return { ok: true }; },
    deleteDevice: async (d) => { log.push(['deleteDevice', d]); return { ok: true }; },
    dropLocalVault: (v) => log.push(['dropLocalVault', v]),
    dropLocalIdentity: () => log.push(['dropLocalIdentity']),
    syncNow: (v) => log.push(['syncNow', v]),
    afterChange: () => log.push(['afterChange']),
    ...over,
  };
  return { io, log };
}

let theWindow = null;
function sharedWindow() {
  if (!theWindow || theWindow.isDestroyed()) {
    theWindow = new BrowserWindow({ show: false, webPreferences: { preload: PRELOAD, contextIsolation: true, sandbox: true, nodeIntegration: false } });
  }
  return theWindow;
}

const snapshot = `({
  title: document.getElementById('title').textContent, sub: document.getElementById('sub').textContent,
  text: document.getElementById('body').innerText,
  sections: [...document.querySelectorAll('.computer')].map(s => ({ name: s.querySelector('.name').textContent, badges: [...s.querySelectorAll('.head .badge')].map(b => b.textContent), buttons: [...s.querySelectorAll('.head button')].map(b => b.textContent), cards: [...s.querySelectorAll('.card')].map(c => ({ vault: c.querySelector('.vault').textContent, text: c.innerText, state: (c.querySelector('.state .meta') || {}).textContent || '', buttons: [...c.querySelectorAll('.actions > button')].map(b => b.textContent) })), note: (s.querySelector('.note') || {}).textContent || '', confirm: (s.querySelector('.confirm') || {}).textContent || '' })),
})`;
const settle = `(async () => { for (let i = 0; i < 100; i++) { if (!document.getElementById('body').innerText.startsWith('Loading')) break; await new Promise(r => setTimeout(r, 50)); } await new Promise(r => setTimeout(r, 100)); return ${snapshot}; })()`;
const clickIn = (scopeText, label) => `(async () => { const s = [...document.querySelectorAll('.computer, .card')].find(n => n.textContent.includes(${JSON.stringify(scopeText)})); if (!s) return 'no-scope'; const b = [...s.querySelectorAll('button')].find(x => x.textContent === ${JSON.stringify(label)}); if (!b) return 'no-button'; b.click(); await new Promise(r => setTimeout(r, 150)); return 'clicked'; })()`;
const confirmIn = (scopeText, label) => `(async () => { const s = [...document.querySelectorAll('.computer, .card')].find(n => n.textContent.includes(${JSON.stringify(scopeText)})); const c = s && s.querySelector('.confirm'); if (!c) return 'no-confirm'; const b = [...c.querySelectorAll('button')].find(x => x.textContent === ${JSON.stringify(label)}); if (!b) return 'no-button'; b.click(); await new Promise(r => setTimeout(r, 400)); return 'clicked'; })()`;

async function scenario(name, { ioSpec, drive, pageUrl = null }) {
  const { io, log } = makeIo(ioSpec);
  const win = sharedWindow();
  const trusted = (e) => isTrustedSetupSender(e, { webContents: win.webContents, appOrigin: APP_ORIGIN, pagePath: schemeMod.SHELL_PATH + PAGE_NAME });
  const view = createManageView(io);
  let closes = 0; let setups = 0;
  for (const ch of ['dockvault:manage.model', 'dockvault:manage.act', 'dockvault:manage.close', 'dockvault:manage.open-setup']) ipcMain.removeHandler(ch);
  ipcMain.handle('dockvault:manage.model', (e) => (trusted(e) ? view.model() : null));
  ipcMain.handle('dockvault:manage.act', (e, a) => (trusted(e) ? view.act(a) : { ok: false, reason: 'refused' }));
  ipcMain.handle('dockvault:manage.close', (e) => { if (trusted(e)) closes++; return null; });
  ipcMain.handle('dockvault:manage.open-setup', (e) => { if (trusted(e)) setups++; return null; });
  await win.loadURL(pageUrl || PAGE);
  await sleep(150);
  const r = await drive(win, { log, io, closes: () => closes, setups: () => setups });
  out[name] = r;
  return r;
}

app.whenReady().then(async () => {
  schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => null, session.defaultSession);
  const ev = (win, expr) => win.webContents.executeJavaScript(expr, true);

  // A) the model renders
  {
    const r = await scenario('A_render', { ioSpec: {}, drive: async (win) => ev(win, settle) });
    const [me, other, old] = r.sections;
    out.A_pass = r.title === 'Computers & synced folders' && r.sub === 'on vault.example.com'
      && me.name === 'Desk' && me.badges.includes('this computer') && me.cards.length === 1 && me.cards[0].vault === 'Photos'
      && me.cards[0].text.includes(`files.example.com:2200/vault_${V1}`) && me.cards[0].text.includes(FOLDER) && me.cards[0].state === 'Up to date'
      && me.cards[0].buttons.join(',') === 'Sync now,Stop syncing here,Revoke permission' && me.buttons.join(',') === 'Revoke computer'
      && other.name === 'Laptop' && other.cards.length === 0 && other.note.includes('Open DockVault on Laptop') && other.buttons.join(',') === 'Revoke computer'
      && old.name === 'Old' && old.badges.includes('revoked') && old.buttons.join(',') === 'Remove from list'
      && (r.text.split(FOLDER).length - 1) === 1;
  }
  // B) revoke a grant: confirm names things; Cancel does nothing; confirm acts and reloads
  {
    const r = await scenario('B_revokeGrant', { ioSpec: {}, drive: async (win, ctx) => {
      await ev(win, settle);
      const listsBefore = ctx.log.filter((l) => l[0] === 'listDevices').length;
      await ev(win, clickIn('Photos', 'Revoke permission'));
      const s1 = await ev(win, snapshot);
      await ev(win, confirmIn('Photos', 'Cancel'));
      const s2 = await ev(win, snapshot);
      const logAfterCancel = ctx.log.slice();
      await ev(win, clickIn('Photos', 'Revoke permission'));
      await ev(win, confirmIn('Photos', 'Revoke permission'));
      await ev(win, settle);
      return { confirm: s1.sections[0].confirm, afterCancel: s2.sections[0].confirm, logAfterCancel, log: ctx.log, listsBefore };
    } });
    out.B_pass = r.confirm.includes("Revoke this computer's permission to sync Photos?") && r.confirm.includes(FOLDER) && r.afterCancel === ''
      && !r.logAfterCancel.some((l) => l[0] === 'revokeGrant')
      && JSON.stringify(r.log.filter((l) => l[0] !== 'listDevices')) === JSON.stringify([['revokeGrant', ME, V1], ['dropLocalVault', V1], ['afterChange']])
      && r.log.filter((l) => l[0] === 'listDevices').length === r.listsBefore + 1;
  }
  // C) revoke this computer; a refusal is shown inline
  {
    const r = await scenario('C_revokeComputer', { ioSpec: {}, drive: async (win, ctx) => {
      await ev(win, settle);
      await ev(win, clickIn('Desk', 'Revoke computer'));
      const s1 = await ev(win, snapshot);
      await ev(win, confirmIn('Desk', 'Revoke computer'));
      await ev(win, settle);
      return { confirm: s1.sections[0].confirm, log: ctx.log };
    } });
    out.C_pass1 = r.confirm.includes('Revoke this computer?') && JSON.stringify(r.log.filter((l) => l[0] !== 'listDevices')) === JSON.stringify([['revokeDevice', ME], ['dropLocalIdentity'], ['afterChange']]);
    const r2 = await scenario('C_refused', { ioSpec: { revokeDevice: async () => ({ ok: false, reason: 'refused' }) }, drive: async (win, ctx) => {
      await ev(win, settle);
      await ev(win, clickIn('Laptop', 'Revoke computer'));
      await ev(win, confirmIn('Laptop', 'Revoke computer'));
      const s = await ev(win, snapshot);
      return { confirm: s.sections[1].confirm, log: ctx.log };
    } });
    out.C_pass2 = r2.confirm.includes('The server refused to make that change. Nothing was changed here.') && r2.log.filter((l) => l[0] === 'listDevices').length === 1 && !r2.log.some((l) => l[0] === 'dropLocalIdentity');
    out.C_pass = out.C_pass1 === true && out.C_pass2 === true;
  }
  // D) remove a revoked computer from the list
  {
    const r = await scenario('D_remove', { ioSpec: {}, drive: async (win, ctx) => {
      await ev(win, settle);
      await ev(win, clickIn('Old', 'Remove from list'));
      const s1 = await ev(win, snapshot);
      await ev(win, confirmIn('Old', 'Remove'));
      await ev(win, settle);
      return { confirm: s1.sections[2].confirm, log: ctx.log };
    } });
    out.D_pass = r.confirm.includes('Remove Old from your account?') && JSON.stringify(r.log.filter((l) => l[0] !== 'listDevices')) === JSON.stringify([['deleteDevice', OLD], ['afterChange']]);
  }
  // E) stop syncing here + sync now
  {
    const r = await scenario('E_local', { ioSpec: {}, drive: async (win, ctx) => {
      await ev(win, settle);
      await ev(win, clickIn('Photos', 'Sync now'));
      await sleep(300);
      await ev(win, clickIn('Photos', 'Stop syncing here'));
      const s1 = await ev(win, snapshot);
      await ev(win, confirmIn('Photos', 'Stop syncing'));
      await ev(win, settle);
      return { confirm: s1.sections[0].confirm, log: ctx.log };
    } });
    out.E_pass = r.confirm.includes('Stop syncing Photos on this computer?') && r.confirm.includes('keeps its permission')
      && JSON.stringify(r.log.filter((l) => l[0] !== 'listDevices')) === JSON.stringify([['syncNow', V1], ['dropLocalVault', V1], ['afterChange']]);
  }
  // F) sign-in gate
  {
    const r = await scenario('F_signIn', { ioSpec: { signedIn: () => false }, drive: async (win) => ev(win, settle) });
    out.F_pass = r.text.startsWith('Sign in first.') && r.sections.length === 0;
  }
  // G) sender gate
  {
    const r = await scenario('G_gate', { ioSpec: {}, pageUrl: `${APP_ORIGIN}/`, drive: async (win, ctx) => {
      const fromRoot = await ev(win, `(async () => { const m = await window.dockvault.manage.model(); const a = await window.dockvault.manage.act({ kind: 'revoke-computer', deviceId: ${JSON.stringify(ME)} }); await window.dockvault.manage.close(); return { model: m, act: a, url: location.href }; })()`);
      return { fromRoot, log: ctx.log, closes: ctx.closes() };
    } });
    out.G_pass = r.fromRoot.url === `${APP_ORIGIN}/` && r.fromRoot.model === null && r.fromRoot.act && r.fromRoot.act.ok === false && r.log.length === 0 && r.closes === 0;
  }
  // H) a pushed sync status refreshes the card without reloading the model
  {
    const r = await scenario('H_live', { ioSpec: {}, drive: async (win, ctx) => {
      const before = await ev(win, settle);
      const lists = ctx.log.filter((l) => l[0] === 'listDevices').length;
      win.webContents.send('dockvault:evt:syncstatus', { state: 'syncing', vaults: [{ vault: V1, state: 'syncing', reason: null, running: true, lastSyncedAt: 1700000000000, via: 'device' }] });
      await sleep(300);
      const after = await ev(win, snapshot);
      return { before: before.sections[0].cards[0].state, after: after.sections[0].cards[0].state, syncNowDisabled: await ev(win, `[...document.querySelectorAll('.card .actions > button')].find(b => b.textContent === 'Sync now').disabled`), lists, listsAfter: ctx.log.filter((l) => l[0] === 'listDevices').length };
    } });
    out.H_pass = r.before === 'Up to date' && r.after === 'Syncing' && r.syncNowDisabled === true && r.lists === r.listsAfter;
  }

  // I) a folder that cannot be found: the card says so and offers "Find the folder…", which asks main for the offer
  {
    const r = await scenario('I_relocate', { ioSpec: {
      liveStatus: () => ({ vaults: [{ vault: V1, state: 'needs-decision', reason: 'folder-missing', running: false, lastSyncedAt: 1700000000000, via: 'device' }] }),
      reasonText: () => "Its folder can't be found where it was.",
      relocateFolder: (v) => { relocated.push(v); },
    }, drive: async (win, ctx) => {
      const s = await ev(win, settle);
      await ev(win, clickIn('Photos', 'Find the folder…'));
      return { card: s.sections[0].cards[0], log: ctx.log };
    } });
    out.I_pass = r.card.state === 'Needs your decision' && r.card.text.includes("can't be found") && r.card.buttons[0] === 'Find the folder…'
      && relocated.length === 1 && relocated[0] === V1 && !r.log.some((l) => l[0] !== 'listDevices');
  }
  // A card in a healthy state offers no such button.
  out.I_pass = out.I_pass && !(out.A_render.sections[0].cards[0].buttons.includes('Find the folder…'));

  // J) a "Sync now" the scheduler turns away: the page says so, with the wait, and the button comes back
  {
    const answers = [
      { accepted: false, reason: 'sync-cooldown', retryInMs: 30400 },
      { accepted: false, reason: 'backing-off', retryInMs: 240000, cause: 'auth-failed' },
    ];
    const r = await scenario('J_turned_away', { ioSpec: { syncNow: (v) => { relocated.push(['syncNow', v]); return answers.shift(); } }, drive: async (win) => {
      await ev(win, settle);
      await ev(win, clickIn('Photos', 'Sync now'));
      await sleep(250);
      const cooldown = await ev(win, snapshot);
      const btn1 = await ev(win, `(() => { const b = [...document.querySelectorAll('.card .actions > button')].find(x => x.textContent === 'Sync now'); return b ? { label: b.textContent, disabled: b.disabled } : null; })()`);
      await ev(win, `(() => { const n = document.querySelector('.card .box'); if (n) n.remove(); return 'cleared'; })()`);
      await ev(win, clickIn('Photos', 'Sync now'));
      await sleep(250);
      const backingOff = await ev(win, snapshot);
      const tone = await ev(win, `(() => { const n = document.querySelector('.card .box'); return n ? n.className : null; })()`);
      return { cooldown: cooldown.sections[0].cards[0], backingOff: backingOff.sections[0].cards[0], btn1, tone };
    } });
    const cd = r.cooldown.text; const bo = r.backingOff.text;
    out.J_pass = cd.includes('was used a moment ago') && cd.includes('31 seconds') && cd.includes('regular schedule')
      && bo.includes('refusing this computer') && bo.includes('4 minutes') && bo.includes('sign in or enter the vault password')
      && r.btn1 && r.btn1.label === 'Sync now' && r.btn1.disabled === false   // the button is usable again
      && r.cooldown.state === 'Up to date' && r.backingOff.state === 'Up to date' // the card's real state is untouched
      && r.tone === 'box'; // a calm note, not the red refusal box
  }

  const KEYS = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J'];
  out.ok = KEYS.every((k) => out[`${k}_pass`] === true);
  clearTimeout(watchdog);
  dump();
  process.stdout.write(`\nMANAGE CHECK: ${out.ok ? 'PASS' : 'FAIL'}  ${KEYS.map((k) => `${k}=${out[`${k}_pass`]}`).join(' ')}\n  details: ${RESULT}\n`);
  app.exit(out.ok ? 0 : 1);
}).catch((e) => { out.fatal = String((e && e.stack) || e); dump(); app.exit(2); });

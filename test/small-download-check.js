'use strict';

/*
 * Live check (run under Electron against a RUNNING throwaway vault, not part of `npm test`): small files
 * download from the main window, from a zero-knowledge vault and from a Standard one.
 *
 * The bundled interface streams a download through its download worker: it opens a slot, writes the
 * file into it, says it is done, and a hidden frame asks the worker for the slot. A small
 * zero-knowledge file is decrypted and written at once, so the page says "done" before the frame's
 * request reaches the worker; the pinned worker had already dropped the slot by then and answered 404,
 * and nothing downloaded, with no error. The app serves its own copy of the worker, which keeps a
 * finished slot until its request comes.
 *
 * Each run uses a window like the main window (the app's scheme handler, policy and in-memory
 * partition, a sandboxed page) and drives the bundled interface as a person would: sign in through the
 * form, set up the account's encryption key, create a zero-knowledge vault, upload files of 10 B, 1 KB
 * and 30 KB through the file picker, and download each one twice through the interface's own
 * downloadFile. A download passes when the browser saved it from the worker's address and its bytes
 * equal the upload.
 *   - bundle:  the app's worker. Every download must pass, from the zero-knowledge vault and from a
 *              Standard vault (the same sizes, through the same window).
 *   - control: the zero-knowledge part again, with the pinned worker served in its place. At least one
 *              of those downloads must be lost, or the check could not have seen the defect, and it
 *              fails.
 *
 * Isolation: two throwaway accounts (one per run) created through the admin API, their vaults, and
 * in-memory partitions; all deleted at the end (Electron keeps its own profile in .local). If
 * zero-knowledge vaults are off on the server they are switched on for the run and off again after.
 *
 *   DOCKVAULT_PROOF_API            the vault's origin, for example http://localhost:8080 (required)
 *   DOCKVAULT_PROOF_ADMIN_PW_FILE  a file holding the admin password (required)
 *   DOCKVAULT_PROOF_ADMIN_USER     the admin account's name (default admin)
 *   DOCKVAULT_PROOF_INSECURE_TLS   1 to accept a test server's self-signed certificate (test servers only)
 *
 * Writes .local/small-download-check.json (one row per step and per download) and prints one line.
 * Exit 0 = PASS. No password or token is written to the result.
 *
 *   node_modules/electron/dist/electron.exe test/small-download-check.js
 */

const { app, BrowserWindow, session } = require('electron');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { APP_ORIGIN, APP_SCHEME } = require('../src/main/config');
const schemeMod = require('../src/main/scheme');
const { buildCsp } = require('../src/main/csp');

if (process.env.DOCKVAULT_PROOF_INSECURE_TLS === '1') app.commandLine.appendSwitch('ignore-certificate-errors'); // a TEST server's self-signed cert; never the app
const httpJson = require('../src/main/http-json').createHttpJson(require('electron').net);

const API = String(process.env.DOCKVAULT_PROOF_API || '').replace(/\/+$/, '');
const ADMIN_USER = process.env.DOCKVAULT_PROOF_ADMIN_USER || 'admin';
const ADMIN_PW = process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE ? fs.readFileSync(process.env.DOCKVAULT_PROOF_ADMIN_PW_FILE, 'utf8').trim() : '';
const RESULT = path.join(__dirname, '..', '.local', 'small-download-check.json');
const STATIC_ROOT = path.resolve(__dirname, '..', 'vendor', 'vault', 'static');
const PINNED_WORKER = path.join(STATIC_ROOT, 'js', 'download-sw.js');
const ZK_SIZES = [10, 1000, 30000];
const STANDARD_SIZES = [10, 1000, 30000];
const REPEATS = 2;

const out = { api: API, rows: [], downloads: [] };
const secrets = [ADMIN_PW];
const cleanup = [];
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-small-download-'));
// Electron's own profile, never the real one: in the ignored .local folder and reused by every run (a running
// process keeps it open, so a temporary one could not be removed at the end).
app.setPath('userData', path.join(__dirname, '..', '.local', 'small-download-check-profile'));

function row(name, ok, detail) { out.rows.push({ row: name, ok: !!ok, detail: detail === undefined ? null : detail }); }
function scrub(text) { let t = String(text); for (const s of secrets) if (s) t = t.split(s).join('[redacted]'); return t; }
function dump() {
  try {
    fs.mkdirSync(path.dirname(RESULT), { recursive: true });
    const text = JSON.stringify(out, null, 2);
    out.leakFree = secrets.every((s) => !s || !text.includes(s));
    fs.writeFileSync(RESULT, scrub(JSON.stringify(out, null, 2)));
  } catch { /* ignore */ }
}
async function teardown() {
  for (const step of cleanup.reverse()) { try { await step(); } catch { /* best effort */ } }
  cleanup.length = 0;
  try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
}
const watchdog = setTimeout(async () => { row('watchdog', false, 'timed out'); await teardown(); dump(); app.exit(3); }, 10 * 60 * 1000);
app.disableHardwareAcceleration();
schemeMod.registerPrivileged();
app.on('window-all-closed', () => {});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function api(pathname, init = {}) {
  const res = await httpJson(`${API}${pathname}`, init);
  let body = null; try { body = await res.json(); } catch { body = null; }
  return { ok: res.ok, status: res.status, body };
}
const auth = (token, extra = {}) => ({ Authorization: `Bearer ${token}`, ...extra });
const jsonBody = () => ({ 'Content-Type': 'application/json' });
const post = (p, token, body) => api(p, { method: 'POST', headers: auth(token, jsonBody()), body: JSON.stringify(body || {}) });

// ---- driving the page --------------------------------------------------------------------------------
const q = (s) => JSON.stringify(s);
const js = (win, code) => win.webContents.executeJavaScript(code, true);
async function waitFor(win, code, ms, what) {
  const end = Date.now() + ms;
  for (;;) {
    let v = null;
    try { v = await js(win, code); } catch { v = null; }
    if (v) return v;
    if (Date.now() > end) throw new Error(`timed out waiting for ${what}`);
    await sleep(250);
  }
}
const visible = (sel) => `(() => { const e = document.querySelector(${q(sel)}); return !!(e && e.getClientRects().length && getComputedStyle(e).visibility !== 'hidden'); })()`;
const hidden = (sel) => `(() => { const e = document.querySelector(${q(sel)}); return !(e && e.getClientRects().length); })()`;
async function click(win, sel) {
  await waitFor(win, visible(sel), 15000, sel);
  await js(win, `document.querySelector(${q(sel)}).click()`);
}
async function fill(win, sel, value) {
  await waitFor(win, visible(sel), 15000, sel);
  await js(win, `(() => { const e = document.querySelector(${q(sel)}); e.value = ${q(value)};
    e.dispatchEvent(new Event('input', { bubbles: true })); e.dispatchEvent(new Event('change', { bubbles: true })); })()`);
}

// The pinned worker, answered the way the scheme answers the app's own (the control only).
function pinnedWorkerResponse() {
  return new Response(fs.readFileSync(PINNED_WORKER), {
    headers: { 'content-type': 'text/javascript; charset=utf-8', 'Service-Worker-Allowed': '/', 'Cache-Control': 'no-cache' },
  });
}

async function makeAccount(adminJwt, label) {
  const username = `smalldl-${label}-${crypto.randomBytes(4).toString('hex')}`;
  const password = `Dv-${crypto.randomBytes(12).toString('hex')}-9aA!`;
  secrets.push(password);
  const made = await post('/users', adminJwt, { username, password, role: 'user', email: `${username}@example.com` });
  const id = made.body && made.body.id;
  row(`${label}: account created`, !!id, made.status);
  if (!id) throw new Error('account not created');
  cleanup.push(() => post(`/users/${id}/delete`, adminJwt, {}));
  const login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username, password }) });
  const jwt = login.body && login.body.access_token;
  if (jwt) secrets.push(jwt);
  if (!jwt) throw new Error(`account sign-in over the API failed (${login.status})`);
  return { id, username, password, jwt };
}

async function openVault(win, vid) {
  await click(win, '.sidebar-item[data-section="vaults"]');
  await click(win, `.open-vault-btn[data-vault-id="${vid}"]`);
  await waitFor(win, `(typeof state !== 'undefined' && state.currentVault && state.currentVault.id === ${q(vid)}) && ${visible('#vault-view-section')}`, 15000, 'the vault to open');
}

// Upload one file through the file picker and return its id once the listing shows it.
async function upload(win, name, bytes) {
  const before = await js(win, '(state.currentFiles || []).map((f) => f.id)');
  await js(win, `(() => {
    const b64 = ${q(Buffer.from(bytes).toString('base64'))};
    const raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
    const dt = new DataTransfer(); dt.items.add(new File([raw], ${q(name)}, { type: 'application/octet-stream' }));
    const input = document.getElementById('file-upload-input'); input.files = dt.files;
    input.dispatchEvent(new Event('change', { bubbles: true }));
  })()`);
  return waitFor(win, `(async () => {
    try { await loadVaultFiles(state.currentVault.id); } catch (e) { return null; }
    const known = new Set(${q(before)});
    const added = (state.currentFiles || []).filter((f) => !known.has(f.id));
    return added.length ? added[0].id : null;
  })()`, 60000, `${name} to be listed`);
}

// Download through the interface's own downloadFile; the browser's download is recorded by the session.
async function download(win, recorder, fileId, name) {
  const index = recorder.list.length;
  const outcome = await js(win, `(async () => {
    const f = (state.currentFiles || []).find((x) => x.id === ${q(fileId)}) || {};
    try { await downloadFile(${q(fileId)}, f.name || f.original_filename || ${q(name)}); return 'resolved'; }
    catch (e) { return 'rejected: ' + (e && e.message); }
  })()`);
  const end = Date.now() + 10000;
  while (Date.now() < end && !(recorder.list.length > index && recorder.list[index].state)) await sleep(200);
  const rec = recorder.list.length > index ? recorder.list[index] : null;
  return { outcome, rec };
}

async function runFlow(label, adminJwt, { pinnedWorker, standard }) {
  const result = { label, downloads: [] };
  const account = await makeAccount(adminJwt, label);
  const partition = `small-download-${label}`;
  const ses = session.fromPartition(partition);   // in-memory, like the main window's
  if (pinnedWorker) {
    let inner = null;
    schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => API, { protocol: { handle: (_s, h) => { inner = h; } } });
    ses.protocol.handle(APP_SCHEME, (request) => (new URL(request.url).pathname === schemeMod.DOWNLOAD_WORKER_PATH
      ? pinnedWorkerResponse() : inner(request)));
  } else {
    schemeMod.installHandler(STATIC_ROOT, buildCsp(), () => API, ses);
  }
  const dir = path.join(tmp, label);
  fs.mkdirSync(dir, { recursive: true });
  const recorder = { list: [] };
  ses.on('will-download', (_e, item) => {
    const rec = { url: item.getURL().slice(0, 40), total: item.getTotalBytes(), state: null, received: 0 };
    recorder.list.push(rec);
    rec.file = path.join(dir, `download-${recorder.list.length}.bin`);
    item.setSavePath(rec.file);
    item.once('done', (_e2, state) => { rec.state = state; rec.received = item.getReceivedBytes(); });
  });

  const win = new BrowserWindow({ show: false, width: 1280, height: 860, webPreferences: { partition, contextIsolation: true, sandbox: true, nodeIntegration: false } });
  try {
    await win.loadURL(`${APP_ORIGIN}/`);
    await js(win, 'window.alert = () => {}; window.confirm = () => false; true');
    await fill(win, '#username', account.username);
    await fill(win, '#password', account.password);
    await js(win, "document.getElementById('password').form.requestSubmit(); true");
    await waitFor(win, visible('#dashboard-screen'), 20000, 'the dashboard');
    row(`${label}: signed in through the form`, !(await js(win, 'location.href')).includes(account.password));

    // The account's encryption key, through the standalone set-up: acknowledge, then the passphrase twice.
    const passphrase = `Pass-${crypto.randomBytes(8).toString('hex')}`;
    secrets.push(passphrase);
    await click(win, '#profile-btn');
    await click(win, '#encryption-key-btn');
    await click(win, '#encryption-key-setup-btn');
    await click(win, '#confirm-modal-confirm-btn');
    for (let i = 0; i < 2; i++) {
      await fill(win, '#confirm-modal-input', passphrase);
      await click(win, '#confirm-modal-confirm-btn');
      await sleep(300);
    }
    await waitFor(win, `(document.getElementById('encryption-key-status') || {}).textContent.includes('set up and active')`, 20000, 'the encryption key');
    await js(win, "document.querySelector('#encryption-key-modal .close-modal-btn').click(); true");
    row(`${label}: encryption key set up`, true);

    // A zero-knowledge vault, through the create form.
    const vname = `smalldl-zk-${crypto.randomBytes(3).toString('hex')}`;
    await click(win, '.sidebar-item[data-section="vaults"]');
    await click(win, '#create-vault-btn');
    await fill(win, '#vault-name', vname);
    await fill(win, '#vault-type', 'zero_knowledge');
    await fill(win, '#vault-label', vname);
    await click(win, '#create-vault-form button[type=submit]');
    await waitFor(win, hidden('#create-vault-modal'), 20000, 'the create form to close');
    const listed = await api('/vaults', { headers: auth(account.jwt) });
    const zk = (Array.isArray(listed.body) ? listed.body : []).find((v) => v.name === vname);
    row(`${label}: zero-knowledge vault created`, !!zk, listed.status);
    if (!zk) throw new Error('zero-knowledge vault not created');
    cleanup.push(() => post(`/vaults/${zk.id}/delete`, account.jwt, {}));

    const vaults = [{ kind: 'zero-knowledge', id: zk.id, sizes: ZK_SIZES }];
    if (standard) {
      const made = await post('/vaults', account.jwt, { name: `smalldl-std-${crypto.randomBytes(3).toString('hex')}`, type: 'standard' });
      const sid = made.body && made.body.id;
      row(`${label}: Standard vault created`, !!sid, made.status);
      if (!sid) throw new Error('Standard vault not created');
      cleanup.push(() => post(`/vaults/${sid}/delete`, account.jwt, {}));
      vaults.push({ kind: 'standard', id: sid, sizes: STANDARD_SIZES });
    }

    for (const vault of vaults) {
      await openVault(win, vault.id);
      result.sink = await js(win, 'state.downloadSink');
      row(`${label}: ${vault.kind} vault opened, downloads stream`, result.sink === 'streaming', result.sink);
      for (const size of vault.sizes) {
        const bytes = crypto.randomBytes(size);
        const name = `small-${size}.bin`;
        const fileId = await upload(win, name, bytes);
        for (let r = 0; r < REPEATS; r++) {
          const { outcome, rec } = await download(win, recorder, fileId, name);
          let same = false;
          if (rec && rec.state === 'completed') { try { same = fs.readFileSync(rec.file).equals(bytes); } catch { same = false; } }
          const streamed = !!(rec && rec.url.startsWith(`${APP_ORIGIN}/__dv_sink__/`));
          const d = { run: label, vault: vault.kind, size, attempt: r + 1, page: outcome,
            download: rec ? { state: rec.state, received: rec.received, streamed } : null, ok: same && streamed };
          result.downloads.push(d);
          out.downloads.push(d);
        }
      }
    }
  } finally {
    win.destroy();
  }
  return result;
}

app.whenReady().then(async () => {
  if (!API || !ADMIN_PW) {
    row('config', false, 'DOCKVAULT_PROOF_API and DOCKVAULT_PROOF_ADMIN_PW_FILE are required');
    dump(); app.exit(2); return;
  }
  try {
    const login = await api('/auth/login', { method: 'POST', headers: jsonBody(), body: JSON.stringify({ username: ADMIN_USER, password: ADMIN_PW }) });
    const adminJwt = login.body && login.body.access_token;
    if (adminJwt) secrets.push(adminJwt);
    row('admin sign-in', !!adminJwt, login.status);
    if (!adminJwt) throw new Error('admin sign-in failed');
    const settings = await api('/settings', { headers: auth(adminJwt) });
    if (!(settings.body && settings.body.zero_knowledge_enabled === true)) {
      const on = await api('/settings', { method: 'PUT', headers: auth(adminJwt, jsonBody()), body: JSON.stringify({ zero_knowledge_enabled: true }) });
      row('zero-knowledge vaults switched on for the run', on.ok, on.status);
      cleanup.push(() => api('/settings', { method: 'PUT', headers: auth(adminJwt, jsonBody()), body: JSON.stringify({ zero_knowledge_enabled: false }) }));
    }

    const bundle = await runFlow('bundle', adminJwt, { pinnedWorker: false, standard: true });
    const control = await runFlow('control', adminJwt, { pinnedWorker: true, standard: false });

    out.bundleAllDownloaded = bundle.downloads.length === (ZK_SIZES.length + STANDARD_SIZES.length) * REPEATS
      && bundle.downloads.every((d) => d.ok);
    out.controlLost = control.downloads.filter((d) => !d.ok).length;
    out.controlShowsDefect = out.controlLost > 0;
    row('bundle: every small download arrived whole, through the worker', out.bundleAllDownloaded,
      `${bundle.downloads.filter((d) => d.ok).length}/${bundle.downloads.length}`);
    row('control: the pinned worker lost a small zero-knowledge download', out.controlShowsDefect,
      `${out.controlLost}/${control.downloads.length} lost`);
  } catch (e) {
    row('fatal', false, scrub(String((e && e.message) || e)));
  }
  await teardown();
  out.ok = out.rows.every((r) => r.ok);
  clearTimeout(watchdog);
  dump();
  console.log(scrub(JSON.stringify({ ok: out.ok, bundleAllDownloaded: out.bundleAllDownloaded, controlShowsDefect: out.controlShowsDefect, controlLost: out.controlLost })));
  app.exit(out.ok ? 0 : 1);
}).catch(async (e) => { row('fatal', false, scrub(String((e && e.stack) || e))); await teardown(); dump(); app.exit(2); });

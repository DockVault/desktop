'use strict';

// The Troubleshoot view's checks: what the first check says about the saved setting, how it lights each leg
// of the live probe, that it probes only what is saved, and that another check slots into the registry.

const test = require('node:test');
const assert = require('node:assert/strict');

const { createTroubleshoot, CHECKS, verdictOf, apiSentence, sftpSentence, syncSentence, apiState, sftpState, HINTS } = require('../src/main/troubleshoot');

const SAVED = { status: 'ok', origin: 'https://vault.example.com', envOrigin: null, fileOrigin: 'https://vault.example.com', envOverrides: false, sftp: { host: 'vault.example.com', port: 2222 } };

function green() {
  return { api: { kind: 'ok', host: 'vault.example.com' }, sync: { kind: 'supported' }, sftp: { kind: 'ok', host: 'vault.example.com', port: 2222, fingerprint: 'SHA256:abc' }, proceed: true, endpoint: { host: 'vault.example.com', port: 2222 }, origin: 'https://vault.example.com' };
}

function make({ state = SAVED, verify = async () => green() } = {}) {
  const calls = [];
  const io = { serverState: () => state, verify: async (fields) => { calls.push(fields); return verify(fields); } };
  return { view: createTroubleshoot(io), calls };
}

test('the registry lists the checks on offer, by id and title only', () => {
  const { view } = make();
  assert.deepEqual(view.checks(), [
    { id: 'server-connection', title: 'Cannot connect to the server' },
    { id: 'folder-missing', title: 'A synced folder is missing' },
  ]);
  // The connection check stays first: it is the one that explains the most other symptoms.
  assert.equal(CHECKS[0].id, 'server-connection');
  // Pinned as a set, so a new check is a deliberate change to this line rather than a silent addition.
  assert.equal(CHECKS.length, 2);
});

test('describe shows the tied server host with its API port, and the SFTP address — and offers Change server', () => {
  const { view } = make();
  const d = view.describe('server-connection');
  assert.equal(d.title, 'Cannot connect to the server');
  assert.deepEqual(d.facts, [
    { label: 'Server address', value: 'vault.example.com:443', mono: true },
    { label: 'File transfer address', value: 'vault.example.com:2222', mono: true },
  ]);
  assert.match(d.intro, /both of your server's doors/);
  assert.deepEqual(d.legs, [{ id: 'api', label: 'Server' }, { id: 'sftp', label: 'File transfer (SFTP)' }]);
  assert.equal(d.canProbe, true);
  assert.deepEqual(d.action, { kind: 'change-server', label: 'Change server…' });
  assert.equal(d.note, '');
});

test('an explicit port, a plain-http loopback, and a missing SFTP address are shown as they are', () => {
  const { view } = make({ state: { ...SAVED, origin: 'https://vault.example.com:8443', sftp: null } });
  const d = view.describe('server-connection');
  assert.equal(d.facts[0].value, 'vault.example.com:8443');
  assert.deepEqual(d.facts[1], { label: 'File transfer address', value: 'not saved', mono: false });
  const dev = make({ state: { ...SAVED, origin: 'http://localhost:8000' } }).view.describe('server-connection');
  assert.equal(dev.facts[0].value, 'http://localhost:8000');
});

test('no server saved: nothing to probe, a plain note, and the setup door', () => {
  const { view, calls } = make({ state: { status: 'absent', origin: null, sftp: null } });
  const d = view.describe('server-connection');
  assert.equal(d.canProbe, false);
  assert.deepEqual(d.facts, []);
  assert.equal(d.intro, '', 'no "tries both doors" when there is nothing to try');
  assert.match(d.note, /No server is set up/);
  assert.deepEqual(d.action, { kind: 'setup-server', label: 'Set up server…' });
  return view.probe('server-connection').then((r) => { assert.equal(r.ran, false); assert.equal(calls.length, 0, 'nothing is contacted'); });
});

test('an unreadable setting is not treated as absent: it says so and offers to replace it', () => {
  const { view } = make({ state: { status: 'unreadable', origin: null, sftp: null } });
  const d = view.describe('server-connection');
  assert.equal(d.canProbe, false);
  assert.match(d.note, /can't be read/);
  assert.deepEqual(d.action, { kind: 'setup-server', label: 'Set up server…' }, 'the same door the tray offers for this state');
});

test('an environment override is named as what is in force, and gets no Change server door (it would be ignored)', () => {
  const { view } = make({ state: { ...SAVED, status: 'env', envOrigin: 'https://dev.example.com', origin: 'https://dev.example.com', envOverrides: true, sftp: null } });
  const d = view.describe('server-connection');
  assert.equal(d.facts[0].value, 'dev.example.com:443');
  assert.match(d.facts[2].value, /DOCKVAULT_SERVER environment variable, overriding/);
  assert.equal(d.action, null);
  assert.match(d.note, /can't be changed from here/);
  assert.equal(d.canProbe, true);
});

test('under an environment override the probe verifies the override, and no sentence points at a Change server door that is not there', async () => {
  const state = { ...SAVED, status: 'env', envOrigin: 'https://dev.example.com', origin: 'https://dev.example.com', envOverrides: true, sftp: null };
  const { view, calls } = make({ state, verify: async () => ({ api: { kind: 'not-dockvault', host: 'dev.example.com' }, sync: { kind: 'not-checked' }, sftp: { kind: 'empty', host: '', port: 0 }, proceed: false }) });
  const r = await view.probe('server-connection');
  assert.deepEqual(calls, [{ input: 'https://dev.example.com', sftp: '' }]);
  for (const leg of r.legs) { assert.ok(!leg.text.includes('Change server'), leg.text); assert.match(leg.text, /DOCKVAULT_SERVER/); }
});

test('the probe verifies exactly the saved origin and SFTP address — never anything the page could name', async () => {
  const { view, calls } = make();
  const r = await view.probe('server-connection');
  assert.deepEqual(calls, [{ input: 'https://vault.example.com', sftp: 'vault.example.com:2222' }]);
  assert.equal(r.ran, true);
  assert.deepEqual(r.legs.map((l) => [l.id, l.state]), [['api', 'ok'], ['sftp', 'ok']]);
  assert.match(r.legs[0].text, /answered as a DockVault server/);
  assert.match(r.legs[1].text, /proved it is who it says it is/);
  assert.equal(r.legs[1].detail, 'Host key fingerprint SHA256:abc');
  assert.deepEqual(r.notes, ['This server can sync folders from this computer.']);
  assert.equal(r.verdict.state, 'ok');
  assert.match(r.verdict.text, /Both doors answered/);
  assert.ok(!JSON.stringify(r).includes('hostKey'), 'no key line travels');
});

test('server down: the server leg is red, the verdict says nothing else can work', async () => {
  const { view } = make({ verify: async () => ({ api: { kind: 'unreachable', host: 'vault.example.com' }, sync: { kind: 'not-checked' }, sftp: { kind: 'unreachable', host: 'vault.example.com', port: 2222 }, proceed: false }) });
  const r = await view.probe('server-connection');
  assert.deepEqual(r.legs.map((l) => l.state), ['bad', 'bad']);
  assert.match(r.legs[0].text, /Nothing answered at vault.example.com/);
  assert.deepEqual(r.notes, []);
  assert.equal(r.verdict.state, 'bad');
  assert.match(r.verdict.text, /can't be reached from this computer right now/);
});

test('server up, SFTP door closed: partial — signing in works, folders cannot sync', async () => {
  const { view } = make({ verify: async () => ({ ...green(), sftp: { kind: 'unreachable', host: 'vault.example.com', port: 2222 }, proceed: false }) });
  const r = await view.probe('server-connection');
  assert.deepEqual(r.legs.map((l) => l.state), ['ok', 'bad']);
  assert.match(r.legs[1].text, /file transfer port may be closed/);
  assert.equal(r.verdict.state, 'partial');
  assert.match(r.verdict.text, /should work/, 'signing in was not tried, so it is not claimed');
});

test('a host key the door could not prove is red with its own warning — leg and verdict alike, never neutral', async () => {
  const { view } = make({ verify: async () => ({ ...green(), sftp: { kind: 'host-key-unverified', host: 'vault.example.com', port: 2222 }, proceed: false }) });
  const r = await view.probe('server-connection');
  assert.equal(r.legs[1].state, 'bad');
  assert.match(r.legs[1].text, /couldn't prove it owns/);
  assert.equal(r.verdict.state, 'bad');
  assert.match(r.verdict.text, /couldn't prove/);
});

test('a server reporting a problem on its side is amber, not green — on its leg and in the verdict', async () => {
  const { view } = make({ verify: async () => ({ ...green(), api: { kind: 'degraded', host: 'vault.example.com' } }) });
  const r = await view.probe('server-connection');
  assert.equal(r.legs[0].state, 'warn');
  assert.equal(r.verdict.state, 'partial');
  assert.match(r.verdict.text, /Both doors answered, but the server reports a problem/);
});

test('a server that answers wrongly is not called unreachable', async () => {
  for (const kind of ['tls-untrusted', 'not-dockvault', 'redirected']) {
    const { view } = make({ verify: async () => ({ api: { kind, host: 'vault.example.com' }, sync: { kind: 'not-checked' }, sftp: { kind: 'ok', host: 'vault.example.com', port: 2222, fingerprint: 'SHA256:abc' }, proceed: false }) });
    const r = await view.probe('server-connection');
    assert.equal(r.verdict.state, 'bad');
    assert.match(r.verdict.text, /Something answered at vault.example.com, but not in a way DockVault can use/);
    assert.ok(!r.verdict.text.includes("can't be reached"), kind);
  }
});

test('a server without sync: the SFTP leg is set aside and the verdict is still green', async () => {
  const { view } = make({ state: { ...SAVED, sftp: null }, verify: async () => ({ api: { kind: 'ok', host: 'vault.example.com' }, sync: { kind: 'unsupported' }, sftp: { kind: 'not-needed', host: '', port: 0 }, proceed: true }) });
  const r = await view.probe('server-connection');
  assert.equal(r.legs[1].state, 'skip');
  assert.match(r.legs[1].text, /doesn't sync folders from a computer/);
  assert.deepEqual(r.notes, [], 'the leg already says it; no second note saying the same');
  assert.equal(r.verdict.state, 'ok');
});

test('a verify that throws or answers nonsense is reported as the check failing, not as the connection failing', async () => {
  for (const verify of [async () => { throw new Error('boom'); }, async () => 'nope']) {
    const { view } = make({ verify });
    const r = await view.probe('server-connection');
    assert.deepEqual(r.legs.map((l) => l.state), ['bad', 'bad']);
    assert.match(r.legs[0].text, /Couldn't run this check/);
    assert.match(r.verdict.text, /says nothing about your connection/);
  }
});

test('one live probe per check at a time: a second ask joins the first', async () => {
  let resolve = null;
  const { view, calls } = make({ verify: () => (resolve ? green() : new Promise((r) => { resolve = r; })) });
  const a = view.probe('server-connection');
  const b = view.probe('server-connection');
  assert.equal(a, b);
  resolve(green());
  await a;
  assert.equal(calls.length, 1);
  await view.probe('server-connection');
  assert.equal(calls.length, 2, 'a later ask runs anew');
});

test('an unknown or malformed check id gets nothing', async () => {
  const { view } = make();
  assert.equal(view.describe('nope'), null);
  assert.equal(view.describe(42), null);
  assert.equal(view.describe({}), null);
  assert.equal(await view.probe('nope'), null);
  assert.equal(await view.probe(undefined), null);
});

test('another check slots into the registry without changing the view or the page contract', async () => {
  // A made-up id, deliberately not one the registry really has: this test is about the registry taking a
  // NEW entry, and reusing a real id would make it collide rather than extend.
  const extra = {
    id: 'made-up-check', title: 'Something else entirely',
    describe: () => ({ id: 'made-up-check', title: 'Something else entirely', intro: '', facts: [{ label: 'Folders', value: '2', mono: false }], legs: [{ id: 'f', label: 'Folders' }], canProbe: true, note: '', action: null }),
    probe: async () => ({ id: 'made-up-check', ran: true, legs: [{ id: 'f', label: 'Folders', state: 'ok', text: 'All present.' }], notes: [], verdict: { state: 'ok', text: 'Fine.' } }),
  };
  const view = createTroubleshoot({ serverState: () => SAVED, verify: async () => green() }, { checks: [...CHECKS, extra] });
  assert.deepEqual(view.checks().map((c) => c.id), ['server-connection', 'folder-missing', 'made-up-check']);
  assert.equal(view.describe('made-up-check').facts[0].value, '2');
  assert.equal((await view.probe('made-up-check')).verdict.state, 'ok');
});

test('a check whose describe or probe throws is contained', async () => {
  const broken = { id: 'b', title: 'B', describe: () => { throw new Error('x'); }, probe: async () => { throw new Error('y'); } };
  const view = createTroubleshoot({ serverState: () => SAVED, verify: async () => green() }, { checks: [broken] });
  assert.match(view.describe('b').note, /couldn't read/);
  assert.equal(view.describe('b').canProbe, false);
  const r = await view.probe('b');
  assert.equal(r.ran, false);
  assert.equal(r.verdict.state, 'bad');
});

test('verdicts cover every combination the verify can produce, and green needs both doors proven', () => {
  const api = { kind: 'ok', host: 'h' };
  const SFTP_KINDS = ['ok', 'not-needed', 'empty', 'malformed', 'unreachable', 'not-ssh', 'ssh-unsupported', 'host-key-unverified', 'failed'];
  const API_KINDS = ['ok', 'degraded', 'unreachable', 'tls-untrusted', 'not-dockvault', 'redirected', 'http-refused', 'malformed', 'empty', 'failed'];
  for (const a of API_KINDS) for (const s of SFTP_KINDS) {
    const v = verdictOf({ api: { kind: a, host: 'h' }, sftp: { kind: s, host: 'h', port: 1 } });
    assert.ok(['ok', 'partial', 'bad'].includes(v.state) && v.text.length > 20, `${a}/${s}`);
    if (v.state === 'ok') assert.ok(a === 'ok' && (s === 'ok' || s === 'not-needed'), `green only when proven: ${a}/${s}`);
  }
  assert.equal(verdictOf({ api, sftp: { kind: 'ok' } }).state, 'ok');
  assert.equal(verdictOf({ api, sftp: { kind: 'not-needed' } }).state, 'ok');
  assert.equal(verdictOf({ api, sftp: { kind: 'empty' } }).state, 'partial');
  assert.equal(verdictOf({ api, sftp: { kind: 'host-key-unverified' } }).state, 'bad');
  assert.equal(verdictOf({ api: { kind: 'degraded', host: 'h' }, sftp: { kind: 'ok' } }).state, 'partial');
  assert.equal(verdictOf({ api: { kind: 'degraded', host: 'h' }, sftp: { kind: 'unreachable' } }).state, 'partial');
  assert.equal(verdictOf({ api: { kind: 'tls-untrusted', host: 'h' }, sftp: { kind: 'ok' } }).state, 'bad');
  assert.equal(verdictOf({ api: { kind: 'failed' }, sftp: { kind: 'failed' } }).state, 'bad');
});

test('every leg kind has its own sentence in the house voice, and the leg states follow the kinds', () => {
  const api = { host: 'vault.example.com', from: 'old.example.com' };
  const seen = new Set();
  for (const kind of ['ok', 'degraded', 'unreachable', 'tls-untrusted', 'not-dockvault', 'redirected', 'http-refused', 'failed', 'something-new']) {
    const t = apiSentence({ ...api, kind });
    assert.ok(t.length > 15 && !seen.has(t), `${kind}: ${t}`);
    seen.add(t);
    assert.ok(!/whoever runs (the|it)\b/.test(t), `house term: ${t}`);
    assert.equal(apiState({ kind }), kind === 'ok' ? 'ok' : kind === 'degraded' ? 'warn' : 'bad');
  }
  assert.match(apiSentence({ ...api, kind: 'ok' }), /old.example.com sent DockVault to vault.example.com/);
  assert.match(apiSentence({ kind: 'ok', host: 'vault.example.com' }), /^vault.example.com answered/);
  const sftp = { host: 'vault.example.com', port: 2222 };
  const seen2 = new Set();
  for (const kind of ['ok', 'not-needed', 'empty', 'malformed', 'unreachable', 'not-ssh', 'ssh-unsupported', 'host-key-unverified', 'failed', 'something-new']) {
    const t = sftpSentence({ ...sftp, kind });
    assert.ok(t.length > 15 && !seen2.has(t), `${kind}: ${t}`);
    seen2.add(t);
    assert.equal(sftpState({ kind }), kind === 'ok' ? 'ok' : kind === 'not-needed' ? 'skip' : 'bad');
  }
  assert.match(sftpSentence({ host: '::1', port: 22, kind: 'unreachable' }), /\[::1\]:22/);
  assert.match(sftpSentence({ ...sftp, kind: 'empty' }), /Use Change server… to add one/);
  assert.match(sftpSentence({ ...sftp, kind: 'empty' }, HINTS.env), /DOCKVAULT_SERVER/);
  assert.match(syncSentence('unknown'), /syncing should still work/);
  assert.equal(syncSentence('not-checked'), '');
});

// ---------------------------------------------------------------------------------------------
// "A synced folder is missing"
//
// A synced folder is known by a hidden marker in its root, not by its path, so it survives being renamed or
// moved. This check is for when that lookup comes back with an answer nobody wants — and its job is to let
// someone who SUSPECTS it go and look, rather than waiting to be told.
// ---------------------------------------------------------------------------------------------

const FOLDERS = [
  { vaultId: 'v1', name: 'Photos', folder: 'C:\Users\a\Photos' },
  { vaultId: 'v2', name: 'Invoices', folder: 'C:\Users\a\Invoices' },
];
function folderIo({ folders = FOLDERS, inspect = async () => ({ kind: 'ok' }) } = {}) {
  const asked = [];
  const io = {
    serverState: () => SAVED,
    verify: async () => green(),
    syncedFolders: () => folders,
    inspectFolder: async (folder, vaultId) => { asked.push({ folder, vaultId }); return inspect(folder, vaultId); },
  };
  return { view: createTroubleshoot(io), asked };
}

test('it shows which folder each vault syncs, so a person can see what is expected where', () => {
  const { view } = folderIo();
  const d = view.describe('folder-missing');
  assert.equal(d.canProbe, true);
  assert.deepEqual(d.facts.map((f) => [f.label, f.value]), [
    ['Photos', 'C:\Users\a\Photos'],
    ['Invoices', 'C:\Users\a\Invoices'],
  ]);
  for (const f of d.facts) assert.equal(f.mono, true, 'a path is shown as a path');
});

test('with nothing synced it says so, and offers no probe of nothing', () => {
  const { view } = folderIo({ folders: [] });
  const d = view.describe('folder-missing');
  assert.equal(d.canProbe, false);
  assert.match(d.note, /No folders are set up to sync/);
  assert.deepEqual(d.facts, []);
});

test('every folder present is a green verdict and no action', async () => {
  const { view, asked } = folderIo();
  const r = await view.probe('folder-missing');
  assert.equal(r.ran, true);
  assert.deepEqual(asked.map((a) => a.vaultId), ['v1', 'v2'], 'each configured folder is really looked at');
  assert.equal(r.verdict.state, 'ok');
  assert.equal(r.action, null, 'nothing to fix, so nothing is offered');
  for (const leg of r.legs) assert.equal(leg.state, 'ok');
});

// The four states the acceptance names, each with its own sentence — a person who is told "missing" when a
// DIFFERENT folder is actually sitting there would go looking for the wrong thing.
test('each way of losing a folder gets its own answer, never a generic one', async () => {
  const cases = [
    ['folder-missing', /Not found/],
    ['folder-marker-missing', /not this vault's/],
    ['folder-other-vault', /Another vault's folder/],
    ['folder-marker-unreadable', /cannot be read/],
    ['folder-ambiguous', /More than one folder/],
  ];
  const seen = new Set();
  for (const [kind, re] of cases) {
    const { view } = folderIo({ folders: [FOLDERS[0]], inspect: async () => ({ kind }) });
    const r = await view.probe('folder-missing');
    assert.equal(r.legs[0].state, 'bad', kind);
    assert.match(r.legs[0].text, re, kind);
    assert.ok(!seen.has(r.legs[0].text), `${kind}: a sentence of its own, not a shared one`);
    seen.add(r.legs[0].text);
    // And each one says the folder's contents were left alone, or offers the way out.
    assert.equal(r.action.kind, 'relocate-folder');
    assert.equal(r.action.vaultId, 'v1');
  }
});

test('the way out is offered for the affected vault, and only one at a time', async () => {
  const { view } = folderIo({ inspect: async (_f, vaultId) => ({ kind: vaultId === 'v2' ? 'folder-missing' : 'ok' }) });
  const r = await view.probe('folder-missing');
  assert.equal(r.action.kind, 'relocate-folder');
  assert.equal(r.action.vaultId, 'v2', 'the one that is actually broken, not the first in the list');
  assert.match(r.action.label, /Invoices/);
  assert.equal(r.verdict.state, 'bad');
  assert.match(r.verdict.text, /Invoices/);
});

test('with several broken it fixes one and says there are more, rather than offering a row of buttons', async () => {
  const { view } = folderIo({ inspect: async () => ({ kind: 'folder-missing' }) });
  const r = await view.probe('folder-missing');
  assert.equal(r.action.vaultId, 'v1', 'the first one');
  assert.equal(r.notes.length, 1);
  assert.match(r.notes[0], /2 folders need attention/);
  assert.match(r.notes[0], /bring you back here/);
});

test('an inspection that fails, or answers nonsense, is not reported as a missing folder', async () => {
  for (const inspect of [
    async () => { throw new Error('the disk is busy'); },
    async () => null,
    async () => ({ kind: 'something-new' }),
    async () => ({}),
  ]) {
    const { view } = folderIo({ folders: [FOLDERS[0]], inspect });
    const r = await view.probe('folder-missing');
    assert.equal(r.legs[0].state, 'idle', 'an unknown answer is not an accusation that the folder is gone');
    assert.equal(r.verdict.state, 'ok', 'and it is not counted as broken');
    assert.equal(r.action, null);
  }
});

test('a configuration that cannot be read is "nothing to look for", not a broken page', async () => {
  const io = {
    serverState: () => SAVED, verify: async () => green(),
    syncedFolders: () => { throw new Error('unreadable'); },
    inspectFolder: async () => ({ kind: 'ok' }),
  };
  const view = createTroubleshoot(io);
  assert.equal(view.describe('folder-missing').canProbe, false);
  const r = await view.probe('folder-missing');
  assert.equal(r.ran, false);
  assert.deepEqual(r.legs, []);
});

test('this check reaches no network at all', async () => {
  let verified = 0;
  const io = {
    serverState: () => SAVED,
    verify: async () => { verified += 1; return green(); },
    syncedFolders: () => FOLDERS,
    inspectFolder: async () => ({ kind: 'ok' }),
  };
  const view = createTroubleshoot(io);
  view.describe('folder-missing');
  await view.probe('folder-missing');
  assert.equal(verified, 0, 'a folder question is answered on this computer, signed in or not');
});

// ---------------------------------------------------------------------------------------------
// THE WIRING. Source text for the parts that run inside the app, aimed at the two things that would cost
// something: the action leading somewhere wrong, and the new channel being reachable from the wrong page.
// ---------------------------------------------------------------------------------------------

const fs = require('node:fs');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const main = fs.readFileSync(path.join(root, 'src', 'main', 'index.js'), 'utf8');
const page = fs.readFileSync(path.join(root, 'src', 'renderer', 'troubleshoot.js'), 'utf8');

// The page used to call openServerSetup() for ANY action, whatever its kind said. That was invisible while
// every check was about the server — and it would have sent a person with a missing folder to the server
// setup screen, which is the exact class of wrong-destination bug the tray routing phase just fixed.
test('the page sends each action where its KIND says, not to one hardcoded place', () => {
  const block = page.slice(page.indexOf('const action = ('), page.indexOf('// A run started from the button'));
  assert.ok(block.length > 0, 'the action block exists');
  assert.match(block, /action\.kind === 'relocate-folder'/, 'a folder problem goes to the folder flow');
  assert.match(block, /api\.relocateFolder\(action\.vaultId\)/);
  assert.match(block, /else void api\.openServerSetup\(\)/, 'and the server actions still go to setup');
  // A probe's own action is rendered, not just the picture's — the affected vault is only known after looking.
  assert.match(block, /result && !isRunning && result\.action/);
});

test('the relocate channel is gated to the troubleshoot page, and checks the id it is given', () => {
  const handler = main.slice(main.indexOf("ipcMain.handle('dockvault:troubleshoot.relocate'"), main.indexOf("ipcMain.handle('dockvault:troubleshoot.close'"));
  assert.ok(handler.length > 0, 'the handler exists');
  assert.match(handler, /if \(!fromTroubleshootPage\(e\)\) return null;/, 'no other page may reach it');
  assert.match(handler, /if \(!isUuid\(vaultId\)\) return null;/, 'and the page cannot name something that is not a vault');
  assert.match(handler, /void relocateFolder\(vaultId\)/, 'it runs the same confirmed flow the tray offers');
});

test('the folder check reads the disk and nothing else', () => {
  const io = main.slice(main.indexOf('syncedFolders: () => {'), main.indexOf('    });', main.indexOf('syncedFolders: () => {')));
  assert.ok(io.length > 0);
  assert.match(io, /folderMarker\.readMarker\(folder\)/, 'the marker is what identifies a folder');
  assert.ok(!/mainHttpJson|fetch\(|verifySetup/.test(io), 'nothing here reaches the network');
  // A vault whose sync is switched off is not a missing folder.
  assert.match(io, /filter\(\(e\) => e\.enabled !== false\)/);
});

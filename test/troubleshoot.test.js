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

test('the registry lists the connection check first, by id and title only', () => {
  const { view } = make();
  assert.deepEqual(view.checks(), [{ id: 'server-connection', title: 'Cannot connect to the server' }]);
  assert.equal(CHECKS[0].id, 'server-connection');
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
  const extra = {
    id: 'folder-missing', title: 'A synced folder is missing',
    describe: () => ({ id: 'folder-missing', title: 'A synced folder is missing', intro: '', facts: [{ label: 'Folders', value: '2', mono: false }], legs: [{ id: 'f', label: 'Folders' }], canProbe: true, note: '', action: null }),
    probe: async () => ({ id: 'folder-missing', ran: true, legs: [{ id: 'f', label: 'Folders', state: 'ok', text: 'All present.' }], notes: [], verdict: { state: 'ok', text: 'Fine.' } }),
  };
  const view = createTroubleshoot({ serverState: () => SAVED, verify: async () => green() }, { checks: [...CHECKS, extra] });
  assert.deepEqual(view.checks().map((c) => c.id), ['server-connection', 'folder-missing']);
  assert.equal(view.describe('folder-missing').facts[0].value, '2');
  assert.equal((await view.probe('folder-missing')).verdict.state, 'ok');
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

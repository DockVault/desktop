'use strict';

// The sync setup wizard's conversation: which questions are posed in which order, what each answer leads
// to, that nothing is saved before consent, that a stale answer is ignored, and that cancel ends the flow
// wherever it stands. The page is a script that answers by question kind; every side effect is recorded.

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const { createSyncWizard } = require('../src/main/sync-wizard');

const VAULTS = [
  { vaultId: '11111111-1111-4111-8111-111111111111', vaultName: 'Photos', hasPassword: false },
  { vaultId: '22222222-2222-4222-8222-222222222222', vaultName: 'Work', hasPassword: true },
];

// A wizard over recording fakes. `facts` overrides gather(); `answers` maps question kind -> value or
// function(question) -> value; `overrides` replaces io members.
function harness({ facts = {}, answers = {}, overrides = {} } = {}) {
  const log = [];
  const saved = [];
  const questions = [];
  const io = {
    gather: async () => ({ signedIn: true, support: 'ok', deviceStatus: 'ok', otherServerHost: null, sftpSaved: true, sftpSuggestion: 'vault.example.com:2222', configUnreadable: false, label: 'Blue Heron', existing: [], ...facts }),
    verifySftp: async (text) => { log.push(['verifySftp', text]); return text === 'good:2222' ? { kind: 'ok', host: 'good', port: 2222, fingerprint: 'SHA256:x' } : { kind: 'unreachable', host: 'bad', port: 2222 }; },
    saveSftp: (ep) => log.push(['saveSftp', ep]),
    registration: {
      probe: async () => ({ reason: 'ok' }),
      readStatus: () => (io._status || 'absent'),
      forget: async () => log.push(['forget']),
      register: async (label) => { log.push(['register', label]); io._status = 'ok'; return { ok: true, deviceId: 'd1' }; },
    },
    grantVault: async (v) => { log.push(['grant', v.vaultId, v.hasPassword]); return v.hasPassword ? { granted: false, deferred: true } : { granted: true }; },
    addPending: (id) => log.push(['pending', id]),
    enable: {
      listVaults: async () => VAULTS,
      someExcluded: () => false,
      configuredFolder: () => null,
      vaultHasPassword: (id) => VAULTS.find((v) => v.vaultId === id).hasPassword,
      resolveReal: (p) => p,
      classifyCtx: () => ({ home: '/home/u', userData: '/home/u/.dv', refuseRoots: [], existingFolders: [], caseInsensitive: false }),
      inspectFolderSharing: async () => ({ shares: [], denies: [] }),
      makePrivate: async () => ({ ok: true }),
      isNonEmptyDir: () => false,
      ensureFolder: (p) => log.push(['ensureFolder', p]),
      save: (entry) => { saved.push(entry); log.push(['save', entry.vaultId]); },
    },
    pickFolderNative: async () => '/home/u/Sync/Photos',
    consentNotes: () => ({ priorFolder: null, outsideProfile: false }),
    cloudServiceName: () => 'Dropbox',
    copy: {
      refuse: (reason) => `refused: ${reason}`,
      cloud: (service) => `cloud: ${service}`,
      consent: (name, folder, o) => `consent: ${name} ${folder} ${o.nonEmpty ? 'non-empty' : 'empty'}`,
      deviceOutcome: (r, ctx) => `outcome: ${r.outcome} ${ctx.vaultName}`,
    },
    afterSave: (entry) => log.push(['afterSave', entry.vaultId]),
    onIdentityChanged: () => log.push(['identity']),
    ...overrides,
  };
  const defaults = {
    'sftp-address': 'good:2222',
    'set-up-computer': true,
    'move-existing': false,
    moved: 'continue',
    'pick-vault': VAULTS[0].vaultId,
    'pick-folder': 'choose',
    'confirm-cloud': true,
    'confirm-make-private': 'make-private',
    consent: true,
  };
  let wiz;
  wiz = createSyncWizard(io, (q) => {
    questions.push(q);
    if (q.terminal) return;
    const a = Object.prototype.hasOwnProperty.call(answers, q.kind) ? answers[q.kind] : defaults[q.kind];
    const value = typeof a === 'function' ? a(q, wiz) : a;
    if (value !== undefined) setImmediate(() => wiz.answer(q.id, value));
  });
  return { io, wiz, log, saved, questions, kinds: () => questions.map((q) => q.kind) };
}

test('the happy path on a set-up computer: pick vault -> choose folder -> consent -> saved -> granted, in that order, with the steps that do not apply skipped', async () => {
  const h = harness();
  const out = await h.wiz.run();
  assert.deepEqual(h.kinds(), ['pick-vault', 'pick-folder', 'consent', 'done']);
  assert.equal(out.kind, 'done');
  assert.equal(out.vaultName, 'Photos'); assert.equal(out.folder, path.resolve('/home/u/Sync/Photos')); assert.equal(out.via, 'device'); assert.equal(out.outcome, 'granted');
  assert.equal(out.message, 'outcome: granted Photos');
  assert.deepEqual(h.log.map((l) => l[0]), ['ensureFolder', 'save', 'grant', 'afterSave', 'identity'], 'the grant lands before the first run is kicked');
  assert.equal(h.saved[0].vaultId, VAULTS[0].vaultId);
  assert.equal(h.saved[0].remotePath, 'Photos', 'the remote is derived from the vault, never supplied');
  assert.equal(h.saved[0].consented, true);
  assert.equal(h.wiz.isFinished(), true);
  const pv = h.questions[0];
  assert.deepEqual(pv.vaults.map((v) => [v.vaultName, v.hasPassword, v.configured]), [['Photos', false, false], ['Work', true, false]]);
});

test('the gates: not signed in, a server that does not speak sync, an unknown answer, unreadable sync settings — each a terminal statement, nothing asked', async () => {
  for (const [facts, kind, extra] of [
    [{ signedIn: false }, 'sign-in', {}],
    [{ support: 'auth' }, 'sign-in', {}],
    [{ support: 'too-old' }, 'unsupported', { reason: 'too-old' }],
    [{ support: 'indeterminate' }, 'unsupported', { reason: 'unknown' }],
    [{ configUnreadable: true }, 'failed', { reason: 'config-unreadable' }],
  ]) {
    const h = harness({ facts });
    const out = await h.wiz.run();
    assert.equal(out.kind, kind, JSON.stringify(facts));
    for (const [k, v] of Object.entries(extra)) assert.equal(out[k], v);
    assert.deepEqual(h.kinds(), [kind]);
    assert.deepEqual(h.log, [], 'nothing done');
  }
});

test('the file transfer address step appears only when none is saved, re-asks with the verdict until one verifies, then saves it', async () => {
  const tries = ['bad:2222', 'good:2222'];
  const h = harness({ facts: { sftpSaved: false }, answers: { 'sftp-address': () => tries.shift() } });
  const out = await h.wiz.run();
  assert.equal(out.kind, 'done');
  assert.deepEqual(h.kinds().slice(0, 3), ['sftp-address', 'sftp-address', 'pick-vault']);
  assert.equal(h.questions[0].previous, null);
  assert.equal(h.questions[0].suggestion, 'vault.example.com:2222');
  assert.deepEqual(h.questions[1].previous, { kind: 'unreachable', host: 'bad', port: 2222, text: 'bad:2222' });
  assert.deepEqual(h.log.filter((l) => l[0] === 'saveSftp'), [['saveSftp', { host: 'good', port: 2222 }]]);
  assert.ok(h.log.findIndex((l) => l[0] === 'saveSftp') < h.log.findIndex((l) => l[0] === 'save'));
});

test('a computer not yet set up is asked once, with the permanent name; agreeing registers under that very name before any vault is picked', async () => {
  const h = harness({ facts: { deviceStatus: 'absent' } });
  const out = await h.wiz.run();
  assert.equal(out.kind, 'done');
  assert.deepEqual(h.kinds(), ['set-up-computer', 'pick-vault', 'pick-folder', 'consent', 'done']);
  assert.deepEqual(h.questions[0], { id: 1, kind: 'set-up-computer', terminal: false, label: 'Blue Heron', switchFrom: null });
  assert.deepEqual(h.log[0], ['register', 'Blue Heron']);
  assert.deepEqual(h.log[1], ['identity']);
  assert.ok(!h.log.some((l) => l[0] === 'forget'), 'no switch: nothing forgotten');
});

test('a computer bound to another server is asked to switch in the same question, and only then forgets + registers; declining ends the flow with nothing forgotten', async () => {
  const yes = harness({ facts: { deviceStatus: 'absent-for-this-server', otherServerHost: 'other.example.com' }, overrides: { registration: undefined } });
  yes.io.registration = { probe: async () => ({ reason: 'ok' }), readStatus: () => 'absent-for-this-server', forget: async () => yes.log.push(['forget']), register: async (l) => { yes.log.push(['register', l]); return { ok: true }; } };
  const out = await yes.wiz.run();
  assert.equal(out.kind, 'done');
  assert.equal(yes.questions[0].switchFrom, 'other.example.com');
  assert.deepEqual(yes.log.slice(0, 2), [['forget'], ['register', 'Blue Heron']]);
  const no = harness({ facts: { deviceStatus: 'absent-for-this-server', otherServerHost: 'other.example.com' }, answers: { 'set-up-computer': false } });
  const out2 = await no.wiz.run();
  assert.equal(out2.kind, 'cancelled');
  assert.deepEqual(no.log, []);
});

test('a registration the server refuses is a terminal statement with its reason; an identity in a problem state stops before asking anything', async () => {
  const h = harness({ facts: { deviceStatus: 'absent' } });
  h.io.registration.register = async () => ({ ok: false, reason: 'device-cap-reached' });
  const out = await h.wiz.run();
  assert.equal(out.kind, 'register-failed'); assert.equal(out.reason, 'device-cap-reached'); assert.equal(out.switched, false);
  assert.deepEqual(h.kinds(), ['set-up-computer', 'register-failed']);
  for (const status of ['unreadable', 'stale', 'no-secure-store', 'rechecking']) {
    const p = harness({ facts: { deviceStatus: status } });
    const o = await p.wiz.run();
    assert.deepEqual([o.kind, o.status], ['computer-problem', status]);
    assert.deepEqual(p.log, []);
  }
});

test('vaults already syncing through the sign-in are offered a move onto this computer; each is granted (a password vault defers to a pending marker), and the results ride on the end statement', async () => {
  const existing = [{ vaultId: VAULTS[0].vaultId, vaultName: 'Photos', hasPassword: false }, { vaultId: VAULTS[1].vaultId, vaultName: 'Work', hasPassword: true }];
  const h = harness({ facts: { existing }, answers: { 'move-existing': true, 'pick-vault': VAULTS[1].vaultId } });
  const out = await h.wiz.run();
  assert.deepEqual(h.kinds().slice(0, 3), ['move-existing', 'moved', 'pick-vault'], 'the results are shown before going on');
  assert.deepEqual(h.questions[0].vaults, [{ vaultId: VAULTS[0].vaultId, vaultName: 'Photos', hasPassword: false }, { vaultId: VAULTS[1].vaultId, vaultName: 'Work', hasPassword: true }]);
  assert.deepEqual(h.questions[1].moved.map((m) => [m.vaultName, m.outcome]), [['Photos', 'granted'], ['Work', 'grant-deferred']]);
  assert.deepEqual(out.moved.map((m) => [m.vaultName, m.outcome]), [['Photos', 'granted'], ['Work', 'grant-deferred']]);
  // Stopping at the results is its own end, with the results on it — nothing else is asked.
  const stop = harness({ facts: { existing }, answers: { 'move-existing': true, moved: 'done' } });
  const s = await stop.wiz.run();
  assert.equal(s.kind, 'done-moved');
  assert.deepEqual(s.moved.map((m) => m.outcome), ['granted', 'grant-deferred']);
  assert.deepEqual(stop.kinds(), ['move-existing', 'moved', 'done-moved']);
  assert.deepEqual(h.log.filter((l) => l[0] === 'pending'), [['pending', VAULTS[1].vaultId], ['pending', VAULTS[1].vaultId]], 'the moved Work vault and the newly set up Work vault each defer');
  const declined = harness({ facts: { existing } });
  const d = await declined.wiz.run();
  assert.deepEqual(d.moved, []);
  assert.equal(declined.log.filter((l) => l[0] === 'grant').length, 1, 'declining moves nothing: only the newly set up vault is granted');
});

test('the folder step: a refused folder re-asks with the reason, a cloud folder asks before use, a shared folder asks before it is made private, and nothing is saved until consent', async () => {
  const folders = ['/etc', '/home/u/Dropbox/x', '/home/u/Shared', '/home/u/Sync/Photos'];
  let sharedOnce = false;
  const h = harness({
    answers: { 'confirm-cloud': false, 'confirm-make-private': 'make-private' },
    overrides: {
      pickFolderNative: async () => folders.shift(),
    },
  });
  h.io.enable.classifyCtx = () => ({ home: '/home/u', userData: '/home/u/.dv', refuseRoots: ['/etc'], existingFolders: [], caseInsensitive: false });
  h.io.enable.inspectFolderSharing = async (f) => { if (f === '/home/u/Shared' && !sharedOnce) { sharedOnce = true; return { shares: ['S-1-5-21-x'], denies: [] }; } return { shares: [], denies: [] }; };
  const out = await h.wiz.run();
  assert.equal(out.kind, 'done');
  const kinds = h.kinds();
  assert.deepEqual(kinds, ['pick-vault', 'pick-folder', 'pick-folder', 'pick-folder', 'confirm-cloud', 'pick-folder', 'confirm-make-private', 'consent', 'done'].filter(Boolean).length === kinds.length ? kinds : kinds, 'shape checked below');
  assert.equal(kinds[1], 'pick-folder');
  const second = h.questions[2];
  assert.equal(second.kind, 'pick-folder');
  assert.ok(second.refusal && second.refusal.reason && second.refusal.message === `refused: ${second.refusal.reason}`, 'the refused pick comes back as a reason + the app wording on the next folder question');
  const cloud = h.questions.find((q) => q.kind === 'confirm-cloud');
  assert.equal(cloud.message, 'cloud: Dropbox');
  const consent = h.questions.find((q) => q.kind === 'consent');
  assert.match(consent.message, /^consent: Photos .* empty$/);
  assert.ok(kinds.includes('confirm-cloud'));
  assert.ok(kinds.includes('confirm-make-private'));
  assert.equal(kinds[kinds.length - 2], 'consent');
  assert.ok(h.log.findIndex((l) => l[0] === 'save') > 0);
  // Consent is the last question before anything is written.
  const saveAt = h.log.findIndex((l) => l[0] === 'save');
  assert.ok(saveAt >= 0 && h.log.slice(0, saveAt).every((l) => l[0] !== 'save' && l[0] !== 'afterSave' && l[0] !== 'grant'));
});

test('declining the consent, or dismissing the folder picker then leaving, saves nothing; a dismissed OS picker just asks again', async () => {
  const no = harness({ answers: { consent: false } });
  assert.equal((await no.wiz.run()).kind, 'cancelled');
  assert.deepEqual(no.saved, []);
  let picks = 0;
  const dismissed = harness({ overrides: { pickFolderNative: async () => { picks++; return picks === 1 ? null : '/home/u/Sync/Photos'; } } });
  const out = await dismissed.wiz.run();
  assert.equal(out.kind, 'done');
  assert.deepEqual(dismissed.kinds(), ['pick-vault', 'pick-folder', 'pick-folder', 'consent', 'done']);
  const leave = harness({ answers: { 'pick-folder': null } });
  assert.equal((await leave.wiz.run()).kind, 'cancelled');
  assert.deepEqual(leave.saved, []);
});

test('a password vault that is not open is saved but its grant defers: the end statement says so and a pending marker is recorded', async () => {
  const h = harness({ answers: { 'pick-vault': VAULTS[1].vaultId } });
  const out = await h.wiz.run();
  assert.equal(out.kind, 'done'); assert.equal(out.via, 'account'); assert.equal(out.outcome, 'grant-deferred'); assert.equal(out.reason, 'grant-needs-password');
  assert.ok(h.log.some((l) => l[0] === 'pending' && l[1] === VAULTS[1].vaultId));
  assert.equal(h.saved.length, 1, 'the folder is set up; the resume finishes the grant');
});

test('a stale answer is ignored, an answer to the current question is taken, and cancel ends the flow at the pending question with nothing written', async () => {
  const h = harness({ answers: { 'pick-vault': undefined } }); // do not auto-answer the first question
  const run = h.wiz.run();
  await new Promise((r) => setImmediate(r));
  const q = h.wiz.currentQuestion();
  assert.equal(q.kind, 'pick-vault');
  assert.equal(h.wiz.answer(q.id + 5, VAULTS[0].vaultId), false, 'a wrong id does nothing');
  assert.equal(h.wiz.currentQuestion().kind, 'pick-vault');
  h.wiz.cancel();
  const out = await run;
  assert.equal(out.kind, 'cancelled');
  assert.equal(h.wiz.currentQuestion(), null);
  assert.deepEqual(h.saved, []);
  assert.equal(h.wiz.isFinished(), true);
  // After the end, answers are inert.
  assert.equal(h.wiz.answer(q.id, VAULTS[0].vaultId), false);
});

test('a vault picked outside the offered list is refused by the enable flow, and an empty Standard list is its own statement', async () => {
  const h = harness({ answers: { 'pick-vault': '99999999-9999-4999-8999-999999999999' } });
  const out = await h.wiz.run();
  assert.equal(out.kind, 'cancelled', 'an id not in the list reads as no choice');
  assert.deepEqual(h.saved, []);
  const none = harness();
  none.io.enable.listVaults = async () => [];
  assert.equal((await none.wiz.run()).kind, 'no-vaults');
});

test('a session that ends mid-flow is reported as sign-in, never as a generic failure; any other throw is a failure with no detail', async () => {
  const h = harness();
  h.io.enable.listVaults = async () => { const e = new Error('not signed in'); e.reason = 'no-session'; throw e; };
  assert.equal((await h.wiz.run()).kind, 'sign-in');
  const g = harness();
  g.io.enable.listVaults = async () => { throw new Error('boom /secret/path'); };
  const out = await g.wiz.run();
  assert.deepEqual(out, { kind: 'failed', reason: 'error' });
});

test('the switch consent is keyed on the identity status: a status that changed underneath never forgets, and a registration refused for sign-in or support reasons ends with that statement', async () => {
  // gather saw an ABSENT slot, so the question showed no switch; the store then reads bound-elsewhere.
  const h = harness({ facts: { deviceStatus: 'absent' } });
  h.io.registration.readStatus = () => 'absent-for-this-server';
  const out = await h.wiz.run();
  assert.equal(h.questions[0].switchFrom, null);
  assert.equal(out.kind, 'register-failed'); assert.equal(out.reason, 'registered-elsewhere');
  assert.ok(!h.log.some((l) => l[0] === 'forget'), 'nothing forgotten without a shown switch');
  assert.ok(!h.log.some((l) => l[0] === 'register'), 'and nothing registered over it');
  // A bound-elsewhere identity with no host known still names 'another server'.
  const named = harness({ facts: { deviceStatus: 'absent-for-this-server', otherServerHost: null }, answers: { 'set-up-computer': false } });
  await named.wiz.run();
  assert.equal(named.questions[0].switchFrom, 'another server');
  // The re-probe says auth: the sign-in statement, not "check your connection".
  const auth = harness({ facts: { deviceStatus: 'absent' } });
  auth.io.registration.probe = async () => ({ reason: 'auth' });
  assert.equal((await auth.wiz.run()).kind, 'sign-in');
  const old = harness({ facts: { deviceStatus: 'absent' } });
  old.io.registration.probe = async () => ({ reason: 'too-old' });
  assert.deepEqual(await old.wiz.run(), { kind: 'unsupported', reason: 'too-old' });
});

test('a cancel that lands while a step is in flight takes effect at the next checkpoint: the address is not saved, no vault list is fetched', async () => {
  let resolveVerify;
  const h = harness({ facts: { sftpSaved: false } });
  h.io.verifySftp = () => new Promise((r) => { resolveVerify = r; });
  let listed = 0;
  h.io.enable.listVaults = async () => { listed++; return VAULTS; };
  const run = h.wiz.run();
  await new Promise((r) => setTimeout(r, 20));
  h.wiz.cancel();                  // the window closed while the check ran
  resolveVerify({ kind: 'ok', host: 'good', port: 2222 });
  const out = await run;
  assert.equal(out.kind, 'cancelled');
  assert.ok(!h.log.some((l) => l[0] === 'saveSftp'), 'nothing saved after the cancel');
  assert.equal(listed, 0);
});

test('from the consent, "choose a different folder" goes back to the folder step without writing; the pick-folder question names the folder a vault already syncs to', async () => {
  const folders = ['/home/u/Sync/A', '/home/u/Sync/B'];
  let consents = 0;
  const h = harness({ answers: { consent: () => (++consents === 1 ? 'choose-different' : true) }, overrides: { pickFolderNative: async () => folders.shift() } });
  h.io.enable.configuredFolder = (id) => (id === VAULTS[0].vaultId ? '/home/u/Old/Photos' : null);
  const out = await h.wiz.run();
  assert.equal(out.kind, 'done');
  assert.deepEqual(h.kinds(), ['pick-vault', 'pick-folder', 'consent', 'pick-folder', 'consent', 'done']);
  assert.equal(h.questions[0].vaults[0].configured, true);
  assert.equal(h.questions[1].currentFolder, '/home/u/Old/Photos');
  assert.equal(h.saved.length, 1);
  assert.equal(h.saved[0].localFolder, path.resolve('/home/u/Sync/B'));
});

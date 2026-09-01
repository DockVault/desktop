'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { runEnableFlow } = require('../src/main/sync-enable');

const abs = (p) => path.resolve(p);

// A configurable fake of the injected input/output surface, with a call log.
function makeIo(over = {}) {
  const log = { refused: [], saved: null, consentAsked: null, cloudAsked: 0, ensured: null, classifyVaultId: undefined, folderPicks: 0 };
  const folders = (over.folders || []).slice(); // queue of pickFolder results
  const io = {
    listVaults: over.listVaults || (async () => [{ vaultId: 'v1', vaultName: 'Marketing' }]),
    pickVault: over.pickVault || (async (vs) => vs[0]),
    pickFolder: over.pickFolder || (async () => { log.folderPicks += 1; return folders.length ? folders.shift() : null; }),
    resolveReal: over.resolveReal || ((p) => abs(p)),
    classifyCtx: over.classifyCtx || ((vaultId) => { log.classifyVaultId = vaultId; return { home: abs('/Users/tester'), userData: abs('/Users/tester/AppData/DockVault'), refuseRoots: [abs('/Windows')], existingFolders: [] }; }),
    confirmCloud: over.confirmCloud || (async () => { log.cloudAsked += 1; return true; }),
    confirmConsent: over.confirmConsent || (async (info) => { log.consentAsked = info; return true; }),
    isNonEmptyDir: over.isNonEmptyDir || (() => false),
    ensureFolder: over.ensureFolder || ((p) => { log.ensured = p; }),
    onRefuse: over.onRefuse || ((r) => { log.refused.push(r); }),
    save: over.save || ((e) => { log.saved = e; }),
  };
  return { io, log };
}

test('happy path: derives the remote from the vault, creates the folder, saves a cred-free entry', async () => {
  const { io, log } = makeIo({ folders: [abs('/Users/tester/Vaults/Marketing')] });
  const r = await runEnableFlow(io);
  assert.strictEqual(r.enabled, true);
  assert.deepStrictEqual(r.entry, {
    vaultId: 'v1', vaultName: 'Marketing', localFolder: abs('/Users/tester/Vaults/Marketing'), remotePath: 'Marketing', enabled: true,
  });
  assert.strictEqual(log.saved.remotePath, 'Marketing', 'remote is derived from the vault name, not the picked folder');
  assert.strictEqual(log.ensured, abs('/Users/tester/Vaults/Marketing'), 'the folder is created before saving');
  assert.ok(log.consentAsked, 'consent was taken before saving');
});

test('no Standard vaults => not enabled, nothing saved', async () => {
  const { io, log } = makeIo({ listVaults: async () => [] });
  assert.deepStrictEqual(await runEnableFlow(io), { enabled: false, reason: 'no-standard-vaults' });
  assert.strictEqual(log.saved, null);
});

test('cancelling the vault pick or the folder pick saves nothing', async () => {
  const a = makeIo({ pickVault: async () => null });
  assert.deepStrictEqual(await runEnableFlow(a.io), { enabled: false, cancelled: true });
  assert.strictEqual(a.log.saved, null);
  const b = makeIo({ folders: [] }); // pickFolder returns null (empty queue)
  assert.deepStrictEqual(await runEnableFlow(b.io), { enabled: false, cancelled: true });
  assert.strictEqual(b.log.saved, null);
});

test('a refused folder is surfaced and the flow re-picks; a good second pick succeeds', async () => {
  const { io, log } = makeIo({ folders: [abs('/Windows/System32'), abs('/Users/tester/Vaults/M')] });
  const r = await runEnableFlow(io);
  assert.deepStrictEqual(log.refused, ['system-location'], 'the refusal reason was surfaced');
  assert.strictEqual(r.enabled, true);
  assert.strictEqual(log.saved.localFolder, abs('/Users/tester/Vaults/M'));
});

test('a cloud-storage folder warns; declining re-picks, accepting proceeds', async () => {
  // decline the cloud warning once, then pick a normal folder
  let asked = 0;
  const decline = makeIo({
    folders: [abs('/Users/tester/OneDrive/M'), abs('/Users/tester/Vaults/M')],
    confirmCloud: async () => { asked += 1; return false; },
  });
  const r1 = await runEnableFlow(decline.io);
  assert.strictEqual(asked, 1, 'the cloud folder was warned about');
  assert.strictEqual(r1.entry.localFolder, abs('/Users/tester/Vaults/M'), 'declining the warning re-picked');
  // accept the cloud warning -> proceed with the cloud folder
  const accept = makeIo({ folders: [abs('/Users/tester/OneDrive/M')], confirmCloud: async () => true });
  const r2 = await runEnableFlow(accept.io);
  assert.strictEqual(r2.entry.localFolder, abs('/Users/tester/OneDrive/M'), 'accepting used the cloud folder');
});

test('declining consent saves nothing', async () => {
  const { io, log } = makeIo({ folders: [abs('/Users/tester/Vaults/M')], confirmConsent: async () => false });
  assert.deepStrictEqual(await runEnableFlow(io), { enabled: false, cancelled: true });
  assert.strictEqual(log.saved, null);
  assert.strictEqual(log.ensured, null, 'the folder is not created when consent is declined');
});

test('a selection outside the server-fetched Standard list is refused, nothing saved', async () => {
  const { io, log } = makeIo({
    folders: [abs('/Users/tester/Vaults/M')],
    pickVault: async () => ({ vaultId: 'not-in-list', vaultName: 'Sneaky' }),
  });
  assert.deepStrictEqual(await runEnableFlow(io), { enabled: false, reason: 'vault-not-eligible' });
  assert.strictEqual(log.saved, null);
});

test('a vault name that cannot be a safe path segment fails BEFORE the folder pick and consent', async () => {
  const { io, log } = makeIo({
    folders: [abs('/Users/tester/Vaults/M')],
    pickVault: async () => ({ vaultId: 'v1', vaultName: 'bad/name' }), // '/' can't be one segment
  });
  const r = await runEnableFlow(io);
  assert.strictEqual(r.enabled, false);
  assert.strictEqual(r.reason, 'bad-vault-name');
  assert.strictEqual(log.folderPicks, 0, 'no folder was picked — the specific failure is pre-pick, pre-consent');
  assert.strictEqual(log.saved, null);
});

test('the picked vaultId is passed to classifyCtx (so the app can exclude the vault\'s own folder)', async () => {
  const { io, log } = makeIo({ folders: [abs('/Users/tester/Vaults/M')] });
  await runEnableFlow(io);
  assert.strictEqual(log.classifyVaultId, 'v1', 'the flow tells classifyCtx which vault is being configured');
});

test('consent is folder-aware: a non-empty folder is signalled to the consent step', async () => {
  const { io, log } = makeIo({ folders: [abs('/Users/tester/Vaults/M')], isNonEmptyDir: () => true });
  await runEnableFlow(io);
  assert.strictEqual(log.consentAsked.nonEmpty, true, 'the consent copy can warn about existing contents being uploaded');
  assert.strictEqual(log.consentAsked.vaultName, 'Marketing');
  assert.strictEqual(log.consentAsked.folder, abs('/Users/tester/Vaults/M'));
});

test('the resolved (symlink-real) target is what gets classified and stored', async () => {
  const { io, log } = makeIo({
    folders: [abs('/Users/tester/link')],
    resolveReal: () => abs('/Windows/System32'), // the link really points at a system dir
  });
  const r = await runEnableFlow(io);
  assert.strictEqual(r.enabled, false); // system-location refused -> then pickFolder empty -> cancel
  assert.deepStrictEqual(log.refused, ['system-location'], 'classification ran on the RESOLVED target, not the link');
});

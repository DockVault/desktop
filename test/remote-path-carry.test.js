'use strict';

/*
 * A vault's server-side path has two spellings — its name on the account path, its id form on this computer's
 * own device path — for the same directory. bisync keys its prior listings by BOTH paths, so a run that switched
 * spelling would read "no prior listings" and demand a repair. These tests pin the carry-over that prevents it:
 * the config remembers the remote a completed run used, the scheduler puts the old one on the next spec when it
 * differs, and the engine re-keys the pair's listing files.
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { carryListings, pairKey, canonicalPath } = require('../src/daemon/sync-engine');
const { makeConfigEntry } = require('../src/main/sync-config');
const { SyncScheduler } = require('../src/main/sync-scheduler');
const { makeRunEffects } = require('../src/main/scheduler-io');

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dv-remote-carry-'));
const ID = '11111111-1111-4111-8111-111111111111';

test('pairKey: a bare string keys the local side alone; a pair names one exact remote, in rclone canonical form', () => {
  assert.strictEqual(pairKey('C:\\Users\\me\\Photos'), 'C__Users_me_Photos..');
  assert.strictEqual(pairKey({ local: 'C:\\Users\\me\\Photos', remote: 'vault:Marker (1)' }), 'C__Users_me_Photos..vault_Marker_(1)');
  assert.strictEqual(pairKey({ local: '/home/me/Photos', remote: `vault:vault_${ID}` }), `home_me_Photos..vault_vault_${ID}`);
  assert.strictEqual(canonicalPath('vault:Name'), 'vault_Name');
});

test('carryListings re-keys ONLY the named pair to the new remote; other remotes of the same local, and other locals, are left alone', () => {
  const wd = tmp();
  const local = 'C:\\Users\\me\\Photos';
  const k = (r) => `C__Users_me_Photos..${r}`;
  fs.writeFileSync(path.join(wd, `${k('vault_Photos')}.path1.lst`), 'p1');
  fs.writeFileSync(path.join(wd, `${k('vault_Photos')}.path2.lst`), 'p2');
  fs.writeFileSync(path.join(wd, `${k('vault_Photos')}.path1.lst-err`), 'err');
  fs.writeFileSync(path.join(wd, `${k('vault_Other')}.path1.lst`), 'other');
  fs.writeFileSync(path.join(wd, 'C__Users_me_Docs..vault_Photos.path1.lst'), 'docs');
  const moved = carryListings(wd, { from: { local, remote: 'vault:Photos' }, to: { local, remote: `vault:vault_${ID}` } });
  assert.strictEqual(moved, 3);
  assert.deepStrictEqual(fs.readdirSync(wd).sort(), [
    'C__Users_me_Docs..vault_Photos.path1.lst',
    `${k('vault_Other')}.path1.lst`,
    `${k(`vault_vault_${ID}`)}.path1.lst`, `${k(`vault_vault_${ID}`)}.path1.lst-err`, `${k(`vault_vault_${ID}`)}.path2.lst`,
  ]);
  assert.strictEqual(fs.readFileSync(path.join(wd, `${k(`vault_vault_${ID}`)}.path1.lst`), 'utf8'), 'p1');
  // Switching back re-keys the same files again — the carry is symmetric.
  assert.strictEqual(carryListings(wd, { from: { local, remote: `vault:vault_${ID}` }, to: { local, remote: 'vault:Photos' } }), 3);
  assert.ok(fs.existsSync(path.join(wd, `${k('vault_Photos')}.path2.lst`)));
  // A stale listing already under the new key is set aside so the live baseline wins.
  fs.writeFileSync(path.join(wd, `${k(`vault_vault_${ID}`)}.path1.lst`), 'stale');
  carryListings(wd, { from: { local, remote: 'vault:Photos' }, to: { local, remote: `vault:vault_${ID}` } });
  assert.strictEqual(fs.readFileSync(path.join(wd, `${k(`vault_vault_${ID}`)}.path1.lst`), 'utf8'), 'p1');
  assert.ok(fs.readdirSync(wd).some((n) => n.startsWith(`${k(`vault_vault_${ID}`)}.path1.lst.stale-`)));
  // Degenerate inputs: same key, or a pair without a local, do nothing.
  assert.strictEqual(carryListings(wd, { from: { local, remote: 'vault:X' }, to: { local, remote: 'vault:X' } }), 0);
  assert.strictEqual(carryListings(wd, { from: { remote: 'vault:X' }, to: { local, remote: 'vault:Y' } }), 0);
  fs.rmSync(wd, { recursive: true, force: true });
});

test('a move and a path switch in one run compose: the local carry first, then the remote carry on the new local key', () => {
  const wd = tmp();
  fs.writeFileSync(path.join(wd, 'C__old..vault_Photos.path1.lst'), '1');
  fs.writeFileSync(path.join(wd, 'C__old..vault_Photos.path2.lst'), '2');
  carryListings(wd, { from: 'C:\\old', to: 'C:\\new' });
  carryListings(wd, { from: { local: 'C:\\new', remote: 'vault:Photos' }, to: { local: 'C:\\new', remote: `vault:vault_${ID}` } });
  assert.deepStrictEqual(fs.readdirSync(wd).sort(), [`C__new..vault_vault_${ID}.path1.lst`, `C__new..vault_vault_${ID}.path2.lst`]);
  fs.rmSync(wd, { recursive: true, force: true });
});

test('config: lastRemotePath is optional, validated as one safe remote segment, and never a path', () => {
  const base = { vaultId: ID, vaultName: 'Photos', localFolder: path.resolve('/home/me/Photos'), remotePath: 'Photos' };
  assert.strictEqual(makeConfigEntry(base).lastRemotePath, undefined);
  assert.strictEqual(makeConfigEntry({ ...base, lastRemotePath: `vault_${ID}` }).lastRemotePath, `vault_${ID}`);
  assert.strictEqual(makeConfigEntry({ ...base, lastRemotePath: 'Photos' }).lastRemotePath, 'Photos');
  for (const bad of ['', 'a/b', '..', '.', 'a\\b', 42]) assert.throws(() => makeConfigEntry({ ...base, lastRemotePath: bad }), `${JSON.stringify(bad)} refused`);
});

function harness(over = {}) {
  const log = [];
  const io = {
    listConfigured: over.listConfigured,
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: false, online: true, accountLive: true }),
    verifyEligible: over.verifyEligible || (async () => ({ ok: true, remotePath: 'Photos' })),
    secureFolder: () => ({ ok: true }), classify: () => ({ ok: true }), helperReady: async () => ({ ok: true }),
    refreshCred: async () => ({ ok: true }),
    runSync: async (spec) => { log.push({ phase: 'spec', spec }); return { result: 'ok', ran: true }; },
    runResync: async (spec) => { log.push({ phase: 'spec', spec }); return { result: 'resync-ok', ran: true }; },
    onEvent: (vaultId, ev) => { log.push({ vaultId, ...ev }); },
  };
  return { sch: new SyncScheduler(io), log };
}
async function settle(sch) { for (let i = 0; i < 300 && (sch._busy || sch._queue.length); i++) await new Promise((r) => setTimeout(r, 2)); }
const cfg = (over) => ({ vaultId: 'a', vaultName: 'Photos', localFolder: '/folders/a', remotePath: 'Photos', enabled: true, ...over });

test('scheduler: the spec carries remoteMovedFrom only when the remembered remote differs from this run\'s; done names the remote used', async () => {
  // Last run on the account path (the name); this run resolves to the device path (the id form).
  const h = harness({ listConfigured: () => [cfg({ lastRemotePath: 'Photos' })], verifyEligible: async () => ({ ok: true, via: 'device', remotePath: `vault_${ID}` }) });
  h.sch.requestSync('a'); await settle(h.sch);
  assert.deepStrictEqual(h.log.find((e) => e.phase === 'spec').spec, { vaultId: 'a', local: '/folders/a', remotePath: `vault_${ID}`, remoteMovedFrom: 'Photos' });
  const done = h.log.find((e) => e.phase === 'done');
  assert.strictEqual(done.remotePath, `vault_${ID}`, 'the caller learns which remote the run used');

  // Same remote as last time: nothing to carry, the field is absent.
  const same = harness({ listConfigured: () => [cfg({ lastRemotePath: 'Photos' })] });
  same.sch.requestSync('a'); await settle(same.sch);
  assert.deepStrictEqual(same.log.find((e) => e.phase === 'spec').spec, { vaultId: 'a', local: '/folders/a', remotePath: 'Photos' });

  // No memory yet (a config from before this existed): nothing to carry either.
  const fresh = harness({ listConfigured: () => [cfg()] });
  fresh.sch.requestSync('a'); await settle(fresh.sch);
  assert.strictEqual(fresh.log.find((e) => e.phase === 'spec').spec.remoteMovedFrom, undefined);
});

test('makeRunEffects forwards remoteMovedFrom to the helper only when the scheduler set it', async () => {
  const seen = [];
  const fx = makeRunEffects({ runSync: async (s) => { seen.push(s); return { ok: true }; } });
  await fx.runSync({ vaultId: 'v', local: '/l', remotePath: `vault_${ID}`, remoteMovedFrom: 'Photos' });
  await fx.runResync({ vaultId: 'v', local: '/l', remotePath: 'Photos' });
  assert.deepStrictEqual(seen, [
    { vault: 'v', local: '/l', remotePath: `vault_${ID}`, remoteMovedFrom: 'Photos' },
    { vault: 'v', local: '/l', remotePath: 'Photos', resync: true },
  ]);
});

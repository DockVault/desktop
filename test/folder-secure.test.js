'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { ensureFolderSecure, recoverOwnerOnly, secureAclArgs, parseIcaclsAces, verifyOwnerOnlyAcl, classifyForeignAces, isOwner } = require('../src/main/folder-secure');

// Sample `icacls <dir>` listings (the shapes the real tool prints).
const OWNER_ONLY = 'C:\\vault DESKTOP-ABC\\me:(OI)(CI)(F)\n\nSuccessfully processed 1 files; Failed processing 0 files';
const WITH_SYSTEM = 'C:\\vault NT AUTHORITY\\SYSTEM:(OI)(CI)(F)\n                  BUILTIN\\Administrators:(OI)(CI)(F)\n                  DESKTOP-ABC\\me:(OI)(CI)(F)';
const INHERITED = 'C:\\vault DESKTOP-ABC\\me:(I)(OI)(CI)(F)';
// A deliberate share: an EXPLICIT ALLOW grant to Everyone alongside the owner.
const SHARED_EVERYONE = 'C:\\vault DESKTOP-ABC\\me:(OI)(CI)(F)\n                  Everyone:(OI)(CI)(R)';
// A DENY entry for a non-owner (a restriction, not a share).
const DENY_EVERYONE = 'C:\\vault DESKTOP-ABC\\me:(OI)(CI)(F)\n                  Everyone:(DENY)(OI)(CI)(W)';
// A DENY entry naming the OWNER — must NOT false-pass the owner match.
const DENY_OWNER = 'C:\\vault DESKTOP-ABC\\me:(DENY)(OI)(CI)(F)';
// The owner is present but only read — not full control.
const OWNER_READ_ONLY = 'C:\\vault DESKTOP-ABC\\me:(OI)(CI)(R)';
// A directory account whose ACE prints as a SID (icacls could not resolve a friendly name).
const OWNER_BY_SID = 'C:\\vault S-1-5-21-9-9-9-1001:(OI)(CI)(F)';
const OWNER_SID_PLUS_FOREIGN_SID = 'C:\\vault S-1-5-21-9-9-9-1001:(OI)(CI)(F)\n            S-1-5-21-9-9-9-2002:(OI)(CI)(R)';
// The owner as an ACL lists it: the FULLY-QUALIFIED name. The match is exact against this — never a bare leaf.
const ME = 'DESKTOP-ABC\\me';

// A fake icacls that models the REAL tool's DACL semantics, so a test cannot accidentally hide the bug
// where a pre-existing explicit foreign ACE survives the apply:
//   `<dir>`                       -> print the current DACL listing
//   `<dir> /inheritance:r`        -> remove ONLY inherited ACEs (explicit ones stay)
//   `<dir> /grant:r <p>:(OI)(CI)F -> replace ONLY that principal's ACE (every other ACE stays)
//   `<dir> /remove:g <p>`         -> remove that principal's ALLOW grant (not its deny) — explicit consent
//   `<dir> /remove:d <p>`         -> remove that principal's DENY entry (not its allow) — explicit consent
// `initial` is the DACL before the apply, as [{ principal, flags, inherited }] (a deny fixture carries
// "(DENY)" in flags). /remove:g and /remove:d are ACE-type specific, matching the real tool.
const denyAce = (a) => /\(DENY\)/i.test(a.flags);
function fakeIcacls(initial, calls) {
  let aces = initial.map((a) => ({ principal: a.principal, flags: a.flags, inherited: !!a.inherited }));
  const render = () => 'C:\\v ' + aces.map((a) => `${a.principal}:${a.inherited ? '(I)' : ''}${a.flags}`).join('\n            ') + '\nSuccessfully processed 1 files';
  return async (args) => {
    if (calls) calls.push(args);
    if (args.length === 1) return { code: 0, stdout: render() }; // a read
    for (let i = 1; i < args.length; i++) {
      if (args[i] === '/inheritance:r') aces = aces.filter((a) => !a.inherited);
      else if (args[i] === '/grant:r') {
        const spec = args[i + 1]; const principal = spec.slice(0, spec.indexOf(':'));
        aces = aces.filter((a) => a.principal !== principal);
        aces.push({ principal, flags: '(OI)(CI)(F)', inherited: false }); // an explicit full-control grant
        i += 1;
      } else if (args[i] === '/remove:g') { const p = args[i + 1]; aces = aces.filter((a) => !(a.principal === p && !denyAce(a))); i += 1; }
      else if (args[i] === '/remove:d') { const p = args[i + 1]; aces = aces.filter((a) => !(a.principal === p && denyAce(a))); i += 1; }
    }
    return { code: 0, stdout: '' };
  };
}

test('secureAclArgs builds the ratified owner-only icacls argv (an argv array, never a shell string)', () => {
  assert.deepStrictEqual(secureAclArgs('C:\\v', 'me'), ['C:\\v', '/inheritance:r', '/grant:r', 'me:(OI)(CI)F']);
});

test('parseIcaclsAces reads the ACE principals + flags, ignoring the path and the summary line', () => {
  const aces = parseIcaclsAces(OWNER_ONLY, 'C:\\vault');
  assert.strictEqual(aces.length, 1);
  assert.strictEqual(aces[0].principal, 'DESKTOP-ABC\\me');
  assert.strictEqual(aces[0].flags, '(OI)(CI)(F)');
});

test('parseIcaclsAces keeps a principal that contains spaces intact (the path is stripped by the known dir)', () => {
  // "NT AUTHORITY\\SYSTEM" has a space: a non-space-token parse would truncate it to "AUTHORITY\\SYSTEM"
  // and a later /remove would name the wrong principal.
  const aces = parseIcaclsAces(WITH_SYSTEM, 'C:\\vault');
  assert.deepStrictEqual(aces.map((a) => a.principal), ['NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators', 'DESKTOP-ABC\\me']);
});

test('verifyOwnerOnlyAcl: owner-only passes; a stray principal, an inherited ACE, or an empty read fail closed', () => {
  assert.deepStrictEqual(verifyOwnerOnlyAcl(OWNER_ONLY, ME, 'C:\\vault'), { ok: true });
  assert.deepStrictEqual(verifyOwnerOnlyAcl(WITH_SYSTEM, ME, 'C:\\vault'), { ok: false, reason: 'acl-non-owner' });
  assert.deepStrictEqual(verifyOwnerOnlyAcl(INHERITED, ME, 'C:\\vault'), { ok: false, reason: 'acl-inherited' });
  assert.deepStrictEqual(verifyOwnerOnlyAcl('', ME, 'C:\\vault'), { ok: false, reason: 'acl-unreadable' });
});

test('verifyOwnerOnlyAcl is DENY-aware: any deny fails closed — a denied OWNER never false-passes owner-only', () => {
  // The core case: a DENY-owner ACE names the owner, but the owner is DENIED — it must not read as
  // owner-only. The deny check runs before the owner match, so this fails closed, distinctly.
  assert.deepStrictEqual(verifyOwnerOnlyAcl(DENY_OWNER, ME, 'C:\\vault'), { ok: false, reason: 'acl-deny-present' });
  // A deny for a non-owner is a restriction, reported as a deny (so recovery uses /remove:d), not a share.
  assert.deepStrictEqual(verifyOwnerOnlyAcl(DENY_EVERYONE, ME, 'C:\\vault'), { ok: false, reason: 'acl-deny-present' });
});

test('verifyOwnerOnlyAcl requires the owner to hold ALLOW full control (a read-only owner is not owner-only)', () => {
  assert.deepStrictEqual(verifyOwnerOnlyAcl(OWNER_READ_ONLY, ME, 'C:\\vault'), { ok: false, reason: 'acl-owner-not-full' });
});

test('classifyForeignAces distinguishes a deliberate ALLOW share from a DENY, and leaves the owner + inherited alone', () => {
  // A deliberate share: Everyone ALLOW alongside the owner -> one share, no denies.
  assert.deepStrictEqual(classifyForeignAces(SHARED_EVERYONE, ME, 'C:\\vault'), { shares: ['Everyone'], denies: [] });
  // A deny -> denies (not shares); never framed as a share.
  assert.deepStrictEqual(classifyForeignAces(DENY_EVERYONE, ME, 'C:\\vault'), { shares: [], denies: ['Everyone'] });
  // A deny naming the owner is still a restriction to remove, listed under denies.
  assert.deepStrictEqual(classifyForeignAces(DENY_OWNER, ME, 'C:\\vault'), { shares: [], denies: ['DESKTOP-ABC\\me'] });
  // Multiple foreign ALLOW grants -> each once, principals intact; the owner's own ALLOW is not foreign.
  assert.deepStrictEqual(classifyForeignAces(WITH_SYSTEM, ME, 'C:\\vault'), { shares: ['NT AUTHORITY\\SYSTEM', 'BUILTIN\\Administrators'], denies: [] });
  // Inherited foreign ACEs are omitted (handled by /inheritance:r on re-apply, not a per-principal remove).
  assert.deepStrictEqual(classifyForeignAces(INHERITED, ME, 'C:\\vault'), { shares: [], denies: [] });
  // An owner-only listing has nothing foreign.
  assert.deepStrictEqual(classifyForeignAces(OWNER_ONLY, ME, 'C:\\vault'), { shares: [], denies: [] });
});

test('identity: an owner ACE printed as a SID is recognized by SID (a name-only match would misread it as foreign)', () => {
  const owner = { name: 'me', sid: 'S-1-5-21-9-9-9-1001' };
  assert.deepStrictEqual(verifyOwnerOnlyAcl(OWNER_BY_SID, owner, 'C:\\vault'), { ok: true }, 'matched by SID');
  assert.strictEqual(verifyOwnerOnlyAcl(OWNER_BY_SID, 'me', 'C:\\vault').ok, false, 'name-only cannot match a SID principal — the SID is doing the work');
  assert.strictEqual(isOwner('S-1-5-21-9-9-9-1001', owner), true);
  assert.strictEqual(isOwner('S-1-5-21-9-9-9-1001', 'me'), false);
});

test('identity: the owner\'s own SID ACE is NEVER classified as a foreign share (never offered for removal)', () => {
  const owner = { name: 'me', sid: 'S-1-5-21-9-9-9-1001' };
  assert.deepStrictEqual(classifyForeignAces(OWNER_BY_SID, owner, 'C:\\vault'), { shares: [], denies: [] }, 'the owner by SID is not foreign');
  // A DIFFERENT SID alongside the owner-by-SID: only the other SID is the foreign share; the owner's own is left alone.
  assert.deepStrictEqual(classifyForeignAces(OWNER_SID_PLUS_FOREIGN_SID, owner, 'C:\\vault'), { shares: ['S-1-5-21-9-9-9-2002'], denies: [] });
});

test('identity: securing still grants BY NAME even when a SID is supplied for matching', () => {
  assert.deepStrictEqual(secureAclArgs('C:\\v', { name: 'me', sid: 'S-1-5-21-9-9-9-1001' }), ['C:\\v', '/inheritance:r', '/grant:r', 'me:(OI)(CI)F']);
});

test('identity: a same-leaf account in a DIFFERENT domain is NOT the owner (no bare-leaf over-match)', () => {
  // Current user DOMAIN1\me; an explicit DOMAIN2\me ACE must read as FOREIGN, never the owner — otherwise a
  // same-named account in another domain could read the decrypted copies while the folder false-passed owner-only.
  const FOREIGN_SAME_LEAF = 'C:\\vault DOMAIN2\\me:(OI)(CI)(F)';
  assert.strictEqual(isOwner('DOMAIN2\\me', 'DOMAIN1\\me'), false, 'a bare-leaf collision across domains is not the owner');
  assert.strictEqual(isOwner('DOMAIN1\\me', 'DOMAIN1\\me'), true, 'the fully-qualified owner still matches');
  assert.strictEqual(verifyOwnerOnlyAcl(FOREIGN_SAME_LEAF, 'DOMAIN1\\me', 'C:\\vault').ok, false, 'a foreign same-leaf account fails owner-only');
  assert.deepStrictEqual(classifyForeignAces(FOREIGN_SAME_LEAF, 'DOMAIN1\\me', 'C:\\vault'), { shares: ['DOMAIN2\\me'], denies: [] }, 'so the setup consent warning is NOT skipped');
});

test('ensureFolderSecure (win32): the common case — inherited ACEs stripped, owner granted → owner-only, ok', async () => {
  const calls = [];
  // A freshly-picked folder under the profile: everything is INHERITED (owner + Users), nothing explicit.
  const icacls = fakeIcacls([
    { principal: 'DESKTOP-ABC\\me', flags: '(OI)(CI)(F)', inherited: true },
    { principal: 'BUILTIN\\Users', flags: '(OI)(CI)(RX)', inherited: true },
  ], calls);
  assert.deepStrictEqual(await ensureFolderSecure('C:\\v', { platform: 'win32', user: 'me', icacls }), { ok: true });
  assert.deepStrictEqual(calls[0], ['C:\\v', '/inheritance:r', '/grant:r', 'me:(OI)(CI)F'], 'apply first');
  assert.deepStrictEqual(calls[1], ['C:\\v'], 'then read the ACL back to verify');
});

test('ensureFolderSecure (win32): a pre-existing EXPLICIT foreign ACE survives the apply → fail closed, never silently stripped', async () => {
  const calls = [];
  // The real-DACL case: someone deliberately shared this folder with Everyone (an EXPLICIT, non-inherited ACE).
  const initial = [
    { principal: 'DESKTOP-ABC\\me', flags: '(OI)(CI)(F)', inherited: true },
    { principal: 'Everyone', flags: '(OI)(CI)(R)', inherited: false },
  ];
  const icacls = fakeIcacls(initial, calls);
  const res = await ensureFolderSecure('C:\\v', { platform: 'win32', user: 'me', icacls });
  assert.deepStrictEqual(res, { ok: false, reason: 'acl-non-owner' }, 'Everyone survives /grant:r + /inheritance:r → read-back refuses');
  assert.ok(!calls.some((c) => c.includes('/remove:g')), 'the foreign share is NEVER silently removed');
  // Observable post-state: Everyone is still on the folder (fail-closed, not a silent strip).
  const after = await icacls(['C:\\v']);
  assert.match(after.stdout, /Everyone:/, 'the Everyone ACE is still present — the person keeps their deliberate share');
});

test('ensureFolderSecure (win32): a failed apply fails closed; a missing user fails closed', async () => {
  assert.deepStrictEqual(await ensureFolderSecure('C:\\v', { platform: 'win32', user: 'me', icacls: async () => ({ code: 1 }) }), { ok: false, reason: 'acl-apply-failed' });
  assert.deepStrictEqual(await ensureFolderSecure('C:\\v', { platform: 'win32', icacls: async () => ({ code: 0 }) }), { ok: false, reason: 'no-user' });
});

test('ensureFolderSecure (POSIX): chmod 0700 then confirm the mode; a wrong mode fails closed', async () => {
  let chmodded = null;
  const okIo = { platform: 'linux', chmod: (d, m) => { chmodded = [d, m]; }, mode: () => 0o700 };
  assert.deepStrictEqual(await ensureFolderSecure('/v', okIo), { ok: true });
  assert.deepStrictEqual(chmodded, ['/v', 0o700]);
  const badIo = { platform: 'linux', chmod: () => {}, mode: () => 0o755 };
  assert.deepStrictEqual(await ensureFolderSecure('/v', badIo), { ok: false, reason: 'mode-not-0700' });
});

test('recoverOwnerOnly (win32): with consent, un-shares an explicit ALLOW grant → owner-only, and the share is gone', async () => {
  const calls = [];
  const icacls = fakeIcacls([
    { principal: 'DESKTOP-ABC\\me', flags: '(OI)(CI)(F)', inherited: true },
    { principal: 'Everyone', flags: '(OI)(CI)(R)', inherited: false }, // a deliberate share
  ], calls);
  const res = await recoverOwnerOnly('C:\\v', { platform: 'win32', user: 'me', icacls });
  assert.deepStrictEqual(res, { ok: true, removed: { shares: ['Everyone'], denies: [] } });
  assert.ok(calls.some((c) => c[1] === '/remove:g' && c[2] === 'Everyone'), 'the ALLOW share is removed with /remove:g');
  assert.ok(!calls.some((c) => c[1] === '/remove:d'), 'a share is never removed as if it were a deny');
  const after = await icacls(['C:\\v']);
  assert.doesNotMatch(after.stdout, /Everyone:/, 'the shared access is gone after the consented recovery');
});

test('recoverOwnerOnly (win32): with consent, removes a DENY with /remove:d (never framed or removed as a share)', async () => {
  const calls = [];
  const icacls = fakeIcacls([
    { principal: 'DESKTOP-ABC\\me', flags: '(OI)(CI)(F)', inherited: true },
    { principal: 'Everyone', flags: '(DENY)(OI)(CI)(W)', inherited: false }, // a restriction, not a share
  ], calls);
  const res = await recoverOwnerOnly('C:\\v', { platform: 'win32', user: 'me', icacls });
  assert.deepStrictEqual(res, { ok: true, removed: { shares: [], denies: ['Everyone'] } });
  assert.ok(calls.some((c) => c[1] === '/remove:d' && c[2] === 'Everyone'), 'the deny is removed with /remove:d');
  assert.ok(!calls.some((c) => c[1] === '/remove:g'), 'a deny is never treated as a share');
});

test('recoverOwnerOnly (win32): a failed removal fails closed — nothing is claimed owner-only', async () => {
  // icacls refuses the /remove (e.g. a permissions error); recovery must not proceed to claim success.
  const icacls = async (args) => (args.length === 1
    ? { code: 0, stdout: 'C:\\v Everyone:(OI)(CI)(R)\n            DESKTOP-ABC\\me:(OI)(CI)(F)\nSuccessfully processed 1 files' }
    : args[1] === '/remove:g' ? { code: 1 } : { code: 0 });
  assert.deepStrictEqual(await recoverOwnerOnly('C:\\v', { platform: 'win32', user: 'me', icacls }), { ok: false, reason: 'acl-remove-failed' });
});

test('recoverOwnerOnly (win32): a folder with BOTH a share and a deny removes each with the right verb → owner-only', async () => {
  const calls = [];
  const icacls = fakeIcacls([
    { principal: 'DESKTOP-ABC\\me', flags: '(OI)(CI)(F)', inherited: true },
    { principal: 'Everyone', flags: '(OI)(CI)(R)', inherited: false },       // a share
    { principal: 'BUILTIN\\Guests', flags: '(DENY)(OI)(CI)(W)', inherited: false }, // a deny
  ], calls);
  const res = await recoverOwnerOnly('C:\\v', { platform: 'win32', user: 'me', icacls });
  assert.deepStrictEqual(res, { ok: true, removed: { shares: ['Everyone'], denies: ['BUILTIN\\Guests'] } });
  assert.ok(calls.some((c) => c[1] === '/remove:g' && c[2] === 'Everyone'), 'the share went through /remove:g');
  assert.ok(calls.some((c) => c[1] === '/remove:d' && c[2] === 'BUILTIN\\Guests'), 'the deny went through /remove:d');
});

test('recoverOwnerOnly (win32): a SID-identified owner is preserved while a foreign SID share is removed', async () => {
  const calls = [];
  const owner = { name: 'me', sid: 'S-1-5-21-9-9-9-1001' };
  const icacls = fakeIcacls([
    { principal: 'S-1-5-21-9-9-9-1001', flags: '(OI)(CI)(F)', inherited: false }, // the owner, by SID
    { principal: 'S-1-5-21-9-9-9-2002', flags: '(OI)(CI)(R)', inherited: false }, // a foreign account, by SID
  ], calls);
  const res = await recoverOwnerOnly('C:\\v', { platform: 'win32', user: owner, icacls });
  assert.strictEqual(res.ok, true);
  assert.deepStrictEqual(res.removed, { shares: ['S-1-5-21-9-9-9-2002'], denies: [] }, 'only the foreign SID is removed');
  assert.ok(!calls.some((c) => c[1] === '/remove:g' && c[2] === 'S-1-5-21-9-9-9-1001'), "the owner's own SID grant is never removed");
});

test('recoverOwnerOnly (win32): a folder with nothing foreign just re-secures (no /remove calls)', async () => {
  const calls = [];
  const icacls = fakeIcacls([{ principal: 'DESKTOP-ABC\\me', flags: '(OI)(CI)(F)', inherited: true }], calls);
  const res = await recoverOwnerOnly('C:\\v', { platform: 'win32', user: 'me', icacls });
  assert.deepStrictEqual(res, { ok: true, removed: { shares: [], denies: [] } });
  assert.ok(!calls.some((c) => c[1] === '/remove:g' || c[1] === '/remove:d'), 'nothing foreign → no removals, just the owner-only re-apply');
});

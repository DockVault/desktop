'use strict';

/*
 * Honest failure reasons, end to end.
 *
 * The claim under test is one sentence: when a sync fails or is held back, every surface a person can look at
 * names the REAL cause in plain words — and where the cause is not knowable on this computer, says so honestly
 * rather than guessing a specific one. So these tests walk the whole path a cause travels:
 *
 *   the server's own refusal text  ->  the helper's typed result + bounded detail  ->  the status model's
 *   state + reason  ->  the tray glance, the tray menu item, the Computers card, and the "Sync now" toast.
 *
 * Two properties are asserted everywhere and are the point of the phase:
 *   1. NOTHING a person sees is a raw error string or an internal token. The server's refusals name its own
 *      configuration settings; those must never be quoted at a user, and neither must a symbol like
 *      'upload-not-stored'.
 *   2. A cause is claimed ONLY from evidence. "This vault is out of space" appears only when the server's own
 *      numbers said so; a stated maximum appears only when the server stated one; a wait appears only when
 *      there is a wait left.
 */

const test = require('node:test');
const assert = require('node:assert');

const { classifyBisyncOutcome, outcomeDetail, RESULT } = require('../src/daemon/bisync-outcome');
const { computeStatus, publicStatus, OUTCOME_STATE, STATE, vaultState: statusModelVaultState } = require('../src/main/sync-status-model');
const tray = require('../src/main/tray-presentation');
const { manualCompletionBody, bodyForConditionReason, turnedAwayBody } = require('../src/main/manual-sync-copy');
const { vaultSpaceOf, isOutOfSpace, fetchVaultSpace } = require('../src/main/vault-space');
const { SyncScheduler } = require('../src/main/sync-scheduler');
const { applySchedulerEvent } = require('../src/main/scheduler-io');
const { SyncStatusHub } = require('../src/main/sync-status-hub');

// The REAL refusals, copied from the server's own SFTP door. Everything downstream is keyed off these, so if
// the server ever rewords them these tests are where it shows.
const SERVER_SAYS = {
  // the buffered upload path's in-stream size refusal (it names the operator's own tuning settings)
  tooLargeBuffered: 'ERROR : reports/big archive.zip: Failed to copy: sftp: "upload rejected: file exceeds the 512 MB SFTP limit (raise the staging buffer setting, or lower the maximum file size to match)" (SSH_FX_FAILURE)',
  // the streaming upload path's version of the same refusal
  tooLargeStreaming: 'ERROR : holiday.mov: Failed to copy: sftp: "upload rejected: file exceeds the 200 MB SFTP limit (raise the maximum file size)" (SSH_FX_FAILURE)',
  // the server's staging space ran out mid-transfer
  noRoom: 'ERROR : a.bin: Failed to copy: sftp: "upload failed: the SFTP staging buffer is full (raise the staging buffer setting)" (SSH_FX_FAILURE)',
  // The door took the bytes and then decided not to keep the file. CAPTURED VERBATIM from a real run against
  // the running server: a 3 MB file bisynced into a vault with a ~1 MB allowance. rclone uploads to a
  // temporary sibling and renames it at the end, so the discard shows up as a rename that finds nothing —
  // and bisync then reports its own generic critical error over the top, which is exactly what used to win
  // and turn this into a wrong "needs a repair".
  notKept: [
    '2026/09/08 22:24:24 ERROR : big.bin.892c9efd.partial: partial file rename failed: Move Rename failed: file does not exist',
    '2026/09/08 22:24:24 ERROR : sftp://user@host:port//probe: not deleting files as there were IO errors',
    '2026/09/08 22:24:24 ERROR : Bisync critical error: Move Rename failed: file does not exist',
    '2026/09/08 22:24:24 ERROR : Bisync aborted. Must run --resync to recover.',
  ].join('\n'),
  // the same event on a path that uploads in place: this server cannot store a client mtime, so rclone's
  // post-upload verification is a stat, and it comes back empty
  notKeptInPlace: 'ERROR : notes.txt: Failed to copy: Update SetModTime failed: SetModTime stat failed: object not found',
  // the server answered and turned the session channel away (a limit, or no session slot free)
  refused: 'Failed to create file system for "vault:/x": NewFs: couldn\'t connect SSH: ssh: rejected: administratively prohibited (open failed)',
};

// Every internal token the app moves around. None of them may ever appear in something a person reads.
const INTERNAL_TOKENS = /upload-not-stored|file-too-large|server-no-space|vault-full|channel-refused|sync-server-refusing|auth-failed|needs-resync|host-key-mismatch|SSH_FX|staging buffer setting|maximum file size|sftp:|rclone|bisync|\.partial\b|SetModTime|Move Rename/;

function assertHuman(text, what) {
  assert.strictEqual(typeof text, 'string', `${what} must be a sentence`);
  assert.ok(text.length > 0, `${what} must not be blank`);
  assert.doesNotMatch(text, INTERNAL_TOKENS, `${what} must never show a raw error string or an internal token`);
}

// ---------------------------------------------------------------------------------------------------------
// 1. The helper: the server's words -> one typed result + a bounded detail
// ---------------------------------------------------------------------------------------------------------

test('a size the server stated becomes the file-too-large result, with the file and the maximum it named', () => {
  const a = classifyBisyncOutcome({ code: 1, stderr: SERVER_SAYS.tooLargeBuffered });
  assert.strictEqual(a.result, RESULT.FILE_TOO_LARGE);
  assert.deepStrictEqual(a.detail, { file: 'big archive.zip', maxBytes: 512 * 1024 * 1024 });
  const b = classifyBisyncOutcome({ code: 1, stderr: SERVER_SAYS.tooLargeStreaming });
  assert.strictEqual(b.result, RESULT.FILE_TOO_LARGE);
  assert.deepStrictEqual(b.detail, { file: 'holiday.mov', maxBytes: 200 * 1024 * 1024 });
});

test('the server saying it has no room, and the server silently not keeping a file, are DIFFERENT results', () => {
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: SERVER_SAYS.noRoom }).result, RESULT.SERVER_NO_SPACE);
  const live = classifyBisyncOutcome({ code: 1, stderr: SERVER_SAYS.notKept });
  assert.strictEqual(live.result, RESULT.UPLOAD_NOT_STORED, 'the real captured run, not a guess at one');
  assert.strictEqual(live.detail.file, 'big.bin', "rclone's temporary upload name is not what the person has in their folder");
  assert.strictEqual(live.resyncRequired, true, 'the resync bisync demanded is still owed');
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: SERVER_SAYS.notKeptInPlace }).result, RESULT.UPLOAD_NOT_STORED);
  // and neither is collapsed into the other, nor into the generic error
  assert.notStrictEqual(RESULT.SERVER_NO_SPACE, RESULT.UPLOAD_NOT_STORED);
  assert.notStrictEqual(RESULT.UPLOAD_NOT_STORED, RESULT.ERROR);
});

test('the real cause outranks the generic "needs a repair" bisync also reports, WITHOUT dropping the repair latch', () => {
  // A failed transfer makes bisync declare a critical error and owe a resync. That generic signature must not
  // win, or every refused file reads as "this needs a repair" — the wrong-cause answer.
  const both = `${SERVER_SAYS.tooLargeBuffered}\n2026/09/08 12:00:00 ERROR : Bisync critical error: cannot find prior Path1 listing`;
  const o = classifyBisyncOutcome({ code: 1, stderr: both });
  assert.strictEqual(o.result, RESULT.FILE_TOO_LARGE, 'the file the server refused is the honest cause');
  assert.strictEqual(o.resyncRequired, true, 'and the resync bisync asked for is still owed');
});

test('a data-safety abort still outranks a file refusal — a mass delete is the more serious event', () => {
  // The abort carries the log level the tool actually writes: a verdict about the run is believed only
  // when it comes from a line the logger wrote, so a file NAME carrying a newline cannot forge one.
  const both = `${SERVER_SAYS.tooLargeBuffered}\nERROR : Safety abort: too many deletes (>50%, 9 of 10). Bisync aborted.`;
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: both }).result, RESULT.ABORT_EXCESSIVE_DELETE);
  // as does a changed server identity
  const mitm = `${SERVER_SAYS.notKept}
ERROR : Failed to create file system: NewFs: couldn't connect SSH: ssh: handshake failed: knownhosts: key mismatch`;
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: mitm }).result, RESULT.HOST_KEY_MISMATCH);
});

test('a clean run is untouched by any of it', () => {
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stderr: 'nothing to transfer' }).result, RESULT.OK);
  assert.strictEqual(classifyBisyncOutcome({ code: 0, stderr: 'nothing to transfer' }).detail, undefined);
});

test('the detail is bounded: a base name only, never a path, never control characters, never a wild number', () => {
  // folders above the file are dropped — only the leaf a person would look for survives
  assert.strictEqual(outcomeDetail('ERROR : deep/nested/dir/report.pdf: Failed to copy: x').file, 'report.pdf');
  // a name carrying control characters is refused outright rather than sanitised into something showable —
  // with nothing else to carry, the whole detail is null and the copy falls back to its no-name wording
  assert.strictEqual(outcomeDetail('ERROR : ..\u0007evil.txt: Failed to copy: x'), null);
  // an absurd stated size is not carried either
  assert.strictEqual(outcomeDetail('exceeds the 99999999999 GB limit'), null);
  // and a line that names nothing yields nothing at all rather than an empty shell
  assert.strictEqual(outcomeDetail('something went wrong'), null);
  // the two halves are independent: a stated size with no nameable file still carries the size
  assert.deepStrictEqual(outcomeDetail('sftp: "file exceeds the 512 MB limit"'), { file: null, maxBytes: 512 * 1024 * 1024 });
});

// ---------------------------------------------------------------------------------------------------------
// 2. The model: each typed result gets its own state, and none of them reads as green
// ---------------------------------------------------------------------------------------------------------

test('each file-level result has its own state and reason, and none is green', () => {
  for (const r of ['file-too-large', 'server-no-space', 'upload-not-stored', 'vault-full']) {
    const m = OUTCOME_STATE[r];
    assert.ok(m, `${r} is mapped`);
    assert.notStrictEqual(m.state, STATE.UP_TO_DATE, `${r} must never read as up to date`);
    assert.ok(m.reason, `${r} carries its own reason`);
  }
  // the two the person must decide about, versus the one that is genuinely just a wait on the server
  assert.strictEqual(OUTCOME_STATE['vault-full'].state, STATE.NEEDS_DECISION);
  assert.strictEqual(OUTCOME_STATE['file-too-large'].state, STATE.NEEDS_DECISION);
  assert.strictEqual(OUTCOME_STATE['server-no-space'].state, STATE.PAUSED);
});

test('the detail rides onto the vault state and the aggregate, and is dropped when a condition takes the face', () => {
  const detail = { file: 'a.bin', maxBytes: 5 };
  const m = computeStatus({
    hasSecureStore: true, online: true, daemon: 'ready',
    vaults: [{ vault: 'v', lastResult: 'file-too-large', detail, retryAt: 123 }],
  });
  assert.deepStrictEqual(m.vaults[0].detail, detail);
  assert.strictEqual(m.detail, detail, 'the winning contributor carries it to the glance');
  // A live can't-run condition replaces the face; the previous outcome's detail must not trail onto it and
  // name a file that has nothing to do with what is now being shown.
  const withCond = computeStatus({
    hasSecureStore: true, online: true, daemon: 'ready',
    vaults: [{ vault: 'v', lastResult: 'file-too-large', detail, condition: { state: STATE.SYNC_PROBLEM, reason: 'not-syncing' } }],
  });
  assert.strictEqual(withCond.vaults[0].reason, 'not-syncing');
  assert.strictEqual(withCond.vaults[0].detail, null);
});

test('the detail never crosses into a renderer', () => {
  const m = computeStatus({
    hasSecureStore: true, online: true, daemon: 'ready',
    vaults: [{ vault: 'v', lastResult: 'file-too-large', detail: { file: 'private-name.txt', maxBytes: 5 }, retryAt: 9 }],
  });
  const pub = publicStatus(m);
  assert.doesNotMatch(JSON.stringify(pub), /private-name\.txt/, 'a file name is main-process-only');
  assert.strictEqual(pub.detail, undefined);
  assert.strictEqual(pub.vaults[0].detail, undefined);
  // everything a page actually renders survives the trip
  assert.strictEqual(pub.vaults[0].reason, 'file-too-large');
  assert.strictEqual(pub.vaults[0].retryAt, 9);
  assert.strictEqual(pub.state, m.state);
});

// ---------------------------------------------------------------------------------------------------------
// 3. The copy: the acceptance sentences, on the tray and in the Computers window
// ---------------------------------------------------------------------------------------------------------

const NOW = 1_700_000_000_000;
const named = { v: 'Photos' };

test('a full vault says it is out of space, in those words, on every surface', () => {
  const v = { vault: 'v', reason: 'vault-full', detail: { limitBytes: 100 * 1024 * 1024, freeBytes: 0 } };
  const item = tray.itemForVault(v, named);
  assertHuman(item.label, 'the tray item');
  assert.match(item.label, /Photos is out of space\./);
  assert.match(item.label, /100 MB/, 'the allowance the server reported');
  assert.ok(tray.HANDLED_ACTION_KINDS.includes(item.kind), 'and it offers a door the app can actually open');
  // the same sentence for a press, from the same source
  const toast = manualCompletionBody({ phase: 'done', outcome: { result: 'vault-full', detail: v.detail } }, 'Photos');
  assert.strictEqual(toast.body, item.label);
  // And the short glance, which has to be true of BOTH shapes of a space failure — a spent allowance and one
  // with a little room left that the file doesn't fit into — so it says the thing common to them.
  assertHuman(tray.REASON_DETAIL['vault-full'], 'the tray glance suffix');
  assert.match(tray.REASON_DETAIL['vault-full'], /doesn't have room/);
});

test('a file the server refused for size names the file and the maximum the server itself stated', () => {
  const v = { vault: 'v', reason: 'file-too-large', detail: { file: 'holiday.mov', maxBytes: 512 * 1024 * 1024 } };
  const label = tray.itemForVault(v, named).label;
  assertHuman(label, 'the tray item');
  assert.match(label, /holiday\.mov/);
  assert.match(label, /larger than the sync server accepts \(max 512 MB\)/);
  // With no stated maximum, the sentence drops the "(max …)" instead of inventing one.
  const noMax = tray.itemForVault({ vault: 'v', reason: 'file-too-large', detail: { file: 'holiday.mov', maxBytes: null } }, named).label;
  assertHuman(noMax, 'the no-maximum tray item');
  assert.doesNotMatch(noMax, /max/, 'a maximum is never invented');
  assert.match(noMax, /holiday\.mov/);
  // With no file name either, it still says the true thing rather than a blank or a token.
  const bare = tray.itemForVault({ vault: 'v', reason: 'file-too-large', detail: null }, named).label;
  assertHuman(bare, 'the no-detail tray item');
  assert.match(bare, /A file in Photos is larger than the sync server accepts/);
});

test('a rate-limited server says so, says how long, and says what will NOT help', () => {
  const v = { vault: 'v', reason: 'sync-server-refusing', retryAt: NOW + 5 * 60 * 1000 };
  const label = tray.itemForVault(v, named, { now: NOW }).label;
  assertHuman(label, 'the refusal sentence');
  assert.match(label, /temporarily limiting sync attempts/);
  assert.match(label, /in about 5 minutes/, 'the wait, in words');
  assert.match(label, /deactivating credentials won't help/);
  assert.doesNotMatch(label, /[Ss]ign in (to|and)|enter the vault password/, 'never a sign-in remedy for a rate limit');
  // A wait already past says nothing about time rather than promising a moment that has gone.
  const lapsed = tray.itemForVault({ ...v, retryAt: NOW - 1 }, named, { now: NOW }).label;
  assert.doesNotMatch(lapsed, /in about/);
  assert.match(lapsed, /temporarily limiting sync attempts/);
  // The glance carries the wait too, and stays inside the tooltip budget.
  const m = computeStatus({ hasSecureStore: true, online: true, daemon: 'ready', vaults: [{ vault: 'v', lastResult: 'channel-refused', retryAt: NOW + 45 * 60 * 1000 }] });
  const tip = tray.tooltip(m, null, null, { now: NOW });
  assertHuman(tip, 'the tray tooltip');
  assert.match(tip, /limiting sync attempts/);
  assert.match(tip, /retrying in about 45 minutes/);
  assert.ok(tip.length <= 127, `the Windows tooltip is cut at about 127 characters (was ${tip.length})`);
});

test("a press turned away by a rate limit is not answered with a sign-in, but a refused credential still is", () => {
  const limited = turnedAwayBody({ accepted: false, reason: 'backing-off', retryInMs: 240_000, cause: 'channel-refused' }, 'Photos');
  assertHuman(limited, 'the rate-limited press answer');
  assert.match(limited, /limiting sync attempts/);
  assert.doesNotMatch(limited, /[Ss]ign in (to|and)|enter the vault password/);
  assert.match(limited, /won't help/);
  const credential = turnedAwayBody({ accepted: false, reason: 'backing-off', retryInMs: 240_000, cause: 'auth-failed' }, 'Photos');
  assertHuman(credential, 'the refused-credential press answer');
  assert.match(credential, /sign in or enter the vault password/, 'here a sign-in genuinely may unblock it');
});

test("a cause this computer cannot know says exactly that — never a guessed specific", () => {
  const v = { vault: 'v', reason: 'upload-not-stored', detail: { file: 'notes.txt' } };
  const label = tray.itemForVault(v, named).label;
  assertHuman(label, 'the not-kept sentence');
  assert.match(label, /accepted “notes\.txt” from Photos and then didn't keep it/);
  assert.match(label, /untouched/, 'and it says what was NOT done');
  assert.doesNotMatch(label, /out of space|too large|full/, 'it must not guess a cause it does not have');
  // With the vault's numbers in hand it adds them — still without asserting they are the cause.
  const withRoom = tray.itemForVault({ ...v, detail: { file: 'notes.txt', freeBytes: 4 * 1024 * 1024, limitBytes: 100 * 1024 * 1024 } }, named).label;
  assert.match(withRoom, /4 MB free of 100 MB/);
});

test('a failure nothing could classify still gets an honest sentence, never a bare "could not sync"', () => {
  const label = tray.itemForVault({ vault: 'v', reason: 'error' }, named).label;
  assertHuman(label, 'the unclassified sentence');
  assert.match(label, /couldn't tell why/, 'it admits what it does not know');
  assert.match(label, /Nothing here was changed/);
  assert.ok(tray.HANDLED_ACTION_KINDS.includes(label && tray.itemForVault({ vault: 'v', reason: 'error' }, named).kind));
  const toast = manualCompletionBody({ phase: 'error', reason: 'run-failed' }, 'Photos');
  assertHuman(toast.body, 'the unclassified press answer');
  assert.match(toast.body, /couldn't tell why/);
});

test('no reason the app can produce falls through to a bare token or a blank', () => {
  // Every outcome the helper (or the scheduler's re-typing) can produce, checked at the surface that actually
  // shows it: a reason that needs a person appears as a tray MENU ITEM, and one that is merely a wait appears
  // as the GLANCE suffix or an enriched sentence. Neither may be missing, and neither may fall through.
  for (const [result, mapped] of Object.entries(OUTCOME_STATE)) {
    if (!mapped.reason) continue;
    const reason = mapped.reason;
    if (mapped.state === STATE.NEEDS_DECISION || mapped.state === STATE.SYNC_PROBLEM) {
      const item = tray.itemForVault({ vault: 'v', reason }, named);
      assertHuman(item.label, `the menu line for ${result}`);
      assert.ok(tray.HANDLED_ACTION_KINDS.includes(item.kind), `${result} offers a door the app can open`);
      assert.doesNotMatch(item.label, /needs attention — open DockVault/, `${result} must not fall through to the last-resort line`);
    } else {
      const calm = tray.reasonSentence(reason, { name: 'Photos' }) || tray.REASON_DETAIL[reason];
      assertHuman(calm, `the calm line for ${result}`);
    }
  }
  // And the last-resort line itself, for a reason that does not exist, is still a sentence and not a symbol.
  const fallback = tray.itemForVault({ vault: 'v', reason: 'a-reason-from-the-future' }, named);
  assertHuman(fallback.label, 'the last-resort line');
  assert.doesNotMatch(fallback.label, /a-reason-from-the-future/);
});

// ---------------------------------------------------------------------------------------------------------
// 4. "Out of space" is only ever said when the server's own numbers say it
// ---------------------------------------------------------------------------------------------------------

test('the space picture is read only from a complete, sane pair of numbers', () => {
  assert.deepStrictEqual(vaultSpaceOf({ size_limit: 100, total_size_bytes: 40 }), { known: true, limitBytes: 100, usedBytes: 40, freeBytes: 60 });
  assert.strictEqual(vaultSpaceOf({ size_limit: 100, total_size_bytes: 100 }).freeBytes, 0);
  assert.strictEqual(vaultSpaceOf({ size_limit: 100, total_size_bytes: 140 }).freeBytes, 0, 'over the line still reads as nothing free, never negative');
  // A vault with no allowance can never be called full — the deployment-wide cap is a limit this cannot see.
  assert.strictEqual(vaultSpaceOf({ size_limit: null, total_size_bytes: 40 }).known, false);
  assert.strictEqual(vaultSpaceOf({ size_limit: 0, total_size_bytes: 40 }).known, false);
  // A scoped credential's answer omits the aggregates; that is unknown, not zero.
  assert.strictEqual(vaultSpaceOf({ size_limit: 100, total_size_bytes: null }).known, false);
  assert.strictEqual(vaultSpaceOf(null).known, false);
  assert.strictEqual(isOutOfSpace(vaultSpaceOf({ size_limit: 100, total_size_bytes: 100 })), true);
  assert.strictEqual(isOutOfSpace(vaultSpaceOf({ size_limit: 100, total_size_bytes: 99 })), false);
  assert.strictEqual(isOutOfSpace(vaultSpaceOf({})), false, 'an unknown pair is never "full"');
});

test('the space read never throws and never invents an answer', async () => {
  const unknown = { known: false, limitBytes: null, usedBytes: null, freeBytes: null };
  assert.deepStrictEqual(await fetchVaultSpace({ serverOrigin: 'https://s', sessionToken: null, vaultId: 'v' }, async () => { throw new Error('x'); }), unknown, 'no session, no call');
  assert.deepStrictEqual(await fetchVaultSpace({ serverOrigin: 'https://s', sessionToken: 't', vaultId: 'v' }, async () => { throw new Error('down'); }), unknown);
  assert.deepStrictEqual(await fetchVaultSpace({ serverOrigin: 'https://s', sessionToken: 't', vaultId: 'v' }, async () => ({ status: 500, json: async () => ({}) })), unknown);
  assert.deepStrictEqual(await fetchVaultSpace({ serverOrigin: 'https://s', sessionToken: 't', vaultId: 'v' }, async () => ({ status: 200, json: async () => { throw new Error('html'); } })), unknown);
  const ok = await fetchVaultSpace({ serverOrigin: 'https://s/', sessionToken: 't', vaultId: 'v' }, async (url, init) => {
    assert.strictEqual(url, 'https://s/vaults/v');
    assert.strictEqual(init.headers.Authorization, 'Bearer t');
    return { status: 200, json: async () => ({ size_limit: 10, total_size_bytes: 10 }) };
  });
  assert.strictEqual(isOutOfSpace(ok), true);
});

// ---------------------------------------------------------------------------------------------------------
// 5. The scheduler: one read of the vault's numbers, and only then the specific name
// ---------------------------------------------------------------------------------------------------------

const V = '7c9e6b4a-2d31-4f58-9a0e-3b5d81c26f4a';

function schedulerFor({ result, space, onEvent }) {
  const calls = { space: 0 };
  const io = {
    listConfigured: () => [{ vaultId: V, vaultName: 'Photos', localFolder: 'C:/f', remotePath: 'Photos', enabled: true }],
    runState: () => ({ lastResult: 'ok', resyncRequired: false }),
    session: () => ({ locked: false, online: true, accountLive: true }),
    verifyEligible: async () => ({ ok: true, remotePath: 'Photos', vaultName: 'Photos', via: 'account' }),
    secureFolder: () => ({ ok: true }),
    classify: () => ({ ok: true }),
    helperReady: async () => ({ ok: true }),
    refreshCred: async () => ({ ok: true }),
    runSync: async () => ({ ok: true, ran: true, result, detail: { file: 'notes.txt' } }),
    vaultSpace: space ? async () => { calls.space += 1; return space; } : undefined,
    onEvent,
  };
  return { sched: new SyncScheduler(io), calls };
}

// The scheduler dispatches on its own pump; wait for it to go idle, exactly as its own suite does.
async function settle(sched) {
  for (let i = 0; i < 300 && (sched._busy || sched._queue.length); i++) await new Promise((r) => setTimeout(r, 2));
}

test('a not-kept upload is re-typed to a full vault ONLY when the vault\'s own numbers say so', async () => {
  // The numbers say the allowance is spent -> the specific, true name.
  const events = [];
  const full = schedulerFor({ result: 'upload-not-stored', space: { known: true, limitBytes: 100, usedBytes: 100, freeBytes: 0 }, onEvent: (v, ev) => events.push(ev) });
  full.sched.requestSync(V);
  await settle(full.sched);
  const done = events.filter((e) => e.phase === 'done').pop();
  assert.strictEqual(done.outcome.result, 'vault-full');
  assert.strictEqual(done.outcome.detail.limitBytes, 100);
  assert.strictEqual(full.calls.space, 1, 'asked exactly once');

  // The numbers say there is room left -> the outcome keeps its weaker, TRUE name, with the room added.
  const room = [];
  const some = schedulerFor({ result: 'upload-not-stored', space: { known: true, limitBytes: 100, usedBytes: 40, freeBytes: 60 }, onEvent: (v, ev) => room.push(ev) });
  some.sched.requestSync(V);
  await settle(some.sched);
  const doneRoom = room.filter((e) => e.phase === 'done').pop();
  assert.strictEqual(doneRoom.outcome.result, 'upload-not-stored', 'never upgraded to "full" on a vault with room');
  assert.strictEqual(doneRoom.outcome.detail.freeBytes, 60);

  // No answer at all (locked, signed out, an unreadable reply) -> nothing is claimed.
  const blind = [];
  const none = schedulerFor({ result: 'upload-not-stored', space: { known: false }, onEvent: (v, ev) => blind.push(ev) });
  none.sched.requestSync(V);
  await settle(none.sched);
  assert.strictEqual(blind.filter((e) => e.phase === 'done').pop().outcome.result, 'upload-not-stored');

  // And a check that throws is contained — the run still resolves with its honest outcome.
  const thrown = [];
  const boom = schedulerFor({ result: 'upload-not-stored', onEvent: (v, ev) => thrown.push(ev) });
  boom.sched._io.vaultSpace = async () => { throw new Error('offline'); };
  boom.sched.requestSync(V);
  await settle(boom.sched);
  assert.strictEqual(thrown.filter((e) => e.phase === 'done').pop().outcome.result, 'upload-not-stored');
});

test('a clean run never triggers a space read', async () => {
  const { sched, calls } = schedulerFor({ result: 'ok', space: { known: true, limitBytes: 100, usedBytes: 100, freeBytes: 0 }, onEvent: () => {} });
  sched.requestSync(V);
  await settle(sched);
  assert.strictEqual(calls.space, 0, 'the vault record is read only when a run actually suggests a space problem');
});

// ---------------------------------------------------------------------------------------------------------
// 6. The sink: the detail reaches the glance, and does not outlive the outcome it describes
// ---------------------------------------------------------------------------------------------------------

test('the outcome detail and the wait travel from the scheduler event to the computed status', () => {
  const seen = [];
  const hub = new SyncStatusHub({ onStatus: (m) => seen.push(m) });
  hub.setVaults([V]);
  applySchedulerEvent(hub, V, { phase: 'done', outcome: { result: 'file-too-large', detail: { file: 'a.mov', maxBytes: 5 } } });
  let vault = hub.current().vaults[0];
  assert.strictEqual(vault.reason, 'file-too-large');
  assert.deepStrictEqual(vault.detail, { file: 'a.mov', maxBytes: 5 });
  assert.match(tray.itemForVault(vault, { [V]: 'Photos' }).label, /a\.mov/);

  applySchedulerEvent(hub, V, { phase: 'done', outcome: { result: 'channel-refused' }, retryAt: NOW + 60_000 });
  vault = hub.current().vaults[0];
  assert.strictEqual(vault.reason, 'sync-server-refusing');
  assert.strictEqual(vault.detail, null, "a new outcome never keeps the previous failure's file");
  assert.strictEqual(vault.retryAt, NOW + 60_000);

  applySchedulerEvent(hub, V, { phase: 'done', outcome: { result: 'ok' } });
  assert.strictEqual(hub.current().vaults[0].detail, null);
  assert.strictEqual(hub.current().vaults[0].retryAt, null);
});

test('the Computers card and the tray say the SAME thing about the same failure', () => {
  // reasonText (main/index.js) resolves a card's sentence through this same source. Assert the three shapes it
  // relies on, so a change here that broke the card would fail rather than quietly diverge.
  for (const [reason, detail] of [
    ['vault-full', { limitBytes: 100 * 1024 * 1024 }],
    ['file-too-large', { file: 'a.mov', maxBytes: 5 * 1024 * 1024 }],
    ['upload-not-stored', { file: 'a.mov' }],
    ['server-no-space', null],
    ['sync-server-refusing', null],
  ]) {
    const sentence = tray.reasonSentence(reason, { name: 'Photos', detail, retryAt: NOW + 60_000, now: NOW });
    assertHuman(sentence, `the card sentence for ${reason}`);
    const toast = bodyForConditionReason(reason, 'Photos', { detail, retryAt: NOW + 60_000, now: NOW });
    assert.strictEqual(toast, sentence, `${reason} reads identically on the card and in the toast`);
  }
  // A reason with no enriched sentence falls back cleanly rather than returning something empty.
  assert.strictEqual(tray.reasonSentence('sign-in-needed', { name: 'Photos' }), null);
});


test("the engine's lookup key for the failing file refuses anything that is not a plain relative path", () => {
  const { failedRelPath } = require('../src/daemon/bisync-outcome');
  assert.strictEqual(failedRelPath('ERROR : sub/dir/big.bin.892c9efd.partial: partial file rename failed: x'), 'sub/dir/big.bin');
  // Everything that could point somewhere other than inside the synced folder is refused outright.
  assert.strictEqual(failedRelPath('ERROR : C:/elsewhere/x.txt: Failed to copy: x'), null, 'an absolute path');
  assert.strictEqual(failedRelPath('ERROR : /etc/passwd: Failed to copy: x'), null, 'a rooted path');
  assert.strictEqual(failedRelPath('ERROR : ../../up.txt: Failed to copy: x'), null, 'a traversal');
  assert.strictEqual(failedRelPath('ERROR : sftp://user@host:port//vault: not deleting files as there were IO errors'), null, 'a URL rclone logged');
  assert.strictEqual(failedRelPath('ERROR : bad\u0007name.txt: Failed to copy: x'), null, 'a control character');
});

test('a vault with room left is not called "out of space" — it is told what does not fit', () => {
  // The case people actually meet: the vault still has room, just not enough for this file. Saying "out of
  // space" and "1 MB is free" in one breath contradicts itself, so this branch says what is actually wrong.
  const label = tray.itemForVault({
    vault: 'v', reason: 'vault-full',
    detail: { file: 'big.bin', bytes: 3 * 1024 * 1024, freeBytes: 1024 * 1024, limitBytes: 8 * 1024 * 1024 },
  }, named).label;
  assertHuman(label, 'the does-not-fit sentence');
  assert.match(label, /Photos doesn't have room for “big\.bin”/);
  assert.match(label, /needs 3 MB, and only 1 MB is free of 8 MB/);
  assert.doesNotMatch(label, /out of space/, 'a vault with 1 MB free is not out of space');
  // A vault whose allowance IS entirely spent says exactly that, without inventing a file.
  const spent = tray.itemForVault({ vault: 'v', reason: 'vault-full', detail: { limitBytes: 8 * 1024 * 1024, freeBytes: 0 } }, named).label;
  assert.match(spent, /Photos is out of space\./);
  assert.match(spent, /used all 8 MB of its allowance/);
  assert.doesNotMatch(spent, /needs/);
});

// ---------------------------------------------------------------------------------------------------------
// 7. The cause must not be laundered back into a generic — by a competing signature, by a green run, or by
//    the resync latch a few minutes later
// ---------------------------------------------------------------------------------------------------------

test('a connection that died mid-transfer is a connection failure, not a claim about the server', () => {
  // Both traces land in one log. Reading it as "the server accepted your file and then didn't keep it" is a
  // specific, confident claim about a server that was never reached — and it would tell the credential bounds
  // the door ANSWERED, re-opening the gate that stops this computer minting against a door that is down.
  const dropped = [
    'ERROR : big.iso: Failed to copy: corrupted on transfer: sizes differ 1048576 vs 524288',
    'ERROR : big.iso: Failed to copy: read tcp: connection reset by peer',
  ].join('\n');
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: dropped }).result, RESULT.CONNECT_FAILED);
  const timedOut = 'ERROR : notes.txt: Failed to copy: object not found\nNewFs: couldn\'t connect SSH: dial tcp: i/o timeout';
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: timedOut }).result, RESULT.CONNECT_FAILED);
  // The scheduler reads that decision to close its endpoint gate — the connection class must stay in the set
  // the gate keys on, or a down door goes back to costing a credential every tick.
  const { CONNECT_RESULTS } = require('../src/main/sync-scheduler');
  assert.ok(CONNECT_RESULTS.has(RESULT.CONNECT_FAILED));
  assert.ok(!CONNECT_RESULTS.has(RESULT.UPLOAD_NOT_STORED));
});

test('a run that SUCCEEDED is never turned into a failure by the retries it recovered from', () => {
  // rclone retries at a low level and logs the attempt it then recovers from, and against this server (which
  // cannot store a client mtime) it logs a modification-time notice on runs that exit 0.
  for (const noisy of [
    'NOTICE: notes.txt: Failed to set modification time: SetModTime stat failed',
    'ERROR : big.iso: Failed to copy: corrupted on transfer: sizes differ 100 vs 50\nINFO : big.iso: Copied (new)',
    'ERROR : a.bin: Failed to copy: sftp: "quota exceeded" (SSH_FX_FAILURE)\nINFO : a.bin: Copied (new)',
  ]) {
    const o = classifyBisyncOutcome({ code: 0, stderr: noisy });
    assert.strictEqual(o.result, RESULT.OK, `a clean exit stays clean: ${noisy.slice(0, 48)}`);
    assert.strictEqual(o.needsAttention, false);
  }
});

test("the LOCAL disk filling up is never reported as the server's problem", () => {
  // These are the phrases the local filesystem uses. Telling someone their server is full while their own
  // disk is full sends them to the wrong place entirely — and promises a wait that will never help.
  for (const local of [
    'ERROR : down.bin: Failed to copy: write /home/x/Vault/down.bin: no space left on device',
    'ERROR : movie.mkv: Failed to copy: write /mnt/usb/movie.mkv: file too large',
    'ERROR : a.bin: Failed to copy: open C:/Users/x/f: disk full',
  ]) {
    const r = classifyBisyncOutcome({ code: 1, stderr: local }).result;
    assert.notStrictEqual(r, RESULT.SERVER_NO_SPACE, `not the server's space: ${local.slice(0, 40)}`);
    assert.notStrictEqual(r, RESULT.FILE_TOO_LARGE, `not the server's size limit: ${local.slice(0, 40)}`);
  }
  // The same words INSIDE the remote wrapper are the server saying it, and are classified as such.
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: 'ERROR : a.bin: Failed to copy: sftp: "quota exceeded" (SSH_FX_FAILURE)' }).result, RESULT.SERVER_NO_SPACE);
});

test('the file and the stated maximum always describe the SAME failure', () => {
  // Two files fail for two reasons in one run. Taking the name from the first failing line and the size from
  // anywhere in the output crosses them into a confident, specific, false sentence.
  const two = [
    'ERROR : notes.txt: Failed to copy: sftp: "upload failed: the SFTP staging buffer is full" (SSH_FX_FAILURE)',
    'ERROR : holiday.mov: Failed to copy: sftp: "upload rejected: file exceeds the 200 MB SFTP limit" (SSH_FX_FAILURE)',
  ].join('\n');
  const o = classifyBisyncOutcome({ code: 1, stderr: two });
  assert.strictEqual(o.result, RESULT.FILE_TOO_LARGE);
  assert.deepStrictEqual(o.detail, { file: 'holiday.mov', maxBytes: 200 * 1024 * 1024 }, 'the file that hit the limit, with that limit');
  assert.strictEqual(o.failedPath, 'holiday.mov', 'and the size is read from that same file');
});

test("rclone's temporary upload name never reaches a person, whatever its random token", () => {
  // The token is lowercase alphanumeric, not hex. A token left on the end of the name is an internal string
  // in front of a person, and it also makes the local size lookup miss the file entirely.
  for (const token of ['892c9efd', '0y2yl3wj', 'zzqq11aa']) {
    const o = classifyBisyncOutcome({ code: 1, stderr: `ERROR : big.bin.${token}.partial: partial file rename failed: Move Rename failed: file does not exist` });
    assert.strictEqual(o.detail.file, 'big.bin', `stripped for token ${token}`);
    assert.strictEqual(o.failedPath, 'big.bin');
    assertHuman(tray.itemForVault({ vault: 'v', reason: 'upload-not-stored', detail: o.detail }, named).label, `the sentence for token ${token}`);
  }
});

test('the resync latch never replaces a cause that already explains itself', () => {
  // A file the server would not take makes bisync abort and owe a resync — so the latch is set on exactly the
  // runs whose cause was just worked out. Answering those with a bare "needs a repair" puts the wrong
  // instruction in front of the person and throws away the sentence that says what to actually do.
  for (const result of ['file-too-large', 'server-no-space', 'upload-not-stored', 'vault-full']) {
    const v = statusModelVaultState({ vault: 'v', lastResult: result, resyncRequired: true, detail: { file: 'a.bin' } });
    assert.strictEqual(v.reason, OUTCOME_STATE[result].reason, `${result} keeps its own reason under the latch`);
    assert.strictEqual(v.state, STATE.NEEDS_DECISION, `${result} is lifted to the tier the repair belongs to`);
    // ...and the sentence then names the repair as the way back, instead of promising a retry that cannot happen.
    const label = tray.itemForVault(v, named).label;
    assertHuman(label, `the latched sentence for ${result}`);
    assert.match(label, /[Uu]se Repair in the DockVault tray menu/, `${result} says how to get syncing again`);
    assert.doesNotMatch(label, /will try again|will keep trying|Everything else keeps syncing/, `${result} promises no retry the latch has blocked`);
  }
  // A vault with a latch and NO cause of its own still reads as the plain repair.
  assert.strictEqual(statusModelVaultState({ vault: 'v', lastResult: null, resyncRequired: true }).reason, 'needs-repair');
  // And without a latch the sentences make their ordinary promises again.
  const free = tray.itemForVault(statusModelVaultState({ vault: 'v', lastResult: 'file-too-large', resyncRequired: false, detail: { file: 'a.bin' } }), named).label;
  assert.match(free, /Everything else keeps syncing/);
});

test('the named file survives the blocked ticks that follow the failure', () => {
  // The latch means the next tick is refused before it runs, and it re-records only "a repair is owed". If
  // that cleared the detail, the honest sentence would decay into its no-detail version a few minutes after
  // the failure — which is exactly when someone is likely to look.
  const hub = new SyncStatusHub({});
  hub.setVaults([V]);
  applySchedulerEvent(hub, V, { phase: 'done', outcome: { result: 'file-too-large', resyncRequired: true, detail: { file: 'holiday.mov', maxBytes: 5 * 1024 * 1024 } } });
  const first = tray.itemForVault(hub.current().vaults[0], { [V]: 'Photos' }).label;
  assert.match(first, /holiday\.mov/);
  applySchedulerEvent(hub, V, { phase: 'blocked', reason: 'needs-repair' });
  const later = hub.current().vaults[0];
  assert.strictEqual(later.reason, 'file-too-large', 'the cause still stands');
  assert.deepStrictEqual(later.detail, { file: 'holiday.mov', maxBytes: 5 * 1024 * 1024 }, 'and it still names the file');
  assert.strictEqual(tray.itemForVault(later, { [V]: 'Photos' }).label, first, 'the sentence does not decay');
});

test('the notification a person gets without opening anything says the same as the tray', () => {
  // The hub's must-act payload has to carry the detail, or the ONE message someone gets passively falls back
  // to a generic "something needs your attention" while every other surface names the real cause.
  const fired = [];
  const hub = new SyncStatusHub({ onNotify: (item) => fired.push(item) });
  hub.setVaults([V]);
  applySchedulerEvent(hub, V, { phase: 'done', outcome: { result: 'file-too-large', resyncRequired: true, detail: { file: 'holiday.mov', maxBytes: 5 * 1024 * 1024 } } });
  assert.strictEqual(fired.length, 1);
  assert.strictEqual(fired[0].reason, 'file-too-large');
  assert.deepStrictEqual(fired[0].detail, { file: 'holiday.mov', maxBytes: 5 * 1024 * 1024 });
  assert.strictEqual(fired[0].resyncRequired, true, 'including whether a repair is owed, so the body can say so');
});


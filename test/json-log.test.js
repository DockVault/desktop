'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { parseLogRecord, recordLine, recordSize, maskObjectIn, nameForms, isVerdictLevel, JSON_LOG_ARGS, MAX_MSG_CHARS } = require('../src/daemon/rclone-log');
const { StatsStderrParser, MAX_KEPT_STDERR_BYTES, MAX_FILE_PROGRESS } = require('../src/daemon/stats-parse');
const { classifyBisyncOutcome, classifyConnectionFailure, RESULT } = require('../src/daemon/bisync-outcome');
const { buildBisyncArgs, SYNC_LOG_ARGS } = require('../src/daemon/sync-engine');
const { spawnSync } = require('node:child_process');

// ---------------------------------------------------------------------------------------------------
// Real helper output. Every line below was RECORDED from the pinned helper (v1.75.0) run with the flag,
// against real folders — a real >50%-delete abort, a real all-changed abort, a real missing baseline, a
// real refused door, a real failed rename, a real keep-both conflict. Paths are shortened; nothing else
// is edited. The point of recording rather than inventing them is that the format moved things: the
// delete abort logs "Safety abort" as the SUBJECT and "too many deletes …" as the message, so a
// signature written against the rendered sentence would silently stop recognising a real abort.
// ---------------------------------------------------------------------------------------------------
const REAL = Object.freeze({
  excessiveDelete: [
    '{"time":"t","level":"error","msg":"too many deletes (>50%, 9 of 10) on Path1 \\"C:\\\\p1\\\\\\". Run with --force if desired.","object":"Safety abort","objectType":"string","source":"bisync/deltas.go:557"}',
    '{"time":"t","level":"notice","msg":"\\u001b[31mBisync aborted. Please try again.\\u001b[0m","source":"bisync/operations.go:215"}',
    '{"time":"t","level":"notice","msg":"Failed to bisync: too many deletes","source":"cmd/cmd.go:334"}',
  ],
  allChanged: [
    '{"time":"t","level":"error","msg":"Safety abort: all files were changed on Path1 \\"C:\\\\p1\\\\\\". Run with --force if desired.","source":"bisync/operations.go:360"}',
    '{"time":"t","level":"notice","msg":"Failed to bisync: all files were changed","source":"cmd/cmd.go:334"}',
  ],
  needsResync: [
    '{"time":"t","level":"error","msg":"\\u001b[31mBisync critical error: cannot find prior Path1 or Path2 listings, likely due to critical error on prior run \\n\\u001b[35mTip: here are the filenames we were looking for.\\u001b[0m","source":"bisync/operations.go:209"}',
    '{"time":"t","level":"error","msg":"\\u001b[31mBisync aborted. Must run --resync to recover.\\u001b[0m","source":"bisync/operations.go:210"}',
  ],
  connectFailed: ['{"time":"t","level":"critical","msg":"Failed to create file system for \\"vault:V\\": NewFs: couldn\'t connect SSH: dial tcp 198.51.100.7:22: connectex: No connection could be made because the target machine actively refused it.","source":"cmd/cmd.go:102"}'],
  hostKeyMismatch: ['{"time":"t","level":"critical","msg":"Failed to create file system for \\"vault:V\\": NewFs: couldn\'t connect SSH: ssh: handshake failed: knownhosts: key mismatch","source":"cmd/cmd.go:102"}'],
  channelRefused: ['{"time":"t","level":"critical","msg":"Failed to create file system for \\"vault:V\\": NewFs: couldn\'t connect SSH: ssh: rejected: administratively prohibited (open failed)","source":"cmd/cmd.go:102"}'],
  authFailed: ['{"time":"t","level":"critical","msg":"Failed to create file system for \\"vault:V\\": NewFs: couldn\'t connect SSH: ssh: handshake failed: ssh: unable to authenticate, attempted methods [none password], no supported methods remain","source":"cmd/cmd.go:102"}'],
  // A failed upload, exactly as recorded: the message names the temporary file AND the final one, and the
  // record's subject is the temporary one. Both are the same name, so both must come out of the message.
  uploadNotStored: [
    '{"time":"t","level":"error","msg":"partial file rename failed: rename \\\\\\\\?\\\\C:\\\\d\\\\holiday.bin.acae40b2.partial \\\\\\\\?\\\\C:\\\\d\\\\holiday.bin: Access is denied.","object":"holiday.bin.acae40b2.partial","objectType":"*local.Object","source":"operations/copy.go:367"}',
    '{"time":"t","level":"error","msg":"Attempt 1/1 failed with 1 errors and: rename \\\\\\\\?\\\\C:\\\\d\\\\holiday.bin.acae40b2.partial \\\\\\\\?\\\\C:\\\\d\\\\holiday.bin: Access is denied.","source":"cmd/cmd.go:283"}',
  ],
  conflict: ['{"time":"t","level":"notice","msg":"- \\u001b[36mPath1\\u001b[0m    \\u001b[35mRenaming Path1 copy\\u001b[0m   - \\u001b[36mC:\\\\p1\\\\f1.txt.conflict1\\u001b[0m","source":"bisync/resolve.go:318"}'],
  // A completed run, with the progress record the helper emits every stats period.
  green: ['{"time":"t","level":"info","msg":"\\u001b[32mBisync successful\\u001b[0m","source":"bisync/operations.go:218"}'],
});

// Feed raw bytes through the SAME path the runner uses — the parser, then the classifier — so these tests
// exercise the real wiring rather than hand-built records.
function run(lines, code, extra = {}) {
  const p = new StatsStderrParser();
  p.push(lines.join('\n') + '\n');
  p.end();
  return classifyBisyncOutcome({ code, stdout: '', stderr: p.stderr(), records: p.records(), ...extra });
}
const jsonLine = (o) => JSON.stringify({ time: 't', source: 's.go:1', ...o });

test('the run is asked for the structured format, and by the same constant the reader is built around', () => {
  assert.deepStrictEqual(JSON_LOG_ARGS, ['--use-json-log']);
  assert.ok(SYNC_LOG_ARGS.includes('--use-json-log'), 'the log flags carry it');
  assert.ok(buildBisyncArgs({ local: '/l', remote: 'vault:V', workdir: '/w' }).includes('--use-json-log'), 'and so does the sync run');
});

test('every outcome the app names still classifies, from real recorded output in the new format', () => {
  const expected = {
    excessiveDelete: [1, RESULT.ABORT_EXCESSIVE_DELETE, true],
    allChanged: [1, RESULT.ABORT_ALL_CHANGED, true],
    needsResync: [1, RESULT.NEEDS_RESYNC, true],
    connectFailed: [1, RESULT.CONNECT_FAILED, null],
    hostKeyMismatch: [1, RESULT.HOST_KEY_MISMATCH, null],
    channelRefused: [1, RESULT.CHANNEL_REFUSED, null],
    authFailed: [1, RESULT.AUTH_FAILED, null],
    uploadNotStored: [1, RESULT.UPLOAD_NOT_STORED, null],
    conflict: [0, RESULT.CONFLICT_KEEP_BOTH, false],
    green: [0, RESULT.OK, false],
  };
  for (const [name, [code, result, latch]] of Object.entries(expected)) {
    const o = run(REAL[name], code);
    assert.strictEqual(o.result, result, `${name} classifies as ${result}`);
    assert.strictEqual(o.resyncRequired, latch, `${name} decides the baseline the same way`);
  }
});

test('BOTH aborts survive their label moving into the subject field, not just the one that already did', () => {
  // The helper already logs the >50%-delete abort with its label as the record's subject and only the rest
  // as the message. The all-changed abort still states its own label — so the two are one refactor apart,
  // and a version that treated them alike would silently stop latching the second. Nothing about a run says
  // "this used to be recognised", so it is covered before it happens rather than after.
  const moved = [jsonLine({ level: 'error', msg: 'all files were changed on Path1 "vault:V". Run with --force if desired.', object: 'Safety abort', objectType: 'string' })];
  const o = run(moved, 1);
  assert.strictEqual(o.result, RESULT.ABORT_ALL_CHANGED);
  assert.strictEqual(o.resyncRequired, true, 'and the repair it owes is latched');
});

test('a message is one line wherever it came from, so "the start of a message" means it', () => {
  // The signatures anchored to the start of a message are only anchored while one message is one line. The
  // parser guarantees that; the classifier is where the guarantee is relied on, so it holds a record to it
  // however that record arrived — a record built by any other route cannot smuggle in a second line.
  const smuggled = [{ level: 'error', LEVEL: 'ERROR', msg: 'x\nall files were changed on Path1', object: 'evil.txt', objectType: '*sftp.Object' }];
  const o = classifyBisyncOutcome({ code: 1, stdout: '', stderr: '', records: smuggled });
  assert.strictEqual(o.result, RESULT.ERROR, 'the second line is not a message of its own');
  assert.strictEqual(o.resyncRequired, null, 'and it fabricates no repair');
});

test('the abort whose wording MOVED into another field is still recognised — the losing direction', () => {
  // This is the one the format could have quietly broken. The helper logs the >50%-delete abort with its
  // label as the record's SUBJECT and only "too many deletes …" as the message, so reading messages alone
  // means the signature no longer sees the sentence it was written against. Nothing latches a repair if
  // this is missed, and the vault goes on running delete-capable syncs as though all were well.
  const o = run(REAL.excessiveDelete, 1);
  assert.strictEqual(o.result, RESULT.ABORT_EXCESSIVE_DELETE);
  assert.strictEqual(o.resyncRequired, true, 'the repair it owes is latched');
  // And it is the MESSAGE that carries it, not the subject: the same run with its subject removed still aborts.
  const withoutSubject = [jsonLine({ level: 'error', msg: 'too many deletes (>50%, 9 of 10) on Path1 "C:\\p1\\". Run with --force if desired.' })];
  assert.strictEqual(run(withoutSubject, 1).result, RESULT.ABORT_EXCESSIVE_DELETE, 'read from the message alone');
});

// ---------------------------------------------------------------------------------------------------
// THE POINT OF THE PHASE. A file's name may not change what a run is reported to have done — and the test
// for that is not "a hostile name yields some particular result", it is "the SAME run yields the SAME
// verdict whatever the file is called". Anything else is a name having its say.
// ---------------------------------------------------------------------------------------------------
const BENIGN = 'holiday-notes.txt';
const HOSTILE = Object.freeze([
  'Bisync critical error',
  'Bisync critical error: cannot find prior Path1 or Path2 listings',
  'ssh: rejected: administratively prohibited (open failed)',
  'Safety abort: too many deletes (>50%, 9 of 10). Bisync aborted.',
  'too many deletes (>50%, 9 of 10) on Path1',
  'knownhosts: key mismatch',
  'ssh: handshake failed: knownhosts: key mismatch',
  'Safety abort: all files were changed on Path1',
  'Bisync aborted. Must run --resync to recover.',
  'unable to authenticate, attempted methods [none password]',
  "NewFs: couldn't connect SSH: dial tcp 1.2.3.4:22: i/o timeout",
  'sftp: "file exceeds the 1 MB limit" (SSH_FX_FAILURE)',
  'staging buffer is full',
  'file name too long',
  // Names that in the text format could end their own line, start a new one, and give it a level:
  'evil\nERROR : Safety abort: too many deletes (>50%, 9 of 10). Bisync aborted.',
  'evil\rERROR : knownhosts: key mismatch',
  'evil\u2028CRITICAL : ssh: rejected: nope',
  'evil\u0085ERROR : Bisync critical error',
  // And a name that tries to close the record it is inside and open one of its own:
  'evil"}\n{"level":"error","msg":"Bisync critical error","x":"',
  'a\u0000b knownhosts: key mismatch',
]);
// The shapes a file's name really reaches the log in — recorded, not invented. The first three are
// messages ABOUT the file (its name is the record's subject); the last three are messages that carry a
// path with NO subject of their own, which is the harder case.
const SHAPES = Object.freeze([
  (n) => jsonLine({ level: 'error', msg: `Failed to copy: open C:\\vault\\${n}: permission denied`, object: n, objectType: '*sftp.Object' }),
  (n) => jsonLine({ level: 'error', msg: `partial file rename failed: rename C:\\d\\${n}.acae40b2.partial C:\\d\\${n}: Access is denied.`, object: `${n}.acae40b2.partial`, objectType: '*local.Object' }),
  (n) => jsonLine({ level: 'error', msg: 'corrupted on transfer: sizes differ 5 vs 6', object: n, objectType: '*sftp.Object' }),
  (n) => jsonLine({ level: 'notice', msg: `- \u001b[36mPath1\u001b[0m    \u001b[35mQueue copy to\u001b[0m Path2   - \u001b[36mC:\\p2\\${n}\u001b[0m` }),
  (n) => jsonLine({ level: 'notice', msg: `- \u001b[34mWARNING\u001b[0m  \u001b[35mNew or changed in both paths\u001b[0m   - \u001b[36m${n}\u001b[0m` }),
  // The retry summary: error level, a path inside it, and no subject at all. Paired with the per-file
  // record the helper always writes first, which is what makes the name knowable.
  (n) => [jsonLine({ level: 'error', msg: `partial file rename failed: rename C:\\d\\${n}.acae40b2.partial C:\\d\\${n}: denied`, object: `${n}.acae40b2.partial`, objectType: '*local.Object' }),
    jsonLine({ level: 'error', msg: `Attempt 1/1 failed with 1 errors and: rename C:\\d\\${n}: denied` })].join('\n'),
]);

test('NO file name can change what a run is reported to have done — the same run, any name, one verdict', () => {
  let compared = 0;
  for (const shape of SHAPES) {
    for (const code of [0, 1]) {
      const benign = run([shape(BENIGN)], code);
      const base = { result: benign.result, resyncRequired: benign.resyncRequired, needsAttention: benign.needsAttention, maxBytes: benign.detail ? benign.detail.maxBytes : null };
      for (const name of HOSTILE) {
        const o = run([shape(name)], code);
        compared += 1;
        assert.deepStrictEqual(
          { result: o.result, resyncRequired: o.resyncRequired, needsAttention: o.needsAttention, maxBytes: o.detail ? o.detail.maxBytes : null },
          base,
          `a file called ${JSON.stringify(name)} changed the verdict (exit ${code})`,
        );
      }
    }
  }
  assert.ok(compared >= 240, `swept every name against every shape (${compared} comparisons)`);
});

// The exact records the pinned helper wrote when a file named "host key has changed " (one trailing space)
// could not be opened mid-run. Recorded, not invented — this shape is what a failed run really looks like,
// and it is where a name could still speak for the run: the helper restates the cause in a message of its
// own, at error level, with NO subject, the whole path inside the sentence. Note also that the name is
// PRINTED differently from how it is REPORTED (a trailing space becomes U+2420), so removing one by matching
// the other finds nothing — both halves of this had to be answered.
const REAL_WRAPPED = (name, printed) => [
  jsonLine({ level: 'error', msg: `Failed to copy: failed to open source object: GetFileAttributesEx \\\\?\\C:\\p1\\${printed}: The system cannot find the file specified.`, object: name, objectType: '*local.Object' }),
  jsonLine({ level: 'error', msg: `\u001b[31mBisync critical error: failed to open source object: GetFileAttributesEx \\\\?\\C:\\p1\\${printed}: The system cannot find the file specified.\u001b[0m` }),
  jsonLine({ level: 'error', msg: '\u001b[31mBisync aborted. Must run --resync to recover.\u001b[0m' }),
  jsonLine({ level: 'notice', msg: 'Failed to bisync with 2 errors: last error was: bisync aborted' }),
];

test('the message the helper writes ABOUT a failure names a file, and that name still says nothing', () => {
  // The benign run: a lost baseline, and the repair it owes is latched.
  const benign = run(REAL_WRAPPED('ordinary notes ', 'ordinary notes\u2420'), 7);
  assert.strictEqual(benign.result, RESULT.NEEDS_RESYNC);
  assert.strictEqual(benign.resyncRequired, true, 'the repair the run owes');
  // The same run, the same exit, the same everything — one file renamed. It must read identically. Before
  // the wrapper was cut to the tool's own words, each of these took the run's verdict AND its repair latch.
  // Two ways a name really reaches that message. A local file whose name ends in a space is PRINTED with
  // that space encoded, so it is spelled one way in the field and another in the sentence. A name from the
  // vault side, where the character is legal, is printed exactly as it was reported.
  const cases = [
    ...['host key has changed ', 'no such host ', 'unable to authenticate ', 'exceeds the 999 MB limit ',
      'staging buffer is full ', 'partial file rename failed ', 'path too long ',
    ].map((n) => [n, `${n.slice(0, -1)}\u2420`]),
    ...['ssh: rejected: nope', 'knownhosts: key mismatch', 'Bisync critical error', 'Safety abort: too many deletes',
    ].map((n) => [n, n]),
  ];
  for (const [name, printed] of cases) {
    const o = run(REAL_WRAPPED(name, printed), 7);
    assert.strictEqual(o.result, RESULT.NEEDS_RESYNC, `a file called ${JSON.stringify(name)} took the verdict`);
    assert.strictEqual(o.resyncRequired, true, `... and with it the repair the run owed: ${JSON.stringify(name)}`);
  }
});

test('a name is taken out of its own message however the helper spelled it there', () => {
  // The helper reports a name one way and prints it another: a trailing space is printed as U+2420, and the
  // characters a filesystem cannot hold are printed full-width. Matching only what was reported found none
  // of it, and a name ending in a space kept every word it spelled.
  const rec = parseLogRecord(jsonLine({
    level: 'error', object: 'no such host ', objectType: '*local.Object',
    msg: 'Failed to copy: failed to open source object: GetFileAttributesEx C:/p1/no such host\u2420: not found',
  }));
  assert.ok(!/no such host/.test(rec.msg), `the printed form is taken out too: ${rec.msg}`);
  assert.strictEqual(run([jsonLine({ level: 'error', object: 'no such host ', objectType: '*local.Object', msg: 'Failed to copy: failed to open source object: GetFileAttributesEx C:/p1/no such host\u2420: not found' })], 1).result, RESULT.ERROR);
});

test('KNOWN RESIDUAL: a message with no subject that is not one of the helper\'s own wrappers', () => {
  // Where this stops. A verdict is read from a message, and the helper writes two messages that carry a
  // path with no file attached to them — both are wrappers around a cause, so both are cut to the words the
  // helper itself wrote. Every message the pinned helper emits was read to find them.
  //
  // A future version could add a third. If it did, a name inside it could once more supply a verdict, and
  // this is what that would look like. It is pinned rather than buried so the shape is visible, and the
  // direction is the recoverable one: such a message asks for attention it did not earn; it cannot silence
  // an abort, because both aborts are read from the START of a message, where no name can be.
  const invented = jsonLine({ level: 'error', msg: 'Failed to finalise transfer of C:/vault/ssh: rejected: nope.txt: giving up' });
  assert.strictEqual(run([invented], 1).result, RESULT.CHANNEL_REFUSED, 'the residual, stated plainly');
  // What holds regardless: it can never take a repair the run owed, nor silence a real abort.
  const withAbort = run([invented, ...REAL.excessiveDelete], 1);
  assert.strictEqual(withAbort.resyncRequired, true, 'a real abort is never silenced by it');
  assert.strictEqual(withAbort.result, RESULT.ABORT_EXCESSIVE_DELETE, 'and the abort still outranks it');
});

// Every name class that has, at some point in getting here, silenced a verdict: names equal to a phrase of
// the verdict itself; the "Bisync"-substring case, which is not an attack at all but an ordinary folder
// called "sync"; and the reported-vs-printed case, where the helper writes a trailing space, a trailing
// period, or a reserved character one way in the field and another in the sentence.
const EVERY_NAME_THAT_HAS_BROKEN_THIS = Object.freeze([
  'too many deletes', 'all files were changed', 'Safety abort', 'max delete limit',
  'Bisync critical error', 'Bisync aborted. Must run --resync to recover.', 'cannot find prior Path1',
  'sync', 'sync notes', 'my sync folder',
  'too many deletes ', 'all files were changed ', 'Safety abort ', 'sync ', 'notes.',
  'knownhosts: key mismatch', 'ssh: rejected: nope', 'no such host ',
  'evil"}\n{"level":"error","msg":"ok","x":"',
]);
// The helper's own encoder, as it prints a name it cannot write verbatim.
const asPrinted = (n) => n.replace(/ $/, '\u2420').replace(/\.$/, '\uff0e')
  .replace(/[*<>:"?|]/g, (c) => ({ '*': '\uff0a', '<': '\uff1c', '>': '\uff1e', ':': '\uff1a', '"': '\uff02', '?': '\uff1f', '|': '\uff5c' }[c]));
// The four record shapes a failing file really produces, including the one whose subject is the SYNCED
// FOLDER itself — which is how an ordinary folder named "sync" got a say in the first place.
const FAILING_FILE_SHAPES = Object.freeze([
  (n) => [jsonLine({ level: 'error', msg: 'corrupted on transfer: sizes differ 5 vs 6', object: n, objectType: '*sftp.Object' })],
  (n) => [jsonLine({ level: 'error', msg: `Failed to copy: failed to open source object: GetFileAttributesEx C:\\p1\\${asPrinted(n)}: not found`, object: n, objectType: '*local.Object' }),
    jsonLine({ level: 'error', msg: `Bisync critical error: failed to open source object: GetFileAttributesEx C:\\p1\\${asPrinted(n)}: not found` })],
  (n) => [jsonLine({ level: 'error', msg: `Attempt 1/1 failed with 1 errors and: C:\\p1\\${asPrinted(n)}: not found` })],
  (n) => [jsonLine({ level: 'error', msg: 'not deleting files as there were IO errors', object: `Local file system at //?/C:/vault/${n}`, objectType: '*local.Fs' })],
]);

test('NO name, of any class that has ever broken this, can silence a real safety abort or drop its latch', () => {
  // The direction that must never fail. A run that aborted on a mass delete, or on every file of one side
  // reading as changed, holds the vault until a person deliberately repairs it — and if that is lost,
  // nothing latches and the vault goes on running delete-capable syncs as though all were well.
  //
  // Swept against both aborts, every name class, every shape a failing file really takes, and BOTH orderings
  // (the decoy before the abort and after it), because the order of records is not ours to choose.
  let checked = 0;
  for (const [abort, want] of [[REAL.excessiveDelete, RESULT.ABORT_EXCESSIVE_DELETE], [REAL.allChanged, RESULT.ABORT_ALL_CHANGED]]) {
    for (const name of EVERY_NAME_THAT_HAS_BROKEN_THIS) {
      for (const shape of FAILING_FILE_SHAPES) {
        for (const decoyFirst of [true, false]) {
          const lines = decoyFirst ? [...shape(name), ...abort] : [...abort, ...shape(name)];
          const o = run(lines, 1);
          checked += 1;
          assert.strictEqual(o.result, want, `a file called ${JSON.stringify(name)} silenced the abort (shape ${FAILING_FILE_SHAPES.indexOf(shape)}, decoyFirst=${decoyFirst})`);
          assert.strictEqual(o.resyncRequired, true, `... or dropped the repair it owed: ${JSON.stringify(name)}`);
        }
      }
    }
  }
  assert.ok(checked >= 300, `swept every combination (${checked})`);
});

test('taking names out never takes a SAFETY ABORT with them — the direction that must not fail', () => {
  // A file named after the words an abort uses would otherwise be removed from the abort's own message,
  // and nothing would latch the repair. A genuine abort keeps every word, whatever the run's files are
  // called; only the naming of a cause may ever be lost to this, never a verdict that latches.
  for (const named of ['too many deletes', 'all files were changed', 'Safety abort']) {
    const decoy = jsonLine({ level: 'error', msg: 'corrupted on transfer: sizes differ 5 vs 6', object: named, objectType: '*sftp.Object' });
    const del = run([decoy, ...REAL.excessiveDelete], 1);
    assert.strictEqual(del.result, RESULT.ABORT_EXCESSIVE_DELETE, `a file called "${named}" cannot silence a real >50%-delete abort`);
    assert.strictEqual(del.resyncRequired, true, 'and the repair it owes is latched');
    const all = run([decoy, ...REAL.allChanged], 1);
    assert.strictEqual(all.result, RESULT.ABORT_ALL_CHANGED, `nor a real all-changed abort: "${named}"`);
    assert.strictEqual(all.resyncRequired, true);
  }
});

test('a name cannot end a line, start one, or forge a record of its own', () => {
  // In the text format this was the residual that could not be closed: a name containing a newline
  // genuinely starts a line, and its author writes every character of it, level included. Here the name
  // is inside a string the helper escapes, so the whole class is gone rather than narrowed.
  for (const name of ['x\nERROR : Bisync critical error', 'x"}\n{"level":"error","msg":"Safety abort: all files were changed on Path1"']) {
    const p = new StatsStderrParser();
    p.push(jsonLine({ level: 'error', msg: 'corrupted on transfer: sizes differ 5 vs 6', object: name, objectType: '*sftp.Object' }) + '\n');
    p.end();
    assert.strictEqual(p.records().length, 1, `one name is one record, whatever it contains: ${JSON.stringify(name)}`);
    const o = classifyBisyncOutcome({ code: 1, stderr: p.stderr(), records: p.records() });
    assert.strictEqual(o.result, RESULT.ERROR);
    assert.strictEqual(o.resyncRequired, null, 'and it fabricates no repair');
  }
});

test("the changed-server alarm is raised only by the run speaking about itself, never by a message about a file", () => {
  // The loudest thing the app can say: syncing stops for EVERY vault until a person clears it. A genuine
  // key change is met when the connection is built, with no file in hand — so a message ABOUT a file may
  // never raise it. One that only surfaces mid-transfer still stops the run as a connection failure, and
  // the next run meets the same door and names it properly.
  const aboutAFile = [jsonLine({ level: 'error', msg: "Failed to copy: NewFs: couldn't connect SSH: ssh: handshake failed: knownhosts: key mismatch", object: 'notes.txt', objectType: '*sftp.Object' })];
  const o = run(aboutAFile, 1);
  assert.notStrictEqual(o.result, RESULT.HOST_KEY_MISMATCH, 'a file-level message never raises the alarm');
  assert.strictEqual(o.result, RESULT.CONNECT_FAILED, 'it is still an honest connection failure, not a bare error');
  // And the door's own refusal still raises it, from the same reading.
  assert.strictEqual(run(REAL.hostKeyMismatch, 1).result, RESULT.HOST_KEY_MISMATCH);
});

test('the connection verdict of any helper run reads the same way (the repair path uses it before a resync)', () => {
  const p = new StatsStderrParser();
  p.push(REAL.hostKeyMismatch.join('\n') + '\n');
  p.end();
  assert.strictEqual(classifyConnectionFailure('', p.stderr(), p.records()), RESULT.HOST_KEY_MISMATCH);
  // The server's file LISTING is stdout, one name per line, every one chosen by whoever can add a file.
  // It gets no vote — the same rule as before, now with the records too (which come from stderr anyway).
  const listing = 'knownhosts: key mismatch\nssh: rejected: nope\n';
  assert.strictEqual(classifyConnectionFailure(listing, '', []), null, 'a listing decides nothing about the connection');
});

test('the file a person is told about comes from the record that named it, not from re-reading a sentence', () => {
  const o = run(REAL.uploadNotStored, 1);
  assert.strictEqual(o.detail.file, 'holiday.bin', "the helper's own field, with its temporary suffix removed");
  assert.strictEqual(o.failedPath, 'holiday.bin', 'and the path the engine looks the size up by');
  // A decoy record sitting ABOVE the real failure cannot be named in its place: the name comes from the
  // record that DECIDED the outcome, and the decoy decided nothing.
  const decoy = jsonLine({ level: 'error', msg: 'corrupted on transfer: sizes differ 5 vs 6', object: 'shared/decoy.txt', objectType: '*sftp.Object' });
  const p = run([decoy, ...REAL.uploadNotStored], 1);
  assert.strictEqual(p.detail.file, 'holiday.bin', 'the file the run actually failed on');
  // The same for a stated limit: the number quoted comes from the failure that was classified, and a name
  // that spells a limit out cannot supply one, because it is taken out of the message before it is read.
  const named = jsonLine({ level: 'error', msg: 'Failed to copy: sftp: "file exceeds the 25 MB per-file limit" (SSH_FX_FAILURE)', object: 'big.bin', objectType: '*sftp.Object' });
  const spelled = jsonLine({ level: 'error', msg: 'Failed to copy: sftp: "..." (SSH_FX_FAILURE)', object: 'exceeds the 1 MB limit.txt', objectType: '*sftp.Object' });
  const q = run([spelled, named], 1);
  assert.strictEqual(q.result, RESULT.FILE_TOO_LARGE);
  assert.strictEqual(q.detail.maxBytes, 25 * 1024 * 1024, 'the limit the SERVER stated, not the one a name spelled out');
  assert.strictEqual(q.detail.file, 'big.bin');
});

test('a name that is not showable is dropped rather than rendered, and a path that is not plain is refused', () => {
  const nasty = jsonLine({ level: 'error', msg: 'partial file rename failed: Move Rename failed: file does not exist', object: 'C:\\somewhere\\else.bin', objectType: '*sftp.Object' });
  const o = run([nasty], 1);
  assert.strictEqual(o.result, RESULT.UPLOAD_NOT_STORED);
  assert.strictEqual(o.failedPath, null, 'an absolute path is never joined to the local folder');
  const traversal = jsonLine({ level: 'error', msg: 'partial file rename failed: Move Rename failed: file does not exist', object: '../../etc/passwd', objectType: '*sftp.Object' });
  assert.strictEqual(run([traversal], 1).failedPath, null, 'nor is a traversal');
  const control = jsonLine({ level: 'error', msg: 'partial file rename failed: Move Rename failed: file does not exist', object: 'a\u202eb.txt', objectType: '*sftp.Object' });
  const c = run([control], 1);
  assert.strictEqual(c.detail && c.detail.file, null, 'a name that reverses the text around it is never shown');
});

// ---------------------------------------------------------------------------------------------------
// The B1 invariants this change had to carry through untouched.
// ---------------------------------------------------------------------------------------------------
test('progress stays INTEGERS ONLY: no name, no path, nothing but numbers leaves the parser', () => {
  const p = new StatsStderrParser();
  // A real stats record: the numbers are fields, and the message RENDERS the block with the in-flight
  // file's path in it. Both the message and the in-flight entries' name/srcFs/dstFs must die here.
  p.push(jsonLine({
    level: 'notice',
    msg: '\nTransferred:   \t    1.027 MiB / 200.000 MiB, 1%, 0 B/s, ETA -\nTransferring:\n *              secret/holiday plans.bin:  3% / 200 MiB, 0 B/s, -\n\n',
    stats: { bytes: 1077260, totalBytes: 209715212, transfers: 2, totalTransfers: 3, transferring: [{ name: 'secret/holiday plans.bin', percentage: 3, size: 209715200, srcFs: 'C:/private/folder', dstFs: 'vault:V' }] },
  }) + '\n');
  p.end();
  const counts = p.counts();
  assert.deepStrictEqual(counts, { files: 2, filesTotal: 3, bytes: 1077260, bytesTotal: 209715212, percent: 1, transferring: 1, fileProgress: [3] });
  // Every value that leaves is a number or null — asserted structurally, not by spot-checking fields.
  for (const [k, v] of Object.entries(counts)) {
    const values = Array.isArray(v) ? v : [v];
    for (const n of values) assert.ok(n === null || Number.isInteger(n), `${k} carries integers only, got ${JSON.stringify(n)}`);
  }
  // And nothing of the block survives anywhere else.
  const everywhere = JSON.stringify(p.records()) + p.stderr();
  for (const leak of ['holiday plans', 'private/folder', 'Transferring', 'secret']) {
    assert.ok(!everywhere.includes(leak), `no trace of ${leak} is retained`);
  }
});

test('the in-flight list is bounded, and the count of files in flight stays exact past the bound', () => {
  const many = Array.from({ length: MAX_FILE_PROGRESS + 20 }, (_, i) => ({ name: `f${i}.bin`, percentage: i % 100 }));
  const p = new StatsStderrParser();
  p.push(jsonLine({ level: 'notice', msg: 'stats', stats: { bytes: 1, totalBytes: 2, transferring: many } }) + '\n');
  p.end();
  const c = p.counts();
  assert.strictEqual(c.fileProgress.length, MAX_FILE_PROGRESS, 'the percentages carried are bounded');
  assert.strictEqual(c.transferring, many.length, 'the COUNT is still exact');
});

test('what is retained for the classifier stays bounded, and says so when it drops anything', () => {
  const p = new StatsStderrParser();
  const one = jsonLine({ level: 'error', msg: `x${'y'.repeat(400)}` });
  for (let i = 0; i < 4000; i += 1) p.push(`${one}\n`);
  p.end();
  const retained = p.records().reduce((n, r) => n + recordSize(r), 0) + p.stderr().length;
  assert.ok(retained <= MAX_KEPT_STDERR_BYTES, `retention is bounded (${retained} bytes for ~1.6 MB of output)`);
  assert.ok(p.truncated(), 'and a run that outgrew the budget says so rather than looking complete');
});

test("taking a name out of a message never takes that message's own safety abort with it", () => {
  // The tool logs the >50%-delete abort with its label as the record's SUBJECT. If a version were also to
  // repeat that label inside the message, removing the subject from its own message would delete the abort —
  // and nothing would latch the repair. Where removal would cost a message its abort, the message is left
  // exactly as written. This is the direction that must never fail, so it is guarded even though the pinned
  // helper does not write that shape today.
  for (const msg of ['Safety abort: too many deletes (>50%, 9 of 10) on Path1', 'Safety abort: all files were changed on Path1']) {
    const rec = parseLogRecord(jsonLine({ level: 'error', msg, object: 'Safety abort', objectType: 'string' }));
    assert.strictEqual(rec.msg, msg, 'the abort keeps every word');
  }
  // And the guard is not a licence to keep everything: an ordinary per-file message still loses its name.
  const ordinary = parseLogRecord(jsonLine({ level: 'error', msg: 'Failed to copy: open C:/v/notes.txt: denied', object: 'notes.txt', objectType: '*sftp.Object' }));
  assert.strictEqual(ordinary.msg, 'Failed to copy: open C:/v/<file>: denied');
});

test('the glance keeps moving while a run is listing and comparing, not only while bytes move', () => {
  // bisync spends its first minutes on a big vault listing and comparing, transferring nothing. The text
  // format reported every block, so "Syncing…" kept moving; reading only the transfer counters would leave
  // it frozen for those minutes and make a working run look hung.
  const p = new StatsStderrParser();
  const checking = (n) => jsonLine({ level: 'notice', msg: 'stats', stats: { bytes: 0, totalBytes: 0, transfers: 0, totalTransfers: 0, checks: n, totalChecks: 900, transferring: [] } });
  const advanced = [40, 80, 120].map((n) => p.push(`${checking(n)}\n`));
  assert.deepStrictEqual(advanced, [true, true, true], 'every block through the listing phase moves the glance');
  // ... and nothing about that phase reaches the feed except numbers that were already allowed.
  assert.deepStrictEqual(Object.keys(p.counts()).sort(), ['bytes', 'bytesTotal', 'fileProgress', 'files', 'filesTotal', 'percent', 'transferring']);
});

test('a bounded message stands alone: what is retained is what was charged', () => {
  // A message is cut to the bound, and a plain slice of a long string keeps the WHOLE of it alive behind the
  // part that was kept. The budget would then say a quarter of a megabyte and the daemon would be holding
  // sixteen. Measured in a child process, where a forced collection makes the answer real rather than noisy.
  const probe = `
    const { StatsStderrParser } = require(${JSON.stringify(require.resolve('../src/daemon/stats-parse'))});
    const p = new StatsStderrParser();
    for (let i = 0; i < 400; i += 1) p.push(JSON.stringify({ level: 'error', msg: 'x'.repeat(250 * 1024) }) + '\\n');
    p.end();
    const kept = p.records();
    global.gc(); global.gc();
    process.stdout.write(JSON.stringify({ records: kept.length, heldKiB: Math.round(process.memoryUsage().heapUsed / 1024) }));
  `;
  const r = spawnSync(process.execPath, ['--expose-gc', '-e', probe], { encoding: 'utf8' });
  assert.strictEqual(r.status, 0, r.stderr);
  const got = JSON.parse(r.stdout);
  assert.ok(got.records > 0, 'the run was retained at all');
  // A hundred megabytes of output. Held flat this is well under a megabyte of messages; held as slices of
  // their original lines it was sixteen. The bound is generous enough not to be about the collector.
  assert.ok(got.heldKiB < 6 * 1024, `the kept messages stand alone (held ${got.heldKiB} KiB)`);
});

test('one message cannot grow the haystack without bound', () => {
  const rec = parseLogRecord(jsonLine({ level: 'error', msg: 'Bisync critical error: ' + 'p'.repeat(MAX_MSG_CHARS * 4) }));
  assert.ok(rec.msg.length <= MAX_MSG_CHARS, 'a message is bounded');
  assert.ok(rec.msg.startsWith('Bisync critical error:'), 'and it is bounded from the END, where a verdict never is');
});

test('a helper that does not write the structured format still classifies exactly as it did', () => {
  // The text path is unchanged, so a version or a build without the flag degrades to today's behaviour
  // rather than to silence. (Its own defences — masking and line anchoring — are covered by their tests.)
  const text = 'ERROR : Safety abort: too many deletes (>50%, 3 of 4). Bisync aborted.\n';
  const p = new StatsStderrParser();
  p.push(text);
  p.end();
  assert.strictEqual(p.records().length, 0, 'nothing was structured');
  assert.strictEqual(p.stderr(), text, 'and the line is kept as it was written');
  const o = classifyBisyncOutcome({ code: 1, stderr: p.stderr(), records: p.records() });
  assert.strictEqual(o.result, RESULT.ABORT_EXCESSIVE_DELETE);
  assert.strictEqual(o.resyncRequired, true);
});

test('a run that mixes the two — some lines structured, some not — reads both and misses neither', () => {
  const p = new StatsStderrParser();
  p.push('panic: something the tool did not write through its logger\n');
  p.push(REAL.needsResync.join('\n') + '\n');
  p.end();
  assert.strictEqual(p.records().length, 2);
  assert.ok(p.stderr().includes('panic:'), 'the unstructured line is still kept');
  assert.strictEqual(classifyBisyncOutcome({ code: 1, stderr: p.stderr(), records: p.records() }).result, RESULT.NEEDS_RESYNC);
});

// ---------------------------------------------------------------------------------------------------
// The reader's own rules.
// ---------------------------------------------------------------------------------------------------
test('a message is the tool\'s words: colours stripped, breaks flattened, the file\'s own name taken out', () => {
  const rec = parseLogRecord(jsonLine({ level: 'error', msg: '\u001b[31mBisync critical error: x\u001b[0m\nTip: y', object: 'notes.txt', objectType: '*sftp.Object' }));
  assert.strictEqual(rec.msg, 'Bisync critical error: x Tip: y');
  assert.strictEqual(recordLine(rec), 'ERROR : Bisync critical error: x Tip: y', 'and it reads under its own level');
  assert.strictEqual(rec.object, 'notes.txt', 'the file it was about is kept apart, for naming it to a person');
});

test('a name is removed from its own message by exact match, including the form the tool derives', () => {
  const n = 'evil ssh: rejected: y.txt';
  assert.strictEqual(
    maskObjectIn(`partial file rename failed: rename C:/d/${n}.abc123.partial C:/d/${n}: denied`, `${n}.abc123.partial`),
    'partial file rename failed: rename C:/d/<file> C:/d/<file>: denied',
    'both the temporary name and the final one come out',
  );
  // A name too short to carry any phrase is left alone rather than shredding the message it rode in on.
  assert.strictEqual(maskObjectIn('a message about a.b', 'a.b'), 'a message about a.b');
  assert.deepStrictEqual(nameForms('ab'), [], 'nothing that short is masked');
  // And the tool's OWN words in that field never take a verdict out of a message.
  assert.strictEqual(maskObjectIn('too many deletes (>50%, 9 of 10)', 'Safety abort'), 'too many deletes (>50%, 9 of 10)');
});

test('only error and critical records may speak for the run', () => {
  assert.ok(isVerdictLevel(parseLogRecord(jsonLine({ level: 'error', msg: 'x' }))));
  assert.ok(isVerdictLevel(parseLogRecord(jsonLine({ level: 'critical', msg: 'x' }))));
  for (const level of ['notice', 'info', 'debug']) {
    assert.ok(!isVerdictLevel(parseLogRecord(jsonLine({ level, msg: 'x' }))), `${level} does not`);
  }
  assert.ok(!isVerdictLevel(parseLogRecord(jsonLine({ level: 'made-up', msg: 'x' }))), 'and neither does a level the tool does not write');
});

test('anything that is not a record is not read as one', () => {
  for (const line of ['', 'plain text', '{not json', '[1,2,3]', '{"level":"error"}', 'null', '{"msg":42}']) {
    assert.strictEqual(parseLogRecord(line), null, `not a record: ${JSON.stringify(line)}`);
  }
  assert.strictEqual(parseLogRecord(`{"level":"error","msg":"${'x'.repeat(300 * 1024)}"}`), null, 'nor is a line too long to be one');
});

test("KNOWN AND DELIBERATE: a file named like a kept-both copy is reported as one", () => {
  // A run that completed is checked for the helper's keep-both rename, and that is logged BELOW error level
  // (it is not a failure), so this one signature reads records the verdicts do not. A file named
  // "x.conflict1" therefore reports a keep-both that this run did not perform.
  //
  // Left as it is, on purpose. It is the mildest outcome there is — nothing latches, nothing alarms,
  // syncing continues — and narrowing it to the tool's exact rename wording would trade a cosmetic false
  // positive for a MISSED keep-both, where a person's edit sits in a second copy while the app says the
  // run was clean. Worth noting too: a file named that way IS an unresolved keep-both copy sitting in the
  // folder, so saying so is not obviously wrong.
  const named = jsonLine({ level: 'notice', msg: '- Path1    Queue copy to Path2   - C:\\p2\\notes.txt.conflict1' });
  assert.strictEqual(run([named], 0).result, RESULT.CONFLICT_KEEP_BOTH);
  // What DOES not reach it: a message about a file (its name is a field, taken out) and one of the
  // helper's own wrappers (cut to its opener). Only its path-echoing progress notices carry the name.
  assert.strictEqual(run([jsonLine({ level: 'error', msg: 'Failed to copy: C:/p2/a.conflict1: denied' })], 0).result, RESULT.OK);
  assert.strictEqual(run([jsonLine({ level: 'error', msg: 'corrupted on transfer: sizes differ 5 vs 6', object: 'a.conflict1', objectType: '*sftp.Object' })], 0).result, RESULT.OK);
  // What must hold regardless: it never latches a repair, and never raises the alarm.
  assert.strictEqual(run([named], 0).resyncRequired, false);
  const alarming = jsonLine({ level: 'notice', msg: '- Path1    Queue copy to Path2   - C:\\p2\\knownhosts: key mismatch.conflict1' });
  assert.notStrictEqual(run([alarming], 0).result, RESULT.HOST_KEY_MISMATCH);
  assert.notStrictEqual(run([alarming], 1).result, RESULT.HOST_KEY_MISMATCH);
});

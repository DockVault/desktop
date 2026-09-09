'use strict';

// The build date, checked by RUNNING the pipeline's own shell rather than by reading it.
//
// This file exists because of a specific failure and the specific test that let it through. The
// workflow took its date from `${{ github.run_started_at }}`, which is not a property of the `github`
// expression context — it exists only in the REST API's payload for a run. A GitHub expression naming
// something the context does not have is not an error; it renders as the empty string. So `built` was
// empty, the guard refused, and all three legs of a real "Build installers" dispatch failed.
//
// What the suite had at the time was `assert.match(yml, /STARTED: \$\{\{ github\.run_started_at \}\}/)`
// — an assertion that PINNED THE BROKEN EXPRESSION and passed. It could not have failed while the bug
// was present, because it checked that the file contained that text, which was exactly the defect. Two
// things follow, and they are what these tests are:
//
//   1. Asserting a value's SOURCE TEXT says nothing about whether the value arrives. So the date is
//      traced to a producer, and that producer is EXECUTED here and required to emit a real date.
//   2. Asserting the guard's source text says nothing about whether it refuses. So the guard's script
//      is lifted out of the YAML and RUN, against an empty date, a malformed one and a good one.
//
// Nothing here re-pins a string that a later edit would have to re-pin again. If the date's source
// changes shape these fail, and whoever changed it has to show the new source produces something.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const root = path.resolve(__dirname, '..');
const WORKFLOW = path.join(root, '.github', 'workflows', 'build-installers.yml');
const yml = fs.readFileSync(WORKFLOW, 'utf8');
const lines = yml.split(/\r?\n/);

const FULL = '3d6bcc8f0e1d2c3b4a5968778695a4b3c2d1e0f9';
const indentOf = (line) => line.length - line.trimStart().length;

// A block is a line and everything indented under it — enough structure for the two questions asked
// here. Every lookup below asserts it found what it went looking for, so a rename breaks these tests
// instead of quietly emptying them.
function blockAt(from, start) {
  assert.ok(start >= 0 && start < from.length, 'the block being read exists');
  const base = indentOf(from[start]);
  const out = [from[start]];
  for (let i = start + 1; i < from.length; i += 1) {
    if (from[i].trim() === '') { out.push(from[i]); continue; }
    if (indentOf(from[i]) <= base) break;
    out.push(from[i]);
  }
  return out;
}

function job(name) {
  const at = lines.findIndex((l) => new RegExp(`^  ${name}:\\s*$`).test(l));
  assert.notEqual(at, -1, `the workflow defines a job named ${name}`);
  return blockAt(lines, at);
}

function step(jobLines, name) {
  const at = jobLines.findIndex((l) => l.trim() === `- name: ${name}`);
  assert.notEqual(at, -1, `that job has a step named "${name}"`);
  return blockAt(jobLines, at);
}

// The step's `run:` body, dedented to what the runner would hand to the shell.
function runScript(stepLines) {
  const at = stepLines.findIndex((l) => /^\s*run: \|\s*$/.test(l));
  assert.notEqual(at, -1, 'that step runs a script');
  const body = blockAt(stepLines, at).slice(1);
  const filled = body.filter((l) => l.trim() !== '');
  assert.ok(filled.length > 0, 'the script is not empty');
  const pad = Math.min(...filled.map(indentOf));
  return body.map((l) => l.slice(pad)).join('\n');
}

// Every `run:` script in a job, concatenated. Used to ask what the LEGS execute, as opposed to what the
// job's YAML merely says — step names and comments are not instructions.
function runScriptsIn(jobLines) {
  const out = [];
  for (let i = 0; i < jobLines.length; i += 1) {
    if (/^\s*run: \|\s*$/.test(jobLines[i])) out.push(runScript(jobLines.slice(i)));
  }
  assert.ok(out.length > 0, 'that job runs at least one script');
  return out.join('\n');
}

// The step's `env:` mapping, values left as the raw expression text.
function stepEnv(stepLines) {
  const at = stepLines.findIndex((l) => /^\s*env:\s*$/.test(l));
  assert.notEqual(at, -1, 'that step declares an environment');
  const out = {};
  for (const l of blockAt(stepLines, at).slice(1)) {
    const m = l.match(/^\s*([A-Za-z_][A-Za-z0-9_]*):\s*(.*)$/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

// Run one of the workflow's own scripts the way the runner does: bash, with the three files a step
// writes to. The script is handed over as a FILE and bash is given an argument list, so nothing here
// goes through a shell command line. Expressions the runner would have substituted are named
// explicitly, so a NEW one appearing in a script fails this rather than being silently replaced by
// something meaningless.
function runStep(script, env, expressions = {}) {
  const found = new Set(script.match(/\$\{\{[^}]*\}\}/g) || []);
  assert.deepEqual([...found].sort(), Object.keys(expressions).sort(),
    'every workflow expression in this script is accounted for by the test');
  let text = script;
  for (const [expr, value] of Object.entries(expressions)) text = text.split(expr).join(value);

  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-step-'));
  try {
    const files = {
      GITHUB_ENV: path.join(dir, 'env'),
      GITHUB_OUTPUT: path.join(dir, 'output'),
      GITHUB_STEP_SUMMARY: path.join(dir, 'summary'),
    };
    for (const f of Object.values(files)) fs.writeFileSync(f, '');
    const file = path.join(dir, 'step.sh');
    fs.writeFileSync(file, text);
    const r = spawnSync('bash', [file], { encoding: 'utf8', env: { PATH: process.env.PATH, ...files, ...env } });
    assert.equal(r.error, undefined, 'bash is available to run the workflow script');
    const read = (f) => fs.readFileSync(f, 'utf8');
    return {
      status: r.status,
      stdout: `${r.stdout || ''}${r.stderr || ''}`,
      exported: read(files.GITHUB_ENV),
      outputs: read(files.GITHUB_OUTPUT),
      summary: read(files.GITHUB_STEP_SUMMARY),
    };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

const buildJob = job('build');
const stampStep = step(buildJob, 'Stamp this build with its commit and date');
const stampScript = runScript(stampStep);
const stampEnv = stepEnv(stampStep);

// The environment value the guard actually takes the date from. Read out of the script rather than
// assumed, so renaming it does not quietly point the rest of this file at nothing.
function dateVariable() {
  const assign = stampScript.match(/^\s*built=.*$/m);
  assert.ok(assign, 'the script assigns the date to `built`');
  const named = Object.keys(stampEnv).filter((k) => new RegExp(`\\$\\{?${k}\\b`).test(assign[0]));
  assert.equal(named.length, 1, `exactly one of the step's environment values feeds \`built\`: ${assign[0].trim()}`);
  return named[0];
}

const DATE_VAR = dateVariable();

// ---------------------------------------------------------------------------------------------
// 1. THE DATE HAS A PRODUCER, AND THE PRODUCER PRODUCES.
//
// This is the assertion the old one should have been. `${{ github.run_started_at }}` fails it — not
// because that string is blacklisted, but because nothing in the workflow writes it. A source that is
// merely NAMED cannot pass here; it has to be traced to a step, and that step has to run and emit.
// ---------------------------------------------------------------------------------------------

test('the date the installers are stamped with comes from something that really writes one', () => {
  const expr = stampEnv[DATE_VAR];
  const ref = expr.match(/^\$\{\{\s*needs\.([A-Za-z0-9_-]+)\.outputs\.([A-Za-z0-9_-]+)\s*\}\}$/);
  assert.ok(ref, `the date must come from another job's output, not a bare context property: got ${expr}`);
  const [, producerName, outputName] = ref;

  // The consuming job has to declare the dependency, or the output is empty at runtime.
  assert.match(buildJob.join('\n'), new RegExp(`^\\s*needs: .*\\b${producerName}\\b`, 'm'),
    `the build job declares needs: ${producerName}`);

  // That job has to publish the output, bound to a step of its own.
  const producer = job(producerName);
  const declared = producer.join('\n').match(
    new RegExp(`^\\s*${outputName}: \\$\\{\\{\\s*steps\\.([A-Za-z0-9_-]+)\\.outputs\\.([A-Za-z0-9_-]+)\\s*\\}\\}\\s*$`, 'm'));
  assert.ok(declared, `job ${producerName} publishes an output ${outputName} from one of its steps`);
  const [, stepId, key] = declared;

  // ONE machine, not several. Everything else here proves the producer PRODUCES; this is the only thing
  // that proves it produces once. Give this job a matrix and you get three runners reading three clocks
  // and a job output merged from whichever finished last — the exact harm the constraint exists to
  // prevent, reintroduced at the one place nothing else looks.
  assert.ok(!/^\s*strategy:/m.test(producer.join('\n')),
    `job ${producerName} must be a single machine reading the clock once, not a matrix`);

  const idAt = producer.findIndex((l) => new RegExp(`^\\s*id: ${stepId}\\s*$`).test(l));
  assert.notEqual(idAt, -1, `and a step with id ${stepId} exists`);

  // And now the part no amount of reading proves: RUN it, and require a real date out the other end.
  // Today is read either side of the run so that a step executing across midnight UTC cannot make this
  // flap — the window is "the day it started or the day it finished", which is still tight enough to
  // catch a source that is well-formed but wrong (an offset, a fixed string, a local-time clock).
  const utcToday = () => new Date().toISOString().slice(0, 10);
  const producerScript = runScript(blockAt(producer, idAt - 1));

  // This one claim is checked as SOURCE TEXT, and it is worth saying why rather than leaving it looking
  // like laziness: it cannot be established by running the step here. Git Bash on Windows ignores TZ,
  // so `date` and `date -u` return the same answer on the machine most likely to run this suite, and a
  // timezone-driven test would pass whether the workflow asked for UTC or not — green by construction,
  // which is the failure this whole file is a response to. So the weak instrument is used knowingly,
  // for the one thing the strong instrument cannot see, and the run below still proves the rest.
  //
  // COMMENTS STRIPPED FIRST, and that is not tidiness. Without it this assertion had already gone
  // vacuous once: a comment was added to the producer step that quoted `date -u +%F` in prose, so the
  // regex matched the comment, and swapping the real call to a local-time `date +%F` kept it green. A
  // source-text assertion has to be aimed at the source that RUNS.
  const producerCode = producerScript.split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  assert.match(producerCode, /\bdate\s+-u\b/, 'the single clock read asks for UTC, not the runner local time');

  const opened = utcToday();
  const out = runStep(producerScript, {});
  const closed = utcToday();
  assert.equal(out.status, 0, `the producing step succeeds: ${out.stdout}`);
  const wrote = out.outputs.match(new RegExp(`^${key}=(.*)$`, 'm'));
  assert.ok(wrote, `it writes ${key}= to $GITHUB_OUTPUT, got ${JSON.stringify(out.outputs)}`);
  // Separate claims, because "empty" is the one that actually shipped.
  assert.notEqual(wrote[1], '', 'what it writes is not the empty string');
  assert.match(wrote[1], /^\d{4}-\d{2}-\d{2}$/, 'and is shaped like a date');
  assert.ok([opened, closed].includes(wrote[1]),
    `and is TODAY in UTC, not merely date-shaped: got ${wrote[1]}, expected ${opened} or ${closed}`);
});

// The producer's own refusal, run rather than read. A clock read that FAILS does not make the step fail
// on its own — `set -e` does not see it when the call sits inside an echo's substitution, and there is no
// pipe for `pipefail` to catch — so the step would go green publishing an empty date and three legs would
// each spend minutes installing dependencies before refusing. This is the case that proves the check.
test('the producing step refuses when the clock cannot be read, rather than publishing nothing', () => {
  const producer = job('build_date');
  const idAt = producer.findIndex((l) => /^\s*id: [A-Za-z0-9_-]+\s*$/.test(l));
  assert.notEqual(idAt, -1, 'the producing step has an id');
  const script = runScript(blockAt(producer, idAt - 1));

  // A `date` that fails, ahead of the real one on PATH. Nothing else about the step changes.
  const bin = fs.mkdtempSync(path.join(os.tmpdir(), 'dv-noclock-'));
  try {
    fs.writeFileSync(path.join(bin, 'date'), '#!/bin/sh\nexit 1\n', { mode: 0o755 });
    const broken = runStep(script, { PATH: `${bin}${path.delimiter}${process.env.PATH}` });
    assert.notEqual(broken.status, 0, 'a clock that cannot be read must stop the build, not pass an empty date on');
    assert.ok(!/^date=\s*$/m.test(broken.outputs), 'and must not publish an empty date');
  } finally {
    fs.rmSync(bin, { recursive: true, force: true });
  }
});

test('one date for all three legs, so a run crossing midnight cannot ship two days', () => {
  // The legs must not read a clock of their own. Scoped to the build job: the producer is allowed to
  // read one, precisely because it is a single machine reading it once.
  //
  // Matching an INVOCATION (`date` followed by a flag or a +format) rather than the bare word, and this
  // shape was arrived at by getting it wrong twice. Forbidding `date -u` left the hole that matters —
  // a leg reading `date +%F`, local time, no -u, stamping every installer with its own runner's date —
  // and forbidding the word `date` outright fails on the step's own error message, which says "the build
  // date is not a date". So: only the leg's own scripts, only outside comments, and only where the word
  // is being CALLED. A bare `$(date)` would slip through and is left to the guard, which refuses it for
  // not being a date at all.
  const legScripts = runScriptsIn(buildJob)
    .split('\n').filter((l) => !l.trim().startsWith('#')).join('\n');
  assert.ok(!/\bdate\s+[-+]/.test(legScripts), 'no leg reads a clock of its own, in any form');
  // The value reaching them is one job output, so the three cannot receive different text.
  assert.match(stampEnv[DATE_VAR], /^\$\{\{\s*needs\./);
});

// ---------------------------------------------------------------------------------------------
// 2. THE GUARD REFUSES. Run, not read.
//
// The guard was never the bug — it did its job, which is why this was a failed run rather than a
// released installer whose About box says it carries no build. But it was only ever checked by matching
// its source text, so nothing knew whether it refused. Now it is asked.
// ---------------------------------------------------------------------------------------------

const asStamped = (env) => runStep(stampScript, env, { '${{ matrix.name }}': 'Windows' });

// A date that can NEVER be today. That is the whole requirement, and it is not fussiness: while this
// fixture read 2026-09-09 it was green on the day it was written, and a leg rewritten to stamp
// `$(date +%F)` — ignoring the value it was handed and reading its own clock — passed, because the
// script's output and the fixture were the same string for those twenty-four hours. A fixture that can
// equal `date +%F` cannot tell "echoed what it was given" from "echoed its own clock".
const GOOD_DATE = '2019-03-07';
const good = (over) => ({ COMMIT: FULL, [DATE_VAR]: GOOD_DATE, ...over });

test('the stamp step proceeds on a good commit and date, exporting both', () => {
  const r = asStamped(good());
  assert.equal(r.status, 0, `expected success, got ${r.status}: ${r.stdout}`);
  assert.match(r.exported, new RegExp(`^DOCKVAULT_BUILD_COMMIT=${FULL}$`, 'm'));
  assert.match(r.exported, new RegExp(`^DOCKVAULT_BUILD_DATE=${GOOD_DATE}$`, 'm'));
  assert.match(r.outputs, /^short=3d6bcc8$/m, 'the short commit the artifact is named with');
  assert.match(r.summary, /3d6bcc8/);
});

test('the stamp step refuses a date that did not arrive, or arrived malformed', () => {
  const refused = [
    ['empty — the failure that actually shipped', ''],
    ['whitespace, which an expression can also render', '   '],
    ['a timestamp rather than a date', '2026-09-09T20:00:35Z'],
    ['unpadded', '2026-9-9'],
    ['a word', 'yesterday'],
    ['a date with something after it', '2026-09-09-extra'],
    // The step's own comment says the pattern is anchored over the WHOLE value to keep a newline out
    // of the $GITHUB_ENV writes, where one would define further variables. That is a claim about
    // behaviour, so it is asked rather than believed.
    ['a second line that would define its own variable', '2026-09-09\nDOCKVAULT_BUILD_COMMIT=deadbee'],
  ];
  for (const [what, value] of refused) {
    const r = asStamped(good({ [DATE_VAR]: value }));
    assert.notEqual(r.status, 0, `${what}: the build must refuse`);
    assert.match(r.stdout, /::error::refusing to build: the build date is not a date/, `${what}: and say why`);
    assert.equal(r.exported.trim(), '', `${what}: and export nothing`);
  }
});

test('the stamp step refuses a commit that is not one, so no installer is named after nothing', () => {
  const refused = [['empty', ''], ['a ref name', 'HEAD'], ['too short', '3d6bcc'], ['not hex', 'zzzzzzz'], ['a second line', `${FULL}\nEVIL=1`]];
  for (const [what, value] of refused) {
    const r = asStamped(good({ COMMIT: value }));
    assert.notEqual(r.status, 0, `${what}: the build must refuse`);
    assert.match(r.stdout, /::error::refusing to build: the commit to stamp is not a commit id/, `${what}: and say why`);
    assert.equal(r.exported.trim(), '', `${what}: and export nothing`);
  }
});

// The two ends have to agree, or the guard passes a value the build then silently drops. One validator
// is the point of build-stamp.js; this checks the shell in front of it does not admit more than it.
test('what the shell guard lets through is what the build configuration accepts', () => {
  const { stampMetadata } = require('../src/main/build-stamp');
  for (const date of [GOOD_DATE, '2026-12-31', '2027-01-01']) {
    assert.equal(asStamped(good({ [DATE_VAR]: date })).status, 0, `${date}: the shell admits it`);
    assert.equal(stampMetadata({ commit: FULL, date }).buildDate, date, `${date}: and the build keeps it`);
  }
});

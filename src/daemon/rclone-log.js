'use strict';

/*
 * The sync helper's STRUCTURED log — one JSON object per line — read on the daemon side of a run.
 *
 * WHY IT EXISTS. In the helper's text log, a message and a file's name are the same flat text: the tool
 * writes names verbatim into its own lines ("ERROR : holiday/notes.txt: Failed to copy: ..."), so "what
 * the run said" and "what a file is called" are the same characters and cannot be told apart by reading
 * them. The names are not ours — in a shared vault they arrive from whoever else can put a file there —
 * so that handed anyone who could add a file a say in what this computer reported about the RUN.
 *
 * The structured format ends the question instead of narrowing it:
 *   - the run's own words are in `msg`; the file a message is ABOUT is in `object` — different fields, so
 *     a name can never occupy the slot a verdict is read from;
 *   - the encoder ESCAPES what a name contains, so a name carrying a newline, a quote, or a brace stays
 *     inside its own string: it cannot end a line, start a line, or manufacture a record of its own;
 *   - the level is a field, not a prefix a name can spell.
 *
 * WHAT THE FORMAT DOES NOT DO ON ITS OWN, and what this module adds. A name can still reach a `msg` two
 * ways, and both are handled here rather than left to pattern-matching:
 *   - the tool interpolates a file's path INTO some error text ("partial file rename failed: rename
 *     <path> <path>: Access is denied"). Because the record also carries that name in `object`, the name
 *     is removed from its own message by EXACT match — there is no guessing where a name ends any more.
 *   - the tool's own progress lines echo a path ("- Path1  Renaming Path1 copy  - <path>.conflict1").
 *     Those are logged at notice/info; every real verdict is logged at error or critical. `isVerdictLevel`
 *     is what keeps a path-echoing progress line out of the haystack a verdict is read from.
 *
 * Also stripped here: the tool colours its own verdict lines, and the escapes sit BETWEEN the level and
 * the first word of the message ("ERROR : <esc>Bisync critical error: ..."). Removing them is what makes
 * anchoring a signature to the start of a message exact rather than lucky.
 *
 * Pure and dependency-free: every rule below is exercised by feeding it real recorded helper output.
 */

// The flag that asks the helper for this format. Kept here, beside the parser that depends on it, so the
// two can never drift apart: the reader and the thing that makes the reader's input live in one file.
const JSON_LOG_ARGS = Object.freeze(['--use-json-log']);

// Terminal colour/format escapes the tool writes into its own messages.
const ANSI_ESCAPE = /\u001b\[[0-9;?]*[ -\/]*[@-~]/g;
// Everything that would otherwise end a line here. A `msg` legitimately contains real newlines (the tool
// writes multi-line messages), and a name inside it arrives escaped — but once decoded, both are just
// characters. Flattening them to a space is what keeps ONE record on ONE haystack line, so "the start of
// a message" stays a place a name cannot reach.
const LINE_BREAKS = /[\r\n\u2028\u2029\u0085\v\f]/g;
// A single record's message is bounded: the tool can print a long message (a listing of paths it looked
// for), and the haystack must not grow with it. A verdict is short and sits at the START of a message, so
// a bound this generous cannot cut one off.
const MAX_MSG_CHARS = 4096;
// Past this, a line is not worth trying to parse as JSON — it takes the text path instead. A real record
// is a message and a name; a megabyte without a newline is neither.
const MAX_JSON_LINE_CHARS = 256 * 1024;
// A name shorter than this cannot contain any phrase a signature reads, and removing it from a message by
// exact match would shred the message instead (a one-character name would match everywhere). So a short
// name is simply left alone — it can do no harm, and the message it rode in on stays whole.
const MIN_MASKABLE_NAME = 4;
// What replaces a name inside its own message. Same token the text-format masking uses, so a person
// reading either format sees the same thing.
const FILE_PLACEHOLDER = '<file>';

// Every level the tool can write, mapped to the text form the signatures are written against. All of them,
// not just the ones seen in practice: an unmapped level would silently become a non-verdict, which is the
// quiet direction, and a verdict that arrives at a level nobody listed would simply never be read.
const LEVELS = Object.freeze({
  emergency: 'CRITICAL', alert: 'CRITICAL', critical: 'CRITICAL', error: 'ERROR',
  warning: 'NOTICE', notice: 'NOTICE', info: 'INFO', debug: 'DEBUG',
});
// The levels a verdict about the RUN may be read from. Every verdict the classifier names — a safety
// abort, a lost baseline, a changed server identity, a refused door, a file the server would not take —
// is logged at one of these. The tool's own progress lines, which are the one remaining place a file's
// path reaches a message, are logged BELOW them. That is the whole reason this set exists.
const VERDICT_LEVELS = Object.freeze(new Set(['error', 'critical', 'alert', 'emergency']));

function stripAnsi(s) { return String(s).replace(ANSI_ESCAPE, ''); }
// A message cut to the bound, as a string that holds nothing but itself. A plain slice of a long string
// keeps a reference to the whole of it, so a record charged a few kilobytes against the retention budget
// would quietly hold a quarter of a megabyte. Copying through an array forces the copy to stand alone.
function bound(s) { return s.length <= MAX_MSG_CHARS ? s : Array.from(s.slice(0, MAX_MSG_CHARS)).join(''); }
function flattenBreaks(s) { return String(s).replace(LINE_BREAKS, ' '); }

// The tool uploads to a temporary sibling — "<name>.<random token>.partial" — and renames it into place at
// the end, so a record about that upload names the TEMPORARY file while the message it carries names both
// it and the final one. The final name is the temporary one with this suffix removed: a form derived from
// the name, so it is masked with the name.
const PARTIAL_SUFFIX = /\.[0-9a-z]{6,12}\.partial$/i;

// The tool does not print a name the way it reports it. Before a path reaches a message it goes through the
// backend's own encoder, which rewrites the characters a filesystem cannot hold — so a file whose name ends
// in a space is REPORTED as "holiday " and PRINTED as "holiday␠", and removing one by matching the other
// finds nothing. That gap was enough on its own: a name ending in a space kept every character it spelled.
// These are the tool's substitutions, so the printed forms are masked alongside the reported one.
const ENCODED = Object.freeze({ '*': '\uff0a', '<': '\uff1c', '>': '\uff1e', ':': '\uff1a', '"': '\uff02', '?': '\uff1f', '|': '\uff5c' });
const ENCODED_CHARS = /[*<>:"?|]/g;
function encodedForm(name) {
  let s2 = String(name).replace(ENCODED_CHARS, (c) => ENCODED[c]);
  s2 = s2.replace(/ $/, '\u2420').replace(/^ /, '\u2420');   // a space the filesystem would eat, at either end
  s2 = s2.replace(/\.$/, '\uff0e');                           // ... and a trailing period, likewise
  return s2;
}

/**
 * Every form of one name worth removing from its own message: as the tool wrote it, with the separators
 * swapped (a record names a file with forward slashes; the message it appears in may use the platform's),
 * its last segment alone (the message usually carries the full path, of which the record's name is the
 * tail), each of those with the temporary-upload suffix removed, and each of THOSE as the tool would print
 * it rather than report it (see ENCODED). Longest first, so removing one form cannot leave a fragment of
 * another behind.
 */
function nameForms(object) {
  const raw = String(object == null ? '' : object);
  if (raw.length < MIN_MASKABLE_NAME) return [];
  const forms = new Set();
  for (const sep of [raw, raw.replace(/\//g, '\\'), raw.replace(/\\/g, '/')]) {
    for (const s of [sep, sep.replace(PARTIAL_SUFFIX, '')]) {
      for (const form of [s, encodedForm(s)]) {
        if (form.length >= MIN_MASKABLE_NAME) forms.add(form);
        const leaf = form.split(/[\\/]/).pop();
        if (leaf && leaf.length >= MIN_MASKABLE_NAME) forms.add(leaf);
      }
    }
  }
  return [...forms].filter(Boolean).sort((a, b) => b.length - a.length);
}

/**
 * A message with the name of the file it is ABOUT taken out of it, by exact match.
 *
 * This is the part the text format could never do. There, where a name ended was a guess, and every guess
 * was walked around by a name chosen to break it. Here the record states the name, so the characters that
 * came from the name are known exactly and are the only ones removed — what the TOOL said is untouched.
 */
function maskObjectIn(msg, object) {
  let out = String(msg == null ? '' : msg);
  for (const form of nameForms(object)) {
    if (!form || !out.includes(form)) continue;
    out = out.split(form).join(FILE_PLACEHOLDER);
  }
  return out;
}

// A safety abort as it reads in a MESSAGE, in either of the two shapes the tool writes: with its label
// ("Safety abort: all files were changed …") or without it, when the label went into the subject field
// ("too many deletes (>50%, 9 of 10) …"). Losing one of these is the direction that must never fail —
// nothing would latch the repair — so if taking a name out of a message would cost it its abort, the
// message is left exactly as the tool wrote it. Safe to do for these and only these: both are read from
// the START of a message, which is a place a file name cannot be.
const ABORT_WORDING = /^(?:safety abort:\s*)?(?:too many deletes\b|all files (?:were )?changed\b|max delete limit\b)/i;
function keepsItsAbort(before, after) { return !(ABORT_WORDING.test(before) && !ABORT_WORDING.test(after)); }

/**
 * Parse ONE raw stderr line as a structured log record.
 *
 * Returns null for anything that is not one — a line from a helper that is not writing this format, or
 * output the tool did not write through its logger at all. The caller then takes the text path, which is
 * exactly today's behaviour, so a missing flag degrades to what it does now rather than to silence.
 *
 * A file name can never produce a record: it lives inside a JSON string and the encoder escapes the
 * characters that would end it, so nothing a name contains can close the string, close the object, or
 * start another one.
 *
 * @returns {{level:(string|null), LEVEL:string, msg:string, object:(string|null), objectType:(string|null),
 *            stats:(object|null)}|null}
 *   `msg` is the tool's own words with colour escapes removed, line breaks flattened, the file's own name
 *   taken out, and bounded. `recordLine` renders it under its level, in the form the signatures read.
 */
function parseLogRecord(line) {
  const s = String(line == null ? '' : line);
  // Cheap rejects before any parse: a record is an object, and one worth parsing is not megabytes long.
  if (s.charCodeAt(0) !== 0x7b /* { */ || s.length > MAX_JSON_LINE_CHARS) return null;
  let o;
  try { o = JSON.parse(s); } catch { return null; }
  if (!o || typeof o !== 'object' || Array.isArray(o) || typeof o.msg !== 'string') return null;
  const level = typeof o.level === 'string' && Object.prototype.hasOwnProperty.call(LEVELS, o.level) ? o.level : null;
  const LEVEL = level ? LEVELS[level] : 'NOTICE'; // an unrecognised level is never a verdict level (see below)
  const object = typeof o.object === 'string' ? o.object : null;
  const objectType = typeof o.objectType === 'string' ? o.objectType : null;
  const stats = o.stats && typeof o.stats === 'object' && !Array.isArray(o.stats) ? o.stats : null;
  // Masked TWICE, around the colour strip, and the order is deliberate. Masking FIRST catches a name that
  // carries colour escapes of its own — strip them first and the name in the message would no longer be the
  // name in the field, so the exact match would miss and what it spelled would survive. Masking AGAIN after
  // catches the other way round: the tool brackets a path it prints in colour, and the escapes it added are
  // gone by then. Neither pass alone covers both.
  const plain = flattenBreaks(stripAnsi(o.msg));
  const masked = flattenBreaks(maskObjectIn(stripAnsi(maskObjectIn(o.msg, object)), object));
  // Bounded from the END, where a verdict never is. A truncating slice would otherwise keep the whole
  // original alive behind it, so the copy is forced flat and what is retained is what is charged.
  const msg = bound(keepsItsAbort(plain, masked) ? masked : plain);
  return { level, LEVEL, msg, object, objectType, stats };
}

/**
 * One record as the line the signatures read: the tool's own words under the level the tool logged them
 * at. DERIVED rather than stored, so a retained record holds each string once — what the daemon keeps for
 * a run is charged honestly against its budget (see stats-parse.js).
 */
function recordLine(rec) { return `${rec.LEVEL} : ${rec.msg}`; }

// What retaining one record really costs, for the budget that bounds how much of a run is kept. The
// per-record overhead is charged generously: a record is a JS object with five fields, not a slice of a
// string, and a run of very short messages would otherwise be charged a fraction of what it holds.
const RECORD_OVERHEAD = 128;
function recordSize(rec) {
  return rec.msg.length + (rec.object ? rec.object.length : 0) + (rec.objectType ? rec.objectType.length : 0) + RECORD_OVERHEAD;
}

/** Whether a record is one a verdict about the RUN may be read from (see VERDICT_LEVELS). */
function isVerdictLevel(rec) { return !!rec && VERDICT_LEVELS.has(rec.level); }

module.exports = {
  JSON_LOG_ARGS, parseLogRecord, recordLine, recordSize, isVerdictLevel, maskObjectIn, nameForms, stripAnsi, flattenBreaks,
  keepsItsAbort, ABORT_WORDING, encodedForm, LEVELS, VERDICT_LEVELS, FILE_PLACEHOLDER, MAX_MSG_CHARS, MIN_MASKABLE_NAME, RECORD_OVERHEAD,
};

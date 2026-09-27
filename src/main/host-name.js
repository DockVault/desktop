'use strict';

/*
 * A server name has two spellings: the one a person reads and types ("τεστ.example"), and the ASCII one the
 * network uses ("xn--qxa2abc.example", the IDNA form an address bar also converts to). Everything that makes a
 * connection or is written down — the saved server setting, the saved SFTP endpoint, the probes, the sync
 * engine's configuration — carries the ASCII form. Only what is put on screen carries the readable form, and a
 * readable form is offered only when it converts back to exactly the same ASCII name, so what is shown and what
 * is connected to can never drift apart.
 *
 * A readable form is also offered only when it cannot easily pass for a different name: every label must
 * consist of letters, marks and digits of ONE script (Japanese may mix Han, Hiragana and Katakana, Korean
 * Hangul and Han), with ASCII digits and hyphens allowed in any script. Anything else — a slash or a dot
 * look-alike inside a label ("vault.example.com∕login.evil.example"), or a label mixing scripts ("vauаlt",
 * with a Cyrillic "а") — is shown in its ASCII form, which is what exposes the trick. A name written entirely
 * in another script can still look like a Latin one ("аррӏе" in Cyrillic), so wherever a person confirms which
 * server they are dealing with, the ASCII form is shown beside the readable one whenever the two differ
 * (addressWithAscii).
 *
 * An IP address (v4 or v6) and a name that is already plain ASCII have one spelling and pass through, apart
 * from lower-casing: a setting saved in punycode by an earlier version reads back unchanged.
 */

const { domainToASCII, domainToUnicode } = require('node:url');

const NON_ASCII = /[^\x00-\x7f]/;
const ENCODED_LABEL = /(^|\.)xn--/i;

// A label a person can read without being misled: letters, marks, digits and hyphens only.
const LABEL_SHAPE = /^[\p{L}\p{M}\p{N}-]+$/u;

// The scripts a readable label may be written in, each on its own, plus the two mixes a language needs. A
// character counts for a script through its Script_Extensions property (so the prolonged sound mark "ー", which
// both kana share, counts for either, and a combining mark counts only for the scripts it is used with). ASCII
// digits and the hyphen go with any script. A script not listed here is shown in the ASCII form: less readable,
// never misleading.
const SCRIPTS = [
  'Latin', 'Greek', 'Cyrillic', 'Armenian', 'Georgian', 'Hebrew', 'Arabic', 'Syriac', 'Thaana', 'Nko',
  'Devanagari', 'Bengali', 'Gurmukhi', 'Gujarati', 'Oriya', 'Tamil', 'Telugu', 'Kannada', 'Malayalam', 'Sinhala',
  'Thai', 'Lao', 'Tibetan', 'Myanmar', 'Khmer', 'Mongolian', 'Ethiopic', 'Cherokee', 'Canadian_Aboriginal',
  'Tifinagh', 'Hangul', 'Hiragana', 'Katakana', 'Bopomofo', 'Han', 'Yi',
];
const SCRIPT_MIXES = [['Han', 'Hiragana', 'Katakana'], ['Hangul', 'Han']];
const SCRIPT_SETS = [...SCRIPTS.map((s) => [s]), ...SCRIPT_MIXES]
  .map((set) => new RegExp(`^[0-9\\-${set.map((s) => `\\p{scx=${s}}`).join('')}]+$`, 'u'));

/** Whether one decoded label may be shown readable: the right shape, and every character from one script set. */
function isReadableLabel(label) {
  return typeof label === 'string' && LABEL_SHAPE.test(label) && SCRIPT_SETS.some((re) => re.test(label));
}

/**
 * The ASCII form of a host name (no port, no brackets), trimmed and lower-cased. A name with characters
 * outside ASCII goes through IDNA; '' when it cannot be converted (the caller treats that as malformed).
 */
function toAsciiHost(name) {
  const s = String(name == null ? '' : name).trim();
  if (!s) return '';
  if (!NON_ASCII.test(s)) return s.toLowerCase();
  let ascii = '';
  try { ascii = domainToASCII(s); } catch { ascii = ''; }
  return typeof ascii === 'string' && !NON_ASCII.test(ascii) ? ascii : '';
}

/**
 * The readable form of an ASCII host name, for the screen. A name without an encoded label, one that does
 * not decode, one with a label that is not plainly written in one script (see above), or one whose readable
 * form would convert to a different ASCII name is shown as it is, in the ASCII form.
 */
function toDisplayHost(name) {
  const s = String(name == null ? '' : name);
  if (!ENCODED_LABEL.test(s)) return s;
  let readable = '';
  try { readable = domainToUnicode(s); } catch { readable = ''; }
  if (!readable || typeof readable !== 'string') return s;
  if (!readable.split('.').every(isReadableLabel)) return s;
  return toAsciiHost(readable) === s.toLowerCase() ? readable : s;
}

// "host[:port]" as its host and its port suffix (':8290', or ''). An IPv6 literal in brackets (or anything
// that does not split) has no name to decode and is kept whole.
function splitAddress(address) {
  const s = String(address == null ? '' : address);
  const m = s && !s.startsWith('[') ? s.match(/^(.*?)(:\d{1,5})?$/) : null;
  return m ? { host: m[1], port: m[2] || '', whole: false } : { host: s, port: '', whole: true };
}

/**
 * The readable form of a "host[:port]" address (a URL's host part). An IPv6 literal in brackets has no name
 * to decode and is returned as it is.
 */
function toDisplayAddress(address) {
  const { host, port, whole } = splitAddress(address);
  return whole ? host : toDisplayHost(host) + port;
}

/**
 * A "host[:port]" address as a person confirms it: the readable form followed by the ASCII form in brackets
 * whenever the two differ, the port in both ("τεστ (xn--qxa2abc)", "τεστ:8290 (xn--qxa2abc:8290)"), else the
 * one spelling. For every screen that says which server this is.
 */
function addressWithAscii(address) {
  const s = String(address == null ? '' : address);
  const shown = toDisplayAddress(s);
  return shown !== s ? `${shown} (${s})` : s;
}

module.exports = { toAsciiHost, toDisplayHost, toDisplayAddress, addressWithAscii, isReadableLabel };

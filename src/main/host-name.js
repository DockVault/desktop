'use strict';

/*
 * A server name has two spellings: the one a person reads and types ("τεστ.example"), and the ASCII one the
 * network uses ("xn--qxa2abc.example", the IDNA form an address bar also converts to). Everything that makes a
 * connection or is written down — the saved server setting, the saved SFTP endpoint, the probes, the sync
 * engine's configuration — carries the ASCII form. Only what is put on screen carries the readable form, and a
 * readable form is offered only when it converts back to exactly the same ASCII name, so what is shown and what
 * is connected to can never drift apart.
 *
 * An IP address (v4 or v6) and a name that is already plain ASCII have one spelling and pass through, apart
 * from lower-casing: a setting saved in punycode by an earlier version reads back unchanged.
 */

const { domainToASCII, domainToUnicode } = require('node:url');

const NON_ASCII = /[^\x00-\x7f]/;
const ENCODED_LABEL = /(^|\.)xn--/i;

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
 * not decode, or one whose readable form would convert to a different ASCII name is shown as it is.
 */
function toDisplayHost(name) {
  const s = String(name == null ? '' : name);
  if (!ENCODED_LABEL.test(s)) return s;
  let readable = '';
  try { readable = domainToUnicode(s); } catch { readable = ''; }
  if (!readable || typeof readable !== 'string') return s;
  return toAsciiHost(readable) === s.toLowerCase() ? readable : s;
}

/**
 * The readable form of a "host[:port]" address (a URL's host part). An IPv6 literal in brackets has no name
 * to decode and is returned as it is.
 */
function toDisplayAddress(address) {
  const s = String(address == null ? '' : address);
  if (!s || s.startsWith('[')) return s;
  const m = s.match(/^(.*?)(:\d{1,5})?$/);
  return toDisplayHost(m[1]) + (m[2] || '');
}

module.exports = { toAsciiHost, toDisplayHost, toDisplayAddress };

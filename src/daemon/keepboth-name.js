'use strict';

/*
 * Builds the human, extension-preserving name for a KEEP-BOTH preservation copy made during a zero-loss
 * resync. When a resync would otherwise overwrite or delete a file's other-side version, that version is
 * preserved under this name so both copies survive.
 *
 * The canonical/original name is NEVER changed - only the diverging copy is renamed to this. The form is:
 *
 *   <base> (conflicting copy from <source>, <friendly date>)<.ext>
 *   e.g. "Q3 Budget (conflicting copy from the vault, Sep 1 2026 2.14pm).xlsx"
 *
 * Load-bearing rules:
 *  - the EXTENSION is always last, so double-click-to-open still works (a marker after .ext looks corrupt);
 *  - the name is filesystem-safe on Windows/macOS/Linux (no reserved chars; a period is the time
 *    separator, so the time is "2.14pm", never "2:14pm");
 *  - `source` names WHICH copy this is by its ACTUAL origin ("the vault" for the server's version, "this
 *    computer" for a local version) - never path1/path2 or a hash;
 *  - a friendly date distinguishes multiple preserved versions;
 *  - on a name collision, a counter goes INSIDE the marker, before the ext: "... 2.14pm) (2).xlsx";
 *  - the result respects a max filename length by truncating only the BASE, keeping the marker + ext whole.
 */

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
// Characters reserved on at least one of Windows/macOS/Linux, plus control chars. Space and hyphen are NOT
// reserved and are legitimate in names, so they are kept.
const FORBIDDEN = new RegExp('[:/\\\\*?"<>|\\x00-\\x1f]', 'g');
const DEFAULT_MAX = 255; // the per-component filename limit on common filesystems

// "Sep 1 2026 2.14pm" - local calendar parts, period (not colon) as the time separator so it stays fs-safe.
function friendlyDate(at) {
  const d = at instanceof Date ? at : new Date(at);
  let h = d.getHours();
  const ampm = h < 12 ? 'am' : 'pm';
  h %= 12; if (h === 0) h = 12;
  const min = String(d.getMinutes()).padStart(2, '0');
  return `${MONTHS[d.getMonth()]} ${d.getDate()} ${d.getFullYear()} ${h}.${min}${ampm}`;
}

// Split a filename into [base, ext] where ext includes its dot and is the final extension only. A leading
// dot (dotfile like ".env") is part of the base, not an extension.
function splitExt(name) {
  const dot = name.lastIndexOf('.');
  if (dot <= 0) return [name, '']; // no dot, or a leading-dot dotfile
  return [name.slice(0, dot), name.slice(dot)];
}

function sanitize(s) { return String(s).replace(FORBIDDEN, ' ').replace(/\s+/g, ' ').trim(); }

/**
 * @param {string} originalName  the file's current (canonical) name, e.g. "Q3 Budget.xlsx"
 * @param {object} o
 * @param {string} o.source      human origin of THIS copy, e.g. "the vault" or "this computer"
 * @param {number|Date} o.at     the preservation time (a friendly date is derived from it)
 * @param {number} [o.counter]   collision counter; 1 (default) omits it, >=2 appends " (n)" inside the marker
 * @param {number} [o.maxLen]    max filename length (default 255); only the base is truncated to fit
 * @returns {string} the keep-both name
 */
function keepBothName(originalName, o) {
  const [base, ext] = splitExt(String(originalName));
  const src = sanitize(o.source);
  const n = Number(o.counter) > 1 ? ` (${Number(o.counter)})` : '';
  const marker = ` (conflicting copy from ${src}, ${friendlyDate(o.at)})${n}`;
  const maxLen = o.maxLen || DEFAULT_MAX;
  // Keep the marker + ext whole; truncate only the base if the whole name would exceed the limit.
  const room = maxLen - marker.length - ext.length;
  const keptBase = base.length > room ? base.slice(0, Math.max(1, room)) : base;
  return `${keptBase}${marker}${ext}`;
}

module.exports = { keepBothName, friendlyDate, splitExt };

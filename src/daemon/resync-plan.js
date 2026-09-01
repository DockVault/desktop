'use strict';

/*
 * Plans the PRESERVATION step of a zero-loss resync: given what a pre-scan found to differ between the
 * local folder (Path1) and the server (Path2), it produces the copies that must be made ON THE LOCAL
 * SIDE, BEFORE the resync, so nothing the resync would overwrite or delete is lost.
 *
 * Why local, and why before: a `bisync --resync` makes Path2 (server) match Path1 (local) — it overwrites
 * a server file that differs, and DELETES a server-only file. So every version the resync would destroy is
 * copied DOWN to local first; the resync then propagates those copies back up, and both versions end up on
 * both sides. A preservation copy placed only on the server would be destroyed by the very resync it is
 * meant to survive (this is the load-bearing subtlety).
 *
 * Two loss modes, two preservations:
 *  - a file only on the SERVER  -> copied down under its ORIGINAL name (nothing local to conflict with),
 *    so the resync keeps it instead of deleting it;
 *  - a file on BOTH sides whose content DIFFERS -> the SERVER's version is copied down under a KEEP-BOTH
 *    name (the local original is left in place), so the resync keeps both.
 *
 * This module is pure — it turns an enumerated diff into a list of {from server path -> to local path}
 * copies. Running the copies + the resync (and enumerating the diff live) is the caller's job.
 */

const { keepBothName } = require('./keepboth-name');

function dirOf(rel) { const i = rel.lastIndexOf('/'); return i < 0 ? '' : rel.slice(0, i + 1); }
function baseOf(rel) { const i = rel.lastIndexOf('/'); return i < 0 ? rel : rel.slice(i + 1); }

/**
 * @param {object} diff
 * @param {string[]} diff.serverOnly   rel paths present on the server but not locally (resync would delete)
 * @param {string[]} diff.differing    rel paths present on both sides whose content differs (server loses)
 * @param {string[]} [diff.localFiles] rel paths that already exist locally (to avoid name collisions)
 * @param {object} o
 * @param {string} [o.source]  human origin of the preserved copy (default "the vault" — it's the server's)
 * @param {number|Date} o.at   preservation time, for the keep-both friendly date
 * @returns {Array<{from:string,to:string,kind:'server-only'|'conflict-keep-both'}>}
 *          each: copy the SERVER file at `from` down to the LOCAL path `to`.
 */
function planPreservation(diff, o) {
  const source = o.source || 'the vault';
  const serverOnly = diff.serverOnly || [];
  const differing = diff.differing || [];
  const taken = new Set(diff.localFiles || []); // names already spoken for (existing local + planned)
  const plan = [];

  // Server-only: preserve under the original name — it cannot collide (absent locally by definition).
  for (const rel of serverOnly) {
    plan.push({ from: rel, to: rel, kind: 'server-only' });
    taken.add(rel);
  }
  // Differing: preserve the server's version under a keep-both name; the local original is untouched.
  for (const rel of differing) {
    const dir = dirOf(rel);
    const base = baseOf(rel);
    let counter = 1;
    let to;
    do { to = dir + keepBothName(base, { source, at: o.at, counter }); counter += 1; } while (taken.has(to));
    plan.push({ from: rel, to, kind: 'conflict-keep-both' });
    taken.add(to);
  }
  return plan;
}

module.exports = { planPreservation };

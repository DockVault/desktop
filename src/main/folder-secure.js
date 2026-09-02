'use strict';

/*
 * Make a sync folder owner-only before anything is written into it, and PROVE it by reading the
 * permissions back — never trust that the apply succeeded. Fail-closed: if the folder cannot be secured,
 * or the read-back does not confirm owner-only, the caller must not let a run proceed. Idempotent, so it
 * is safe to re-apply before every run (folders configured before this check existed get secured too).
 *
 *  - POSIX: chmod 0700, then confirm the mode is exactly 0700.
 *  - Windows: an explicit owner-only ACL — inheritance stripped and ONLY the current user granted — then
 *    confirmed by reading the ACL back and refusing if any entry is still inherited or names any principal
 *    other than the owner (SYSTEM, Administrators, Everyone, ...).
 *
 * This module runs NO subprocess itself: the caller injects an `icacls(argv)` runner (an execFile-style,
 * argv-array call — never a shell string), a `chmod`, and a `mode` reader. So the apply + the read-back
 * verification are unit-tested without touching real ACLs, and the app-level check exercises the real
 * icacls (via execFile) on a real folder and asserts the OBSERVABLE ACL — the security gate.
 */

// The owner identity is either a bare name string, or { name, sid } so ACEs can be MATCHED by the account
// SID as well as the name. The SID is the robust match: a directory account (e.g. Entra/AzureAD) prints in
// an icacls listing as a display name — "AzureAD\First Last" — whose leaf is NOT the login username, so a
// name-only match would read the OWNER'S OWN ACE as foreign (failing owner-only, and — worse — offering to
// remove the owner's own access). Granting is still BY NAME; matching accepts the SID or the name.
function ownerName(user) { return typeof user === 'string' ? user : ((user && user.name) || ''); }
function ownerSid(user) { return (user && typeof user === 'object' && user.sid) ? String(user.sid) : null; }

// icacls argv to apply an owner-only ACL: strip inherited ACEs (/inheritance:r), then grant ONLY the user
// full control with object + container inherit (OI/CI) so files/dirs created inside are owner-only too.
function secureAclArgs(dir, user) {
  return [String(dir), '/inheritance:r', '/grant:r', ownerName(user) + ':(OI)(CI)F'];
}

// Parse an icacls listing into [{ principal, flags }] ACEs (flags like "(OI)(CI)(F)"). Parsed line by line:
// each ACE line is `<principal>:<flag-groups>`, and the principal MAY contain spaces (e.g. "NT
// AUTHORITY\\SYSTEM", or an Entra display name "AzureAD\\First Last") — so it must not be read as a single
// non-space token, or the principal string handed to a later /remove would be wrong. The first line also
// carries the directory path before the principal; the known `dir` is stripped from it (a Windows account
// name cannot contain `:`, but a drive path can, so the path is removed by exact prefix, not by guessing).
function parseIcaclsAces(stdout, dir) {
  const aces = [];
  const prefix = dir == null ? '' : String(dir);
  for (const line of String(stdout == null ? '' : stdout).split(/\r?\n/)) {
    const m = line.match(/^(.*?):((?:\([A-Za-z,]+\))+)\s*$/); // principal (may contain spaces), then the flag groups
    if (!m) continue;
    let principal = m[1];
    if (prefix && principal.startsWith(prefix)) principal = principal.slice(prefix.length); // drop the path on the first line
    principal = principal.trim();
    if (principal) aces.push({ principal, flags: m[2] });
  }
  return aces;
}

function isOwner(principal, user) {
  const p = String(principal).toLowerCase();
  const sid = ownerSid(user);
  if (sid && p === String(sid).toLowerCase()) return true; // SID: globally unique — the primary, unambiguous match
  const u = ownerName(user).toLowerCase();
  if (!u) return false;
  // Exact match only, against the FULLY-QUALIFIED owner name (DOMAIN\user or MACHINE\user), never a bare leaf.
  // A leaf-only match would accept a same-named account in a DIFFERENT domain ("OTHERDOMAIN\me" for login "me") as
  // the owner — a confidentiality-direction over-match: a foreign account could read the decrypted copies while the
  // folder false-passes owner-only. The caller supplies the qualified name (and the SID above is the robust key).
  return p === u;
}

// True if an ACE is a DENY. icacls prints a denied ACE with a "(DENY)" token among its flags. A deny is a
// restriction, NOT a share: it is never treated as one, and it is removed with /remove:d, never /remove:g.
function isDeny(ace) {
  return /\(DENY\)/i.test((ace && ace.flags) || '');
}

function isInherited(ace) {
  return ((ace && ace.flags) || '').includes('(I)');
}

// Owner-only requires ALL of: at least one ACE; NO deny entry anywhere (any "(DENY)", even for a
// non-owner, is a foreign restriction — not owner-only); NO inherited ACE; no ACE naming a principal
// other than the owner; and the owner holding an ALLOW full-control ("(F)") ACE. Fail-closed on an
// empty/unreadable listing — absence of evidence is not evidence of owner-only. Each failure carries a
// DISTINCT reason so the run-time copy can be specific and the recovery can choose the right remediation.
// The deny check comes FIRST so a denied owner cannot false-pass the owner match, and a denied non-owner
// is reported as a deny (removed with /remove:d) rather than as an ordinary foreign share.
function verifyOwnerOnlyAcl(stdout, user, dir) {
  const aces = parseIcaclsAces(stdout, dir);
  if (aces.length === 0) return { ok: false, reason: 'acl-unreadable' };
  if (aces.some(isDeny)) return { ok: false, reason: 'acl-deny-present' };
  for (const a of aces) {
    if (isInherited(a)) return { ok: false, reason: 'acl-inherited' };
    if (!isOwner(a.principal, user)) return { ok: false, reason: 'acl-non-owner' };
  }
  if (!aces.some((a) => isOwner(a.principal, user) && a.flags.includes('(F)'))) return { ok: false, reason: 'acl-owner-not-full' };
  return { ok: true };
}

// Split the entries that keep a folder from being owner-only into the two kinds the consent-recovery must
// treat differently. An explicit ALLOW grant to another principal is a deliberate SHARE (removed with
// /remove:g under consent, framed "other accounts will lose access"); a DENY entry is a restriction, not a
// share (removed with /remove:d under consent, and NEVER framed as "remove sharing"). The owner's own
// ALLOW is not foreign and is left alone. Inherited ACEs are omitted — they are stripped by the
// /inheritance:r in the re-apply, not by a per-principal /remove. Principals are de-duplicated, first-seen
// order preserved, so the recovery issues one removal per principal.
function classifyForeignAces(stdout, user, dir) {
  const shares = [];
  const denies = [];
  for (const a of parseIcaclsAces(stdout, dir)) {
    if (isInherited(a)) continue;
    if (isDeny(a)) { if (!denies.includes(a.principal)) denies.push(a.principal); continue; }
    if (!isOwner(a.principal, user) && !shares.includes(a.principal)) shares.push(a.principal);
  }
  return { shares, denies };
}

/**
 * @param {string} dir
 * @param {object} io
 * @param {string} io.platform  'win32' or a POSIX platform string
 * @param {string} [io.user]    the current user (win32: for the grant AND the owner match)
 * @param {(args:string[])=>Promise<{code:number,stdout?:string}>} [io.icacls]  run icacls with an argv array
 * @param {(dir:string, mode:number)=>void} [io.chmod]  POSIX chmod
 * @param {(dir:string)=>number} [io.mode]  POSIX mode reader (returns at least st_mode & 0o777)
 * @returns {Promise<{ok:boolean, reason?:string}>}
 */
async function ensureFolderSecure(dir, io = {}) {
  if (!dir) return { ok: false, reason: 'no-folder' };
  if (io.platform === 'win32') {
    if (!ownerName(io.user)) return { ok: false, reason: 'no-user' }; // a grant needs a name (the SID alone can't be granted here)
    let applied;
    try { applied = await io.icacls(secureAclArgs(dir, io.user)); }
    catch { return { ok: false, reason: 'acl-apply-failed' }; }
    if (!applied || applied.code !== 0) return { ok: false, reason: 'acl-apply-failed' };
    let read;
    try { read = await io.icacls([String(dir)]); }
    catch { return { ok: false, reason: 'acl-unreadable' }; }
    if (!read || read.code !== 0) return { ok: false, reason: 'acl-unreadable' };
    return verifyOwnerOnlyAcl(read.stdout, io.user, dir); // read the ACL back and refuse unless it is owner-only
  }
  // POSIX: 0700, then confirm by reading the mode back.
  try { io.chmod(dir, 0o700); } catch { return { ok: false, reason: 'chmod-failed' }; }
  let mode;
  try { mode = io.mode(dir); } catch { return { ok: false, reason: 'mode-unreadable' }; }
  if ((mode & 0o777) !== 0o700) return { ok: false, reason: 'mode-not-0700' };
  return { ok: true };
}

/**
 * Recover an owner-only folder that carries foreign entries — called ONLY after the person has explicitly
 * consented (the caller owns the consent gate; this module never strips otherwise, and the default
 * ensureFolderSecure never strips at all). Remove each explicit foreign ALLOW grant with /remove:g and
 * each DENY with /remove:d, then re-apply owner-only and read the ACL back to confirm. Fail-closed: a
 * failed removal, or a read-back still not owner-only, returns { ok:false, reason } with nothing claimed —
 * never a silent partial. On success, reports exactly which principals were removed.
 * @returns {Promise<{ok:boolean, reason?:string, removed?:{shares:string[],denies:string[]}}>}
 */
async function recoverOwnerOnly(dir, io = {}) {
  if (!dir) return { ok: false, reason: 'no-folder' };
  if (io.platform !== 'win32') return ensureFolderSecure(dir, io); // POSIX owner-only is the mode alone; nothing to un-share
  if (!io.user) return { ok: false, reason: 'no-user' };
  let read;
  try { read = await io.icacls([String(dir)]); }
  catch { return { ok: false, reason: 'acl-unreadable' }; }
  if (!read || read.code !== 0) return { ok: false, reason: 'acl-unreadable' };
  const { shares, denies } = classifyForeignAces(read.stdout, io.user, dir);
  // Shares are un-shared with /remove:g, denies removed with /remove:d — the distinction R4 draws. Any
  // removal that fails leaves the folder unchanged-enough that the re-verify below would refuse anyway;
  // reporting it distinctly lets the copy say "couldn't change the folder's permissions".
  for (const p of shares) {
    let r; try { r = await io.icacls([String(dir), '/remove:g', p]); } catch { return { ok: false, reason: 'acl-remove-failed' }; }
    if (!r || r.code !== 0) return { ok: false, reason: 'acl-remove-failed' };
  }
  for (const p of denies) {
    let r; try { r = await io.icacls([String(dir), '/remove:d', p]); } catch { return { ok: false, reason: 'acl-remove-failed' }; }
    if (!r || r.code !== 0) return { ok: false, reason: 'acl-remove-failed' };
  }
  const secured = await ensureFolderSecure(dir, io); // re-apply owner-only + read the ACL back to prove it
  return secured.ok ? { ok: true, removed: { shares, denies } } : secured;
}

module.exports = { ensureFolderSecure, recoverOwnerOnly, secureAclArgs, parseIcaclsAces, verifyOwnerOnlyAcl, classifyForeignAces, isOwner, isDeny };

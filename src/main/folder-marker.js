'use strict';

/*
 * The marker that gives a synced folder an identity of its own: a small hidden file in the folder's root,
 * written when the sync is set up, carrying a random sync id and the vault it belongs to. From then on the
 * app knows a folder by its marker, not by where it happens to sit — a rename or a move keeps the marker
 * with the files, so the sync follows; a folder that merely has the same path but no marker (or someone
 * else's marker) is NOT the synced folder, and is never written to.
 *
 * The marker never leaves the machine: it is excluded from every transfer by name (the daemon's rclone
 * filters), so it is not uploaded to the vault and never appears on the server. It carries no secret, no
 * credential, no server name, and no path — only the two ids.
 *
 * A copy of a folder carries a copy of the marker. So the marker file's own identity on disk — the volume and
 * file id the filesystem gives it, which a rename or a same-volume move keeps and a copy does not — is
 * recorded too (markerIdentity), and a folder found elsewhere is followed on its own only when that matches;
 * otherwise the person is asked. Everything that touches the disk takes an injected fs (Node's by default)
 * so the rules are unit-tested on a fake; the bounded search for a moved folder walks asynchronously with a
 * budget so a slow disk can never wedge a sync tick. Symlinks and junctions are never followed.
 */

const path = require('node:path');
const nodeFs = require('node:fs');
const crypto = require('node:crypto');

const MARKER_NAME = '.dockvault-sync';
const MARKER_VERSION = 1;
// A real marker is a few hundred bytes. The search reads whatever sits under this name in thousands of
// folders, so the read is bounded: a plain file only (never a link), at most this many bytes, into a fixed
// buffer — a huge or odd file is 'unreadable', never loaded whole.
const MARKER_MAX_BYTES = 4096;
// A sync id is a UUID the app made; a vault id is the server's UUID. Both are validated on read so a
// tampered or torn marker is 'unreadable', never half-trusted.
const ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function newSyncId() { return crypto.randomUUID(); }
function markerPath(folder) { return path.join(folder, MARKER_NAME); }

function markerContents({ syncId, vaultId }) {
  if (!ID_RE.test(String(syncId)) || !ID_RE.test(String(vaultId))) throw new Error('a marker needs a sync id and a vault id');
  return JSON.stringify({ v: MARKER_VERSION, syncId: String(syncId).toLowerCase(), vaultId: String(vaultId).toLowerCase(), app: 'DockVault', note: 'This hidden file lets DockVault recognise this synced folder if it is moved or renamed. It is not uploaded. If you delete it, DockVault will stop recognising the folder and ask you about it.' }) + '\n';
}

/** Parse marker text into { syncId, vaultId }, or null when it is not a marker this app wrote. */
function parseMarker(text) {
  let o;
  try { o = JSON.parse(String(text)); } catch { return null; }
  if (!o || typeof o !== 'object' || o.v !== MARKER_VERSION) return null;
  if (!ID_RE.test(String(o.syncId)) || !ID_RE.test(String(o.vaultId))) return null;
  return { syncId: String(o.syncId).toLowerCase(), vaultId: String(o.vaultId).toLowerCase() };
}

/**
 * What the folder at `folder` carries:
 *   { kind: 'ok', syncId, vaultId }   a marker this app wrote
 *   { kind: 'absent' }                the folder exists but has no marker
 *   { kind: 'folder-missing' }        no folder at that path (or not a folder)
 *   { kind: 'unreadable' }            a marker file exists but cannot be read or is not one of ours
 */
function readMarker(folder, fs = nodeFs) {
  let st;
  try { st = fs.statSync(folder); } catch { return { kind: 'folder-missing' }; }
  if (!st || !st.isDirectory()) return { kind: 'folder-missing' };
  const file = markerPath(folder);
  let fst;
  try { fst = fs.lstatSync(file); } catch (e) {
    return (e && e.code === 'ENOENT') ? { kind: 'absent' } : { kind: 'unreadable' };
  }
  if (!fst.isFile() || fst.isSymbolicLink() || fst.size > MARKER_MAX_BYTES) return { kind: 'unreadable' };
  let text;
  try {
    const fd = fs.openSync(file, 'r');
    try {
      const buf = Buffer.alloc(MARKER_MAX_BYTES);
      const n = fs.readSync(fd, buf, 0, MARKER_MAX_BYTES, 0);
      text = buf.subarray(0, n).toString('utf8');
    } finally { fs.closeSync(fd); }
  } catch { return { kind: 'unreadable' }; }
  const m = parseMarker(text);
  return m ? { kind: 'ok', ...m } : { kind: 'unreadable' };
}

/**
 * Write (or replace) the marker in `folder`. Written through a temporary file and a rename so a crash
 * mid-write leaves either the old marker or the new one, never a torn file. `hide` is the platform's way of
 * hiding a file (the Windows hidden attribute; a dot-name already hides it elsewhere) — best-effort.
 */
function writeMarker(folder, ids, { fs = nodeFs, hide = null } = {}) {
  const text = markerContents(ids);
  const target = markerPath(folder);
  const tmp = `${target}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, { mode: 0o600 });
  try { fs.renameSync(tmp, target); } catch (e) {
    // A hidden file on Windows refuses a plain rename over it: drop the old one and try once more.
    try { fs.rmSync(target, { force: true }); } catch { /* best-effort */ }
    try { fs.renameSync(tmp, target); } catch { try { fs.rmSync(tmp, { force: true }); } catch { /* best-effort */ } throw e; }
  }
  if (hide) { try { hide(target); } catch { /* the marker works unhidden too */ } }
  return target;
}

/**
 * The marker file's identity on its volume, "<device>:<file id>", or null when it cannot be read. A rename or a
 * move within the same volume keeps it; a copy, or a move across volumes, gets a new one.
 */
function markerIdentity(folder, fs = nodeFs) {
  try {
    const st = fs.statSync(markerPath(folder), { bigint: true });
    if (!st || !st.isFile()) return null;
    return `${st.dev}:${st.ino}`;
  } catch { return null; }
}

/** Remove the marker from `folder`, but only when it is the one for `syncId`. Best-effort, never throws. */
function removeMarker(folder, syncId, fs = nodeFs) {
  const m = readMarker(folder, fs);
  if (m.kind !== 'ok' || m.syncId !== String(syncId).toLowerCase()) return false;
  try { fs.rmSync(markerPath(folder), { force: true }); return true; } catch { return false; }
}

// Folders a moved sync folder is not looked for in: the app's and the system's own trees, and dependency/cache
// trees that are huge and never a person's documents; in the wide walk, hidden folders too. The nearby pass
// (the old parent and its ancestors, one level each) looks at hidden names as well, so a synced folder whose
// own name starts with a dot is still found after a rename.
const SKIP_NAMES = new Set(['node_modules', 'appdata', 'application data', 'library', '$recycle.bin', 'system volume information', 'windows', 'program files', 'program files (x86)', 'programdata', '.git', '.trash', 'cache', 'caches']);
function skipByDefault(name, { nearby = false } = {}) {
  const n = String(name).toLowerCase();
  if (SKIP_NAMES.has(n)) return true;
  return !nearby && n.startsWith('.');
}

/**
 * Look for the folder carrying the marker for `syncId` after it went missing from `lastPath`. The search is
 * ordered by likelihood and bounded: the old parent's children first (a rename in place), then each ancestor's
 * children up to the first root (a move nearby), then a breadth-first walk of the given roots (a move
 * elsewhere under the home folder) — never following symlinks, skipping hidden and system trees, and stopping
 * at the directory or time budget. Every folder with a matching marker is reported, so a copy is never
 * silently taken for the original.
 * @returns {{ kind: 'found', folder } | { kind: 'ambiguous', folders } | { kind: 'not-found', exhausted: boolean }}
 */
async function findFolderByMarker({ syncId, vaultId, lastPath, roots = [], maxDirs = 20000, maxMs = 4000, maxDepth = 8, skip = skipByDefault, now = Date.now }, fs = nodeFs) {
  const want = String(syncId).toLowerCase();
  const wantVault = vaultId ? String(vaultId).toLowerCase() : null;
  const started = now();
  const seen = new Set();
  const found = [];
  let visited = 0;
  let exhausted = true;

  const norm = (p) => (process.platform === 'win32' ? path.resolve(p).toLowerCase() : path.resolve(p));
  const matches = (dir) => {
    const m = readMarker(dir, fs);
    return m.kind === 'ok' && m.syncId === want && (!wantVault || m.vaultId === wantVault);
  };
  const budgetLeft = () => visited < maxDirs && (now() - started) < maxMs;

  // Examine one directory's children (one level), returning the subdirectories for a deeper pass. Read
  // asynchronously, so a slow disk yields to the rest of the app between directories.
  const readdir = fs.promises && fs.promises.readdir ? (d) => fs.promises.readdir(d, { withFileTypes: true }) : async (d) => fs.readdirSync(d, { withFileTypes: true });
  const children = async (dir, nearby) => {
    let entries;
    try { entries = await readdir(dir); } catch { return []; }
    const subs = [];
    for (const e of entries) {
      if (!e.isDirectory() || e.isSymbolicLink()) continue;
      if (skip(e.name, { nearby })) continue;
      subs.push(path.join(dir, e.name));
    }
    return subs;
  };
  const look = (dir) => {
    const key = norm(dir);
    if (seen.has(key)) return;
    seen.add(key);
    visited += 1;
    if (matches(dir)) found.push(dir);
  };

  // 1. The old parent, then each ancestor's children (one level each), nearest first.
  const ancestors = [];
  if (lastPath) {
    let cur = path.dirname(path.resolve(lastPath));
    while (cur && !ancestors.includes(cur)) { ancestors.push(cur); const up = path.dirname(cur); if (up === cur) break; cur = up; }
  }
  for (const a of ancestors) {
    for (const sub of await children(a, true)) { if (!budgetLeft()) { exhausted = false; break; } look(sub); }
    if (!budgetLeft()) break;
  }

  // 2. Breadth-first under the roots, depth-limited.
  if (budgetLeft()) {
    let frontier = roots.filter(Boolean).map((r) => ({ dir: path.resolve(r), depth: 0 }));
    while (frontier.length && budgetLeft()) {
      const next = [];
      for (const { dir, depth } of frontier) {
        if (!budgetLeft()) break;
        for (const sub of await children(dir, false)) {
          if (!budgetLeft()) break;
          look(sub);
          if (depth + 1 < maxDepth) next.push({ dir: sub, depth: depth + 1 });
        }
      }
      frontier = next;
    }
    if (!budgetLeft() && frontier.length) exhausted = false;
  }

  if (found.length === 1) return { kind: 'found', folder: found[0] };
  if (found.length > 1) return { kind: 'ambiguous', folders: found };
  return { kind: 'not-found', exhausted };
}

module.exports = { MARKER_NAME, MARKER_MAX_BYTES, ID_RE, newSyncId, markerPath, markerContents, parseMarker, readMarker, writeMarker, markerIdentity, removeMarker, findFolderByMarker, skipByDefault };

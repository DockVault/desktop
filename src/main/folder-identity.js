'use strict';

/*
 * Resolving a synced folder by its identity before every run. The config remembers a path and a sync id;
 * the folder itself carries the marker (folder-marker.js). Before a run the two are compared, and only a
 * folder whose marker matches is ever synced:
 *
 *   - marker at the remembered path matches           -> run there
 *   - the remembered path is gone, or holds a different folder (no marker, someone else's marker, a torn
 *     marker)                                          -> look for the marked folder nearby; found once ->
 *                                                        FOLLOW it (the config is re-pointed after the new
 *                                                        place passes the same placement rules as at setup);
 *                                                        found twice -> pause, ask which; not found -> pause,
 *                                                        offer relocate-or-stop
 *   - a config from before markers existed (no sync id) -> ADOPT: give the folder its marker now, or take
 *                                                        over a marker for the same vault already there
 *
 * Every answer is typed. A pause never syncs the wrong place: nothing is written to a folder whose marker
 * does not match, and nothing is written anywhere while the answer is in doubt. All IO is injected.
 */

const { newSyncId } = require('./folder-marker');

const NO_FOLDER_REASONS = new Set(['folder-missing', 'folder-marker-missing', 'folder-other-vault', 'folder-marker-unreadable', 'folder-ambiguous', 'folder-moved-rejected', 'folder-found-elsewhere', 'folder-marker-unwritable', 'config-unwritable']);

/**
 * @param {{ vaultId: string, localFolder: string, syncId?: string, markerId?: string, movedFrom?: string }} entry
 * @param {object} io
 *   readMarker(folder)                    -> folder-marker.js readMarker shape
 *   writeMarker(folder, { syncId, vaultId })
 *   markerIdentity(folder)                -> "<device>:<file id>" of the marker file, or null
 *   find({ syncId, vaultId, lastPath })    -> folder-marker.js findFolderByMarker shape (may be throttled by the caller)
 *   classify(folder, vaultId)             -> { ok, reason?, warn? } the placement rules (sync-config.js classifyLocalTarget)
 *   repoint(entry, { localFolder, syncId, markerId?, movedFrom? }) -> persist the change (movedFrom = the FIRST old path
 *                                          since the last completed run, for the engine to carry its listings over);
 *                                          throws when the config cannot be written
 * @returns {Promise<{ ok: true, folder: string, syncId: string, moved?: { from: string, to: string }, adopted?: boolean }
 *                 | { ok: false, reason: string, folders?: string[], placement?: string }>}  placement = why the found place is refused
 */
async function resolveSyncFolder(entry, io) {
  const vaultId = String(entry.vaultId).toLowerCase();
  const at = entry.localFolder;
  const m = io.readMarker(at);
  const identity = (folder) => { try { return io.markerIdentity ? io.markerIdentity(folder) : null; } catch { return null; } };
  // A write that fails (a read-only folder, a config that cannot be saved) is its own typed pause, never a raw error.
  const write = (folder, ids) => { try { io.writeMarker(folder, ids); return null; } catch { return { ok: false, reason: 'folder-marker-unwritable' }; } };
  const repoint = (change) => { try { io.repoint(entry, change); return null; } catch { return { ok: false, reason: 'config-unwritable' }; } };

  // A config that predates markers: adopt.
  if (!entry.syncId) {
    if (m.kind === 'folder-missing') return { ok: false, reason: 'folder-missing' };
    if (m.kind === 'ok' && m.vaultId !== vaultId) return { ok: false, reason: 'folder-other-vault' };
    if (m.kind === 'unreadable') return { ok: false, reason: 'folder-marker-unreadable' };
    const syncId = m.kind === 'ok' ? m.syncId : newSyncId();
    if (m.kind !== 'ok') { const w = write(at, { syncId, vaultId }); if (w) return w; }
    const r = repoint({ localFolder: at, syncId, markerId: identity(at) || undefined });
    if (r) return r;
    return { ok: true, folder: at, syncId, adopted: true };
  }

  const syncId = String(entry.syncId).toLowerCase();
  if (m.kind === 'ok' && m.syncId === syncId && m.vaultId === vaultId) {
    // In place. A config that has not recorded the marker's identity yet learns it now (once).
    if (!entry.markerId) { const id = identity(at); if (id) { const r = repoint({ localFolder: at, syncId, markerId: id }); if (r) return r; } }
    return { ok: true, folder: at, syncId };
  }

  // The remembered path no longer holds this sync's folder. What sits there decides the words if the
  // folder cannot be found elsewhere; the search decides whether it can.
  const whyHere = m.kind === 'folder-missing' ? 'folder-missing'
    : m.kind === 'absent' ? 'folder-marker-missing'
      : m.kind === 'unreadable' ? 'folder-marker-unreadable'
        : 'folder-other-vault'; // a marker, but not this sync's
  let f;
  try { f = await io.find({ syncId, vaultId, lastPath: at }); } catch { f = { kind: 'not-found', exhausted: false }; }
  if (!f || f.kind === 'not-found') return { ok: false, reason: whyHere };
  if (f.kind === 'ambiguous') return { ok: false, reason: 'folder-ambiguous', folders: f.folders };
  // Found once. Only the same marker FILE — renamed or moved along with its folder, not copied — is followed
  // on its own; a copy (or a move across volumes) looks the same by content, so the person is asked first.
  // Fail closed when the identity was never recorded or cannot be read now.
  const id = identity(f.folder);
  if (!entry.markerId || !id || id !== entry.markerId) return { ok: false, reason: 'folder-found-elsewhere', folders: [f.folder] };
  // The same placement rules as at set-up. A cloud-synced place is only a warning there, asked about in
  // person; followed silently it would put two sync engines over one tree, so here it counts as refused.
  const cl = io.classify(f.folder, entry.vaultId);
  if (!cl || !cl.ok) return { ok: false, reason: 'folder-moved-rejected', folders: [f.folder], placement: (cl && cl.reason) || 'folder-rejected' };
  if (cl.warn === 'inside-cloud-sync') return { ok: false, reason: 'folder-moved-rejected', folders: [f.folder], placement: 'inside-cloud-sync' };
  // The FIRST old path since the last completed run is what the engine's listings are still keyed by.
  const r = repoint({ localFolder: f.folder, syncId, markerId: id, movedFrom: entry.movedFrom || at });
  if (r) return r;
  return { ok: true, folder: f.folder, syncId, moved: { from: at, to: f.folder } };
}

/**
 * The person points at a folder to relocate a sync to (the relocate-or-stop offer). Only the folder carrying
 * THIS sync's marker is accepted — a look-alike is refused with the reason, so a wrong folder is never synced.
 * @returns {{ ok: true, markerId: (string|null) } | { ok: false, reason: 'no-marker' | 'other-sync' | 'folder-missing' | 'marker-unreadable' | string }}
 */
function checkRelocation(entry, folder, io) {
  const m = io.readMarker(folder);
  if (m.kind === 'folder-missing') return { ok: false, reason: 'folder-missing' };
  if (m.kind === 'absent') return { ok: false, reason: 'no-marker' };
  if (m.kind === 'unreadable') return { ok: false, reason: 'marker-unreadable' };
  if (!entry.syncId || m.syncId !== String(entry.syncId).toLowerCase() || m.vaultId !== String(entry.vaultId).toLowerCase()) return { ok: false, reason: 'other-sync' };
  const cl = io.classify(folder, entry.vaultId);
  if (!cl || !cl.ok) return { ok: false, reason: (cl && cl.reason) || 'folder-rejected' };
  let markerId = null;
  try { markerId = io.markerIdentity ? io.markerIdentity(folder) : null; } catch { markerId = null; }
  return { ok: true, markerId };
}

module.exports = { resolveSyncFolder, checkRelocation, NO_FOLDER_REASONS };

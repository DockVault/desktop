'use strict';

/*
 * THE MODEL BEHIND THE DEDICATED SYNC-STATUS WINDOW.
 *
 * One row per synced folder: what state it is in, the honest sentence for that state, how far a transfer has
 * got, and when it last finished. Pure — it takes the same injected pieces the Computers view takes and
 * returns a plain object, so it is testable without a window, a server, or a signed-in session.
 *
 * THREE THINGS DECIDE THE SHAPE, and they are worth stating because each rules out an easier design.
 *
 * 1. THE SENTENCE IS COMPOSED HERE, IN MAIN, NOT IN THE PAGE. `reasonSentence` builds its answer out of a
 *    vault's outcome DETAIL — the file that would not go, the size the server stated, the room the vault has
 *    left. `publicStatus` deliberately strips `detail` from anything a renderer can ask for, because that
 *    channel is reachable from the window hosting the vault's own web interface. So a page cannot compose
 *    this sentence, and widening that channel to carry it would push file names into the one window that is
 *    not ours. It is composed here and delivered on a page-gated channel, exactly as the Computers card is.
 *
 * 2. IT READS THE SAME `reasonText` THE COMPUTERS CARD READS. Not a second copy of the same logic — the same
 *    injected function. Two windows open at once, describing one vault differently, is the failure this whole
 *    area of the app has been fighting; the way to not have it is to have one source, not two careful ones.
 *
 * 3. IT ASKS NOTHING OF THE NETWORK OR THE SESSION. The Computers view fetches the account's devices and
 *    grants, so it needs a session and can fail with 'sign-in'. A person watching a sync that is misbehaving
 *    is often exactly the person whose session or server is the problem, and a status window that says "sign
 *    in first" in that moment is useless. Everything here comes from local configuration and the live status
 *    the scheduler already publishes, so this window works when the rest does not.
 */

/**
 * @param {object} io
 *   configured()            -> [{ vaultId, vaultName, localFolder, enabled }]
 *   liveStatus()            -> { state, label, reason, vaults: [{ vault, state, reason, running, lastSyncedAt, via, progress }] }
 *   reasonText(live, name)  -> a plain sentence for a vault's live reason, or null   (the Computers card's own)
 *   lastSyncedLabel(ts)     -> "2 minutes ago" etc, or null
 */
function createStatusView(io) {
  return { model: () => buildModel(io) };
}

// The transfer, as numbers only — never a path or a file name. A percentage is shown only when the helper
// stated one; the rest is what has moved of what is queued. Anything malformed is dropped rather than shown,
// because a progress bar that lies is worse than one that is absent.
function transferOf(progress) {
  if (!progress || typeof progress !== 'object') return null;
  const int = (v, lo, hi) => (Number.isInteger(v) && v >= lo && (hi == null || v <= hi) ? v : null);
  const num = (v) => (typeof v === 'number' && Number.isFinite(v) && v >= 0 ? v : null);
  const percent = int(progress.percent, 0, 100);
  const bytes = num(progress.bytes);
  const bytesTotal = num(progress.bytesTotal);
  const files = int(progress.files, 0, null);
  const filesTotal = int(progress.filesTotal, 0, null);
  // A bar needs a fraction. Prefer the stated percentage; fall back to bytes, then to files — and only when
  // the total is a real total, so a "3 of 0 files" can never produce a bar.
  let fraction = null;
  if (percent != null) fraction = percent / 100;
  else if (bytes != null && bytesTotal != null && bytesTotal > 0) fraction = Math.min(1, bytes / bytesTotal);
  else if (files != null && filesTotal != null && filesTotal > 0) fraction = Math.min(1, files / filesTotal);
  if (percent == null && bytes == null && files == null) return null;
  return { percent, bytes, bytesTotal, files, filesTotal, fraction };
}

function buildModel(io) {
  const configured = safe(() => io.configured(), []) || [];
  const live = safe(() => io.liveStatus(), null);
  const liveVaults = (live && Array.isArray(live.vaults)) ? live.vaults : [];
  const byId = new Map();
  for (const v of liveVaults) if (v && v.vault) byId.set(String(v.vault).toLowerCase(), v);

  const items = configured.map((cfg) => {
    const id = String(cfg.vaultId || '').toLowerCase();
    const l = byId.get(id) || null;
    const name = cfg.vaultName || cfg.vaultId;
    // A vault whose sync is switched off is not "waiting" — it is off, and saying "waiting to start" about it
    // would be the calm-sounding lie this window exists to remove.
    const enabled = cfg.enabled !== false;
    return {
      vaultId: cfg.vaultId,
      name,
      folder: cfg.localFolder || null,
      enabled,
      state: enabled ? (l ? l.state : null) : 'off',
      running: !!(l && l.running),
      // The honest sentence, from the one source the Computers card uses. Null when the state explains
      // itself — a bare "Up to date" needs no paragraph under it.
      note: enabled && l ? (safe(() => io.reasonText(l, name), null) || null) : null,
      lastSynced: l && l.lastSyncedAt ? safe(() => io.lastSyncedLabel(l.lastSyncedAt), null) : null,
      transfer: enabled && l && l.running ? transferOf(l.progress) : null,
    };
  });

  return {
    // The one-line answer for the window's own title area, from the same model the tray glances at.
    headline: (live && typeof live.label === 'string') ? live.label : null,
    state: live ? live.state : null,
    items,
    // Said explicitly rather than left as an empty list, so the page never renders a blank panel with no
    // explanation of why it is blank.
    empty: items.length === 0,
  };
}

function safe(fn, fallback) { try { const v = fn(); return v == null ? fallback : v; } catch { return fallback; } }

module.exports = { createStatusView, transferOf };

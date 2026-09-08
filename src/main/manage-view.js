'use strict';

/*
 * The "Computers" view — the in-app account view of every computer registered to sync, the vaults each one
 * syncs, and the actions that end a sync: as one testable module over injected io.
 *
 * What it shows, and where each fact comes from:
 *   computers    the account's registered devices (the server's device list: label, active, created, last
 *                seen, expiry) — the server is the authority on which computers exist and which are revoked.
 *   this one     the computer the view runs on is marked as such (its identity's id matches a listed device)
 *                and is the only one whose vault cards carry a LOCAL side: the folder the vault syncs to
 *                here, its live sync state and the reason behind it, when it last synced, and which path it
 *                runs on. Those facts are read here and shown here; they are never sent anywhere.
 *   its vaults   this computer's grants come from the server's own list for this device (the device route),
 *                joined with the vault names recorded here and the sync configuration. A vault configured
 *                here without an active grant is labelled by the SAME rule the scheduler uses to choose a
 *                credential path (mint-path.js): never recorded here -> it syncs through the sign-in;
 *                recorded here but no longer granted -> its permission was withdrawn; recorded here while this
 *                computer has no identity -> this computer was removed. Nothing is called "syncing through
 *                the sign-in" that the scheduler would refuse.
 *   others       other computers cannot have their grants listed from an account session on this server
 *                version, so their cards show the computer's metadata, the plain statement that their
 *                synced vaults are managed on that computer, and the actions that apply to the whole
 *                computer.
 *
 * Actions (each confirm-gated in the page; each server-authoritative and fail-closed here):
 *   revoke-grant       POST the grant revoke on the server; when the grant is this computer's, also drop the
 *                      local pointer (the sync configuration entry, the grant record, any pending marker) so
 *                      the folder stops syncing at once — the server refusing the mint is the backstop.
 *   revoke-computer    POST the device revoke; when it is this computer, also clear the local identity and
 *                      its records (it can never be presented again), leaving the synced files alone.
 *   remove-computer    DELETE a computer that is already revoked (housekeeping of the list).
 *   stop-sync          drop a local sync configuration entry (this computer only; the grant stays).
 *   sync-now           ask the scheduler for a run (this computer only).
 * Ids arriving from the page are checked for shape before anything is done with them, and a server refusal
 * is reported as a typed reason, never as a raw message. An answer the server gave that could not be read as
 * a confirmation is 'indeterminate': nothing local changes, and the page says the change could not be confirmed.
 */

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const isUuid = (v) => typeof v === 'string' && UUID.test(v);
// A device id is the server's opaque identifier: one bounded, path-safe segment (the client never assumes
// its format — see device-secret-store.js), compared exactly as the server returned it.
const DEVICE_ID = /^[A-Za-z0-9_.:-]{1,128}$/;
const isDeviceId = (v) => typeof v === 'string' && DEVICE_ID.test(v);

// How a vault configured on this computer stands, by the scheduler's own rule (decideMintPath):
//   'device'      granted to this computer's identity
//   'account'     never recorded here: syncs through the sign-in
//   'withdrawn'   recorded here, no longer granted: held
//   'removed'     recorded here, and this computer has no identity for this server: held
//   'identity'    this computer's identity is in a problem state (stale, unreadable, elsewhere, no store): held
function standingOf({ granted, recorded, identityStatus }) {
  if (granted) return 'device';
  if (identityStatus === 'ok') return recorded ? 'withdrawn' : 'account';
  if (identityStatus === 'absent') return recorded ? 'removed' : 'account';
  return recorded ? 'identity' : 'account';
}

/**
 * @param {object} io
 *   signedIn()                 -> boolean
 *   listDevices()              -> Promise<{ ok, devices?: [{device_id,label,is_active,epoch,created_at,last_seen,expires_at}], reason? }>
 *   myIdentity()               -> { status, deviceId|null }   (this computer's identity for the server in force; no secret decrypted)
 *   myGrants()                 -> Promise<{ ok, grants?: [{vaultId, grantedAt, name, metaKnown}], reason? }>  (device route; only when status is ok)
 *   grantRecord()              -> { status: 'ok'|'absent'|'unreadable', has: (vaultId) => boolean }  (the local grant record)
 *   configured()               -> [{ vaultId, vaultName, localFolder, enabled }]
 *   liveStatus()               -> { vaults: [{ vault, state, reason, running, lastSyncedAt, via }] }
 *   reasonText(live, name)     -> a plain sentence for a vault's live reason, or null
 *   endpoint()                 -> { serverHost, sftp: {host, port}|null }
 *   remotePathFor(vaultId, via, vaultName) -> the remote directory a run uses
 *   revokeGrant(deviceId, vaultId), revokeDevice(deviceId), deleteDevice(deviceId) -> Promise<{ ok, reason? }>
 *   relocateFolder(vaultId)    -> open main's relocate-or-stop offer for a folder that cannot be found
 *   dropLocalVault(vaultId)    -> remove the local sync entry + records for a vault
 *   dropLocalIdentity()        -> clear this computer's identity + grant records locally
 *   syncNow(vaultId)
 *   afterChange()              -> refresh whatever reads the config / identity
 */
function createManageView(io) {
  let inFlightModel = null; // one model build at a time: a second read while one runs shares its answer
  let actInFlight = false;  // one action at a time

  function model() {
    if (inFlightModel) return inFlightModel;
    inFlightModel = buildModel().finally(() => { inFlightModel = null; });
    return inFlightModel;
  }

  async function buildModel() {
    if (!io.signedIn()) return { kind: 'sign-in' };
    const dev = await io.listDevices();
    if (!dev || !dev.ok) return { kind: dev && dev.reason === 'too-old' ? 'unsupported' : (dev && dev.reason === 'auth' ? 'sign-in' : 'unavailable'), reason: (dev && dev.reason) || 'unavailable' };
    const me = safe(() => io.myIdentity(), null) || { status: 'unreadable', deviceId: null };
    const myId = isDeviceId(me.deviceId) ? me.deviceId : null; // known for a live identity and for a retired/unreadable one whose meta still reads
    const identityOk = me.status === 'ok' && !!myId;
    const record = safe(() => io.grantRecord(), null) || { status: 'unreadable', has: () => false };
    const recorded = (vaultId) => (record.status === 'ok' ? !!record.has(vaultId) : record.status === 'unreadable' ? null : false);
    const configured = safe(() => io.configured(), []);
    const live = safe(() => io.liveStatus(), { vaults: [] });
    const liveById = new Map((live.vaults || []).map((v) => [v.vault, v]));
    const liveFor = (id) => liveById.get(id) || liveById.get(String(id).toLowerCase()) || null;
    const ep = safe(() => io.endpoint(), { serverHost: '', sftp: null });
    const remoteHost = ep.sftp ? `${ep.sftp.host}:${ep.sftp.port}` : (ep.serverHost || '');
    const mk = (args) => card({ ...args, remoteHost, identityStatus: me.status, recorded, io });

    // This computer's vault cards: every grant the server lists for this device, joined with the local
    // configuration; plus configured vaults without an active grant, labelled by their standing.
    let myVaults = null;
    let myGrantsReason = null;
    if (identityOk) {
      const g = await io.myGrants();
      if (g && g.ok) {
        const grantedIds = new Set();
        myVaults = [];
        for (const gr of g.grants) {
          if (!isUuid(gr.vaultId)) continue;
          grantedIds.add(gr.vaultId.toLowerCase());
          const cfg = configured.find((c) => c.vaultId && c.vaultId.toLowerCase() === gr.vaultId.toLowerCase()) || null;
          myVaults.push(mk({ vaultId: cfg ? cfg.vaultId : gr.vaultId, name: gr.name || (cfg && cfg.vaultName) || null, grantedAt: gr.grantedAt || null, granted: true, cfg, live: liveFor(gr.vaultId) }));
        }
        for (const cfg of configured) {
          if (!cfg.vaultId || grantedIds.has(cfg.vaultId.toLowerCase())) continue;
          myVaults.push(mk({ vaultId: cfg.vaultId, name: cfg.vaultName || null, grantedAt: null, granted: false, cfg, live: liveFor(cfg.vaultId) }));
        }
      } else {
        myGrantsReason = (g && g.reason) || 'device-request-refused';
      }
    }

    // The configured vaults as cards without a grant list behind them: what this computer shows when its identity
    // is not live (each labelled by its standing), and the local block's content when it is not listed at all.
    const configuredCards = () => configured.map((cfg) => mk({ vaultId: cfg.vaultId, name: cfg.vaultName || null, grantedAt: null, granted: false, cfg, live: liveFor(cfg.vaultId) }));
    const computers = (dev.devices || []).map((d) => {
      const id = typeof d.device_id === 'string' ? d.device_id : '';
      const isThis = !!(myId && id === myId);
      return {
        deviceId: id,
        label: typeof d.label === 'string' && d.label ? d.label : 'A computer',
        isActive: d.is_active !== false,
        createdAt: d.created_at || null,
        lastSeen: d.last_seen || null,
        expiresAt: d.expires_at || null,
        isThis,
        // This computer's row: its grant-list cards when the identity is live; the configured vaults by their standing
        // when it is not (the row is still this computer — a retired identity does not make it someone else's).
        vaults: isThis ? (identityOk ? myVaults : configuredCards()) : null,   // null: not listable from here
        vaultsUnavailable: isThis ? (identityOk ? myGrantsReason : null) : 'not-listable',
        identityNote: isThis && !identityOk ? me.status : null,
      };
    });
    // This computer first, then active computers, then revoked ones; each group by label.
    computers.sort((a, b) => (b.isThis - a.isThis) || (b.isActive - a.isActive) || a.label.localeCompare(b.label));

    // The local side when this computer is NOT one of the listed, identity-live computers: no identity here (the
    // vaults sync through the sign-in, or are held as removed), an identity in a problem state, or an identity
    // the server no longer lists. The configured vaults must stay reachable (Stop syncing, Sync now) in every case.
    const listed = computers.some((c) => c.isThis);
    let local = null;
    if (!listed) local = { status: identityOk ? 'not-listed' : me.status, vaults: myVaults || configuredCards() };
    return {
      kind: 'ok',
      serverHost: ep.serverHost || '',
      remoteHost,
      thisComputer: { deviceId: myId, status: me.status, registered: listed },
      computers,
      local,
    };
  }

  function card({ vaultId, name, grantedAt, granted, cfg, live, remoteHost, identityStatus, recorded, io: o }) {
    const rec = recorded(vaultId);
    const standing = standingOf({ granted, recorded: rec === true, identityStatus });
    const via = granted ? 'device' : 'account';
    const remoteVia = live && live.via ? live.via : via;
    let remotePath = null;
    try { remotePath = o.remotePathFor(vaultId, remoteVia, name || (cfg && cfg.vaultName) || null); } catch { remotePath = null; }
    return {
      vaultId,
      name: name || 'A vault',
      granted,
      grantedAt,
      standing,
      remote: remotePath ? `${remoteHost}/${remotePath}` : remoteHost,
      local: cfg ? {
        folder: cfg.localFolder, enabled: cfg.enabled !== false,
        state: live ? live.state : null, reason: live ? live.reason : null, running: !!(live && live.running), lastSyncedAt: live ? live.lastSyncedAt : null,
        via: remoteVia,
        reasonText: live && live.reason ? safe(() => o.reasonText(live, name || (cfg && cfg.vaultName) || null), null) : null,
      } : null,
    };
  }

  /**
   * Carry out one confirmed action. The page confirmed with the person; this checks the shape of what it
   * asked for and does the server call first, the local drop second (a server refusal or an unconfirmable
   * answer changes nothing here). One action at a time.
   * @returns {Promise<{ ok: boolean, reason?: string }>}
   */
  async function act(action) {
    if (actInFlight) return { ok: false, reason: 'busy' };
    actInFlight = true;
    try { return await doAct(action); } finally { actInFlight = false; }
  }

  async function doAct(action) {
    const kind = action && action.kind;
    const deviceId = action && action.deviceId;
    const vaultId = action && action.vaultId;
    const me = safe(() => io.myIdentity(), null) || { status: 'unreadable', deviceId: null };
    // "This computer" for the local drop: the id matches, whatever the identity's status — a stale or
    // unreadable identity for a row the server just revoked must be cleared too.
    const isThis = isDeviceId(me.deviceId) && isDeviceId(deviceId) && me.deviceId === deviceId;
    switch (kind) {
      case 'revoke-grant': {
        if (!isDeviceId(deviceId) || !isUuid(vaultId)) return { ok: false, reason: 'bad-request' };
        const r = await io.revokeGrant(deviceId, vaultId);
        if (!r || !r.ok) return { ok: false, reason: (r && r.reason) || 'refused' };
        if (isThis) { try { io.dropLocalVault(vaultId); } catch { /* the server grant is gone; the local drop is best-effort and the mint is refused anyway */ } }
        try { io.afterChange(); } catch { /* best-effort */ }
        return { ok: true };
      }
      case 'revoke-computer': {
        if (!isDeviceId(deviceId)) return { ok: false, reason: 'bad-request' };
        const r = await io.revokeDevice(deviceId);
        if (!r || !r.ok) return { ok: false, reason: (r && r.reason) || 'refused' };
        if (isThis) { try { io.dropLocalIdentity(); } catch { /* best-effort: a retired identity is refused by the server regardless */ } }
        try { io.afterChange(); } catch { /* best-effort */ }
        return { ok: true };
      }
      case 'remove-computer': {
        if (!isDeviceId(deviceId)) return { ok: false, reason: 'bad-request' };
        const r = await io.deleteDevice(deviceId);
        if (!r || !r.ok) return { ok: false, reason: (r && r.reason) || 'refused' };
        if (isThis) { try { io.dropLocalIdentity(); } catch { /* best-effort */ } }
        try { io.afterChange(); } catch { /* best-effort */ }
        return { ok: true };
      }
      case 'stop-sync': {
        if (!isUuid(vaultId)) return { ok: false, reason: 'bad-request' };
        try { io.dropLocalVault(vaultId); } catch (e) { return { ok: false, reason: e && e.code === 'CONFIG_UNREADABLE' ? 'config-unreadable' : 'refused' }; }
        try { io.afterChange(); } catch { /* best-effort */ }
        return { ok: true };
      }
      case 'sync-now': {
        if (!isUuid(vaultId)) return { ok: false, reason: 'bad-request' };
        try { io.syncNow(vaultId); } catch { return { ok: false, reason: 'refused' }; }
        return { ok: true };
      }
      // The relocate-or-stop offer for a folder that cannot be found: main runs it (its own dialogs); the page
      // only asks for it, and only for a vault configured here.
      case 'relocate-folder': {
        if (!isUuid(vaultId)) return { ok: false, reason: 'bad-request' };
        const here = (safe(() => io.configured(), []) || []).some((c) => c && c.vaultId === vaultId);
        if (!here) return { ok: false, reason: 'not-found' };
        try { io.relocateFolder(vaultId); } catch { return { ok: false, reason: 'refused' }; }
        return { ok: true };
      }
      default:
        return { ok: false, reason: 'bad-request' };
    }
  }

  return { model, act };
}

function safe(fn, fallback) { try { const v = fn(); return v == null ? fallback : v; } catch { return fallback; } }

module.exports = { createManageView, isUuid, isDeviceId, standingOf };

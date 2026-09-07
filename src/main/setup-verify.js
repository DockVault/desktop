'use strict';

/*
 * The setup screen's verify step: two independent legs, run together, and one decision.
 *
 *   api    the server address — normalised, its health route asked, redirects followed to the landing
 *          origin (server-probe.js). Green when it answers as a DockVault server (ok or degraded).
 *   sync   whether the landed server supports syncing from a computer at all (sync-capability.js),
 *          asked only once the API leg has landed somewhere. Not a light of its own: a plain sentence.
 *   sftp   the SFTP address — parsed, reached, and its host key obtained through a verified key
 *          exchange (sftp-probe.js). Green when the exchange verified.
 *
 * `proceed` is true when the API leg is green AND the SFTP leg is green — with one honest exception: a
 * server that does not support syncing has no SFTP door for this app to use, so an SFTP leg that merely
 * could not be reached (or was left empty) is marked 'not-needed' and does not block connecting (a person
 * may still sign in and use the server). A door that answered with a host key it could not prove stays
 * red even then — that is a warning sign, never neutral — though it does not block either, since nothing
 * from it is saved. When it could not be told whether the server supports syncing, the SFTP leg is
 * required: failing closed on an unknown is what keeps a misdirected address from being saved silently.
 *
 * Everything with a side effect is injected; the outcome carries no error text, path, or credential —
 * kinds, hosts, a port, and a host-key fingerprint (which is public by nature). A failure inside the
 * verify itself (a bug, not the network) is reported as its own kind, 'failed', so it is never read as
 * "check your connection".
 */

const serverProbe = require('./server-probe');
const { parseSftpEndpoint } = require('./sftp-endpoint');
const { probeSyncCapability: defaultSyncProbe } = require('./sync-capability');
const { probeSftp: defaultSftpProbe } = require('./sftp-probe');

const API_GREEN = new Set(['ok', 'degraded']);
// The SFTP outcomes that mean "nothing answered as SFTP here" — set aside on a server without sync.
const SFTP_ABSENT = new Set(['empty', 'malformed', 'unreachable', 'not-ssh', 'ssh-unsupported']);

function apiIsGreen(api) { return !!(api && API_GREEN.has(api.kind)); }

// What the screen needs of the API leg: the kind, the host, and where a redirect came from. Never the
// normalised origin (main keeps that for the write) and never anything else the probe may carry.
function apiForScreen(api) {
  const out = { kind: api.kind };
  if (typeof api.host === 'string') out.host = api.host;
  if (typeof api.from === 'string') out.from = api.from;
  return out;
}

/** The outcome for a verify that itself failed (a bug or an unexpected throw), fail-closed. */
function failedVerify() {
  return { api: { kind: 'failed' }, sync: { kind: 'not-checked' }, sftp: { kind: 'failed', host: '', port: 0 }, proceed: false, endpoint: null, origin: null };
}

/**
 * @param {{ input: string, sftp: string }} fields  what was typed in the two fields
 * @param {{ httpJson: Function, probeSftp?: Function, probeSyncCapability?: Function }} deps
 * @returns {Promise<{ api: object, sync: { kind: string }, sftp: object, proceed: boolean, endpoint: ({host:string,port:number}|null) }>}
 */
async function verifySetup(fields, { httpJson, probeSftp = defaultSftpProbe, probeSyncCapability = defaultSyncProbe }) {
  const input = fields && typeof fields.input === 'string' ? fields.input : '';
  const sftpText = fields && typeof fields.sftp === 'string' ? fields.sftp : '';

  const parsed = parseSftpEndpoint(sftpText);
  const endpoint = parsed.kind === 'ok' ? { host: parsed.host, port: parsed.port } : null;

  // Both legs at once: they are independent doors, and a person waiting on a slow one should see the
  // other's answer as soon as it is in.
  const apiLeg = (async () => {
    let api;
    try { api = await serverProbe.probeServer(input, { httpJson }); } catch { api = { kind: 'unreachable' }; }
    let sync = { kind: 'not-checked' };
    if (apiIsGreen(api)) {
      try { sync = await probeSyncCapability(api.origin, { httpJson }); } catch { sync = { kind: 'unknown' }; }
    }
    return { api, sync };
  })();
  const sftpLeg = (async () => {
    if (!endpoint) return { kind: parsed.kind, host: '', port: 0 }; // 'empty' | 'malformed'
    try { return await probeSftp(endpoint); } catch { return { kind: 'unreachable', ...endpoint }; }
  })();

  const [{ api, sync }, sftpRaw] = await Promise.all([apiLeg, sftpLeg]);
  // Only what the screen shows travels: never the host-key line itself (the pin comes from the vault's
  // authenticated answer at sync time, not from this probe), never a raw error.
  let sftp = { kind: sftpRaw.kind, host: sftpRaw.host, port: sftpRaw.port };
  if (sftpRaw.kind === 'ok') sftp.fingerprint = sftpRaw.fingerprint;
  const syncUnsupported = sync.kind === 'unsupported';
  if (syncUnsupported && SFTP_ABSENT.has(sftp.kind)) sftp = { ...sftp, kind: 'not-needed' };

  const proceed = apiIsGreen(api) && (sftp.kind === 'ok' || syncUnsupported);
  // `origin` is the normalised landing origin for the caller that writes it; the screen gets the projection.
  return { api: apiForScreen(api), sync, sftp, proceed, endpoint: sftp.kind === 'ok' ? endpoint : null, origin: apiIsGreen(api) ? api.origin : null };
}

module.exports = { verifySetup, apiIsGreen, failedVerify };

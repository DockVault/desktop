'use strict';

/*
 * The setup screen's main-process half, apart from the window it lives in: answer the screen's three
 * intents from the saved setting and the probes, and decide what may be written.
 *
 *   state()             { mode, status, host, sftp } — all the screen may know
 *   check(args)         run the verify step (setup-verify.js) on what was typed and hand back the two
 *                       legs and the sync sentence. Writes nothing. This is what lights the screen.
 *   connect(args)       verify AGAIN — main never trusts a renderer's claim that the lights were green —
 *                       and on a passing verify, save the origin and the verified SFTP endpoint, unless a
 *                       saved setting exists that could not be read and the person has not confirmed
 *                       replacing it (kind 'needs-confirm', nothing written). Resolves the typed
 *                       outcome with the verify attached; `onSaved` is called with the outcome after a
 *                       write so the caller can open the sign-in page (after a moment for a degraded
 *                       server, so its sentence can be read).
 *
 * Connecting to a server is all this does. It never registers this computer for sync, never picks a
 * vault or a folder: sync is set up separately, later, and only if the person asks for it.
 *
 * Everything with a side effect is injected, so the whole decision is testable without Electron.
 */

const serverConfig = require('./server-config');
const serverProbe = require('./server-probe');
const { verifySetup, failedVerify } = require('./setup-verify');
const { formatSftpEndpoint } = require('./sftp-endpoint');

const DEGRADED_HOLD_MS = 1500;

// Only the shell's own setup page may drive these intents: every page on the app origin shares the
// preload, including the web interface the server supplies, and none of those may re-point the app.
// Full-URL equality, not a prefix: the shell serves that exact path from its own files before the
// proxy is consulted, so the server can never mint content at it.
function isSetupPageUrl(url, appOrigin, pagePath) {
  if (typeof url !== 'string' || typeof appOrigin !== 'string' || typeof pagePath !== 'string') return false;
  return url === appOrigin + pagePath;
}

// The three legs of the sender check, all required: the request comes from the main window's page,
// from that page's MAIN frame (never something framed inside it), and that frame is at exactly the
// setup page's URL. The shell serves that URL from its own files before the proxy is consulted, so
// the server can never mint content there, and shell pages forbid framing; together the three legs
// mean only the shell's own setup screen can ask for a server to be saved.
function isTrustedSetupSender(event, { webContents, appOrigin, pagePath }) {
  try {
    if (!event || !webContents || event.sender !== webContents) return false;
    if (!event.senderFrame || event.senderFrame !== event.sender.mainFrame) return false;
    return isSetupPageUrl(event.senderFrame.url, appOrigin, pagePath);
  } catch { return false; }
}

function fieldsOf(args) {
  return {
    input: args && typeof args.input === 'string' ? args.input : '',
    sftp: args && typeof args.sftp === 'string' ? args.sftp : '',
  };
}

function createServerSetup({ dir, httpJson, probeSftp, probeSyncCapability, onSaved = () => {}, schedule = setTimeout, mode = () => null, changeHost = () => null, changeSftp = () => null }) {
  const probes = { httpJson };
  if (probeSftp) probes.probeSftp = probeSftp;
  if (probeSyncCapability) probes.probeSyncCapability = probeSyncCapability;

  function state() {
    let s;
    try { s = serverConfig.readServerConfigState(dir); }
    catch { s = { status: 'unreadable', origin: null, sftp: null }; }
    const change = mode() === 'change';
    // While switching, the old server is already forgotten on disk; its host and SFTP address are kept
    // in memory only so the fields can be pre-filled.
    const host = s.origin ? serverProbe.hostOf(s.origin) : (change ? (changeHost() || null) : null);
    const sftp = s.sftp ? formatSftpEndpoint(s.sftp) : (change ? (changeSftp() || null) : null);
    return { mode: change ? 'change' : 'first-run', status: s.status, host, sftp: sftp || null };
  }

  // The verify with the landing origin split off: the screen never needs it, the write does.
  async function runVerify(args) {
    let v;
    try { v = await verifySetup(fieldsOf(args), probes); } catch { v = failedVerify(); }
    const { origin, ...forScreen } = v;
    return { origin, verify: forScreen };
  }

  async function check(args) { return (await runVerify(args)).verify; }

  async function connect(args) {
    const replaceUnreadable = !!(args && args.replaceUnreadable === true);
    const checked = await runVerify(args);
    const verify = checked.verify;
    const outcome = { ...verify.api, origin: checked.origin || undefined };
    if (outcome.kind !== 'ok' && outcome.kind !== 'degraded') return { kind: outcome.kind, host: outcome.host, verify };
    // The API answered as DockVault but the SFTP door did not verify (and the server does speak sync):
    // nothing is written. The screen already shows which light is red and why.
    if (!verify.proceed) return { kind: 'not-verified', host: outcome.host, verify };
    // Write policy: a write is allowed only when nothing is saved yet, when the person is switching
    // servers (the old one already forgotten through the consent flow), or when a saved setting could
    // not be read and they confirmed replacing it. A saved, readable server is never re-pointed from
    // here: that path is the consent flow, nowhere else.
    const saved = serverConfig.readSavedServer(dir);
    const switching = mode() === 'change';
    if (saved.status === 'unreadable' && !replaceUnreadable) return { kind: 'needs-confirm', host: outcome.host, verify };
    if (saved.status === 'ok' && !switching) return { kind: 'not-allowed', host: outcome.host, verify };
    try { serverConfig.writeServerOrigin(dir, outcome.origin, verify.endpoint); }
    catch { return { kind: 'save-failed', host: outcome.host, verify }; }
    const result = { ...outcome, verify };
    schedule(() => { try { onSaved(result); } catch { /* the caller's problem */ } }, outcome.kind === 'degraded' ? DEGRADED_HOLD_MS : 0);
    return result;
  }

  return { state, check, connect };
}

module.exports = { createServerSetup, isSetupPageUrl, isTrustedSetupSender, DEGRADED_HOLD_MS };

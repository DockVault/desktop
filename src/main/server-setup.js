'use strict';

/*
 * The setup screen's main-process half, apart from the window it lives in: answer the screen's two
 * intents from the saved setting and the probe, and decide what may be written.
 *
 *   state()             { mode, status, host } — all the screen may know
 *   connect(args)       probe what was typed; on a DockVault answer, save it — unless a saved setting
 *                       exists that could not be read and the person has not confirmed replacing it
 *                       (kind 'needs-confirm', nothing written). Resolves the typed outcome; `onSaved`
 *                       is called with the outcome after a write so the caller can open the sign-in page
 *                       (after a moment for a degraded server, so its sentence can be read).
 *
 * Everything with a side effect is injected, so the whole decision is testable without Electron.
 */

const serverConfig = require('./server-config');
const serverProbe = require('./server-probe');

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

function createServerSetup({ dir, httpJson, onSaved = () => {}, schedule = setTimeout, mode = () => null, changeHost = () => null }) {
  function state() {
    let s;
    try { s = serverConfig.readServerConfigState(dir); }
    catch { s = { status: 'unreadable', origin: null }; }
    const change = mode() === 'change';
    // While switching, the old server is already forgotten on disk; its host is kept in memory only
    // so the field can be pre-filled.
    const host = s.origin ? serverProbe.hostOf(s.origin) : (change ? (changeHost() || null) : null);
    return { mode: change ? 'change' : 'first-run', status: s.status, host };
  }

  async function connect(args) {
    const input = args && typeof args.input === 'string' ? args.input : '';
    const replaceUnreadable = !!(args && args.replaceUnreadable === true);
    let outcome;
    try { outcome = await serverProbe.probeServer(input, { httpJson }); }
    catch { outcome = { kind: 'unreachable' }; }
    if (outcome.kind !== 'ok' && outcome.kind !== 'degraded') return outcome;
    // Write policy: a write is allowed only when nothing is saved yet, when the person is switching
    // servers (the old one already forgotten through the consent flow), or when a saved setting could
    // not be read and they confirmed replacing it. A saved, readable server is never re-pointed from
    // here: that path is the consent flow, nowhere else.
    const saved = serverConfig.readSavedServer(dir);
    const switching = mode() === 'change';
    if (saved.status === 'unreadable' && !replaceUnreadable) return { kind: 'needs-confirm', host: outcome.host };
    if (saved.status === 'ok' && !switching) return { kind: 'not-allowed', host: outcome.host };
    try { serverConfig.writeServerOrigin(dir, outcome.origin); }
    catch { return { kind: 'save-failed', host: outcome.host }; }
    schedule(() => { try { onSaved(outcome); } catch { /* the caller's problem */ } }, outcome.kind === 'degraded' ? DEGRADED_HOLD_MS : 0);
    return outcome;
  }

  return { state, connect };
}

module.exports = { createServerSetup, isSetupPageUrl, isTrustedSetupSender, DEGRADED_HOLD_MS };

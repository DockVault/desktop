'use strict';

/*
 * The Troubleshoot view: a list of checks, and for the chosen one a picture of what is set up plus a live
 * probe run from this computer right now. The page is a plain renderer of what a check hands back — facts
 * (label + value rows), legs (lights with a sentence each), notes, and a verdict — so a new check is a new
 * entry in the registry below and nothing else. The page never names what to probe: it sends a check id,
 * main reads the saved setting itself and probes that. Nothing here writes anything.
 *
 * The first check, "Cannot connect to the server", reuses the setup screen's verify (setup-verify.js):
 * the server address is asked its health route, the fixed device route says whether the server speaks
 * sync, and the saved SFTP address is reached for a host key it must prove. Each leg lights green, amber,
 * or red on its own, with a sentence about what that means and what to do next; the verdict above them
 * says only what the legs prove — never "reachable" when nothing answered, never green on a doubt.
 *
 * The outcome carries kinds, hosts, ports, and a public host-key fingerprint — never an error object, a
 * key line, a credential, or a local path. A verify that throws is reported as its own 'failed' kind, so
 * a bug is never read as "your connection is down".
 */

const { formatSftpEndpoint } = require('./sftp-endpoint');
const { apiIsGreen, failedVerify } = require('./setup-verify');

const LEG_SERVER = 'Server';
const LEG_SFTP = 'File transfer (SFTP)';
const ADMIN = 'whoever runs your server';
// Where a fix leads. The saved addresses are changed from the setup screen; an address forced by the
// environment variable cannot be changed there, and the sentences must not send a person to a door that
// is not offered.
const HINTS = {
  saved: { change: 'Use Change server… to enter it again.', add: 'Use Change server… to add one.', landing: 'use Change server… to enter the address it lands on.' },
  env: { change: "The address comes from the DOCKVAULT_SERVER environment variable, so it can't be changed here.", add: "The address comes from the DOCKVAULT_SERVER environment variable, so one can't be added here.", landing: "the address comes from the DOCKVAULT_SERVER environment variable, so it can't be changed here." },
};

// --- Words -------------------------------------------------------------------------------------------

function endpointText(leg) {
  if (!leg || !leg.host) return 'that address';
  const h = leg.host.includes(':') ? `[${leg.host}]` : leg.host;
  return `${h}:${leg.port}`;
}

// The server leg, as what happened and what to do. Only the host of the normalised origin is ever named.
function apiSentence(api, hints = HINTS.saved) {
  const host = (api && api.host) || 'the server';
  switch (api && api.kind) {
    case 'ok': return api.from && api.from !== host ? `${api.from} sent DockVault to ${host}, which answered as a DockVault server.` : `${host} answered as a DockVault server.`;
    case 'degraded': return `${host} answered as a DockVault server, but it reports a problem on its side. Signing in may still work; if it doesn't, ask ${ADMIN}.`;
    case 'unreachable': return `Nothing answered at ${host}. Check that this computer is online and the server is up, and that nothing between them (a firewall, a VPN) is in the way.`;
    case 'tls-untrusted': return `${host} answered, but its certificate isn't trusted by this computer, so DockVault won't connect to it. Ask ${ADMIN} to install its certificate on this computer.`;
    case 'not-dockvault': return `Something answered at ${host}, but not a DockVault server. The saved address may be wrong, or the server may have moved. ${hints.change}`;
    case 'redirected': return `${host} now sends DockVault somewhere else. The server may have moved — ${hints.landing}`;
    case 'http-refused': case 'malformed': case 'empty': return `The saved server address isn't usable. ${hints.change}`;
    case 'failed': return "Couldn't run this check. Try again; if it keeps failing, restart DockVault.";
    default: return `Couldn't check ${host}.`;
  }
}

function sftpSentence(sftp, hints = HINTS.saved) {
  const at = endpointText(sftp);
  switch (sftp && sftp.kind) {
    case 'ok': return `${at} answered as an SFTP server and proved it is who it says it is.`;
    case 'not-needed': return "Not needed — this server doesn't sync folders from a computer, so there is no file transfer door to check. You can still sign in and use your files in the app.";
    case 'empty': return `No file transfer address is saved for this server, so folders can't sync from this computer. ${hints.add}`;
    case 'malformed': return `The saved file transfer address isn't usable. ${hints.change}`;
    case 'unreachable': return `Nothing answered at ${at}. The file transfer port may be closed, blocked (a firewall, a VPN), or changed — ask ${ADMIN} which port SFTP is on.`;
    case 'not-ssh': return `${at} answers, but not as an SFTP server — usually the wrong port. Ask ${ADMIN} which port SFTP is on.`;
    case 'ssh-unsupported': return `${at} is an SSH server, but not one DockVault can use. Ask ${ADMIN}.`;
    case 'host-key-unverified': return `${at} presented a host key it couldn't prove it owns, so DockVault won't use it. Something between this computer and the server may be interfering — ask ${ADMIN}.`;
    case 'failed': return "Couldn't run this check. Try again; if it keeps failing, restart DockVault.";
    default: return `Couldn't check ${at}.`;
  }
}

function syncSentence(kind) {
  switch (kind) {
    case 'supported': return 'This server can sync folders from this computer.';
    case 'unsupported': return "This server doesn't support syncing folders from a computer. You can still sign in and use your files in the app.";
    case 'unknown': return "Couldn't tell whether this server supports syncing folders from a computer. If the file transfer door above is green, syncing should still work.";
    default: return '';
  }
}

// The light for each leg: green only for a proven door, amber for a door that answered with a caveat of its
// own (a server reporting a problem), grey for a door that is not needed, red for everything else.
function apiState(api) {
  if (!apiIsGreen(api)) return 'bad';
  return api.kind === 'degraded' ? 'warn' : 'ok';
}
function sftpState(sftp) {
  if (sftp.kind === 'ok') return 'ok';
  return sftp.kind === 'not-needed' ? 'skip' : 'bad';
}

// One sentence on the whole picture, from the two legs. It agrees with the leg sentences: "can't be reached"
// only when nothing answered, "answered but not usable" when something did, and never green on a doubt.
const API_SILENT = new Set(['unreachable', 'empty']);
function verdictOf(verify) {
  const api = verify.api || {};
  const sftp = verify.sftp || {};
  const host = api.host || 'the server';
  if (api.kind === 'failed' || sftp.kind === 'failed') return { state: 'bad', text: "This check couldn't run, so it says nothing about your connection. Try again." };
  if (!apiIsGreen(api)) {
    if (API_SILENT.has(api.kind)) return { state: 'bad', text: `${host} can't be reached from this computer right now. Nothing else can work until it can.` };
    return { state: 'bad', text: `Something answered at ${host}, but not in a way DockVault can use, so it can't connect. Nothing else can work until that is put right — the Server line below says what to do.` };
  }
  if (sftp.kind === 'host-key-unverified') return { state: 'bad', text: `${host} answers, but its file transfer door presented a host key it couldn't prove. DockVault won't sync through it; something between this computer and the server may be interfering — ask ${ADMIN}.` };
  const doorsFine = sftp.kind === 'ok' || sftp.kind === 'not-needed';
  if (api.kind === 'degraded' && doorsFine) return { state: 'partial', text: `${sftp.kind === 'ok' ? 'Both doors answered' : `${host} answered`}, but the server reports a problem on its side. Signing in may still work; if it doesn't, ask ${ADMIN}.` };
  const notCause = `If signing in still fails, the connection isn't the cause — check the sign-in details, and if they are right ask ${ADMIN}.`;
  if (sftp.kind === 'ok') return { state: 'ok', text: `Both doors answered: DockVault can reach ${host} and its file transfer address from this computer right now. ${notCause}` };
  if (sftp.kind === 'not-needed') return { state: 'ok', text: `DockVault can reach ${host} from this computer right now. ${notCause}` };
  if (sftp.kind === 'empty' || sftp.kind === 'malformed') return { state: 'partial', text: `${host} answers, but no usable file transfer address is saved for it. Signing in and browsing should work; folders can't sync from this computer until one is.` };
  return { state: 'partial', text: `${host} answers, but its file transfer door isn't usable from this computer. Signing in and browsing should work; folders can't sync until it is — see File transfer below.` };
}

// --- The checks ----------------------------------------------------------------------------------------

// Each check: { id, title, describe(io) -> picture, probe(io) -> result }. `describe` is synchronous and
// reads only what is saved; `probe` reaches out. Both hand back the generic shapes the page renders.

// The saved origin as an address a person can compare with what they were given: always with its port, so
// the "API port" is never implied; a plain-http loopback (a development server) says so.
function addressText(origin) {
  try {
    const u = new URL(origin);
    const http = u.protocol === 'http:';
    const port = u.port || (http ? '80' : '443');
    return `${http ? 'http://' : ''}${u.hostname}:${port}`;
  } catch { return String(origin); }
}

const INTRO = "Tries both of your server's doors from this computer, without signing in: the server address (signing in, browsing) and the file transfer address (syncing folders).";

const serverConnection = {
  id: 'server-connection',
  title: 'Cannot connect to the server',
  describe(io) {
    const state = safeState(io);
    const legs = [{ id: 'api', label: LEG_SERVER }, { id: 'sftp', label: LEG_SFTP }];
    if (state.status === 'absent') {
      return { id: this.id, title: this.title, intro: '', facts: [], legs, canProbe: false, note: 'No server is set up on this computer yet, so there is nothing to check.', action: { kind: 'setup-server', label: 'Set up server…' } };
    }
    if (state.status === 'unreadable' || !state.origin) {
      return { id: this.id, title: this.title, intro: '', facts: [], legs, canProbe: false, note: "The saved server setting can't be read, so DockVault doesn't know which server to reach. Set the server up again to replace it.", action: { kind: 'setup-server', label: 'Set up server…' } };
    }
    const env = state.status === 'env';
    const facts = [
      { label: 'Server address', value: addressText(state.origin), mono: true },
      { label: 'File transfer address', value: state.sftp ? formatSftpEndpoint(state.sftp) : 'not saved', mono: !!state.sftp },
    ];
    if (env) facts.push({ label: 'Set by', value: state.envOverrides ? 'the DOCKVAULT_SERVER environment variable, overriding the saved setting' : 'the DOCKVAULT_SERVER environment variable', mono: false });
    return {
      id: this.id, title: this.title, intro: INTRO, facts, legs, canProbe: true,
      note: env ? "The server address comes from the DOCKVAULT_SERVER environment variable, so it can't be changed from here." : '',
      action: env ? null : { kind: 'change-server', label: 'Change server…' },
    };
  },
  async probe(io) {
    const state = safeState(io);
    if (!state.origin) return { id: this.id, ran: false, legs: [], notes: [], verdict: null };
    const hints = state.status === 'env' ? HINTS.env : HINTS.saved;
    let verify;
    try {
      verify = await io.verify({ input: state.origin, sftp: state.sftp ? formatSftpEndpoint(state.sftp) : '' });
      if (!verify || typeof verify !== 'object') verify = failedVerify();
    } catch { verify = failedVerify(); }
    const api = verify.api || { kind: 'failed' };
    const sftp = verify.sftp || { kind: 'failed', host: '', port: 0 };
    const legs = [
      { id: 'api', label: LEG_SERVER, state: apiState(api), text: apiSentence(api, hints) },
      { id: 'sftp', label: LEG_SFTP, state: sftpState(sftp), text: sftpSentence(sftp, hints), detail: sftp.kind === 'ok' && sftp.fingerprint ? `Host key fingerprint ${sftp.fingerprint}` : '' },
    ];
    const notes = [];
    // The SFTP leg already says "not needed" when the server does not sync; saying it twice helps no one.
    const syncText = sftp.kind === 'not-needed' ? '' : syncSentence(verify.sync && verify.sync.kind);
    if (syncText) notes.push(syncText);
    return { id: this.id, ran: true, legs, notes, verdict: verdictOf(verify) };
  },
};

function safeState(io) {
  try {
    const s = io.serverState();
    return s && typeof s === 'object' ? s : { status: 'unreadable', origin: null, sftp: null };
  } catch { return { status: 'unreadable', origin: null, sftp: null }; }
}

const CHECKS = Object.freeze([serverConnection]);

// --- The view --------------------------------------------------------------------------------------------

/**
 * @param {{ serverState: () => object, verify: (fields: {input: string, sftp: string}) => Promise<object> }} io
 *   serverState  the server setting in force (server-config.js readServerConfigState shape)
 *   verify       the setup verify over the real network (setup-verify.js verifySetup with main's deps)
 * @param {{ checks?: ReadonlyArray<object> }} [options]  the registry; tests slot a check in here
 */
function createTroubleshoot(io, { checks = CHECKS } = {}) {
  const byId = new Map(checks.map((c) => [c.id, c]));
  const inFlight = new Map(); // one live probe per check at a time; a second ask joins the first

  function find(id) { return typeof id === 'string' ? byId.get(id) || null : null; }

  function list() { return checks.map((c) => ({ id: c.id, title: c.title })); }

  function describe(id) {
    const check = find(id);
    if (!check) return null;
    try { return check.describe(io); } catch { return { id: check.id, title: check.title, intro: '', facts: [], legs: [], canProbe: false, note: "This check couldn't read what is set up.", action: null }; }
  }

  function probe(id) {
    const check = find(id);
    if (!check) return Promise.resolve(null);
    if (inFlight.has(id)) return inFlight.get(id);
    const p = (async () => {
      try { return await check.probe(io); } catch { return { id: check.id, ran: false, legs: [], notes: [], verdict: { state: 'bad', text: "This check couldn't run. Try again." } }; }
    })().finally(() => inFlight.delete(id));
    inFlight.set(id, p);
    return p;
  }

  return { checks: list, describe, probe };
}

module.exports = { createTroubleshoot, CHECKS, apiSentence, sftpSentence, syncSentence, verdictOf, apiState, sftpState, HINTS };

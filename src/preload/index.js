'use strict';

/*
 * The typed capability preload — the primary control on how far a renderer compromise can reach.
 *
 * Invariants enforced here:
 *   - Secrets flow in, never out. No method returns key material, a passphrase, or a token.
 *   - No generic IO. There is no readFile / writeFile / process spawn / generic fetch / arbitrary
 *     external-URL open — only enumerated, high-level intents.
 *   - Capability, not ambient authority. `window.dockvault` is the only exposed surface, via
 *     contextBridge from a context-isolated, sandboxed preload; every channel name is a fixed
 *     literal, never a caller-supplied string.
 *
 * This surface is deliberately minimal: the capabilities that need no background helper (app facts
 * and the inert deep-link event stream), plus a READ-ONLY view of sync status. Unlock, session,
 * conflict, and folder-picking capabilities are added alongside the components that back them. A
 * test asserts no forbidden name ever appears here.
 *
 * The sync view is observe-only and cred-free: it returns the one computed status the main process
 * already renders to the tray (states, labels, symbolic reasons) and never a credential, host key,
 * token, or raw helper output. It exposes no way to start, stop, or configure sync from the renderer
 * — those remain main-driven so the lock, latch, and refresh gates can never be bypassed from a page.
 *
 * The sync setup wizard is the one place a page takes part in setting sync up, and it is a conversation
 * main leads: main poses a typed question (which vault, whether to choose a folder, whether to consent)
 * and the page hands back a choice among what was offered. The page never names a folder (main opens the
 * OS picker), never supplies a config, and never picks outside the server's list; main checks every
 * answer. Only the shell's own wizard page, in its own window, passes the sender gate for these channels.
 */

const { contextBridge, ipcRenderer } = require('electron');

// Enumerated event channels the renderer may subscribe to (main -> renderer). No wildcard.
const EVENT_CHANNELS = Object.freeze(['deeplink', 'lockstate', 'syncstatus', 'wizard', 'manage']);

function subscribe(channel, cb) {
  if (!EVENT_CHANNELS.includes(channel)) throw new Error('unknown event channel');
  if (typeof cb !== 'function') throw new Error('callback required');
  const listener = (_event, payload) => { try { cb(payload); } catch { /* a renderer callback error is not ours to handle */ } };
  ipcRenderer.on(`dockvault:evt:${channel}`, listener);
  return () => ipcRenderer.removeListener(`dockvault:evt:${channel}`, listener);
}

const api = Object.freeze({
  app: Object.freeze({
    // Non-secret app facts. Returns { version, platform, channel, keyProtection, persistence } for any
    // page, and for the SHELL'S OWN pages only, WHICH BUILD this is: `build` ({ version, commit, date,
    // stamped }), `buildLine` (the one line main already composed for showing, build-stamp.js) and
    // `buildNote` (what "not stamped" means, or null). Those three are gated because the interface the
    // server supplies runs on this same origin with this same preload, and the commit would tell it
    // exactly which build a computer runs; a page that is not the shell's simply gets the fields absent.
    // Still never a path, host, credential, or build-machine detail — a short commit and a date only.
    info: () => ipcRenderer.invoke('dockvault:app.info'),
    // Deep-link (dockvault://) events. Handling is benign navigation only and is default-deny in the
    // main process; it never auto-triggers a confirmation-gated action. Returns an unsubscribe fn.
    onDeepLink: (cb) => subscribe('deeplink', cb),
  }),
  lock: Object.freeze({
    // Observe the authoritative lock state (main -> renderer). The main process is the single source
    // of truth; the renderer only reflects it and never holds a divergent unlocked state. The payload
    // carries no key material — only { state, reason }. Returns an unsubscribe fn.
    onState: (cb) => subscribe('lockstate', cb),
  }),
  server: Object.freeze({
    // The setup screen's view of the server setting: { mode, status, host, sftp } — mode 'first-run' |
    // 'change', status 'absent' | 'unreadable' | 'ok' | 'env', the host of the origin in force and the
    // saved SFTP address as "host:port" (both for pre-filling). Never the file's contents, never whether
    // the file exists beyond that status.
    state: () => ipcRenderer.invoke('dockvault:server.state'),
    // The verify step: main normalises the typed address and checks it against the fixed health route,
    // asks the fixed device route whether the server supports syncing, and reaches the typed SFTP
    // address for its host key (no other URL or port is ever contacted). Writes nothing. Returns
    // { api: { kind, host? }, sync: { kind }, sftp: { kind, host, port, fingerprint? }, proceed } — kinds
    // and hosts only, never an error, a key, or a credential.
    check: (input, sftp) => ipcRenderer.invoke('dockvault:server.check', { input: String(input == null ? '' : input), sftp: String(sftp == null ? '' : sftp) }),
    // Hand the typed address and SFTP address to the main process, which verifies them again (it never
    // trusts the page's lights) and saves them only when both verified. The renderer never touches the
    // file. Returns the typed outcome { kind, origin?, host?, verify }; kind 'needs-confirm' means a saved
    // setting exists that could not be read and the person must confirm replacing it (replaceUnreadable:
    // true) before anything is written; 'not-verified' means the SFTP door did not check out. On
    // ok/degraded, main then loads the sign-in page from the new server; the page just shows "Connected".
    connect: (input, sftp, options) => ipcRenderer.invoke('dockvault:server.connect', { input: String(input == null ? '' : input), sftp: String(sftp == null ? '' : sftp), replaceUnreadable: !!(options && options.replaceUnreadable) }),
  }),
  sync: Object.freeze({
    // Read the current computed sync status on demand. Cred-free: { state, label, reason, vaults[],
    // condition } — never a credential, host key, or token. Observe-only, no control surface.
    status: () => ipcRenderer.invoke('dockvault:sync.status'),
    // Observe status changes (main -> renderer), same cred-free shape. Returns an unsubscribe fn.
    onStatus: (cb) => subscribe('syncstatus', cb),
    // Observe-only by design: there is deliberately NO renderer method to start, configure, or list
    // sync. Enabling/stopping is driven from the tray in the main process, so a compromised page can
    // neither initiate the native flow nor supply a folder or config.
  }),
  wizard: Object.freeze({
    // The question the wizard is currently posing ({ id, kind, ...facts } or null) — for the page's first
    // paint and after a reload. Facts are names, hosts, ports, a folder path main itself picked, and flags.
    state: () => ipcRenderer.invoke('dockvault:wizard.state'),
    // Answer the question with this id. The value is a choice among what the question offered (a vault id
    // from its list, a boolean, a fixed word, or a typed address for the file-transfer question); an answer
    // to any other id is ignored. Resolves true when it was taken.
    answer: (id, value) => ipcRenderer.invoke('dockvault:wizard.answer', { id: Number(id), value }),
    // End the wizard where it stands and close its window. Nothing is written after this.
    close: () => ipcRenderer.invoke('dockvault:wizard.close'),
    // Bring the main DockVault window forward (to sign in, or to open a vault) — the app's own window, nothing else.
    openApp: () => ipcRenderer.invoke('dockvault:wizard.open-app'),
    // Each new question (main -> renderer). Returns an unsubscribe fn.
    onQuestion: (cb) => subscribe('wizard', cb),
  }),
  manage: Object.freeze({
    // The Computers view's model, built by main (manage-view.js): the account's registered computers, this
    // computer's vault cards (with their local folder — shown here, never sent anywhere), the others' metadata.
    // Names, ids, dates, states, and the folder paths main itself holds; never a credential or a raw error.
    model: () => ipcRenderer.invoke('dockvault:manage.model'),
    // Carry out an action the person confirmed on the page: { kind, deviceId?, vaultId? } with kind one of
    // revoke-grant | revoke-computer | remove-computer | stop-sync | sync-now | relocate-folder. Main checks the ids' shape and
    // decides; the server is the authority. Resolves { ok, reason?, retryInSec? } (retryInSec rides with a sync-now turned
    // away for its cooldown or the server's refusal back-off).
    act: (action) => ipcRenderer.invoke('dockvault:manage.act', { kind: String(action && action.kind), deviceId: action && action.deviceId != null ? String(action.deviceId) : undefined, vaultId: action && action.vaultId != null ? String(action.vaultId) : undefined }),
    // Open the sync setup wizard (the app's own window), and close this one.
    openSetup: () => ipcRenderer.invoke('dockvault:manage.open-setup'),
    // Open the dedicated sync-status window (main owns it; this only asks).
    openStatus: () => ipcRenderer.invoke('dockvault:manage.open-status'),
    close: () => ipcRenderer.invoke('dockvault:manage.close'),
    // Something the view shows changed (a sync ran, a set-up finished): reload. Returns an unsubscribe fn.
    onChanged: (cb) => subscribe('manage', cb),
  }),
  status: Object.freeze({
    // The dedicated sync-status view's model, built by main (status-view.js): one row per synced folder with
    // its state, the honest sentence for that state, its transfer numbers and when it last finished.
    //
    // A SEPARATE CHANNEL from `sync.status()` on purpose. That one is reachable from the window hosting the
    // vault's own web interface, which is why it strips each vault's outcome DETAIL — the file that would not
    // go, the size the server stated. The sentence below is composed FROM that detail, so it travels only
    // here, on a channel main gates to this page and this window.
    //
    // Read-only, like the Computers model. There is deliberately no way from this page to start, stop or
    // change a sync: those live in the tray, and a renderer that could reach them would be attack surface
    // for a convenience that already exists.
    model: () => ipcRenderer.invoke('dockvault:status.model'),
    // A sync ran, or a set-up finished: re-ask for the model. Returns an unsubscribe fn.
    onChanged: (cb) => subscribe('manage', cb),
  }),
  troubleshoot: Object.freeze({
    // The Troubleshoot view. Main owns the list of checks and everything each one does; the page only names a
    // check by the id main gave it and renders what comes back. Nothing here writes, and nothing takes an
    // address from the page. The server check reaches the SAVED server setting and nothing else; the folder
    // check reaches no network at all and names LOCAL FOLDER PATHS, which is the one place this channel does
    // — a missing folder cannot be answered without saying which folder and where it was expected. Gated to
    // this page and this window, the same as the Computers view, which shows the same paths for the same reason.
    // The checks on offer: [{ id, title }].
    checks: () => ipcRenderer.invoke('dockvault:troubleshoot.checks'),
    // What is set up, for one check: { id, title, intro, facts: [{ label, value, mono }], legs: [{ id, label }],
    // canProbe, note, action } — the saved server host and ports, never a credential or a local path.
    describe: (id) => ipcRenderer.invoke('dockvault:troubleshoot.describe', { id: String(id) }),
    // Run the check's live probe from this computer now. Resolves { id, ran, legs: [{ id, label, state, text,
    // detail }], notes, verdict: { state, text } } — kinds and sentences, a public host-key fingerprint at most.
    probe: (id) => ipcRenderer.invoke('dockvault:troubleshoot.probe', { id: String(id) }),
    // Open the server setup (the same screen the app opens with, or the change-server flow with its consent).
    openServerSetup: () => ipcRenderer.invoke('dockvault:troubleshoot.open-server-setup'),
    // Point DockVault at a synced folder again, or stop syncing it — the same confirmed flow the tray
    // offers. The page names only a vault id a check gave it; main checks its shape and owns the flow.
    relocateFolder: (vaultId) => ipcRenderer.invoke('dockvault:troubleshoot.relocate', { vaultId: String(vaultId) }),
    close: () => ipcRenderer.invoke('dockvault:troubleshoot.close'),
  }),
});

contextBridge.exposeInMainWorld('dockvault', api);

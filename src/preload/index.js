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
 */

const { contextBridge, ipcRenderer } = require('electron');

// Enumerated event channels the renderer may subscribe to (main -> renderer). No wildcard.
const EVENT_CHANNELS = Object.freeze(['deeplink', 'lockstate', 'syncstatus']);

function subscribe(channel, cb) {
  if (!EVENT_CHANNELS.includes(channel)) throw new Error('unknown event channel');
  if (typeof cb !== 'function') throw new Error('callback required');
  const listener = (_event, payload) => { try { cb(payload); } catch { /* a renderer callback error is not ours to handle */ } };
  ipcRenderer.on(`dockvault:evt:${channel}`, listener);
  return () => ipcRenderer.removeListener(`dockvault:evt:${channel}`, listener);
}

const api = Object.freeze({
  app: Object.freeze({
    // Non-secret app facts. Returns { version, platform, channel }.
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
});

contextBridge.exposeInMainWorld('dockvault', api);

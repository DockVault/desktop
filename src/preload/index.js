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
 * This surface is deliberately minimal for the shell: the capabilities that need no background
 * helper (app facts and the inert deep-link event stream). Sync, unlock, session, conflict, and
 * folder-picking capabilities are added alongside the components that back them. A test asserts no
 * forbidden name ever appears here.
 */

const { contextBridge, ipcRenderer } = require('electron');

// Enumerated event channels the renderer may subscribe to (main -> renderer). No wildcard.
const EVENT_CHANNELS = Object.freeze(['deeplink']);

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
});

contextBridge.exposeInMainWorld('dockvault', api);

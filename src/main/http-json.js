'use strict';

/*
 * The main process's one JSON request helper, in the injected-fetch shape the sync modules expect:
 * `httpJson(url, init)` where `init` is a fetch-style options object ({ method, headers, body }), NOT
 * a bare header map, resolving { ok, status, json() }. A request timeout and a response-size cap keep
 * a hung or oversized server from stalling the caller. It carries only what the caller puts in the
 * request (the account session token among them); it never holds or returns a vault credential.
 *
 * It is built on the network module handed in — in the app, Electron's `net`, whose certificate
 * checks use the OPERATING SYSTEM's trust store, exactly as the interface's own requests do through
 * the proxy. Node's https would use Node's bundled roots instead, so a self-hosted server whose
 * certificate comes from an internal authority installed on this computer would be accepted by the
 * interface and refused by every background call, and the setup screen's remedy ("install the
 * certificate on this computer") would be a false promise. One trust store for the whole app.
 *
 * Tests hand in a fetch of their own (Node's global fetch against a loopback server) — the contract
 * is the same, so the callers cannot tell the difference.
 */

const TIMEOUT_MS = 15000;
const MAX_BYTES = 5 * 1024 * 1024;

// Every transport throw below carries a CODE, because the classifier that decides retry-or-give-up
// (net-errors transportCode, which device-http imports) reads e.code. Without a code a timed-out or
// over-cap request is classified as OUR bug rather than a transient network failure, and an internal
// error is never retried — a request that timed out would fail permanently. The choice of code is
// load-bearing too: neither is a "never sent" code, because a timeout or a capped response means the
// request WAS sent and only the answer was lost.
const TIMED_OUT = 'ETIMEDOUT';
const TOO_LARGE = 'ERESPONSE_TOO_LARGE';
const coded = (message, code) => Object.assign(new Error(message), { code });

/**
 * @param {{ fetch: (url: string, init: object) => Promise<Response> }} net  Electron's net (or any fetch holder)
 * @returns {(url: string, init?: { method?: string, headers?: object, body?: string|Buffer }) => Promise<{ ok: boolean, status: number, json: () => Promise<any> }>}
 */
function createHttpJson(net, { timeoutMs = TIMEOUT_MS, maxBytes = MAX_BYTES } = {}) {
  if (!net || typeof net.fetch !== 'function') throw new TypeError('httpJson needs a network module with fetch');
  return async function httpJson(url, init = {}) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(coded('request timed out', TIMED_OUT)), timeoutMs);
    if (timer.unref) timer.unref();
    try {
      // Copy the caller's headers so their object is never mutated, and drop any Content-Length: the
      // network layer sets the length itself for a known body, and a caller-supplied one is a restricted
      // header that makes the whole request fail.
      const headers = {};
      for (const [k, v] of Object.entries(init.headers || {})) if (k.toLowerCase() !== 'content-length') headers[k] = v;
      const hasBody = init.body != null;
      // Redirects are refused by default: following one would carry the session token (or a
      // credential request) to wherever the server pointed, possibly another origin. A caller may opt
      // in with redirect: 'follow' ONLY for a request that carries no Authorization — the setup
      // screen's health check, which has nothing to leak and needs to land on a server that sits
      // behind a redirecting front; it then reads the final URL back from `url`. The opt-in is refused
      // outright, before any request, when a bearer is present.
      const carriesAuth = Object.keys(headers).some((k) => k.toLowerCase() === 'authorization');
      const mayFollow = init.redirect === 'follow';
      if (mayFollow && carriesAuth) throw new Error('a request carrying a credential may not follow redirects');
      if (mayFollow && hasBody) throw new Error('a request with a body may not follow redirects');
      if (mayFollow) return await followByHand(net, url, headers, controller, maxBytes);
      const res = await net.fetch(url, {
        method: init.method || 'GET',
        headers,
        body: hasBody ? init.body : undefined,
        signal: controller.signal,
        credentials: 'omit',   // never the interface's cookies or storage
        cache: 'no-store',
        redirect: 'error',
      });
      // Read as a stream and stop the moment the cap is passed, so a hostile server cannot make the
      // helper buffer an arbitrary body before refusing it.
      const chunks = [];
      let total = 0;
      if (res.body && typeof res.body.getReader === 'function') {
        const reader = res.body.getReader();
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          total += value.length;
          if (total > maxBytes) { controller.abort(coded('response too large', TOO_LARGE)); throw coded('response too large', TOO_LARGE); }
          chunks.push(Buffer.from(value));
        }
      } else {
        const buf = Buffer.from(await res.arrayBuffer());
        if (buf.length > maxBytes) throw coded('response too large', TOO_LARGE);
        chunks.push(buf);
      }
      const text = Buffer.concat(chunks).toString('utf8');
      // `url` is where the reply actually came from (after a followed redirect, if one was allowed).
      return { ok: res.ok, status: res.status, url: typeof res.url === 'string' && res.url ? res.url : url, json: async () => JSON.parse(text) };
    } finally {
      clearTimeout(timer);
    }
  };
}

// A credential-free GET that may follow redirects, walked hop by hop so the final URL is known
// exactly (the network layer does not report where a followed request landed). Electron's request
// API announces each redirect target and then cancels the request; a fetch-only transport (the
// tests) answers the 3xx itself. At most a few hops; every hop is a plain GET with the same
// credential-free headers.
const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);
const MAX_HOPS = 5;

async function followByHand(net, startUrl, headers, controller, maxBytes) {
  let current = startUrl;
  for (let hop = 0; ; hop++) {
    const step = typeof net.request === 'function'
      ? await requestOnce(net, current, headers, controller, maxBytes)
      : await fetchOnce(net, current, headers, controller, maxBytes);
    if (step.redirectTo) {
      if (hop >= MAX_HOPS) throw new Error('too many redirects');
      current = new URL(step.redirectTo, current).href;
      continue;
    }
    const text = step.text;
    return { ok: step.status >= 200 && step.status < 300, status: step.status, url: current, json: async () => JSON.parse(text) };
  }
}

async function fetchOnce(net, url, headers, controller, maxBytes) {
  const res = await net.fetch(url, { method: 'GET', headers, signal: controller.signal, credentials: 'omit', cache: 'no-store', redirect: 'manual' });
  const location = res.headers && typeof res.headers.get === 'function' ? res.headers.get('location') : null;
  if (REDIRECT_STATUSES.has(res.status) && location) {
    try { await res.arrayBuffer(); } catch { /* the redirect body is irrelevant */ }
    return { redirectTo: location };
  }
  const buf = Buffer.from(await res.arrayBuffer());
  if (buf.length > maxBytes) throw coded('response too large', TOO_LARGE);
  return { status: res.status, text: buf.toString('utf8') };
}

function requestOnce(net, url, headers, controller, maxBytes) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const done = (fn) => { if (!settled) { settled = true; fn(); } };
    let redirectTo = null;
    let req;
    try { req = net.request({ url, method: 'GET', redirect: 'manual', credentials: 'omit', useSessionCookies: false }); }
    catch (e) { return reject(e); }
    for (const [k, v] of Object.entries(headers)) { try { req.setHeader(k, String(v)); } catch { /* a header the layer refuses is dropped */ } }
    // Not calling followRedirect() makes the network layer cancel the request; the target is kept.
    req.on('redirect', (_status, _method, redirectUrl) => { redirectTo = redirectUrl; });
    req.on('response', (res) => {
      const chunks = [];
      let total = 0;
      res.on('data', (c) => {
        total += c.length;
        if (total > maxBytes) { try { req.abort(); } catch { /* already gone */ } done(() => reject(coded('response too large', TOO_LARGE))); return; }
        chunks.push(Buffer.from(c));
      });
      res.on('end', () => done(() => resolve({ status: res.statusCode, text: Buffer.concat(chunks).toString('utf8') })));
      res.on('error', (e) => done(() => reject(e)));
    });
    // A cancelled redirect surfaces as an error/abort/close after the 'redirect' event; anything else on
    // those events is only a failure when no response is being read (a normal transaction closes too).
    const settleCancelled = (e) => { if (redirectTo) done(() => resolve({ redirectTo })); else if (e) done(() => reject(e)); };
    req.on('error', settleCancelled);
    req.on('abort', () => settleCancelled(redirectTo ? null : new Error('request aborted')));
    req.on('close', () => settleCancelled(null));
    controller.signal.addEventListener('abort', () => { try { req.abort(); } catch { /* already gone */ } done(() => reject(coded('request timed out', TIMED_OUT))); });
    req.end();
  });
}

module.exports = { createHttpJson, TIMEOUT_MS, MAX_BYTES };

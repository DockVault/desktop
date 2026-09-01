'use strict';

/*
 * The transparent API forwarder.
 *
 * The reused UI computes its API base from its own origin, so every API/auth call the UI makes goes
 * to the shell's origin. For those non-asset paths the shell forwards the request to the configured
 * server through the main process's network stack and returns the response verbatim.
 *
 * Transparent means transparent: the request's own headers (including the Authorization bearer the
 * UI attached) are passed through unchanged, and the forwarder adds NO credential of its own. It
 * holds no token; a request that arrives without one is forwarded without one and the server answers
 * with a 401. The Host header is dropped so the network stack sets it for the real target.
 *
 * Because the renderer only ever talks to its own origin, the shell is the single point that reaches
 * the network — which is what lets the content policy keep connect-src to 'self'.
 */

// Headers that must not be copied verbatim to the upstream request.
const HOP_BY_HOP = new Set(['host', 'connection', 'keep-alive', 'proxy-authenticate',
  'proxy-authorization', 'te', 'trailer', 'transfer-encoding', 'upgrade']);

function buildTargetUrl(requestUrl, serverOrigin) {
  const inUrl = new URL(requestUrl);
  // Preserve path + query exactly; the server owns the routing.
  return serverOrigin.replace(/\/+$/, '') + inUrl.pathname + inUrl.search;
}

/**
 * @param {Request} request      the incoming protocol request
 * @param {string}  serverOrigin e.g. https://vault.example.com
 * @param {{fetch: Function}} netModule Electron's `net` (injectable for tests)
 * @returns {Promise<Response>}
 */
async function proxyRequest(request, serverOrigin, netModule) {
  const target = buildTargetUrl(request.url, serverOrigin);

  const headers = new Headers(request.headers);
  for (const h of HOP_BY_HOP) headers.delete(h);

  const init = { method: request.method, headers, redirect: 'manual' };
  if (request.method !== 'GET' && request.method !== 'HEAD') {
    init.body = request.body;
    init.duplex = 'half'; // required when streaming a request body
  }

  try {
    return await netModule.fetch(target, init);
  } catch (e) {
    // A transport failure is reported as 502 so the UI sees a network error, not a crash. No detail
    // is leaked to the renderer beyond the status.
    return new Response('upstream unreachable', {
      status: 502,
      headers: { 'content-type': 'text/plain; charset=utf-8' },
    });
  }
}

module.exports = { proxyRequest, buildTargetUrl };

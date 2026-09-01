'use strict';

/*
 * A minimal main-process JSON GET that conforms to the injected-fetch contract the sync modules expect:
 * `httpJson(url, init)` where `init` is a fetch-style options object ({ method, headers }), NOT a bare
 * header map. The sync modules call it exactly as they would call `fetch`, so the request options — the
 * Authorization header among them — must be read out of `init`, never treated as the header map itself.
 *
 * A request timeout and a response-size cap keep a hung or oversized server from stalling the caller.
 * This carries only the account session token supplied by the caller; it never holds or returns a
 * vault credential.
 */

const TIMEOUT_MS = 15000;
const MAX_BYTES = 5 * 1024 * 1024;

/**
 * @param {string} url
 * @param {{ method?: string, headers?: object, body?: string|Buffer }} [init]  fetch-style options (NOT a flat header map)
 * @returns {Promise<{ ok: boolean, status: number, json: () => Promise<any> }>}
 */
function httpJson(url, init = {}) {
  const mod = url.startsWith('https:') ? require('node:https') : require('node:http');
  const method = init.method || 'GET';
  const headers = { ...(init.headers || {}) }; // copy, so the caller's object is never mutated
  const hasBody = init.body != null;
  const bodyBuf = hasBody ? Buffer.from(init.body) : null; // the caller pre-serialises (e.g. JSON.stringify)
  // A request body must actually be written AND length-declared — a fetch-style caller (e.g. the cred
  // mint POST) sets init.body, and dropping it would send an empty request, the same failure class the
  // vault-list auth bug was. Set Content-Length for the known-length body so it is not sent chunked;
  // honour a Content-Type the caller already set (never override or invent one).
  if (hasBody && !Object.keys(headers).some((k) => k.toLowerCase() === 'content-length')) {
    headers['Content-Length'] = String(bodyBuf.length);
  }
  return new Promise((resolve, reject) => {
    const req = mod.request(url, { method, headers }, (res) => {
      let s = ''; let bytes = 0; let capped = false;
      res.on('data', (c) => {
        bytes += c.length;
        if (bytes > MAX_BYTES) { capped = true; req.destroy(new Error('response too large')); return; }
        s += c;
      });
      res.on('end', () => { if (!capped) resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: async () => JSON.parse(s || 'null') }); });
    });
    req.setTimeout(TIMEOUT_MS, () => req.destroy(new Error('request timed out')));
    req.on('error', reject);
    if (hasBody) req.write(bodyBuf);
    req.end();
  });
}

module.exports = { httpJson };

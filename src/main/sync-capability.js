'use strict';

/*
 * Does this server support syncing from a computer at all? Answered at setup time, BEFORE anyone signs
 * in, so a person is told plainly up front instead of finding out when sync fails later.
 *
 * The signal is the presence of the device routes, not a version number (the version shape is the
 * server's to change, and a fork or a front may rewrite it). The device list route needs an account
 * session, so an unauthenticated request to it can only be refused — and HOW it is refused is the
 * answer: a 401/403 means the route exists and guards itself (the server speaks sync); a 404 means the
 * route is not there (a server from before device sync existed). Anything else — a 5xx, a transport
 * failure, an odd 2xx from a front that answers everything — is 'unknown': the app says it could not
 * tell, never that the server is old, and never that it is fine.
 *
 * Same fixed route the signed-in capability check uses (device-register.js); this is its credential-free
 * twin for the setup screen. Nothing is sent but a GET; nothing is read from the body.
 */

async function probeSyncCapability(serverOrigin, { httpJson }) {
  let res;
  try {
    res = await httpJson(`${serverOrigin}/devices`, { method: 'GET', headers: { Accept: 'application/json' } });
  } catch { return { kind: 'unknown' }; }
  const s = (res && res.status) || 0;
  if (s === 401 || s === 403) return { kind: 'supported' };
  if (s === 404) return { kind: 'unsupported' };
  if (s === 200) {
    // A 200 with a real device list would mean an unauthenticated device route — not a vault behaviour, but the
    // route being there is still the fact asked for. Anything else answering 200 (an index page, a captive
    // front) is not a signal either way.
    let body = null;
    try { body = await res.json(); } catch { body = null; }
    return { kind: body && typeof body === 'object' && Array.isArray(body.devices) ? 'supported' : 'unknown' };
  }
  return { kind: 'unknown' };
}

module.exports = { probeSyncCapability };

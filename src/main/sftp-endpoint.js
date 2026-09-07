'use strict';

/*
 * The SFTP endpoint a person enters on the setup screen — "host:port", or a bare host on the default
 * port — and what it is for once saved.
 *
 * A vault deployment publishes two doors: the API (the server address) and SFTP (where synced files
 * actually move). The credential the vault mints for a sync run advertises the SFTP host and port it
 * BELIEVES it serves on, but a deployment that publishes SFTP on a different host port than the one
 * the vault process binds inside its container advertises the inside number, and every sync would
 * quietly connect to the wrong place. So the endpoint the person entered and verified at setup is
 * kept, and at mint time it REPLACES the advertised host and port. The advertised values are still
 * reported alongside so a later diagnostic can say "the server thinks its SFTP is elsewhere".
 *
 * Nothing here touches a credential or a host key: only the host and the port.
 */

const { isIPv6 } = require('node:net');

const DEFAULT_SFTP_PORT = 2222;

// A hostname or IPv4 literal (labels of letters, digits, hyphens), matching what the mint accepts.
const HOST_SHAPE = /^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)*$/;

function validPort(n) { return Number.isInteger(n) && n >= 1 && n <= 65535; }
// A bracket-free IPv6 literal must be a real address, so a stray trailing colon ("1.2.3.4:22:") is not
// mistaken for one and blamed on the network later.
function validHost(h) { return typeof h === 'string' && h.length > 0 && h.length <= 253 && (HOST_SHAPE.test(h) || isIPv6(h)); }

/**
 * Parse what was typed. Accepts "host", "host:port", "[v6]:port", "[v6]", and tolerates a pasted
 * "sftp://host:port" or a trailing slash. Returns { kind: 'ok', host, port } or { kind: 'empty' } or
 * { kind: 'malformed' }. A missing port means the default.
 */
function parseSftpEndpoint(input) {
  let s = String(input == null ? '' : input).trim();
  if (!s) return { kind: 'empty' };
  s = s.replace(/^sftp:\/\//i, '').replace(/^ssh:\/\//i, '').replace(/\/+$/, '');
  if (!s || /\s/.test(s) || /\//.test(s)) return { kind: 'malformed' };
  let host; let portText = null;
  const bracket = s.match(/^\[([^\]]+)\](?::(\d{1,5}))?$/);
  if (bracket) {
    if (!isIPv6(bracket[1])) return { kind: 'malformed' }; // brackets are for an IPv6 literal only
    host = bracket[1]; portText = bracket[2] == null ? null : bracket[2];
  }
  else {
    const colons = (s.match(/:/g) || []).length;
    if (colons > 1) { host = s; }                                    // a bare IPv6 literal, no port
    else if (colons === 1) { const i = s.lastIndexOf(':'); host = s.slice(0, i); portText = s.slice(i + 1); }
    else host = s;
  }
  if (!validHost(host)) return { kind: 'malformed' };
  let port = DEFAULT_SFTP_PORT;
  if (portText != null) {
    if (!/^\d{1,5}$/.test(portText)) return { kind: 'malformed' };
    port = Number(portText);
    if (!validPort(port)) return { kind: 'malformed' };
  }
  return { kind: 'ok', host, port };
}

/** "host:port" for the screen (an IPv6 host in brackets). */
function formatSftpEndpoint(endpoint) {
  if (!endpoint || !validHost(endpoint.host) || !validPort(endpoint.port)) return '';
  const h = endpoint.host.includes(':') ? `[${endpoint.host}]` : endpoint.host;
  return `${h}:${endpoint.port}`;
}

/** A saved endpoint read back from disk is used only when it is whole and well-formed. */
function isSftpEndpoint(value) {
  return !!(value && typeof value === 'object' && validHost(value.host) && validPort(value.port));
}

/** The endpoint to suggest for a server address: its hostname on the default SFTP port. */
function suggestSftpEndpoint(serverOrigin) {
  try { return { host: new URL(serverOrigin).hostname.replace(/^\[|\]$/g, ''), port: DEFAULT_SFTP_PORT }; }
  catch { return null; }
}

/**
 * Apply the saved endpoint to a freshly minted credential bundle: the entered host and port replace the
 * advertised ones IN PLACE. The bundle carries a plaintext credential that the credential cache blanks
 * when it is done with it, so exactly one object must ever hold it — a copy would keep the password
 * alive out of the cache's reach. Returns the same bundle plus what the server had advertised and whether
 * anything actually changed. With no saved endpoint the bundle is left as-is and `overridden` is false,
 * so set-ups made before the endpoint existed keep working.
 */
function applySftpEndpoint(bundle, endpoint) {
  if (!bundle || typeof bundle !== 'object') throw new TypeError('a credential bundle is required');
  const advertised = { host: bundle.host, port: bundle.port };
  if (!isSftpEndpoint(endpoint)) return { bundle, advertised, overridden: false };
  const overridden = bundle.host !== endpoint.host || bundle.port !== endpoint.port;
  bundle.host = endpoint.host;
  bundle.port = endpoint.port;
  return { bundle, advertised, overridden };
}

module.exports = { parseSftpEndpoint, formatSftpEndpoint, isSftpEndpoint, suggestSftpEndpoint, applySftpEndpoint, DEFAULT_SFTP_PORT };

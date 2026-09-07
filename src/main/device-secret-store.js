'use strict';

/*
 * Durable, OS-encrypted store for the per-device sync identity.
 *
 * TWO artifacts live side by side in the app data directory:
 *   - device-secret.bin — the SOURCE OF TRUTH: a safeStorage-encrypted JSON blob
 *     { v, deviceId, secret, epoch, serverOrigin }. The bearer SECRET and the rotation EPOCH live ONLY
 *     inside this encrypted blob, never in plaintext. Confidentiality rests on safeStorage (a user-bound
 *     DPAPI/keychain key): a stolen file is useless without the user's own OS secret store.
 *     serverOrigin is the server that issued the secret, bound INSIDE the encrypted blob (never in a
 *     plaintext file, which could be rewritten to point this computer's secret at a different server):
 *     a device secret is only ever presented to the server it was registered with.
 *   - device-id.json — an ADVISORY plaintext sidecar holding ONLY { v, deviceId } (NEVER the secret,
 *     NEVER the epoch). Its sole purpose: if the encrypted blob later becomes unreadable (a rotated OS
 *     keychain), a reset path can still name the exact old server device row to self-revoke under the
 *     account session — so a keychain rotation ends in a cleanly-revoked device, not an orphaned live
 *     one. It is DECOUPLED from the four-state read and is NEVER consulted by readDeviceSecret.
 *
 * The five-state read (readDeviceSecret) is determined SOLELY by the encrypted blob and NEVER collapses
 * its outcomes to one null (the mistake token-store.loadSession makes, whose single catch->null
 * conflates a locked keychain with "no session"):
 *   - 'no-secure-store' — no secure backend (unavailable, or the hardcoded-key fallback). The caller
 *     degrades and NEVER treats this as "no device".
 *   - 'absent' — a secure backend and genuinely no blob file (ENOENT). The ONLY status that permits
 *     registration.
 *   - 'unreadable' — a blob exists but cannot be turned into a valid secret THIS moment: a non-ENOENT
 *     read error, a decrypt throw (locked/rotated keychain), a blob that does not JSON.parse to the
 *     required shape, or an empty/garbage secret inside it. TRANSIENT — wait/retry and ask the user to
 *     unlock the keychain; NEVER re-register (that would duplicate the device, burn a per-device cap
 *     slot, and orphan the still-valid server secret). unreadable != absent.
 *   - 'absent-for-this-server' — a valid blob, but registered with a DIFFERENT server than the one
 *     configured now (its bound origin differs; `otherOrigin` names it). The secret is NOT returned:
 *     presenting one server's secret to another is exactly what the binding prevents. This is neither a
 *     locked keychain nor permission to register: registering with the new server first goes through
 *     the explicit forget path, so a still-valid other-server identity is never silently overwritten.
 *   - 'stale' — a valid identity for this server whose secret is known to be RETIRED on the server (a
 *     rotation's answer was lost: the refresh was refused as stale, or the server rotated but the new
 *     secret could not be kept here). The secret is withheld: presenting a retired secret past the
 *     server's grace window is a replay that suspends the device. Recorded by markDeviceSecretStale as a
 *     small non-secret marker beside the blob so it SURVIVES a restart, and cleared only when the identity
 *     itself is cleared or replaced (a stale identity is forgotten and set up again, never repaired). A
 *     second marker, written by markDeviceSecretRotating BEFORE a rotation request goes out and removed
 *     only once the new secret is stored (or the server has definitely answered without rotating), covers
 *     a crash in between: a survivor of that window reads 'stale' the same way, since the secret on disk
 *     may already be retired.
 *   - 'ok' — decrypted, valid, bound to the configured server, and not marked stale; { deviceId, secret,
 *     epoch } carry the identity.
 *
 * The origin comparison is canonical and fails CLOSED: both sides reduce to URL.origin (lower-cased
 * scheme + host, the default port dropped, path/query/fragment/userinfo dropped); http and https differ,
 * a non-default port is kept, and any value that does not parse — or a blob with no origin — is a
 * mismatch (or unreadable), never a match. A wrong "different server" is a safe refusal; a wrong "same
 * server" would hand the secret to the wrong party.
 *
 * Writes are ATOMIC and DURABLE (mirroring sync-config-store.js saveConfig): encrypt, write a fresh
 * temp file in the same directory, fsync it, then rename it over the target. The live blob is untouched
 * until the rename, so a failed or power-interrupted write can neither truncate the prior-valid secret
 * (the old writeFileSync O_TRUNC would destroy it on any write error) nor leave a torn/partial file
 * that would read as PERMANENTLY 'unreadable' — which would break the "unreadable is transient"
 * contract. A reader always sees the complete old blob or the complete new one, never a partial.
 *
 * The secret is never logged, never sent over IPC, and never exposed to the renderer; it lives in
 * memory only transiently around a register/mint. zeroizeSecret is honest best-effort: an immutable JS
 * string cannot be scrubbed in place (it fills a Buffer, and is a documented no-op for a string), so
 * the real protections are minimal in-memory lifetime + encryption at rest, not a memory wipe.
 *
 * The keychain backend is injected so the fail-closed logic, the atomic write, and the four-state read
 * are unit-testable without a live keychain; the real Electron safeStorage is passed in at runtime.
 */

const fs = require('node:fs');
const path = require('node:path');
const nodeCrypto = require('node:crypto');
const { isSecureBackend, backendName } = require('./token-store');

const BLOB = 'device-secret.bin';   // encrypted source of truth
const SIDECAR = 'device-id.json';   // advisory plaintext { v, deviceId }
const STALE = 'device-secret.stale'; // non-secret marker { v, markedAt }: the stored secret is retired on the server
const ROTATING = 'device-secret.rotating'; // non-secret marker { v, startedAt }: a rotation request is in flight or was cut off
const FILE_MODE = 0o600;            // POSIX defence-in-depth only; safeStorage is the confidentiality anchor
const FORMAT_V = 1;

function blobPath(dir) { return path.join(dir, BLOB); }
function sidecarPath(dir) { return path.join(dir, SIDECAR); }
function stalePath(dir) { return path.join(dir, STALE); }
function rotatingPath(dir) { return path.join(dir, ROTATING); }
function isMarkedStale(dir) { try { return fs.existsSync(stalePath(dir)) || fs.existsSync(rotatingPath(dir)); } catch { return false; } }

// The canonical form of a server origin for binding + comparison, or null when it is not a usable
// http(s) origin. URL.origin lower-cases the scheme and host and drops the default port, the path, the
// query, the fragment and any userinfo, so equal deployments compare equal however they were typed —
// while http vs https and a non-default port stay distinct.
function canonicalOrigin(origin) {
  if (typeof origin !== 'string' || origin.length === 0) return null;
  try {
    const u = new URL(origin);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return null;
    return u.origin === 'null' ? null : u.origin;
  } catch { return null; }
}
// True only when BOTH parse to a usable origin and those origins are identical. Fails closed.
function sameOrigin(a, b) {
  const ca = canonicalOrigin(a); const cb = canonicalOrigin(b);
  return ca !== null && cb !== null && ca === cb;
}

// A non-empty secret is a string OR a Buffer of non-zero length. This rejects undefined/null/'' and a
// zero-length Buffer BEFORE encryption, so a garbage/empty secret can never be sealed into a blob that
// would later read 'ok', mint a credential the server 401s forever, and wedge the device with no path
// to recover (such a blob would be neither 'absent' nor 'unreadable', so it would never re-register).
// It is deliberately NOT a `typeof === 'string'` gate, so a Buffer caller is not broken.
//
// Presence/non-emptiness ONLY — never a token FORMAT check (no fixed length, no base64url/charset
// regex). The secret's shape belongs to the server (today it mints a URL-safe token, but that is the
// server's to change); a desktop-side format assertion would turn every valid secret into 'unreadable'
// the day the server changed its token format — the same permanent-wedge failure this guard exists to
// prevent, in a new coat. The deviceId is likewise validated present-and-non-empty, never as a UUID.
function isNonEmptySecret(secret) {
  if (typeof secret === 'string') return secret.length > 0;
  if (Buffer.isBuffer(secret)) return secret.length > 0;
  return false;
}

// Atomic + durable replace: a fresh temp in the SAME directory, written 0600, fsync'd, then renamed
// over the target (atomic on one filesystem). The live file is untouched until the rename; a crash or a
// failed write leaves either the intact prior file or nothing — never a torn/partial file. The temp is
// removed best-effort on any failure so a failed write leaves no stray fragment.
function atomicWrite(target, data) {
  const dir = path.dirname(target);
  fs.mkdirSync(dir, { recursive: true });
  const tmp = `${target}.${process.pid}.${nodeCrypto.randomBytes(6).toString('hex')}.tmp`;
  let fd = fs.openSync(tmp, 'wx', FILE_MODE); // wx: never clobber an existing name (the suffix is random)
  try {
    fs.writeSync(fd, data);
    fs.fsyncSync(fd);        // the bytes are on disk before the rename publishes them
    fs.closeSync(fd);
    fd = undefined;
    fs.renameSync(tmp, target); // atomic publish: a reader sees complete-old or complete-new, never torn
  } catch (e) {
    if (fd !== undefined) { try { fs.closeSync(fd); } catch { /* ignore */ } }
    try { fs.rmSync(tmp, { force: true }); } catch { /* best effort */ }
    throw e;
  }
  // Best-effort durability of the rename itself (POSIX; swallowed where a directory fsync is
  // unsupported, e.g. Windows). The write already succeeded, so this must never fail the store.
  try { const dfd = fs.openSync(dir, 'r'); try { fs.fsyncSync(dfd); } finally { fs.closeSync(dfd); } }
  catch { /* best effort */ }
}

/**
 * Persist the device identity ({ deviceId, secret, epoch }), encrypted and atomically. The CALLER owns
 * ORDERING: store only after the server has confirmed the device, so a store failure can never leave a
 * secret with no server device behind it.
 *
 * Error channel (pinned by tests):
 *   - throws TypeError for an empty/invalid secret or a missing deviceId (a programming error);
 *   - returns { stored:false, backend } when there is NO secure backend — an expected refusal, no write
 *     attempted, so the caller (having pre-checked the backend before creating the server row) aborts
 *     registration cleanly with nothing to undo;
 *   - throws (propagates) on an encrypt or I/O failure; the atomic write leaves the prior-valid blob
 *     byte-for-byte intact, and the caller catches, zeroizes the in-memory secret, and cleans up the
 *     just-created server row;
 *   - returns { stored:true, backend } on success.
 *
 * The advisory sidecar ({ v, deviceId }, no secret) is written best-effort AFTER the blob: a sidecar
 * failure degrades the later reset self-revoke hint but does NOT fail the store — the blob is the
 * source of truth.
 * @returns {{stored: boolean, backend: string}}
 */
function storeDeviceSecret(safeStorage, dir, payload) {
  const { deviceId, secret, epoch, serverOrigin, rotatedAt } = payload || {};
  if (!isNonEmptySecret(secret)) throw new TypeError('device secret must be a non-empty string or Buffer');
  if (typeof deviceId !== 'string' || deviceId.length === 0) throw new TypeError('deviceId must be a non-empty string');
  // The issuing server is bound into the blob at registration (the exact origin the register request
  // went to) and carried forward unchanged by a rotation. Stored in canonical form; anything else refuses.
  const boundOrigin = canonicalOrigin(serverOrigin);
  if (boundOrigin === null) throw new TypeError('serverOrigin must be the http(s) origin the device was registered with');
  const backend = backendName(safeStorage);
  if (!isSecureBackend(safeStorage)) return { stored: false, backend };
  const blob = {
    v: FORMAT_V,
    deviceId,
    secret: Buffer.isBuffer(secret) ? secret.toString('utf8') : secret,
    epoch: Number.isInteger(epoch) ? epoch : 1,
    serverOrigin: boundOrigin,
    // When this identity was written (registration or the latest rotation), so the rotation schedule has
    // a footing. Informational: an unusable value reads back as unknown, never as a malformed blob.
    rotatedAt: typeof rotatedAt === 'string' && Number.isFinite(Date.parse(rotatedAt)) ? rotatedAt : new Date().toISOString(),
  };
  const enc = safeStorage.encryptString(JSON.stringify(blob)); // encrypt failure throws before any write
  atomicWrite(blobPath(dir), enc);                             // I/O failure throws; live blob intact
  // A freshly stored secret is by definition current: drop any stale mark left by a lost rotation answer,
  // and the in-flight mark of the rotation that produced it (the write above is the point of no return).
  try { fs.rmSync(stalePath(dir), { force: true }); } catch { /* best effort */ }
  try { fs.rmSync(rotatingPath(dir), { force: true }); } catch { /* best effort */ }
  // Advisory sidecar — best-effort, never fails the store (the encrypted blob is authoritative).
  try { atomicWrite(sidecarPath(dir), JSON.stringify({ v: FORMAT_V, deviceId })); }
  catch { /* a missing sidecar only weakens the reset self-revoke hint; the blob still governs */ }
  return { stored: true, backend };
}

/**
 * Read the device identity from the ENCRYPTED BLOB with its readability STATUS, for the server configured
 * NOW (`serverOrigin`). Five strictly-distinct outcomes (see the file header), determined SOLELY by the
 * blob; the advisory sidecar is never consulted here. Precedence: no-secure-store -> absent (no blob) ->
 * unreadable (a blob that cannot be decrypted, parsed, or is malformed — including one with no bound
 * origin) -> and only for a fully valid blob: 'ok' when its bound origin equals the configured one, else
 * 'absent-for-this-server' with the secret withheld and `otherOrigin` naming the server it belongs to.
 * A decrypt/read/parse failure is 'unreadable' (TRANSIENT) and is NEVER reported as 'absent' or
 * 'absent-for-this-server'; only a genuine ENOENT on a secure backend is 'absent'.
 * An 'ok' result also carries the bound `serverOrigin` (canonical) and `rotatedAt` (when the identity was
 * written, or null when unknown) so a rotation can carry the binding forward and the schedule can decide.
 * A SIXTH status sits between 'absent-for-this-server' and 'ok': a valid blob whose secret is marked retired
 * (a STALE/ROTATING marker beside it) reads 'stale' with the secret withheld — presenting it would be a replay
 * — distinct from 'ok'; the run-time rotation-recovery reconciles it.
 * @returns {{status:'no-secure-store'|'absent'|'unreadable'|'absent-for-this-server'|'stale'|'ok', deviceId:(string|null), secret:(string|null), epoch:(number|null), otherOrigin?:string, serverOrigin?:string, rotatedAt?:(string|null)}}
 */
function readDeviceSecret(safeStorage, dir, serverOrigin) {
  const miss = (status) => ({ status, deviceId: null, secret: null, epoch: null });
  if (!isSecureBackend(safeStorage)) return miss('no-secure-store');
  let enc;
  try {
    enc = fs.readFileSync(blobPath(dir));
  } catch (e) {
    // ENOENT on a secure backend = genuinely not registered. Any other read error is an
    // existing-but-unreadable file (I/O) — TRANSIENT, and must not be mistaken for "absent".
    return miss((e && e.code === 'ENOENT') ? 'absent' : 'unreadable');
  }
  try {
    const obj = JSON.parse(safeStorage.decryptString(enc));
    // Shape + content check INSIDE this try, so a blob that decrypts to malformed JSON, the wrong
    // shape, or an empty secret yields 'unreadable' — never a spurious 'ok' and never 'absent'.
    if (!obj || typeof obj !== 'object'
        || typeof obj.deviceId !== 'string' || obj.deviceId.length === 0
        || typeof obj.secret !== 'string' || obj.secret.length === 0
        || canonicalOrigin(obj.serverOrigin) === null) {
      return miss('unreadable');
    }
    // Bound to a different server than the one configured now (or the configured value is unusable):
    // the identity is real but is not for THIS server. Withhold the secret; name the other server.
    if (!sameOrigin(obj.serverOrigin, serverOrigin)) return { ...miss('absent-for-this-server'), otherOrigin: canonicalOrigin(obj.serverOrigin) };
    // Marked stale (the secret is retired on the server), or a rotation was cut off between the request and
    // the store (the secret on disk may be retired): withhold it — presenting it would be a replay.
    if (isMarkedStale(dir)) return miss('stale');
    return {
      status: 'ok', deviceId: obj.deviceId, secret: obj.secret, epoch: Number.isInteger(obj.epoch) ? obj.epoch : 1,
      serverOrigin: canonicalOrigin(obj.serverOrigin),
      rotatedAt: typeof obj.rotatedAt === 'string' && Number.isFinite(Date.parse(obj.rotatedAt)) ? obj.rotatedAt : null,
    };
  } catch {
    // The blob exists but could not be decrypted/parsed this moment (locked/rotated keychain, or a
    // corrupt file). Do NOT re-register: the server-side secret is still valid; wait and retry.
    return miss('unreadable');
  }
}

/**
 * The NON-SECRET identity fields — deviceId, epoch, bound serverOrigin — read from the blob for the rotation
 * recovery, which must match this computer's row in the account's device list WITHOUT presenting the (possibly
 * retired) secret. Decrypts and parses the blob like readDeviceSecret, but returns ONLY these three fields and
 * NEVER the secret, regardless of any STALE/ROTATING marker (the marker withholds the secret from
 * readDeviceSecret; the reconcile still needs the id + epoch to compare against the server). Returns null when
 * there is no readable, well-formed blob.
 * @returns {{deviceId:string, epoch:number, serverOrigin:string} | null}
 */
function readIdentityMeta(safeStorage, dir) {
  if (!isSecureBackend(safeStorage)) return null;
  let enc;
  try { enc = fs.readFileSync(blobPath(dir)); } catch { return null; }
  try {
    const obj = JSON.parse(safeStorage.decryptString(enc));
    if (!obj || typeof obj !== 'object' || typeof obj.deviceId !== 'string' || obj.deviceId.length === 0) return null;
    const origin = canonicalOrigin(obj.serverOrigin);
    if (origin === null) return null;
    // A MISSING/non-integer epoch is passed through as null, NOT invented as 1: the rotation reconcile treats a
    // null epoch as doubt and KEEPS the marker rather than risking a wrong 'clear' against a server that also
    // reads 1. (The full readDeviceSecret keeps its own epoch:1 default for the mint; this reader is stricter.)
    return { deviceId: obj.deviceId, epoch: Number.isInteger(obj.epoch) ? obj.epoch : null, serverOrigin: origin }; // NB: obj.secret is deliberately never read or returned
  } catch { return null; }
}

/**
 * Whether a write-ahead ROTATING marker is present: a rotation request is in flight, or was cut off by a crash
 * between the request and the store. The rotation recovery uses this to tell a CRASH-SURVIVOR (reconcile it
 * against the server) from a durable STALE mark (already known retired). Non-secret; never throws.
 */
function hasRotatingMarker(dir) { try { return fs.existsSync(rotatingPath(dir)); } catch { return false; } }

/**
 * Record that the stored secret is RETIRED on the server (a rotation's answer was lost), so every later read
 * — in this process and after a restart — reports 'stale' and withholds it. A small non-secret marker
 * beside the blob; the blob itself is left as it is (the forget path still names the device from it or the
 * sidecar). Best-effort: returns whether the mark is on disk; the caller keeps its own in-memory mark too.
 */
function markDeviceSecretStale(dir) {
  try { atomicWrite(stalePath(dir), JSON.stringify({ v: FORMAT_V, markedAt: new Date().toISOString() })); return true; }
  catch { return isMarkedStale(dir); }
}

/**
 * Record that a rotation request is about to go out. Written BEFORE the irreversible request; while it
 * exists the identity reads 'stale'-on-survival: if the process dies between the request and the store,
 * the next launch finds the marker and withholds the (possibly retired) secret. Removed by
 * storeDeviceSecret once the new secret is on disk, or by clearDeviceSecretRotating when the server has
 * definitely answered WITHOUT rotating. Returns false when it could not be written — the caller must
 * then not rotate (the window would be unprotected).
 */
function markDeviceSecretRotating(dir) {
  try { atomicWrite(rotatingPath(dir), JSON.stringify({ v: FORMAT_V, startedAt: new Date().toISOString() })); return fs.existsSync(rotatingPath(dir)); }
  catch { return false; }
}

/** The server definitely answered without rotating: the in-flight mark is no longer needed. */
function clearDeviceSecretRotating(dir) {
  try { fs.rmSync(rotatingPath(dir), { force: true }); } catch { /* best effort */ }
  return !fs.existsSync(rotatingPath(dir));
}

/**
 * Read the ADVISORY deviceId from the plaintext sidecar. Used ONLY by a reset/list path when the
 * encrypted blob is unreadable or absent — so a keychain-rotation reset can still name the exact old
 * server device row to self-revoke under the account session (a cleanly-revoked device, not an orphaned
 * live one). It is NEVER consulted by readDeviceSecret; when the blob is 'ok', the blob's deviceId is
 * authoritative. Returns the deviceId string, or null if the sidecar is absent/unreadable/malformed.
 */
function readDeviceIdHint(dir) {
  try {
    const obj = JSON.parse(fs.readFileSync(sidecarPath(dir), 'utf8'));
    return (obj && typeof obj.deviceId === 'string' && obj.deviceId.length > 0) ? obj.deviceId : null;
  } catch { return null; }
}

/**
 * Write ONLY the advisory deviceId sidecar (never a secret), atomically. Used by the registration
 * orphan-cleanup path when the server-row delete ITSELF fails after a failed store: retaining the
 * deviceId lets a later reset/Remove still name the exact server device row to revoke, rather than
 * losing the id and leaving a live orphan nobody can point at. Mirrors the sidecar that
 * storeDeviceSecret writes on the happy path; throws only on a bad deviceId or a hard I/O failure.
 */
function writeDeviceIdHint(dir, deviceId) {
  if (typeof deviceId !== 'string' || deviceId.length === 0) throw new TypeError('deviceId must be a non-empty string');
  atomicWrite(sidecarPath(dir), JSON.stringify({ v: FORMAT_V, deviceId }));
}

/**
 * Remove BOTH the encrypted blob and the advisory sidecar. Best-effort per file; returns
 * { removed:true } only when NEITHER remains afterwards, so the sign-out / forget-device path can
 * verify the wipe. Only for an EXPLICIT end of the device relationship — the device was removed/revoked,
 * or a reset — NEVER on an idle-lock (a lock is transient; the identity must survive it, like the
 * state-DB key).
 *
 * CONSUMER ORDERING (the forget / reset flows in later slices): read the deviceId FIRST (from the blob
 * when it reads 'ok', else from readDeviceIdHint) -> self-revoke the server device row under the
 * account session -> and only THEN call clearDeviceSecret. Clearing first removes BOTH files and so
 * destroys the only copy of the deviceId the revoke needs, re-creating exactly the orphaned-live-device
 * this sidecar exists to prevent. read-id -> revoke -> clear, always.
 * @returns {{removed: boolean}}
 */
function clearDeviceSecret(dir) {
  try { fs.rmSync(blobPath(dir), { force: true }); } catch { /* best effort */ }
  try { fs.rmSync(sidecarPath(dir), { force: true }); } catch { /* best effort */ }
  try { fs.rmSync(stalePath(dir), { force: true }); } catch { /* best effort */ }
  try { fs.rmSync(rotatingPath(dir), { force: true }); } catch { /* best effort */ }
  const removed = !fs.existsSync(blobPath(dir)) && !fs.existsSync(sidecarPath(dir)) && !fs.existsSync(stalePath(dir)) && !fs.existsSync(rotatingPath(dir));
  return { removed };
}

/**
 * Best-effort scrub of an in-memory secret. Honest by construction (see the file header): a JS string
 * is immutable and cannot be erased in place, so for a string this is a no-op beyond signalling intent
 * — the caller must drop its reference. Given a Buffer it overwrites the bytes with zeros. It never
 * claims to wipe an immutable string; the real anchors are minimal lifetime + encryption at rest.
 */
function zeroizeSecret(secret) {
  if (Buffer.isBuffer(secret)) secret.fill(0);
}

module.exports = { storeDeviceSecret, readDeviceSecret, readIdentityMeta, hasRotatingMarker, isMarkedStale, readDeviceIdHint, writeDeviceIdHint, clearDeviceSecret, markDeviceSecretStale, markDeviceSecretRotating, clearDeviceSecretRotating, zeroizeSecret, canonicalOrigin, sameOrigin };

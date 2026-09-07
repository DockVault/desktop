'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {
  storeDeviceSecret, readDeviceSecret, readIdentityMeta, hasRotatingMarker, readDeviceIdHint, writeDeviceIdHint, clearDeviceSecret, markDeviceSecretStale, markDeviceSecretRotating, clearDeviceSecretRotating, zeroizeSecret, canonicalOrigin, sameOrigin,
} = require('../src/main/device-secret-store');

// A stand-in for Electron safeStorage with FRAMING fidelity: encryptString prepends a magic marker
// before base64, and decryptString THROWS unless that marker is present — so a truncated/zero-byte/
// garbage file fails to decrypt exactly as real safeStorage would (the base64-only mock used earlier
// would have round-tripped junk to a false 'ok'). Flags exercise the fail paths: unavailable/basic_text
// backends (fail-closed), encryptThrows (a write-time keychain failure), decryptThrows (a locked/rotated
// keychain at read time).
const MAGIC = 'DVENC1:';
function mockSafe(backend, { available = true, encryptThrows = false, decryptThrows = false } = {}) {
  return {
    isEncryptionAvailable: () => available,
    getSelectedStorageBackend: () => backend,
    encryptString: (s) => {
      if (encryptThrows) throw new Error('keychain write failed');
      return Buffer.from(MAGIC + Buffer.from(String(s), 'utf8').toString('base64'), 'utf8');
    },
    decryptString: (buf) => {
      if (decryptThrows) throw new Error('keychain locked');
      const str = Buffer.from(buf).toString('utf8');
      if (!str.startsWith(MAGIC)) throw new Error('bad ciphertext framing');
      return Buffer.from(str.slice(MAGIC.length), 'base64').toString('utf8');
    },
  };
}
function tmp() { return fs.mkdtempSync(path.join(os.tmpdir(), 'dv-dstore-')); }
function blobPath(dir) { return path.join(dir, 'device-secret.bin'); }
function sidecarPath(dir) { return path.join(dir, 'device-id.json'); }
function strayTmps(dir) { return fs.readdirSync(dir).filter((f) => f.includes('.tmp')); }

const SECRET = 'opaque-device-bearer-secret-xyz789';
const ORIGIN = 'https://vault.example';
// An 'ok' read also carries the bound origin and the write time; check those, then compare the identity fields.
function stripMeta(r) {
  const { serverOrigin, rotatedAt, ...rest } = r;
  if (r.status === 'ok') { assert.strictEqual(serverOrigin, ORIGIN); assert.ok(Number.isFinite(Date.parse(rotatedAt)), 'rotatedAt is a timestamp'); }
  return rest;
}
const DEVICE_ID = 'dev-11112222-3333-4444';
const secure = () => mockSafe('gnome_libsecret');

test('store + read round-trips { deviceId, secret, epoch }; secret and epoch are not on disk in plaintext', () => {
  const dir = tmp();
  const r = storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET, epoch: 3 });
  assert.deepStrictEqual(r, { stored: true, backend: 'gnome_libsecret' });
  const read = readDeviceSecret(secure(), dir, ORIGIN);
  assert.deepStrictEqual(stripMeta(read), { status: 'ok', deviceId: DEVICE_ID, secret: SECRET, epoch: 3 });
  const raw = fs.readFileSync(blobPath(dir), 'utf8');
  assert.ok(!raw.includes(SECRET), 'the secret is never in the blob file in plaintext');
  // The sidecar is plaintext but must carry ONLY the deviceId — never the secret or the epoch.
  const sidecar = JSON.parse(fs.readFileSync(sidecarPath(dir), 'utf8'));
  assert.strictEqual(sidecar.deviceId, DEVICE_ID);
  assert.ok(!('secret' in sidecar) && !('epoch' in sidecar), 'sidecar carries no secret and no epoch');
  assert.ok(!fs.readFileSync(sidecarPath(dir), 'utf8').includes(SECRET), 'sidecar has no secret');
  assert.strictEqual(read.epoch, 3);
  assert.strictEqual(strayTmps(dir).length, 0, 'a successful write leaves no stray temp file');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('epoch defaults to 1 when the caller omits it', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).epoch, 1);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('no-secure-store: store writes nothing and read reports no-secure-store (never "absent")', () => {
  const dir = tmp();
  const safe = mockSafe('basic_text');
  assert.deepStrictEqual(storeDeviceSecret(safe, dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET }),
    { stored: false, backend: 'basic_text' });
  assert.ok(!fs.existsSync(blobPath(dir)), 'no blob under a non-secure backend');
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'no-secure-store');
  assert.strictEqual(readDeviceSecret(mockSafe('gnome_libsecret', { available: false }), dir, ORIGIN).status, 'no-secure-store');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('absent: a secure backend with no blob reports absent (registration may proceed)', () => {
  const dir = tmp();
  const read = readDeviceSecret(secure(), dir, ORIGIN);
  assert.strictEqual(read.status, 'absent');
  assert.strictEqual(read.secret, null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('storeDeviceSecret rejects an empty/invalid secret or missing deviceId (throws, so registration aborts)', () => {
  const dir = tmp();
  const safe = secure();
  for (const bad of [undefined, null, '', Buffer.alloc(0)]) {
    assert.throws(() => storeDeviceSecret(safe, dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: bad }), TypeError);
  }
  assert.throws(() => storeDeviceSecret(safe, dir, { serverOrigin: ORIGIN, deviceId: '', secret: SECRET }), TypeError);
  assert.throws(() => storeDeviceSecret(safe, dir, { serverOrigin: ORIGIN, secret: SECRET }), TypeError);
  assert.ok(!fs.existsSync(blobPath(dir)), 'a rejected store writes nothing');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a valid Buffer secret is accepted (validation is not a typeof===string gate)', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: Buffer.from(SECRET, 'utf8'), epoch: 2 });
  assert.deepStrictEqual(stripMeta(readDeviceSecret(secure(), dir, ORIGIN)),
    { status: 'ok', deviceId: DEVICE_ID, secret: SECRET, epoch: 2 });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a blob that decrypts to malformed JSON reads unreadable, not ok/absent', () => {
  const dir = tmp();
  fs.writeFileSync(blobPath(dir), secure().encryptString('not json{'));
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'unreadable');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a blob whose secret field is empty reads unreadable (the false-ok wedge is closed)', () => {
  const dir = tmp();
  fs.writeFileSync(blobPath(dir), secure().encryptString(JSON.stringify({ v: 1, deviceId: DEVICE_ID, secret: '', epoch: 1 })));
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'unreadable');
  // Wrong shape (no secret field at all) is equally unreadable, never a spurious ok.
  fs.writeFileSync(blobPath(dir), secure().encryptString(JSON.stringify({ v: 1, deviceId: DEVICE_ID, epoch: 1 })));
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'unreadable');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('an undecryptable blob is "unreadable" (TRANSIENT), NEVER "absent"', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });
  const read = readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, ORIGIN);
  assert.strictEqual(read.status, 'unreadable');
  assert.notStrictEqual(read.status, 'absent');
  assert.strictEqual(read.secret, null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('a corrupt / truncated / zero-byte ciphertext reads unreadable (framing-checked, not false-ok)', () => {
  for (const bad of [Buffer.alloc(0), Buffer.from('garbage-not-framed'), Buffer.from(MAGIC.slice(0, 3))]) {
    const dir = tmp();
    fs.writeFileSync(blobPath(dir), bad);
    assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'unreadable');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('a non-ENOENT read error (existing-but-unreadable) reports unreadable, not absent', () => {
  const dir = tmp();
  fs.mkdirSync(blobPath(dir)); // a directory at the blob path -> readFileSync throws EISDIR (non-ENOENT)
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'unreadable');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('absent and unreadable are DISTINCT statuses, and a read never returns a bare null', () => {
  const dirAbsent = tmp();
  const dirUnreadable = tmp();
  storeDeviceSecret(secure(), dirUnreadable, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });
  const absent = readDeviceSecret(secure(), dirAbsent, ORIGIN);
  const unreadable = readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dirUnreadable, ORIGIN);
  assert.notStrictEqual(absent.status, unreadable.status);
  for (const r of [absent, unreadable]) {
    assert.ok(r && typeof r === 'object', 'a read always returns an object, never a bare null');
    assert.ok(['no-secure-store', 'absent', 'ok', 'unreadable'].includes(r.status));
  }
  fs.rmSync(dirAbsent, { recursive: true, force: true });
  fs.rmSync(dirUnreadable, { recursive: true, force: true });
});

// ---- sidecar (advisory deviceId) — decoupled from the four-state read --------------------------
test('sidecar-only (blob absent): read is absent, but the deviceId hint survives for reset self-revoke', () => {
  const dir = tmp();
  fs.writeFileSync(sidecarPath(dir), JSON.stringify({ v: 1, deviceId: DEVICE_ID }));
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'absent'); // read ignores the sidecar
  assert.strictEqual(readDeviceIdHint(dir), DEVICE_ID);                 // reset path can still name the row
  fs.rmSync(dir, { recursive: true, force: true });
});

test('the blob deviceId is authoritative; the sidecar is never consulted by readDeviceSecret', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });
  fs.writeFileSync(sidecarPath(dir), JSON.stringify({ v: 1, deviceId: 'a-different-stale-id' }));
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).deviceId, DEVICE_ID, 'read uses the blob id, not the sidecar');
  assert.strictEqual(readDeviceIdHint(dir), 'a-different-stale-id', 'the hint reads the sidecar (a separate path)');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('when the blob is unreadable, the sidecar still yields the deviceId for a clean self-revoke', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET }); // writes blob + sidecar
  assert.strictEqual(readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, ORIGIN).status, 'unreadable');
  assert.strictEqual(readDeviceIdHint(dir), DEVICE_ID);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('clearDeviceSecret removes BOTH blob and sidecar and reports { removed:true }; idempotent', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });
  assert.ok(fs.existsSync(blobPath(dir)) && fs.existsSync(sidecarPath(dir)));
  assert.deepStrictEqual(clearDeviceSecret(dir), { removed: true });
  assert.ok(!fs.existsSync(blobPath(dir)) && !fs.existsSync(sidecarPath(dir)));
  assert.strictEqual(readDeviceSecret(secure(), dir, ORIGIN).status, 'absent');
  assert.strictEqual(readDeviceIdHint(dir), null);
  assert.deepStrictEqual(clearDeviceSecret(dir), { removed: true }); // idempotent, no throw
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---- durability: a failed store never destroys the prior-valid blob, and leaves no fragment -----
test('a write-time keychain failure throws and leaves the prior-valid blob byte-for-byte intact', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET, epoch: 5 });
  const before = fs.readFileSync(blobPath(dir));
  // A later store whose encrypt throws must propagate AND not touch the live blob (the old O_TRUNC
  // writeFileSync would have truncated it first; the atomic temp+rename never touches it on failure).
  assert.throws(() => storeDeviceSecret(mockSafe('gnome_libsecret', { encryptThrows: true }), dir,
    { deviceId: 'new-id', secret: 'a-new-secret', epoch: 6 }));
  const after = fs.readFileSync(blobPath(dir));
  assert.ok(before.equals(after), 'the prior blob is unchanged after a failed store');
  assert.strictEqual(strayTmps(dir).length, 0, 'a failed store leaves no stray temp file');
  // The prior identity still reads back intact.
  assert.deepStrictEqual(stripMeta(readDeviceSecret(secure(), dir, ORIGIN)),
    { status: 'ok', deviceId: DEVICE_ID, secret: SECRET, epoch: 5 });
  fs.rmSync(dir, { recursive: true, force: true });
});

test('zeroizeSecret overwrites a Buffer and is a safe no-op for a string (honest best-effort)', () => {
  const buf = Buffer.from('secret-bytes');
  zeroizeSecret(buf);
  assert.ok(buf.every((b) => b === 0), 'a Buffer secret is overwritten with zeros');
  assert.doesNotThrow(() => zeroizeSecret('an-immutable-string'));
  assert.doesNotThrow(() => zeroizeSecret(null));
  assert.doesNotThrow(() => zeroizeSecret(undefined));
});

// ---- never-logged: with a non-vacuity self-check + base64/hex forms + a pinned return value ------
test('the device secret is NEVER logged (self-checked capture, in plaintext or base64/hex form)', () => {
  const dir = tmp();
  const seen = [];
  const methods = ['log', 'info', 'warn', 'error', 'debug'];
  const origConsole = {};
  for (const m of methods) { origConsole[m] = console[m]; console[m] = (...a) => { seen.push(a.map(String).join(' ')); }; }
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  process.stdout.write = (chunk) => { seen.push(String(chunk)); return true; };
  process.stderr.write = (chunk) => { seen.push(String(chunk)); return true; };
  let selfCheckCaught = false;
  let pinnedOk = false;
  try {
    // Non-vacuity: prove the capture actually catches a logged secret BEFORE trusting the real sweep.
    console.log('planted', SECRET);
    selfCheckCaught = seen.some((l) => l.includes(SECRET));
    seen.length = 0;
    const safe = secure();
    const stored = storeDeviceSecret(safe, dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });      // store + sidecar
    const okRead = readDeviceSecret(safe, dir, ORIGIN);                                                  // ok read
    readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, ORIGIN);                 // unreadable
    readDeviceSecret(mockSafe('basic_text'), dir, ORIGIN);                                               // no-secure-store
    storeDeviceSecret(mockSafe('basic_text'), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });     // refuse-to-write
    readDeviceIdHint(dir);
    clearDeviceSecret(dir);                                                                      // clear both
    zeroizeSecret(Buffer.from(SECRET));
    pinnedOk = stored.stored === true && okRead.status === 'ok'; // pin >=1 return value: the code ran
  } finally {
    for (const m of methods) console[m] = origConsole[m];
    process.stdout.write = origOut;
    process.stderr.write = origErr;
  }
  assert.ok(selfCheckCaught, 'self-check: the capture must catch a deliberately-logged secret (non-vacuous)');
  assert.ok(pinnedOk, 'the real store/read paths executed inside the capture window');
  const b64 = Buffer.from(SECRET, 'utf8').toString('base64');
  const hex = Buffer.from(SECRET, 'utf8').toString('hex');
  const swept = seen.join('\n');
  assert.ok(!swept.includes(SECRET), 'no log sink carried the secret in plaintext');
  assert.ok(!swept.includes(b64), 'no log sink carried the secret in base64 (the on-disk form)');
  assert.ok(!swept.includes(hex), 'no log sink carried the secret in hex');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---- atomic-write failure branch + rename-over-existing -----------------------------------------
test('a store into a blocked blob path (a directory) throws and leaves no stray temp file', () => {
  const dir = tmp();
  fs.mkdirSync(blobPath(dir)); // the blob path is itself a directory -> the atomic rename over it fails
  assert.throws(() => storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET }));
  assert.strictEqual(strayTmps(dir).length, 0, 'atomicWrite removes its temp on a failed rename');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('storing twice replaces the blob atomically (rename-over-existing works on every platform)', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: 'd1', secret: 's1-secret', epoch: 1 });
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: 'd2', secret: 's2-secret', epoch: 2 });
  assert.deepStrictEqual(stripMeta(readDeviceSecret(secure(), dir, ORIGIN)), { status: 'ok', deviceId: 'd2', secret: 's2-secret', epoch: 2 });
  assert.strictEqual(strayTmps(dir).length, 0, 'the replaced blob leaves no stray temp');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('writeDeviceIdHint writes ONLY the deviceId sidecar (never a secret), atomically', () => {
  const dir = tmp();
  writeDeviceIdHint(dir, DEVICE_ID);
  assert.strictEqual(readDeviceIdHint(dir), DEVICE_ID);
  const sidecar = JSON.parse(fs.readFileSync(sidecarPath(dir), 'utf8'));
  assert.deepStrictEqual(sidecar, { v: 1, deviceId: DEVICE_ID });
  assert.ok(!('secret' in sidecar) && !('epoch' in sidecar), 'the hint carries no secret and no epoch');
  assert.ok(!fs.readFileSync(sidecarPath(dir), 'utf8').includes(SECRET), 'the hint never contains a secret');
  // Overwriting an existing hint is atomic and leaves no stray temp.
  writeDeviceIdHint(dir, 'dev-second');
  assert.strictEqual(readDeviceIdHint(dir), 'dev-second');
  assert.strictEqual(strayTmps(dir).length, 0);
  // A bad deviceId throws TypeError and writes nothing new.
  for (const bad of ['', undefined, null, 123]) assert.throws(() => writeDeviceIdHint(dir, bad), TypeError);
  assert.strictEqual(readDeviceIdHint(dir), 'dev-second');
  fs.rmSync(dir, { recursive: true, force: true });
});

// ---- the server binding: a device secret is only ever presented to the server that issued it ----------

// Decrypt the blob through the mock (test-side only) to look at what was bound.
function blobOf(dir) { return JSON.parse(mockSafe('gnome_libsecret').decryptString(fs.readFileSync(blobPath(dir)))); }

test('binding: the blob carries the issuing server in canonical form; the sidecar stays exactly { v, deviceId }', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { deviceId: DEVICE_ID, secret: SECRET, epoch: 1, serverOrigin: 'HTTPS://Vault.Example:443/some/path?q=1#frag' });
  const blob = blobOf(dir);
  assert.strictEqual(blob.serverOrigin, 'https://vault.example', 'lower-cased, default port dropped, path/query/fragment dropped');
  assert.deepStrictEqual(Object.keys(blob).sort(), ['deviceId', 'epoch', 'rotatedAt', 'secret', 'serverOrigin', 'v']);
  assert.deepStrictEqual(JSON.parse(fs.readFileSync(sidecarPath(dir), 'utf8')), { v: 1, deviceId: DEVICE_ID }, 'no origin (and no secret) in the plaintext sidecar');
  assert.ok(!fs.readFileSync(blobPath(dir), 'utf8').includes('vault.example'), 'the origin is inside the encrypted blob, not in the clear');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('binding: a store with a missing or unusable serverOrigin is refused (TypeError) and writes nothing', () => {
  for (const bad of [undefined, null, '', 'vault.example', 'ftp://vault.example', 'file:///x', 'not a url', 42, 'https://', 'https://user:pw@']) {
    const dir = tmp();
    assert.throws(() => storeDeviceSecret(secure(), dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: bad }), TypeError, `origin ${JSON.stringify(bad)}`);
    assert.ok(!fs.existsSync(blobPath(dir)) && !fs.existsSync(sidecarPath(dir)) && strayTmps(dir).length === 0, 'nothing written');
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('read: the same server (however typed) reads ok; a different server reads absent-for-this-server with the secret withheld and the other server named', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { deviceId: DEVICE_ID, secret: SECRET, epoch: 2, serverOrigin: 'https://vault.example:443/' });
  for (const same of ['https://vault.example', 'HTTPS://VAULT.EXAMPLE', 'https://vault.example:443', 'https://vault.example/other/path', 'https://vault.example/?x=1', 'https://vault.example#f']) {
    const r = readDeviceSecret(secure(), dir, same);
    assert.strictEqual(r.status, 'ok', `same server: ${same}`);
    assert.strictEqual(r.secret, SECRET);
    assert.strictEqual(r.deviceId, DEVICE_ID);
    assert.strictEqual(r.otherOrigin, undefined);
  }
  for (const other of ['http://vault.example', 'https://vault.example:8443', 'https://other.example', 'https://vault.example.evil', 'https://evil.vault.example', 'https://vault.examp']) {
    const r = readDeviceSecret(secure(), dir, other);
    assert.strictEqual(r.status, 'absent-for-this-server', `different server: ${other}`);
    assert.strictEqual(r.secret, null, 'the secret is never returned for another server');
    assert.strictEqual(r.deviceId, null);
    assert.strictEqual(r.epoch, null);
    assert.strictEqual(r.otherOrigin, 'https://vault.example', 'the server the identity belongs to is named');
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('read: an unusable configured origin is a MISMATCH (fail closed), never ok', () => {
  const dir = tmp();
  storeDeviceSecret(secure(), dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN });
  for (const bad of [undefined, null, '', 'vault.example', 'not a url', 42, {}, 'file:///x']) {
    const r = readDeviceSecret(secure(), dir, bad);
    assert.strictEqual(r.status, 'absent-for-this-server', `configured ${JSON.stringify(bad)}`);
    assert.strictEqual(r.secret, null);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('read: precedence — no-secure-store, then absent, then unreadable, and only a fully valid blob is compared', () => {
  const safe = secure();
  // no blob: absent, whatever the configured origin (usable or not)
  const dir = tmp();
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'absent');
  assert.strictEqual(readDeviceSecret(safe, dir, 'garbage').status, 'absent');
  assert.strictEqual(readDeviceSecret(mockSafe('basic_text'), dir, ORIGIN).status, 'no-secure-store');
  // a blob for ANOTHER server that cannot be decrypted right now: unreadable, never absent-for-this-server
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: 'https://other.example' });
  assert.strictEqual(readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, ORIGIN).status, 'unreadable');
  assert.strictEqual(readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, 'https://other.example').status, 'unreadable');
  assert.strictEqual(readDeviceSecret(mockSafe('basic_text'), dir, ORIGIN).status, 'no-secure-store');
  // a blob with NO bound origin (or a non-string / unusable one) is malformed: unreadable, never assumed current
  for (const origin of [undefined, null, '', 42, 'vault.example', 'file:///x']) {
    const raw = { v: 1, deviceId: DEVICE_ID, secret: SECRET, epoch: 1 };
    if (origin !== undefined) raw.serverOrigin = origin;
    fs.writeFileSync(blobPath(dir), safe.encryptString(JSON.stringify(raw)));
    const r = readDeviceSecret(safe, dir, ORIGIN);
    assert.strictEqual(r.status, 'unreadable', `blob origin ${JSON.stringify(origin)}`);
    assert.strictEqual(r.secret, null);
  }
  fs.rmSync(dir, { recursive: true, force: true });
});

test('rotation keeps the binding: a new secret + epoch written with the read-back origin still reads ok; only a fresh registration changes the server', () => {
  const dir = tmp();
  const safe = secure();
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: SECRET, epoch: 1, serverOrigin: ORIGIN });
  const cur = readDeviceSecret(safe, dir, ORIGIN);
  assert.strictEqual(cur.status, 'ok');
  // the rotate write carries the bound origin forward (the caller re-stores under the SAME configured origin)
  storeDeviceSecret(safe, dir, { deviceId: cur.deviceId, secret: 'rotated-secret-2', epoch: cur.epoch + 1, serverOrigin: ORIGIN });
  const rotated = readDeviceSecret(safe, dir, ORIGIN);
  assert.deepStrictEqual(stripMeta(rotated), { status: 'ok', deviceId: DEVICE_ID, secret: 'rotated-secret-2', epoch: 2 });
  assert.strictEqual(blobOf(dir).serverOrigin, 'https://vault.example');
  // a registration with a NEW server writes that server's binding; the old server then reads it as not-for-this-server
  storeDeviceSecret(safe, dir, { deviceId: 'dev-new', secret: 'new-server-secret', epoch: 1, serverOrigin: 'https://new.example' });
  assert.strictEqual(readDeviceSecret(safe, dir, 'https://new.example').status, 'ok');
  const old = readDeviceSecret(safe, dir, ORIGIN);
  assert.strictEqual(old.status, 'absent-for-this-server');
  assert.strictEqual(old.otherOrigin, 'https://new.example');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('canonicalOrigin / sameOrigin: URL.origin semantics, http(s) only, fail closed on anything else', () => {
  assert.strictEqual(canonicalOrigin('HTTPS://Vault.Example:443/a/b?c#d'), 'https://vault.example');
  assert.strictEqual(canonicalOrigin('http://vault.example:80'), 'http://vault.example');
  assert.strictEqual(canonicalOrigin('https://vault.example:8443'), 'https://vault.example:8443');
  assert.strictEqual(canonicalOrigin('http://127.0.0.1:8360/'), 'http://127.0.0.1:8360');
  assert.strictEqual(canonicalOrigin('https://user:pw@vault.example/'), 'https://vault.example', 'userinfo is dropped');
  for (const bad of ['', 'vault.example', 'ftp://x', 'file:///x', 'not a url', 42, null, undefined, 'https://']) assert.strictEqual(canonicalOrigin(bad), null, `bad ${JSON.stringify(bad)}`);
  assert.strictEqual(sameOrigin('https://vault.example', 'HTTPS://VAULT.EXAMPLE:443/x'), true);
  assert.strictEqual(sameOrigin('https://vault.example', 'http://vault.example'), false, 'scheme matters');
  assert.strictEqual(sameOrigin('https://vault.example:443', 'https://vault.example:8443'), false, 'a non-default port matters');
  assert.strictEqual(sameOrigin('https://vault.example', 'https://vault.example.evil'), false, 'no suffix/prefix fuzz');
  assert.strictEqual(sameOrigin('https://vault.example', 'garbage'), false);
  assert.strictEqual(sameOrigin('garbage', 'garbage'), false, 'two unusable values never match each other');
  assert.strictEqual(sameOrigin(null, null), false);
});

test('rotatedAt: the write time is stored in the blob and read back; a caller-supplied time is kept; an unusable one reads null, never a malformed blob', () => {
  const dir = tmp(); const safe = secure();
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN });
  const r1 = readDeviceSecret(safe, dir, ORIGIN);
  assert.ok(Number.isFinite(Date.parse(r1.rotatedAt)) && Math.abs(Date.now() - Date.parse(r1.rotatedAt)) < 60000, 'defaults to now');
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN, rotatedAt: '2026-01-02T03:04:05.000Z' });
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).rotatedAt, '2026-01-02T03:04:05.000Z');
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).serverOrigin, ORIGIN, 'the bound origin is returned in canonical form');
  for (const bad of ['garbage', 42, null]) {
    const raw = { v: 1, deviceId: DEVICE_ID, secret: SECRET, epoch: 1, serverOrigin: ORIGIN, rotatedAt: bad };
    fs.writeFileSync(blobPath(dir), safe.encryptString(JSON.stringify(raw)));
    const r = readDeviceSecret(safe, dir, ORIGIN);
    assert.strictEqual(r.status, 'ok', `rotatedAt ${JSON.stringify(bad)} never makes the blob unreadable`);
    assert.strictEqual(r.rotatedAt, null);
  }
  // a mismatched read carries neither the secret nor the write time
  const other = readDeviceSecret(safe, dir, 'https://other.example');
  assert.strictEqual(other.rotatedAt, undefined); assert.strictEqual(other.secret, null);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('stale mark: a marked identity reads stale with the secret withheld, survives a re-read (a restart), and is cleared only with the identity or by a fresh store', () => {
  const dir = tmp(); const safe = secure();
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN });
  assert.strictEqual(markDeviceSecretStale(dir), true);
  const marker = JSON.parse(fs.readFileSync(path.join(dir, 'device-secret.stale'), 'utf8'));
  assert.deepStrictEqual(Object.keys(marker).sort(), ['markedAt', 'v'], 'the marker holds no secret and no id');
  for (let i = 0; i < 2; i++) { // two reads, as two processes would
    const r = readDeviceSecret(safe, dir, ORIGIN);
    assert.strictEqual(r.status, 'stale'); assert.strictEqual(r.secret, null); assert.strictEqual(r.deviceId, null);
  }
  // precedence: no-secure-store, another server, and an unreadable blob still win over the mark
  assert.strictEqual(readDeviceSecret(mockSafe('basic_text'), dir, ORIGIN).status, 'no-secure-store');
  assert.strictEqual(readDeviceSecret(safe, dir, 'https://other.example').status, 'absent-for-this-server');
  assert.strictEqual(readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, ORIGIN).status, 'unreadable');
  // the sidecar hint still names the device for the forget path
  assert.strictEqual(readDeviceIdHint(dir), DEVICE_ID);
  // a fresh store (a new registration or a kept rotation answer) drops the mark
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: 'new-secret', epoch: 2, serverOrigin: ORIGIN });
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'ok');
  assert.ok(!fs.existsSync(path.join(dir, 'device-secret.stale')));
  // and clearing the identity clears the mark too, reporting removed only when all three files are gone
  markDeviceSecretStale(dir);
  assert.deepStrictEqual(clearDeviceSecret(dir), { removed: true });
  assert.ok(!fs.existsSync(path.join(dir, 'device-secret.stale')));
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'absent', 'a mark with no blob is not an identity');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('in-flight rotation mark: reads as stale while present (after the origin check, before ok), holds no secret, is dropped by a fresh store, by clearDeviceSecretRotating, and by clearDeviceSecret', () => {
  const dir = tmp(); const safe = secure();
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN });
  assert.strictEqual(markDeviceSecretRotating(dir), true);
  assert.deepStrictEqual(Object.keys(JSON.parse(fs.readFileSync(path.join(dir, 'device-secret.rotating'), 'utf8'))).sort(), ['startedAt', 'v']);
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'stale');
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).secret, null);
  assert.strictEqual(readDeviceSecret(safe, dir, 'https://other.example').status, 'absent-for-this-server', 'another server still wins');
  assert.strictEqual(readDeviceSecret(mockSafe('gnome_libsecret', { decryptThrows: true }), dir, ORIGIN).status, 'unreadable', 'unreadable still wins');
  assert.strictEqual(clearDeviceSecretRotating(dir), true);
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'ok');
  markDeviceSecretRotating(dir);
  storeDeviceSecret(safe, dir, { deviceId: DEVICE_ID, secret: 'next', epoch: 2, serverOrigin: ORIGIN });
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'ok', 'a completed store ends the in-flight window');
  markDeviceSecretRotating(dir);
  assert.deepStrictEqual(clearDeviceSecret(dir), { removed: true });
  assert.ok(!fs.existsSync(path.join(dir, 'device-secret.rotating')));
  fs.rmSync(dir, { recursive: true, force: true });
});

test('readIdentityMeta returns the NON-SECRET id/epoch/origin, never the secret, even under a rotating marker', () => {
  const dir = tmp();
  const safe = secure();
  storeDeviceSecret(safe, dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET, epoch: 4 });
  const m = readIdentityMeta(safe, dir);
  assert.deepStrictEqual(m, { deviceId: DEVICE_ID, epoch: 4, serverOrigin: canonicalOrigin(ORIGIN) });
  assert.ok(!('secret' in m), 'no secret field at all');
  assert.ok(!JSON.stringify(m).includes(SECRET), 'the secret never appears in the meta');
  // still readable under a ROTATING marker — readDeviceSecret withholds ('stale'), but the reconcile needs the meta
  markDeviceSecretRotating(dir);
  assert.strictEqual(readDeviceSecret(safe, dir, ORIGIN).status, 'stale');
  assert.deepStrictEqual(readIdentityMeta(safe, dir), { deviceId: DEVICE_ID, epoch: 4, serverOrigin: canonicalOrigin(ORIGIN) }, 'the meta is still available for the reconcile');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('readIdentityMeta returns null with no secure store, no blob, or an unreadable blob (never a guess)', () => {
  const dir = tmp();
  assert.strictEqual(readIdentityMeta(mockSafe('gnome_libsecret', { available: false }), dir), null, 'no secure backend');
  assert.strictEqual(readIdentityMeta(secure(), dir), null, 'no blob');
  storeDeviceSecret(secure(), dir, { serverOrigin: ORIGIN, deviceId: DEVICE_ID, secret: SECRET });
  assert.strictEqual(readIdentityMeta(mockSafe('gnome_libsecret', { decryptThrows: true }), dir), null, 'a locked keychain → null');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('hasRotatingMarker reflects the write-ahead marker only, not a terminal stale mark', () => {
  const dir = tmp();
  assert.strictEqual(hasRotatingMarker(dir), false, 'none by default');
  markDeviceSecretRotating(dir);
  assert.strictEqual(hasRotatingMarker(dir), true);
  clearDeviceSecretRotating(dir);
  assert.strictEqual(hasRotatingMarker(dir), false);
  markDeviceSecretStale(dir);
  assert.strictEqual(hasRotatingMarker(dir), false, 'a durable stale mark is not a crash-survivor rotating marker');
  fs.rmSync(dir, { recursive: true, force: true });
});

test('readIdentityMeta passes a missing / non-integer epoch through as null (doubt for the reconcile), never invented as 1', () => {
  const dir = tmp();
  const safe = secure();
  fs.writeFileSync(blobPath(dir), safe.encryptString(JSON.stringify({ v: 1, deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN })));
  assert.deepStrictEqual(readIdentityMeta(safe, dir), { deviceId: DEVICE_ID, epoch: null, serverOrigin: canonicalOrigin(ORIGIN) });
  fs.writeFileSync(blobPath(dir), safe.encryptString(JSON.stringify({ v: 1, deviceId: DEVICE_ID, secret: SECRET, serverOrigin: ORIGIN, epoch: 2.5 })));
  assert.strictEqual(readIdentityMeta(safe, dir).epoch, null, 'a non-integer epoch is null too');
  fs.rmSync(dir, { recursive: true, force: true });
});

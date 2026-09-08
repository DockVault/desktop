'use strict';

/*
 * The background sync scheduler — the first caller of the proven-but-dormant sync engine. It decides
 * WHEN and WHETHER to dispatch a run for each configured Standard vault, and enforces the run-time
 * safety gate on EVERY dispatch, never trusting the enable-time config (which may predate these checks).
 *
 * Load-bearing invariants (all enforced here, unit-tested one by one):
 *   - GLOBAL mutex: mint/refresh-cred -> send -> run is ONE atomic critical section across ALL vaults,
 *     so exactly one credential is ever live in the helper at a time. Further requests QUEUE; a manual
 *     "Sync now" is ordered ahead of routine ticks; a request for a vault already queued or in flight is
 *     coalesced (a manual press joins the in-flight run rather than stacking a second).
 *   - Fail-closed eligibility: a run happens only when the app is UNLOCKED, the account session is live,
 *     and the network is reachable; if any of those is unknown, it does NOT dispatch (never sync blind).
 *     Lock keys off the ACCOUNT-session lifecycle here (Standard sync holds no zero-knowledge key) —
 *     coded explicitly Standard-only so a future zero-knowledge path can add its own key-state gate.
 *   - Run-time re-assertion before every write: the vault is re-confirmed Standard and its remote is
 *     re-derived from the CURRENT name (a renamed / re-tiered / removed vault fails closed); the folder
 *     is re-secured and re-classified.
 *   - Refresh-before-dispatch: the credential is refreshed-if-needed and re-sent before the run; a
 *     refresh failure fails closed (no run on a stale credential).
 *   - Two resync branches: a NEVER-RUN vault (no completed run yet, including an interrupted first sync)
 *     gets its consented INITIAL baseline resync; a vault BLOCKED after a completed run (a safety abort
 *     or an owed resync) is NEVER auto-resynced — it waits for a deliberate Repair. Both resync paths go
 *     through the zero-loss resync (keep-both), never a destructive bare resync.
 *   - The endpoint gate: after a run that could not reach the sync server (or met a changed server
 *     identity), NO credential is minted until the server answers a credential-free probe. A single-use
 *     credential minted against a door that is shut is never spent, yet it counts against the server's
 *     hourly per-computer allowance — the old per-tick minting ended in a misleading "credential limit"
 *     message with the real cause (the server can't be reached) never shown. Routine ticks wait out a
 *     growing back-off; a deliberate press probes at once; the probe's answer IS the surfaced state.
 *   - Bounded minting under ANY refusal: a door that keeps turning this computer's credential away (an auth
 *     refusal, or a refused session channel — a spent single-use credential, a credential or attempt limit, a
 *     server with no session slot free) puts THAT vault on a growing per-vault back-off. The ceiling inside one
 *     window is at most ONE automatic attempt (the tick the window's end releases) plus at most ONE deliberate
 *     attempt (a press or a Repair, only while the window still holds it) — never a burst, and nothing at all
 *     from the ticks and presses in between. The decision is made at the DISPATCH, the one place that can lead
 *     to a mint, so no request-time path can slip past it. Without this a refusing door drew a fresh credential
 *     every tick and every press — each one spent against the very limit that was refusing it.
 *   - "Sync now" cooldown: a deliberate press that reached the mint starts a short per-vault cooldown; a
 *     further press inside it is answered at once (how long until the next is allowed) and mints nothing. A
 *     press that FOLDS INTO the run already in flight for that vault is always free — it costs no credential,
 *     so it is never refused and never starts a cooldown of its own.
 *   - Consent before the mint: the first-upload / Repair confirmation is asked BEFORE a credential is minted,
 *     so a declined (or slow) answer never leaves an unspent credential counting at the server.
 *
 * Pure orchestration over injected IO, so every invariant is unit-testable with no Electron or network.
 */

// The refusals that are SETTLED until a person acts here: re-running them on every routine tick cannot change
// the answer, and for a changed server identity each attempt would mint a credential only to discard it.
// States the SERVER may resolve on its own (a suspension lifted on the web, an account unlocked, a
// credential limit freed as credentials expire) and transient waits (an unreadable store, details pending,
// offline, a failing server) are deliberately NOT here — a later tick can genuinely succeed for those, and
// a refused mint costs nothing.
const HELD_REASONS = new Set([
  'grant-needs-reproof', 'device-revoked', 'device-removed', 'device-expired', 'invalid-device-credential', 'device-secret-stale',
  'no-grant', 'vault-not-standard', 'device-request-refused', 'host-key-mismatch',
]);

// The run results after which the endpoint gate closes (see the class comment): the door could not be reached,
// or the server presented an identity other than the pinned one. Minting again next tick cannot help either.
const CONNECT_RESULTS = new Set(['connect-failed', 'host-key-mismatch']);
// The back-off routine ticks wait after each consecutive connect failure: 5 min, 10, 20, 40, then an hour.
const ENDPOINT_BACKOFF_BASE_MS = 5 * 60 * 1000;
const ENDPOINT_BACKOFF_MAX_MS = 60 * 60 * 1000;
// The refusal class that backs off PER VAULT: the door answered, and turned this computer's credential away.
// (A connect-class failure is the shared endpoint gate above; a settled device-side refusal is a hold.)
const REFUSAL_RESULTS = new Set(['auth-failed', 'channel-refused']);
// The run results that MIGHT be the vault running out of room, and are worth one read of the vault's own
// record to find out. The SFTP door decides at close whether to keep an upload and the protocol gives a close
// no way to say no, so the client sees only that the file is not there ('upload-not-stored'), or a bare
// out-of-space word from the server ('server-no-space') that does not say WHOSE space. Neither names the
// vault's allowance, and neither may be presented as if it did — hence the check (io.vaultSpace), which
// answers from the server's own two numbers or not at all.
const SPACE_SUSPECT_RESULTS = new Set(['upload-not-stored', 'server-no-space']);
// The per-vault back-off after each consecutive refusal — the same schedule as the endpoint gate, and for the
// same reason: every further attempt is a credential spent against a limit that is still refusing.
const REFUSAL_BACKOFF_BASE_MS = 5 * 60 * 1000;
const REFUSAL_BACKOFF_MAX_MS = 60 * 60 * 1000;
// How long after a deliberate press reaches the mint before the next press on the same vault may mint again.
const MANUAL_SYNC_COOLDOWN_MS = 45 * 1000;

class SyncScheduler {
  /**
   * @param {object} io injected input/output surface (all side effects live in the caller)
   * @param {() => Array<{vaultId,vaultName,localFolder,remotePath,enabled}>} io.listConfigured
   * @param {(vaultId:string) => ({lastResult:(string|null),resyncRequired:boolean}|null)} io.runState  null => never-run
   * @param {() => ({locked:boolean,online:boolean,accountLive:boolean,deviceLive?:boolean})} io.session
   * @param {(vaultId:string) => Promise<{ok:true,remotePath:string,vaultName?:string}|{ok:false,reason:string}>} io.verifyEligible
   * @param {(cfg:object) => Promise<{ok:true,folder:string}|{ok:false,reason:string}>} [io.resolveFolder]  find the vault's folder by its marker (folder-identity.js); absent => the configured path is used as-is
   * @param {(localFolder:string) => (({ok:boolean,reason?:string})|Promise<{ok:boolean,reason?:string}>)} io.secureFolder  may be async (applies + reads back a real ACL); it is awaited
   * @param {(localFolder:string) => ({ok:boolean,reason?:string})} io.classify
   * @param {() => Promise<{ok:true}|{ok:false,reason:string}>} [io.probeEndpoint]  a credential-free probe of the sync server (reachable + the pinned identity), run INSTEAD of a mint after a connect failure; absent => the back-off alone bounds the minting
   * @param {() => number} [io.now]
   * @param {(vaultId:string) => Promise<{known:boolean,limitBytes:(number|null),usedBytes:(number|null),freeBytes:(number|null)}>} [io.vaultSpace]  the vault's own allowance and how much of it is stored, read from the server (vault-space.js); asked ONCE after a run whose file the server took and did not keep, so "out of space" is only ever said when the server's numbers say so. Absent, or an answer of `known:false` => the outcome keeps its weaker, true name.
   * @param {(vaultId:string) => Promise<{ok:boolean,reason?:string}>} io.refreshCred
   * @param {(vaultId:string) => (string|null)} [io.credentialPath]  which credential path the vault's run took ('device' | 'account'), when known
   * @param {(vaultId:string) => Promise<boolean>} [io.confirmFirstUpload]  gate the first upload of a not-yet-consented config
   * @param {(spec:{vaultId,local,remotePath,movedFrom?,remoteMovedFrom?}) => Promise<object>} io.runSync    normal bidirectional run
   * @param {(spec:{vaultId,local,remotePath,movedFrom?,remoteMovedFrom?}) => Promise<object>} io.runResync  zero-loss resync (initial baseline / Repair)
   * @param {(vaultId:string, ev:{phase:string,reason?:string,after?:string,outcome?:object}) => void} [io.onEvent]
   */
  constructor(io = {}) {
    this._io = io;
    this._busy = false;
    this._current = null;       // vaultId of the in-flight dispatch, or null
    this._queue = [];           // [{ vaultId, manual, repair }], at most one entry per vaultId
    this._authRetried = new Set(); // vaultIds that have already used their one auth-failed retry this episode
    this._held = new Map();        // vaultId -> the settled device-side refusal that holds routine ticks (see HELD_REASONS)
    this._now = typeof io.now === 'function' ? io.now : () => Date.now();
    // The endpoint gate's state: one sync server serves every vault, so its reachability is shared. `failures`
    // counts consecutive connect-class failures (a probe that failed, or a run that could not connect); `until`
    // is when routine ticks may probe again; `reason` is the last real cause, surfaced meanwhile.
    this._endpoint = { failures: 0, until: 0, reason: null };
    // Per-vault refusal back-off: vaultId -> { failures, until, manualAllowed, reason }. `failures` counts the
    // consecutive refusals; `until` is when a routine tick may try again; `manualAllowed` is whether this window
    // still holds its ONE deliberate attempt — a window opened BY a deliberate attempt does not, else a person
    // could press their way through every window, which is the burst this exists to stop. The record is kept
    // until a run the door ACCEPTS clears it: a stretch of runs that never executed (a down helper, say) teaches
    // nothing about the door's standing, so the last thing it actually said stands — the fail-closed direction.
    this._refusal = new Map();
    // vaultId -> when a deliberate press last reached the mint (the "Sync now" cooldown's clock).
    this._lastManualMint = new Map();
  }

  /** The endpoint gate's view: how many consecutive connect failures, and the cause surfaced meanwhile. */
  endpointState() { return { failures: this._endpoint.failures, reason: this._endpoint.reason, until: this._endpoint.until }; }

  /** A vault's refusal back-off, or null when its door is not known to be refusing. */
  refusalState(vaultId) {
    const r = this._refusal.get(vaultId);
    return r ? { failures: r.failures, until: r.until, manualAllowed: r.manualAllowed, reason: r.reason } : null;
  }

  // Whether a routine tick for this vault is inside its refusal back-off (nothing to mint until it lapses).
  _refusalWaiting(vaultId) { const r = this._refusal.get(vaultId); return !!(r && this._now() < r.until); }

  // A refusal-class run outcome: the door answered and refused. Open (or lengthen) this vault's back-off.
  // `manual` says whether the run that was refused was itself a deliberate attempt — if so, the new window opens
  // with its attempt already spent, so a person cannot walk a burst through by pressing once per window.
  _noteRefusal(vaultId, manual, reason) {
    const r = this._refusal.get(vaultId) || { failures: 0 };
    r.failures += 1;
    r.reason = reason;
    r.until = this._now() + Math.min(REFUSAL_BACKOFF_BASE_MS * (2 ** (r.failures - 1)), REFUSAL_BACKOFF_MAX_MS);
    r.manualAllowed = !manual;
    this._refusal.set(vaultId, r);
  }

  // When this vault's back-off will next let an attempt through, as an absolute time — or null when its door
  // is not on record as refusing. Handed to the status layer so a wait can be stated in words and keep
  // counting down as the glance is read.
  _retryAt(vaultId) { const r = this._refusal.get(vaultId); return r && r.until > this._now() ? r.until : null; }

  // Milliseconds left on the "Sync now" cooldown for this vault, or 0 when a press may mint.
  _cooldownLeft(vaultId) {
    const at = this._lastManualMint.get(vaultId);
    if (at == null) return 0;
    return Math.max(0, at + MANUAL_SYNC_COOLDOWN_MS - this._now());
  }

  // A connect-class failure: close the gate (further) and remember the cause. The back-off doubles per failure.
  _noteConnectFailure(reason) {
    const ep = this._endpoint;
    ep.failures += 1;
    ep.reason = reason;
    ep.until = this._now() + Math.min(ENDPOINT_BACKOFF_BASE_MS * (2 ** (ep.failures - 1)), ENDPOINT_BACKOFF_MAX_MS);
  }

  _clearConnectFailures() { this._endpoint = { failures: 0, until: 0, reason: null }; }

  // The endpoint gate, run in a dispatch's place of minting. Returns the event to emit INSTEAD of minting, or
  // null when this dispatch may go on to mint. Open (no failure on record) => null at once. Closed: a routine
  // tick inside the back-off is answered with the last cause, no probe, no mint; a due tick or a deliberate press
  // probes the server without a credential — an answer opens the gate for this dispatch, a failure closes it
  // further and becomes the surfaced state (unreachable / not the server / a changed identity). With no probe
  // wired, a due tick mints (the back-off alone bounds how often).
  async _endpointGate(manual) {
    const ep = this._endpoint;
    if (ep.failures === 0) return null;
    if (!manual && this._now() < ep.until) return { phase: 'paused', reason: ep.reason || 'sync-server-unreachable' };
    if (typeof this._io.probeEndpoint !== 'function') return null;
    let p;
    try { p = await this._io.probeEndpoint(); } catch { p = { ok: false, reason: 'sync-server-unreachable' }; }
    if (p && p.ok === true) return null;
    const reason = (p && typeof p.reason === 'string' && p.reason) ? p.reason : 'sync-server-unreachable';
    this._noteConnectFailure(reason);
    // A changed server identity is a settled refusal (HELD_REASONS): routine ticks stop until a person acts.
    return { phase: reason === 'host-key-mismatch' ? 'refused' : 'paused', reason };
  }

  _emit(vaultId, ev) {
    // A SETTLED refusal from this computer's sync identity holds the vault's routine ticks: re-dispatching every
    // tick would only re-present the same refusal (and, for a credential cap, mint against it). A run that
    // actually starts, or a deliberate press, lifts the hold — the person's action is what changes the answer.
    if (ev && (ev.phase === 'refused' || ev.phase === 'paused') && HELD_REASONS.has(ev.reason)) this._held.set(vaultId, ev.reason);
    else if (ev && (ev.phase === 'running' || ev.phase === 'done')) this._held.delete(vaultId);
    try { if (this._io.onEvent) this._io.onEvent(vaultId, ev); } catch { /* consumer error is not ours */ }
  }

  /** The settled device-side refusal holding a vault's routine ticks, or null. */
  held(vaultId) { return this._held.get(vaultId) || null; }

  /**
   * Lift every hold (a sign-in, an unlock, or a set-up change may have changed the server's answer) — and open
   * the endpoint gate: a changed SFTP address must be tried at once, not after the old address's back-off.
   */
  releaseHolds() { this._held.clear(); this._clearConnectFailures(); this._refusal.clear(); }

  // Enqueue a request, coalescing per vault. A request for the IN-FLIGHT vault is dropped (the running
  // dispatch already serves it). A manual request is ordered ahead of routine ticks and upgrades an
  // already-queued routine entry to manual.
  _enqueue(vaultId, { manual = false, repair = false, press = false } = {}) {
    // A request for the vault whose run is in flight folds into it — EXCEPT a deliberate Repair, which
    // must SURVIVE (its intent is to re-baseline AFTER the current run, not to join it).
    if (this._current === vaultId && !repair) return;
    const existing = this._queue.find((q) => q.vaultId === vaultId);
    if (existing) {
      if (repair) existing.repair = true;
      if (manual && !existing.manual) { existing.manual = true; existing.press = !!press; this._toManualFifo(existing); } // keep manual FIFO
      return;
    }
    const item = { vaultId, manual: !!manual, repair: !!repair, press: !!press };
    if (manual) {
      // ahead of routine ticks, behind any earlier manual requests
      const lastManual = this._queue.reduce((i, q, idx) => (q.manual ? idx : i), -1);
      this._queue.splice(lastManual + 1, 0, item);
    } else {
      this._queue.push(item);
    }
    // If something is already running or ahead in the queue, this one is honestly "queued", not syncing.
    if (this._busy || this._queue[0] !== item) this._emit(vaultId, { phase: 'queued', after: this._current || undefined });
  }

  // Move an entry to just after the last EARLIER manual entry, so manual requests keep FIFO order
  // (an upgraded routine entry does not jump ahead of manual presses that were already waiting).
  _toManualFifo(entry) {
    const rest = this._queue.filter((q) => q !== entry);
    const lastManual = rest.reduce((i, q, idx) => (q.manual ? idx : i), -1);
    rest.splice(lastManual + 1, 0, entry);
    this._queue = rest;
  }

  /**
   * Request a routine or manual sync for one vault. Progress arrives via onEvent; the return is the immediate
   * verdict on the REQUEST itself: { accepted: true } when it was queued, or folded into the run already in
   * flight for this vault (which costs nothing), or { accepted: false, reason, retryInMs } when it was turned
   * away with no event at all: 'sync-cooldown' (a press inside the cooldown started by the last press that
   * minted), 'backing-off' (the door is refusing this vault and the window's one deliberate attempt is spent),
   * or 'held' (a routine request for a settled refusal — the answer already on the glance stands). A refused
   * request mints nothing and changes nothing; `press: false` marks a deliberate pass that is not a person
   * pressing this vault's button, so it neither reads nor starts the cooldown.
   */
  requestSync(vaultId, { manual = false, press = true } = {}) {
    if (!manual) {
      if (this._held.has(vaultId)) return { accepted: false, reason: 'held' }; // the settled answer stands
      const r = this._refusal.get(vaultId);
      if (r && this._now() < r.until) return { accepted: false, reason: 'backing-off', retryInMs: r.until - this._now(), cause: r.reason };
      this._enqueue(vaultId, { manual: false }); this._pump();
      return { accepted: true };
    }
    return this._requestManual(vaultId, { repair: false, press });
  }

  /**
   * The deliberate Repair action (the only thing that clears a blocked-after-run latch). Same verdict as
   * requestSync. A Repair is not subject to the "Sync now" cooldown — it is confirmed before anything is minted
   * and is often pressed right after the sync that found the repair owed — but it is subject to the refusal
   * back-off like any deliberate press: one attempt per window against a refusing door.
   */
  requestRepair(vaultId) { return this._requestManual(vaultId, { repair: true, press: true }); }

  _requestManual(vaultId, { repair, press = true }) {
    // A press FOLDS INTO the run already in flight for this vault — it costs nothing, so it is never refused.
    // ONLY that case: a press that merely finds an entry QUEUED still leads to a dispatch that mints, and a
    // Repair is never folded (_enqueue keeps it deliberately), so both face the gates like any other request.
    const joins = !repair && this._current === vaultId;
    if (!joins) {
      // A bulk deliberate pass (a folder just found again re-runs every vault) is not a person pressing THIS
      // vault's button: it is ordered ahead and clears holds, but it neither reads nor starts the cooldown.
      const left = (repair || !press) ? 0 : this._cooldownLeft(vaultId);
      if (left > 0) return { accepted: false, reason: 'sync-cooldown', retryInMs: left };
      const r = this._refusal.get(vaultId);
      if (r && this._now() < r.until && !r.manualAllowed) return { accepted: false, reason: 'backing-off', retryInMs: r.until - this._now(), cause: r.reason };
    }
    this._held.delete(vaultId); // a deliberate press always gets one fresh answer
    this._enqueue(vaultId, { manual: true, repair, press });
    this._pump();
    return { accepted: true };
  }

  /**
   * The vaultId whose run is in flight right now, or null. It is the ONLY vault a per-step credential request
   * may be authorised for: the helper's requested vaultId is checked against this, never trusted as an input.
   */
  current() { return this._busy ? this._current : null; }

  /** A routine cadence tick: enqueue a run for every enabled configured vault (coalesced). */
  tickAll() {
    for (const c of this._io.listConfigured() || []) {
      if (!c || !c.enabled || this._held.has(c.vaultId) || this._refusalWaiting(c.vaultId)) continue;
      this._enqueue(c.vaultId, { manual: false });
    }
    this._pump();
  }

  _pump() {
    if (this._busy || this._queue.length === 0) return;
    const item = this._queue.shift();
    this._busy = true;
    this._current = item.vaultId;
    Promise.resolve()
      .then(() => this._dispatch(item))
      .catch(() => { /* a dispatch never rejects into the pump; _dispatch handles its own errors */ })
      .finally(() => { this._busy = false; this._current = null; this._pump(); });
  }

  // The atomic critical section: one credential live, one run, at a time. Every gate below is
  // fail-closed — on any doubt it emits a non-running status and returns WITHOUT dispatching. The whole
  // body is wrapped: a dep that THROWS (a fetch that rejects, a dead helper channel) must surface as a
  // terminal 'error', never leave the vault stuck at 'running' (which the status would read as an endless
  // "syncing" — the exact lie this design forbids).
  async _dispatch(item) {
    const { vaultId, repair } = item;
    const io = this._io;
    try {
      const cfg = (io.listConfigured() || []).find((c) => c && c.vaultId === vaultId);
      if (!cfg || !cfg.enabled) { this._emit(vaultId, { phase: 'skipped', reason: 'not-configured' }); return; }

      // Eligibility, fail-closed on uncertainty.
      const s = io.session ? io.session() : {};
      if (!s || typeof s.locked !== 'boolean' || typeof s.online !== 'boolean' || typeof s.accountLive !== 'boolean') {
        this._emit(vaultId, { phase: 'skipped', reason: 'state-uncertain' }); return;
      }
      // The account-tier lock splits by path: a vault synced on THIS computer's own device identity keeps
      // running under the OS lock, while an account-path vault still pauses. The path is decided per run at the
      // eligibility step below (which latches it), so here we can only refuse EARLY when there is no device
      // identity that could carry a run — every vault is then account-path and the lock pauses it. With a device
      // identity present we proceed and re-check the LATCHED path after eligibility (fail-closed, below).
      if (s.locked && s.deviceLive !== true) { this._emit(vaultId, { phase: 'skipped', reason: 'paused-locked' }); return; }
      // A run needs SOME principal: the account session, or this computer's own sync identity. Which one a vault
      // uses is the eligibility step's decision; a vault that needs the one that is missing is refused there.
      if (!s.accountLive && s.deviceLive !== true) { this._emit(vaultId, { phase: 'skipped', reason: 'no-session' }); return; }
      if (!s.online) { this._emit(vaultId, { phase: 'paused', reason: 'waiting-to-reconnect' }); return; } // offline

      // A vault BLOCKED after a completed run is never auto-resynced — cheap no-op, needs a deliberate Repair.
      const st = io.runState ? io.runState(vaultId) : null;
      // 'unknown' = the run-state could not be read (a throwing store, or no state DB this session). It is NOT
      // never-run: dispatching would spuriously initial-resync a possibly-established vault. Skip, uncertain.
      if (st === 'unknown') { this._emit(vaultId, { phase: 'skipped', reason: 'state-uncertain' }); return; }
      const neverRun = !st || st.lastResult == null;
      if (!repair && !neverRun && st.resyncRequired) { this._emit(vaultId, { phase: 'blocked', reason: 'needs-repair' }); return; }

      // Run-time re-assertion (fail-closed): still a server-confirmed Standard vault; remote re-derived from the CURRENT name.
      const el = await io.verifyEligible(vaultId);
      if (!el || !el.ok) { this._emit(vaultId, { phase: 'refused', reason: (el && el.reason) || 'ineligible' }); return; }
      // The eligibility step latched the credential path. Under the account-tier lock, ONLY the device path
      // proceeds (this computer's own identity, no account session or zero-knowledge key); an account path — or an
      // eligibility result that did not name the device path — pauses. Fail-closed: any doubt pauses under lock.
      if (s.locked && el.via !== 'device') { this._emit(vaultId, { phase: 'skipped', reason: 'paused-locked' }); return; }
      const remotePath = el.remotePath;

      // The folder is known by its marker, not its path: a moved or renamed folder is followed, a folder that
      // cannot be found (or is not the one the marker names) PAUSES the vault — nothing is ever written to a
      // folder whose identity is in doubt. Without a resolver (a bare test io) the configured path stands.
      let localFolder = cfg.localFolder;
      // Where the folder was before a move, for the engine to carry its prior listings over: a move just
      // followed, or one recorded on the config from an earlier tick whose run did not complete.
      let movedFrom = typeof cfg.movedFrom === 'string' ? cfg.movedFrom : undefined;
      if (typeof io.resolveFolder === 'function') {
        const rf = await io.resolveFolder(cfg);
        if (!rf || !rf.ok || typeof rf.folder !== 'string' || !rf.folder) { this._emit(vaultId, { phase: 'paused', reason: (rf && rf.reason) || 'folder-missing', folders: (rf && rf.folders) || undefined }); return; }
        localFolder = rf.folder;
        if (rf.moved && typeof rf.moved.from === 'string') movedFrom = rf.moved.from;
      }
      // Re-secure + re-classify the folder before any write (covers configs/folders created before these
      // checks). secureFolder may be async (it applies + reads back a real ACL), so it is awaited — a
      // Promise left unawaited would read as a truthy object with no `ok` and wrongly refuse every run.
      const sec = await io.secureFolder(localFolder);
      if (!sec || !sec.ok) { this._emit(vaultId, { phase: 'refused', reason: (sec && sec.reason) || 'folder-insecure' }); return; }
      const cl = io.classify(localFolder);
      if (!cl || !cl.ok) { this._emit(vaultId, { phase: 'refused', reason: (cl && cl.reason) || 'folder-rejected' }); return; }

      // gate-before-mint: verify the sync helper is READY before minting a single-use credential. This SKIPS the
      // mint on ANY not-ready result, so a not-ready helper never burns a single-use server credential. The reply
      // is then split by SHAPE (see the precedence note below): a typed answer (a `sub`: wrong version, failed
      // checksum, can't-prepare) is the non-retrying 'helper-not-ready' fix-the-setup lane; a no-answer transport
      // failure (no sub) is the calm, retryable 'helper-unavailable' lane — a DOWN helper is never misconfigured.
      // A MISSING io.helperReady is a wiring fault, not a green light: fail CLOSED (treat the helper as not
      // ready) so a gate that was never wired can never mint a credential — the io-contract test guarantees the
      // method is present in production, so this fallback is only reachable in a mis-wired build or a bare test.
      const hr = typeof io.helperReady === 'function' ? await io.helperReady() : { ok: false, sub: 'prepare-failed' };
      if (!hr || !hr.ok) {
        // PRECEDENCE: a reply carrying a `sub` is the helper ANSWERING not-ready (a wrong version / failed
        // checksum / can't-prepare) — the non-retrying, fix-the-setup lane — even if a `reason` also rides along.
        // A reply with NO sub is a NO-ANSWER transport failure (the daemon is down, timed out, or exited): the
        // calm, RETRYABLE 'helper-unavailable' lane, so a crashed-but-fine helper is never mislabelled as
        // misconfigured, and the single must-act on a crash stays the hub's own 'restart'.
        if (hr && hr.sub) { this._emit(vaultId, { phase: 'refused', reason: 'helper-not-ready', sub: hr.sub, installed: hr.installed || null }); return; }
        this._emit(vaultId, { phase: 'paused', reason: 'helper-unavailable' });
        return;
      }

      // The endpoint gate (see the class comment): after a connect-class failure nothing is minted until the sync
      // server answers a credential-free probe. Placed right before the mint so every cheaper refusal above still
      // wins, and after the helper gate so a down helper is never mistaken for a down server.
      const gate = await this._endpointGate(!!item.manual);
      if (gate) { this._emit(vaultId, gate); return; }

      // The refusal back-off (see the class comment) — decided HERE, at the one place a dispatch can lead to a
      // mint, so no request-time shortcut can slip past it: a routine tick inside the window never runs, and a
      // deliberate one runs only while the window still holds its single attempt (spent at the mint below). The
      // request-time verdict is the same rule read early for the person who pressed; THIS is what enforces it.
      // Keeps the last state: the refusal already on the glance IS the honest answer, and nothing new was learned.
      const rf = this._refusal.get(vaultId);
      if (rf && this._now() < rf.until && (!item.manual || !rf.manualAllowed)) {
        // `cause` is WHICH refusal opened the window: a server limiting attempts ('channel-refused') and a
        // credential the server would not accept ('auth-failed') both wait, but only one of them is ever helped
        // by signing in — so the answer a person gets must be able to tell them apart.
        this._emit(vaultId, { phase: 'skipped', reason: 'backing-off', retryInMs: rf.until - this._now(), cause: rf.reason });
        return;
      }

      const useResync = repair || neverRun; // initial baseline OR deliberate Repair — always zero-loss (keep-both)
      // The first upload is gated, fail-closed — and asked BEFORE the mint, so a declined (or long-pondered)
      // answer never leaves an unspent credential counting at the server. `kind` lets the caller show the right
      // dialog: an initial first-upload (the two-way consent for a not-yet-consented config) vs a Repair confirm —
      // and lets an already-consented config's Repair skip the two-way consent it was already asked.
      if (useResync && io.confirmFirstUpload) {
        let proceed = false;
        try { proceed = await io.confirmFirstUpload({ vaultId, kind: repair ? 'repair' : 'initial' }); } catch { proceed = false; }
        if (!proceed) { this._emit(vaultId, { phase: 'skipped', reason: 'consent-declined' }); return; }
      }

      // A deliberate press that gets this far is about to mint: start its cooldown. Stamped HERE and not at the
      // press, so a press turned away by a cheaper gate above (nothing minted) may be repeated freely and answered
      // honestly each time, while the one that costs a credential is what the cooldown bounds.
      if (item.manual) {
        if (item.press !== false) this._lastManualMint.set(vaultId, this._now());
        const r = this._refusal.get(vaultId);
        if (r && this._now() < r.until) r.manualAllowed = false; // this deliberate run is the window's one attempt
      }
      // Refresh + re-send the credential before dispatch; a refresh failure fails closed. A readiness/prepare
      // failure that surfaces HERE (past the gate) is likewise the non-retrying 'helper-not-ready' + its sub.
      const cr = await io.refreshCred(vaultId);
      if (!cr || !cr.ok) { this._emit(vaultId, { phase: 'paused', reason: (cr && cr.reason) || 'cred-refresh-failed', sub: (cr && cr.sub) || null, installed: (cr && cr.installed) || null }); return; }

      // The remote path the last completed run used, when it differs from this run's: the engine re-keys the
      // pair's listings so an account<->device path switch continues from the same baseline.
      const remoteMovedFrom = (typeof cfg.lastRemotePath === 'string' && cfg.lastRemotePath && cfg.lastRemotePath !== remotePath) ? cfg.lastRemotePath : undefined;
      const spec = { vaultId, local: localFolder, remotePath, ...(movedFrom && movedFrom !== localFolder ? { movedFrom } : {}), ...(remoteMovedFrom ? { remoteMovedFrom } : {}) };
      this._emit(vaultId, { phase: 'running' });
      const outcome = useResync ? await io.runResync(spec) : await io.runSync(spec);
      // A BENIGN refusal: the helper already has a run in flight for this vault (its in-flight guard fired,
      // which only happens when a healthy long run is still going). Route it by the TYPED field, never the
      // prose. It is neither a failure nor a completion — emit a no-op that leaves the in-flight run's
      // status untouched, so it is never counted toward the failure streak nor stamped as a completed run.
      if (outcome && outcome.refused === 'already-running') {
        this._emit(vaultId, { phase: 'noop', reason: 'already-running' });
        return outcome;
      }
      // A run stopped by a TRANSIENT authority refusal mid-resync (a per-step credential request refused because
      // the app locked, or went offline) did not happen and carries no typed result — read it as the same calm
      // skip the pre-dispatch gate emits (keeps the last state, no notification), never a 'couldn't sync' error.
      if (outcome && outcome.ran === false && outcome.result == null && outcome.reason) {
        this._emit(vaultId, { phase: 'skipped', reason: outcome.reason });
        return outcome;
      }
      // A single 'auth-failed' from a run that DID execute may be a boundary race (the single-use credential
      // lapsed or was spent right at connect) rather than a real account problem — the two are otherwise
      // indistinguishable. Retry ONCE with a fresh mint (a fresh dispatch re-mints) before letting it latch a
      // "sign in": emit a calm retry and re-enqueue, not the 'done' that maps to sign-in-needed. A SECOND
      // consecutive auth-failed falls through to 'done' and latches — a genuine session problem. Any other
      // outcome clears the one-shot, so each episode gets its single retry.
      // The one-shot retry is for the RACE only: once this vault's door is on record as refusing (a back-off is
      // open), a further refusal is the door still refusing, and retrying at once would be exactly the second
      // credential per attempt the back-off exists to stop.
      const refused = !!(outcome && outcome.ran === true && REFUSAL_RESULTS.has(outcome.result));
      if (refused && !this._authRetried.has(vaultId) && !this._refusal.has(vaultId)) {
        this._authRetried.add(vaultId);
        this._emit(vaultId, { phase: 'paused', reason: 'retrying' });
        // Queue the one retry directly: _enqueue would coalesce it away because _current is still this vault
        // mid-dispatch. It dispatches on the next pump, once the finally has cleared _current. Skip if the vault
        // is already queued (a manual press, say) — that pending run is the retry. Carry the dispatch's identity:
        // a Repair must retry AS a repair (else it re-hits the blocked gate and reads "repair owed again"), and a
        // manual press must retry AS manual so the press is answered by the retry's real outcome.
        if (!this._queue.some((q) => q.vaultId === vaultId)) this._queue.push({ vaultId, manual: !!item.manual, repair: !!repair, press: item.press !== false });
        return outcome;
      }
      // What the run taught the two minting bounds, learned BEFORE the outcome is routed to its state (several
      // routes below return early). The refusal back-off: a refused run opens or lengthens this vault's window;
      // any other run that executed clears it (the door took a credential again). The endpoint gate: a
      // connect-class result closes it (the next dispatch probes instead of minting); any run that actually
      // reached the server — refused or not — opens it again.
      if (refused) this._noteRefusal(vaultId, !!item.manual, outcome.result);
      else if (outcome && outcome.ran === true) this._refusal.delete(vaultId);
      if (outcome && CONNECT_RESULTS.has(outcome.result)) this._noteConnectFailure(outcome.result === 'host-key-mismatch' ? 'host-key-mismatch' : 'sync-server-unreachable');
      else if (outcome && outcome.ran === true) this._clearConnectFailures();
      // a persistent auth-failed (past its one retry) for a PASSWORD-PROTECTED vault is far more likely a
      // server-side vault-password ROTATION — the mint's password proof was voided — than a dead account session.
      // Route it to the "needs unlock" must-act (re-enter the vault password), NOT the sign-in latch, by rewriting
      // the latching outcome to a distinct typed result the status model maps to that state. A vault with no
      // password still latches sign-in (its auth-failed can only be the account credential).
      // On the DEVICE path an auth failure past its retry is never an account or vault-password matter: the
      // device's own standing (revoked, suspended, a rotated vault password) is re-checked on the next pass and
      // surfaces as its own state there. Record a calm, distinct outcome instead of the account remedies.
      if (outcome && outcome.ran === true && outcome.result === 'auth-failed'
          && typeof this._io.credentialPath === 'function' && this._io.credentialPath(vaultId) === 'device') {
        this._authRetried.delete(vaultId);
        this._emit(vaultId, { phase: 'done', outcome: { ...outcome, result: 'auth-failed-device' } });
        return outcome;
      }
      if (outcome && outcome.ran === true && outcome.result === 'auth-failed'
          && typeof this._io.vaultHasPassword === 'function' && this._io.vaultHasPassword(vaultId)) {
        this._authRetried.delete(vaultId);
        this._emit(vaultId, { phase: 'done', outcome: { ...outcome, result: 'auth-failed-locked' } });
        return outcome;
      }
      if (!(outcome && outcome.ran === true && outcome.result === 'auth-failed')) this._authRetried.delete(vaultId);
      // A file the server took and then did not keep, or a bare "no space" from it. Ask the vault's own record
      // ONCE whether the allowance is spent, so "this vault is out of space" is said only when the server's
      // numbers say it — and never guessed from a silence that has several possible causes. The space picture
      // rides along either way (the honest line names what is free when it is known); a check that cannot
      // answer changes nothing, so the outcome keeps its own, weaker, true name.
      if (outcome && outcome.ran === true && SPACE_SUSPECT_RESULTS.has(outcome.result)
          && typeof this._io.vaultSpace === 'function') {
        let space = null;
        try { space = await this._io.vaultSpace(vaultId); } catch { space = null; }
        if (space && space.known === true) {
          const detail = { ...(outcome.detail || {}), limitBytes: space.limitBytes, freeBytes: space.freeBytes };
          // Out of space is claimed on either of two facts the server's own numbers establish, and on nothing
          // else: the allowance is entirely spent, or what is left is smaller than the file that was refused
          // (its size read from the untouched local copy). The second is the case people actually meet — a
          // vault with a little room left still cannot take a file bigger than that room — and without it a
          // real "no room for this" would be reported as the vague "the server didn't keep it". With no file
          // size to compare, only the first fact can be established, and the weaker true name stands.
          const noRoomAtAll = space.freeBytes <= 0;
          const tooBigForWhatIsLeft = Number.isFinite(detail.bytes) && detail.bytes > 0 && space.freeBytes < detail.bytes;
          const result = (noRoomAtAll || tooBigForWhatIsLeft) ? 'vault-full' : outcome.result;
          this._emit(vaultId, { phase: 'done', outcome: { ...outcome, result, detail }, remotePath });
          return outcome;
        }
      }
      // A run that could not EXECUTE (timeout / no helper / send-failed) resolves { ok:false } — that is an
      // 'error', not 'done'. 'done' means the run ran; its typed result (which may still be a conflict or a
      // safety abort) is carried in `outcome` for the status model to classify.
      if (!outcome || outcome.ok === false) {
        this._emit(vaultId, { phase: 'error', reason: (outcome && (outcome.reason || outcome.error || outcome.result)) || 'run-failed', outcome: outcome || null });
      } else {
        // `remotePath` names the server-side path this run used, so the caller can remember it for the next
        // run's carry-over (a vault name or an id form — never a local path).
        // A refused run also carries WHEN the back-off will let the next attempt through, as an absolute time.
        // It is what turns "the server is limiting sync attempts" into a sentence with a wait in it. Absolute
        // rather than a duration on purpose: a duration frozen at the moment of the refusal would be a lie a
        // minute later, whereas an instant can be re-read against the clock every time a surface is rendered
        // (which is why the tray re-renders itself while a wait is live).
        this._emit(vaultId, { phase: 'done', outcome, remotePath, retryAt: refused ? this._retryAt(vaultId) : null });
      }
      return outcome;
    } catch (e) {
      this._emit(vaultId, { phase: 'error', reason: String((e && e.message) || e) });
    }
  }
}

module.exports = { SyncScheduler, CONNECT_RESULTS, REFUSAL_RESULTS, ENDPOINT_BACKOFF_BASE_MS, ENDPOINT_BACKOFF_MAX_MS, REFUSAL_BACKOFF_BASE_MS, REFUSAL_BACKOFF_MAX_MS, MANUAL_SYNC_COOLDOWN_MS };

'use strict';

/*
 * The sync setup wizard — the flow behind the in-app "Set up sync" window, as one testable sequence.
 *
 * The wizard is a conversation: main poses one typed QUESTION at a time ({ id, kind, ...facts }) and the
 * page answers it ({ id, value }). Everything that decides or acts stays here and in the modules this
 * drives; the page only renders the current question and hands back a choice. So the renderer can never
 * name a folder (the folder comes from a native picker main opens), never supply a config, never pick a
 * vault outside the server's own list, and never skip a check: the answers are choices among things main
 * offered, and every safety rule of the enable flow (sync-enable.js) and the device step (device-enable.js)
 * runs unchanged underneath.
 *
 * The steps, in order — each shown only when it applies:
 *   0  gates    signed in? does the server support syncing from a computer? can the sync settings be read?
 *   1  address  the file transfer (SFTP) address, when none was verified at setup (a setting saved before the
 *              address was asked for, or a setup where the server's support could not be told). Verified the
 *              same way the setup screen verifies it, then saved beside the server.
 *   2  computer "set this computer up to sync" — register it (or switch it here from another server, with
 *              consent), shown only when it is not already set up. Required: the wizard sets up syncing on
 *              THIS computer's own identity, never silently through the sign-in.
 *   2b existing when vaults already sync through the sign-in on this computer, offer to move them onto it.
 *   3  vault    pick a vault (the server's Standard list, in the window).
 *   4  folder   choose a folder (native picker), the folder checks (refused / cloud / shared), the readable-
 *              copies consent — the enable flow's own order.
 *   5  grant    grant the vault to this computer; a password vault that is not open defers (the resume finishes
 *              it when it is next opened) and the wizard says so.
 *
 * Every question carries a fresh id; an answer for any other id is ignored, so a stale click can never
 * answer a later question. cancel() ends the flow at whatever question is pending, and at the next checkpoint
 * when a step was in flight: nothing further is asked, no new step starts, and a step the person had already
 * confirmed (a save, a grant) completes rather than being torn in half.
 */

const { runEnableFlow } = require('./sync-enable');
const { runDeviceRegistration, runDeviceGrant } = require('./device-enable');

const CANCELLED = Symbol('cancelled');
class Cancelled extends Error { constructor() { super('sync setup cancelled'); this.cancelled = true; } }

/**
 * @param {object} io  every side effect, injected (see index.js for the app's wiring):
 *   gather()                      -> { signedIn, support: 'ok'|'too-old'|'auth'|'indeterminate', deviceStatus,
 *                                      otherServerHost, sftpSaved, sftpSuggestion, configUnreadable, label,
 *                                      existing: [{vaultId, vaultName, hasPassword}] }   (existing = vaults syncing
 *                                      through the sign-in with no grant record here)
 *   verifySftp(text)              -> { kind, host, port, fingerprint? }   (the setup screen's SFTP leg)
 *   saveSftp({host, port})
 *   registration                  -> the device-enable io members probe / readStatus / forget / register
 *   grantVault(vault)             -> the device-enable grantVault member
 *   addPending(vaultId)           -> record a deferred grant for the resume sweep
 *   enable                        -> the sync-enable io members that are NOT questions: listVaults, resolveReal,
 *                                    classifyCtx, inspectFolderSharing, makePrivate, isNonEmptyDir, ensureFolder, markFolder, save;
 *                                    plus someExcluded() (the picker note), configuredFolder(vaultId) (the folder a
 *                                    vault already syncs to here, or null) and vaultHasPassword(vaultId)
 *   pickFolderNative()            -> the OS directory picker; null when cancelled
 *   consentNotes({vaultId, folder}) -> { priorFolder, outsideProfile } for the consent copy
 *   cloudServiceName(folder)      -> the cloud service a folder is inside
 *   copy                          -> the app's own wording, so the page shows the same sentences the tray flows did:
 *                                    refuse(reason), cloud(service), consent(vaultName, folder, {nonEmpty}),
 *                                    deviceOutcome(result, {vaultName}) -> string
 *   afterSave(entry)              -> the app's reaction to a saved config (start the first run, refresh)
 *   onIdentityChanged()           -> refresh whatever reads the identity
 * @param {(question: object) => void} [onQuestion]  told each time a new question is posed
 */
function createSyncWizard(io, onQuestion = () => {}) {
  let nextId = 1;
  let pending = null;   // { id, resolve }
  let current = null;   // the question the page should be showing
  let cancelled = false;
  let finished = false;

  function pose(kind, facts = {}, terminal = false) {
    const q = { id: nextId++, kind, terminal, ...facts };
    current = q;
    try { onQuestion(q); } catch { /* the page's problem */ }
    return q;
  }

  // Ask the page and wait for its answer. Resolves the answer's value; throws Cancelled once cancel() ran.
  function ask(kind, facts) {
    if (cancelled) return Promise.reject(new Cancelled());
    const q = pose(kind, facts);
    return new Promise((resolve, reject) => {
      pending = { id: q.id, resolve: (v) => { pending = null; if (v === CANCELLED) reject(new Cancelled()); else resolve(v); } };
    });
  }

  // A terminal statement: the page shows it with a single way out; nothing more is asked.
  function end(kind, facts) { finished = true; pose(kind, facts, true); return { kind, ...facts }; }

  /** The page's initial read, and its refresh after a reload: the question currently posed (or null). */
  function currentQuestion() { return current; }

  /** The page's answer to question `id`. An answer to any other id is ignored (a stale click). */
  function answer(id, value) {
    if (!pending || pending.id !== id) return false;
    pending.resolve(value);
    return true;
  }

  /** End the flow wherever it stands: the pending question is dropped, and no further step starts. */
  function cancel() {
    cancelled = true;
    if (pending) pending.resolve(CANCELLED);
  }
  // Between steps: a cancel that arrived while a step was in flight takes effect here, before the next one.
  function checkpoint() { if (cancelled) throw new Cancelled(); }

  async function setUpComputer(facts) {
    // One question carries the register consent and, for a computer bound to another server, the switch
    // consent too: the permanent name, the can't-rename truth, the under-lock disclosure, and the other server.
    // The switch is keyed on the identity's STATUS, so the irreversible forget can only follow a question that
    // showed the switch; a status that changed underneath reads as a declined switch, never a silent forget.
    const switching = facts.deviceStatus === 'absent-for-this-server';
    const agreed = await ask('set-up-computer', { label: facts.label, switchFrom: switching ? (facts.otherServerHost || 'another server') : null });
    if (agreed !== true) return { ok: false, outcome: { outcome: 'register-cancelled' } };
    const reg = io.registration;
    return runDeviceRegistration({
      probe: reg.probe,
      readStatus: reg.readStatus,
      confirmSwitchServer: async () => switching,   // consented in the question above, and only if it was shown
      forget: reg.forget,
      promptLabel: async () => facts.label,        // the very name that was shown and accepted
      register: reg.register,
    });
  }

  // The account-path outcomes of a registration that did not happen, as the wizard's own terminal statements.
  function endForRegistration(outcome) {
    const o = outcome || {};
    if (o.outcome === 'sign-in') return end('sign-in', {});
    if (o.outcome === 'account-only') {
      if (o.reason === 'server-too-old') return end('unsupported', { reason: 'too-old' });
      if (o.reason === 'indeterminate') return end('unsupported', { reason: 'unknown' });
      const status = o.reason === 'no-secure-store' ? 'no-secure-store' : (o.reason === 'identity-stale' ? 'stale' : 'unreadable');
      return end('computer-problem', { status });
    }
    return end('register-failed', { reason: o.reason || 'register-refused', switched: !!o.switched, outcome: o.outcome || 'register-failed' });
  }

  async function moveExisting(existing) {
    const move = await ask('move-existing', { vaults: existing.map((v) => ({ vaultId: v.vaultId, vaultName: v.vaultName, hasPassword: !!v.hasPassword })) });
    if (move !== true) return [];
    const results = [];
    for (const v of existing) {
      checkpoint();
      let r;
      try { r = await runDeviceGrant({ grantVault: io.grantVault }, v); } catch { r = { via: 'account', outcome: 'grant-failed', reason: 'device-step-error' }; }
      if (r.outcome === 'grant-deferred') { try { io.addPending(v.vaultId); } catch { /* the resume sweep is best-effort */ } }
      results.push({ vaultId: v.vaultId, vaultName: v.vaultName, outcome: r.outcome, reason: r.reason || null, message: io.copy.deviceOutcome(r, { vaultName: v.vaultName, hasPassword: !!v.hasPassword }) });
    }
    try { io.onIdentityChanged(); } catch { /* best-effort */ }
    return results;
  }

  // The enable flow's questions, answered by the page. The flow itself (order, checks, what is saved) is
  // sync-enable.js, unchanged.
  let currentVaultName = '';
  let currentVaultId = null;
  function enableIo(vaultsShown) {
    let refusal = null; // the last refused folder's reason, shown with the next folder question
    const e = io.enable;
    return {
      listVaults: async () => vaultsShown,
      pickVault: async (vaults) => {
        const chosen = await ask('pick-vault', { vaults: vaults.map((v) => ({ vaultId: v.vaultId, vaultName: v.vaultName, hasPassword: v.hasPassword !== false, configured: !!v.configured })), someExcluded: !!io.enable.someExcluded() });
        return typeof chosen === 'string' ? (vaults.find((v) => v.vaultId === chosen) || null) : null;
      },
      pickFolder: async () => {
        for (;;) {
          const go = await ask('pick-folder', { vaultName: currentVaultName, currentFolder: currentVaultId ? (e.configuredFolder(currentVaultId) || null) : null, refusal: refusal ? { reason: refusal, message: io.copy.refuse(refusal) } : null });
          refusal = null;
          if (go !== 'choose') return null;
          const picked = await io.pickFolderNative();
          if (picked) return picked; // the OS picker was dismissed: ask again, nothing changed
        }
      },
      resolveReal: e.resolveReal,
      classifyCtx: e.classifyCtx,
      confirmCloud: async (folder) => {
        const service = io.cloudServiceName(folder);
        return (await ask('confirm-cloud', { folder, service, message: io.copy.cloud(service) })) === true;
      },
      inspectFolderSharing: e.inspectFolderSharing,
      confirmMakePrivate: async ({ folder, shares, denies }) => {
        const d = await ask('confirm-make-private', { folder, shares, denies });
        return d === 'make-private' || d === 'choose-different' ? d : 'cancel';
      },
      makePrivate: e.makePrivate,
      isNonEmptyDir: e.isNonEmptyDir,
      confirmConsent: async ({ vaultId, vaultName, folder, nonEmpty }) => {
        const notes = io.consentNotes({ vaultId, folder }) || {};
        const a = await ask('consent', { vaultId, vaultName, folder, nonEmpty: !!nonEmpty, priorFolder: notes.priorFolder || null, outsideProfile: !!notes.outsideProfile, message: io.copy.consent(vaultName, folder, { nonEmpty: !!nonEmpty }) });
        // true = consented; 'choose-different' = back to the folder step (the enable flow re-picks); anything else = leave.
        return a === true ? true : (a === 'choose-different' ? 'choose-different' : false);
      },
      ensureFolder: e.ensureFolder,
      markFolder: e.markFolder,
      // WHAT THE PICKED FOLDER HAS ALREADY BEEN USED FOR. These four are what make the re-use step run at
      // all: runEnableFlow skips the whole block when `readMarker` is absent, so leaving them out of this
      // object did not fail — it silently turned the step off, and another vault's marker went back to being
      // taken over without anyone being asked. This io is an explicit whitelist, which is the right shape;
      // the cost is that a step added to the flow has to be added HERE too, and forgetting is invisible.
      readMarker: e.readMarker,
      knownFolderFor: e.knownFolderFor,
      vaultNameFor: e.vaultNameFor,
      confirmReuse: async ({ title, detail, reuse, folder }) => {
        const d = await ask('confirm-reuse', {
          folder,
          heading: title,
          message: detail,
          // Taking over another vault's marker is the one outcome here that costs something, so the page
          // leads with the safe choice for that and not for the rest.
          takeover: !!(reuse && reuse.takesOverMarker),
        });
        return d === 'use' ? true : (d === 'choose-different' ? 'choose-different' : false);
      },
      onRefuse: async (reason) => { refusal = reason; },
      save: e.save,
    };
  }

  /** Run the whole conversation. Resolves the terminal statement, or { kind: 'cancelled' }. */
  async function run() {
    try {
      const facts = await io.gather();
      if (facts.configUnreadable) return end('failed', { reason: 'config-unreadable' });
      if (!facts.signedIn) return end('sign-in', {});
      if (facts.support === 'auth') return end('sign-in', {});
      if (facts.support !== 'ok') return end('unsupported', { reason: facts.support === 'too-old' ? 'too-old' : 'unknown' });

      // Step 1: the file transfer address, when none was verified for this server yet.
      if (!facts.sftpSaved) {
        let previous = null;
        for (;;) {
          const typed = await ask('sftp-address', { suggestion: facts.sftpSuggestion || '', previous });
          if (typeof typed !== 'string') throw new Cancelled();
          const v = await io.verifySftp(typed);
          checkpoint(); // a window closed during the check saves nothing
          if (v && v.kind === 'ok') { io.saveSftp({ host: v.host, port: v.port }); break; }
          previous = { kind: (v && v.kind) || 'failed', host: (v && v.host) || '', port: (v && v.port) || 0, text: typed };
        }
      }

      // Step 2: this computer. Only a live identity for this server skips it; a problem state stops with its reason.
      const status = facts.deviceStatus;
      if (status !== 'ok') {
        if (status !== 'absent' && status !== 'absent-for-this-server') return end('computer-problem', { status });
        const r = await setUpComputer(facts);
        if (!r.ok) {
          if (r.outcome && r.outcome.outcome === 'register-cancelled') throw new Cancelled();
          return endForRegistration(r.outcome);
        }
        try { io.onIdentityChanged(); } catch { /* best-effort */ }
        checkpoint();
      }

      // Step 2b: vaults already syncing through the sign-in here can move onto this computer now. What happened to
      // each is shown right away — the person may have come for exactly this — with a way out or a way on.
      let moved = [];
      if (Array.isArray(facts.existing) && facts.existing.length) {
        moved = await moveExisting(facts.existing);
        if (moved.length) {
          const next = await ask('moved', { moved });
          if (next !== 'continue') return end('done-moved', { moved });
        }
      }

      // Steps 3–5: the enable flow, then the grant.
      checkpoint();
      const vaults = await io.enable.listVaults();
      checkpoint();
      if (!Array.isArray(vaults) || vaults.length === 0) return end('no-vaults', { moved });
      const shown = vaults.map((v) => ({ ...v, configured: !!io.enable.configuredFolder(v.vaultId) }));
      const flow = enableIo(shown);
      const origPickVault = flow.pickVault;
      flow.pickVault = async (list) => { const v = await origPickVault(list); currentVaultName = v ? v.vaultName : ''; currentVaultId = v ? v.vaultId : null; return v; };
      const r = await runEnableFlow(flow);
      if (!r || !r.enabled) {
        if (r && r.cancelled) throw new Cancelled();
        return end('failed', { reason: (r && r.reason) || 'error', vaultName: (r && r.vaultName) || null, moved });
      }
      // The grant comes BEFORE the first run is kicked (afterSave), so that run already takes this computer's own
      // path; a deferred or failed grant leaves the saved config syncing through the sign-in meanwhile, as before.
      const vault = { vaultId: r.entry.vaultId, vaultName: r.entry.vaultName, hasPassword: io.enable.vaultHasPassword(r.entry.vaultId) };
      let g;
      try { g = await runDeviceGrant({ grantVault: io.grantVault }, vault); } catch { g = { via: 'account', outcome: 'grant-failed', reason: 'device-step-error' }; }
      if (g.outcome === 'grant-deferred') { try { io.addPending(vault.vaultId); } catch { /* best-effort */ } }
      try { io.afterSave(r.entry); } catch { /* the saved config is what matters; the reaction is best-effort */ }
      try { io.onIdentityChanged(); } catch { /* best-effort */ }
      checkpoint(); // the window went away while the confirmed step completed: it landed, but nobody is reading
      return end('done', { vaultName: vault.vaultName, folder: r.entry.localFolder, via: g.via, outcome: g.outcome, reason: g.reason || null, message: io.copy.deviceOutcome(g, { vaultName: vault.vaultName, hasPassword: vault.hasPassword }), moved });
    } catch (e) {
      if (e && e.cancelled) { finished = true; current = null; return { kind: 'cancelled' }; }
      if (e && e.reason === 'no-session') return end('sign-in', {}); // the session ended mid-flow
      if (e && e.code === 'CONFIG_UNREADABLE') return end('failed', { reason: 'config-unreadable' }); // the save refused to clobber
      return end('failed', { reason: 'error' });
    }
  }

  return { run, answer, cancel, currentQuestion, isFinished: () => finished };
}

module.exports = { createSyncWizard };

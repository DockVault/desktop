'use strict';

/*
 * The "Computers & synced folders" page. It renders the model the main process built (manage-view.js): every
 * computer registered to sync in the account, this computer marked as such and the only one whose vault cards
 * show a local side, the others with their metadata and a plain "managed on that computer". Each ending action
 * (revoke a vault's permission, revoke or remove a computer, stop a sync here) opens an inline confirmation on
 * the card; only its explicit confirm asks main to act. A pushed sync status patches the cards' live state in
 * place. Every element is built with textContent, never markup.
 */

(function manage() {
  const api = (window.dockvault && window.dockvault.manage) || null;
  const body = document.getElementById('body');
  const sub = document.getElementById('sub');
  const btnRefresh = document.getElementById('refresh');
  const btnSetup = document.getElementById('setup');
  const btnClose = document.getElementById('close');
  const buildEl = document.getElementById('build');

  let busy = false;
  let lastModel = null;
  const FOLDER_LOST = new Set(['folder-missing', 'folder-marker-missing', 'folder-other-vault', 'folder-marker-unreadable', 'folder-ambiguous', 'folder-moved-rejected', 'folder-found-elsewhere', 'folder-marker-unwritable']);

  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const para = (text, cls) => el('p', cls, text);
  function button(label, { primary = false, danger = false, quiet = false, onClick, disabled = false } = {}) {
    const b = el('button', `btn${primary ? ' primary' : ''}${danger ? ' danger' : ''}${quiet ? ' quiet' : ''}`, label);
    b.type = 'button'; b.disabled = disabled;
    b.addEventListener('click', () => { if (!busy) onClick(b); });
    return b;
  }
  function row(k, v, mono = false, title = null) {
    const r = el('div', 'row'); r.appendChild(el('span', 'k', k)); const val = el('span', `v${mono ? ' mono' : ''}`, v); if (title) val.title = title; r.appendChild(val); return r;
  }
  // Dates: a day for things that happened once; "x ago" for things that keep happening, with the exact time on hover.
  function dayOf(iso) {
    if (!iso) return '—';
    const d = new Date(iso); if (Number.isNaN(d.getTime())) return '—';
    return d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
  }
  function agoOf(value) {
    if (!value) return { text: 'never', exact: '' };
    const d = new Date(value); if (Number.isNaN(d.getTime())) return { text: 'never', exact: '' };
    const s = Math.max(0, Math.round((Date.now() - d.getTime()) / 1000));
    const text = s < 60 ? 'just now' : s < 3600 ? `${Math.round(s / 60)} min ago` : s < 86400 ? `${Math.round(s / 3600)} h ago` : s < 7 * 86400 ? `${Math.round(s / 86400)} d ago` : d.toLocaleDateString();
    return { text, exact: d.toLocaleString() };
  }

  // Sizes for the transfer detail: binary steps, a round number below 10 of a unit, one decimal otherwise.
  function fmtBytes(n) {
    if (typeof n !== 'number' || !(n > 0)) return null;
    const units = ['B', 'KB', 'MB', 'GB', 'TB']; let v = n; let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${(i === 0 || v >= 10) ? Math.round(v) : Math.round(v * 10) / 10} ${units[i]}`;
  }
  // The transfer in flight, as numbers only (main hands over counts, totals and percentages — never a name):
  // the headline percentage, a one-line detail for the hover, and how many files are moving.
  function transferOf(p) {
    if (!p || typeof p !== 'object') return null;
    const pct = Number.isInteger(p.percent) && p.percent >= 0 && p.percent <= 100 ? p.percent : null;
    const parts = [];
    if (pct != null) parts.push(`${pct}%`);
    const moved = fmtBytes(p.bytes); const total = fmtBytes(p.bytesTotal);
    if (moved && total) parts.push(`${moved} of ${total}`); else if (moved) parts.push(moved);
    if (typeof p.files === 'number' && typeof p.filesTotal === 'number' && p.filesTotal > 0) parts.push(`${p.files} of ${p.filesTotal} ${p.filesTotal === 1 ? 'file' : 'files'} done`);
    else if (typeof p.files === 'number' && p.files > 0) parts.push(`${p.files} ${p.files === 1 ? 'file' : 'files'} done`);
    const inFlight = Number.isInteger(p.transferring) && p.transferring > 0 ? p.transferring : 0;
    const bars = Array.isArray(p.fileProgress) ? p.fileProgress.filter((x) => Number.isInteger(x) && x >= 0 && x <= 100).slice(0, 8) : [];
    return { pct, detail: parts.join(' · ') || 'Transferring…', inFlight, bars };
  }

  // The live state of a vault synced here: one plain phrase, a colour, an icon, and what the hover says. Three
  // faces are kept distinct on purpose — idle (a tick), syncing (an animated arrow; the percentage on hover),
  // and a problem (a mark) — so a glance at the card tells them apart without reading.
  // Faces that outrank a plain "syncing": a run may be moving bytes under one of these (a Repair transfers while
  // it still "needs your decision"). Then the face stays, and the transfer strip shows the numbers underneath —
  // so the window never reads a bare "Syncing" while the tray reads "Needs your decision" for the same vault.
  const OUTRANKS_SYNCING = new Set(['paused', 'needs-decision', 'sync-problem', 'unavailable']);
  function faceOf(state) {
    switch (state) {
      case 'up-to-date': return { text: 'Up to date', tone: 'ok', icon: 'ok', title: 'Everything in this folder matches the vault.' };
      case 'waiting': return { text: 'Waiting to start', tone: '', icon: 'idle', title: 'Set up, but it has not synced yet.' };
      case 'syncing': return { text: 'Syncing', tone: 'run', icon: 'xfer', title: 'Transferring…' };
      case 'paused': return { text: 'Paused', tone: 'warn', icon: 'pause', title: 'Syncing is paused for now; it resumes on its own when it can.' };
      case 'needs-decision': return { text: 'Needs your decision', tone: 'warn', icon: 'ask', title: 'Syncing is waiting for a choice from you.' };
      case 'sync-problem': return { text: 'Problem', tone: 'bad', icon: 'bad', title: 'Syncing is not working right now.' };
      case 'unavailable': return { text: 'Unavailable', tone: 'bad', icon: 'bad', title: 'Syncing cannot run on this computer right now.' };
      case null: case undefined: return { text: 'Not run yet', tone: '', icon: 'idle', title: '' };
      default: return { text: 'Checking…', tone: '', icon: 'idle', title: '' }; // an unknown state never shows a raw token
    }
  }
  function stateOf(local) {
    if (!local) return { text: '', tone: '', icon: '', title: '' };
    const t = local.running ? transferOf(local.progress) : null;
    if (t) {
      // Bytes are moving. If nothing higher-ranked is outstanding, this is the plain syncing face; otherwise the
      // higher face (a Repair, say) stays and the strip carries the numbers.
      const higher = OUTRANKS_SYNCING.has(local.state) ? faceOf(local.state) : { text: 'Syncing', tone: 'run', icon: 'xfer' };
      return { ...higher, title: `Transferring — ${t.detail}${t.inFlight ? ` · ${t.inFlight} ${t.inFlight === 1 ? 'file' : 'files'} at once` : ''}`, transfer: t };
    }
    if (local.running && local.state !== 'syncing' && !OUTRANKS_SYNCING.has(local.state)) {
      // A run in flight that is only scanning (no bytes yet), and nothing higher outstanding: an honest "Checking…".
      // A state the model already calls 'syncing' keeps the syncing face below (it means bytes are, or were just, moving).
      return { text: 'Checking…', tone: 'run', icon: 'busy', title: 'Checking for changes…' };
    }
    return faceOf(local.state);
  }
  const ICON_GLYPH = { ok: '\u2713', xfer: '\u2191', busy: '\u21bb', pause: '\u2016', ask: '?', bad: '!', idle: '\u00b7' };

  // How a configured vault stands with this computer (the scheduler's own rule), as a badge and a sentence.
  function standingOf(v) {
    switch (v.standing) {
      case 'device': return null;
      case 'account': return { badge: 'syncs using your sign-in', tone: 'warn', text: 'Syncs using your account sign-in; it pauses when you sign out. Run Set up sync… to give this computer its own key.' };
      case 'withdrawn': return { badge: 'permission withdrawn', tone: 'bad', text: `This computer's permission to sync ${v.name} was taken away, so it is held. Run Set up sync… and pick ${v.name} to set it up again, or stop syncing it here.` };
      case 'removed': return { badge: 'this computer was removed', tone: 'bad', text: 'This computer was removed from your synced computers, so this vault is held. Run Set up sync… to set this computer up again, or stop syncing it here.' };
      default: return { badge: 'held', tone: 'bad', text: "This computer's sync identity is in a state that stops syncing for now (see the note above)." };
    }
  }

  // An inline confirmation under a card: the sentence, and Cancel / the confirming verb. Focus lands on Cancel;
  // after the box closes it returns to the button that opened it.
  function confirmBox(host, opener, { text, mono = null, verb, danger = true, onConfirm }) {
    const existing = host.querySelector('.confirm'); if (existing) existing.remove();
    const box = el('div', `confirm${danger ? ' danger' : ''}`);
    box.setAttribute('aria-live', 'polite');
    box.appendChild(para(text));
    if (mono) box.appendChild(el('p', 'mono', mono));
    const acts = el('div', 'actions');
    const cancel = button('Cancel', { onClick: () => { box.remove(); try { opener.focus(); } catch { /* gone */ } } });
    const go = button(verb, { danger, onClick: async (b) => { b.textContent = 'Working…'; b.disabled = true; cancel.disabled = true; box.dataset.working = 'true'; await onConfirm(box, opener); } });
    acts.appendChild(cancel); acts.appendChild(go);
    box.appendChild(acts);
    host.appendChild(box);
    setTimeout(() => { try { cancel.focus(); } catch { /* ignore */ } }, 0);
  }

  async function act(action, box, opener) {
    if (!api) return;
    busy = true;
    let r;
    try { r = await api.act(action); } catch { r = { ok: false, reason: 'refused' }; }
    if (!r || !r.ok) {
      busy = false;
      box.dataset.working = '';
      box.replaceChildren(para(failureText(r && r.reason, action)));
      const acts = el('div', 'actions');
      const ok = button('OK', { onClick: () => { box.remove(); try { opener.focus(); } catch { /* gone */ } } });
      acts.appendChild(ok); box.appendChild(acts);
      setTimeout(() => { try { ok.focus(); } catch { /* ignore */ } }, 0);
      return;
    }
    await load();
    busy = false;
  }

  // A wait, in words a person can act on: whole seconds under a minute and a half, else whole minutes rounded up.
  function waitWords(sec) {
    const n = Math.max(1, Math.ceil(Number(sec) || 0));
    if (n < 90) return n === 1 ? '1 second' : n + ' seconds';
    const m = Math.ceil(n / 60);
    return 'about ' + (m === 1 ? '1 minute' : m + ' minutes');
  }

  function failureText(reason, action) {
    const what = action && action.kind === 'sync-now' ? 'start a sync' : 'make that change';
    switch (reason) {
      // "Sync now" was used a moment ago: the scheduler turned this press away without a run, and says when the
      // next is allowed. Changes are not lost — the regular schedule still picks them up.
      case 'cooldown': return '"Sync now" was used a moment ago. It is available again in ' + waitWords(action && action.retryInSec) + ' — changes are still picked up on the regular schedule.';
      // The server is refusing this computer's sync credentials and this wait's one try is spent: honest about the
      // wait, and that the state already on the card is what to act on (a sign-in or the vault password lets it try
      // at once); a fresh credential is not the fix — each try is what the server is limiting.
      // The door is refusing and this wait's one try is spent. WHICH refusal decides the answer: a server
      // limiting attempts ('channel-refused') clears itself and no sign-in or credential change touches it —
      // saying otherwise sends a person to do useless work — while a refused credential genuinely may be
      // unblocked by a sign-in or the vault's password. An unknown cause keeps the wider, older wording.
      case 'backing-off': return action && action.cause === 'channel-refused'
        ? 'The sync server is temporarily limiting sync attempts from this computer, so DockVault is waiting before it tries again (' + waitWords(action && action.retryInSec) + "). Signing in again or deactivating credentials won't help — the wait is what clears it."
        : "The sync server is refusing this computer's sync credentials, so DockVault is waiting before it tries again (" + waitWords(action && action.retryInSec) + '). If the status above asks you to sign in or enter the vault password, doing that lets it try at once.';
      case 'not-found': return 'The server no longer lists that, so there was nothing to change here. Refresh to see the current state.';
      case 'auth': case 'no-session': return 'Your sign-in has ended. Open DockVault and sign in, then try again.';
      case 'network': return "Couldn't reach the server, so nothing was changed. Check your connection and try again.";
      case 'indeterminate': return "The server answered, but not in a way DockVault could confirm, so nothing was changed here. Refresh to see the current state, then try again.";
      case 'busy': return 'Another sync set-up or change is in progress. Finish it, then try again.';
      case 'config-unreadable': return 'Your sync settings could not be read, so nothing was changed. This usually clears up after unlocking your login keychain and reopening DockVault.';
      case 'bad-request': return `Something went wrong on this computer's side; nothing was changed. Refresh and try again.`;
      default: return `The server refused to ${what}. Nothing was changed here.`;
    }
  }

  // "Sync now": immediate feedback on the card; the live status restores the button when the run ends.
  function syncNow(card, v, btn) {
    if (!api) return;
    btn.disabled = true; btn.textContent = 'Syncing…';
    setChip(card, { text: 'Checking…', tone: 'run', icon: 'busy', title: 'Checking for changes…' });
    api.act({ kind: 'sync-now', vaultId: v.vaultId }).then((r) => {
      if (r && r.ok) return;
      btn.disabled = false; btn.textContent = 'Sync now';
      const s = stateOf(v.local); setChip(card, s);
      const waiting = r && (r.reason === 'cooldown' || r.reason === 'backing-off');
      const note = el('div', waiting ? 'box' : 'box bad'); note.appendChild(para(failureText((r && r.reason) || 'refused', { kind: 'sync-now', retryInSec: r && r.retryInSec, cause: r && r.cause })));
      card.appendChild(note); setTimeout(() => note.remove(), waiting ? 9000 : 6000);
    }).catch(() => { btn.disabled = false; btn.textContent = 'Sync now'; });
  }
  function setChip(card, s) {
    const st = card.querySelector('.state');
    const dot = card.querySelector('.state .dot'); const txt = card.querySelector('.state .meta'); const ico = card.querySelector('.state .ico');
    if (dot) dot.className = `dot ${s.tone}`;
    if (txt) txt.textContent = s.text;
    if (ico) { ico.className = `ico ${s.icon || 'idle'}`; ico.textContent = ICON_GLYPH[s.icon] || ''; }
    if (st) st.title = s.title || '';
    setTransfer(card, s.transfer || null);
  }
  // The transfer strip under the title while bytes move: an overall bar, how many files are in flight, and a
  // small bar per file (numbers only — the files are not named here). Removed the moment nothing is moving.
  function setTransfer(card, t) {
    let strip = card.querySelector('.xfer');
    if (!t) { if (strip) strip.remove(); return; }
    if (!strip) { strip = el('div', 'xfer'); const title = card.querySelector('.title'); if (title && title.nextSibling) card.insertBefore(strip, title.nextSibling); else card.appendChild(strip); }
    strip.replaceChildren();
    const bar = el('div', 'bar'); const fill = el('div', 'fill'); fill.style.width = `${t.pct != null ? t.pct : 0}%`; if (t.pct == null) fill.classList.add('indeterminate'); bar.appendChild(fill); bar.title = t.detail;
    strip.appendChild(bar);
    const line = el('div', 'xfer-line');
    line.appendChild(el('span', 'meta', t.detail));
    if (t.inFlight) {
      const files = el('span', 'files'); files.appendChild(el('span', 'meta', `${t.inFlight} ${t.inFlight === 1 ? 'file' : 'files'} at once`));
      for (const pct of t.bars) { const mini = el('span', 'mini'); mini.title = `${pct}%`; const f = el('span', 'fill'); f.style.width = `${pct}%`; mini.appendChild(f); files.appendChild(mini); }
      if (t.inFlight > t.bars.length && t.bars.length) files.appendChild(el('span', 'meta', `+${t.inFlight - t.bars.length}`));
      line.appendChild(files);
    }
    strip.appendChild(line);
  }

  function vaultCard(computer, v) {
    const c = el('div', 'card'); c.dataset.vault = v.vaultId;
    const t = el('div', 'title');
    t.appendChild(el('span', 'vault', v.name));
    const standing = standingOf(v);
    if (standing) t.appendChild(el('span', `badge ${standing.tone}`, standing.badge));
    if (v.local) { const st = el('span', 'state'); st.appendChild(el('span', 'dot')); st.appendChild(el('span', 'ico')); st.appendChild(el('span', 'meta')); t.appendChild(el('span', 'spacer')); t.appendChild(st); }
    c.appendChild(t);
    if (v.local) setChip(c, stateOf(v.local));
    if (standing) c.appendChild(el('p', 'standing', standing.text));
    if (v.local && v.local.reasonText) c.appendChild(el('p', 'reason', v.local.reasonText));
    c.appendChild(row('On server', v.remote, true));
    if (v.local) {
      c.appendChild(row('Folder here', v.local.folder, true));
      const last = agoOf(v.local.lastSyncedAt);
      c.appendChild(row('Last synced', last.text, false, last.exact));
      if (v.standing === 'device' || v.standing === 'account') c.appendChild(row('Syncs using', v.standing === 'device' ? "this computer's own key — keeps working while the screen is locked" : 'your account sign-in — pauses when you sign out'));
    } else {
      c.appendChild(row('Folder here', 'not synced to a folder on this computer'));
    }
    if (v.granted && v.grantedAt) c.appendChild(row('Permission since', dayOf(v.grantedAt)));
    const acts = el('div', 'actions');
    if (v.local) {
      // A folder that cannot be found (or is not the one at its path) is answered by main's own relocate-or-stop
      // offer: the card only opens that door.
      if (FOLDER_LOST.has(v.local.reason)) {
        acts.appendChild(button(v.local.reason === 'folder-ambiguous' ? 'Choose the folder…' : (v.local.reason === 'folder-found-elsewhere' ? 'Confirm the folder…' : 'Find the folder…'), { primary: true, onClick: () => { if (api) void api.act({ kind: 'relocate-folder', vaultId: v.vaultId }); } }));
      }
      const syncBtn = button('Sync now', { onClick: (b) => syncNow(c, v, b), disabled: !!v.local.running });
      syncBtn.dataset.role = 'sync-now';
      acts.appendChild(syncBtn);
      acts.appendChild(button('Stop syncing here', { onClick: (b) => confirmBox(c, b, {
        text: `Stop syncing ${v.name} on this computer? The files already in the folder are left as they are.${v.granted ? " This computer keeps its permission for the vault; use Revoke permission to take that away too." : ''}`,
        mono: v.local.folder, verb: 'Stop syncing', danger: false, onConfirm: (box, opener) => act({ kind: 'stop-sync', vaultId: v.vaultId }, box, opener),
      }) }));
    }
    if (v.granted) {
      const who = computer.isThis ? "this computer's" : `${computer.label}'s`;
      const them = computer.isThis ? 'This computer' : computer.label;
      acts.appendChild(button('Revoke permission', { danger: true, onClick: (b) => confirmBox(c, b, {
        text: `Revoke ${who} permission to sync ${v.name}? ${them} stops syncing ${v.name} right away and can't sync it again until it is set up again.${computer.isThis && v.local ? ' The folder and its files are left as they are.' : ''}`,
        mono: computer.isThis && v.local ? v.local.folder : null, verb: 'Revoke permission', onConfirm: (box, opener) => act({ kind: 'revoke-grant', deviceId: computer.deviceId, vaultId: v.vaultId }, box, opener),
      }) }));
    }
    if (acts.childElementCount) c.appendChild(acts);
    return c;
  }

  function computerBlock(cmp) {
    const wrap = el('section', `computer${cmp.isActive ? '' : ' revoked'}`);
    const head = el('div', 'head');
    const names = el('div', 'names');
    names.appendChild(el('span', 'name', cmp.label));
    if (cmp.isThis) names.appendChild(el('span', 'badge this', 'this computer'));
    if (!cmp.isActive) names.appendChild(el('span', 'badge off', 'revoked'));
    head.appendChild(names);
    const seen = agoOf(cmp.lastSeen);
    const meta = el('div', 'meta', `Added ${dayOf(cmp.createdAt)} · Last seen ${seen.text}${cmp.expiresAt ? ` · Expires ${dayOf(cmp.expiresAt)}` : ''}`);
    if (seen.exact) meta.title = `Last seen ${seen.exact}`;
    head.appendChild(meta);
    const headActs = el('div', 'head-actions');
    if (cmp.isActive) {
      headActs.appendChild(button('Revoke computer', { quiet: true, danger: true, onClick: (b) => confirmBox(wrap, b, {
        text: cmp.isThis
          ? 'Revoke this computer? It stops syncing every vault right away and is removed from your account\u2019s list of syncing computers. The synced folders and their files stay where they are. To sync here again, run Set up sync.'
          : `Revoke ${cmp.label}? It stops syncing every vault right away and can't connect on its own any more. The files already on ${cmp.label} stay there. It stays in this list as revoked until you remove it.`,
        verb: 'Revoke computer', onConfirm: (box, opener) => act({ kind: 'revoke-computer', deviceId: cmp.deviceId }, box, opener),
      }) }));
    } else {
      headActs.appendChild(button('Remove from list', { quiet: true, onClick: (b) => confirmBox(wrap, b, {
        text: `Remove ${cmp.label} from your account? It is already revoked; this only clears it from the list.`,
        verb: 'Remove', danger: false, onConfirm: (box, opener) => act({ kind: 'remove-computer', deviceId: cmp.deviceId }, box, opener),
      }) }));
    }
    head.appendChild(headActs);
    wrap.appendChild(head);
    if (cmp.isThis && cmp.identityNote) {
      wrap.appendChild(el('div', 'note', {
        stale: "This computer's sync identity was retired by the server, so its vaults are held. Run Set up sync… to set it up again.",
        rechecking: "This computer's sync identity is being re-checked with the server. Its vaults are held until that finishes.",
        unreadable: "This computer's sync identity can't be read right now, so its vaults are held. This usually clears up after unlocking your login keychain and reopening DockVault.",
      }[cmp.identityNote] || "This computer's sync identity is unavailable right now, so its vaults are held."));
    }
    if (cmp.isThis) {
      if (Array.isArray(cmp.vaults)) {
        if (cmp.vaults.length) { const cards = el('div', 'cards'); for (const v of cmp.vaults) cards.appendChild(vaultCard(cmp, v)); wrap.appendChild(cards); }
        else wrap.appendChild(el('div', 'note', 'No vaults are synced to this computer yet. Use Set up sync… to add one.'));
      } else {
        wrap.appendChild(el('div', 'note', cmp.vaultsUnavailable === 'device-suspended'
          ? "This computer's sync access is suspended by the server, so its vaults can't be listed right now."
          : "Couldn't list this computer's vaults right now. Refresh to try again."));
      }
    } else if (cmp.isActive) {
      wrap.appendChild(el('div', 'note', `Open DockVault on ${cmp.label} to see and manage the vaults it syncs — this server can't list them from another computer.`));
    }
    return wrap;
  }

  // This computer's local side when it is not one of the listed, identity-live computers.
  function localBlock(local) {
    const wrap = el('section', 'computer');
    const head = el('div', 'head');
    const names = el('div', 'names');
    names.appendChild(el('span', 'name', 'This computer'));
    const badge = { 'not-listed': 'not in your account\u2019s list', absent: 'not set up to sync on its own', stale: 'sync identity retired', rechecking: 'sync identity being re-checked', unreadable: 'sync identity can\u2019t be read right now', 'absent-for-this-server': 'set up with a different server', 'no-secure-store': 'no secure store for a sync identity' }[local.status] || 'sync identity unavailable';
    names.appendChild(el('span', 'badge warn', badge));
    head.appendChild(names);
    wrap.appendChild(head);
    const note = {
      'not-listed': 'This computer has a sync identity, but your account no longer lists it — it was probably removed from another computer. Run Set up sync… to set it up again.',
      absent: 'Vaults here sync using your account sign-in. Run Set up sync… to give this computer its own key, so they keep syncing even while DockVault or the screen is locked.',
      stale: "This computer's sync identity was retired by the server. Run Set up sync… to set it up again.",
      rechecking: "This computer's sync identity is being re-checked with the server. Try again in a little while.",
      unreadable: "This computer's sync identity can't be read right now. This usually clears up after unlocking your login keychain and reopening DockVault.",
      'absent-for-this-server': 'This computer is set up to sync with a different server. Run Set up sync… to switch it to this one.',
      'no-secure-store': "This computer has no secure place to keep a sync identity, so it can't sync on its own.",
    }[local.status] || "This computer's sync identity is unavailable right now.";
    wrap.appendChild(el('div', 'note', note));
    if (local.vaults.length) { const cards = el('div', 'cards'); for (const v of local.vaults) cards.appendChild(vaultCard({ label: 'This computer', isThis: true, deviceId: null }, v)); wrap.appendChild(cards); }
    return wrap;
  }

  // A live sync status (observe-only, pushed by main) patches the cards' state in place: no reload, no redraw.
  function applyLive(status) {
    if (!lastModel || lastModel.kind !== 'ok' || !status || !Array.isArray(status.vaults)) return;
    for (const live of status.vaults) {
      const card = body.querySelector(`.card[data-vault="${cssEscape(live.vault)}"]`);
      if (!card) continue;
      const local = { state: live.state, reason: live.reason, running: !!live.running, lastSyncedAt: live.lastSyncedAt, progress: live.progress || null };
      setChip(card, stateOf(local));
      const syncBtn = card.querySelector('button[data-role="sync-now"]');
      if (syncBtn && !card.querySelector('.confirm')) { syncBtn.disabled = !!live.running; if (!live.running) syncBtn.textContent = 'Sync now'; }
      const rows = card.querySelectorAll('.row');
      for (const r of rows) { if (r.firstChild && r.firstChild.textContent === 'Last synced') { const last = agoOf(live.lastSyncedAt); r.lastChild.textContent = last.text; r.lastChild.title = last.exact; } }
      setReason(card, live.reasonText);
    }
  }
  // The card's one plain sentence about why this vault is where it is. Main composes it and pushes it with the
  // state it explains, so a live patch never leaves the chip saying one thing and the sentence beside it
  // saying another — or, when a failure clears, an explanation of something that is no longer true. Added,
  // replaced, or removed in place, right after the standing note.
  function setReason(card, text) {
    const existing = card.querySelector('p.reason');
    if (!text) { if (existing) existing.remove(); return; }
    if (existing) { existing.textContent = text; return; }
    const p = el('p', 'reason', text);
    const after = card.querySelector('p.standing') || card.querySelector('.xfer') || card.querySelector('.title');
    if (after && after.nextSibling) card.insertBefore(p, after.nextSibling); else card.appendChild(p);
  }
  function cssEscape(s) { return (window.CSS && CSS.escape) ? CSS.escape(String(s)) : String(s).replace(/["\\]/g, '\\$&'); }

  function render(m) {
    lastModel = m;
    body.replaceChildren();
    sub.textContent = '';
    if (!m) { body.appendChild(para("Couldn't load. Refresh to try again.")); return; }
    switch (m.kind) {
      case 'sign-in':
        body.appendChild(para('Sign in first. Open DockVault and sign in to your account, then open this window again.'));
        return;
      case 'unsupported':
        body.appendChild(para("This server doesn't support syncing folders from your computers, so there is nothing to manage here."));
        return;
      case 'unavailable':
        body.appendChild(para("Couldn't reach the server to list your computers. Check your connection and refresh."));
        return;
      default: break;
    }
    sub.textContent = m.serverHost ? `on ${m.serverHost}` : '';
    if (!m.computers.length && !(m.local && m.local.vaults.length)) body.appendChild(para('No computer is set up to sync in this account yet. Use Set up sync… to set this one up.'));
    if (m.local) body.appendChild(localBlock(m.local));
    for (const cmp of m.computers) body.appendChild(computerBlock(cmp));
  }

  async function load() {
    if (!api) { body.replaceChildren(para('This screen is unavailable.')); return; }
    btnRefresh.disabled = true;
    let m = null;
    try { m = await api.model(); } catch { m = null; }
    btnRefresh.disabled = false;
    render(m);
  }

  btnRefresh.addEventListener('click', () => { if (!busy) void load(); });
  btnSetup.addEventListener('click', () => { if (api) void api.openSetup(); });
  btnClose.addEventListener('click', () => { if (!busy && api) void api.close(); });
  document.addEventListener('keydown', (e) => {
    if (e.key !== 'Escape') return;
    const open = body.querySelector('.confirm');
    if (open) { if (open.dataset.working !== 'true') open.remove(); return; }
    if (!busy && api) void api.close();
  });
  // Which build this is, in the footer. Main composed the line (build-stamp.js); the page only shows it,
  // and shows it once — a build's identity does not change while the app runs, so it never needs a refresh.
  // It stays blank only if main could not be asked at all, which is a window that has bigger problems.
  async function showBuild() {
    const appApi = (window.dockvault && window.dockvault.app) || null;
    if (!appApi || !buildEl) return;
    let info = null;
    try { info = await appApi.info(); } catch { info = null; }
    if (info && typeof info.buildLine === 'string') buildEl.textContent = info.buildLine;
    // "build not stamped" is only half an answer on a line with no room to explain itself, so the
    // explanation main sends rides along as the hover. Nothing is hidden by it: the About box says the
    // same sentence outright, and a stamped build sends none because it needs none.
    if (info && typeof info.buildNote === 'string' && info.buildNote) buildEl.title = info.buildNote;
  }

  if (api) api.onChanged(() => { if (!busy) void load(); });
  if (window.dockvault && window.dockvault.sync) window.dockvault.sync.onStatus((st) => applyLive(st));
  void load();
  void showBuild();
})();

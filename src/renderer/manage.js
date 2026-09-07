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

  let busy = false;
  let lastModel = null;

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

  // The live state of a vault synced here, as one plain phrase and a colour.
  function stateOf(local) {
    if (!local) return { text: '', tone: '' };
    if (local.running) return { text: 'Syncing now', tone: 'run' };
    switch (local.state) {
      case 'up-to-date': return { text: 'Up to date', tone: 'ok' };
      case 'waiting': return { text: 'Waiting to start', tone: '' };
      case 'syncing': return { text: 'Syncing', tone: 'run' };
      case 'paused': return { text: 'Paused', tone: 'warn' };
      case 'needs-decision': return { text: 'Needs your decision', tone: 'warn' };
      case 'sync-problem': return { text: 'Problem', tone: 'bad' };
      case 'unavailable': return { text: 'Unavailable', tone: 'bad' };
      case null: case undefined: return { text: 'Not run yet', tone: '' };
      default: return { text: String(local.state), tone: '' };
    }
  }

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

  function failureText(reason, action) {
    const what = action && action.kind === 'sync-now' ? 'start a sync' : 'make that change';
    switch (reason) {
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
    setChip(card, { text: 'Syncing now', tone: 'run' });
    api.act({ kind: 'sync-now', vaultId: v.vaultId }).then((r) => {
      if (r && r.ok) return;
      btn.disabled = false; btn.textContent = 'Sync now';
      const s = stateOf(v.local); setChip(card, s);
      const note = el('div', 'box bad'); note.appendChild(para(failureText((r && r.reason) || 'refused', { kind: 'sync-now' })));
      card.appendChild(note); setTimeout(() => note.remove(), 6000);
    }).catch(() => { btn.disabled = false; btn.textContent = 'Sync now'; });
  }
  function setChip(card, s) {
    const dot = card.querySelector('.state .dot'); const txt = card.querySelector('.state .meta');
    if (dot) dot.className = `dot ${s.tone}`;
    if (txt) txt.textContent = s.text;
  }

  function vaultCard(computer, v) {
    const c = el('div', 'card'); c.dataset.vault = v.vaultId;
    const t = el('div', 'title');
    t.appendChild(el('span', 'vault', v.name));
    const standing = standingOf(v);
    if (standing) t.appendChild(el('span', `badge ${standing.tone}`, standing.badge));
    if (v.local) { const s = stateOf(v.local); const st = el('span', 'state'); st.appendChild(el('span', `dot ${s.tone}`)); st.appendChild(el('span', 'meta', s.text)); t.appendChild(el('span', 'spacer')); t.appendChild(st); }
    c.appendChild(t);
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
      const local = { state: live.state, reason: live.reason, running: !!live.running, lastSyncedAt: live.lastSyncedAt };
      setChip(card, stateOf(local));
      const syncBtn = card.querySelector('button[data-role="sync-now"]');
      if (syncBtn && !card.querySelector('.confirm')) { syncBtn.disabled = !!live.running; if (!live.running) syncBtn.textContent = 'Sync now'; }
      const rows = card.querySelectorAll('.row');
      for (const r of rows) { if (r.firstChild && r.firstChild.textContent === 'Last synced') { const last = agoOf(live.lastSyncedAt); r.lastChild.textContent = last.text; r.lastChild.title = last.exact; } }
    }
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
  if (api) api.onChanged(() => { if (!busy) void load(); });
  if (window.dockvault && window.dockvault.sync) window.dockvault.sync.onStatus((st) => applyLive(st));
  void load();
})();

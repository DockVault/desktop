'use strict';

/*
 * The dedicated sync-status page. One row per synced folder: its state, the honest sentence for that state,
 * how far a transfer has got, and when it last finished.
 *
 * The page decides nothing. It asks main for a model and renders it, and there is deliberately no way from
 * here to start, stop or change a sync — those live in the tray, and a renderer that could reach them would
 * be attack surface for a convenience the tray already provides. Every element is built with textContent,
 * never markup, so a vault name or a folder path can never be read as HTML.
 *
 * The reason sentence is composed in MAIN and arrives as text. It is built from a vault's outcome detail —
 * which file, which size — and that detail is deliberately stripped from the general status channel before
 * any renderer sees it, because that channel is reachable from the window hosting the vault's own web
 * interface. So this page could not compose it even if it wanted to, and should not.
 */

(function statusPage() {
  const api = (window.dockvault && window.dockvault.status) || null;
  const listEl = document.getElementById('list');
  const headlineEl = document.getElementById('headline');
  const footEl = document.getElementById('foot');

  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const clear = (node) => { while (node.firstChild) node.removeChild(node.firstChild); };

  // The state, as a person reads it. One phrase and one tone each; an unknown state never leaks its raw
  // token onto the screen, because an internal symbol in front of someone is worse than a vague word.
  const FACE = {
    'up-to-date': ['Up to date', 'ok'],
    syncing: ['Syncing', 'run'],
    waiting: ['Waiting to start', ''],
    paused: ['Paused', 'warn'],
    'needs-decision': ['Needs your decision', 'warn'],
    'sync-problem': ['Problem', 'bad'],
    unavailable: ['Unavailable', 'bad'],
    off: ['Sync off', 'off'],
  };
  function faceOf(state, running) {
    if (Object.prototype.hasOwnProperty.call(FACE, state)) return FACE[state];
    if (running) return ['Checking…', 'run'];
    return state == null ? ['Not run yet', ''] : ['Checking…', ''];
  }

  function bytes(n) {
    if (typeof n !== 'number' || !(n > 0)) return null;
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = n; let i = 0;
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
    return `${(i === 0 || v >= 10) ? Math.round(v) : Math.round(v * 10) / 10} ${units[i]}`;
  }

  // The numbers under the bar, in the order a person wants them: how far, how much, how many.
  function numbersFor(t) {
    const parts = [];
    if (t.percent != null) parts.push(`${t.percent}%`);
    const moved = bytes(t.bytes); const total = bytes(t.bytesTotal);
    if (moved && total) parts.push(`${moved} of ${total}`); else if (moved) parts.push(moved);
    if (t.files != null && t.filesTotal != null && t.filesTotal > 0) parts.push(`${t.files} of ${t.filesTotal} ${t.filesTotal === 1 ? 'file' : 'files'}`);
    else if (t.files != null && t.files > 0) parts.push(`${t.files} ${t.files === 1 ? 'file' : 'files'}`);
    return parts.join(' · ');
  }

  function renderItem(item) {
    const row = el('div', 'item');

    const top = el('div', 'top');
    top.appendChild(el('span', 'name', item.name || 'This vault'));
    const [text, tone] = faceOf(item.state, item.running);
    top.appendChild(el('span', `badge${tone ? ` ${tone}` : ''}`, text));
    row.appendChild(top);

    if (item.folder) {
      const f = el('div', 'folder', item.folder);
      f.title = item.folder;   // the whole path, since the line itself is truncated
      row.appendChild(f);
    }

    // The bar, only while something is actually moving. A run with no measurable fraction gets the
    // indeterminate bar rather than an empty one, because a bar sitting at zero reads as stuck.
    if (item.transfer) {
      const t = item.transfer;
      const bar = el('div', `bar${t.fraction == null ? ' indeterminate' : ''}`);
      const fill = el('i');
      if (t.fraction != null) fill.style.width = `${Math.round(t.fraction * 100)}%`;
      bar.appendChild(fill);
      bar.setAttribute('role', 'progressbar');
      if (t.fraction != null) {
        bar.setAttribute('aria-valuemin', '0');
        bar.setAttribute('aria-valuemax', '100');
        bar.setAttribute('aria-valuenow', String(Math.round(t.fraction * 100)));
      }
      row.appendChild(bar);
      const nums = numbersFor(t);
      if (nums) row.appendChild(el('div', 'nums', nums));
    }

    // The honest sentence. Last, and free to wrap: it is the one thing here that must never be cut off.
    if (item.note) row.appendChild(el('p', 'note', item.note));
    if (item.lastSynced) row.appendChild(el('div', 'when', `Last synced ${item.lastSynced}`));
    return row;
  }

  function render(model) {
    clear(listEl);
    headlineEl.textContent = (model && model.headline) || '';
    if (!model) {
      const box = el('div', 'empty');
      box.appendChild(el('b', null, 'Sync status is not available right now'));
      box.appendChild(el('div', null, 'DockVault could not read the current state. It keeps trying; nothing in your folders is affected.'));
      listEl.appendChild(box);
      footEl.textContent = '';
      return;
    }
    if (model.empty) {
      const box = el('div', 'empty');
      box.appendChild(el('b', null, 'No folders are set up to sync yet'));
      box.appendChild(el('div', null, 'Choose "Set up sync…" in the DockVault tray menu to sync a vault to a folder on this computer.'));
      listEl.appendChild(box);
      footEl.textContent = '';
      return;
    }
    for (const item of model.items) listEl.appendChild(renderItem(item));
    const n = model.items.length;
    footEl.textContent = `${n} ${n === 1 ? 'folder' : 'folders'} · this window updates on its own`;
  }

  async function refresh() {
    if (!api || typeof api.model !== 'function') { render(null); return; }
    let model = null;
    try { model = await api.model(); } catch { model = null; }
    render(model);
  }

  // Live, because a status window that needs reopening to be current is a status window nobody trusts. The
  // push is the same one the tray listens to; the refresh re-asks main for the whole model rather than
  // trying to patch a row from an event, so the page can never drift from what main believes.
  if (api && typeof api.onChanged === 'function') {
    try { api.onChanged(() => { void refresh(); }); } catch { /* the poll below still carries it */ }
  }
  void refresh();
  setInterval(() => { void refresh(); }, 5000);
}());

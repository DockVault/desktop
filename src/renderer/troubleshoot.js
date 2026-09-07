'use strict';

/*
 * The Troubleshoot page. A sidebar lists the checks main offers; the pane shows the chosen check as main
 * describes it — what is set up (facts), the doors it will try (legs), and a Run button — and, once run, the
 * live outcome: each leg lit green, red, or set aside, with a sentence, then one verdict. The page decides
 * nothing and probes nothing itself: it asks main by check id and renders what comes back. Every element is
 * built with textContent, never markup.
 */

(function troubleshoot() {
  const api = (window.dockvault && window.dockvault.troubleshoot) || null;
  const checksEl = document.getElementById('checks');
  const pane = document.getElementById('pane');
  const btnClose = document.getElementById('close');

  let current = null;     // the chosen check id
  const running = new Set(); // the check ids whose probes are in flight (each check runs on its own)
  let lastRun = new Map(); // check id -> the last probe result shown, so switching back keeps it

  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const para = (text, cls) => el('p', cls, text);
  function button(label, { primary = false, onClick, disabled = false } = {}) {
    const b = el('button', `btn${primary ? ' primary' : ''}`, label);
    b.type = 'button'; b.disabled = disabled;
    b.addEventListener('click', () => onClick(b));
    return b;
  }

  function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }

  // The states the page knows how to draw. Anything else is a problem by definition — a colour it cannot
  // show must never come out looking neutral.
  const LEG_STATES = new Set(['ok', 'warn', 'bad', 'skip', 'off', 'checking']);
  const VERDICT_STATES = new Set(['ok', 'partial', 'bad', 'checking']);
  const legState = (s) => (LEG_STATES.has(s) ? s : 'bad');
  const verdictState = (s) => (VERDICT_STATES.has(s) ? s : 'bad');
  // The state in words, for readers who do not see the dot.
  const STATE_WORDS = { ok: 'OK', warn: 'Warning', bad: 'Problem', skip: 'Not needed', off: 'Not checked', checking: 'Checking' };

  function renderChecks(list) {
    clear(checksEl);
    for (const c of list) {
      const b = el('button', null, c.title);
      b.type = 'button';
      b.dataset.id = c.id;
      if (c.id === current) b.setAttribute('aria-current', 'true');
      b.addEventListener('click', () => { if (c.id !== current) void show(c.id); });
      checksEl.appendChild(b);
    }
  }
  function markCurrent() {
    for (const b of checksEl.querySelectorAll('button')) { if (b.dataset.id === current) b.setAttribute('aria-current', 'true'); else b.removeAttribute('aria-current'); }
  }

  // One light: a dot, the leg's name, its sentence, and an optional small detail line.
  function light(leg, rawState, text, detail) {
    const state = legState(rawState);
    const l = el('div', 'light'); l.dataset.state = state; l.dataset.leg = leg.id;
    const dot = el('span', 'dot'); dot.appendChild(el('span', 'sr', STATE_WORDS[state])); l.appendChild(dot);
    const body = el('div');
    body.appendChild(el('div', 'name', leg.label));
    body.appendChild(para(text || '', 'what'));
    if (detail) body.appendChild(para(detail, 'detail'));
    l.appendChild(body);
    return l;
  }

  function renderPane(picture, result, state, { focusRun = false } = {}) {
    clear(pane);
    let runButton = null;
    if (!picture) { pane.appendChild(para("This check isn't available.")); return; }
    pane.appendChild(el('h2', null, picture.title));
    if (picture.intro) pane.appendChild(para(picture.intro));

    if (picture.facts && picture.facts.length) {
      const facts = el('div', 'facts');
      for (const f of picture.facts) { facts.appendChild(el('span', 'k', f.label)); facts.appendChild(el('span', `v${f.mono ? ' mono' : ''}`, f.value)); }
      pane.appendChild(facts);
    }
    if (picture.note) { const box = el('div', 'box'); box.appendChild(para(picture.note)); pane.appendChild(box); }

    if (picture.canProbe) {
      const bar = el('div', 'toolbar');
      const isRunning = state === 'checking';
      runButton = button(isRunning ? 'Checking…' : (result ? 'Run again' : 'Run check'), { primary: true, disabled: isRunning, onClick: () => void run(picture.id, { focusRun: true }) });
      bar.appendChild(runButton);
      if (result && result.at && !isRunning) bar.appendChild(el('span', 'ran', `Last run ${new Date(result.at).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' })}`));
      pane.appendChild(bar);

      // The conclusion first, then the legs as its evidence. The box is there while checking too, so the pane
      // does not jump when the verdict lands; it is announced to readers who cannot see it.
      const v = el('div', 'verdict'); v.setAttribute('role', 'status'); v.setAttribute('aria-live', 'polite');
      if (isRunning) { v.dataset.state = 'checking'; v.appendChild(para('Checking…')); }
      else if (result && result.verdict) { v.dataset.state = verdictState(result.verdict.state); v.appendChild(para(result.verdict.text)); }
      if (v.firstChild) pane.appendChild(v);

      const lights = el('div', 'lights');
      const legs = picture.legs || [];
      const byId = new Map(((result && result.legs) || []).map((l) => [l.id, l]));
      for (const leg of legs) {
        if (isRunning) lights.appendChild(light(leg, 'checking', 'Checking…'));
        else if (byId.has(leg.id)) { const r = byId.get(leg.id); lights.appendChild(light(leg, r.state, r.text, r.detail)); }
        else lights.appendChild(light(leg, 'off', 'Not checked yet.'));
      }
      pane.appendChild(lights);

      if (result && !isRunning) for (const n of result.notes || []) pane.appendChild(para(n, 'note'));
    }

    if (picture.action) {
      const actions = el('div', 'actions');
      actions.appendChild(button(picture.action.label, { onClick: () => { if (api) void api.openServerSetup(); } }));
      pane.appendChild(actions);
    }
    // A run started from the button keeps the keyboard where it was: on that button, rebuilt.
    if (focusRun && runButton) runButton.focus();
  }

  async function show(id) {
    current = id;
    markCurrent();
    let picture = null;
    try { picture = await api.describe(id); } catch { picture = null; }
    if (current !== id) return;
    const result = lastRun.get(id) || null;
    renderPane(picture, result, running.has(id) ? 'checking' : 'idle');
    pane.dataset.check = id;
    // A check opened for the first time runs at once: the pane is live on arrival. Later visits keep the
    // last outcome and offer Run again.
    if (picture && picture.canProbe && !result && !running.has(id)) void run(id);
  }

  async function run(id, { focusRun = false } = {}) {
    if (running.has(id)) return;
    running.add(id);
    let picture = null;
    try { picture = await api.describe(id); } catch { picture = null; }
    if (current === id) renderPane(picture, lastRun.get(id) || null, 'checking', { focusRun });
    let result = null;
    try { result = await api.probe(id); } catch { result = null; }
    running.delete(id);
    if (result && result.ran) { result.at = Date.now(); lastRun.set(id, result); }
    else lastRun.set(id, { ran: false, at: Date.now(), legs: [], notes: [], verdict: { state: 'bad', text: "This check couldn't run. Try again." } });
    if (current === id) {
      // What is set up may have changed while the probe ran (a server change lands mid-run): describe again.
      let fresh = picture;
      try { fresh = await api.describe(id); } catch { /* keep the earlier picture */ }
      if (current === id) renderPane(fresh, lastRun.get(id), 'idle', { focusRun }); // the person may have moved on meanwhile
    }
  }

  btnClose.addEventListener('click', () => { if (api) void api.close(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && api) void api.close(); });

  (async () => {
    if (!api) { clear(pane); pane.appendChild(para('This page is only available inside DockVault.')); return; }
    let list = [];
    try { list = (await api.checks()) || []; } catch { list = []; }
    if (!list.length) { clear(pane); pane.appendChild(para('No checks are available.')); return; }
    current = list[0].id;
    renderChecks(list);
    await show(current);
  })();
})();

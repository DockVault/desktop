'use strict';

/*
 * The "Set up sync" wizard page. The main process leads a conversation (sync-wizard.js): it poses one typed
 * question at a time and this page renders it — a step to set this computer up, a vault list, a folder
 * choice, the checks and the consent — and hands back the person's choice over the one narrow capability
 * (window.dockvault.wizard.answer). The page holds no state beyond the question on screen, fetches nothing,
 * and never names a folder: "Choose folder…" asks main to open the OS picker. Every element is built with
 * textContent, never markup from data.
 */

(function wizard() {
  const api = (window.dockvault && window.dockvault.wizard) || null;
  const title = document.getElementById('title');
  const body = document.getElementById('body');
  const footer = document.getElementById('footer');
  const steps = { computer: document.getElementById('step-computer'), vault: document.getElementById('step-vault'), folder: document.getElementById('step-folder') };

  let current = null;   // the question on screen
  let answering = false;
  let escapeAction = null; // what Escape does on this screen (the screen's own "leave" button), if anything

  // --- small builders (textContent only) -----------------------------------------------------------
  const el = (tag, cls, text) => { const n = document.createElement(tag); if (cls) n.className = cls; if (text != null) n.textContent = text; return n; };
  const para = (text, cls) => el('p', cls, text);
  const box = (tone, ...children) => { const b = el('div', `box${tone ? ` ${tone}` : ''}`); for (const c of children) b.appendChild(c); return b; };
  // `busy` is the label the button takes while its answer is being acted on (a network call, a save), so the
  // screen shows that something is happening rather than a row of greyed buttons. `escape` marks the button
  // the Escape key presses.
  function button(label, { primary = false, danger = false, onClick, disabled = false, autofocus = false, busy = null, escape = false } = {}) {
    const b = el('button', `btn${primary ? ' primary' : ''}${danger ? ' danger' : ''}`, label);
    b.type = 'button'; b.disabled = disabled;
    b.addEventListener('click', () => { if (answering) return; if (busy) { b.textContent = busy; b.setAttribute('aria-busy', 'true'); } onClick(); });
    if (autofocus) setTimeout(() => { try { b.focus(); } catch { /* not focusable yet */ } }, 0);
    if (escape) escapeAction = () => { if (!answering && !b.disabled) b.click(); };
    return b;
  }
  function endpointText(leg) {
    if (!leg || !leg.host) return 'that address';
    const h = leg.host.includes(':') ? `[${leg.host}]` : leg.host;
    return `${h}:${leg.port}`;
  }

  function setSteps(state) {
    for (const [k, node] of Object.entries(steps)) {
      const s = state[k];
      if (s) node.dataset.state = s; else delete node.dataset.state;
    }
  }

  function render(q) {
    current = q;
    answering = false;
    escapeAction = null;
    title.textContent = '';
    body.replaceChildren();
    footer.replaceChildren();
    if (!q) { title.textContent = 'Getting things ready…'; setSteps({}); return; }
    const view = VIEWS[q.kind] || VIEWS.failed;
    view(q);
  }

  async function answer(value) {
    if (!api || !current || answering) return;
    answering = true;
    const id = current.id;
    // A question that has been answered shows a waiting state until the next one arrives.
    for (const b of footer.querySelectorAll('button')) b.disabled = true;
    try { await api.answer(id, value); } catch { /* the next question (or the end) tells the story */ }
  }
  const closeWindow = () => { if (api) void api.close(); };
  const openApp = () => { if (api) void api.openApp(); };

  // The one way out of a terminal statement.
  function doneFooter(label = 'Close') {
    footer.appendChild(el('span', 'spacer'));
    footer.appendChild(button(label, { primary: true, onClick: closeWindow, autofocus: true, escape: true }));
  }

  // The results of moving already-syncing vaults onto this computer, as one list.
  function movedList(moved) {
    const wrap = el('div');
    wrap.appendChild(para('Vaults that already synced here:'));
    const l = el('ul', 'plain');
    for (const m of moved) l.appendChild(el('li', null, m.message || `${m.vaultName}: ${m.outcome}`));
    wrap.appendChild(l);
    return wrap;
  }

  // The SFTP failure sentences — the same words the setup screen uses.
  function sftpSentence(prev) {
    const at = endpointText(prev);
    switch (prev && prev.kind) {
      case 'empty': return 'Enter the file transfer address (SFTP).';
      case 'malformed': return 'Enter a host and port, for example vault.example.com:2222.';
      case 'unreachable': return `Couldn't reach ${at}. Check the address and the port — ask whoever runs your server which port SFTP is on.`;
      case 'not-ssh': return `${at} answers, but not as an SFTP server — usually the wrong port. Try the port whoever runs your server gave you (often 2222).`;
      case 'ssh-unsupported': return `${at} is an SSH server, but not one DockVault can use. Check the port; if it's right, ask whoever runs your server.`;
      case 'host-key-unverified': return `${at} presented a host key it couldn't prove it owns, so DockVault won't use it. Check the address; if it's right, ask whoever runs your server.`;
      default: return `Couldn't check ${at}.`;
    }
  }

  const VIEWS = {
    'sign-in': () => {
      setSteps({});
      title.textContent = 'Sign in first';
      body.appendChild(para('Sign in to your account, then set up sync again from the tray menu.'));
      footer.appendChild(button('Close', { onClick: closeWindow, escape: true }));
      footer.appendChild(button('Open DockVault', { primary: true, onClick: () => { openApp(); closeWindow(); }, autofocus: true }));
    },
    unsupported: (q) => {
      setSteps({});
      if (q.reason === 'too-old') {
        title.textContent = "This server doesn't support syncing folders from this computer";
        body.appendChild(para('You can still sign in and use your files in DockVault. Ask whoever runs your server about updating it.'));
      } else {
        title.textContent = "Couldn't check whether this server supports syncing";
        body.appendChild(para('DockVault could not tell right now. Check your connection and try again in a little while.'));
      }
      doneFooter();
    },
    'computer-problem': (q) => {
      setSteps({ computer: 'current' });
      title.textContent = "This computer can't be set up to sync right now";
      const why = q.status === 'no-secure-store'
        ? "This computer has no secure place to keep a sync identity, so it can't sync on its own."
        : (q.status === 'stale' || q.status === 'rechecking')
          ? "This computer's sync identity is being re-checked with the server. Try again in a little while."
          : "DockVault can't read this computer's sync identity right now. This usually clears up after unlocking your login keychain, then closing DockVault and starting it again.";
      body.appendChild(para(why));
      doneFooter();
    },
    failed: (q) => {
      setSteps({});
      if (q && q.reason === 'config-unreadable') {
        title.textContent = 'Your sync settings could not be read';
        body.appendChild(para('DockVault will not overwrite them. This usually clears up after unlocking your login keychain, then closing DockVault and starting it again.'));
      } else if (q && q.reason === 'bad-vault-name') {
        title.textContent = "That vault can't be synced to a folder";
        body.appendChild(para("Its name contains characters that can't be used as a folder name. Rename the vault, then try again."));
      } else {
        title.textContent = "Sync couldn't be set up";
        body.appendChild(para("Nothing was changed. Try again; if it keeps happening, check your connection and that the folder can be created."));
      }
      if (q && Array.isArray(q.moved) && q.moved.length) body.appendChild(movedList(q.moved));
      doneFooter();
    },
    'no-vaults': (q) => {
      setSteps({ computer: 'done', vault: 'current' });
      title.textContent = 'No vaults can be synced to this computer yet';
      body.appendChild(para('Syncing to a folder is available for standard vaults. Create one, then set up sync again from the tray menu.'));
      if (Array.isArray(q.moved) && q.moved.length) body.appendChild(movedList(q.moved));
      footer.appendChild(button('Close', { onClick: closeWindow, escape: true }));
      footer.appendChild(button('Open DockVault', { primary: true, onClick: () => { openApp(); closeWindow(); }, autofocus: true }));
    },
    'sftp-address': (q) => {
      setSteps({});
      title.textContent = 'One more thing about your server';
      body.appendChild(para("To sync files, DockVault needs your server's file transfer (SFTP) address. It is usually your server's name on port 2222. Enter it once — DockVault checks it before going on."));
      const field = el('input'); field.type = 'text'; field.id = 'sftp'; field.autocomplete = 'off'; field.spellcheck = false;
      field.value = (q.previous && typeof q.previous.text === 'string' && q.previous.text) ? q.previous.text : (q.suggestion || '');
      const lbl = el('label', null, 'File transfer address (SFTP)'); lbl.htmlFor = 'sftp';
      body.appendChild(lbl); body.appendChild(field);
      if (q.previous) { field.setAttribute('aria-invalid', 'true'); body.appendChild(box('bad', para(sftpSentence(q.previous)))); }
      const go = button('Check and continue', { primary: true, busy: 'Checking…', onClick: () => answer(field.value.trim()) });
      field.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); if (field.value.trim()) answer(field.value.trim()); } });
      field.addEventListener('input', () => { go.disabled = !field.value.trim(); });
      go.disabled = !field.value.trim();
      footer.appendChild(button('Cancel', { onClick: () => answer(null), escape: true }));
      footer.appendChild(go);
      setTimeout(() => { try { field.focus(); field.select(); } catch { /* ignore */ } }, 0);
    },
    'set-up-computer': (q) => {
      setSteps({ computer: 'current' });
      title.textContent = 'Set this computer up to sync';
      body.appendChild(para(`It will appear in your account as "${q.label}". You can't rename it later without setting this computer up again.`, 'lead'));
      body.appendChild(para('This computer keeps syncing on its own — even while DockVault or the screen is locked. You can remove it from your account at any time.'));
      if (q.switchFrom) {
        body.appendChild(box('warn',
          para(`This computer is already set up to sync with ${q.switchFrom}.`),
          para(`It will stop using its identity there and get a new one here. ${q.switchFrom} will still list this computer until its owner removes it there.`)));
      }
      footer.appendChild(button('Not now', { onClick: () => answer(false), autofocus: true, escape: true }));
      footer.appendChild(button(q.switchFrom ? 'Switch to this server' : 'Set up this computer', { primary: true, busy: 'Setting up…', onClick: () => answer(true) }));
    },
    'register-failed': (q) => {
      setSteps({ computer: 'current' });
      title.textContent = "This computer couldn't be set up to sync";
      const lines = [];
      if (q.switched) lines.push('This computer is no longer set up with its previous server.');
      if (q.reason === 'device-cap-reached') lines.push("You've reached this server's limit of synced computers, so it couldn't be added here. Remove a computer you no longer use from your account, then try again.");
      else if (q.reason === 'registered-elsewhere') lines.push('This computer turned out to be set up with another server. Run Set up sync again to switch it to this one.');
      else lines.push("Setting this computer up didn't finish. Check your connection and try again in a little while.");
      for (const l of lines) body.appendChild(para(l));
      doneFooter();
    },
    'move-existing': (q) => {
      setSteps({ computer: 'current' });
      const n = q.vaults.length;
      title.textContent = n === 1 ? 'One vault already syncs here through your sign-in' : `${n} vaults already sync here through your sign-in`;
      body.appendChild(para('This computer can now sync them on its own — even while DockVault or the screen is locked. Set them up on this computer too?'));
      const list = el('ul', 'plain');
      for (const v of q.vaults) list.appendChild(el('li', null, v.vaultName));
      body.appendChild(list);
      if (q.vaults.some((v) => v.hasPassword)) body.appendChild(para('For a password-protected vault, the move finishes the next time you open that vault in DockVault.', 'hint'));
      footer.appendChild(button('Skip', { onClick: () => answer(false), autofocus: true, escape: true }));
      footer.appendChild(button(n === 1 ? 'Set it up here' : 'Set them up here', { primary: true, busy: 'Setting up…', onClick: () => answer(true) }));
    },
    moved: (q) => {
      setSteps({ computer: 'done' });
      const all = q.moved.every((m) => m.outcome === 'granted');
      title.textContent = all ? 'Done — those vaults now sync on this computer' : 'Here is where those vaults stand';
      const l = el('ul', 'plain');
      for (const m of q.moved) l.appendChild(el('li', null, m.message || `${m.vaultName}: ${m.outcome}`));
      body.appendChild(l);
      body.appendChild(para('Want to sync another vault to this computer as well?'));
      footer.appendChild(button('Done', { onClick: () => answer('done'), autofocus: true, escape: true }));
      footer.appendChild(button('Sync another vault', { primary: true, onClick: () => answer('continue') }));
    },
    'done-moved': (q) => {
      setSteps({ computer: 'done' });
      title.textContent = 'Sync setup finished';
      body.appendChild(movedList(q.moved || []));
      body.appendChild(para('Sync status shows in the DockVault tray menu.', 'hint'));
      doneFooter('Done');
    },
    'pick-vault': (q) => {
      setSteps({ computer: 'done', vault: 'current' });
      title.textContent = 'Which vault do you want to sync to this computer?';
      body.appendChild(para('Its files will be kept in a folder you choose in the next step.'));
      const list = el('ul', 'vaults'); list.setAttribute('role', 'radiogroup'); list.setAttribute('aria-label', 'Vaults');
      let chosen = null;
      const go = button('Continue', { primary: true, disabled: true, onClick: () => { if (chosen) answer(chosen); } });
      const select = (v, b) => {
        chosen = v.vaultId;
        for (const other of list.querySelectorAll('.vault')) other.setAttribute('aria-checked', other === b ? 'true' : 'false');
        go.disabled = false;
      };
      q.vaults.forEach((v, i) => {
        const li = el('li');
        const b = el('button', 'vault'); b.type = 'button'; b.setAttribute('role', 'radio'); b.setAttribute('aria-checked', 'false');
        b.appendChild(el('span', 'name', v.vaultName));
        if (v.hasPassword) b.appendChild(el('span', 'badge', 'password-protected'));
        if (v.configured) b.appendChild(el('span', 'badge', 'already syncing — picking it moves it to a new folder'));
        b.addEventListener('click', () => select(v, b));
        b.addEventListener('dblclick', () => { select(v, b); answer(chosen); });
        // Keyboard: arrows move between vaults, Enter picks the focused one and continues.
        b.addEventListener('keydown', (e) => {
          const items = [...list.querySelectorAll('.vault')];
          const at = items.indexOf(b);
          if (e.key === 'ArrowDown' || e.key === 'ArrowUp') { e.preventDefault(); const n = items[(at + (e.key === 'ArrowDown' ? 1 : items.length - 1)) % items.length]; n.focus(); }
          if (e.key === 'Enter') { e.preventDefault(); select(v, b); answer(chosen); }
        });
        li.appendChild(b); list.appendChild(li);
        if (i === 0) setTimeout(() => { try { b.focus(); } catch { /* ignore */ } }, 0);
      });
      body.appendChild(list);
      if (q.someExcluded) body.appendChild(para('Some of your vaults are not shown here — only standard vaults can be synced to a folder.', 'hint'));
      footer.appendChild(button('Cancel', { onClick: () => answer(null), escape: true }));
      footer.appendChild(go);
    },
    'pick-folder': (q) => {
      setSteps({ computer: 'done', vault: 'done', folder: 'current' });
      title.textContent = `Choose a folder for ${q.vaultName}`;
      body.appendChild(para('The vault\'s files will be kept in this folder, and files you put there are uploaded to the vault. Pick an empty folder, or one you mean to fill with this vault.'));
      if (q.currentFolder) body.appendChild(box('warn', para(`${q.vaultName} currently syncs to ${q.currentFolder}. Choosing a new folder moves it there; the old folder stops syncing and its files stay where they are.`)));
      if (q.refusal) body.appendChild(box('bad', para(q.refusal.message || "That folder can't be used for sync. Pick another folder.")));
      footer.appendChild(button('Cancel', { onClick: () => answer(null), escape: true }));
      footer.appendChild(button('Choose folder…', { primary: true, onClick: () => answer('choose'), autofocus: true }));
    },
    'confirm-cloud': (q) => {
      setSteps({ computer: 'done', vault: 'done', folder: 'current' });
      title.textContent = `This folder is inside ${q.service}`;
      body.appendChild(el('p', 'mono', q.folder));
      body.appendChild(box('warn', para(q.message || '')));
      footer.appendChild(button('Choose another folder', { onClick: () => answer(false), autofocus: true, escape: true }));
      footer.appendChild(button('Use it anyway', { onClick: () => answer(true) }));
    },
    'confirm-make-private': (q) => {
      setSteps({ computer: 'done', vault: 'done', folder: 'current' });
      title.textContent = 'This folder is shared with other accounts on this computer';
      body.appendChild(el('p', 'mono', q.folder));
      body.appendChild(para('Synced files are readable copies, so the folder has to be private to you. DockVault can make it private — only you will have access — or you can choose a different folder.'));
      if ((q.shares || []).length) { body.appendChild(para('Currently shared with:')); const l = el('ul', 'plain'); for (const s of q.shares) l.appendChild(el('li', 'mono', s)); body.appendChild(l); }
      if ((q.denies || []).length) body.appendChild(para('The folder also carries explicit deny rules, which would be removed.', 'hint'));
      footer.appendChild(button('Cancel setup', { onClick: () => answer('cancel'), escape: true }));
      footer.appendChild(button('Choose a different folder', { onClick: () => answer('choose-different'), autofocus: true }));
      footer.appendChild(button('Make it private', { primary: true, busy: 'Making it private…', onClick: () => answer('make-private') }));
    },
    consent: (q) => {
      setSteps({ computer: 'done', vault: 'done', folder: 'current' });
      title.textContent = `Sync ${q.vaultName} to this computer?`;
      body.appendChild(el('p', 'mono', q.folder));
      body.appendChild(para(q.message || ''));
      if (q.priorFolder) body.appendChild(box('warn', para(`The previous folder (${q.priorFolder}) will no longer sync; the files already there are left as they are.`)));
      if (q.outsideProfile) body.appendChild(box('warn', para('On Windows, a folder outside your user profile can be read by other accounts on this PC — a folder inside your profile keeps these copies private.')));
      // Neither confirm nor abandon on a stray Enter: the focused button only goes back to the folder step. The
      // readable-copies + upload decision takes a deliberate click, and so does throwing the set-up away.
      footer.appendChild(button('Cancel setup', { onClick: () => answer(false), escape: true }));
      footer.appendChild(button('Choose a different folder', { onClick: () => answer('choose-different'), autofocus: true }));
      footer.appendChild(button('Sync this vault', { primary: true, busy: 'Setting up…', onClick: () => answer(true) }));
    },
    done: (q) => {
      setSteps({ computer: 'done', vault: 'done', folder: 'done' });
      title.textContent = `${q.vaultName} is set up to sync`;
      body.appendChild(el('p', 'mono', q.folder));
      // Anything short of a clean grant is a note, not an alarm: the vault IS set up and syncs through the sign-in
      // meanwhile; the sentence says what finishes it.
      const tone = q.outcome === 'granted' ? 'ok' : 'warn';
      body.appendChild(box(tone, para(q.message || '')));
      if (q.outcome === 'grant-failed') body.appendChild(para('To move it onto this computer later, run Set up sync again and pick this vault.', 'hint'));
      if (Array.isArray(q.moved) && q.moved.length) body.appendChild(movedList(q.moved));
      doneFooter('Done');
    },
  };

  async function start() {
    if (!api) { title.textContent = 'This screen is unavailable.'; return; }
    let seen = false;
    api.onQuestion((q) => { seen = true; render(q); });
    let q = null;
    try { q = await api.state(); } catch { q = null; }
    if (!seen) render(q); // a question pushed meanwhile is newer than this read
  }

  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && escapeAction) { e.preventDefault(); escapeAction(); } });
  start();
})();

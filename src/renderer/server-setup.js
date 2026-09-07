'use strict';

/*
 * The server setup screen. It renders exactly one of the typed outcomes the main process answers
 * with, in plain words; it fetches nothing itself and holds no state beyond what is on screen. The
 * address is sent over the one narrow capability (window.dockvault.server.connect); main normalises,
 * checks, saves, and loads the sign-in page. "Try again" is the same action as "Connect": the person
 * can correct the address first.
 */

(function setup() {
  const api = (window.dockvault && window.dockvault.server) || null;
  const field = document.getElementById('server');
  const line = document.getElementById('line');
  const button = document.getElementById('connect');
  const form = document.getElementById('form');
  const confirmBox = document.getElementById('confirm');
  const confirmText = document.getElementById('confirm-text');
  const replace = document.getElementById('replace');
  const title = document.getElementById('title');
  const intro = document.getElementById('intro');

  let busy = false;
  let needsConfirm = false;

  function say(text, tone) {
    line.textContent = text || '';
    if (tone) line.dataset.tone = tone; else delete line.dataset.tone;
    field.setAttribute('aria-invalid', tone === 'error' ? 'true' : 'false');
  }

  function setButton(label, enabled) {
    button.textContent = label;
    button.disabled = !enabled;
  }

  function refreshButton() {
    if (busy) return;
    const nonEmpty = field.value.trim().length > 0;
    const okToTry = nonEmpty && (!needsConfirm || replace.checked);
    setButton(button.textContent === 'Checking…' ? 'Connect' : button.textContent, okToTry);
  }

  // "Connected", and unmissably so when a redirect changed the server the person typed.
  function connectedLine(outcome) {
    const host = outcome.host || '';
    return outcome.from && outcome.from !== host
      ? `${outcome.from} sent us to ${host} — connected there.`
      : `Connected to ${host}.`;
  }

  // The words for each outcome. Only the host of the normalised origin is ever shown, never an error.
  function render(outcome) {
    const host = outcome.host || '';
    switch (outcome.kind) {
      case 'http-refused':
        say('DockVault connects over https only. Change http:// to https://.', 'error');
        setButton('Connect', true); break;
      case 'malformed':
        say("That doesn't look like a server address.", 'error');
        setButton('Connect', true); break;
      case 'empty':
        say('', null); setButton('Connect', false); break;
      case 'unreachable':
        say(`Couldn't reach ${host}. Check the address and your connection, then try again.`, 'error');
        setButton('Try again', true); break;
      case 'tls-untrusted':
        say("This server's certificate isn't trusted by this computer, so DockVault won't connect. Ask your administrator to install the certificate on this computer, then try again.", 'error');
        setButton('Try again', true); break;
      case 'not-dockvault':
        say("That address answers, but it isn't a DockVault server.", 'error');
        setButton('Try again', true); break;
      case 'redirected':
        say('That address redirects somewhere else. Enter the address it lands on.', 'error');
        setButton('Try again', true); break;
      case 'needs-confirm':
        needsConfirm = true;
        confirmBox.hidden = false;
        confirmText.textContent = "Your saved server setting couldn't be read. Connecting will replace it.";
        say('', null); setButton('Connect', replace.checked); break;
      case 'degraded':
        say(`${connectedLine(outcome)} Your server is running but reports a problem — signing in may still work.`, 'note');
        setButton('Connected', false); break;
      case 'ok':
        say(connectedLine(outcome), 'ok');
        setButton('Connected', false); break;
      case 'save-failed':
        say("Couldn't save the server setting on this computer. Try again.", 'error');
        setButton('Try again', true); break;
      case 'refused':
      case 'not-allowed':
        // A server is already saved and no change was asked for from the tray: nothing is written.
        say('This screen is unavailable.', 'error');
        setButton('Connect', false); break;
      default:
        say("Couldn't check that server. Try again.", 'error');
        setButton('Try again', true);
    }
  }

  async function connect(event) {
    if (event) event.preventDefault();
    if (busy || !api) return;
    const typed = field.value.trim();
    if (!typed) return;
    busy = true;
    say(`Connecting to ${typed.match(/^[a-z][a-z0-9+.-]*:\/\//i) ? typed : `https://${typed}`}`, 'note');
    setButton('Checking…', false);
    let outcome;
    try { outcome = await api.connect(typed, { replaceUnreadable: needsConfirm && replace.checked }); }
    catch { outcome = { kind: 'failed' }; }
    busy = false;
    if (outcome && (outcome.kind === 'ok' || outcome.kind === 'degraded')) {
      // Main is loading the sign-in page from the new server now; leave the confirmation on screen.
      render(outcome);
      return;
    }
    render(outcome || { kind: 'failed' });
    field.focus();
  }

  async function start() {
    if (!api) { say('This screen is unavailable.', 'error'); return; }
    let state = null;
    try { state = await api.state(); } catch { state = null; }
    if (state && state.mode === 'change') {
      title.textContent = 'Change your DockVault server';
      intro.textContent = 'Enter the address of the server to use from now on.';
      if (state.host) field.value = state.host;
    }
    if (state && state.status === 'unreadable') render({ kind: 'needs-confirm' });
    refreshButton();
    field.focus();
    if (field.value) field.select();
  }

  field.addEventListener('input', () => { if (!busy) { say('', null); refreshButton(); } });
  replace.addEventListener('change', refreshButton);
  form.addEventListener('submit', connect);
  start();
})();

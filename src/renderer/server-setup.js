'use strict';

/*
 * The server setup screen. Two addresses (the server, and where synced files are sent over SFTP), a
 * verify step that lights each of them independently, and a Connect that is offered only once both
 * are green — or once the server has said it does not support syncing, in which case the SFTP light is
 * set aside and the screen says so in plain words. It renders exactly the typed outcomes the main
 * process answers with; it fetches nothing itself and holds no state beyond what is on screen. The
 * addresses go over the two narrow capabilities (window.dockvault.server.check / .connect); main
 * normalises, checks, saves, and loads the sign-in page. Connecting never sets up sync: that is a
 * separate flow, later, only if the person asks for it.
 */

(function setup() {
  const api = (window.dockvault && window.dockvault.server) || null;
  const field = document.getElementById('server');
  const sftpField = document.getElementById('sftp');
  const line = document.getElementById('line');
  const button = document.getElementById('connect');
  const form = document.getElementById('form');
  const confirmBox = document.getElementById('confirm');
  const confirmText = document.getElementById('confirm-text');
  const replace = document.getElementById('replace');
  const title = document.getElementById('title');
  const intro = document.getElementById('intro');
  const lights = document.getElementById('lights');
  const lightApi = document.getElementById('light-api');
  const lightSftp = document.getElementById('light-sftp');
  const apiWhat = document.getElementById('api-what');
  const sftpWhat = document.getElementById('sftp-what');
  const sftpFp = document.getElementById('sftp-fp');
  const syncLine = document.getElementById('sync');

  const DEFAULT_SFTP_PORT = 2222;
  // A submit that lands within this long of the button turning into Connect is a second Enter from the
  // check, not a decision made on the lights; it is ignored.
  const SETTLE_MS = 400;

  let busy = false;
  let needsConfirm = false;
  let verified = false;       // the last check passed for the addresses as they stand now
  let verifiedAt = 0;
  let suggestedHost = null;   // the host the SFTP field was last filled with by the screen (not the person)

  function say(text, tone) {
    line.textContent = text || '';
    if (tone) line.dataset.tone = tone; else delete line.dataset.tone;
  }

  // Each field is marked invalid on its own leg's verdict, never on the other's.
  function markFields(apiBad, sftpBad) {
    field.setAttribute('aria-invalid', apiBad ? 'true' : 'false');
    sftpField.setAttribute('aria-invalid', sftpBad ? 'true' : 'false');
  }

  function setButton(label, enabled) {
    button.textContent = label;
    button.disabled = !enabled;
  }

  function refreshButton() {
    if (busy) return;
    const okToTry = field.value.trim().length > 0 && (!needsConfirm || replace.checked);
    if (verified) setButton('Connect', okToTry);
    else setButton(button.textContent === 'Check again' ? 'Check again' : 'Check', okToTry);
  }

  function hostnameOf(typed) {
    try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(typed) ? typed : `https://${typed}`).hostname; } catch { return ''; }
  }
  // The host part of what is in the SFTP field, and the port part (kept when the host is swapped).
  function splitSftpField() {
    const v = sftpField.value.trim();
    const m = v.match(/^(\[[^\]]*\]|[^:]*)(?::(\d{1,5}))?$/);
    return m ? { host: m[1], port: m[2] || null } : { host: v, port: null };
  }

  // The SFTP address is almost always the server's own name on the default port: suggest it as the
  // person types the server. The suggestion follows the server host for as long as the field still
  // holds a host the screen put there — a port the person changed is kept — and stops the moment they
  // type a host of their own. So a server change never leaves a stale host behind, and a pre-filled
  // address from a previous server (when switching) is replaced as soon as a different server is typed.
  function suggestSftp() {
    const typed = field.value.trim();
    const current = splitSftpField();
    const followable = sftpField.value.trim() === '' || (suggestedHost !== null && current.host === suggestedHost);
    if (!followable) return;
    if (!typed) { sftpField.value = ''; suggestedHost = null; return; }
    const hostname = hostnameOf(typed);
    if (!hostname) { sftpField.value = ''; suggestedHost = null; return; }
    sftpField.value = `${hostname}:${current.port || DEFAULT_SFTP_PORT}`;
    suggestedHost = hostname;
  }

  function setLight(el, whatEl, state, text) {
    el.dataset.state = state;
    whatEl.textContent = text;
  }

  function endpointText(leg) {
    if (!leg || !leg.host) return 'that address';
    const h = leg.host.includes(':') ? `[${leg.host}]` : leg.host;
    return `${h}:${leg.port}`;
  }

  // The API leg's sentence. Only the host of the normalised origin is ever shown, never an error.
  function apiSentence(outcome) {
    const host = (outcome && outcome.host) || '';
    switch (outcome && outcome.kind) {
      case 'ok': return outcome.from && outcome.from !== host ? `${outcome.from} sent us to ${host} — that's a DockVault server.` : `${host} is a DockVault server.`;
      case 'degraded': return `${host} is a DockVault server, but it reports a problem — signing in may still work.`;
      case 'http-refused': return 'DockVault connects over https only. Change http:// to https://.';
      case 'malformed': return "That doesn't look like a server address.";
      case 'empty': return 'Enter your server address.';
      case 'unreachable': return `Couldn't reach ${host}. Check the address and your connection.`;
      case 'tls-untrusted': return "This server's certificate isn't trusted by this computer, so DockVault won't connect. Ask your administrator to install the certificate on this computer.";
      case 'not-dockvault': return "That address answers, but it isn't a DockVault server. Check the address with whoever runs it.";
      case 'redirected': return 'That address redirects somewhere else. Enter the address it lands on.';
      default: return "Couldn't check that server.";
    }
  }

  function sftpSentence(leg) {
    const at = endpointText(leg);
    switch (leg && leg.kind) {
      case 'ok': return `Reachable at ${at}, and it answered as an SFTP server.`;
      case 'not-needed': return "Not needed — this server doesn't sync folders, so this address is set aside.";
      case 'empty': return 'Enter the file transfer address (SFTP).';
      case 'malformed': return 'Enter a host and port, for example vault.example.com:2222.';
      case 'unreachable': return `Couldn't reach ${at}. Check the address and the port — ask whoever runs your server which port SFTP is on.`;
      case 'not-ssh': return `${at} answers, but not as an SFTP server — usually the wrong port. Try the port whoever runs your server gave you (often 2222).`;
      case 'ssh-unsupported': return `${at} is an SSH server, but not one DockVault can use. Check the port; if it's right, ask whoever runs your server.`;
      case 'host-key-unverified': return `${at} presented a host key it couldn't prove it owns, so DockVault won't use it. Check the address; if it's right, ask whoever runs your server — something between you and the server may be interfering.`;
      default: return `Couldn't check ${at}.`;
    }
  }

  function syncSentence(kind) {
    switch (kind) {
      case 'supported': return 'This server can sync folders from this computer. Nothing is syncing yet — you can set that up later from the DockVault tray menu.';
      case 'unsupported': return "This server doesn't support syncing folders from this computer. You can still sign in and use your files in the app.";
      case 'unknown': return "Couldn't tell whether this server supports syncing folders from this computer, so the file transfer address must check out before you connect. If it can't, ask whoever runs your server.";
      default: return '';
    }
  }

  function renderLights(verify) {
    if (!verify) { lights.hidden = true; markFields(false, false); return; }
    lights.hidden = false;
    const api = verify.api || {};
    const apiGreen = api.kind === 'ok' || api.kind === 'degraded';
    setLight(lightApi, apiWhat, apiGreen ? 'ok' : 'bad', apiSentence(api));
    const sftp = verify.sftp || {};
    const sftpState = sftp.kind === 'ok' ? 'ok' : (sftp.kind === 'not-needed' ? 'skip' : 'bad');
    setLight(lightSftp, sftpWhat, sftpState, sftpSentence(sftp));
    markFields(!apiGreen, sftpState === 'bad');
    if (sftp.kind === 'ok' && sftp.fingerprint) { sftpFp.textContent = `Host key fingerprint ${sftp.fingerprint}`; sftpFp.hidden = false; }
    else { sftpFp.textContent = ''; sftpFp.hidden = true; }
    const sync = (verify.sync && verify.sync.kind) || 'not-checked';
    const sentence = syncSentence(sync);
    syncLine.textContent = sentence;
    syncLine.hidden = !sentence;
    if (sync === 'supported') delete syncLine.dataset.tone; else syncLine.dataset.tone = 'no';
  }

  function showChecking() {
    lights.hidden = false;
    setLight(lightApi, apiWhat, 'checking', 'Checking…');
    setLight(lightSftp, sftpWhat, 'checking', 'Checking…');
    sftpFp.hidden = true; syncLine.hidden = true;
  }

  // "Connected", and unmissably so when a redirect changed the server the person typed.
  function connectedLine(outcome) {
    const host = outcome.host || '';
    return outcome.from && outcome.from !== host
      ? `${outcome.from} sent us to ${host} — connected there.`
      : `Connected to ${host}.`;
  }

  // The words for each outcome of Connect. Only the host of the normalised origin is ever shown, never an error.
  function render(outcome) {
    renderLights(outcome.verify);
    switch (outcome.kind) {
      case 'http-refused':
        say('DockVault connects over https only. Change http:// to https://.', 'error');
        setButton('Check', true); break;
      case 'malformed':
        say("That doesn't look like a server address.", 'error');
        setButton('Check', true); break;
      case 'empty':
        say('', null); setButton('Check', false); break;
      case 'unreachable':
      case 'tls-untrusted':
      case 'not-dockvault':
      case 'redirected':
        say('', null);
        setButton('Check again', true); break;
      case 'not-verified':
        say("Not connected: the file transfer address didn't check out.", 'error');
        setButton('Check again', true); break;
      case 'needs-confirm':
        // The check passed; only the confirmation is missing, so the button stays Connect.
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
        // Likewise: verified, but the setting could not be written; Connect tries the write again.
        say("Couldn't save the server setting on this computer. Try again.", 'error');
        setButton('Connect', true); break;
      case 'refused':
      case 'not-allowed':
        // A server is already saved and no change was asked for from the tray: nothing is written.
        say('This screen is unavailable.', 'error');
        setButton('Check', false); break;
      default:
        say("Couldn't check that server. Try again.", 'error');
        setButton('Check again', true);
    }
  }

  function fieldsNow() { return `${field.value.trim()}\n${sftpField.value.trim()}`; }

  async function check() {
    if (busy || !api) return;
    busy = true;
    verified = false;
    const checkedFields = fieldsNow();
    say('', null);
    showChecking();
    setButton('Checking…', false);
    let verify;
    try { verify = await api.check(field.value.trim(), sftpField.value.trim()); } catch { verify = null; }
    busy = false;
    // Typed while the check ran: the verdict is for addresses no longer on screen, so it is dropped.
    if (fieldsNow() !== checkedFields) { renderLights(null); setButton('Check', true); refreshButton(); return; }
    if (!verify) { renderLights(null); say("Couldn't check that server. Try again.", 'error'); setButton('Check again', true); return; }
    renderLights(verify);
    verified = verify.proceed === true;
    verifiedAt = Date.now();
    if (verified) {
      const setAside = verify.sftp && verify.sftp.kind !== 'ok';
      say(setAside ? 'Your server checks out. Connect to continue.' : 'Both addresses check out. Connect to continue.', 'ok');
      setButton('Connect', !needsConfirm || replace.checked);
    } else {
      const apiGreen = verify.api && (verify.api.kind === 'ok' || verify.api.kind === 'degraded');
      say(apiGreen ? 'Fix the file transfer address, then check again.' : 'Fix the server address, then check again.', 'error');
      setButton('Check again', true);
      (apiGreen ? sftpField : field).focus();
    }
  }

  async function connect() {
    if (busy || !api) return;
    busy = true;
    say('Connecting…', 'note');
    setButton('Connecting…', false);
    let outcome;
    try { outcome = await api.connect(field.value.trim(), sftpField.value.trim(), { replaceUnreadable: needsConfirm && replace.checked }); }
    catch { outcome = { kind: 'failed' }; }
    busy = false;
    if (outcome && (outcome.kind === 'ok' || outcome.kind === 'degraded')) {
      // Main is loading the sign-in page from the new server now; leave the confirmation on screen.
      render(outcome);
      return;
    }
    // The verify main ran on connect still stands for these two: only the write was held back.
    verified = !!(outcome && (outcome.kind === 'needs-confirm' || outcome.kind === 'save-failed'));
    render(outcome || { kind: 'failed' });
  }

  function submit(event) {
    if (event) event.preventDefault();
    if (busy || !api) return;
    if (!field.value.trim()) return;
    if (verified && Date.now() - verifiedAt < SETTLE_MS) return;
    if (verified) void connect(); else void check();
  }

  function edited() {
    if (busy) return;
    verified = false;
    say('', null);
    lights.hidden = true;
    markFields(false, false);
    setButton('Check', false);
    refreshButton();
  }

  async function start() {
    if (!api) { say('This screen is unavailable.', 'error'); return; }
    let state = null;
    try { state = await api.state(); } catch { state = null; }
    if (state && state.mode === 'change') {
      title.textContent = 'Change your DockVault server';
      intro.textContent = 'Enter the addresses of the server to use from now on. Both are checked before anything changes.';
      if (state.host) field.value = state.host;
      // The previous server's SFTP address is a starting point, not a decision: it follows the server
      // host as soon as a different one is typed, exactly like a suggestion would.
      if (state.sftp) { sftpField.value = state.sftp; suggestedHost = splitSftpField().host; }
    }
    if (!sftpField.value) suggestSftp();
    if (state && state.status === 'unreadable') render({ kind: 'needs-confirm' });
    refreshButton();
    field.focus();
    if (field.value) field.select();
  }

  field.addEventListener('input', () => { suggestSftp(); edited(); });
  sftpField.addEventListener('input', () => {
    // A host the person typed themselves is theirs; a suggestion left in place still follows the server.
    if (splitSftpField().host !== suggestedHost) suggestedHost = null;
    edited();
  });
  replace.addEventListener('change', refreshButton);
  form.addEventListener('submit', submit);
  start();
})();

'use strict';

/*
 * Start-at-login as one honest fact.
 *
 * The app never remembers whether it starts at login: it asks the platform every time. What the
 * tray shows, what the first launch discloses, and what the person toggles all read and write the
 * same registration, under the same name, so the checkbox can never disagree with what the machine
 * will actually do.
 *
 *   Windows / macOS  Electron's login-item settings, registered under LOGIN_ITEM_NAME (on Windows
 *                    that is the per-user Run value the uninstaller removes; see build/installer.nsh).
 *   Linux            an XDG autostart entry, ~/.config/autostart/<desktopName>, pointing at the
 *                    AppImage when the app runs from one (the APPIMAGE variable the runtime sets),
 *                    else at the installed executable. Electron has no login-item support there.
 *
 * Everything that touches the OS is injected, so the logic is testable without a desktop.
 */

const path = require('node:path');
const { LOGIN_ITEM_NAME } = require('./app-identity');

function createLoginItem({ app, platform, fs, homeDir, env = {}, execPath, isPortable = false, desktopName = 'dockvault.desktop', productName = 'DockVault' }) {
  const autostartDir = path.join(homeDir || '', '.config', 'autostart');
  const autostartFile = path.join(autostartDir, desktopName);
  // The command the desktop runs at login: the AppImage itself when running from one, else this executable.
  const launchPath = () => (platform === 'linux' && env.APPIMAGE) ? env.APPIMAGE : execPath;
  // Electron parses the path it is given as a command line, so a path with spaces must be handed over
  // quoted or it is cut at the first space and never matches the entry it wrote itself.
  const quotedPath = () => `"${String(launchPath()).replace(/"/g, '')}"`;

  function isEnabled() {
    if (platform === 'linux') {
      // Desktops disable an autostart entry IN PLACE (KDE and gnome-session-properties write Hidden=true
      // or X-GNOME-Autostart-enabled=false) rather than deleting it, so "the file exists" is not the state.
      try {
        if (!fs.existsSync(autostartFile)) return false;
        const text = String(fs.readFileSync(autostartFile, 'utf8'));
        const disabled = /^\s*Hidden\s*=\s*true\s*$/im.test(text) || /^\s*X-GNOME-Autostart-enabled\s*=\s*false\s*$/im.test(text);
        return !disabled;
      } catch { return false; }
    }
    try {
      const s = app.getLoginItemSettings({ path: quotedPath() });
      if (s.openAtLogin !== true) return false;
      // Windows keeps the registration and a separate "startup apps" switch (Task Manager): a registered
      // item the person switched off there will NOT start. Electron reports that per launch item, so the
      // checkbox says what will actually happen: our own item, and it must be enabled.
      if (Array.isArray(s.launchItems) && s.launchItems.length) {
        return s.launchItems.some((it) => it && it.name === LOGIN_ITEM_NAME && it.enabled === true);
      }
      return true;
    } catch { return false; }
  }

  function setEnabled(enabled) {
    if (platform === 'linux') {
      if (enabled) {
        fs.mkdirSync(autostartDir, { recursive: true });
        const exec = launchPath().replace(/"/g, '');
        // The installed icon theme entry exists only for a package install; an AppImage carries its icon
        // inside itself, and a name that points at nothing shows a placeholder in startup-app lists.
        const icon = env.APPIMAGE ? [] : ['Icon=dockvault'];
        fs.writeFileSync(autostartFile, [
          '[Desktop Entry]',
          'Type=Application',
          `Name=${productName}`,
          `Exec="${exec}"`,
          ...icon,
          'Terminal=false',
          'X-GNOME-Autostart-enabled=true',
          `Comment=${productName} starts when you log in`,
          '',
        ].join('\n'), { mode: 0o644 });
      } else {
        try { fs.unlinkSync(autostartFile); } catch (e) { if (!e || e.code !== 'ENOENT') throw e; }
      }
    } else {
      // `enabled: true` also flips the Windows "startup apps" switch back on for an item the person had
      // switched off there, so turning the checkbox on from that state really does re-enable it.
      app.setLoginItemSettings({ openAtLogin: enabled, enabled: true, name: LOGIN_ITEM_NAME, path: quotedPath() });
    }
    return isEnabled();
  }

  // A PORTABLE copy registers nothing and reports nothing, whoever asks and however they ask.
  //
  // The guard belongs HERE and not only on the launch path, which is where it was first put. The
  // tray's "Start at login" switch is a different path to the same registry value, and a person who
  // ticks it is asking just as much as a first launch is. The value name is the application id — the
  // same for every copy of DockVault — so a portable copy ticking that box overwrites the INSTALLED
  // app's entry and points it at the temporary folder the launcher deletes when the run ends. The
  // installed app then stops starting at login, aimed at nothing, and its own switch reads "off"
  // because the value no longer names it. On a machine with no install it is orphaned for good.
  //
  // Reporting false rather than the real registration is deliberate: a portable copy that read back
  // the INSTALLED app's registration would show a ticked box for something it does not own and did
  // not do, and the obvious next move — untick it — would be the same damage by another route.
  //
  // `canChange` is the same fact asked a different way, for callers that do more than flip the switch. The
  // tray's toggle also RECORDS the person's choice in the app's data folder, and that write is not covered by
  // refusing setEnabled: a portable click was refused by the line above and still left a
  // login-item.json saying {"startAtLogin":true} behind it - a stored preference nothing honours, which the
  // next reader has to work out. Callers ask this before doing anything at all.
  if (isPortable) return { isEnabled: () => false, setEnabled: () => false, canChange: () => false, autostartFile };

  return { isEnabled, setEnabled, canChange: () => true, autostartFile };
}

/*
 * The person's explicit choice about starting at login, kept in the app's data folder (which an
 * uninstall leaves in place). It governs ONE thing: whether the app may register a login item
 * without being asked. The tray checkbox never reads it — that always shows the real registration.
 *
 *   no stored choice   first launch of an installed app: register, tell the person, store "on"
 *   stored "on"        leave the registration as it is — a login item the person removed by hand
 *                      is not quietly put back; the checkbox shows the truth and they can turn it on
 *   stored "off"       never register, never notify again
 */
const CHOICE_FILE = 'login-item.json';

function createLoginChoiceStore({ fs, dir }) {
  const file = path.join(dir, CHOICE_FILE);
  // null = no choice was ever stored; 'unreadable' = a file exists but cannot be trusted (truncated,
  // malformed, unreadable). Unreadable is NOT absent: the app then writes nothing unasked.
  function read() {
    let raw;
    try { raw = fs.readFileSync(file, 'utf8'); } catch (e) { return (e && e.code === 'ENOENT') ? null : 'unreadable'; }
    try {
      const v = JSON.parse(raw);
      return typeof v.startAtLogin === 'boolean' ? v.startAtLogin : 'unreadable';
    } catch { return 'unreadable'; }
  }
  function write(startAtLogin) {
    fs.mkdirSync(dir, { recursive: true });
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify({ startAtLogin: !!startAtLogin, decidedAt: new Date().toISOString() }) + '\n', { mode: 0o600 });
    fs.renameSync(tmp, file);
  }
  return { read, write, file };
}

// What an installed app does at launch, from the stored choice alone. Development runs never register,
// and only a genuinely ABSENT choice (null) may register: an unreadable one is not "no choice".
function decideOnLaunch({ storedChoice, isPackaged, isPortable = false }) {
  if (!isPackaged) return { register: false, notify: false, store: null };
  // A PORTABLE run never registers and never announces itself, and this is not a nicety.
  // Registration is keyed on the application id, which is the same string for every copy of
  // DockVault, so a portable run would overwrite the INSTALLED app's start-at-login entry — and
  // point it at its own executable, which lives in a temporary folder that is deleted the moment
  // the portable run ends. The installed app would then silently stop starting at login, aimed at
  // a path that no longer exists, and its own switch would read "off" because the value no longer
  // names it. On a machine with no install at all, the entry would simply be left behind forever:
  // nothing removes it, because the thing that removes it is an uninstaller that will never run.
  // A portable build is supposed to leave nothing behind, and this is the largest thing it could.
  // The notification is suppressed for the same reason — it says "DockVault is installed" and
  // "It starts when you sign in", neither of which is true of a build that was not installed.
  if (isPortable) return { register: false, notify: false, store: null };
  if (storedChoice === null) return { register: true, notify: true, store: true };
  return { register: false, notify: false, store: null };
}

module.exports = { createLoginItem, createLoginChoiceStore, decideOnLaunch, CHOICE_FILE };

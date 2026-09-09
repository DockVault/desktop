'use strict';

/*
 * THE APPLICATION MENU FOR A TRAY APP.
 *
 * Electron gives every app a default menubar — File, Edit, View, Window, Help — built for a document editor.
 * DockVault is a tray app whose main window hosts the vault's own web interface, and that default menu was
 * both wrong for it and, in one place, actively unwanted:
 *
 *   View -> Reload / Force Reload / Toggle Developer Tools, on the one window that holds a signed-in
 *   session. Developer tools on a credentialed page in a SHIPPED build is a door nobody asked for: it is
 *   the standard way to read a page's storage, and it is offered by default to anyone at the keyboard.
 *   In a development run it is exactly what a developer needs, so this keeps it there and drops it when
 *   packaged — the same split `serverConfig.setEnvOverrideAllowed(!app.isPackaged)` already makes for the
 *   server override.
 *
 *   Help -> Learn More points at electronjs.org, which is not this app's help.
 *
 * WHAT STAYS, AND WHY IT IS NOT OPTIONAL. The Edit menu keeps its clipboard ROLES — undo, redo, cut, copy,
 * paste, select all. Not for the menu items themselves, which few people use, but because on Windows and
 * Linux those roles are what bind Ctrl+C / Ctrl+V / Ctrl+A inside text inputs. Remove the menu entirely and
 * the server-address field silently stops accepting a pasted address, which is the first thing anyone does
 * with it. That is the trap this phase exists to avoid, and it is why the menu is slimmed rather than
 * removed.
 *
 * Pure: it returns a template of plain objects and roles, so what the menu contains is unit-tested without
 * an Electron instance. The caller turns it into a real menu and supplies the actions.
 */

/**
 * @param {object} o
 * @param {boolean} o.isPackaged       a shipped build; false in a development run
 * @param {string}  o.platform         process.platform
 * @param {object}  o.actions          { status, computers, troubleshoot, about, quit } — each a function
 * @param {string}  [o.appName]        for the macOS application menu's own label
 * @returns {Array<object>} an Electron menu template
 */
function buildMenuTemplate({ isPackaged, platform, actions = {}, appName = 'DockVault' }) {
  const mac = platform === 'darwin';
  const item = (label, fn, extra = {}) => ({ label, click: typeof fn === 'function' ? fn : () => {}, ...extra });

  // The things this app can actually do, in the order someone would look for them. These are the same
  // affordances the tray offers: one place to change them, and no menu entry that leads somewhere the tray
  // does not also go.
  const doors = [
    item('Sync status…', actions.status),
    item('Computers & synced folders…', actions.computers),
    item('Troubleshoot…', actions.troubleshoot),
  ];

  const template = [];

  if (mac) {
    // macOS puts the app's own menu first, and expects About and Quit to live in it. `quit` is a role there
    // rather than a click, so the standard Cmd+Q keeps working.
    template.push({
      label: appName,
      submenu: [
        item(`About ${appName}`, actions.about),
        { type: 'separator' },
        ...doors,
        { type: 'separator' },
        { role: 'hide' }, { role: 'hideOthers' }, { role: 'unhide' },
        { type: 'separator' },
        { role: 'quit' },
      ],
    });
  } else {
    template.push({
      label: '&File',
      submenu: [
        ...doors,
        { type: 'separator' },
        item(`About ${appName}`, actions.about),
        { type: 'separator' },
        // Not the `quit` role: this is a tray app, and Quit must go through the app's own shutdown so a
        // run in flight is not cut off mid-write. The accelerator is stated because dropping the default
        // menu would otherwise take Ctrl+Q with it.
        item('Quit DockVault', actions.quit, { accelerator: 'CmdOrCtrl+Q' }),
      ],
    });
  }

  // THE ONE MENU THAT IS NOT DECORATION. These roles carry the clipboard accelerators for every text input
  // in the app. Cutting them would leave the server-address field unable to accept a paste.
  template.push({
    label: '&Edit',
    submenu: [
      { role: 'undo' }, { role: 'redo' },
      { type: 'separator' },
      { role: 'cut' }, { role: 'copy' }, { role: 'paste' },
      ...(mac ? [{ role: 'pasteAndMatchStyle' }] : []),
      { role: 'delete' },
      { type: 'separator' },
      { role: 'selectAll' },
    ],
  });

  // Developer tools, in a development run only. Reload belongs with them: reloading the window that hosts
  // the vault's interface mid-session is a developer's action, not a person's.
  if (!isPackaged) {
    template.push({
      label: '&View',
      submenu: [
        { role: 'reload' }, { role: 'forceReload' }, { role: 'toggleDevTools' },
        { type: 'separator' },
        { role: 'resetZoom' }, { role: 'zoomIn' }, { role: 'zoomOut' },
      ],
    });
  }

  return template;
}

// Every label this menu can put on screen, flattened — so a test can assert what a person is offered
// without reaching into nested submenus, and so nothing can be added without being visible to that test.
function labelsOf(template) {
  const out = [];
  const walk = (items) => {
    for (const it of items || []) {
      if (!it || it.type === 'separator') continue;
      if (it.label) out.push(it.label);
      if (it.role && !it.label) out.push(`role:${it.role}`);
      if (Array.isArray(it.submenu)) walk(it.submenu);
    }
  };
  walk(template);
  return out;
}

// The roles present anywhere in the template, which is what actually decides whether an accelerator works.
function rolesOf(template) {
  const out = [];
  const walk = (items) => {
    for (const it of items || []) {
      if (!it) continue;
      if (it.role) out.push(it.role);
      if (Array.isArray(it.submenu)) walk(it.submenu);
    }
  };
  walk(template);
  return out;
}

module.exports = { buildMenuTemplate, labelsOf, rolesOf };

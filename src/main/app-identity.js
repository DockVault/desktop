'use strict';

/*
 * The app's platform identity, shared between the running app and the installer so the two can
 * never disagree.
 *
 *   APP_ID           The application id: the bundle / package id electron-builder stamps on the
 *                    installers and, on Windows, the AppUserModelId the installer writes into every
 *                    shortcut. The running app must report the SAME id, or Windows will not group
 *                    its taskbar button with its shortcut and may not show its notifications.
 *   LOGIN_ITEM_NAME  The name under which the app registers itself to start at login (on Windows,
 *                    the value name in the per-user Run key). It is the application id: Electron
 *                    looks a login item up under the AppUserModelId, so any other name would be
 *                    written but never read back. The uninstaller removes exactly this name.
 *
 * This is deliberately separate from the app's name, which decides where its data lives.
 */

const APP_ID = 'io.dockvault.desktop';
const LOGIN_ITEM_NAME = APP_ID;

module.exports = { APP_ID, LOGIN_ITEM_NAME };

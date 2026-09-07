# DockVault Desktop

A cross-platform desktop client for [DockVault](https://github.com/DockVault/vault) — the self-hosted,
zero-knowledge encrypted file vault.

> Status: early development. Structure and interfaces are expected to change.

## Planned capabilities

- Vault browsing and management from the desktop, reusing the vault's own web interface.
- Two-way local folder sync for Standard vaults, backed by [rclone](https://rclone.org/).
- Client-side handling of zero-knowledge vaults, using the vault's existing browser cryptography.
- A system-tray presence with sync status and conflict handling.

Windows, macOS, and Linux are treated as first-class targets.

## Server requirements

Background sync for Standard vaults requires the server to run DockVault vault 0.27.0 or later — the first
release that serves its full SFTP host key. The client pins that key to verify the server before it syncs.
Against an older server, sync degrades gracefully rather than failing: the client pauses and reports that it
cannot verify the server yet, and never syncs unverified.

## Repository layout

- `vendor/vault` — the DockVault vault application, included as a git submodule and pinned to a released
  tag. It provides the reused web interface and cryptography, and is read-only within this repository.

Clone with submodules:

```
git clone --recurse-submodules https://github.com/DockVault/desktop.git
```

## Installing

Installers are produced by the `Build installers` workflow (see below) and attached to releases:

- Windows: `DockVault-<version>-win-x64.exe` — a one-click installer with no questions and no
  administrator prompt. It installs under `%LOCALAPPDATA%\Programs\dockvault-desktop` for the current Windows user only (other people on this PC
  install it separately) and starts DockVault when it finishes. Uninstalling removes the program
  and its start-at-login entry; your synced files stay in their folders and the app's data stays
  in `%APPDATA%\dockvault-desktop`, so this computer's registration and sync state survive a
  reinstall. Delete that folder yourself if you want it gone.
- macOS: `DockVault-<version>-mac-arm64.dmg` (Apple silicon) or `DockVault-<version>-mac-x64.dmg`
  (Intel) — drag DockVault into Applications.
- Linux: `DockVault-<version>-linux-x64.AppImage` (make it executable and run it) or
  `DockVault-<version>-linux-x64.deb` for Debian and Ubuntu. The tray needs a status-notifier host;
  on GNOME install the AppIndicator extension.

DockVault lives in the system tray. Closing its window keeps it running in the background. The
first launch after installing registers DockVault to start when you sign in and tells you so; the
tray menu's "Start at login" switch shows the real state and turns it off or on. That entry points
at where DockVault was when you switched it on: if you move the app (for example the AppImage),
turn the switch off and on again. On macOS and Linux, turn it off before deleting the app, as
nothing else removes it; the Windows uninstaller removes it for you.

Each installer carries its own copy of [rclone](https://rclone.org/), the helper that performs
Standard-vault sync, so nothing else needs to be installed.

The first time DockVault opens it asks for two addresses and checks both before saving anything:
your server's address (https only), and the file transfer (SFTP) address that synced folders are
sent to, which is usually the server's own name on port 2222. Each gets its own light: the server
must answer as DockVault, and the SFTP address must be reachable and prove its host key. An address
that cannot be reached, a certificate this computer does not trust, a server that is not DockVault,
or a port that is not SFTP each get a plain explanation, never a bypass. The check also tells you up
front whether the server supports syncing folders from this computer at all; if it does not, you can
still connect and use your files, and the SFTP address is not needed. The SFTP address you verified is
what sync connects to from then on, even when a deployment publishes SFTP on a different port than the
server believes. Connecting to a server never sets up sync by itself.

From then on the saved server is used; the tray's "Change server…" signs you out of the old one
first. For development, `DOCKVAULT_SERVER` overrides the saved setting, and the tray says so when it
does.

## Building installers

Installers are produced by [electron-builder](https://www.electron.build/), pinned in
`package-lock.json`. From a clean clone (on Windows, keep the clone path short: the installer
compiler cannot read include files from a path longer than 260 characters):

```
git clone --recurse-submodules https://github.com/DockVault/desktop.git
cd desktop
npm ci
npm run dist          # installers for the platform you are on
npm run pack          # an unpacked app under dist/ for inspection, no installer
```

`npm run dist:win`, `dist:mac`, and `dist:linux` pick a platform explicitly. Each platform is built
on its own operating system (macOS builds must run on a Mac to be signed and notarized); the
`Build installers` workflow under `.github/workflows` does exactly that for all three.

Nothing is compiled at build time: the state-database module ships as a prebuilt N-API binary for
every target, and only the binary for the target platform is included. Two builds of the same commit
have the same contents but not the same bytes (signatures and timestamps differ).

The bundled sync helper is downloaded by `scripts/fetch-rclone.js` (the `dist` scripts run it) from
the official rclone release and checked, before anything is written, against the SHA-256 values
pinned in `build/rclone.json`: one for the release archive, one for the binary inside it. The app
re-checks that binary hash before every launch of the helper. Packaging refuses to run when the
verified binary is missing, so an installer can never quietly ship without it. To move to a new
rclone release, update the version and both hashes in the manifest.

Signing and notarization are driven entirely by the environment of the build — locally or as
repository secrets in CI — and never by anything checked in:

| Variable | Purpose |
| --- | --- |
| `CSC_LINK`, `CSC_KEY_PASSWORD` | Code-signing certificate (Windows Authenticode `.pfx`, or the macOS Developer ID `.p12`) |
| `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD`, `APPLE_TEAM_ID` | macOS notarization |

Without them the build still succeeds and produces an **unsigned** installer, which is fine for
local testing but not for distribution; CI states in its job summary whether a build was signed.

## License

AGPL-3.0-only — see [LICENSE](LICENSE). Because vault sources are bundled, the client as a whole is
distributed under AGPL-3.0, with corresponding source made available.

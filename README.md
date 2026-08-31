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

## Repository layout

- `vendor/vault` — the DockVault vault application, included as a git submodule and pinned to a released
  tag. It provides the reused web interface and cryptography, and is read-only within this repository.

Clone with submodules:

```
git clone --recurse-submodules https://github.com/DockVault/desktop.git
```

## License

AGPL-3.0-only — see [LICENSE](LICENSE). Because vault sources are bundled, the client as a whole is
distributed under AGPL-3.0, with corresponding source made available.

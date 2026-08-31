# Contributing

## Commit messages

Clear and self-contained, with a conventional prefix (`feat`, `fix`, `docs`, `chore`, `test`, `ci`).

## Never committed

- Secrets, tokens, credentials, or private keys — in the tree or in history.
- Local-only runtime data, scratch files, or generated build output. Local data belongs under `.local/`,
  which is gitignored.

## The vault submodule

`vendor/vault` is read-only within this repository. It tracks a released tag of the vault application and
is advanced only deliberately. Vault changes are made in the vault project, not here.

## Secret scanning

Pushes and pull requests are scanned for secrets in CI (`.github/workflows/leak-scan.yml`); a finding
blocks the merge.

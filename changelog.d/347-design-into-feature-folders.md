### Changed

- **The feature folders now hold the design content that was only in `docs/design/DESIGN.md` (#347).** The new sections are:
  - **Cancellation** (`docs/keyslots/architecture.md`, `docs/volumes/engineering.md`). A key derivation is never interrupted. `ctx` is checked before and after each derivation, between keyslots in a scan, between digest checks and before each PBKDF2 calibration probe, so a cancellation takes effect within one derivation.
  - **Portability** (`docs/volumes/architecture.md`). `pkg/luks2` and `pkg/keyprovider` build on Linux and darwin; `pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`, `pkg/wipe` and the CLI are Linux-only; Windows is out of scope.
  - **The `MigrateToFIPS` example**, moved from the user guide to `docs/fips/api.md`.
  - **A FIDO2 enrollment example** in `docs/tokens/api.md`.

  `docs/volumes/cli.md` now also states that `SIGINT` and `SIGTERM` cancel the running `luks2` command, that a write in progress stops at its next consistent step boundary, and that the command exits with the resulting error's status, 1 for a cancellation. Look for these topics in the feature folders, not in `docs/design/`.

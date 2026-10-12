# go-luks2 roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-12 against train/docs5 (adeb2ca)
> Changes are proposed by docs-only PR.

## Mission

go-luks2 is the Layer 0 LUKS2 disk encryption library and CLI of the portfolio.
It creates, opens and manages LUKS2 volumes interoperably with the cryptsetup userspace tools.
Key material stays in go-enclave locked memory for its whole lifetime.

## Current milestone

[Release candidate (M7)](../../milestone/7): target kind RC, `v1.0.0-rc.4` tagged; the only open milestone.
Projected date: not set.

## Now

Each item names the `docs/<feature>/` folder that specifies it. Folders still in review are code spans.

- [#211](../../issues/211) public release readiness signed off, in all of [docs/](docs/): in review
- [#312](../../issues/312) dm-crypt activation specified, in `docs/dm-crypt-activation/`: in review
- [#313](../../issues/313) kernel keyring hand-off specified, in `docs/kernel-keyring/`: in review
- [#314](../../issues/314) filesystem creation specified, in `docs/filesystems/`: in review
- [#315](../../issues/315) loop devices specified, in `docs/loop-devices/`: in review
- [#316](../../issues/316) every `pkg/luks2` export documented, unprovided operations stated, in [docs/volumes/](docs/volumes/), [docs/header/](docs/header/), [docs/tokens/](docs/tokens/), [docs/fips/](docs/fips/): in review
- [#317](../../issues/317) stale names, paths and keyring order corrected, in [docs/volumes/](docs/volumes/), [docs/fips/](docs/fips/): in review
- [#319](../../issues/319) rejected alternatives recorded, in [docs/cryptsetup-interop/](docs/cryptsetup-interop/), [docs/header/](docs/header/), [docs/keyslots/](docs/keyslots/), [docs/recovery-keys/](docs/recovery-keys/), [docs/tokens/](docs/tokens/), [docs/wipe/](docs/wipe/): in review
- [#326](../../issues/326) `pkg/luks2` unit tests inside the CI time budget, specified by [docs/keyslots/](docs/keyslots/): in review
- [#334](../../issues/334) `ValidatePassphrase` returns one error shape, every failure an `*Error` so `errors.As` matches all of them, in [docs/volumes/](docs/volumes/): in review
- [#335](../../issues/335) every export gated against the feature docs, failing when an exported identifier appears in no `docs/<feature>/` file, in [docs/volumes/](docs/volumes/) (the api-diff contract): in review
- [#330](../../issues/330) roadmap names the feature folder behind every item, across all of [docs/](docs/): in review
- [#324](../../issues/324) keyring-unavailable remedy names `dmcrypt.CheckKeyring`, in `docs/kernel-keyring/`: in review
- [#331](../../issues/331) docs scrub: remaining content of the monolithic design record migrated into every feature folder, feature docs publication-clean, the design record retired with the docs index and stamps current, in all of [docs/](docs/): blocked: waits for open PRs to land

## Next

- [#211](../../issues/211) release readiness: go-enclave pinned at an RC or release (key custody in [docs/volumes/](docs/volumes/)) and the owner-run joint staging run, in all of [docs/](docs/): blocked: go-enclave RC or release before `v1.0.0`
- [M7](../../milestone/7) `v1.0.0` cut once M7 closes, in all of [docs/](docs/): blocked: [#211](../../issues/211)

## Readiness

- `v1.0.0-rc.4` tagged and consumer-checked — done
- CI and nightly FIPS green on `main` — done
- [#290](../../issues/290) release artifacts signed — open
- [#294](../../issues/294) every doc carries banner and stamp — done
- [#308](../../issues/308) nightly FIPS gate green — done
- ROADMAP.md present — done

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-rc.1 (locked-memory primitive, the only in-house module). It needs a final release before `v1.0.0` ([#211](../../issues/211)).
- Down: go-trusted-platform (encrypted volume management).

## Non-goals

- No service transport: go-luks2 is an embedded Go library with no REST, gRPC, QUIC, MCP or Unix-socket form ([docs/volumes/api.md](docs/volumes/api.md)).
- No in-house dependency beyond go-enclave.

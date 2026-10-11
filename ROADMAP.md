# go-luks2 roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-11 against main (f871541)
> Changes are proposed by docs-only PR.

## Mission

go-luks2 is the Layer 0 LUKS2 disk encryption library and CLI of the portfolio.
It creates, opens and manages LUKS2 volumes interoperably with the cryptsetup userspace tools.
Key material stays in go-enclave locked memory for its whole lifetime.

## Current milestone

[Release candidate (M7)](../../milestone/7): target kind RC, `v1.0.0-rc.4` tagged.
Projected date: not set.

## Now

- [#211](../../issues/211) public release readiness signed off: in review
- [#311](../../issues/311) CLI exit codes documented as the code returns them: open
- [#312](../../issues/312), [#313](../../issues/313), [#314](../../issues/314), [#315](../../issues/315) feature folders for dm-crypt activation, kernel keyring, filesystems and loop devices: open
- [#316](../../issues/316), [#317](../../issues/317) every exported name documented, stale names fixed: open
- [#318](../../issues/318), [#319](../../issues/319) design content migrated into feature docs, rejected alternatives recorded: open
- [#320](../../issues/320) feature docs publication-clean: open
- [#321](../../issues/321) legacy docs/design retired, docs index and stamps current: open

## Next

- `v1.0.0` cut once M7 closes — blocked on:
  - [#211](../../issues/211) public release readiness
  - an RC or release of the upstream go-enclave
  - the joint staging run, which is owner-run

## Readiness

- `v1.0.0-rc.4` tagged and consumer-checked — done
- CI and nightly FIPS green on `main` — done
- [#290](../../issues/290) release artifacts signed — deferred
- [#294](../../issues/294) every doc carries banner and stamp — done
- [#308](../../issues/308) nightly FIPS gate green — done
- ROADMAP.md present — done

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-alpha (locked-memory primitive, the only in-house module). It needs an RC or release before `v1.0.0`.
- Down: go-trusted-platform (encrypted volume management).

## Non-goals

- Ownership boundaries and non-goals are defined in [the ownership and SDK boundary document, §R](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
- No in-house dependency beyond go-enclave.

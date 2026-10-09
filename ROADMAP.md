# go-luks2 roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-08
> Changes are proposed by docs-only PR.

## Mission

go-luks2 is the Layer 0 LUKS2 disk encryption library and CLI of the portfolio.
It creates, opens and manages LUKS2 volumes interoperably with the cryptsetup userspace tools.
Key material stays in go-enclave locked memory for its whole lifetime.

## Current milestone

[Release candidate (M7)](../../milestone/7): target kind RC, v1.0.0-rc.4 tagged.
Projected date: not set.

## Now

- [#211](../../issues/211) public release readiness signed off — in review
- [#290](../../issues/290) release artifacts signed — open
- [#294](../../issues/294) every doc carries banner and stamp, serena config conforms — open
- readiness: ROADMAP.md present — done

## Next

- readiness: v1.0.0 cut once M7 closes — blocked: #211, #290

## Later

Nothing accepted. New work arrives as issues.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-alpha (locked-memory primitive, the only in-house module).
- Down: go-trusted-platform (encrypted volume management).

## Non-goals

- Ownership boundaries are defined in [the ownership and SDK boundary document](../handbook/software/docs/00-ownership-and-sdk-boundary.md).
- No in-house dependency beyond go-enclave.

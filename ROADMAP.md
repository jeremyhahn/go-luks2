# go-luks2 roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-13 against fef1d25
> Changes are proposed by docs-only PR. [docs/SPEC.md](docs/SPEC.md) is normative: every line here names one of its features, and where the two disagree, SPEC.md wins.

## Mission

go-luks2 is the Layer 0 LUKS2 disk encryption library and CLI of the portfolio.
It creates, opens and manages LUKS2 volumes interoperably with the cryptsetup userspace tools.
Key material stays in go-enclave locked memory for its whole lifetime.
Purpose and boundaries are in [SPEC.md](docs/SPEC.md#purpose).

## Milestones

- [Release candidate (M7)](../../milestone/7) — RC — Due: 2026-10-15. `v1.0.0-rc.4` is tagged, the version is confirmed at publish approval, and it closes on the [SPEC.md release criteria](docs/SPEC.md#release-criteria).

## Complete

Shipped features, with the release or closing issues that shipped them.

- **volumes** — every `pkg/luks2` export documented and unprovided operations stated — [#316](../../issues/316) — done
- **volumes** — stale names, paths and keyring order corrected — [#317](../../issues/317) — done
- **volumes** — `ValidatePassphrase` returns one error shape — [#334](../../issues/334) — done
- **volumes** — every export gated against the feature docs — [#335](../../issues/335) — done
- **keyslots** — rejected alternatives recorded — [#319](../../issues/319) — done
- **keyslots** — `pkg/luks2` unit tests inside the CI time budget — [#326](../../issues/326) — done
- **recovery-keys** — rejected alternatives recorded — [#319](../../issues/319) — done
- **tokens** — exports documented — [#316](../../issues/316) — done
- **tokens** — rejected alternatives recorded — [#319](../../issues/319) — done
- **header** — exports documented and unprovided operations stated — [#316](../../issues/316) — done
- **header** — rejected alternatives recorded — [#319](../../issues/319) — done
- **dm-crypt-activation** — specified — [#312](../../issues/312) — done
- **kernel-keyring** — specified — [#313](../../issues/313) — done
- **kernel-keyring** — the keyring-unavailable remedy names `dmcrypt.CheckKeyring` — [#324](../../issues/324) — done
- **loop-devices** — specified — [#315](../../issues/315) — done
- **filesystems** — specified — [#314](../../issues/314) — done
- **wipe** — rejected alternatives recorded — [#319](../../issues/319) — done
- **fips** — nightly FIPS gate green — [#308](../../issues/308) — done
- **fips** — exports documented — [#316](../../issues/316) — done
- **fips** — stale names, paths and keyring order corrected — [#317](../../issues/317) — done
- **cryptsetup-interop** — rejected alternatives recorded — [#319](../../issues/319) — done

Closed issues on features still in progress:

- **release** — [#290](../../issues/290), [#294](../../issues/294), [#330](../../issues/330), [#331](../../issues/331) — signed releases; banners and stamps on every doc; the roadmap names the feature folder behind every item; the monolithic design record migrated into the feature folders and retired

## Now

- **release** — public release readiness — [#211](../../issues/211) — blocked: owner publish approval and choice of public version; go-enclave final release and the owner-run joint staging run

## Next

- **release** — v1.0.0 cut once [M7](../../milestone/7) closes — [#211](../../issues/211) — blocked: M7 open

## Later

No planned feature. SPEC.md lists none.

## Future

No future feature. SPEC.md lists none.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-rc.2 (locked-memory primitive, the only in-house module), for **volumes** key custody. It needs a final release before `v1.0.0` ([#211](../../issues/211)).
- Down: go-trusted-platform (encrypted volume management), which uses **volumes**.

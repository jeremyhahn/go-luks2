# go-luks2 roadmap

> **Status: REFERENCE** · Owner: Software Department · Last verified: 2026-10-16 against aa16242
> Changes are proposed by docs-only PR. [docs/SPEC.md](docs/SPEC.md) is normative: every line here names one of its features, and where the two disagree, SPEC.md wins.

## Mission

go-luks2 is the Layer 0 LUKS2 disk encryption library and CLI of the portfolio.
It creates, opens and manages LUKS2 volumes interoperably with the cryptsetup userspace tools.
It embeds go-enclave as a library and inherits its locked-memory custody: key material stays in go-enclave locked memory for its whole lifetime, and credentials and keys cross its API as go-enclave's own `*enclave.Memory`.
It runs embedded in its consumer's process, never as a second product, and keeps no store, cluster, engine or service of its own; the only state it writes is the LUKS2 header, keyslots and tokens on the volume.
Purpose and boundaries are in [SPEC.md](docs/SPEC.md#purpose).

## Milestones

- [Dev complete (M7)](../../milestone/7) — Dev complete — Due: 2026-10-16. Closes on the dev-complete list of the [SPEC.md release criteria](docs/SPEC.md#release-criteria): every own feature row shipped, go-trusted-platform's seam rows on go-luks2 shipped on go-luks2's side; the API is stable from the release candidate on, not at dev complete; `-alpha` tags only until go-trusted-platform is dev complete, and the release-candidate tags already cut stay.

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

## Now

- **release** — public release readiness — [#211](../../issues/211) — blocked: owner publish approval and choice of public version; go-enclave final release and the owner-run joint staging run
- **release** — signed releases; banners and stamps on every doc; the roadmap names the feature folder behind every item; the monolithic design record migrated into the feature folders and retired — [#290](../../issues/290), [#294](../../issues/294), [#330](../../issues/330), [#331](../../issues/331) — done

## Next

- **release** — v1.0.0 cut after the release candidate that follows [M7](../../milestone/7) — [#211](../../issues/211) — blocked: M7 open; go-trusted-platform dev complete

## Later

No planned feature. SPEC.md lists none.

## Future

No future feature. SPEC.md lists none.

## Dependencies

- Up: `github.com/jeremyhahn/go-enclave` v0.8.0-rc.2 (locked-memory primitive, the only in-house module), for **volumes** key custody. It needs a final release before `v1.0.0` ([#211](../../issues/211)).
- Down: go-trusted-platform (encrypted volume management), which uses **volumes**.
- Standards watch: LUKS2 On-Disk Format Specification (work in progress), pinned at version 1.1.3 (LUKS2-docs commit `55f31ae5`), implemented by `internal/header` and `pkg/luks2` ([docs/reference/](docs/reference/README.md)).

# go-luks2 docs

> **Status: NORMATIVE** · Last verified: 2026-10-08 against v1.0.0-rc.2 (12a364e)
> Conflicts with this document are defects. Fix them here first.

Documentation is organized as one feature folder per CLI command group
(`software/conventions/feature-docs.md`, handbook), not as flat topic files.
Each folder holds five files — `architecture.md`, `engineering.md`, `cli.md`,
`api.md`, `user.md` — with its own status banner and `Last verified:` stamp.
**An agent picking up work on a feature reads its folder before it reads
code.**

## Index

| Folder | Covers |
|---|---|
| [volumes](volumes/) | Create, open, mount, close; the device layer; key custody; trust boundaries |
| [keyslots](keyslots/) | Keyslot structure, KDF, cost inheritance, removal |
| [recovery-keys](recovery-keys/) | Generated recovery credentials |
| [tokens](tokens/) | Header token metadata, key providers (FIDO2, helper commands) |
| [header](header/) | On-disk layout, binary header, JSON metadata, untrusted-header bounds |
| [wipe](wipe/) | Crypto-erase and full-device sanitization |
| [fips](fips/) | FIPS 140-3 mode, SHA-1 handling, `MigrateToFIPS` |
| [cryptsetup-interop](cryptsetup-interop/) | Compatibility policy, the two-way interop matrix |

[design/DESIGN.md](design/DESIGN.md) is the target architecture and public
API the redesign was built against; [design/DECISIONS.md](design/DECISIONS.md)
is the decisions log for every step, including what each step did not finish.
The redesign has landed: every feature folder above documents the real,
`go doc`-checked API, not a target, and `make api-diff` holds the exported
surface to DESIGN.md §B.6. The seam-variable allowlist
(`test/makefile/seamvars_test.go`) is empty: `pkg/luks2`'s seams live on
`Volume`'s `volumeSys`.

## Versioning policy

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Tags carry
a `v` (`v1.0.0-rc.2`); the `VERSION` file does not (`1.0.0-rc.2`). A `-rc.N`
or `-alpha` suffix is a prerelease (lower precedence than the version it
precedes) and promises nothing outside this project: `-rc.N` says only "this
is what `1.0.0` will be unless a defect is found".

go-luks2 is at `1.0.0-rc.4`, the release candidate for `1.0.0`. From `1.0.0`:

| Bump | Means |
|---|---|
| PATCH (`1.0.0` → `1.0.1`) | A fix. No exported API change, no change to what is written to disk. |
| MINOR (`1.0.x` → `1.1.0`) | New API, backward compatible. |
| MAJOR (`1.x` → `2.0.0`) | A breaking change. The module path gains `/vN`, so every consumer's import lines change with it; a major is taken deliberately, never mechanically. |

A breaking change is anything that can stop a correct consumer compiling or
change what it observes: a removed or renamed exported identifier, a changed
signature, a changed error a caller is documented to match, a refused input
that used to be accepted, or a change to what is written to a LUKS2 header.

### Until `1.0.0`

Backward compatibility is not a goal for any release candidate. API, on-disk
choices and CLI change when the design requires it, with no shims, migration
code or deprecated aliases (owner ruling 2026-10-05: the cleanest API wins, and
stricter than cryptsetup is fine). `CHANGELOG.md` marks such changes with
`BREAKING:` in the heading. The API redesign (DESIGN.md) was such a change and
shipped that way. The pre-1.0 rule expires at the `1.0.0` release.

### From `1.0.0`

- A breaking change is a new major version, and its changelog heading carries
  `BREAKING:` and what a consumer must change.
- A breaking change lands with its consumers: dependent projects are updated,
  built and tested against it, bottom of the dependency graph up, before it
  is released.
- Published tags are never moved or deleted. A bad release is superseded by
  the next version.
- Versions only go up.
- The on-disk format is cryptsetup's. A header go-luks2 writes must open in
  cryptsetup and the reverse; breaking that is a defect, not a breaking
  change — see [cryptsetup-interop](cryptsetup-interop/architecture.md).

**Deprecation.** There is no deprecation window and no deprecation policy:
the engineering standards (`release-versioning.md` §5) state that none exists
for the portfolio, and this project does not invent one. Until `1.0.0` an API
is removed in the release that announces it. From `1.0.0` a removal is a
breaking change and follows the rules above, so it waits for a new major
version. If a window is ever adopted it will be stated here and in the
changelog. The interop contract is in
[cryptsetup-interop](cryptsetup-interop/architecture.md).

## Migration state

This `docs/` tree converted to the feature-folder convention in #277 (H15 of
the API redesign). What moved, and what is still outstanding:

| Absorbed into | From |
|---|---|
| `volumes/` | `ARCHITECTURE.md` (packages/DAG, key custody, keyring, device layer, trust boundaries), `luks/README.md`, `luks/encryption.md`, `cli/{create,open,close,mount,unmount,info,key-input}.md`, and `cli/README.md`'s general command rules and typical session |
| `keyslots/` | `luks/keyslots.md`, `luks/kdf.md`, `cli/keyslots.md` |
| `recovery-keys/` | `cli/recovery.md`, recovery-specific notes from `luks/keyslots.md` |
| `tokens/` | `luks/tokens.md`, `luks/keyprovider.md`, `cli/token.md` |
| `header/` | `luks/header.md`, `cli/header.md` |
| `wipe/` | `cli/wipe.md` |
| `fips/` | `FIPS.md` |
| `cryptsetup-interop/` | `COMPATIBILITY.md`'s interop matrix, metadata-lock table and stricter-than-cryptsetup table |
| here (versioning policy) | `COMPATIBILITY.md`'s versions section |

All of the above legacy files are deleted in the same commits that landed
this index (feature-docs §9).

**The DESIGN.md §G.1 fold is done** (after v1.0.0-rc.2). `TESTING.md`'s coverage,
unit-runtime and integration-container detail is in
[volumes/engineering.md](volumes/engineering.md#test-strategy), which the other
folders' test-strategy sections link to, and `RELEASABILITY.md`'s gate and
waiver rules are the package documentation of `test/internal/labstrings`
(`go doc ./test/internal/labstrings`). Both files are deleted. The
releasability gate does not need a fixed docs path: it scans the whole index.
`CLAUDE.md`/`AGENTS.md` now exist at `cmd/luks2/` and
`test/integration/` (DESIGN.md §G.1, project-scaffold §7), alongside the
root pair. The portfolio view of conversion progress is derived, never
maintained by hand: count `docs/*/architecture.md` per repo (feature-docs
§9).

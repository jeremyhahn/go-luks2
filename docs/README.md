# go-luks2 docs

> **Status: NORMATIVE** · Last verified: 2026-10-12 against base/331 (a9c840c)
> Conflicts with this document are defects. Fix them here first.

Documentation is organized as one feature folder per capability, not as flat
topic files. Each folder holds five files — `architecture.md`,
`engineering.md`, `cli.md`, `api.md`, `user.md` — with its own status banner
and `Last verified:` stamp. **An agent picking up work on a feature reads its
folder before it reads code.**

## Index

| Folder | Covers |
|---|---|
| [volumes](volumes/) | Create, open, mount, close; package layout; the device layer; key custody; the error model; trust boundaries; the project-wide test strategy |
| [keyslots](keyslots/) | Keyslot structure, KDF, cost inheritance, removal |
| [recovery-keys](recovery-keys/) | Generated recovery credentials |
| [tokens](tokens/) | Header token metadata, key providers (FIDO2, helper commands) |
| [header](header/) | On-disk layout, binary header, JSON metadata, untrusted-header bounds |
| [dm-crypt-activation](dm-crypt-activation/) | Turning an unlocked volume key into `/dev/mapper/<name>`; the dm-crypt table; teardown |
| [kernel-keyring](kernel-keyring/) | Handing the volume key to dm-crypt through the kernel keyring; the startup preflight |
| [loop-devices](loop-devices/) | Attaching a regular file as a block device and detaching it |
| [filesystems](filesystems/) | Making, checking, repairing, detecting, mounting and unmounting filesystems |
| [wipe](wipe/) | Crypto-erase and full-device sanitization |
| [fips](fips/) | FIPS 140-3 mode, SHA-1 handling, `MigrateToFIPS` |
| [cryptsetup-interop](cryptsetup-interop/) | Compatibility policy, the two-way interop matrix |

Each folder documents the API as shipped. Two checks in `test/tools/apidump`
hold the exported surface: `make api-diff` (part of `make ci`) checks that
every export of the pre-1.0 `pkg/luks2` (`baseline/luks2.tsv`) went where its
row in `baseline/disposition-luks2.tsv` says, and the unit test
`TestEveryPkgExportIsNamedInAFeatureDoc` fails when an exported identifier of
any package under `pkg/` is named in no feature folder. Neither
checks prose against behaviour; that is what each file's `Last verified:`
stamp records.

The package import graph is data, not prose: `.golangci.yml`'s `depguard`
section has one rule per package, and `pkg/luks2`'s rule also denies
`os/exec`, so the core cannot gain root-only or exec code without a lint
failure. Package-level mutable seams are refused by
`test/makefile/seamvars_test.go`, whose allowlist is empty: `pkg/luks2`'s
seams live on `Volume`'s unexported `volumeSys`.

## Versioning policy

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Tags carry
a `v` (`v1.0.0-rc.4`); the `VERSION` file does not (`1.0.0-rc.4`). A `-rc.N`
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
code or deprecated aliases: the cleanest API wins, and being stricter than
cryptsetup is acceptable. `CHANGELOG.md` marks such changes with `BREAKING:`
in the heading. The pre-1.0 rule expires at the `1.0.0` release.

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

## Conversion state

Every document in this tree is a feature folder, this index or the release
reference [release/public-releasability.md](release/public-releasability.md);
no legacy topic file remains. The test-strategy detail is in
[volumes/engineering.md](volumes/engineering.md#test-strategy), which the
other folders' test-strategy sections link to, and the releasability gate's
rules are the package documentation of `test/internal/labstrings`
(`go doc ./test/internal/labstrings`). The releasability gate scans the whole
tracked tree, so it does not depend on any docs path. How the files that stay
private are excluded from every archive (`.gitattributes` export-ignore,
`.dockerignore`), and what that does not cover, is in
[release/public-releasability.md](release/public-releasability.md).

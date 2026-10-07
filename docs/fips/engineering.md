# FIPS 140-3 — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume` (`pkg/luks2`)

```go
type MigrateParams struct { KeepNonApproved bool; KDF KDFParams }
type Migration struct { Keyslot int; KeyslotAdded bool; MigratedDigests, RemovedKeyslots, RetainedNonApproved []int; Complete bool }
func (v *Volume) MigrateToFIPS(ctx context.Context, pass *enclave.MemoryEnclave, p MigrateParams) (*Migration, error)
type NonApprovedKDF struct { ID int; Type, Hash, Reason string }
func (k NonApprovedKDF) String() string
type FIPSMigrationStage uint8 // StagePreflight, StageVerify, StageWrite, StageRemove, StageVerifyWritten
```

`DefaultKDFType()` applies when `Format`/`AddKeyslot`/`AddRecoveryKey` are
given no KDF type (`DefaultKDFSpec()` is its string form, retained for
callers that name the type by its LUKS2 spelling). `(KDFParams).Validate()`
is the pre-flight check, including FIPS approval → `ErrFIPSNotApproved`.
`MigratedDigests`/`RemovedKeyslots`/`RetainedNonApproved` are `[]int`
(canonical keyslot/digest ids).

`make api-diff` holds this surface to DESIGN.md §B.6: the free-function
`MigrateToFIPS`, `FIPSMigrationOptions`, `FIPSMigrationResult` and
`IsFIPSCompliantKDF` are not exported.

## Invariants

- `fipsMode` (target: `fips.Probe()`) is consulted before any derivation
  that could run Argon2 or SHA-1, not only at the public entry point, so a
  foreign header cannot make a FIPS process run either
  ([architecture.md](architecture.md#the-problem-and-the-shape-chosen)).
- `MigrateToFIPS` removes nothing before its verify step (stage 5 in
  [architecture.md](architecture.md#data-flow-importing-a-volume-migratetofips))
  passes; every intermediate state still opens with the original passphrase.
- SHA-1 is never written by any code path, in or out of FIPS mode
  ([architecture.md](architecture.md#sha-1)).

## Approved KDFs

| KDF type | FIPS-approved | Notes |
|---|---|---|
| `pbkdf2` | true | SHA-256 unless a hash is given |
| `pbkdf2-sha256`, `pbkdf2-sha384` | true | |
| `pbkdf2-sha512` | true | Default in FIPS mode |
| `pbkdf2-sha1` | false | Read from old headers outside FIPS mode, never written |
| `argon2i`, `argon2id` | false | Refused in FIPS mode; `argon2id` is the default otherwise |

`DefaultKDFType()` applies when `Format`, `AddKeyslot`, `ChangeKeyslot` or
`AddRecoveryKey` is given no KDF type. The FIPS default is calibrated to
`PBKDFIterTime` (2000 ms by default) and never below the SHA-512 floor for
that budget (210,000 at 2000 ms). A caller that names no type but sets an
Argon2 cost gets `argon2id`, which FIPS mode refuses.

## Error semantics

| Error | Meaning |
|---|---|
| `ErrFIPSNotApproved` | A derivation would use Argon2 or SHA-1 in FIPS mode |
| `*FIPSImportRequiredError` / `ErrFIPSImportRequired` | Every keyslot that could not be tried was refused only for non-approval; the volume is intact and `MigrateToFIPS` would open it |
| `*FIPSMigrationError` | A migration stage failed; names the stage and the state left behind. Calling `MigrateToFIPS` from a FIPS process, or with a passphrase whose key matches no digest binding every data segment, is reported this way, at the precondition and verify stages |
| `ErrDeviceCacheStale` | The page-cache and `O_DIRECT` reads of the header disagree at the start of a run |
| `ErrUnsupported` | The device stack cannot be read with `O_DIRECT` and is not tmpfs/ramfs |
| `ErrKeyslotAreaOverlap` | A keyslot area is not confined to the keyslots area, clear of the data segment |

When every keyslot that could not be tried was refused only because its KDF,
or the KDF of every digest attesting it, is not approved, unlock returns
`*FIPSImportRequiredError` instead of `ErrKeyslotNotFound`/`ErrInvalidHeader`.
If any keyslot also failed for another reason, that failure is reported
instead. Damage is not reported as a FIPS refusal: the refusal is returned
only when re-screening with approved stand-ins shows the policy is the only
obstacle; a malformed SHA-1 digest is `ErrInvalidHeader`.

### Edge cases

Approved means what strict FIPS mode will run. Under `fips140=only`,
`crypto/pbkdf2` also refuses a salt under 128 bits and an output under
112 bits. A PBKDF2 keyslot or digest below either is treated like Argon2, and
`NonApprovedKDF.Reason` names the parameter.

Argon2 digests from other writers (`time`, `memory`, `cpus` members, bounded
like keyslot KDFs) are evaluated outside FIPS mode and rewritten as PBKDF2 by
the import. In FIPS mode they are refused with `*FIPSImportRequiredError`.

## Persistence

`MigrateToFIPS` writes keyslots and digests using the same schema as any
other keyslot/digest write ([header/architecture.md](../header/architecture.md));
nothing about the on-disk shape is FIPS-specific. The crash-safety properties
(durable write order, torn-primary refusal, cache-staleness check) are listed
in [architecture.md](architecture.md#interrupted-imports).

## Test strategy

CI's `FIPS` job (`.github/workflows/nightly.yml`) sets `GOFIPS140=latest` and
`GODEBUG=fips140=only`, builds `./...`, runs the cross-process import tests
below, and runs `go test ./...`. `fips140=only` is used because `on` still
lets non-approved algorithms run.

`TestMigrateToFIPSEveryCrashStateStillOpens`,
`TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume` and
`TestMigrateToFIPSResumedAfterACrashKeepsAWayIn` cover interruption.
`TestFIPSImportOfACryptsetupArgon2idVolume`,
`TestFIPSImportOfACryptsetupVolumeWithShortSalts` and
`TestFIPSImportOfACryptsetupVolumeWithAnUnboundKey` migrate a cryptsetup
volume in a `fips140=off` child and open it in a `fips140=only` child. On the
kernel, `TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData` checks that
the migrated mapping reads the same plaintext as cryptsetup's — part of
[cryptsetup-interop/engineering.md](../cryptsetup-interop/engineering.md).

## Observability

No logging; every failure above is a typed, returned error.

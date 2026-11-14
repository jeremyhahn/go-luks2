# FIPS 140-3 — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c
> Conflicts with this document are defects. Fix them here first.

## Exported surface

### `*Volume` (`pkg/luks2`)

```go
type MigrateParams struct { KeepNonApproved bool; KDF KDFParams }
type Migration struct { Keyslot int; KeyslotAdded bool; MigratedDigests, RemovedKeyslots, RetainedNonApproved []int; Complete bool }
func (v *Volume) MigrateToFIPS(ctx context.Context, pass enclave.ByteAccess, p MigrateParams) (*Migration, error)
type NonApprovedKDF struct { ID int; Type, Hash, Reason string }
func (k NonApprovedKDF) String() string
type FIPSMigrationStage uint8 // StagePreflight, StageVerify, StageWrite, StageRemove, StageVerifyWritten
func (e *FIPSMigrationError) MigrationStage() FIPSMigrationStage
```

`(*FIPSMigrationError).MigrationStage()` gives the coarse phase in which a
migration stopped, so a caller can switch on it without matching the
`Stage` string. Ten `Stage` strings fold onto five phases:

| `Stage` | `MigrationStage()` |
|---|---|
| `"precondition"`, `"sync"` | `StagePreflight` |
| `"unlock"`, `"plan"`, `"verify"` | `StageVerify` |
| `"reconcile header copies"`, `"add keyslot"`, `"migrate digest"` | `StageWrite` |
| `"remove keyslot"` | `StageRemove` |
| `"final check"` | `StageVerifyWritten` |

`StageVerify` covers the checks that bracket the writes on both sides:
unlocking and planning before them, and the opens that prove the result
after them. A `Stage` that `MigrateToFIPS` never sets, which is possible
only for an error a caller built, maps to `StagePreflight`, which implies
nothing was written.

`DefaultKDFType()` applies when `Format`/`AddKeyslot`/`AddRecoveryKey` are
given no KDF type; it returns `KDFPBKDF2` in FIPS mode and `KDFArgon2id`
otherwise, with the hash in `KDFParams.Hash`. `DefaultKDFSpec()` is a different
thing: it returns the package's internal combined spelling (`pbkdf2-sha512` or
`argon2id`), not a string form of the public type. `ChangeKeyslot` with a zero
`KDF` does not apply the default; it keeps the slot's existing KDF.
`(KDFParams).Validate()` is the pre-flight check, including FIPS approval →
`ErrFIPSNotApproved`; it accepts only the three public types. It judges by
the process's mode; the `Volume` methods that take a `KDFParams` run the same
check against the volume's policy ([architecture.md](architecture.md#component-boundaries)).
`MigratedDigests`/`RemovedKeyslots`/`RetainedNonApproved` are `[]int`
(canonical keyslot/digest ids).

`make api-diff` holds this surface to the per-identifier dispositions in
`test/tools/apidump/baseline/disposition-luks2.tsv`: it fails if `pkg/luks2`
exports a free function `MigrateToFIPS`, or `FIPSMigrationOptions`,
`FIPSMigrationResult` or `IsFIPSCompliantKDF`. The import is the
`(*Volume).MigrateToFIPS` method with `MigrateParams` and `Migration`, and
the pre-flight check is `(KDFParams).Validate()`.

## Invariants

- `fipsMode` (target: `fips.Probe()`) is consulted before any derivation
  that could run Argon2 or SHA-1, not only at the public entry point, so a
  foreign header cannot make a FIPS process run either
  ([architecture.md](architecture.md#the-problem-and-the-shape-chosen)).
- `MigrateToFIPS` refuses a `MigrateParams.KDF` naming Argon2 (`KDFArgon2id`,
  `KDFArgon2i`, or a non-zero `Time`, `MemoryKiB` or `Parallel`) before
  anything is written, as a `*FIPSMigrationError` at stage `precondition`
  wrapping `ErrFIPSNotApproved` and naming the field; it never drops it
  silently.
- `MigrateToFIPS` removes nothing before its verify step (stage 5 in
  [architecture.md](architecture.md#data-flow-importing-a-volume-migratetofips))
  passes; every intermediate state still opens with the original passphrase.
- SHA-1 is never written by any code path, in or out of FIPS mode
  ([architecture.md](architecture.md#sha-1)). In FIPS mode the refusal
  matches `ErrFIPSNotApproved`, from `KDFParams.Validate` and from every write
  path; outside it, `ErrInvalidArgument`.

## Approved KDFs

| `KDFParams.Type` and `Hash` | FIPS-approved | Notes |
|---|---|---|
| `KDFPBKDF2` with `SHA256`, `SHA384` or `SHA512` | true | SHA-256 when `Hash` is zero; SHA-512 when the type was defaulted in FIPS mode |
| `KDFPBKDF2` with SHA-1 | false | Never written; `Validate` refuses it in FIPS mode with `ErrFIPSNotApproved`; read from old headers outside FIPS mode only |
| `KDFArgon2i`, `KDFArgon2id` | false | Refused in FIPS mode; `KDFArgon2id` is the default otherwise |

The combined `pbkdf2-sha*` spellings are internal aliases, not public types.

`DefaultKDFType()` applies when `Format`, `AddKeyslot` or `AddRecoveryKey` is
given no KDF type; `ChangeKeyslot` with a zero `KDF` keeps the slot's existing
KDF instead. The FIPS default is calibrated to
`PBKDFIterTime` (2000 ms by default) and never below the SHA-512 floor for
that budget (210,000 at 2000 ms). A caller that names no type but sets an
Argon2 cost gets `argon2id`, which FIPS mode refuses.

## Error semantics

| Error | Meaning |
|---|---|
| `ErrFIPSNotApproved` | A derivation would use Argon2 or SHA-1 in FIPS mode; `KDFParams.Validate` or a write path was given Argon2 or a SHA-1 PBKDF2 in FIPS mode |
| `*FIPSImportRequiredError` / `ErrFIPSImportRequired` | Every keyslot that could not be tried was refused only for non-approval; the volume is intact and `MigrateToFIPS` would open it. `FIPSImportRequiredError.Unwrap` reports both `ErrFIPSImportRequired` and `ErrFIPSNotApproved` |
| `*FIPSMigrationError` | A migration stage failed; names the stage and the state left behind. Calling `MigrateToFIPS` from a FIPS process, or with a passphrase whose key matches no digest binding every data segment, is reported this way, at the precondition and verify stages. `FIPSMigrationError.Unwrap` reports `ErrFIPSMigration` for every stage, and the stage's own cause |
| `ErrDeviceCacheStale` | The page-cache and `O_DIRECT` reads of the header disagree at the start of a run |
| `ErrUnsupported` | The device stack cannot be read with `O_DIRECT` and is not tmpfs/ramfs |
| `ErrKeyslotAreaOverlap` | A keyslot area is not confined to the keyslots area, clear of the data segment |

When every keyslot that could not be tried was refused only because its KDF,
or the KDF of every digest attesting it, is not approved, unlock returns
`*FIPSImportRequiredError` instead of `ErrKeyslotNotFound`/`ErrInvalidHeader`.
If any keyslot also failed for another reason, that failure is reported
instead. Damage is not reported as a FIPS refusal: the refusal is returned
only when re-screening with approved stand-ins shows the policy is the only
obstacle; a malformed SHA-1 digest is `ErrInvalidHeader`, and so is any
keyslot one of whose attesting digests is malformed, even beside a short-salt
digest strict mode refuses. A malformed digest no tried keyslot consults --
one covering no keyslot, or binding no data segment -- is `ErrInvalidHeader`
too. `MigrateToFIPS` refuses such a volume at the plan stage with the same
`ErrInvalidHeader`, writing nothing.

### Edge cases

Approved means what strict FIPS mode will run. Under `fips140=only`,
`crypto/pbkdf2` also refuses a salt under 128 bits and an output under
112 bits. A PBKDF2 keyslot or digest below either is treated like Argon2, and
`NonApprovedKDF.Reason` names the parameter. Such a keyslot or digest passes
the pre-derivation screen, whose names are approved, and is refused at
derivation; unlock still reports it as `*FIPSImportRequiredError`, not as
`ErrInvalidHeader`.

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

CI's `FIPS` job (`.github/workflows/ci.yml`, full tier: every push to `main`,
every `workflow_dispatch` and every pull request labelled `ci:full`; gated by
`CI Gate`) sets `GOFIPS140=latest` and
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

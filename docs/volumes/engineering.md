# Volumes — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
> Conflicts with this document are defects. Fix them here first.

The implementation contract for the volume lifecycle: create, unlock, mount,
close. Keyslot/recovery-key/token/header/wipe/FIPS contracts live in their own
folders and are linked from here, not repeated.

## Exported surface

### `*Volume` (`pkg/luks2`)

```go
type Volume struct{ /* unexported */ }
type Option func(*options)
func WithReadOnly() Option
func WithLockWait(d time.Duration) Option
func Open(ctx context.Context, path string, opts ...Option) (*Volume, error)
func (v *Volume) Path() string
func (v *Volume) Close() error

func (v *Volume) Format(ctx context.Context, pass *enclave.MemoryEnclave, p FormatParams) error
func (v *Volume) Unlock(ctx context.Context, pass *enclave.MemoryEnclave) (*Key, error)
func (v *Volume) UnlockKeyslot(ctx context.Context, slot int, pass *enclave.MemoryEnclave) (*Key, error)
func (v *Volume) UnlockWithProvider(ctx context.Context, p KeyProvider) (*Key, error)
func (v *Volume) UnlockWithVolumeKey(ctx context.Context, vk *enclave.MemoryEnclave) (*Key, error)
func (v *Volume) Target(ctx context.Context, key *Key) (*Target, error)
func (v *Volume) Erase(ctx context.Context) error
```

`(*Volume).Header`/`SecondaryHeader`/`RestorePrimaryHeader`/
`ReplacePrimaryHeader` are [header](../header/engineering.md)'s contract;
`AddKeyslot`/`ChangeKeyslot`/`RemoveKeyslot` are
[keyslots](../keyslots/engineering.md)'s; `AddToken`/`SetToken`/`RemoveToken`/
`Enroll` are [tokens](../tokens/engineering.md)'s; `AddRecoveryKey` is
[recovery-keys](../recovery-keys/engineering.md)'s; `MigrateToFIPS` is
[fips](../fips/engineering.md)'s.

### Activation, loop, filesystems (separate packages)

```go
func dmcrypt.Activate(ctx context.Context, v *luks2.Volume, key *luks2.Key, name string) (*Mapping, error)
func dmcrypt.Deactivate(ctx context.Context, name string) error
func dmcrypt.Lookup(ctx context.Context, name string) (*Mapping, error)
func dmcrypt.CheckKeyring(ctx context.Context) error

func loop.Attach(ctx context.Context, file string) (*Device, error)
func loop.Find(ctx context.Context, file string) (*Device, error)
func loop.Lookup(ctx context.Context, path string) (*Device, error)
func (d *loop.Device) Detach(ctx context.Context) (loop.DetachState, error)

func filesystem.Make(ctx context.Context, device string, t Type, p MakeParams) error
func filesystem.Check(ctx, device, t) (CheckResult, error)
func filesystem.Repair(ctx, device, t) (CheckResult, error)
func filesystem.Mount(ctx context.Context, p MountParams) error
func filesystem.Unmount(ctx context.Context, target string, flags UnmountFlags) error
func filesystem.DeviceMounted(ctx context.Context, major, minor uint32) (bool, error)
```

Full signatures, including every params struct field: DESIGN.md §B.2–§B.5,
cross-checked against `go doc` for each package.

`make api-diff` (`test/tools/apidump` against
`baseline/disposition-luks2.tsv`) checks that the exported surface of
`pkg/luks2` is exactly DESIGN.md §B.6's. The few exports retained on purpose
(`DefaultKDFSpec`, `LegacyToken`, `dmcrypt.ErrIntegerOverflow`,
`dmcrypt.ErrDeviceChanged`) are recorded there.

$1

- **Lock order is a type property.** `internal/device` implements it (H6,
  DECISIONS.md): `Pinned` is read-only; `Pinned.Lock(ctx, mode)` takes the
  node flock then the cryptsetup lock and returns `*Locked`;
  `Locked.Claim(ctx, ...)` returns `*Claimed` by reopening the locked
  descriptor's own `/proc/self/fd/N` entry, so the claim targets the locked
  inode by construction. Every `*Volume` write method goes through it
  (`v.lockFor(ctx, device.LockExclusive)`, then `locked.Claim` where an
  O_EXCL write is needed — confirmed in `volume.go`'s `lockFor` and
  `format.go`'s `Format`).
- **No lock is held between calls** on the `*Volume` handle: each method
  takes its lock, does its I/O and releases it before returning.
- **Concurrency.** `Volume` is safe for concurrent use through an internal
  `sync.RWMutex` (`v.mu`; shared for reads, exclusive for writes), with
  `KeyProvider.Passphrase` called before the mutex or any file lock is taken
  (go-style's rule on locks around external code).
- **The volume key is a capability, not a byte slice.** `*luks2.Key` (alias
  of `volkey.Key`) is obtained only by unlocking (`Unlock`, `UnlockKeyslot`,
  `UnlockWithProvider`, `UnlockWithVolumeKey`), is bound to the volume, and
  records the keyslot it came from (`-1` for a supplied key). Mutations that
  need it (`AddKeyslot`, `ChangeKeyslot`, `AddRecoveryKey`, `Enroll`)
  re-verify it against the digest under the exclusive lock, because the
  header may have changed since `Unlock`. Its bytes are not exported:
  `volkey.Borrow` is reachable only inside the module, so `dmcrypt` can hand
  the key to the keyring and no consumer can extract it.

## Error semantics

One struct, `errs.Error{Op, Path, Kind, Detail, Err}` (internal/errs),
aliased as `luks2.Error`. `Kind` is never nil (a public `Err*` sentinel, or
`context.Canceled`/`context.DeadlineExceeded`) — enforced for every
`errs.Error` literal in `pkg/` and `internal/` by a static go/ast check
(`test/makefile`'s `TestKindIsNeverNil`), with no allowlist. `Detail` carries
the human-readable reason.

`ErrInvalidArgument`, `ErrInvalidCredential` and `ErrIO` are module-wide
kinds with no single owner below the public API (DESIGN.md §C.2 rule 6,
H3c's rule generalised): defined once in `internal/errs` and re-exported by
value from `luks2`. The shared device kinds (`ErrDeviceNotFound`,
`ErrPermissionDenied`, `ErrDeviceInUse`, `ErrDeviceChanged`,
`ErrDeviceCacheStale`, `ErrLockContended`, `ErrMetadataLockUnavailable`) are
defined once in `internal/device` the same way.

A few struct types still carry data a caller needs programmatically rather
than folding into `Kind` + `Detail` alone: `LockTimeoutError{Path, Waited,
Attempts}` (device.LockTimeoutError, aliased), `KDFCostError{Param, Value,
Min, Max}` (unifies what used to be two types, `Argon2CostError` and
`PBKDFIterationsError`; `Is` reports `ErrInvalidArgument`),
`KDFCalibrationError`, `FIPSImportRequiredError` and `FIPSMigrationError`.
`InvalidKeyslotError` and `UnlockError` are gone: a keyslot or unlock refusal
is a plain `*Error` now, with `ErrKeyslotNotFound` (or whatever the refusal
classifies as) in `Kind` and the keyslot id or step folded into `Detail`.

No "wrong passphrase" error exists: with an unauthenticated keyslot cipher a
wrong passphrase and damaged key material look the same, so both match
`ErrWrongKey`.

Sentinels follow DESIGN.md §C.3's table: the narrower refusals (a bad size,
a too-short passphrase, an unsupported cipher) are `ErrInvalidArgument`,
`ErrInvalidCredential` or `ErrUnsupported` with the detail in `Detail`;
`make api-diff` checks the exported set.

## Configuration

Zero value of a params struct means library policy (target shape, DESIGN.md
§B.1):

| `FormatParams` field | Zero means |
|---|---|
| `Cipher` | `DefaultCipher` (`aes-xts-plain64`) |
| `KeySize` | `DefaultKeySize` (512 bits) |
| `Hash` | `DefaultHash` (SHA-256) |
| `SectorSize` | `DefaultSectorSize` (512) |
| `MetadataSize` | 16 KiB header area |
| `KDF` | `DefaultKDFType()`: PBKDF2-SHA512 in FIPS mode, Argon2id otherwise |

`filesystem.MountParams` carries source, target, type,
mount flags and data string; there is no default mount beyond what the kernel
itself defaults.

## Persistence

The on-disk schema (binary header, JSON metadata, keyslots area layout) is
[header](../header/engineering.md)'s contract, not repeated here. What belongs
to the volume lifecycle specifically: `Format` writes both header copies and
fills the rest of the 16 MiB header region with random bytes, so the
allocation (not the content) of a new container is fixed at format time; the
data area is left as it was. A header-only wipe (crypto-erase) is
[wipe](../wipe/engineering.md)'s contract.

## Test strategy

**Unit** (`make test-unit`): the rootless core (`pkg/luks2`) makes format,
unlock, mount and close real against temp files at minimum legal KDF cost; no
device-mapper or loop-device mock. Root-only paths (device-mapper, loop,
mount) are covered by the unit tier's fakes plus the combined tier below.
`pkg/luks2` is held to a 90% floor in the combined tier (`coverage-floors.txt`);
race-detected unit runtime has a 240 s budget on the CI runner
(`UNIT_TEST_TARGET`) and a 10-minute hard ceiling.

**Integration** (`make integration-test`, build tag `integration`, run in the
devcontainer): the full create → open → mount → unmount → close → detach
cycle against real loop devices, device-mapper and the kernel keyring, plus
the cryptsetup two-way compatibility matrix
([cryptsetup-interop](../cryptsetup-interop/engineering.md)).

**Fault injection**: the seam-var enforcement test (no package-level mutable
`var` of func/interface type outside `errors.go`, DESIGN.md §E) is on and
enforcing for every package, `pkg/luks2` included, with an EMPTY allowlist
(`test/makefile/seamvars_test.go`, H13/H13d, DECISIONS.md). The seams live in
the unexported `volumeSys` each `*Volume` carries, so a test builds a `Volume`
with its own `volumeSys` and nothing is shared through package state. A
separate test (`TestSeamAllowlistNamesOnlyRealSeams`) keeps the allowlist
honest if one is ever added.

## Observability

No logging. Every failure is a typed, returned `*errs.Error` (or one of the
few struct types above). There are no metric names or audit records to
document: this is a Layer 0 library with no process of its own (see
[api.md](api.md)).

## Key custody detail

This section mirrors [`internal/secret`](../../internal/secret/doc.go)'s
package documentation, which is the canonical copy — if the two disagree, that
file is right and this one is the defect. Design rationale and the trust
boundary are in [architecture.md](architecture.md#key-custody).

The ownership model: key material is owned by an `*enclave.MemoryEnclave` for
its whole lifetime and only ever borrowed, through the narrowest `WithBytes`
window the consuming call permits. Nothing in this module returns raw key
bytes across a function boundary where an enclave handle could be returned
instead. Deliberately not enclaved: encrypted keyslot material (already on
disk in that form), and KDF salts and the stored digest (cleartext header
fields).

Six residual exposures are documented, not five and not seven — `doc.go`'s own
preamble treats an undercount as worse than the current state:

1. **Credentials that arrive as plain bytes.** The library API takes
   `*enclave.MemoryEnclave` (`Format`, `Unlock`, `UnlockKeyslot`, `AddKeyslot`,
   `ChangeKeyslot`, `ParseRecoveryKey`). What is left is the CLI's terminal
   prompt (`term.ReadPassword` returns a plain `[]byte`; `--key-file` is read
   straight into locked memory), `keyprovider.WithStdin` (non-secret helper
   input only) and the `[]byte` credential id `keyprovider.NewFIDO2Credential`
   returns (not secret).
2. **Validated-module KDF input — on two paths, the input is the master
   key.** `crypto/pbkdf2.Key` takes its password as a `string`, so
   `derivePBKDF2` must convert, for every enclave-held credential it borrows;
   inside the Go Cryptographic Module a second copy is made for the HMAC
   state. `x/crypto/argon2` copies its input into BLAKE2b state that is never
   wiped. This is a **ruled** position (owner ruling 2026-08-25: no hand-rolled
   cryptography, this exact case named by name), not an oversight — see
   `doc.go` for the full ruling text.
3. **KDF output.** `crypto/pbkdf2.Key` and `argon2.IDKey` return their result
   on the ordinary heap; the derivation moves it into an enclave immediately,
   so the window is the return statement plus one copy.
4. **Expanded cipher keys.** `xts.NewCipher`/`crypto/aes` hold the AES key
   schedule on the ordinary heap for the cipher's lifetime; neither offers a
   way to place it elsewhere or wipe it. The keyslot wrap uses
   `golang.org/x/crypto/xts`, which is outside the Go Cryptographic Module.
5. **The kernel keyring.** The key spends the duration of one activation ioctl
   in the kernel's session keyring, as a write-only `logon` key, then is
   revoked, unlinked and verified gone. Kernel keyrings are not namespaced by
   container (see [architecture.md](architecture.md#kernel-keyring)).
6. **Hash state.** `sha256.Sum256` leaves the area key (ESSIV salt) or the
   recovery credential (its printed digest) in the hash's internal state,
   which cannot be wiped.

A seventh exposure found anywhere in this codebase belongs in `doc.go`'s list
on the same commit that finds it, not here first.

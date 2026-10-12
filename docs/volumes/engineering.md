# Volumes — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8;
> the container flag table was checked against `test/tools/docker-run`'s
> `privileges`, and its measurements were not re-run.
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

### Passphrase policy (`pkg/luks2`)

```go
const (
	MinPassphraseLength = 8
	MaxPassphraseLength = 512
)
func ValidatePassphrase(pass *enclave.MemoryEnclave) error
```

A credential this package enrolls must be `MinPassphraseLength` to
`MaxPassphraseLength` bytes, inclusive. That covers the passphrase given to
`Format`, the new passphrase of `AddKeyslot` and `ChangeKeyslot`, and the
credential a `KeyProvider` returns to `Enroll`, and each of them runs the
check itself. `ValidatePassphrase` exports the same check so that a caller
can refuse a passphrase before it asks for anything else. Nothing in the
module calls it. It borrows `pass` for the length check alone and leaves it
usable. It returns `nil` for a passphrase within the policy, and reports
every failure as an `*Error` whose `Op` is `ValidatePassphrase`: a
passphrase shorter than `MinPassphraseLength` (8 bytes) or longer than
`MaxPassphraseLength` (512 bytes) has kind `ErrInvalidCredential`, and a
destroyed enclave has kind `ErrProtectedMemory`; `errors.Is` matches either
kind.

A credential presented to open an existing keyslot is not held to this
policy: anything from 1 byte to 8 MiB is accepted, so a short passphrase or a
key file that cryptsetup enrolled still opens. `AddRecoveryKey` also uses
`MaxPassphraseLength`, refusing a recovery-key length whose rendering would
be longer than that.

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
func (d *loop.Device) BackingFile() string

func filesystem.Make(ctx context.Context, device string, t Type, p MakeParams) error
func filesystem.Check(ctx, device, t) (CheckResult, error)
func filesystem.Repair(ctx, device, t) (CheckResult, error)
func filesystem.Mount(ctx context.Context, p MountParams) error
func filesystem.Unmount(ctx context.Context, target string, flags UnmountFlags) error
func filesystem.IsMounted(ctx context.Context, target string) (bool, error)
func filesystem.DeviceMounted(ctx context.Context, major, minor uint32) (bool, error)
func filesystem.Inspect(ctx context.Context, device string) (*Info, error)
func filesystem.Detect(ctx context.Context, device string) (Type, error)
func filesystem.Supported() []Type
```

`loop.Device.BackingFile` is the absolute path of the file the device is
attached to, or `""` for a device from `loop.Lookup` that is attached to
nothing. `Detach` returns `loop.Released` once the release is observed, or
`loop.Deferred` when the kernel accepted the request but something (a mount, a
dm-crypt mapping) still holds the device: that is a success, as it is for
`losetup -d`, and the device is released when its last user goes away. Its
sentinels:

| Sentinel | Meaning |
|---|---|
| `loop.ErrNotFound` | `Find`: no loop device is attached to the file |
| `loop.ErrDetachIncomplete` | The detach was accepted but the release was not observed before the wait expired: something else still holds the device |
| `loop.ErrNodeAbsent` | The kernel allocated a loop device but its `/dev` node did not appear in time. The allocation succeeded; this is not "no loop devices available" |
| `loop.ErrDeviceReassigned` | `Detach` refused: the device is now backed by a different file |

Full signatures, including every params struct field, are the packages'
own: `go doc` on `pkg/luks2`, `pkg/keyprovider`, `pkg/loop` and
`pkg/filesystem`. `pkg/dmcrypt` is specified in
[dm-crypt-activation/engineering.md](../dm-crypt-activation/engineering.md),
`pkg/loop` in [loop-devices/engineering.md](../loop-devices/engineering.md),
and `pkg/filesystem` in [filesystems/engineering.md](../filesystems/engineering.md#exported-surface).

`make api-diff` (`test/tools/apidump` against
`baseline/disposition-luks2.tsv`) checks that every export recorded in
`baseline/luks2.tsv`, the earlier `pkg/luks2` surface, is where its disposition row
says: `KEEP` rows still exported, `RENAME`/`MOVE`/`UNEXPORT`/`DELETE` rows
gone under the old name. It does not see exports added since, such as
`DefaultKDFSpec` and `LegacyToken`.

Those are checked by a second gate, `TestEveryPkgExportIsNamedInAFeatureDoc`
in `test/tools/apidump` (`apidump documented`), which the unit tests run on
every push. Every exported constant, variable, function, type and method of
every package under `pkg/` must be named in a feature doc: a `*.md` in a
`docs/<feature>/` directory that has an `api.md`; a directory without one does not count.
Only code counts, meaning inline code spans and fenced blocks, never prose,
and only whole identifiers: `OpenVolume` does not name `Open`. A top-level
identifier is covered by its own name. A method is covered by `Type.Method`,
or by `Method` in a doc whose code also names `Type`. Struct fields and
interface methods are not checked on their own. An export that no doc should
name is listed, with its reason, in `test/tools/apidump/doc-exceptions.tsv`.
The gate also fails on an exception whose export is gone or that a doc now
names.

## Invariants

- **Lock order is a type property.** `internal/device/lock.go` implements
  it: `Pinned` is the opened descriptor; `Pinned.Lock(ctx, mode, ...)` takes
  the node flock then the cryptsetup lock and returns `*Locked`;
  `Locked.Claim(ctx, ...)` returns `*Claimed` by reopening the locked
  descriptor's own `/proc/self/fd/N` entry, so the claim targets the locked
  inode by construction. A claim is reachable only from a `*Locked`, so it
  cannot precede the lock. Every `*Volume` write method goes through it
  (`v.lockFor(ctx, device.LockExclusive)`, then `locked.Claim` where an
  O_EXCL write is needed: `volume.go`'s `lockFor` and `format.go`'s
  `Format`).
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
- **`ctx` comes first.** Every exported function that does I/O on a
  device, takes a file lock, runs a KDF or runs an external program takes
  `ctx context.Context` as its first parameter. Functions that work only on
  in-memory values do not (`Path`, `NewRecoveryKey`, `ParseRecoveryKey`,
  `ValidatePassphrase`, `FormatParams.Validate`, `KDFParams.Validate`,
  `filesystem.Supported`, the `Header` accessors), and two methods keep a
  standard-library interface's signature: `Volume.Close` (`io.Closer`) and
  `RecoveryKey.WriteTo` (`io.WriterTo`, onto the caller's writer).
- **Waits run on an injected clock.** Lock polling, retry backoff and a
  helper's exit grace period wait on a timer from an `internal/clock.Clock`; `time.Sleep` is refused by
  `forbidigo`. A caller's deadline arrives only through `ctx.Done()`, never
  by reading `ctx.Deadline()`, so a test drives every wait with
  `clock.Fake` and stays deterministic.

## Cancellation

Every method that does I/O, takes a lock or runs a KDF takes a `ctx`, and
observes it only where stopping leaves the device consistent:

| Blocking point | How `ctx` is observed |
|---|---|
| Node flock and cryptsetup lock | Polled with backoff on the clock (`internal/device/lock.go`, `cryptsetuplock.go`). The budget is `WithLockWait` (default `DefaultLockWait`); running out is a `*LockTimeoutError`, a cancellation is an `*Error` whose `Kind` is `ctx.Err()` |
| KDF (PBKDF2, Argon2) and PBKDF2 calibration | Not interruptible. `ctx` is checked before each derivation and each calibration probe; a derivation that finishes after a cancellation has its output destroyed and the cancellation is returned (`internal/kdf/kdf.go`, `calibration.go`) |
| Keyslot, token, header and FIPS-migration writes | Checked only before each write step: the keyslot-area write, the header write, the keyslot-area wipe (`volumeSys.keyslotWriteStep`, `pkg/luks2/keyslotdevice.go`). Once `AddKeyslot` or `ChangeKeyslot` has written its keyslot area, the rest of the transaction runs under `context.WithoutCancel` to its next consistent state, so no area holding a wrapped volume key is left unnamed by the header (`pkg/luks2/keyslot.go`) |
| Rollback of a written keyslot | Always under `context.WithoutCancel`: a keyslot that was written and could not be proved to open is taken back out whether or not the caller is still waiting |
| Header-copy repair on read | One write step, never cancelled (`repairHeaderCopies`) |
| `Format` random fill, header wipe | Checked per 64 KiB chunk; a cancelled fill names the bytes written in `Detail` (`writeRandom`, `zeroRange`) |

## Error semantics

One struct, `errs.Error{Op, Path, Kind, Detail, Err}` (internal/errs),
aliased as `luks2.Error`. `Kind` is never nil (a public `Err*` sentinel, or
`context.Canceled`/`context.DeadlineExceeded`) — enforced for every
`errs.Error` literal in `pkg/` and `internal/` by a static go/ast check
(`test/makefile`'s `TestKindIsNeverNil`), with no allowlist. `Detail` carries
the human-readable reason.

`ErrInvalidArgument`, `ErrInvalidCredential` and `ErrIO` are module-wide
kinds with no single owner below the public API: defined once in
`internal/errs` and re-exported by value from `luks2` (`pkg/luks2/errors.go`,
`ErrInvalidArgument = errs.ErrInvalidArgument`). The shared device kinds (`ErrDeviceNotFound`,
`ErrPermissionDenied`, `ErrDeviceInUse`, `ErrDeviceChanged`,
`ErrDeviceCacheStale`, `ErrLockContended`, `ErrMetadataLockUnavailable`) are
defined once in `internal/device` the same way, and `pkg/wipe` re-exports
the same values (`pkg/wipe/errors.go`). Errors are typed only: `forbidigo` in
`.golangci.yml` refuses `fmt.Errorf` everywhere but `_test.go` files and
`test/`, and `errors.New` everywhere but a package's `errors.go`, where its
sentinels are declared.

A package's internals return an `*errs.Error` with `Kind` set and `Op`
empty. Its exported entry points pass the result through `errs.At` on the
way out, which fills the package prefix, `Op` and `Path` only where they
are still empty and returns any other error unchanged, so an error that
crosses two boundaries keeps the inner one's `Op` and is never wrapped a
second time. `Error()` prints `<pkg>: <Op> <Path>: <kind>[: <Detail>][: <Err>]`
and names the package once, dropping the sentinel's own prefix
(`internal/errs`, `(*Error).Error`); an `*Error` that never passed through
`errs.At` (`RecoveryKey.WriteTo`'s, for one) prints only
`<kind>[: <Detail>][: <Err>]`. A cancelled or expired context is reported
with `Kind` set to `ctx.Err()` (`errs.KindOf` carries it through a wrapper),
so `errors.Is(err, context.DeadlineExceeded)` holds.

A few struct types still carry data a caller needs programmatically rather
than folding into `Kind` + `Detail` alone: `LockTimeoutError{Path, Waited,
Attempts}` (device.LockTimeoutError, aliased), `KDFCostError{Param, Value,
Min, Max}` (one type for both KDFs' cost bounds; `Is` reports
`ErrInvalidArgument`), `KDFCalibrationError`, `FIPSImportRequiredError` and
`FIPSMigrationError`. A keyslot or unlock refusal has no type of its own: it
is a plain `*Error`, with `ErrKeyslotNotFound` (or whatever the refusal
classifies as) in `Kind` and the keyslot id or step folded into `Detail`.

Two sentinels belong to the `*Volume` handle itself. Each reaches the
caller as an `*Error` whose `Kind` is the sentinel and whose `Op` is the
method that refused, and neither touches the device:

| Sentinel | Returned when |
|---|---|
| `ErrClosed` | Any method except `Path` and `Close` is called after `Close`. `Close` itself is idempotent and returns `nil` the second time |
| `ErrReadOnly` | A method that writes (`Format`, `Erase`, `AddKeyslot`, `ChangeKeyslot`, `RemoveKeyslot`, `AddToken`, `SetToken`, `RemoveToken`, `Enroll`, `AddRecoveryKey`, `RestorePrimaryHeader`, `ReplacePrimaryHeader`, `MigrateToFIPS`) is called on a `Volume` opened with `WithReadOnly`. A closed handle is checked first, so it reports `ErrClosed` |

No "wrong passphrase" error exists: with an unauthenticated keyslot cipher a
wrong passphrase and damaged key material look the same, so both match
`ErrWrongKey`.

A sentinel exists only where a caller can act on it differently (a remedy, a
retry, an exit code, a prompt). The narrower refusals (a bad size, a
too-short passphrase, an unsupported cipher) are `ErrInvalidArgument`,
`ErrInvalidCredential` or `ErrUnsupported` with the detail in `Detail`
(recorded beside the sentinels in `pkg/luks2/errors.go`); `make api-diff`
checks the exported set.

## Configuration

Operations take their required operands positionally plus one params
struct, and the zero value of a params struct means library policy
(`FormatParams`, `KDFParams`, `KeyslotParams`, `MigrateParams`,
`filesystem.MakeParams`, `filesystem.MountParams`, `wipe.Params`). No exported
function or method takes a boolean argument. Constructors take functional options instead
(`Open` with `WithReadOnly` and `WithLockWait`).

| `FormatParams` field | Zero means |
|---|---|
| `Cipher` | `DefaultCipher` (`aes-xts-plain64`) |
| `KeySize` | `DefaultKeySize` (512 bits) |
| `Hash` | `DefaultHash` (SHA-256) |
| `SectorSize` | `DefaultSectorSize` (512) |
| `MetadataSize` | 16 KiB header area |
| `KDF` | `DefaultKDFType()`: PBKDF2-SHA512 in FIPS mode, Argon2id otherwise |

`filesystem.MountParams` carries source, target, type,
mount flags and data string. An empty type is detected with `blkid`;
otherwise there is no default mount beyond what the kernel itself defaults.

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
unlock and close real against temp files at minimum legal KDF cost; no
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
`var` of func/interface type outside `errors.go`) is on and enforcing for
every package under `pkg/` and `internal/`, `pkg/luks2` included, with an
EMPTY allowlist (`test/makefile/seamvars_test.go`). The seams live in
the unexported `volumeSys` each `*Volume` carries, so a test builds a `Volume`
with its own `volumeSys` and nothing is shared through package state. A
separate test (`TestSeamAllowlistNamesOnlyRealSeams`) keeps the allowlist
honest if one is ever added.

Integration tests live under `test/integration/<package>/`, with one
exception: four white-box files stay in `pkg/luks2`
(`canonicalconformance_integration_test.go`,
`lockcompat_integration_test.go`, `lockwait_integration_test.go` and
`pinnedpaths_integration_test.go`). Each overrides a `volumeSys` field that
no exported API may carry: `cryptoRand`, `newUUID` and `digestIterationsFor`
for byte-for-byte conformance against a cryptsetup-written image,
`calibratedCountFloor` for a cheap KDF cost in a real-cryptsetup lock test,
`lockHeld` to act while a lock is being waited for, and the open seam that
retargets a symlink the instant it is first opened
(`relinkAfterFirstOpen`). They keep the `integration` build
tag, so they run in the container with the rest of the suite. A test
qualifies for the exception only if its hook is a correctness- or
security-relevant seam of this package that no exported API could carry
without handing it to every caller.

The rest of this section is the project-wide test infrastructure, kept here
because `volumes/` owns the device layer the integration tier runs against.
It is the only copy: the other feature folders' test-strategy sections link
here rather than restate it.

```bash
make test-unit          # unit tests, -race, per-package coverage profiles
make test-unit-norace   # the same legs and profiles without -race (CI's PR tier)
make coverage-gate      # refuse unit coverage below any package's floor
make ci                 # everything CI's fast tier runs, including the above
make integration-test   # integration suite in a scoped container (Docker)
make ci-full            # ci, then the container and the combined coverage gate
```

Unit tests need no root, devices or network. The integration suite needs a real
kernel (loop devices, device-mapper, the kernel keyring, mounts), so it runs in
a container launched by `test/tools/docker-run`.

### Coverage

Every package is held to 90%, per package and exactly: 89.99% fails, and an
aggregate above 90% does not excuse a package below it. Floors are in
`coverage-floors.txt`; the gate is `test/tools/covergate`.

| Tier | Measured by | Gated in |
|---|---|---|
| `unit` | `make test-unit-norace` in CI (`make test-unit`, the same legs with `-race`, locally): every package from `go list ./...`, default tags | CI's `Unit Tests` job (PR tier) and `make ci` |
| `combined` | `make coverage-combined` inside the container: unit plus integration, with `-coverpkg` over the packages `coverage-floors.txt` lists as `combined` | CI's `Integration Tests` job (full tier) and `make ci-full` |

`pkg/luks2`, `pkg/dmcrypt`, `pkg/filesystem`, `pkg/loop`, `internal/dm`,
`internal/keyring` and `test/internal/harness` are held to 90% in the combined
tier, because part of each only runs against a real kernel. Each also has a unit floor at its measured level. Every other package
is held to 90% in the unit tier. The gate
also fails on a missing or unreadable profile, a package with no floor, a floor
for a package that no longer exists, and a package held to 90% in no tier.

### Unit runtime and race coverage

`go test -race ./pkg/luks2` has a budget of 240 s on the CI runner
(`UNIT_TEST_TARGET`, printed against the measured time) and a hard ceiling of
10 minutes (`UNIT_TEST_TIMEOUT`). Both are Makefile variables CI reads through
`make test-unit`, in the full tier's `Race` job.

The race detector covers the default-tag build of every package, in the full
tier only: push to `main`, `workflow_dispatch`, and a pull request labelled
`ci:full`. The label is read when the pull request is opened, pushed to or
reopened: adding it takes effect on the next push, or on closing and reopening
the pull request, because CI does not run on label events. An ordinary pull
request runs the same unit legs without `-race`. The
`integration`-tagged tests run in the container without `-race`. `make vet`
vets both the default and `integration` configurations; a new build tag needs
its own vet leg.

### The integration container

`docker run --privileged` grants every capability, disables seccomp and
AppArmor, and exposes the host's whole `/dev`. The suite does not use it. The
narrowest set that was measured to work lives in one place, the `privileges`
function in `test/tools/docker-run`, and a unit test pins it flag by
flag. Every Makefile target and the CI workflow go through that launcher.

Each row was measured on Linux 6.17 with Docker 29.1.3 by removing that one
item and running the lifecycle the suite performs (loop attach, `luksFormat`,
`luksOpen`, `mkfs.ext4`, `mount`, close, detach):

| Given | Why | First thing that breaks without it |
|---|---|---|
| `--cap-add SYS_ADMIN` | device-mapper ioctls | `luksOpen` (`DM_DEV_CREATE`) |
| `--cap-add MKNOD` | `/dev` is a bare tmpfs; loop and dm nodes are created in it | every `mknod`, `EPERM` |
| `--cap-add SETUID`, `--cap-add SETGID` | the lock-directory tests run cryptsetup and go-luks2 as uid 1000 in the disk group, a real setuid/setgid child | `setresuid`, `EPERM` |
| `--cap-drop ALL` | nothing else in Docker's default set is used | nothing |
| `--security-opt seccomp=test/integration/seccomp.json` | `add_key`, `keyctl`, `request_key` | every keyring test |
| `--security-opt apparmor=unconfined` | `docker-default` denies `mount(2)` | `mount` |
| `--device /dev/mapper/control` | dm ioctl interface | `dmsetup` and the host-state guard |
| `--device /dev/loop-control` | `LOOP_CTL_GET_FREE` | loop attach |
| `--device-cgroup-rule 'b 7:* rwm'` | opening loop devices | attach, `EPERM` |
| `--device-cgroup-rule "b <dm major>:* rwm"` | opening the mappings created | opening `/dev/mapper/<name>` |

The dm major is read from `/proc/devices` at run time because it is allocated
dynamically; a wrong one yields a container that creates a mapping and cannot
open it.

Seccomp is the constraint, not capabilities. Docker's default profile denies the keyring
syscalls whatever capabilities are added; with the custom profile they work
with none. `test/integration/seccomp.json` is Docker's default profile
(`github.com/moby/profiles/seccomp v0.1.0`) byte for byte plus one allow block
for those three calls. Its header gives the sha256 and how to re-fetch it.
`seccomp=unconfined` would also work and is not used.

AppArmor is off because `docker-default` denies `mount(2)` and loading a
custom profile would mean changing the CI host.

### What the container does not isolate

Device-mapper and loop devices are not namespaced. `dmsetup ls` in the
container lists every mapping on the host, and the cgroup rules allow opening
any loop device and any dm mapping. What keeps the suite off other devices is
`test/internal/harness`: it records every loop device and mapping in a host-side ledger
before creating it, removes only what it recorded, and never sweeps. Treat the
state directory as part of that boundary.

The state directory is opened once and checked through that
handle, and every ledger read, lock, write and delete goes through the same
handle. A run's temp root is named `go-luks2-run-<run id>-<n>`, and the reaper
detaches loop devices under a recorded root only when its name carries the id
of the run that recorded it. A ledger written before run ids were recorded has a
root with no run id. If loop devices are still backed under it, the reap fails and keeps the
ledger, because they may belong to a live run. Once no integration run is live,
detach them by hand (see below) and delete the ledger.

The entrypoint reaps the previous run's recorded state, then refuses to run if
`dmsetup` is missing, the inventory fails, or a mapping already carries this
container's scope (every name the suite creates is
`<base>-<container scope>-<run id>`). Mappings that belong to the host, such as
an LVM root, or to other containers do not block a run.

### A device no ledger recorded is an operator's job, not this repository's

The reaper removes only what a ledger recorded and only while the live device
still carries the recorded identity. A loop device or mapping that no ledger
names, from an older run, another branch or another process, is cleared by an
operator, one device at a time, after attributing it:

```bash
losetup -a              # find the backing file; attribute the device
losetup -d /dev/loopN   # detach the one you attributed
```

This is a requirement, not a gap. Ownership is never inferred from
appearance: a path prefix, a deleted backing file or an absence of holders all
match devices that belong to someone else. The refusals in
`test/internal/harness/system.go` and `test/tools/luks2-testreap` are deliberate.
Do not add a sweep.

### Running part of the suite

```bash
make docker-test-specific TEST=TestSHA1AFVolumesMapTheSameDataOnTheKernel
make integration-test-luks2   # test/integration/<name>/ for any package named in the Makefile's PKG_<name>
make integration-test-cli

# A shell under the suite's privilege set
make docker-run-bin
ITEST_ID=debug make docker-build-integration
IMAGE=go-luks2-integration-test:debug build/docker-run --rm -it -- bash
```

Run the built `build/docker-run`, not `go run`: under `go run` every non-zero
exit status becomes 1.

### Images

Each run builds `go-luks2-integration-test:$(ITEST_ID)` and a matching
container name, so concurrent runs on one host do not collide. Each target
removes its own image and container on exit. Every image carries the label
`go-luks2-itest=1`, and `make docker-prune-itest` (also run before every
integration build and in CI) removes labelled images no container uses that
are older than `ITEST_PRUNE_AGE` (default `2h`). That catches what a `kill -9`
leaves.

To keep an image, name it: `ITEST_ID=debug make docker-build-integration`. It
is still pruned once older than `ITEST_PRUNE_AGE`.
`ITEST_ID`, `ITEST_IMAGE` and `ITEST_CONTAINER` all take their values from the
environment when set.

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
   wiped. This is a deliberate position, not an oversight: the project
   forbids hand-rolled cryptography, and a PBKDF2 or Argon2 rewritten to read
   its input from locked memory would be exactly that (for PBKDF2, one outside
   the Go Cryptographic Module) — see `doc.go` for the full reasoning.
3. **KDF output.** `crypto/pbkdf2.Key` and `argon2.IDKey` return their result
   on the ordinary heap; the derivation moves it into an enclave immediately,
   so the window is the return statement plus one copy.
4. **Expanded cipher keys.** `xts.NewCipher`/`crypto/aes` hold the AES key
   schedule on the ordinary heap for the cipher's lifetime; neither offers a
   way to place it elsewhere or wipe it. The keyslot wrap uses
   `golang.org/x/crypto/xts`, which is outside the Go Cryptographic Module.
5. **The kernel keyring.** The key spends the table load and resume in the
   kernel's session keyring, as a write-only `logon` key, then is
   revoked, unlinked and verified gone. Kernel keyrings are not namespaced by
   container (see [architecture.md](architecture.md#kernel-keyring)).
6. **Hash state.** `sha256.Sum256` leaves the area key (ESSIV salt) or the
   recovery credential (its printed digest) in the hash's internal state,
   which cannot be wiped.

A seventh exposure found anywhere in this codebase belongs in `doc.go`'s list
on the same commit that finds it, not here first.

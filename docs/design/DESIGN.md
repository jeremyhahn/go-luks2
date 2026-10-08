# go-luks2 target architecture and public API

> **Status: IMPLEMENTED in v1.0.0-rc.1** · Baseline: `g50/main` 7d40045 (0.4.0-alpha) plus `fix/g-compat` (assumed merged first) · Date: 2026-10-05
> Breaking by intent (owner direction: no backward compatibility). Released: `1.0.0-rc.1`, `BREAKING:` heading (release-versioning §5). DECISIONS.md is the record of what each step actually landed, including the corrections made after the plan (H13b and H13d finished the token free functions, `EnrollKeyProvider` and the seam-variable cleanup, and H13e, #284, removed the last transitional forwards); this document is the plan it was built from and is not updated to match drift.

Inventory this design is based on, measured from the tree:

- pkg/luks2 has 22,767 non-test lines in 34 files, plus ~127 test files. It exports 401 identifiers: 84 funcs, 64 types, 90 vars, 80 consts and 82 methods. 3 more files arrive with g-compat.
- There are 191 `fmt.Errorf` and 235 `&detailError{}` sites in pkg/luks2 production code. There are 0 `fmt.Errorf` in cmd.
- 35 package-level mutable seam vars. 26 `*_integration_test.go` files are in pkg/luks2; g-compat adds 3. Of the 26, 15 use no unexported identifier and 11 use 27 distinct unexported ones.
- The file graph is acyclic only by accident. Almost every file reaches `keyslot.go`, `header.go` or `unlock.go` through misplaced helpers: `TrimRight` lives in unlock.go, `writeZeros` in wipe.go, `ErrDeviceInUse` in wipe.go.
- Portfolio consumers are go-trusted-platform (16 files) and go-xkms/xkey (9 files). The hot identifiers are `Lock`/`DetachLoopDevice` (28 each), `FormatOptions` (18), `Token` (15), `Unlock` (12) and `AddKey` (11).

---

## A. Package layout

### A.1 Tree

`pkg/` stays: project-scaffold §1 makes it the default for library code. The root-package exemption covers single-package libraries only, and this module is not one. The module path is unchanged.

```
cmd/luks2/main.go            signal ctx -> cli.Run -> os.Exit (about 25 lines)
pkg/
  luks2/        LUKS2 container + volume API. Rootless, no exec, no kernel subsystems beyond file I/O.
  dmcrypt/      Activation: kernel keyring + device-mapper (root).
  keyprovider/  KeyProvider implementations that exec helpers (command, systemd-fido2).
  loop/         Loop devices (root).
  filesystem/   mkfs / fsck / blkid (exec) and mount(2) / umount(2) (root).
  wipe/         Whole-device sanitization (multi-pass, verified, discard).
internal/
  errs/         The one error struct (aliased publicly), constructors.
  clock/        Clock{Now, NewTimer} + System + Fake. No Sleep.
  secret/       go-enclave custody helpers; THE canonical residual raw-bytes list.
  fips/         FIPS-mode probe (a value, not a global) + approved-algorithm predicates.
  af/           Anti-forensic split/merge.
  areacipher/   Keyslot-area cipher: AES-XTS, CBC-ESSIV/plain64/plain.
  kdf/          PBKDF2/Argon2 into enclaves; calibration; cost floors; aggregate budget; SHA-1 cost conversion.
  header/       On-disk model + codec + validation (binary header, JSON, canonical JSON,
                unknown members, checksums, requirements, segment/keyslot/digest checks, scan order).
  recoverykey/  Render/parse recovery-key text inside enclaves.
  volkey/       The Key type and Borrow, the only route to volume-key bytes outside luks2.
  device/       Pinned / Locked / Claimed descriptors; node flock + cryptsetup lock; O_EXCL claim;
                size; O_DIRECT medium reads; shared device sentinels; LockTimeoutError.
  dm/           device-mapper ioctls, busy retry, node placement, readiness wait.
  keyring/      Kernel keyring add/release/verify on a discarded OS thread.
  command/      Trusted tool resolution, scrubbed env, CommandContext + process-group kill, output caps.
  cli/          The luks2 command (§F).
test/
  integration/<pkg>/   One dir per package under test (§E), incl. internal ones.
  integration/interop/ cryptsetup/systemd as the real peer, both directions.
  internal/harness, internal/labstrings     (was test/harness, test/labstrings: no longer importable)
  tools/{covergate,releasability-gate,luks2-testreap,require-tool,release-gate,docker-run}  (mains)
  ci/workflows, makefile                    (unchanged test packages)
build/docker/{devcontainer,integration,cli}/Dockerfile   (.devcontainer/devcontainer.json points here)
```

### A.2 Import DAG (in-module edges; stdlib, x/sys and go-enclave omitted)

| Package | Single responsibility | May import | Root | Exec |
|---|---|---|---|---|
| internal/errs | error shape | — | | |
| internal/clock | time source for waits | — | | |
| internal/fips | FIPS mode and approval | — | | |
| internal/secret | enclave custody | errs | | |
| internal/af | AF split/merge | secret, fips, errs | | |
| internal/areacipher | keyslot-area crypto | secret, errs | | |
| internal/kdf | key derivation and cost | secret, fips, clock, errs | | |
| internal/header | LUKS2 on-disk format | kdf, fips, errs | | |
| internal/recoverykey | recovery-key text | secret, errs | | |
| internal/volkey | volume-key custody | secret, errs | | |
| internal/device | descriptor, locks, claim | clock, errs | | |
| internal/dm | device-mapper | clock, errs | yes | |
| internal/keyring | kernel keyring | secret, errs | | |
| internal/command | external tools | errs | | yes |
| **pkg/luks2** | container + volume API | errs, clock, fips, secret, af, areacipher, kdf, header, recoverykey, volkey, device | **no** | **no** |
| **pkg/dmcrypt** | activation | luks2, volkey, dm, keyring, device, clock, errs | yes | |
| **pkg/keyprovider** | helper-backed credentials | luks2, command, secret, errs | | yes |
| **pkg/loop** | loop devices | device, clock, errs | yes | |
| **pkg/filesystem** | filesystems on a device | command, errs | yes | yes |
| **pkg/wipe** | sanitization | device, clock, errs | | |
| internal/cli | luks2 command | all pkg/*, secret, errs | | |
| cmd/luks2 | entry point | internal/cli | | |

Enforced mechanically with golangci `depguard`, one rule per row. pkg/luks2 additionally denies `os/exec`, `github.com/anatol/devmapper.go`, internal/dm, internal/keyring and internal/command. The core cannot regain root or exec without a red lint. Root-only and exec code is isolated in exactly dmcrypt, loop, filesystem, keyprovider, internal/dm, internal/keyring and internal/command.

### A.3 Portability

pkg/luks2 and pkg/keyprovider build for `linux` and `darwin`. `make build` cross-compiles both, so the existing CI job enforces this without changing the template.

Linux-only facilities live in `internal/device/*_linux.go`: BLKGETSIZE64, O_DIRECT medium reads, the `/run/cryptsetup` lock and BLKDISCARD. Their `*_unix.go` siblings give regular-file behaviour, and the medium check fails closed with `ErrUnsupported`. Windows is out of scope because there is no flock.

### A.4 Why six public packages

Fewer is better, so each one has to earn its place:

- **luks2.** Required. It is the rootless core.
- **dmcrypt.** The only way to keep luks2 rootless. Activation needs dm and the keyring.
- **keyprovider.** The only way to keep luks2 exec-free. The interface it implements is `luks2.KeyProvider`, defined at the consumer.
- **loop**, **filesystem** and **wipe.** Each is LUKS-independent, consumed directly by go-trusted-platform, and has its own trust boundary: loop ioctls, external binaries, and whole-device destruction. Consumers import only what they use.

Rejected alternative: a single `host` package. It would mix the exec trust boundary with ioctl code and drag exec into every importer.

Also rejected: a public `fips` package. FIPS mode is a process property, and migration is a Volume operation.

---

## B. Public API after the redesign

### B.1 Shape decisions

- **A `*luks2.Volume` handle.** `luks2.Open(ctx, path, ...Option)` pins one descriptor and nothing else.
  - It does not require a valid header, because `RestorePrimaryHeader` and `Erase` must work on a damaged one.
  - Every method takes the lock it needs on that descriptor, does its I/O, and releases the lock. No lock is held between calls; cryptsetup behaves the same way.
- **The lock order and the write path are type properties.** internal/device exposes three types:
  - `Pinned`, which is read-only.
  - `Pinned.Lock(ctx, mode)` returns `*Locked`. It takes the node flock, then the cryptsetup lock, both on the pinned descriptor.
  - `Locked.Claim(ctx)` returns `*Claimed`. It applies O_EXCL by reopening `/proc/self/fd/N`, so the claim targets the locked inode by construction and `requireSameDevice` disappears.

  Write methods exist only on `*Locked` (exclusive mode) and `*Claimed`. Code holding a `Pinned` cannot write, cannot claim before locking, and cannot lock in the wrong order. The convention becomes a compile error.
- **Concurrency.** `Volume` is safe for concurrent use. flock does not exclude within one open file description, so an internal `sync.RWMutex` serializes operations: shared for reads, exclusive for writes. Following go-style's rule on locks around external code, `KeyProvider.Passphrase` is called before the mutex or any file lock is taken.
- **Credentials.** Every secret crossing the API is an `*enclave.MemoryEnclave`, and the caller keeps ownership. The "caller-supplied `[]byte` credential" entry is removed from the residual-exposure list.
- **The volume key is a capability.** `*luks2.Key` is obtained only by unlocking. It is bound to the volume and records the keyslot it came from (-1 for a supplied key).
  - Mutations that need it (AddKeyslot, ChangeKeyslot, AddRecoveryKey, Enroll) re-verify it against the digest under the exclusive lock, because the header may have changed since Unlock.
  - Its bytes are not exported. `luks2.Key` is an alias of `volkey.Key`, and `volkey.Borrow` is reachable only inside the module, so dmcrypt can hand the key to the keyring and no consumer can extract it.
- **Removal is guarded, not authenticated.** `RemoveKeyslot(ctx, slot)` keeps every data-safety guard: `ErrLastKeyslot` and `ErrKeyslotAreaOverlap`. Authorization belongs to the caller: the CLI's passphrase prompt, or the platform's IAM (go-trusted-platform's daemon removes slots under IAM today).
- **Options style** (go-style §Naming, clean-code §3.3).
  - Constructors take functional options: `Open`, `NewRecoveryKey`, `keyprovider.NewCommand`/`NewFIDO2`/`FromToken`.
  - Operations take required operands positionally plus one named params struct whose **zero value means library policy**: `FormatParams`, `KDFParams`, `KeyslotParams`, `MigrateParams`, `filesystem.MakeParams`/`MountParams`, `wipe.Params`.
  - No boolean arguments (clean-code §3.4). Force-restore and check-vs-repair become separate methods.
- **ctx** is the first parameter of everything that touches the OS (go-style). Pure accessors on in-memory values take none.

### B.2 pkg/luks2

```go
// volume.go
type Volume struct{ /* unexported */ }
type Option func(*options)
func WithReadOnly() Option                 // O_RDONLY; mutations return ErrReadOnly
func WithLockWait(d time.Duration) Option  // library bound on lock waits; default DefaultLockWait
const DefaultLockWait = 30 * time.Second
func Open(ctx context.Context, path string, opts ...Option) (*Volume, error)
func (v *Volume) Path() string
func (v *Volume) Close() error

// format.go
type FormatParams struct {
	Cipher       string      // cryptsetup spec; zero: DefaultCipher
	KeySize      int         // bits; zero: DefaultKeySize
	Hash         crypto.Hash // digest + AF hash; zero: DefaultHash
	SectorSize   int         // zero: DefaultSectorSize
	MetadataSize int         // zero: 16 KiB header area
	Label, Subsystem string
	KDF          KDFParams
}
func (p FormatParams) Validate() error
func (v *Volume) Format(ctx context.Context, pass *enclave.MemoryEnclave, p FormatParams) error
const DefaultCipher = "aes-xts-plain64"
const DefaultKeySize = 512
const DefaultSectorSize = 512
const DefaultHash = crypto.SHA256

// kdf.go
type KDFType string
const (KDFArgon2id KDFType = "argon2id"; KDFArgon2i KDFType = "argon2i"; KDFPBKDF2 KDFType = "pbkdf2")
type KDFParams struct {
	Type       KDFType       // zero: DefaultKDFType()
	Hash       crypto.Hash   // PBKDF2 PRF
	IterTime   time.Duration // calibration target; zero: 2s
	Iterations int           // exact PBKDF2 count (floors still apply)
	Time, MemoryKiB, Parallel int // Argon2
}
func (p KDFParams) Validate() error // includes FIPS approval -> ErrFIPSNotApproved
func DefaultKDFType() KDFType       // pbkdf2 (SHA-512) in FIPS mode, argon2id otherwise

// header.go: read model (snapshot under the shared lock)
type Header struct{ /* unexported */ }
func (v *Volume) Header(ctx context.Context) (*Header, error)          // ErrNotLUKS2, ErrInvalidHeader
func (v *Volume) SecondaryHeader(ctx context.Context) (*Header, error)
func (v *Volume) RestorePrimaryHeader(ctx context.Context) error       // ErrPrimaryHeaderCurrent
func (v *Volume) ReplacePrimaryHeader(ctx context.Context) error       // unconditional (was Force)
func (h *Header) UUID() string
func (h *Header) Label() string
func (h *Header) Subsystem() string
func (h *Header) SequenceID() uint64
func (h *Header) Size() int64
func (h *Header) Keyslots() []KeyslotInfo
func (h *Header) Segments() []Segment
func (h *Header) Tokens() map[int]Token
func (h *Header) Requirements() []string
func (h *Header) Dropped() []DroppedEntry
func (h *Header) MarshalJSON() ([]byte, error)   // canonical metadata JSON
type Segment struct { ID int; Type string; Offset, Size int64; Encryption string; SectorSize int; IVTweak uint64 }
const SizeDynamic int64 = -1
type KeyslotInfo struct { ID int; Type string; KeySize int; Priority Priority; Encryption string; KDF KDFParams }
type Priority int
const (PriorityDefault Priority = iota; PriorityIgnore; PriorityNormal; PriorityPrefer) // zero = keep/normal; DECISIONS.md "Priority zero value (pre-1.0)"
type DroppedEntry struct{ Kind, ID string }
func (e DroppedEntry) String() string

// key.go
type Key = volkey.Key // methods: Keyslot() int, Size() int, Destroy()
func (v *Volume) Unlock(ctx context.Context, pass *enclave.MemoryEnclave) (*Key, error)
func (v *Volume) UnlockKeyslot(ctx context.Context, slot int, pass *enclave.MemoryEnclave) (*Key, error)
func (v *Volume) UnlockWithProvider(ctx context.Context, p KeyProvider) (*Key, error) // only p.Token().Keyslots are tried
func (v *Volume) UnlockWithVolumeKey(ctx context.Context, vk *enclave.MemoryEnclave) (*Key, error)
func (v *Volume) Target(ctx context.Context, key *Key) (*Target, error) // dm-crypt parameters; no secret
type Target struct { Major, Minor uint32; Offset, Length uint64; Cipher string; KeySize int; IVOffset uint64; SectorSize int; Flags []string }

// keyslot.go
const MaxKeyslots = 32
type KeyslotParams struct { Slot *int /* nil: lowest free */; Priority Priority; KDF KDFParams }
func (v *Volume) AddKeyslot(ctx context.Context, key *Key, pass *enclave.MemoryEnclave, p KeyslotParams) (KeyslotInfo, error)
func (v *Volume) ChangeKeyslot(ctx context.Context, key *Key, pass *enclave.MemoryEnclave, p KeyslotParams) (KeyslotInfo, error) // the slot key came from
func (v *Volume) RemoveKeyslot(ctx context.Context, slot int) error
// KeyslotInfo.KDF reports the cost written, including an inherited Argon2 cost (was the AddKeyOptions.InheritedArgon2Cost out-parameter).

// token.go and provider.go
const MaxTokens = 32
const TokenTypeRecovery = "systemd-recovery"
type Token struct { Type string; Keyslots []int; Members map[string]json.RawMessage } // + MarshalJSON/UnmarshalJSON
func (v *Volume) AddToken(ctx context.Context, t Token) (int, error)
func (v *Volume) SetToken(ctx context.Context, id int, t Token) error
func (v *Volume) RemoveToken(ctx context.Context, id int) error
type KeyProvider interface {
	Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
	Token() Token
}
type Enrollment struct { Keyslot KeyslotInfo; Token int }
func (v *Volume) Enroll(ctx context.Context, key *Key, p KeyProvider, kp KeyslotParams) (Enrollment, error) // keyslot rolled back if the token write fails

// recovery.go
type RecoveryKeyFormat uint8
const (RecoveryDashed RecoveryKeyFormat = iota; RecoveryHex; RecoveryBase64) // zero = systemd's dashed
func (f RecoveryKeyFormat) String() string
func ParseRecoveryKeyFormat(name string) (RecoveryKeyFormat, error)
const DefaultRecoveryKeyLength = 32
type RecoveryKey struct{ /* unexported: only NewRecoveryKey makes one, so the library-generated KDF exemption stays sound */ }
type RecoveryKeyOption func(*recoveryOptions)
func WithRecoveryFormat(f RecoveryKeyFormat) RecoveryKeyOption
func WithRecoveryLength(n int) RecoveryKeyOption
func NewRecoveryKey(opts ...RecoveryKeyOption) (*RecoveryKey, error)
func (r *RecoveryKey) Format() RecoveryKeyFormat
func (r *RecoveryKey) Hash() string                       // SHA-256 of the text, hex
func (r *RecoveryKey) WriteTo(w io.Writer) (int64, error) // the text; never a Go string
func (r *RecoveryKey) Destroy()
func ParseRecoveryKey(text *enclave.MemoryEnclave) (*enclave.MemoryEnclave, error) // normalize typed input
func (v *Volume) AddRecoveryKey(ctx context.Context, key *Key, rk *RecoveryKey, p KeyslotParams) (Enrollment, error)
// Two-phase on purpose: the caller shows or persists rk BEFORE adding it, so there is no RecoveryKey.SaveError.

// fips.go
type MigrateParams struct { KeepNonApproved bool; KDF KDFParams }
type Migration struct { Keyslot int; KeyslotAdded bool; MigratedDigests, RemovedKeyslots, RetainedNonApproved []int; Complete bool }
func (v *Volume) MigrateToFIPS(ctx context.Context, pass *enclave.MemoryEnclave, p MigrateParams) (*Migration, error)
type NonApprovedKDF struct { ID int; Type, Hash, Reason string }
func (k NonApprovedKDF) String() string
type FIPSMigrationStage uint8 // StagePreflight, StageVerify, StageWrite, StageRemove, StageVerifyWritten

// erase.go
func (v *Volume) Erase(ctx context.Context) error // crypto-erase: every header copy + keyslot area (was Wipe{HeaderOnly})

// passphrase.go
const MinPassphraseLength = 8
const MaxPassphraseLength = 512
func ValidatePassphrase(pass *enclave.MemoryEnclave) error

// errors.go: see §C
```

### B.3 pkg/dmcrypt

```go
func Activate(ctx context.Context, v *luks2.Volume, key *luks2.Key, name string) (*Mapping, error)
func Deactivate(ctx context.Context, name string) error
func Lookup(ctx context.Context, name string) (*Mapping, error) // ErrNotActive
type Mapping struct { Name, UUID string; Major, Minor uint32 }
func (m *Mapping) Path() string // /dev/mapper/<name>
func ValidateName(name string) error
const MaxNameLength = 127
func CheckKeyring(ctx context.Context) error
type KeyringError struct { Op string; Kind, Err error } // Remedy() string
func (e *KeyringError) Error() string
func (e *KeyringError) Unwrap() []error
func (e *KeyringError) Remedy() string
```

`Activate` calls `v.Target(ctx, key)`, which re-reads the header under the shared lock and re-verifies the key if `SequenceID` changed. It then maps the pinned descriptor's major:minor, never a path.

The mapping is a transaction from the moment the create succeeds. Rollback runs under `context.WithoutCancel(ctx)` with its own clock budget, so a cancelled caller never leaves a plaintext device behind.

### B.4 pkg/keyprovider

```go
const TokenTypeFIDO2 = "systemd-fido2"
const DefaultRelyingParty = "io.systemd.cryptsetup"
const SaltLength = 32
const SecretLength = 32
type Command struct{ /* unexported */ }
type CommandOption func(*commandOptions)
func WithArgs(args ...string) CommandOption
func WithStdin(b []byte) CommandOption
func WithLine(n int) CommandOption
func WithEnv(kv ...string) CommandOption
func WithToken(t luks2.Token) CommandOption
func NewCommand(path string, opts ...CommandOption) (*Command, error)
func (c *Command) Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
func (c *Command) Token() luks2.Token
type FIDO2Params struct { RelyingParty string; CredentialID, Salt []byte; UserPresence, UserVerification, ClientPIN bool }
type FIDO2 struct{ /* unexported */ }
type FIDO2Option func(*fido2Options)
func WithFIDO2Tools(credPath, assertPath string) FIDO2Option
func WithDevice(path string) FIDO2Option
func NewFIDO2(p FIDO2Params, opts ...FIDO2Option) (*FIDO2, error)
func (f *FIDO2) Passphrase(ctx context.Context) (*enclave.MemoryEnclave, error)
func (f *FIDO2) Token() luks2.Token
type FIDO2CredentialParams struct { RelyingParty, UserName string; UserID []byte; Resident, UserVerification bool }
func NewFIDO2Credential(ctx context.Context, p FIDO2CredentialParams, opts ...FIDO2Option) ([]byte, error)
func NewFIDO2Salt() ([]byte, error)
func FromToken(t luks2.Token, opts ...FIDO2Option) (luks2.KeyProvider, error) // ErrUnsupportedToken
type HelperError struct { Path string; ExitCode int; Stderr string; Err error }
var _ luks2.KeyProvider = (*Command)(nil)
var _ luks2.KeyProvider = (*FIDO2)(nil)
```

The systemd-fido2 token schema (fido2-credential, salt, rp, the up/uv/pin flags) is parsed here from `Token.Members`. `luks2.Token` is generic.

### B.5 pkg/loop, pkg/filesystem, pkg/wipe

```go
// loop
func Attach(ctx context.Context, file string) (*Device, error)
func Find(ctx context.Context, file string) (*Device, error)     // by backing file; ErrNotFound
func Lookup(ctx context.Context, path string) (*Device, error)   // by /dev/loopN
type Device struct{ /* unexported */ }
func (d *Device) Path() string
func (d *Device) BackingFile() string
func (d *Device) Detach(ctx context.Context) (DetachState, error)
type DetachState int
const (Released DetachState = iota; Deferred) // Deferred is success (losetup -d on a busy device)

// filesystem
type Type string
const (Ext4 Type = "ext4"; XFS Type = "xfs"; FAT32 Type = "vfat"; ZFS Type = "zfs")
func Supported() []Type
type MakeParams struct { Label string; BlockSize int; Force bool; Ext4 *Ext4Params; XFS *XFSParams; ZFS *ZFSParams }
type Ext4Params struct { /* fields as Ext4Options */ }
type XFSParams struct { /* fields as XFSOptions */ }
type ZFSParams struct { /* fields as ZFSOptions */ }
func Make(ctx context.Context, device string, t Type, p MakeParams) error
func Check(ctx context.Context, device string, t Type) (CheckResult, error)
func Repair(ctx context.Context, device string, t Type) (CheckResult, error)
type CheckResult struct { Repaired, RebootRequired bool }
func Detect(ctx context.Context, device string) (Type, error)   // ErrNotDetected
func Inspect(ctx context.Context, device string) (*Info, error)
type Info struct { /* as FilesystemInfo */ }
type MountParams struct { Source, Target string; Type Type; Flags uintptr; Data string }
func Mount(ctx context.Context, p MountParams) error
type UnmountFlags int // Force, Detach, Expire; invalid combos refused before the syscall
func Unmount(ctx context.Context, target string, flags UnmountFlags) error // ErrNotMounted
func IsMounted(ctx context.Context, target string) (bool, error)
func DeviceMounted(ctx context.Context, major, minor uint32) (bool, error) // with dmcrypt.Lookup, replaces IsMappingMounted
type CommandError struct { Command string; ExitCode int; Output string; Err error }

// wipe
type Pattern uint8
const (Zeros Pattern = iota; Ones; Random)
type Standard uint8
const (NoStandard Standard = iota; DoD3Pass; DoD7Pass; NIST)
func (s Standard) Patterns() []Pattern
type VerifyMode uint8
const (VerifyDefault VerifyMode = iota; VerifyAlways; VerifyNever) // replaces Verify+NoVerify bools
type Params struct { Standard Standard; Patterns []Pattern; Verify VerifyMode; Discard bool; Progress func(Progress) }
type Progress struct { Pass, Passes int; Written, Total int64; Pattern Pattern; Verifying bool }
func Sanitize(ctx context.Context, path string, p Params) error
```

`String()` is kept on `Pattern` and `Standard`.

### B.6 Disposition of every exported identifier in pkg/luks2 (401)

Generated from a go/ast dump of `g50/main`, with coverage checked by script: none missing, none extra. Counts: KEEP 55, RENAME 132, MOVE 47, UNEXPORT 73, DELETE 94.

Exported struct fields follow their type. Fields named in a target are renamed as shown.

| Identifier(s) | Action | Target / replacement |
|---|---|---|
| `DefaultCipher`, `DefaultKeySize`, `DefaultSectorSize` | KEEP | luks2 (zero FormatParams fields resolve to these) |
| `DefaultKDFType` | KEEP | luks2.DefaultKDFType() KDFType |
| `DefaultLockWait` | KEEP | luks2.DefaultLockWait; per-Volume override luks2.WithLockWait |
| `DroppedEntry` | KEEP | luks2.DroppedEntry via (*Header).Dropped() |
| `DroppedEntry.String`, `NonApprovedKDF.String` | KEEP |  |
| `ErrDeviceCacheStale`, `ErrDeviceChanged`, `ErrDeviceInUse`, `ErrDeviceNotFound`, `ErrLockContended`, `ErrPermissionDenied` | KEEP | luks2 (same value re-exported by wipe; defined once in internal/device) |
| `ErrInvalidHeader` | KEEP | luks2.ErrInvalidHeader |
| `ErrNoKeyslots` | KEEP | luks2.ErrNoKeyslots (distinct from ErrWrongKey (#30)) |
| `ErrUnsupportedRequirement` | KEEP | luks2.ErrUnsupportedRequirement |
| `FIPSImportRequiredError.Error`, `FIPSMigrationError.Error`, `FIPSMigrationError.Unwrap`, `KDFCalibrationError.Error`, `KDFCalibrationError.Unwrap`, `LockTimeoutError.Error`, `LockTimeoutError.Unwrap`, `OrphanedKeyslotError.Error`, `OrphanedKeyslotError.Unwrap` | KEEP | Follows its type (see the type row). |
| `DefaultKDFSpec` | KEEP | luks2.DefaultKDFSpec() string: the LUKS2 spelling (`pbkdf2-sha512` in FIPS mode, `argon2id` otherwise) of the type DefaultKDFType() returns; retained exported for callers that name a KDF as a string |
| `LegacyToken` | KEEP | luks2.LegacyToken (= header.Token): the on-disk token codec with its typed FIDO2 members and unknown-field passthrough; callers use the generic Token |
| `ErrIntegerOverflow` | KEEP | dmcrypt.ErrIntegerOverflow, raised by pkg/dmcrypt when a segment size or offset does not fit the device-mapper table; pkg/luks2's own is luks2.ErrInvalidArgument (see the RENAME row) |
| `ErrDeviceChanged` | KEEP | also dmcrypt.ErrDeviceChanged: the same value as luks2's, re-exported by pkg/dmcrypt for the target Activate just created (internal/device.ErrChanged, defined once) |
| `KDFCalibrationError` | KEEP | luks2.KDFCalibrationError |
| `KeyProvider` | KEEP | luks2.KeyProvider{Passphrase(ctx); Token() Token} |
| `KeyslotInfo` | KEEP | luks2.KeyslotInfo (KDF field is KDFParams) |
| `LockTimeoutError` | KEEP | luks2.LockTimeoutError (re-exported alias of internal/device's) |
| `MaxKeyslots` | KEEP | luks2.MaxKeyslots |
| `MaxPassphraseLength`, `MinPassphraseLength`, `FIPSImportRequiredError`, `FIPSMigrationError`, `NonApprovedKDF`, `ErrFIPSImportRequired`, `ErrFIPSNotApproved`, `ErrKDFCalibration`, `ErrKeyProvider`, `ErrKeyslotAreaOverlap`, `ErrLastKeyslot`, `ErrOrphanedKeyslot`, `ErrPrimaryHeaderCurrent`, `ErrProtectedMemory`, `ErrTokenNotFound` | KEEP | luks2 |
| `OrphanedKeyslotError` | KEEP | luks2.OrphanedKeyslotError |
| `ParseRecoveryKey` | KEEP | luks2.ParseRecoveryKey(*enclave.MemoryEnclave) (*enclave.MemoryEnclave, error) |
| `ParseRecoveryKeyFormat` | KEEP | luks2.ParseRecoveryKeyFormat |
| `RecoveryKey` | KEEP | luks2.RecoveryKey (unexported fields; accessors) |
| `RecoveryKeyFormat` | KEEP | luks2.RecoveryKeyFormat (uint8 enum) |
| `Token` | KEEP | luks2.Token{Type, Keyslots, Members map[string]json.RawMessage}; FIDO2 fields move to keyprovider |
| `Token.MarshalJSON`, `Token.UnmarshalJSON` | KEEP | luks2.Token |
| `ValidatePassphrase` | KEEP | luks2.ValidatePassphrase(*enclave.MemoryEnclave) |
| `AddKey` | RENAME | (*luks2.Volume).AddKeyslot(ctx, *Key, pass, KeyslotParams) |
| `AddKeyOptions` | RENAME | luks2.KeyslotParams{Slot, Priority, KDF KDFParams}; InheritedArgon2Cost becomes the returned KeyslotInfo.KDF |
| `AddRecoveryKey` | RENAME | (*luks2.Volume).AddRecoveryKey(ctx, *Key, *RecoveryKey, KeyslotParams) |
| `Argon2CostError`, `PBKDFIterationsError` | RENAME | luks2.KDFCostError{Param, Value, Min, Max} (one type) |
| `Argon2CostError.Error`, `Argon2CostError.Unwrap`, `FilesystemCommandError.Error`, `FilesystemCommandError.Unwrap`, `KeyringUnavailableError.Error`, `KeyringUnavailableError.Unwrap`, `PBKDFIterationsError.Error`, `PBKDFIterationsError.Unwrap` | RENAME | Follows its type (see the type row). |
| `ChangeKey` | RENAME | (*luks2.Volume).ChangeKeyslot(ctx, *Key, pass, KeyslotParams) |
| `CheckFilesystem`, `CheckFilesystemDetailed` | RENAME | filesystem.Check(ctx, dev, t) / filesystem.Repair(ctx, dev, t) (no bool flag) |
| `CommandKeyProvider` | RENAME | keyprovider.Command via keyprovider.NewCommand(path, ...CommandOption) |
| `DefaultHashAlgo` | RENAME | luks2.DefaultHash (crypto.Hash) |
| `DetachLoopDeviceState` | RENAME | (*loop.Device).Detach(ctx) (DetachState, error) |
| `DetectFilesystem` | RENAME | filesystem.Detect(ctx, dev) |
| `EnrollKeyProvider` | RENAME | (*luks2.Volume).Enroll(ctx, *Key, KeyProvider, KeyslotParams) |
| `ErrCredentialEmpty`, `ErrCredentialTooLong`, `ErrInvalidVolumeKey`, `ErrPassphraseTooLong`, `ErrPassphraseTooShort` | RENAME | luks2.ErrInvalidCredential |
| `ErrDeviceNodeUnverified` | RENAME | dmcrypt.ErrNodeUnverified |
| `ErrDeviceTooSmall`, `ErrIntegerOverflow`, `ErrInvalidKeySize`, `ErrInvalidLabel`, `ErrInvalidMetadataSize`, `ErrInvalidPath`, `ErrInvalidRecoveryKeyFormat`, `ErrInvalidSectorSize`, `ErrInvalidSize`, `ErrNotBlockDevice`, `ErrRecoveryKeyTooShort`, `ErrSHA1NotWritten` | RENAME | luks2.ErrInvalidArgument |
| `ErrDirectIOUnsupported`, `ErrUnsupportedCipher`, `ErrUnsupportedHash`, `ErrUnsupportedHeaderChecksum`, `ErrUnsupportedKDF`, `ErrUnsupportedKeyslotCipher`, `ErrUnsupportedSegmentLayout` | RENAME | luks2.ErrUnsupported |
| `ErrFilesystemNotDetected` | RENAME | filesystem.ErrNotDetected |
| `ErrFilesystemTool` | RENAME | filesystem.ErrTool |
| `ErrFIPSMigrationDigest`, `ErrFIPSMigrationUnboundKey`, `ErrFIPSMigrationUnderFIPS`, `ErrFIPSMigrationVerification` | RENAME | luks2.ErrFIPSMigration + typed FIPSMigrationError.Stage |
| `ErrHelperNotConfigured`, `ErrHelperPathNotAbsolute` | RENAME | keyprovider.ErrInvalidArgument (NewCommand validation) |
| `ErrInvalidFIDO2Binding` | RENAME | keyprovider.ErrInvalidBinding |
| `ErrInvalidFilesystemOption` | RENAME | filesystem.ErrInvalidArgument |
| `ErrInvalidKeyslot` | RENAME | luks2.ErrKeyslotNotFound (structural keyslot faults are ErrInvalidHeader) |
| `ErrInvalidMappingName` | RENAME | dmcrypt.ErrInvalidName |
| `ErrKeyslotsAreaFull`, `ErrMetadataTooLarge`, `ErrNoFreeTokenSlot` | RENAME | luks2.ErrNoSpace |
| `ErrLoopNodeAbsent` | RENAME | loop.ErrNodeAbsent |
| `ErrMappingBusy` | RENAME | dmcrypt.ErrBusy |
| `ErrMappingStillLive` | RENAME | dmcrypt.ErrStillLive |
| `ErrMasterKeyVerification` | RENAME | luks2.ErrWrongKey |
| `ErrNoFIDO2Device` | RENAME | keyprovider.ErrNoDevice |
| `ErrNoKeyProvider` | RENAME | luks2.ErrInvalidArgument (nil provider) |
| `ErrUnsupportedFilesystem` | RENAME | filesystem.ErrUnsupported |
| `ErrUnsupportedLUKSVersion` | RENAME | luks2.ErrNotLUKS2 |
| `ErrVolumeAlreadyUnlocked` | RENAME | dmcrypt.ErrActive |
| `ErrVolumeNotUnlocked` | RENAME | dmcrypt.ErrNotActive |
| `ErrWipeVerification` | RENAME | wipe.ErrVerification |
| `Ext4Options`, `XFSOptions`, `ZFSOptions` | RENAME | filesystem.Ext4Params / XFSParams / ZFSParams |
| `FIDO2CredentialOptions` | RENAME | keyprovider.FIDO2CredentialParams |
| `FilesystemCheckResult` | RENAME | filesystem.CheckResult |
| `FilesystemCommandError` | RENAME | filesystem.CommandError |
| `FilesystemInfo` | RENAME | filesystem.Info |
| `FilesystemOptions` | RENAME | filesystem.MakeParams |
| `FilesystemType` | RENAME | filesystem.Type |
| `FindLoopDevice` | RENAME | loop.Find(ctx, file) |
| `FIPSMigrationOptions` | RENAME | luks2.MigrateParams |
| `FIPSMigrationResult` | RENAME | luks2.Migration |
| `Format` | RENAME | (*luks2.Volume).Format(ctx, pass, FormatParams) |
| `FormatOptions` | RENAME | luks2.FormatParams (Device and Passphrase leave it) |
| `GenerateRecoveryKey` | RENAME | luks2.NewRecoveryKey(...RecoveryKeyOption) |
| `GetFilesystemInfo` | RENAME | filesystem.Inspect(ctx, dev) |
| `ImportToken` | RENAME | (*luks2.Volume).SetToken(ctx, id, Token) |
| `IsFilesystemSupported`, `SupportedFilesystems` | RENAME | filesystem.Supported() []Type |
| `IsMappingMounted` | RENAME | filesystem.DeviceMounted(ctx, devNo) with dmcrypt.Lookup |
| `KDFTypeArgon2i`, `KDFTypeArgon2id`, `KDFTypePBKDF2` | RENAME | luks2.KDFArgon2i / KDFArgon2id / KDFPBKDF2 of type KDFType |
| `KeyringUnavailableError` | RENAME | dmcrypt.KeyringError |
| `KeyslotPriorityIgnore`, `KeyslotPriorityNormal`, `KeyslotPriorityPrefer` | RENAME | luks2.PriorityIgnore / PriorityNormal / PriorityPrefer of type Priority |
| `KillKeyslot` | RENAME | (*luks2.Volume).RemoveKeyslot(ctx, slot): guarded (ErrLastKeyslot, ErrKeyslotAreaOverlap); authorization is the caller's policy |
| `ListKeyslots` | RENAME | (*luks2.Header).Keyslots() |
| `Lock` | RENAME | dmcrypt.Deactivate(ctx, name) |
| `MakeFilesystem`, `MakeFilesystemWithOptions` | RENAME | filesystem.Make(ctx, dev, t, MakeParams) |
| `MaxTokenSlots` | RENAME | luks2.MaxTokens |
| `MigrateToFIPS` | RENAME | (*luks2.Volume).MigrateToFIPS(ctx, pass, MigrateParams) |
| `NewFIDO2KeyProvider` | RENAME | keyprovider.NewFIDO2(FIDO2Params, ...FIDO2Option) (*FIDO2, error) |
| `ProviderFromToken` | RENAME | keyprovider.FromToken(luks2.Token, ...FIDO2Option) |
| `ReadHeader` | RENAME | (*luks2.Volume).Header(ctx) |
| `ReadSecondaryHeader` | RENAME | (*luks2.Volume).SecondaryHeader(ctx) |
| `RecoveryKey.Clear` | RENAME | (*RecoveryKey).Destroy |
| `RecoveryKeyFormatBase64`, `RecoveryKeyFormatDashed`, `RecoveryKeyFormatHex` | RENAME | luks2.RecoveryBase64 / RecoveryDashed / RecoveryHex |
| `RecoveryKeyLength` | RENAME | luks2.DefaultRecoveryKeyLength |
| `RecoveryKeyOptions` | RENAME | luks2.RecoveryKeyOption (WithRecoveryFormat, WithRecoveryLength) + KeyslotParams; OutputPath deleted |
| `RemoveToken` | RENAME | (*luks2.Volume).RemoveToken(ctx, id) |
| `RestorePrimaryHeader` | RENAME | (*luks2.Volume).RestorePrimaryHeader(ctx) |
| `Segment` | RENAME | on-disk struct -> internal/header; luks2.Segment becomes a typed read-only value (Offset/Size int64) |
| `SetupLoopDevice` | RENAME | loop.Attach(ctx, file, ...loop.Option) |
| `TokenTypeSystemdRecovery` | RENAME | luks2.TokenTypeRecovery |
| `Unlock` | RENAME | (*luks2.Volume).Unlock(ctx, pass) + dmcrypt.Activate(ctx, v, key, name) |
| `UnlockWithProvider` | RENAME | (*luks2.Volume).UnlockWithProvider(ctx, p) + dmcrypt.Activate |
| `UnlockWithVolumeKey` | RENAME | (*luks2.Volume).UnlockWithVolumeKey(ctx, vk) + dmcrypt.Activate |
| `ValidateFormatOptions` | RENAME | (luks2.FormatParams).Validate() |
| `Wipe`, `WipeOptions` | RENAME | wipe.Sanitize(ctx, path, wipe.Params); HeaderOnly is (*luks2.Volume).Erase(ctx) |
| `WipePattern`, `WipeStandard` | RENAME | wipe.Pattern / wipe.Standard |
| `WipeProgress`, `WipeProgressFunc` | RENAME | wipe.Progress (PercentComplete dropped: derivable) / wipe.Params.Progress func(Progress) |
| `WipeStandard.GetPatternSequence` | RENAME | wipe.Standard.Patterns() |
| `CheckKeyringAvailable` | MOVE | dmcrypt.CheckKeyring(ctx) |
| `CommandKeyProvider.Passphrase` | MOVE | (*keyprovider.Command).Passphrase |
| `CommandKeyProvider.Token` | MOVE | (*keyprovider.Command).Token |
| `DefaultFIDO2RelyingParty`, `FIDO2SaltLength`, `FIDO2SecretLength` | MOVE | keyprovider.DefaultRelyingParty / SaltLength / SecretLength |
| `DetachDeferred`, `DetachReleased`, `DetachState` | MOVE | loop.Deferred / loop.Released / loop.DetachState |
| `ErrDetachIncomplete` | MOVE | loop.ErrDetachIncomplete |
| `ErrHelperFailed`, `ErrHelperOutput` | MOVE | keyprovider.<same name> |
| `ErrKeyring`, `ErrKeyringBlocked`, `ErrKeyringEntryExists`, `ErrKeyringFailed`, `ErrKeyringKeyNotReleased`, `ErrKeyringQuotaExhausted`, `ErrKeyringUnavailable`, `ErrKeyringUnsupported` | MOVE | dmcrypt.<same name> |
| `ErrNotMounted` | MOVE | filesystem.ErrNotMounted |
| `ErrUnsupportedTokenType` | MOVE | keyprovider.ErrUnsupportedToken |
| `FIDO2Params` | MOVE | keyprovider.FIDO2Params |
| `FilesystemExt4`, `FilesystemFAT32`, `FilesystemXFS`, `FilesystemZFS` | MOVE | filesystem.Ext4 / FAT32 / XFS / ZFS |
| `HelperError` | MOVE | keyprovider.HelperError |
| `HelperError.Error`, `HelperError.Unwrap` | MOVE | Follows its type (see the type row). |
| `IsMounted` | MOVE | filesystem.IsMounted(ctx, target) |
| `MaxMappingNameLength` | MOVE | dmcrypt.MaxNameLength |
| `Mount`, `MountOptions` | MOVE | filesystem.Mount(ctx, MountParams) |
| `NewFIDO2Credential`, `NewFIDO2Salt` | MOVE | keyprovider.NewFIDO2Credential / NewFIDO2Salt |
| `PatternOnes`, `PatternRandom`, `PatternZeros` | MOVE | wipe.Ones / Random / Zeros |
| `StandardDoD3Pass`, `StandardDoD7Pass`, `StandardNIST` | MOVE | wipe.DoD3Pass / DoD7Pass / NIST |
| `TokenTypeSystemdFIDO2` | MOVE | keyprovider.TokenTypeFIDO2 |
| `Unmount` | MOVE | filesystem.Unmount(ctx, target, UnmountFlags) |
| `ValidateMappingName` | MOVE | dmcrypt.ValidateName |
| `WipePattern.String` | MOVE | wipe.Pattern.String |
| `WipeStandard.String` | MOVE | wipe.Standard.String |
| `AcquireFileLock`, `AcquireFileLockTimeout` | UNEXPORT | internal/device: (*Pinned).Lock(ctx, mode) |
| `AFStripes`, `DroppedKindKeyslot`, `DroppedKindToken`, `KeyslotAreaAlignment`, `KeyslotAreaEncryption`, `LUKS2DefaultKeyslotsSize`, `LUKS2DefaultSize`, `LUKS2HeaderDefaultSize`, `LUKS2HeaderMaxOffset`, `LUKS2HeaderMaxSize`, `LUKS2HeaderMinSize`, `LUKS2HeaderSize`, `LUKS2Magic`, `LUKS2MagicLen`, `LUKS2MaxKeyslotsSize`, `LUKS2PrimaryHeaderOffset`, `LUKS2SecondaryHeaderOffset`, `LUKS2SecondaryMagic`, `LUKS2SectorSize`, `LUKS2Version`, `MaxKeyslotKeySize` | UNEXPORT | internal/header |
| `AntiForensic`, `Config`, `Digest`, `KDF`, `Keyslot`, `KeyslotArea`, `LUKS2BinaryHeader`, `LUKS2Metadata`, `Requirements` | UNEXPORT | internal/header (public read model: luks2.Header, KeyslotInfo, Segment) |
| `AntiForensic.MarshalJSON`, `AntiForensic.UnmarshalJSON`, `Config.MarshalJSON`, `Config.UnmarshalJSON`, `Digest.MarshalJSON`, `Digest.UnmarshalJSON`, `KDF.MarshalJSON`, `KDF.UnmarshalJSON`, `Keyslot.MarshalJSON`, `Keyslot.UnmarshalJSON`, `KeyslotArea.MarshalJSON`, `KeyslotArea.UnmarshalJSON`, `Requirements.MarshalJSON`, `Requirements.UnmarshalJSON`, `Segment.MarshalJSON`, `Segment.UnmarshalJSON` | UNEXPORT | Moves with its type to internal/header (JSON codec of the on-disk model). |
| `BenchmarkPBKDF2` | UNEXPORT | internal/kdf.Calibrate(ctx, ...) |
| `BLKDISCARD` | UNEXPORT | internal/device (unix.BLKDISCARD) |
| `CheckOverflow`, `SafeInt64ToUint64`, `SafeUint64ToInt`, `SafeUint64ToInt64` | UNEXPORT | internal/header (guarded narrowing helpers, clean-code 4.3) |
| `CreateBinaryHeader`, `CreateKDF`, `DeriveKeyEnclave`, `WriteHeader` | UNEXPORT | internal/header, internal/kdf (raw header writes leave the public API) |
| `DefaultFIDO2AssertPath`, `DefaultFIDO2CredPath` | UNEXPORT | pkg/keyprovider (defaults behind WithFIDO2Tools) |
| `DigestCalibrationKeyLen`, `DigestIterationTargetMs` | UNEXPORT | internal/kdf |
| `FileLock` | UNEXPORT | internal/device.Locked |
| `FileLock.Release` | UNEXPORT | (*device.Locked).Release |
| `MaxCredentialLength` | UNEXPORT | internal/secret |
| `MaxKeySize`, `MaxSectorSize`, `MinKeySize`, `MinSectorSize` | UNEXPORT | internal/header (reported in ErrInvalidArgument detail) |
| `MinArgon2MemoryKB`, `MinArgon2Parallel`, `MinArgon2Time` | UNEXPORT | internal/kdf (reported through *KDFCostError.Min) |
| `WipeStandard.RequiresVerification` | UNEXPORT | pkg/wipe |
| `ConstantTimeEqual` | DELETE | callers use crypto/subtle.ConstantTimeCompare |
| `CountTokens`, `FindFreeTokenSlot`, `GetToken`, `ListTokens`, `TokenExists` | DELETE | (*Header).Tokens() map; AddToken picks the free slot |
| `CryptoError`, `DeviceError`, `InvalidKeyslotError`, `KeyProviderError`, `KeyslotError`, `MetadataJSONError`, `ProtectedMemoryError`, `UnlockError`, `UnsupportedKeyslotCipherError`, `UnsupportedRequirementError`, `VolumeError` | DELETE | luks2.Error{Op, Path, Kind, Detail, Err}; the data lives in Kind + Detail |
| `CryptoError.Error`, `CryptoError.Unwrap`, `DeviceError.Error`, `DeviceError.Unwrap`, `InvalidKeyslotError.Error`, `InvalidKeyslotError.Is`, `InvalidKeyslotError.Unwrap`, `KeyProviderError.Error`, `KeyProviderError.Is`, `KeyProviderError.Unwrap`, `KeyslotError.Error`, `KeyslotError.Unwrap`, `MetadataJSONError.Error`, `MetadataJSONError.Is`, `MetadataJSONError.Unwrap`, `ProtectedMemoryError.Error`, `ProtectedMemoryError.Is`, `ProtectedMemoryError.Unwrap`, `UnlockError.Error`, `UnlockError.Unwrap`, `UnsupportedFilesystemError.Error`, `UnsupportedFilesystemError.Unwrap`, `UnsupportedKeyslotCipherError.Error`, `UnsupportedKeyslotCipherError.Is`, `UnsupportedRequirementError.Error`, `UnsupportedRequirementError.Unwrap`, `VolumeError.Error`, `VolumeError.Unwrap` | DELETE | Deleted with its type. |
| `DefaultCipherMode` | DELETE | FormatParams.Cipher is one cryptsetup spec, e.g. aes-xts-plain64; DefaultCipher becomes that spec |
| `DetachLoopDevice` | DELETE | (*loop.Device).Detach(ctx) (DetachState, error); loop.Lookup(ctx, "/dev/loopN") yields the Device |
| `ErrAmbiguousJSONMember`, `ErrMetadataJSON` | DELETE | luks2.ErrInvalidHeader with detail |
| `ErrInvalidArgon2Memory`, `ErrInvalidArgon2Parallel`, `ErrInvalidArgon2Time`, `ErrPBKDFIterationsTooHigh`, `ErrPBKDFIterationsTooLow` | DELETE | *luks2.KDFCostError (Is ErrInvalidArgument) |
| `ExecConfig` | DELETE | keyprovider.WithFIDO2Tools / WithDevice options |
| `ExportToken`, `ImportTokenJSON` | DELETE | json.Marshal / json.Unmarshal on luks2.Token |
| `FilesystemExt2`, `FilesystemExt3` | DELETE | unsupported by design (#195); Detect still reports them as filesystem.Type("ext2") |
| `FIPSImportRequiredError.Is`, `HelperError.Is`, `KDFCalibrationError.Is`, `KeyringUnavailableError.Is`, `LockTimeoutError.Is`, `OrphanedKeyslotError.Is` | DELETE | Unwrap() []error {Kind, Err} replaces hand-written Is |
| `GetMappedDevicePath`, `IsUnlocked` | DELETE | dmcrypt.Lookup(ctx, name) -> *Mapping (ErrNotActive); (*Mapping).Path() |
| `GetVolumeInfo`, `VolumeInfo` | DELETE | (*luks2.Volume).Header(ctx) getters |
| `IsFIPSCompliantKDF` | DELETE | operations refuse with ErrFIPSNotApproved; (KDFParams).Validate() for pre-flight |
| `IsLUKS`, `IsLUKS2` | DELETE | (*luks2.Volume).Header(ctx): ErrNotLUKS2 when absent or LUKS1 |
| `KDFTypePBKDF2SHA1`, `KDFTypePBKDF2SHA256`, `KDFTypePBKDF2SHA384`, `KDFTypePBKDF2SHA512` | DELETE | KDFParams{Type: KDFPBKDF2, Hash: crypto.SHA512}; the CLI keeps parsing pbkdf2-sha512 |
| `KillSlot`, `RemoveKey` | DELETE | credential checks are CLI policy: Unlock / UnlockKeyslot, then RemoveKeyslot |
| `LoadRecoveryCredential`, `LoadRecoveryKey`, `SaveRecoveryKey` | DELETE | file I/O moves to internal/cli; library offers (*RecoveryKey).WriteTo and ParseRecoveryKey |
| `LUKS2MaxKeyslots` | DELETE | duplicate of MaxKeyslots |
| `OpenFileSecure` | DELETE | os.OpenFile; device opens go through internal/device |
| `RecoveryCredential` | DELETE | ParseRecoveryKey takes an enclave |
| `ParseLegacyRecoveryKey` | UNEXPORT | parseLegacyRecoveryKey: ParseRecoveryKey is the one public parse (done: unexported in 37078b0; the rc.1 code still exported it, see DECISIONS.md, cr-docs and its correction) |
| `RecoveryKey.FormattedString` | DELETE | (*RecoveryKey).WriteTo(io.Writer): a credential never becomes a Go string |
| `RestorePrimaryHeaderWithOptions`, `RestoreHeaderOptions` | DELETE | Force=true is (*luks2.Volume).ReplacePrimaryHeader(ctx) (no flag argument) |
| `StandardCustom` | DELETE | zero wipe.Params.Standard means custom |
| `TestKey`, `VerifyRecoveryKey` | DELETE | (*luks2.Volume).Unlock(ctx, cred) then (*Key).Destroy |
| `TrimRight` | DELETE | bytes.TrimRight; the NUL-field trim moves to internal/header |
| `UnsupportedFilesystemError` | DELETE | filesystem.Error with Kind filesystem.ErrUnsupported |
| `ValidateDevicePath` | DELETE | luks2.Open validates and pins |
| `WipeKeyslot` | DELETE | same operation as RemoveKeyslot (which always destroys the area) |

### B.7 Disposition of cmd/luks2 exports (nothing stays exported)

| Identifier(s) | Action | Target |
|---|---|---|
| `CLI`, `NewCLI`, `CLI.Run` | UNEXPORT | `internal/cli.Run(ctx, args, stdin, stdout, stderr) int` |
| `LuksOperations`, `DefaultLuksOperations` + its 40 methods | DELETE | The CLI calls the library directly. Rootless commands are tested against real pkg/luks2 on temp files; root commands go through 4 small unexported interfaces (§F). |
| `FileSystem`, `DefaultFileSystem` + 7 methods | DELETE | `os` directly; `removeCreated` stays as an unexported func |
| `Terminal`, `DefaultTerminal` + 2 methods | UNEXPORT | `internal/cli.terminal` |
| `DeviceProber`, `DefaultDeviceProber` + `Kind`, `Claim` | UNEXPORT | `internal/cli.deviceProber` |
| `ParseSize` | UNEXPORT | `internal/cli.parseSize` (distinct from luks2's on-disk size parser) |
| `ClearBytes` | DELETE | input is read straight into an enclave; `enclave.Wipe` for the one terminal buffer |
| `KeySource` | UNEXPORT | `internal/cli.keySource` |
| `ConfirmationError`, `DevicePathError`, `KeyInputError`, `UsageError` + methods | UNEXPORT | internal/cli |
| `ErrDeviceHasData`, `ErrEmptyKeyFilePath`, `ErrKeyFileTooLarge`, `ErrKeyInput`, `ErrNotConfirmed`, `ErrPassphraseMismatch`, `ErrUsage` | UNEXPORT | internal/cli |
| `Version` | UNEXPORT | `main.version`, set with `-ldflags -X main.version=` |

---

## C. Error model

### C.1 One struct type

The struct lives in internal/errs and is aliased in every public package (`type Error = errs.Error`). It is the generalization of today's `detailError`, which already proved the shape across 235 sites.

```go
type Error struct {
	Op     string // exported entry point, "Type.Method" or "Func" (errors.md P2-A spirit): "Volume.AddKeyslot"
	Path   string // device/file the operation was opened on, if any
	Kind   error  // classifying sentinel, NEVER nil (a public Err*, or context.Canceled/DeadlineExceeded)
	Detail string // which object and why, in words (fmt.Sprintf allowed; it is not an error)
	Err    error  // typed cause (*fs.PathError, unix.Errno, *enclave.LockedMemoryError, ...) or nil
	pkg    string // "luks2", "dmcrypt", ... (prefix)
}
func (e *Error) Error() string   // "<pkg>: <Op> <Path>: <kind text>[: <Detail>][: <Err>]"
func (e *Error) Unwrap() []error // {Kind, Err}
```

### C.2 Rules

1. **Typed only.** `fmt.Errorf` and inline `errors.New` are banned in pkg/, internal/ and cmd/ (errors.md §2). golangci `forbidigo` enforces it. `errors.New` is allowed only in the `errors.go` sentinel block of each package.
2. **Sentinels vs structs.** A sentinel exists if and only if a caller can act on it differently: a remedy, a retry, an exit code, a prompt. A struct type exists if and only if it carries data a caller needs programmatically (errors.md §1). Everything else is `Kind` + `Detail`. Hand-written `Is` methods go: `Unwrap() []error` makes both Kind and Err matchable.
3. **Strings.** Sentinel text is lowercase with the package prefix: `errors.New("luks2: no room in the keyslots area")`. `Error()` prints the prefix once and strips it from the Kind text when composing. There is no trailing punctuation. Remedies stay in `Detail`, as now.
4. **Wrapping.** Internal packages return `*errs.Error` with Kind set and Op empty. Each exported entry point calls `errs.At(op, path, err)` once on the way out. It fills Op and Path if empty and never stacks a second wrapper (errors.md §3: once per layer boundary, never reclassify). A different classification means a new Error.
5. **ctx errors.** `Kind = ctx.Err()`, so `errors.Is(err, context.DeadlineExceeded)` holds.
6. **Shared device kinds** are defined once in internal/device and re-exported by value (`var ErrDeviceInUse = device.ErrInUse`, errors.md §4) from luks2, wipe and dmcrypt. They read "luks2:" because they originate in the module's device layer.

### C.3 Public sentinels and types

| Package | Sentinels | Error types |
|---|---|---|
| luks2 | `ErrInvalidArgument`, `ErrInvalidCredential`, `ErrNotLUKS2`, `ErrInvalidHeader`, `ErrUnsupported`, `ErrUnsupportedRequirement`, `ErrNoSpace`, `ErrWrongKey`, `ErrNoKeyslots`, `ErrKeyslotNotFound`, `ErrLastKeyslot`, `ErrKeyslotAreaOverlap`, `ErrTokenNotFound`, `ErrPrimaryHeaderCurrent`, `ErrKeyProvider`, `ErrOrphanedKeyslot`, `ErrFIPSNotApproved`, `ErrFIPSImportRequired`, `ErrFIPSMigration`, `ErrKDFCalibration`, `ErrProtectedMemory`, `ErrIO`, `ErrReadOnly`, `ErrClosed`; shared: `ErrDeviceNotFound`, `ErrPermissionDenied`, `ErrDeviceInUse`, `ErrDeviceChanged`, `ErrDeviceCacheStale`, `ErrLockContended`, `ErrMetadataLockUnavailable` | `Error`, `LockTimeoutError{Path, Waited, Attempts}`, `KDFCostError{Param, Value, Min, Max}` (Is `ErrInvalidArgument`), `KDFCalibrationError{Hash, Target, Probe, Elapsed}`, `FIPSImportRequiredError{Path, Keyslots, Digests}`, `FIPSMigrationError{Path, Stage, State}`, `OrphanedKeyslotError{Keyslot, Cause}` |
| dmcrypt | `ErrActive`, `ErrNotActive`, `ErrBusy`, `ErrStillLive`, `ErrInvalidName`, `ErrNodeUnverified`, `ErrKeyring`, `ErrKeyringUnavailable`, `ErrKeyringBlocked`, `ErrKeyringUnsupported`, `ErrKeyringQuotaExhausted`, `ErrKeyringFailed`, `ErrKeyringEntryExists`, `ErrKeyringKeyNotReleased`; shared `ErrPermissionDenied` | `Error`, `KeyringError` |
| keyprovider | `ErrInvalidArgument`, `ErrHelperFailed`, `ErrHelperOutput`, `ErrNoDevice`, `ErrInvalidBinding`, `ErrUnsupportedToken` | `Error`, `HelperError` |
| loop | `ErrNotFound`, `ErrDetachIncomplete`, `ErrNodeAbsent`; shared `ErrPermissionDenied` | `Error` |
| filesystem | `ErrInvalidArgument`, `ErrUnsupported`, `ErrNotDetected`, `ErrTool`, `ErrNotMounted` | `Error`, `CommandError` |
| wipe | `ErrVerification`; shared `ErrDeviceInUse`, `ErrDeviceChanged`, `ErrPermissionDenied`, `ErrLockContended` | `Error` |

### C.4 Mapping the 191 `fmt.Errorf` and 235 `detailError` sites

The rules are mechanical, with per-site review:

| Today | Count | Becomes |
|---|---|---|
| `fmt.Errorf("%w: …", ErrX, …)` | ≈110 | `errs.New(kind(ErrX), detailf)`. kind() is the consolidation in B.6, e.g. ErrKeyslotsAreaFull→ErrNoSpace. |
| `fmt.Errorf("failed to <verb>: %w", err)` | ≈60 | `errs.Wrap(ErrIO \| ErrPermissionDenied \| ErrDeviceNotFound, "<verb>", err)`. internal/device classifies open errors (as classifyDeviceOpen does now). |
| `fmt.Errorf("<message>")`, no wrap | ≈18 | `errs.New(ErrInvalidArgument, msg)` |
| `var ErrX = fmt.Errorf(…)` | 3 | `errors.New("luks2: …")` |
| `&detailError{Kind, Detail, Err}` | 235 | `errs.Error` (field-compatible; Kind nil→explicit kind) |
| `DeviceError`/`VolumeError`/`KeyslotError`/`CryptoError`/`UnlockError` | — | `errs.Wrap` with Op set at the boundary |

`fmt.Errorf` in test/ stays (74 sites; errors.md §2 permits it).

---

## D. Context plumbing

### D.1 Who takes ctx

Every function in §B that does I/O, takes a lock, runs a KDF, or execs takes ctx. These do not: `Close`, `Path`, the `Header`/`Key`/`RecoveryKey` accessors, `NewRecoveryKey` (CSPRNG only), `ParseRecoveryKey`, the `Validate*` functions, `Supported`, and `String`.

### D.2 Where cancellation is observed

| Blocking point | Mechanism |
|---|---|
| Node flock, cryptsetup lock (`device.Lock`) | Poll with backoff. Each wait is `select { <-ctx.Done(); <-clk.NewTimer(backoff).C() }`. Budget = `WithLockWait` (default 30 s), measured on the clock. Returns `LockTimeoutError` on budget, `ctx.Err()` kind on cancel. |
| KDF (argon2.IDKey, crypto/pbkdf2.Key) | **Not interruptible**, and not wrapped in an abandoned goroutine: go-style requires a shutdown path for every goroutine, and an orphan would keep deriving into memory nobody supervises. ctx is checked before each derivation, between keyslots in a scan, between digest checks, and between calibration probes. A derivation in flight finishes (bounded by the per-derivation ceiling and g-compat's aggregate `checkKDFBudget`), its output is destroyed, and `ctx.Err()` is returned. Hand-rolled interruptible PBKDF2 is rejected: it would leave the Go FIPS module's approved service. |
| Write transactions (keyslot add/change/remove, token, header, FIPS migration) | ctx is consulted only at step boundaries where the on-disk state is consistent: the `keyslotWriteStep` boundaries the crash suite enumerates. Once a transaction's first write lands, it runs to its next consistent state, then honours cancellation. |
| Format random fill, Erase, wipe passes, wipe verify | ctx checked per 1 MiB chunk. A cancelled sanitize returns `ctx.Err()` kind with `Detail` stating bytes written. |
| dm busy-retry, `/dev/mapper` readiness, node placement, loop node wait, loop detach wait | Poll-until-condition re-checking the real state each pass (go-style's permitted form): `select` on ctx and a clock timer. Budgets are unchanged and measured on the clock. |
| dm rollback after a failed or cancelled Activate | `context.WithoutCancel(ctx)` plus its own clock budget. Cleanup of plaintext devices is never cancellable. |
| exec (helpers, mkfs, fsck, blkid, zpool) | `exec.CommandContext` + `Setpgid` + `Cancel` killing the process group + `WaitDelay` (internal/command). |
| `KeyProvider.Passphrase` | The provider's own ctx contract. It is called before any mutex or lock. |

### D.3 Clock

`internal/clock.Clock` is `{ Now() time.Time; NewTimer(d time.Duration) Timer }`, where `Timer` has `C() <-chan time.Time; Stop() bool`.

`Sleep` is removed. go-style bans `time.Sleep`, and a sleep cannot observe ctx.

**Library budgets are measured on the clock. Caller deadlines arrive only through `ctx.Done()`.** `ctx.Deadline()` is never compared with `clk.Now()`, so a fake clock stays deterministic and a real deadline still fires.

`clock.Fake` (Advance, BlockUntilWaiters) lives in internal/clock as non-test code, so test/integration and test/internal/harness reuse it. harness's own clock.go is deleted (DRY).

The clock is a field of each handle's unexported `sys` struct (§E). It is never a public option.

---

## E. Tests

**Unit tests** live beside source in every package, white-box where needed (testing-guidelines), with `//go:build !integration` as today. The rootless core makes most pkg/luks2 and internal/cli tests real: temp files with minimum legal cost (argon2id m=64 MiB t=1 p=1, or PBKDF2 at the floor).

**Seams become structure.** All 35 package-level mutable vars become fields of an unexported `sys` struct:

- `Volume.sys`, plus dmcrypt's, loop's, filesystem's and keyprovider's equivalents.
- Each is defaulted in the constructor and overridden only by in-package tests.
- internal packages take their seams as parameters or struct fields.

This removes global state (tests can `t.Parallel()`) and makes "no production code path can flip a seam" structural. Enforcement: a test in test/makefile parses pkg/ and internal/ and fails on any package-level `var` of func or interface type outside `errors.go` and `const`-like tables.

**Integration tests** follow integration-testing §3: they live under `test/integration/<package>/`, `//go:build integration`, run in the devcontainer, with no skip guards.

| From | To |
|---|---|
| 15 black-box `pkg/luks2/*_integration_test.go` (argon2interop, format, header, info, keyslotpriority, keyslotsafety, loopdev, persistence, pinnedpaths, release, root, token, unlock, volumename, wipe, workflow) | `test/integration/{luks2,dmcrypt,loop,wipe}/` by package under test, converted to the new API. `pinnedpaths_integration_test.go`'s white-box retargeted-symlink tests are a second, permanent file of the same base name -- see below -- and do not move with this row. |
| 10 white-box files (activation, filesystem, headervalidation, kdfiterations, keyring, laned, leakledger, mount, unlockreadlock -- **not** canonicalconformance, see below) | `test/integration/{dm,keyring,header,kdf,device,filesystem}/`. Their unexported identifiers become exported-within-internal API, which test/ can import because it is in the same module. |
| g-compat's compatmatrix -- **not** lockcompat or lockwait, see below | `test/integration/interop/`: cryptsetup and systemd are the real peer (testing-guidelines), both directions |
| `test/integration/pkg/*` | split into `test/integration/<pkg>/` |
| `test/harness`, `test/labstrings` | `test/internal/harness`, `test/internal/labstrings` (only test/ may import them) |
| `test/covergate`, `test/*/cmd/*`, `test/integration/cmd/docker-run` | `test/tools/<name>/` |

**Four white-box integration files stay in `pkg/luks2`, permanently** (H13d,
ratified): `canonicalconformance_integration_test.go`,
`lockcompat_integration_test.go`, `lockwait_integration_test.go` and
`pinnedpaths_integration_test.go`. Each needs a hook the public API must
never expose -- `cryptoRand`/`newUUID`/`digestIterationsFor` (determinism:
byte-for-byte conformance against a cryptsetup-written golden image),
`calibratedCountFloor` (a cheap KDF cost so a real-cryptsetup-interop lock
test runs in budget), `fileLockHeld` (simulating a lock already held, to
drive wait behaviour), and `openFileFunc` (retargeting a symlink the instant
it is first opened, to prove a writer stays on the descriptor it locked) --
and exporting any of them, even "within-internal API" as the row above
describes for the general case, would make a security- or
determinism-relevant seam of a Layer 0 library reachable from outside it.
This is the deviation from this section's "integration tests live under
`test/integration/`" rule the H12c/H13 entries in DECISIONS.md deferred and
H13d ratifies: these four build a `Volume`/call the unexported
`*WithSys`-suffixed core directly, with a `volumeSys` they construct and
override, exactly as an in-package unit test does, and stay
`//go:build integration` so they still run in the devcontainer with real
loop devices/cryptsetup. Nothing else qualifies for this exception without
the same two-part test: the hook is a correctness-or-security-relevant seam
of this package specifically, and no shape of exported API could carry it
without exposing it to every caller.

**CLI parity** (integration-testing §5, §9 floor): `test/integration/cli/commands/` holds a `CommandDefinition`/`ArgDefinition` table owned per command group. A runner crosses it with the columns {CLI binary, embedded (library calls)}. An enumerating test fails when a registry verb has no definition (P2 recommendation), and the `cli.md` verbs are the same list.

**Coverage.** The 90% per-package floor applies. Root-only packages (dmcrypt, loop, filesystem, internal/dm, internal/keyring) gate on the combined unit+integration tier, as pkg/luks2 does now. `coverage-floors.txt` gains one row per package.

---

## F. CLI

```
cmd/luks2/main.go        ctx := signal.NotifyContext(SIGINT, SIGTERM); os.Exit(cli.Run(ctx, os.Args, os.Stdin, os.Stdout, os.Stderr))
internal/cli/
  cli.go        Run, env{stdin,stdout,stderr,term,host}, registry, dispatch, top-level usage
  command.go    type command struct{ name, synopsis, usage string; run func(ctx, *env, []string) error; sub map[string]*command }
  exit.go       error -> exit code table (errors.Is over a slice; map-based, go-style)
  flags.go      the interspersed-flag parser (was options.go)
  keyinput.go   passphrase / --key-file / stdin -> enclave
  confirm.go    YES confirmation + signature probe (was destructive.go)
  kdfflags.go   --pbkdf etc. -> luks2.KDFParams (accepts pbkdf2-sha512 spelling)
  size.go       parseSize
  host.go       the root-only boundary: activator, looper, mounter, mkfs (unexported 1-3 method interfaces; real impls wrap dmcrypt/loop/filesystem)
  create.go     create (file and block device)
  volume.go     open, close, info, isluks
  mount.go      mount, unmount
  keyslot.go    keyslots, testkey, addkey, changekey, removekey, killslot
  recovery.go   recovery generate|add|verify (file I/O for recovery keys lives here now)
  token.go      token list|show|export|import|remove|free|exists|count
  header.go     header show|secondary|restore
  wipe.go       wipe (Erase by default, --full -> wipe.Sanitize)
```

**Dispatch** is a `map[string]*command`. Groups carry a nested `sub` map. An unknown verb returns `ErrUnknownCommand` (go-style: map-based dispatch with a typed miss). Every handler returns `error` and never prints its own failure; `Run` prints once and maps the exit code.

**Exit codes follow cryptsetup(8)**, because the owner direction is "compatible with cryptsetup's behaviour":

- 0: success.
- 1: wrong parameters (usage errors, `ErrInvalidArgument`).
- 2: no permission or bad passphrase (`ErrWrongKey`, `ErrInvalidCredential`, `ErrPermissionDenied`).
- 3: out of memory (`ErrProtectedMemory`).
- 4: wrong device (`ErrDeviceNotFound`, `ErrNotLUKS2`, `ErrInvalidHeader`).
- 5: exists or busy (`dmcrypt.ErrActive`, `ErrBusy`, `ErrDeviceInUse`, `ErrLockContended`).

`isluks` and `token exists` keep 0/1.

**Tests.** Nothing is exported "for testing", and testing goes through `Run`. Rootless verbs run against real temp-file volumes. Root verbs are tested through fake `host` interfaces. No file exceeds about 400 lines (cli.go is 1297 today). Help text sits next to each command's definition, so `usage` is built from the registry and cannot drift from it.

---

## G. Docs, Makefile, scaffold

### G.1 Docs

Feature folders follow feature-docs §1. There is one per CLI command group, per feature-docs P1's recommendation. Each folder has all five files plus a status banner and `Last verified:`.

| New folder | Absorbs |
|---|---|
| `docs/volumes/` | ARCHITECTURE.md (packages/DAG, key custody, keyring, device layer, trust boundaries), luks/README.md, luks/encryption.md, cli/{create,open,close,mount,unmount,info,key-input}.md |
| `docs/keyslots/` | luks/keyslots.md, luks/kdf.md, cli/keyslots.md |
| `docs/recovery-keys/` | cli/recovery.md + recovery sections of luks/keyslots.md |
| `docs/tokens/` | luks/tokens.md, luks/keyprovider.md, cli/token.md |
| `docs/header/` | luks/header.md, cli/header.md |
| `docs/wipe/` | cli/wipe.md |
| `docs/fips/` | FIPS.md (`cli.md`: --pbkdf behaviour; "MigrateToFIPS: no CLI verb, library only") |
| `docs/cryptsetup-interop/` | COMPATIBILITY.md interop matrix; TESTING.md interop parts |
| `docs/README.md` | index, versioning policy (from COMPATIBILITY.md), migration state (feature-docs §9) |

Other content moves as follows:

- TESTING.md goes into each `engineering.md` test-strategy section and a new `test/integration/CLAUDE.md` + `AGENTS.md`.
- RELEASABILITY.md goes into `test/internal/labstrings` package documentation.

Further rules for the docs:

- `api.md` gives the Go API, the embedded transport, per capability. It states "REST/gRPC/QUIC/MCP/Unix: not applicable, Layer 0 library (docs/00 L1 exemption)".
- `engineering.md` of `volumes/` carries the lock-order invariant, the error table, the ctx table and the residual raw-bytes list. That list mirrors `internal/secret`'s package documentation, which becomes the canonical copy.
- CLAUDE.md and AGENTS.md change at the root: the canonical list moves from `pkg/luks2/enclave.go` to `internal/secret`. A new level is added at `cmd/` and `test/integration/` (scaffold §7).
- The legacy files are deleted in the same commits (feature-docs §9).

### G.2 Makefile

Existing targets are kept. These are added to complete the scaffold §4 contract:

- `vuln`: an alias of govulncheck.
- `coverage-report`: HTML + func summary from the gated profiles.
- `docker-build` / `docker-run`: the CLI image from `build/docker/cli`, run with the integration seccomp profile.
- `proto`: honest no-op, `@echo "no .proto sources (Layer 0 library)"`.
- The per-package quartet as pattern rules over a `PKG_<name>` path map covering every pkg/ and internal/ package: `test-%`, `coverage-%`, `integration-test-%`, `bench-%`.
- `test-pkg PKG=` (testing-guidelines).
- `integration-test-%` runs in the devcontainer.
- `bench-%` covers kdf, af, areacipher, header and wipe.
- `make build` adds the darwin cross-compile of pkg/luks2 + pkg/keyprovider (§A.3).

### G.3 Lint

Add `depguard` (§A.2) and `forbidigo` (`fmt.Errorf`, `errors.New` outside errors.go, `time.Sleep`).

### G.4 Scaffold

- `build/docker/` holds the Dockerfiles.
- `changelog.d/<issue>-api-redesign.md` with `BREAKING:`.
- `VERSION` becomes `0.5.0-alpha`.
- `coverage-floors.txt` gets new rows.
- The CI workflows change only their package paths; the ci-template instance is untouched.

---

## H. Execution plan

The plan runs on one branch, `issue/<n>-api-redesign`, after `fix/g-compat` merges. **pkg/luks2 is frozen on main from H5 until merge**; any other PR there rebases after.

Every step ends with `make ci` green (unit + lint + gosec + vuln + coverage gate). The steps marked ◆ also run `make integration-test` in the devcontainer. Transitional type aliases and forwarding functions are allowed only *inside* the branch and are all removed in H13.

Estimates are focused agent-days.

| # | Step | Est. | Depends on |
|---|---|---|---|
| H0 | Rebase on main post-g-compat; record baseline coverage, unit runtime and the exported-identifier dump (the B.6 script, checked in under test/tools as the API diff gate) | 0.25 | — |
| H1 | `internal/errs`. Make `detailError` an alias. Convert all 191 `fmt.Errorf` + 235 `detailError` sites mechanically with **existing** sentinels (no API change). Enable forbidigo. | 1.5 | H0 |
| H2 | `internal/clock` (Now/NewTimer). Replace `clock.Sleep` with timer+select. `clock.Fake`. harness reuses it. | 0.5 | H0 |
| H3a–f | Leaf extractions, each with its tests and seams→params: `secret`, `fips`, `af`, `areacipher`, `recoverykey`, `command` | 0.3 each | H1 |
| H4 | `internal/kdf` (derive, calibrate, floors, g-compat `kdfbudget`, sha1kdf). luks2's `KDF` JSON ↔ `kdf.Params`. | 1.0 | H3a,b |
| H5 ◆ | `internal/header` (types, codec, validation, unknown members, checksum, requirements, segment/keyslot checks, scan order). pkg/luks2 keeps transitional aliases (`type LUKS2Metadata = header.Metadata`). | 2.5 | H4 |
| H6 ◆ | `internal/device`: Pinned/Locked/Claimed, flock→cryptsetup→claim, medium reads, size, shared sentinels. `keyslotDevice`, Format and Wipe re-based on it. `requireSameDevice` deleted. | 1.5 | H1, H2 |
| H7 ◆ | `internal/dm`, `internal/keyring` extracted. pkg/luks2 still calls them, temporarily. | 1.0 | H1, H2 |
| H8 | ctx through every internal layer (§D). Exported functions pass `context.Background()` for this step only. | 1.5 | H5–H7 |
| H9 | New pkg/luks2 API (Volume, Key/volkey, Header, params, Target) **beside** the old. Old functions re-implemented as thin calls into it. | 3.0 | H8 |
| H10a–e ◆ | Public packages, each moving code and tests: `dmcrypt` (1.0), `loop` (0.5), `filesystem` (0.75), `keyprovider` (1.0), `wipe` (0.5). Old luks2 functions forward to them. | 3.75 | H9 |
| H11 | `internal/cli` rewrite: split by command, map dispatch, exit table, new API only, real-volume unit tests, host interfaces. cmd/luks2 shrinks to main.go. | 2.0 | H10 |
| H12 ◆ | Test relocation (§E table). Convert black-box tests to the new API. `test/internal`, `test/tools`. CommandDefinition table + runner + enumerating test. | 2.5 | H10, H11 |
| H13 | Delete the old API and transitional aliases. Consolidate sentinels to §C.3. `depguard` on. Seam-var enforcement test on. API-diff gate checks B.6. | 1.0 | H11, H12 |
| H14 | Makefile contract, coverage floors, build/docker, CI paths | 1.0 | H13 |
| H15 | Docs feature folders, CLAUDE.md/AGENTS.md (3 levels), README quick start, changelog fragment, VERSION | 2.0 | H13 |
| H16 | Consumer issues filed on go-trusted-platform and go-xkms (cross-project rule) with the B.6 table as the migration map | 0.25 | H13 |

The total is about 27 agent-days serial and about 15 calendar days with the parallel lanes below.

**Parallel without conflicts.** Each lane is a worktree producing commits that are cherry-picked in table order. Lanes touch disjoint source files; call-site edits in shared files are deferred to the integrating commit.

- **Lane set 1** runs after H1: H2 ∥ H3a–f ∥ H7. These are disjoint files: clock.go; enclave.go, antiforensic.go, format.go's XTS half, recovery.go's render half, systemtool.go; devicemapper.go, keyring.go.
- **Lane set 2** runs after H4: H5 ∥ H6. H5 touches header/validation files; H6 touches security.go, cryptsetuplock.go, medium.go, keyslotdevice.go. The shared constant `LUKS2HeaderMaxSize` is imported from header by H6 after H5 lands.
- **Lane set 3** runs after H9: H10a–e are mutually independent. H14 and the H15 docs skeleton can start once H9 fixes the API.
- **Serial points**: H8, H9, H11, H13. These are the steps that change signatures across the tree.

---

## I. Risks and decisions for the owner

1. **Freeze window (decision).** pkg/luks2 must take no other changes on main from H5 to merge, about 2 calendar weeks. The alternative is to accept repeated rebases of a 20k-line move, which is where moved-code regressions hide. Approve the freeze, or name the lanes that must keep landing.
2. **Feature-doc granularity (decision).** §G.1 follows feature-docs P1's *unratified* recommendation: one folder per CLI command group. Feature folders are requirements, and feature-docs §7 makes their shape the owner's call, so confirm or override before H15.
3. **Consumer break (risk, no decision needed).** go-trusted-platform (15 files) and go-xkms/xkey (7 files) stay pinned to v0.1.7-alpha, and both need Go 1.27.1, until they migrate under the H16 issues (filed: jeremyhahn/go-trusted-platform#746 and jeremyhahn/go-xkms#1427). Two behavioural points they must absorb:
   - The volume key is no longer extractable: no consumer extracts it today.
   - Credentials are enclaves, not `[]byte`.

Every other choice in this document has been made and is not open: package set, Volume/Key model, unauthenticated-but-guarded `RemoveKeyslot`, cryptsetup exit codes, error shape, KDF non-interruption, `pkg/` placement, and darwin portability via `make build`.

# Volumes — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-12 against 7ee49b8
> Conflicts with this document are defects. Fix them here first.

The volume lifecycle: creating a LUKS2 container, unlocking it to a
dm-crypt mapping, mounting a filesystem on it, and tearing both down. Keyslot,
recovery-key, token, header-copy and wipe detail each have their own folder;
this one covers the container as a whole, the device layer under it, and the
key-custody boundary every other feature relies on.

| Folder | Covers |
|---|---|
| [keyslots](../keyslots/architecture.md) | Keyslot structure, KDF, cost inheritance |
| [recovery-keys](../recovery-keys/architecture.md) | Generated recovery credentials |
| [tokens](../tokens/architecture.md) | Header token metadata, key providers |
| [header](../header/architecture.md) | On-disk layout, binary header, JSON metadata |
| [wipe](../wipe/architecture.md) | Crypto-erase and full-device sanitization |
| [fips](../fips/architecture.md) | FIPS 140-3 mode and `MigrateToFIPS` |
| [cryptsetup-interop](../cryptsetup-interop/architecture.md) | Compatibility policy, the interop matrix |

## The problem and the shape chosen

A LUKS2 consumer that shells out to cryptsetup gets the protected-memory
guarantee for free: the master key is derived, held and handed to the kernel
inside a separate process whose address space the caller cannot read, and
which exits. go-luks2 does the work in
process instead — no `cryptsetup` binary, no `exec` in the core — so the
rootless core can run in places a setuid helper cannot, at the cost of
providing the protected-memory guarantee itself (see "Key custody", below, and
[engineering.md](engineering.md)).

The public surface is six packages, split along trust boundaries so a
consumer imports, and trusts, only what it uses:

- `pkg/luks2` is the rootless, exec-free core. Opening, formatting and
  unlocking a container needs neither root nor an external binary.
- `pkg/dmcrypt` holds activation, which needs root and the kernel keyring.
  Keeping it out of `pkg/luks2` is what keeps the core rootless.
- `pkg/keyprovider` holds the providers that exec a helper. `luks2.KeyProvider`
  is defined in `pkg/luks2`, where it is consumed, so the core stays exec-free
  while providers that exec live beside it.
- `pkg/loop`, `pkg/filesystem` and `pkg/wipe` do not depend on LUKS2 at all
  (their depguard rules allow none of the `pkg/` packages) and each has a
  trust boundary of its own: loop ioctls, mkfs and mount, whole-device writes.

Rejected alternatives for the package split:

- **A single `host` package** combining device-mapper, loop and mount ioctls
  with external-command execution. Rejected: it would mix the exec trust
  boundary with ioctl code and drag `exec` into every importer, including
  ones that only ever open block devices.
- **A public `fips` package.** Rejected: FIPS mode is a process property, not
  a thing to configure per call, and migrating a volume into FIPS compliance
  is a `Volume` operation, not a separate subsystem.

## Component boundaries

| Path | Role |
|---|---|
| `pkg/luks2` | The container + volume API: `*Volume` (`Open`, `Format`, `Unlock*`, keyslots, tokens, recovery keys, FIPS migration, header reads). No root, no exec. |
| `pkg/dmcrypt` | Activation: kernel keyring + device-mapper (root). `Activate` calls `(*Volume).Target`. |
| `pkg/keyprovider` | `KeyProvider` implementations that exec helpers (`Command`, FIDO2). |
| `pkg/loop` | Loop devices (root). |
| `pkg/filesystem` | mkfs / fsck / blkid (exec) and mount(2) / umount(2) (root). |
| `pkg/wipe` | Whole-device sanitization. |
| `cmd/luks2` | `main.go` only: a signal context in, `internal/cli.Run`, `os.Exit`. |
| `internal/cli` | The CLI ([cli.md](cli.md)). Built on the `Volume` API, `pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem` and `pkg/wipe`. Root-only boundaries (activation, loop devices, mounting) sit behind small unexported interfaces so unit tests run without root. It holds no LUKS2 logic of its own. |
| `internal/errs`, `internal/clock`, `internal/secret`, `internal/fips`, `internal/af`, `internal/areacipher`, `internal/kdf`, `internal/header`, `internal/recoverykey`, `internal/volkey`, `internal/command`, `internal/device`, `internal/dm`, `internal/keyring` | Leaf packages below the public API. |

Runtime dependencies: `github.com/jeremyhahn/go-enclave` (locked memory),
`github.com/anatol/devmapper.go` (device-mapper ioctls), `golang.org/x/crypto`
(Argon2, XTS), `golang.org/x/sys`, `golang.org/x/term`, `github.com/google/uuid`.

`depguard` enforces this layout mechanically: `.golangci.yml`'s `depguard` settings carry one rule per
package, each listing the in-module packages it may import.
`pkg/luks2`'s allow list names none of `github.com/anatol/devmapper.go`,
`pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`, `pkg/wipe`, `pkg/keyprovider`,
`internal/dm`, `internal/keyring` or `internal/command`, and it additionally
denies `os/exec`, so the core cannot regain root or exec without a red lint.

`make api-diff` (`test/tools/apidump` against
`test/tools/apidump/baseline/disposition-luks2.tsv`) is the mechanical check
that every export recorded in `test/tools/apidump/baseline/luks2.tsv`, the
earlier `pkg/luks2` surface, went where its
disposition row says: a `KEEP` row (`ErrDeviceChanged`, for one) is still
exported under its name, and a `RENAME`, `MOVE`, `UNEXPORT` or `DELETE` row
is gone under its old one (`ErrIntegerOverflow` became
`ErrInvalidArgument`). Exports added since, such as `DefaultKDFSpec` and
`LegacyToken`, are not in the baseline, and the check does not see them.

## Portability

`pkg/luks2` and `pkg/keyprovider` build on Linux and darwin: `make build`
cross-compiles both for `darwin/amd64` and `darwin/arm64`, so a change that
breaks the darwin build fails the build target. Reading a header, formatting
an image file and unlocking a key need nothing Linux-specific.

The Linux-specific device calls live in `internal/device`, each in a
`*_linux.go` file with a `//go:build !linux` sibling in `*_other.go`:

| Call | Linux | Elsewhere |
|---|---|---|
| Device size (`size_linux.go`) | `BLKGETSIZE64` on a block device | The file's stat size |
| Uncached read (`medium_linux.go`) | `O_DIRECT` read past the page cache | `ErrUnsupported` |
| Discard (`discard_linux.go`) | `BLKDISCARD` | No-op |
| Cache drop (`drop_linux.go`) | `posix_fadvise(FADV_DONTNEED)` | No-op |

`pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`, `pkg/wipe` and the CLI are not
part of the darwin build: device-mapper, the kernel keyring, loop ioctls and
mount(2) exist only on Linux, and `pkg/loop` and `pkg/filesystem` carry
`//go:build linux`. Windows is out of scope for every package: the device and
cryptsetup-compatible locks are `flock(2)` (`internal/device/lock.go`,
`internal/device/cryptsetuplock.go`).

## Data flow

### Format

Draw the master key into an enclave, create the keyslot KDF, derive the
passphrase key, create the PBKDF2 digest, AF-split the master key (4000
stripes), encrypt the stripes with AES-XTS, wipe any old header copies, write
the keyslot material, fill the rest of the keyslots area with random bytes,
sync, and write both header copies last (each synced), so no header ever
names a keyslot that is not yet on the device. Cipher and AF detail:
[keyslots](../keyslots/architecture.md).

### Unlock

`(*Volume).Unlock` takes cryptsetup's read lock (`LOCK_SH` on the device, then
on `/run/cryptsetup/L_<maj>:<min>`), so a writer holding it exclusively is
waited for; reads the header, size and keyslots through the pinned descriptor;
refuses an unimplemented mandatory requirement or more than one segment; tries
only keyslots bound to the crypt segment (`prefer` before `normal`, each in
ascending number, never `ignore`; see
[keyslots](../keyslots/architecture.md#data-flow-unlock-order)); derives, decrypts, AF-merges and verifies against that segment's digest;
and releases the read lock. It returns a `*Key` and touches no device-mapper
state. `Volume.UnlockWithVolumeKey` skips the keyslots and verifies the
caller's key against the segment's digest.

`dmcrypt.Activate` then validates the mapping name, creates the dm target and
loads a dm-crypt table that names the device as `major:minor` and references
the key in the kernel keyring, and waits until `/dev/mapper/<name>` carries the
target's device number.

If any step after this call's own create fails, the target is removed if it
still carries the dm UUID and the device number that create returned. A create
refused because the name is taken rolls nothing back (`dmcrypt.ErrActive`). If
the rollback cannot complete, the error matches `dmcrypt.ErrStillLive`.

### Volume, Target and activation

A `*luks2.Volume` handle (`Open`) pins one descriptor and nothing else; every
method takes the lock it needs on that descriptor, does its I/O, and releases
the lock — no lock is held between calls, matching cryptsetup's own
behaviour. Unlock and activation are two calls: `(*Volume).Unlock(ctx, pass)
(*Key, error)` derives and verifies the key without touching dm-crypt, and
`dmcrypt.Activate(ctx, v, key, name)` calls `v.Target(ctx, key)` (re-reads the
header under the shared lock and re-verifies the key against its digest, so a
header rewritten since Unlock, or another volume's key, is refused with
`ErrWrongKey`; the lock is released before the table is loaded) before mapping the pinned descriptor's major:minor. Rollback after a failed or
cancelled `Activate` runs under `context.WithoutCancel(ctx)` with its own
clock budget, so a cancelled caller never leaves a plaintext device behind.

The lock order and the write path are type properties, not a calling
convention. `internal/device` implements `Pinned` (read-only),
`Pinned.Lock(ctx, mode) *Locked` (node flock, then the cryptsetup lock) and
`Locked.Claim(ctx) *Claimed` (O_EXCL by reopening `/proc/self/fd/N`, so the
claim targets the locked inode by construction). Every `*Volume` write method (`Format`, `AddKeyslot`,
`ChangeKeyslot`, `RemoveKeyslot`, `AddToken`, `SetToken`, `RemoveToken`,
`AddRecoveryKey`, `Enroll`, `MigrateToFIPS`, `RestorePrimaryHeader`,
`ReplacePrimaryHeader`, `Erase`) takes its lock through `v.lockFor(ctx,
device.LockExclusive)` and, where it needs an O_EXCL write, claims the
descriptor with `locked.Claim(ctx, ...)`; `Volume` is safe for concurrent use
through an internal `sync.RWMutex` (`v.mu`, shared for reads, exclusive for
writes), with `KeyProvider.Passphrase` called before the mutex or any file
lock is taken.

## Key custody

The library does LUKS2 work in process, so key material shares the caller's
address space. Shelling out to cryptsetup kept it in a separate process; here
the library has to protect it itself.

- Every key it derives or recovers lives in a go-enclave `*enclave.Memory`
  (mlock'd, guard-paged, wiped on release) and is only borrowed through
  `WithBytes` for the call that needs it. That covers the master key, derived
  keys, AF stripes, digest inputs and recovery credentials.
- If locked memory cannot be had, the operation fails with `ErrProtectedMemory`.
  There is no fallback to the heap.
- Credentials cross the API as enclaves too: `Format`, `Unlock`,
  `UnlockKeyslot`, `AddKeyslot`, `ChangeKeyslot` and `ParseRecoveryKey` take a
  `*enclave.Memory` the caller owns and the library only borrows.
- Not enclaved, on purpose: encrypted keyslot material (it is on disk in that
  form), and salts and digests (cleartext header fields).
- Plain bytes that reach the library from outside, before any enclave exists:
  the CLI's terminal prompt and `--key-file` input, `keyprovider.WithStdin`
  (non-secret helper input only), and the `[]byte` credential id
  `keyprovider.NewFIDO2Credential` returns (not secret).
- Raw bytes that cannot be avoided inside the library: the PBKDF2 password
  (`pbkdf2.Key` takes a `string`, and copies it again inside the Go
  Cryptographic Module), Argon2 input (copied into BLAKE2b state that is never
  wiped), KDF output (returned on the heap, then moved into an enclave), AES
  key schedules, and `sha256` hash state over the area key or a recovery
  credential. The keyslot wrap uses `golang.org/x/crypto/xts`, which is outside
  the Go Cryptographic Module.
- The canonical, exhaustive list of the residual raw-bytes exposures — what
  they are, why each is accepted — is
  the package documentation of [`internal/secret`](../../internal/secret/doc.go)
  (`doc.go`). A summary, kept in sync with that canonical copy, is in
  [engineering.md](engineering.md#key-custody-detail).
- Those raw-bytes copies are ordinary heap, so only process hardening keeps
  them out of a core dump, and that is the binary's decision, not the
  library's: importing the library changes no process state.
  `enclave.HardenProcess` sets `RLIMIT_CORE` to 0/0 and, on Linux, makes the
  process non-dumpable, which also covers a `core_pattern` that pipes to a
  handler. The `luks2` CLI calls it before any command reads a credential and
  refuses to run if it fails. An application that embeds the library must call
  it from its own `main`.
- Every enclave is admitted against go-enclave's process `Allocator` before
  its pages are mapped; the binary sizes that budget with
  `enclave.SetAllocator`, and RLIMIT_MEMLOCK is the default.
- Enclaves are released through `secret.Custody.Release`, which drops
  go-enclave's release report: the operation's outcome is already decided and
  the library does not log. The CLI releases through the same `secret.Custody`,
  so it does not report a release problem either.

The largest locked allocation is the AF stripe material, `key_size × 4000`
bytes: 256,000 bytes for a 64-byte key. Keyslots with a key size other than 16,
24, 32, 48 or 64 bytes are refused before derivation, so a foreign header cannot
raise that. Budget about 1 MiB of `RLIMIT_MEMLOCK` per concurrent operation, which is
what the test suite allows. Some container runtimes default to 64 KiB, which is
not enough.

## Kernel keyring

The volume key reaches dm-crypt as a kernel keyring reference, as cryptsetup
does it. The table carries `:<size>:logon:luks2:<sha256 of the dm UUID>`, never
the key.

1. The dm target is created under the mapping name and dm UUID, with no
   table yet.
2. `add_key` puts the key in the session keyring as a `logon` key, whose
   payload user space cannot read back.
3. The dm-crypt table naming that key is loaded and the target resumed.
4. The key is revoked, unlinked and checked gone, whether or not step 3
   succeeded. If it cannot be confirmed gone, activation fails with
   `dmcrypt.ErrKeyringKeyNotReleased` and the target is rolled back.

The key is in the keyring only for step 3. The keyring mechanism itself is
documented in [kernel-keyring](../kernel-keyring/architecture.md).

There is no fallback that puts the key in the table. If the keyring is
unavailable, `dmcrypt.Activate` fails with an error matching
`dmcrypt.ErrKeyringUnavailable`. `dmcrypt.CheckKeyring` runs the same add and
release with a throwaway key, so a service can fail at startup instead.

A keyring that is unavailable fails with a `*dmcrypt.KeyringError`. Its `Op`
names the step that failed, its `Kind` names the cause, and `Remedy` returns
the operator guidance for that cause. `KeyringError.Error` ends with that
remedy. `KeyringError.Unwrap` reports `dmcrypt.ErrKeyring`,
`dmcrypt.ErrKeyringUnavailable`, the cause and the errno, so `errors.Is`
matches any of them:

| Cause | Meaning |
|---|---|
| `dmcrypt.ErrKeyringBlocked` | The keyring syscalls are refused by policy (`EPERM`, `EACCES`), almost always a container seccomp profile |
| `dmcrypt.ErrKeyringUnsupported` | The kernel has no keyring syscalls (`ENOSYS`: built without `CONFIG_KEYS`) |
| `dmcrypt.ErrKeyringQuotaExhausted` | The per-user kernel key quota is full (`EDQUOT`, `EKEYREJECTED`) |
| `dmcrypt.ErrKeyringFailed` | The keyring refused the operation for any other reason |

Two keyring failures are not unavailability and do not match
`dmcrypt.ErrKeyringUnavailable`: `dmcrypt.ErrKeyringEntryExists` (a key was
already present under the description this unlock was about to use; refused,
not resolved) and `dmcrypt.ErrKeyringKeyNotReleased`. `dmcrypt.ErrKeyring`
is the root every keyring error matches.

Keyrings are not namespaced by container. Docker's default seccomp profile
denies the three keyring syscalls whatever the capabilities, so a container
needs a profile that allows them (`test/integration/seccomp.json`: Docker's
default plus that one allow block).

The keyring logic lives in `internal/keyring`, called from `pkg/dmcrypt`;
`pkg/luks2` cannot import it.

## Device layer

| Part | Implementation |
|---|---|
| Device-mapper | Wraps `anatol/devmapper.go` behind a seam. The dm UUID is `CRYPT-LUKS2-<header uuid without dashes>-<name>`. Without udev the library creates `/dev/dm-N` and `/dev/mapper/<name>` with `mknod`. |
| Mapping names | `dmcrypt.ValidateName`: `[A-Za-z0-9]`, then `[A-Za-z0-9_.+-]`, at most `dmcrypt.MaxNameLength` (127) bytes, and not `control` (the device-mapper control node). Anything else: `dmcrypt.ErrInvalidName` |
| Close | `dmcrypt.Deactivate` records the target's UUID and device number, then retries removal on `EBUSY` for up to 3 s, re-checking them before each attempt. A mapping recreated under the same name normally gets a new device number and is left alone; a reused number in the gap between check and removal is a remaining race. Still held: `dmcrypt.ErrBusy`. |
| Loop devices | Loop ioctls through `/dev/loop-control` |
| Mount | `mount(2)` and `umount2(2)` |

Mapping names are validated at every entry, device-mapper decides whether a
mapping exists, and a `/dev/mapper` or `/dev/dm-N` node is used only when its
device number matches the target's (`dmcrypt.ErrNodeUnverified`).

External programs run only for work that is not LUKS2: `mkfs.ext4`,
`mkfs.xfs`, `mkfs.fat`, `zpool` and `zfs` to make filesystems; `e2fsck`,
`xfs_repair`, `fsck.fat` and `zpool scrub` to check them; `blkid` for
`filesystem.Inspect` and `filesystem.Detect`; and whatever helper a `keyprovider.Command` names, such as
`fido2-assert` (detail: [tokens](../tokens/architecture.md)). The filesystem
programs come from `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/usr/local/sbin`
or `/usr/local/bin`, never `PATH`, only if nobody but root or the caller can
write them or a directory above them; they get `PATH` and `LC_ALL=C` as their
environment and `--` before every operand.

## FIPS mode

Every FIPS decision asks one function, `internal/fips.Probe`
(`crypto/fips140.Enabled`), which `pkg/luks2` reaches through its `fipsMode`
seam.
In FIPS mode the default KDF is PBKDF2-SHA512, Argon2 and SHA-1 derivations are
refused with `ErrFIPSNotApproved`, and a volume that only opens through them
gets `*FIPSImportRequiredError` naming `MigrateToFIPS`. Full detail:
[fips](../fips/architecture.md).

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| LUKS2 header and keyslot areas | Untrusted: anyone with the disk can write them | Segments whitelisted at read; each keyslot bounded before use; removal and `MigrateToFIPS` also check areas against the device, the keyslots area and other keyslots |
| Passphrase, volume key, key provider output | Secret | Borrowed or moved into enclaves; never logged |
| Mapping name | Caller-chosen | Validated before use in the dm UUID, the keyring description (hashed) and `/dev/mapper` |
| Key provider helper | Runs with the caller's privileges | Absolute path required; walked from `/` by descriptor, every directory, symlink and the file owned by root or the caller and not writable by others (directories may be sticky), and run from the descriptor that was checked; minimal environment (system `PATH` and `LC_ALL=C`, plus `WithEnv`); output capped at 64 KiB and read into locked memory |
| Kernel keyring | Shared per uid and session | `logon` type, session keyring, released as soon as the table load and resume return |
| Device-mapper and loop | Global to the host | Device-mapper: identity checked before every removal; the check and the removal are separate ioctls, so a same-name race between them remains. Loop: `Detach` reads the backing file's device and inode (LOOP_GET_STATUS64) on the descriptor it then clears, and refuses with `loop.ErrDeviceReassigned` unless they are the ones recorded when the `Device` was obtained; the check and LOOP_CLR_FD are separate ioctls, so a reassignment between them remains |

## What this feature deliberately does not do

No TPM, HSM or KMS code: hardware-backed keys come in through
`Volume.UnlockWithVolumeKey` or a `KeyProvider`. No LUKS1 opening, no online
reencryption, no dm-integrity. No logging; errors are typed and returned.

Nor does it provide these cryptsetup operations, which a volume's owner runs
with cryptsetup itself on the same container:

| Not provided | Reason |
|---|---|
| Resize (`cryptsetup resize`) | A mapping's size is fixed when `dmcrypt.Activate` loads its table, and `pkg/dmcrypt` has no call that reloads a live mapping at a new size |
| Suspend and resume (`luksSuspend`/`luksResume`) | `pkg/dmcrypt` has no suspend or resume call. Suspending wipes the key from the kernel and resuming asks for a credential again, and no consumer of this library needs that cycle |
| KDF benchmark (`cryptsetup benchmark`) | PBKDF2 is calibrated internally, against `KDFParams.IterTime`, each time a keyslot is written without an iteration count. Argon2 costs are set, not measured. Nothing reports throughput as a separate result |

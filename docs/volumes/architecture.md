# Volumes — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-06 against v1.0.0-rc.1 (8924d5d1)
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

Every other LUKS2 consumer in the portfolio used to shell out to cryptsetup,
and that got the protected-memory guarantee for free: the master key was
derived, held and handed to the kernel inside a separate process whose address
space this one could not read, and which exited. go-luks2 does the work in
process instead — no `cryptsetup` binary, no `exec` in the core — so the
rootless core can run in places a setuid helper cannot, at the cost of
providing the protected-memory guarantee itself (see "Key custody", below, and
[engineering.md](engineering.md)).

Rejected alternatives for the package split (DESIGN.md §A.4):

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
| `internal/cli` | The CLI (DESIGN.md §F). Built on the `Volume` API, `pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem` and `pkg/wipe`. Root-only boundaries (activation, loop devices, mounting) sit behind small unexported interfaces so unit tests run without root. It holds no LUKS2 logic of its own. |
| `internal/secret`, `internal/fips`, `internal/af`, `internal/areacipher`, `internal/kdf`, `internal/header`, `internal/recoverykey`, `internal/command`, `internal/device`, `internal/dm`, `internal/keyring` | Leaf packages below the public API. |

Runtime dependencies: `github.com/jeremyhahn/go-enclave` (locked memory),
`github.com/anatol/devmapper.go` (device-mapper ioctls), `golang.org/x/crypto`
(Argon2, XTS), `golang.org/x/sys`, `golang.org/x/term`, `github.com/google/uuid`.

`depguard` enforces this layout mechanically, one rule per DESIGN.md §A.2 row.
`pkg/luks2` additionally denies `os/exec`, `github.com/anatol/devmapper.go`,
`pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`, `pkg/wipe`, `pkg/keyprovider`,
`internal/dm`, `internal/keyring` and `internal/command`, so the core cannot
regain root or exec without a red lint (`make lint`: 0 issues).

`make api-diff` (`test/tools/apidump` against
`baseline/disposition-luks2.tsv`) is the mechanical check that the exported
surface of `pkg/luks2` is exactly what DESIGN.md §B.6 specifies. A few
exports are retained on purpose and are recorded there: `DefaultKDFSpec`,
`LegacyToken`, and `dmcrypt.ErrIntegerOverflow` and `ErrDeviceChanged`.

$1

### Format

Draw the master key into an enclave, create the keyslot KDF, derive the
passphrase key, create the PBKDF2 digest, AF-split the master key (4000
stripes), encrypt the stripes with AES-XTS, write both header copies, write
the keyslot material, fill the rest of the keyslots area with random bytes,
sync. Cipher and AF detail: [keyslots](../keyslots/architecture.md).

### Unlock

`(*Volume).Unlock` takes cryptsetup's read lock (`LOCK_SH` on the device, then
on `/run/cryptsetup/L_<maj>:<min>`), so a writer holding it exclusively is
waited for; reads the header, size and keyslots through the pinned descriptor;
refuses an unimplemented mandatory requirement or more than one segment; tries
only keyslots bound to the crypt segment (ascending number; priority is not
read); derives, decrypts, AF-merges and verifies against that segment's digest;
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
header under the shared lock, re-verifies the key if `SequenceID` changed)
before mapping the pinned descriptor's major:minor. Rollback after a failed or
cancelled `Activate` runs under `context.WithoutCancel(ctx)` with its own
clock budget, so a cancelled caller never leaves a plaintext device behind.

The lock order and the write path are type properties, not a calling
convention. `internal/device` implements `Pinned` (read-only),
`Pinned.Lock(ctx, mode) *Locked` (node flock, then the cryptsetup lock) and
`Locked.Claim(ctx) *Claimed` (O_EXCL by reopening `/proc/self/fd/N`, so
`requireSameDevice` is unnecessary: the claim targets the locked inode by
construction). Every `*Volume` write method (`Format`, `AddKeyslot`,
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

- Every key it derives or recovers lives in a go-enclave `*enclave.MemoryEnclave`
  (mlock'd, guard-paged, wiped on release) and is only borrowed through
  `WithBytes` for the call that needs it. That covers the master key, derived
  keys, AF stripes, digest inputs and recovery credentials.
- If locked memory cannot be had, the operation fails with `ErrProtectedMemory`.
  There is no fallback to the heap.
- Credentials cross the API as enclaves too: `Format`, `Unlock`,
  `UnlockKeyslot`, `AddKeyslot`, `ChangeKeyslot` and `ParseRecoveryKey` take a
  `*enclave.MemoryEnclave` the caller owns and the library only borrows.
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
  they are, why each is accepted, and the owner ruling behind each one — is
  the package documentation of [`internal/secret`](../../internal/secret/doc.go)
  (`doc.go`). A summary, kept in sync with that canonical copy, is in
  [engineering.md](engineering.md#key-custody-detail).
- Every enclave is admitted against go-enclave's process `Allocator` before
  its pages are mapped; the binary sizes that budget with
  `enclave.SetAllocator`, and RLIMIT_MEMLOCK is the default.
- Enclaves are released through `secret.Custody.Release`, which drops
  go-enclave's release report: the operation's outcome is already decided and
  the library does not log. The CLI warns when releasing a recovery credential
  reports a problem.

The largest locked allocation is the AF stripe material, `key_size × 4000`
bytes: 256,000 bytes for a 64-byte key. Keyslots with a key size other than 32,
48 or 64 bytes are refused before derivation, so a foreign header cannot raise
that. Budget about 1 MiB of `RLIMIT_MEMLOCK` per concurrent operation, which is
what the test suite allows. Some container runtimes default to 64 KiB, which is
not enough.

## Kernel keyring

The volume key reaches dm-crypt as a kernel keyring reference, as cryptsetup
does it. The table carries `:<size>:logon:luks2:<sha256 of the dm UUID>`, never
the key.

1. `add_key` puts the key in the session keyring as a `logon` key, whose
   payload user space cannot read back.
2. The target is created with a table naming that key.
3. The key is revoked, unlinked and checked gone. If it cannot be confirmed
   gone, activation fails with `dmcrypt.ErrKeyringKeyNotReleased`.

There is no fallback that puts the key in the table. If the keyring is
unavailable, `dmcrypt.Activate` fails with an error matching
`dmcrypt.ErrKeyringUnavailable`. `dmcrypt.CheckKeyring` runs the same add and
release with a throwaway key, so a service can fail at startup instead.

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
| Mapping names | `dmcrypt.ValidateName`: `[A-Za-z0-9]`, then `[A-Za-z0-9_.+-]`, at most 127 bytes |
| Close | `dmcrypt.Deactivate` records the target's UUID and device number, then retries removal on `EBUSY` for up to 3 s, re-checking them before each attempt. A mapping recreated under the same name normally gets a new device number and is left alone; a reused number in the gap between check and removal is a remaining race. Still held: `dmcrypt.ErrBusy`. |
| Loop devices | Loop ioctls through `/dev/loop-control` |
| Mount | `mount(2)` and `umount2(2)` |

Mapping names are validated at every entry, device-mapper decides whether a
mapping exists, and a `/dev/mapper` or `/dev/dm-N` node is used only when its
device number matches the target's (`dmcrypt.ErrNodeUnverified`).

External programs run only for work that is not LUKS2: `mkfs.ext4`,
`mkfs.xfs`, `mkfs.fat`, `zpool` and `zfs` to make filesystems; `e2fsck`,
`xfs_repair`, `fsck.fat` and `zpool scrub` to check them; `blkid` for
`filesystem.Inspect`; and whatever helper a `keyprovider.Command` names, such as
`fido2-assert` (detail: [tokens](../tokens/architecture.md)). The filesystem
programs come from `/usr/sbin`, `/usr/bin`, `/sbin`, `/bin`, `/usr/local/sbin`
or `/usr/local/bin`, never `PATH`, only if nobody but root or the caller can
write them or a directory above them; they get `PATH` and `LC_ALL=C` as their
environment and `--` before every operand.

## FIPS mode

Every FIPS decision asks one function, `fipsMode` (`crypto/fips140.Enabled`).
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
| Key provider helper | Runs with the caller's privileges | Absolute path required; minimal environment (system `PATH` plus `Env`); output capped at 64 KiB and read into locked memory |
| Kernel keyring | Shared per uid and session | `logon` type, session keyring, removed after one ioctl |
| Device-mapper and loop | Global to the host | Identity checked before every removal; the check and the removal are separate ioctls, so a same-name race between them remains |

## What this feature deliberately does not do

No TPM, HSM or KMS code: hardware-backed keys come in through
`Volume.UnlockWithVolumeKey` or a `KeyProvider`. No LUKS1 opening, no online
reencryption, no dm-integrity. No logging; errors are typed and returned.

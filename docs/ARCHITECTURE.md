# Architecture

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

How go-luks2 is built, for maintainers. The API by task is in the
[library guide](luks/README.md); the commands are in the
[CLI reference](cli/README.md).

## Packages

| Path | Role |
|---|---|
| `pkg/luks2` | The library. One package: header I/O, KDFs, keyslots, tokens, recovery keys, unlock, device-mapper, loop devices, mount, wipe, FIPS import. |
| `cmd/luks2` | The CLI. Parses arguments and calls the library through the `LuksOperations` interface (`cli.go`), so unit tests replace the library with a mock. It holds no LUKS2 logic of its own. |
| `test/harness` | Ledger and reaper for loop devices and mappings the integration suite creates, plus `cmd/luks2-testreap`. |
| `test/integration/{pkg,cli}` | Integration suites, build tag `integration`, run in a container. |
| `test/integration/cmd/docker-run` | Launcher that owns the container's privilege set. |
| `test/covergate` | Per-package coverage gate. |
| `test/labstrings` | Public-releasability gate, with `cmd/releasability-gate`. |
| `test/ci/cmd/require-tool`, `test/makefile` | CI tool check; Makefile tests. |

Runtime dependencies: `github.com/jeremyhahn/go-enclave` (locked memory),
`github.com/anatol/devmapper.go` (device-mapper ioctls), `golang.org/x/crypto`
(Argon2, XTS), `golang.org/x/sys`, `golang.org/x/term`, `github.com/google/uuid`.

## On-disk format handling

The layout and field rules are in [luks/header.md](luks/header.md). The design
points:

- `ReadHeader` reads the primary copy and checks magic, version, area size,
  checksum and the JSON. Segment fields that reach the dm-crypt table are
  checked against a whitelist then (`segmentvalidation.go`).
- Keyslots are screened one at a time before use (`screenKeyslot`,
  `validateKeyslot`): geometry, key size and KDF cost are bounded before any
  derivation or allocation, and one bad keyslot does not block the others. See
  [Untrusted headers](luks/header.md#untrusted-headers).
- `writeHeaderInternal` encodes canonical JSON, writes and syncs the primary,
  then writes and syncs the secondary, so a crash tears at most one copy.
  Keyslot and token changes advance `sequence_id`.
- Members the structs do not model survive a read-modify-write in every
  nested metadata object (`unknownfields.go`); see
  [header.md](luks/header.md#encoding) for the limits.
- Every operation that writes the container takes an exclusive `flock` on the
  device, waiting up to 30 s (`DefaultLockWait`) before `LockTimeoutError`.
- Every keyslot removal path goes through one check that refuses to remove the
  last keyslot that can open the volume (`ErrLastKeyslot`).

## Format and unlock

`Format`: draw the master key into an enclave, create the keyslot KDF, derive
the passphrase key, create the PBKDF2 digest, AF-split the master key
(4000 stripes), encrypt the stripes with AES-XTS, write both header copies,
write the keyslot material, fill the rest of the keyslots area with random
bytes, sync.

`Unlock`: validate the path, passphrase and mapping name; read the header; try
keyslots (bound to every data segment first, then ascending number; priority
is not read); derive, decrypt, AF-merge, verify against the digest; load a
dm-crypt table that references the key in the kernel keyring; wait for the
device node. `UnlockWithVolumeKey` skips the keyslots and verifies the caller's
key against the segment's digest.

If any step after the target is created fails, the target is removed if it
still carries the dm UUID this call set. If that rollback cannot complete, the
error matches `ErrMappingStillLive`.

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
- Not enclaved, on purpose: encrypted keyslot material (it is on disk in that
  form), salts and digests (cleartext header fields), and passphrases the
  caller passes as `[]byte` (the caller's memory).
- Five exposures remain and are documented as accepted: caller credentials,
  the string copy `crypto/pbkdf2` makes of its input (on unlock and format that
  input is the master key), KDF output before it is moved into an enclave,
  AES key schedules inside `xts.Cipher`, and the kernel keyring entry. The
  canonical list with reasoning is the comment at the top of
  [`pkg/luks2/enclave.go`](../pkg/luks2/enclave.go).
- Enclaves are released through `releaseSecret`, which drops go-enclave's
  release report: the operation's outcome is already decided and the library
  does not log. The CLI warns when releasing a recovery credential reports a
  problem.

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
   gone, the unlock fails with `ErrKeyringKeyNotReleased`.

There is no fallback that puts the key in the table. If the keyring is
unavailable, `Unlock` fails with an error matching `ErrKeyringUnavailable`.
`CheckKeyringAvailable` runs the same add and release with a throwaway key, so
a service can fail at startup instead.

Keyrings are not namespaced by container. Docker's default seccomp profile
denies the three keyring syscalls whatever the capabilities, so a container
needs a profile that allows them. `test/integration/seccomp.json` is Docker's
default plus that one allow block; [TESTING.md](TESTING.md) has the measurements.

## Device layer

| Part | Implementation |
|---|---|
| Device-mapper | `devicemapper.go` wraps `anatol/devmapper.go` behind the `dm` seam. The dm UUID is `CRYPT-LUKS2-<header uuid without dashes>-<name>`. Without udev the library creates `/dev/dm-N` and `/dev/mapper/<name>` with `mknod`. |
| Mapping names | `ValidateMappingName`: `[A-Za-z0-9]`, then `[A-Za-z0-9_.+-]`, at most 127 bytes |
| Close | `Lock` records the target's UUID and device number, then retries removal on `EBUSY` for up to 3 s, re-checking them before each attempt. A mapping recreated under the same name normally gets a new device number and is left alone; a reused number in the gap between check and removal is a remaining race. Still held: `ErrMappingBusy`. |
| Loop devices | Loop ioctls through `/dev/loop-control` |
| Mount | `mount(2)` and `umount2(2)` |

External programs run only for work that is not LUKS2: `mkfs.ext4`,
`mkfs.xfs`, `mkfs.fat`, `zpool` and `zfs` to make filesystems; `e2fsck`,
`xfs_repair`, `fsck.fat` and `zpool scrub` to check them; `blkid` for
`GetFilesystemInfo`; and whatever helper a `CommandKeyProvider` names, such as
`fido2-assert`.

## FIPS mode

Every FIPS decision asks one function, `fipsMode` (`crypto/fips140.Enabled`).
In FIPS mode the default KDF is PBKDF2-SHA512, Argon2 and SHA-1 derivations are
refused with `ErrFIPSNotApproved`, and a volume that only opens through them
gets `*FIPSImportRequiredError` naming `MigrateToFIPS`. Details: [FIPS.md](FIPS.md).

## Trust boundaries

| Input | Trust | Handling |
|---|---|---|
| LUKS2 header and keyslot areas | Untrusted: anyone with the disk can write them | Segments whitelisted at read; each keyslot bounded before use; removal and `MigrateToFIPS` also check areas against the device, the keyslots area and other keyslots |
| Passphrase, volume key, key provider output | Secret | Borrowed or moved into enclaves; never logged |
| Mapping name | Caller-chosen | Validated before use in the dm UUID, the keyring description (hashed) and `/dev/mapper` |
| Key provider helper | Runs with the caller's privileges | Run as named (a bare name is looked up on `PATH`, so callers should pass an absolute path); output capped at 64 KiB and read into locked memory |
| Kernel keyring | Shared per uid and session | `logon` type, session keyring, removed after one ioctl |
| Device-mapper and loop | Global to the host | Identity checked before every removal; the check and the removal are separate ioctls, so a same-name race between them remains |

## Out of scope

No TPM, HSM or KMS code: hardware-backed keys come in through
`UnlockWithVolumeKey` or a `KeyProvider`. No LUKS1 opening, no online
reencryption, no dm-integrity. No logging; errors are typed and returned.

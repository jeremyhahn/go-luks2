# go-luks2

Pure Go implementation of LUKS2 disk encryption. No external dependencies on cryptsetup.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

## Installation

```bash
# CLI tool
go install github.com/jeremyhahn/go-luks2/cmd/luks2@latest

# Library
go get github.com/jeremyhahn/go-luks2/pkg/luks2
```

## CLI Usage

All commands require root privileges.

### Commands

| Command | Description |
|---------|-------------|
| `create <path> [size] [fs]` | Create LUKS2 volume (block device or file) |
| `open <device> <name>` | Unlock volume to /dev/mapper/\<name\> |
| `close <name>` | Lock volume |
| `mount <name> <mountpoint>` | Mount unlocked volume |
| `unmount <mountpoint>` | Unmount volume |
| `info <device>` | Show volume information |
| `wipe [opts] <device>` | Securely wipe volume (`--full`, `--passes N`, `--random`, `--trim`) |
| `keyslots <device>` | List keyslots, in the order an unlock tries them |
| `testkey <device>` | Check that a passphrase opens a volume |
| `addkey <device>` | Add another passphrase (`--slot N`, `--kdf NAME`) |
| `changekey <device> <slot>` | Replace the passphrase in a keyslot |
| `removekey <device> <slot>` | Remove a keyslot, using its own passphrase |
| `killslot <device> <slot>` | Remove a keyslot, using any valid passphrase |
| `recovery generate\|add\|verify` | Recovery keys (`--format`, `--length`, `--output`) |
| `token list\|show\|export\|import\|remove\|free\|exists\|count` | Token management |
| `header show\|secondary\|restore` | Inspect or repair the two header copies |
| `isluks [--luks2] <device>` | Exit 0 if the device holds a LUKS container |
| `help` | Show help |
| `version` | Show version |

Every command that needs a passphrase accepts `--key-file <path>` (and `-` for
standard input), and reads a piped passphrase as one line when standard input is
not a terminal — so the tool works from a script, a systemd unit or a timer.
**A key file's trailing newline is part of the passphrase**, exactly as in
cryptsetup, so write one with `printf %s`, not `echo`. See
[docs/cli/key-input.md](docs/cli/key-input.md).

### Examples

**Block device:**
```bash
sudo luks2 create /dev/sdb1
sudo luks2 open /dev/sdb1 mydisk
sudo mkfs.ext4 /dev/mapper/mydisk
sudo luks2 mount mydisk /mnt/encrypted
# ... use /mnt/encrypted ...
sudo luks2 unmount /mnt/encrypted
sudo luks2 close mydisk
```

**File-based volume (auto-configures loop device and filesystem):**
```bash
sudo luks2 create secret.luks 500M ext4
sudo luks2 mount luks-auto /mnt/encrypted
# ... use /mnt/encrypted ...
sudo luks2 unmount /mnt/encrypted
sudo luks2 close luks-auto
```

## Library API

### Core Operations

```go
import "github.com/jeremyhahn/go-luks2/pkg/luks2"

// Format new volume
luks2.Format(luks2.FormatOptions{
    Device:     "/dev/sdb1",
    Passphrase: []byte("secret"),
    Label:      "MyVolume",
    KDFType:    "argon2id",  // or "pbkdf2", "argon2i"
})

// Unlock/Lock
luks2.Unlock("/dev/sdb1", []byte("secret"), "myvolume")
luks2.Lock("myvolume")

// Status
luks2.IsUnlocked("myvolume")                    // bool
luks2.GetVolumeInfo("/dev/sdb1")                // *VolumeInfo, error
luks2.GetMappedDevicePath("myvolume")           // string, error
```

`Unlock` is **transactional**: if any step after the dm-crypt target is created
fails, the target this call created is removed before the error is returned, so
a reported failure never leaves a decrypted device behind. Only a target
carrying the dm UUID this call generated is removed — a mapping that merely
shares the name is left untouched.

The one case a caller must branch on is when the rollback itself could not
complete, or could not be confirmed:

```go
if err := luks2.Unlock(device, passphrase, name); err != nil {
    if errors.Is(err, luks2.ErrMappingStillLive) {
        // The unlock failed AND a plaintext mapping may still be live.
        // Releasing the backing device or reusing the name will fail until
        // it is closed: luks2.Lock(name) / `luks close <name>`.
    }
    return err
}
```

### Keyslot Management

```go
// Add passphrase to new keyslot
luks2.AddKey(device, existingPass, newPass, &luks2.AddKeyOptions{
    KDFType: "argon2id",
    Hash:    "sha256",  // for pbkdf2
})

// Change passphrase in specific keyslot
luks2.ChangeKey(device, oldPass, newPass, keyslotNumber)

// Remove passphrase (requires matching passphrase)
luks2.RemoveKey(device, passphrase, keyslotNumber)

// Kill keyslot (authenticate with any valid passphrase)
luks2.KillSlot(device, authPassphrase, targetSlot)

// Kill keyslot without authentication (dangerous)
luks2.KillKeyslot(device, keyslotNumber)

// Verify passphrase without unlocking
luks2.TestKey(device, passphrase)

// List active keyslots
luks2.ListKeyslots(device)  // []KeyslotInfo, error
```

### Token Management

Tokens store metadata for external key sources (FIDO2, TPM2, etc.):

```go
luks2.ListTokens(device)                        // map[int]*Token, error
luks2.GetToken(device, tokenID)                 // *Token, error
luks2.ImportToken(device, tokenID, token)       // error
luks2.ImportTokenJSON(device, tokenID, json)    // error
luks2.ExportToken(device, tokenID)              // []byte, error
luks2.RemoveToken(device, tokenID)              // error
luks2.FindFreeTokenSlot(device)                 // int, error
luks2.TokenExists(device, tokenID)              // bool, error
luks2.CountTokens(device)                       // int, error
```

### Recovery Keys

Generate and manage recovery keys for emergency access:

**The printed string is the passphrase.** The keyslot holds the formatted text
byte for byte, so a page in a safe opens the volume from any rescue system with
stock cryptsetup and nothing else — `cryptsetup open /dev/sdb1 vault`, paste.
It is the same 32 CSPRNG bytes either way; only the alphabet differs.

```go
// Generate and add a recovery key. A systemd-recovery token is written
// alongside the keyslot, and the keyslot is rolled back if it cannot be.
key, _ := luks2.AddRecoveryKey(device, existingPass, &luks2.RecoveryKeyOptions{
    Format:     luks2.RecoveryKeyFormatDashed,  // "XXXXXX-XXXXXX-..."
    OutputPath: "/secure/recovery.key",
})
defer key.Clear()

// key.Credential is the passphrase, in an *enclave.MemoryEnclave rather than a
// []byte or string. Materialize it only at the point of display.
rendered, _ := key.FormattedString()
fmt.Println(rendered)
fmt.Println(key.Keyslot, key.TokenID)

// Generate key only (without adding to volume)
key, _ := luks2.GenerateRecoveryKey(32, luks2.RecoveryKeyFormatHex)

// Save and load. LoadRecoveryCredential returns the credential itself.
luks2.SaveRecoveryKey(key, "/path/to/key")               // streams from locked memory
loaded, _ := luks2.LoadRecoveryCredential("/path/to/key")
defer loaded.Destroy()

// Verify, and take a typed or pasted key verbatim
luks2.VerifyRecoveryKey(device, loaded)         // bool, error
luks2.RecoveryCredential("XXXXXX-XXXXXX-...")   // *enclave.MemoryEnclave, error

// For a volume enrolled BEFORE the credential became the printed text, the
// keyslot holds the decoded bytes; these two produce those instead.
luks2.ParseRecoveryKey("XXXXXX-XXXXXX-...")
luks2.LoadRecoveryKey("/path/to/key")
```

### Filesystem & Mount

```go
luks2.MakeFilesystem("myvolume", "ext4", "label")

// Advanced filesystem options
luks2.MakeFilesystemWithOptions(device, luks2.FilesystemExt4, &luks2.FilesystemOptions{
    Label:     "MyVolume",
    BlockSize: 4096,
})

luks2.Mount(luks2.MountOptions{
    Device:     "myvolume",
    MountPoint: "/mnt/encrypted",
    FSType:     "ext4",
})

luks2.Unmount("/mnt/encrypted", 0)
luks2.IsMounted("/mnt/encrypted")              // bool, error
luks2.CheckFilesystem(device, fstype, repair)  // error
luks2.GetFilesystemInfo(device)                // *FilesystemInfo, error
luks2.SupportedFilesystems()                   // []FilesystemType
```

Supported filesystems: ext2, ext3, ext4, xfs, zfs, vfat

### Loop Devices

```go
loopDev, _ := luks2.SetupLoopDevice("encrypted.img")
defer luks2.DetachLoopDevice(loopDev)
luks2.Unlock(loopDev, passphrase, "myvolume")

luks2.FindLoopDevice("encrypted.img")  // Find existing loop device
```

### Secure Wipe

```go
// Wipe entire device
luks2.Wipe(luks2.WipeOptions{
    Device:     "/dev/sdb1",
    Passes:     3,      // overwrite passes
    Random:     true,   // random data vs zeros
    HeaderOnly: false,  // true = headers only (fast)
    Trim:       true,   // TRIM/DISCARD for SSDs
})

// Wipe specific keyslot
luks2.WipeKeyslot(device, keyslotNumber)
```

### Header Access

```go
hdr, metadata, err := luks2.ReadHeader(device)
luks2.WriteHeader(device, hdr, metadata)         // error
luks2.CreateBinaryHeader(opts)                   // *LUKS2BinaryHeader, error

// Validation
luks2.IsLUKS(device)                             // bool, error
luks2.IsLUKS2(device)                            // bool, error
```

### FIPS Compliance

For FIPS 140-2/3 environments, use PBKDF2:

```go
luks2.IsFIPSCompliantKDF("pbkdf2-sha256")  // true
luks2.IsFIPSCompliantKDF("argon2id")       // false

luks2.Format(luks2.FormatOptions{
    Device:     device,
    Passphrase: pass,
    KDFType:    "pbkdf2-sha256",  // FIPS-approved
})
```

FIPS-approved KDFs: `pbkdf2-sha256`, `pbkdf2-sha384`, `pbkdf2-sha512`

`pbkdf2-sha1` is **not** FIPS-approved — the Go Cryptographic Module permits
PBKDF2 only with SHA-2/SHA-3. It remains available outside FIPS mode to open
LUKS headers written by older cryptsetup releases; in FIPS mode it returns
`ErrFIPSNotApproved`.

Argon2 is not FIPS-approved either, and `GODEBUG=fips140=only` cannot catch it
because `x/crypto/argon2` is pure Go. While the process runs in FIPS 140-3 mode
(`crypto/fips140.Enabled()`), `DeriveKeyEnclave` and `CreateKDF` refuse `argon2i` and
`argon2id` with `ErrFIPSNotApproved` — including `CreateKDF`'s empty-`KDFType`
default, so a FIPS caller must select an approved KDF explicitly. Outside FIPS
mode Argon2id remains the default and nothing changes.

See [docs/FIPS.md](docs/FIPS.md).

## Cryptographic Defaults

| Parameter | Value |
|-----------|-------|
| Cipher | AES-256-XTS |
| KDF | Argon2id (1GB memory, 4 iterations, 4 threads) |
| Hash | SHA-256 |
| Key Size | 512 bits |
| Anti-Forensic | 4000-stripe split |

## Protected Memory

Every piece of key material this library derives or recovers is held in
[go-enclave](https://github.com/jeremyhahn/go-enclave) locked memory — mlock'd,
guard-paged, zeroized on release — for its whole lifetime, and is only ever
borrowed through the narrowest window the consuming call allows. That covers the
master key, passphrase-derived keys, the anti-forensic stripes (which *are* the
master key, spread wide), the master-key digest derivation and recovery keys
including their printable rendering.

This matters because the library performs LUKS2 operations **in process**.
Shelling out to `cryptsetup` kept key material in a separate address space for
free; doing the work here does not, so the guarantee has to be provided
explicitly.

**Operational requirement.** The library **fails closed**: if locked memory
cannot be obtained the operation is refused with `ErrProtectedMemory` rather
than completed with the key on the ordinary heap. `Unlock` fails closed the
same way when the **kernel keyring** is unavailable (`ErrKeyringUnavailable`),
with **no fallback and no opt-out** — the only alternative is putting the volume
key in the device-mapper table, and that is the exposure this library exists to
close. See [Kernel keyring requirement](#kernel-keyring-requirement).

A container this library writes needs roughly **512 KiB of `RLIMIT_MEMLOCK` per
concurrent operation** (the anti-forensic stripes are `key_size × 4000` bytes —
256 KiB for a 512-bit key, held alongside its decrypted counterpart). A
container written by someone else can legitimately need more: the bounds in
[Untrusted Headers](#untrusted-headers) cap one operation at about **8 MiB**
(`key_size` ≤ 1024 × 4000 stripes, for both the stripe buffer and the decrypted
keyslot material). **Budget 8 MiB per concurrent operation if the headers are
not yours.**

That is under a typical host default of 8 MiB only barely, and **well above the
64 KiB some container runtimes impose**; a container running
Format/Unlock/AddKey/ChangeKey must raise its `memlock` ulimit.

There is no aggregate work or memory budget across an unlock — the per-item
bounds cannot express one. Tracked as issue #26.

What is deliberately *not* locked, and why:

| Bytes | Why not |
|-------|---------|
| Encrypted keyslot material | Stored on the device in exactly that form; locking a copy of public data would double the memlock cost for no confidentiality |
| KDF salts, the stored digest | Cleartext LUKS2 header fields |
| Caller-supplied passphrases | The caller's own memory, already on the heap before this library is entered |

Five exposures remain that this library cannot close and does not claim to. The
canonical list, with the reasoning, is the file comment in
[`pkg/luks2/enclave.go`](pkg/luks2/enclave.go):

1. **Caller-supplied credentials** — passphrases as `[]byte`, and a recovery
   key as a `string` at `ParseRecoveryKey`. The caller's own memory, already on
   the heap before this library is entered; a Go string additionally cannot be
   borrowed without copying, nor wiped at all. Copies this library makes for its
   own convenience are not covered by this and are not made.
2. **Validated-module KDF input, and on two paths the input is the master key.**
   `crypto/pbkdf2.Key` takes its password as a `string`, so the call site must
   write `string(passphrase)` — an immutable Go string that can never be wiped —
   and the Go Cryptographic Module then takes a second copy via `hmac.New`.
   `deriveKeySecret` borrows an enclave and hands the slice straight down that
   path, so **every unlock (once per digest tried) and every format materializes
   the volume master key in unwipeable memory.**

   This is a **ruled position, not an oversight.** Avoiding it means
   hand-rolling PBKDF2 over `crypto/hmac` — writing new cryptographic
   primitive code to dodge a memory-hygiene boundary — and this project's
   security policy prohibits hand-rolled cryptography outright (owner ruling
   2026-08-25), with this exact case resolved by name: *use `crypto/pbkdf2`;
   accept the bounded transient copy; document it; the protected-memory mandate
   yields at that boundary.* This section is the documentation that ruling
   requires, and it is why the boundary is enumerated rather than hidden.
3. **KDF output** — `crypto/pbkdf2.Key`/`argon2.IDKey` allocate and return their
   result on the heap; it is moved into an enclave immediately, but the return
   itself is unavoidable.
4. **Expanded cipher keys** — `xts.NewCipher` holds the AES key schedule for
   both key halves on the heap for the cipher's lifetime. A schedule is a
   deterministic expansion of the key.
5. **The kernel keyring** (was: *the device-mapper table*). The volume key is
   handed to `dm-crypt` as a **kernel-keyring reference** — `add_key`, `logon`
   type, in the **session** keyring, revoked/unlinked/verified-gone as soon as
   the activation ioctl returns — which is what `cryptsetup` does. It goes from
   its enclave into the kernel and **no userspace string ever holds it**.
   Nothing in the package assigns `CryptTable.Key`, and there is **no
   fallback**, so `devmapper.go`'s hex encoding is structurally unreachable
   rather than conditionally avoided.

   What remains is smaller but real: **kernel keyrings are not namespaced by
   container** — keys live in the host's key subsystem scoped by uid and
   session. Three things bound it: the `logon` payload is **write-only**
   (`KEYCTL_READ` returns `EOPNOTSUPP`, so nothing reads the bytes back, not
   even root — a same-uid neighbor could *use* the entry by reference, not
   *learn* the key); the ring is the session keyring, never the uid-wide user
   keyring, and container runtimes give each container its own; and the entry
   lives for one ioctl.

Exposures 2 and 4 were missing from an earlier version of this list, which named
three. They are recorded here because an understated list is the one failure
mode that stops anyone looking again.

## Kernel keyring requirement

`Unlock` gives the volume key to `dm-crypt` **by kernel-keyring reference**, so
the process must be able to call `add_key`, `keyctl` and `request_key`. If it
cannot, the unlock is **refused** — there is no fallback to putting the key in
the device-mapper table, because that is the exposure this design exists to
close (owner ruling 2026-08-31).

**Call `luks2.CheckKeyringAvailable()` at startup.** It performs one add and one
release of a throwaway probe and returns the same typed error `Unlock` would.
The condition it detects is fixed at boot, so checking early turns a mid-service
outage into a configuration error at launch.

### Containers: the constraint is seccomp, not capabilities

Measured 2026-08-31 with the exact syscall sequence the library uses:

| Environment | `add_key` |
|---|---|
| host, unprivileged (uid 1000) | **OK** |
| container, default seccomp, no caps | **FAILS** — `operation not permitted` |
| container, `--cap-add SYS_ADMIN`, default seccomp | **FAILS** — `operation not permitted` |
| container, narrow custom profile, **no caps added** | **OK** |
| container, `--security-opt seccomp=unconfined` | **OK** |
| container, `--privileged` | **OK** |

**`CAP_SYS_ADMIN` does not help.** Docker's default seccomp profile denies
`add_key`, `keyctl` and `request_key` regardless of capabilities; only relaxing
seccomp lifts it. That is the opposite of the usual intuition, and it means the
least-privilege choice for dm-crypt (`--cap-add SYS_ADMIN` instead of
`--privileged`) needs a seccomp change as well — and that the seccomp change
needs no capability at all.

The fix is a **narrow custom profile** — take the default profile, add those
three syscalls, and pass `--security-opt seccomp=<profile>.json`. Prefer that
over `seccomp=unconfined`, which also drops every other syscall restriction. On
Kubernetes the equivalent is a localhost profile in
`securityContext.seccompProfile`.

**This repository ships one you can copy:
[`test/integration/seccomp.json`](test/integration/seccomp.json).** It is
Docker's default profile byte for byte with one appended allow block, and its
header records the upstream module version, the sha256 and how to re-verify it.
The invocation that goes with it — capabilities, device scoping, and what each
was measured to buy — is [`test/integration/docker-run.sh`](test/integration/docker-run.sh)
and [`docs/TESTING.md`](docs/TESTING.md). The suite has not used `--privileged`
since #80.

`ErrKeyring` is the root and matches **every** keyring condition — it is the
only safe catch-all. `ErrKeyringUnavailable` covers *unavailability* only, and
each unavailability also matches exactly one cause, because they need different
fixes:

| Sentinel | Cause | Fix |
|---|---|---|
| `ErrKeyringBlocked` | seccomp policy (`EPERM`) | allow the three syscalls |
| `ErrKeyringUnsupported` | kernel built without `CONFIG_KEYS` (`ENOSYS`) | none — use a kernel with keyring support |
| `ErrKeyringQuotaExhausted` | per-user key quota (`EDQUOT`) | raise `/proc/sys/kernel/keys/maxkeys`, `maxbytes` |
| `ErrKeyringFailed` | the kernel refused for another reason | read the errno |

Two further refusals are anomalies rather than configuration, and they do
**not** match `ErrKeyringUnavailable` — use `ErrKeyring` if you want everything:
`ErrKeyringEntryExists` (a key was already present under this volume's
description — refused rather than silently overwritten or adopted) and
`ErrKeyringKeyNotReleased` (the entry could not be confirmed gone after the
activation, so the volume key may still be in the kernel keyring). The second in
particular should never be folded into a generic handler: it is the one that
says a master key may still be resident.

### The reference is a digest, and mapping names are validated

The keyring description is `luks2:<SHA-256 of the dm UUID>`. A dm target
specification is **space-delimited and positional**
(`<cipher> <key> <iv_offset> <device> <start>`), and the reference is one token
in it — while the dm UUID is built from 40 bytes read straight off the device
(the LUKS2 header's `uuid`, whose charset nothing constrains and whose checksum
a hostile header author also controls) plus the caller's mapping name. Hashing
gives that token a closed alphabet **by construction**, so there is no charset
to get wrong and no escaping to forget.

`Unlock` also validates the mapping name (`ValidateMappingName`,
`ErrInvalidMappingName`): `[A-Za-z0-9]` first, then
`[A-Za-z0-9_.+-]`, at most 127 bytes. The name is not covered by the hash on its
other routes — it becomes `/dev/mapper/<name>`, the dm ioctl name field, and
part of the dm UUID the rollback uses to prove a target is its own.

## Untrusted Headers

A LUKS2 header is attacker-controlled input. Its keyslot fields are not
descriptive — they *size work*: `key_size` is handed to the KDF as the requested
output length (PBKDF2's cost scales with it) and then sizes the locked region
the derived key is moved into, and `stripes`/`area.size` decide how much is
read, decrypted and merged. None of it requires knowing a passphrase, because
the derivation is what authentication is built on and therefore runs first.

Keyslot geometry is therefore bounded **once, where the metadata is parsed**, so
that every consumer — unlock, `AddKey`, `ChangeKey`, and the inspection APIs —
inherits the same bound. A header that fails those bounds is refused with
`ErrInvalidHeader` before any derivation or allocation.

| Field | Bound | Justification (measured against cryptsetup 2.7.0) |
|-------|-------|---------------------------------------------------|
| `key_size` | 1..1024 bytes | cryptsetup refuses to format anything but a 256- or 512-bit key in XTS mode, so 64 bytes is the largest it writes; 16× headroom |
| `af.stripes` | 1..4000 | the LUKS1/LUKS2 formats fix this at 4000 |
| `area.size` | 1..128 MiB | matches cryptsetup's `LUKS2_MAX_KEYSLOTS_SIZE` |
| `key_size × stripes` | ≤ `area.size` | cryptsetup refuses to open a keyslot violating this (`Keyslot open failed`) |

Keyslots of a type this library does not implement (LUKS2's `reencrypt`) are
checked only against the bounds that apply to any keyslot, so a container in the
middle of a reencryption stays readable and inspectable.

## Requirements

- Linux with device-mapper support **and kernel keyring support**
  (`CONFIG_KEYS`); in containers the `add_key`/`keyctl`/`request_key` syscalls
  must not be blocked by seccomp — see
  [Kernel keyring requirement](#kernel-keyring-requirement)
- Root privileges for device-mapper operations
- `RLIMIT_MEMLOCK` headroom of ~512 KiB per concurrent operation (see
  [Protected Memory](#protected-memory))
- Go 1.25.5 (for building)

## Compatibility

- Fully compliant with LUKS2 specification
- Interoperable with cryptsetup 2.3+
- Volumes created with go-luks2 work with cryptsetup and vice versa

## Limitations

- Linux only (requires device-mapper)
- LUKS2 only (LUKS1 not supported)
- AES-XTS only (other ciphers not implemented)

## Testing

```bash
make test              # Unit tests
make vet               # Compile every supported build-tag configuration
sudo make integration  # Integration tests (requires root)
make ci-full           # Full test suite in Docker
```

### What the race detector covers, exactly

Stated plainly because "we run the race detector" is easy to read as more than
it is:

| | raced |
|---|---|
| `pkg/luks2`, `cmd/luks2`, default build tags | **yes** — `-race -covermode=atomic`, in CI and in `make test-unit` |
| `test/harness`, `test/harness/cmd/luks2-testreap` | **yes** — same legs; the ledger and reaper are in-memory and file-based and touch no host device, which is what lets them be raced |
| `pkg/luks2`'s `//go:build integration` test files | no — the package is raced under the default tag set, which excludes them |
| `test/integration/pkg`, `test/integration/cli` | no — these packages do not exist without the `integration` tag |

So the honest statement of race coverage is **the default-tag build of four
packages**, not "the module". The integration suites run in a container,
against loop devices, device-mapper and mounts — host-global resources with
real interleaving concerns — and they run without `-race`. That
is a deliberate, reversible decision rather than an accident of how the CI legs
were written; the reasoning, and the measurement that would change it, are
recorded at the race legs in `.github/workflows/ci.yml`.

The package list the race legs name is asserted against `go list ./...` on
every run (`scripts/race-packages.sh`), so a package added later cannot be
quietly left out of both the legs and this table.

Build-tag coverage is a separate property with its own gate:
`scripts/build-tags.sh` compiles every configuration the tree declares, with
the tag list derived from the `//go:build` lines rather than written down.

## License

Apache License 2.0

## Author

Jeremy Hahn

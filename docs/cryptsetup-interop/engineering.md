# cryptsetup interop — engineering

> **Status: NORMATIVE** · Last verified: 2026-10-12 against a9c840c and cryptsetup 2.7.5
> Conflicts with this document are defects. Fix them here first.

## The interop matrix

Each row is done by one tool and checked by the other; the tests are in
`test/integration/interop` unless a path is given.

| Operation | go-luks2 → cryptsetup | cryptsetup → go-luks2 | Test |
|---|---|---|---|
| Format, `isLuks`, `luksDump` | ✓ | ✓ | `TestCompatMatrix/format*`, `TestCompatLibraryFormats` |
| Open; data written through one tool's mapping, read through the other's | ✓ | ✓ | `TestCompatMatrix/open_and_data*`, every format row |
| Add key | ✓ | ✓ | `TestCompatMatrix/add_key*` |
| Remove key | ✓ | ✓ | `TestCompatMatrix/remove_key*` |
| Kill slot | ✓ | ✓ | `TestCompatMatrix/kill_slot*` |
| Change key | ✓ | ✓ | `TestCompatMatrix/change_key*` |
| Key files (binary, NUL, trailing newline) | ✓ | ✓ | `TestCompatMatrix/key_file*`, `test/integration/cli` `TestCLI_KeyFilesAreReadAsCryptsetupReadsThem` |
| Tokens: `systemd-tpm2`, `systemd-fido2` JSON, import and remove | ✓ | ✓ | `TestCompatMatrix/token*` |
| Header backup and restore (`luksHeaderBackup`/`luksHeaderRestore`; `(*Volume).RestorePrimaryHeader`) | ✓ | ✓ | `TestCompatMatrix/header*` |
| Wipe keyslot (`(*Volume).RemoveKeyslot`; `luksErase`) | ✓ | ✓ | `TestCompatMatrix/wipe_keyslot*` |
| Header-only wipe | ✓ | – | `test/integration/device` `TestHeaderOnlyWipeIsACryptoEraseOnTheMedium` |
| Recovery keys (printed key; `systemd-cryptenroll` form) | ✓ | ✓ | `TestCompatMatrix/recovery_key*`, `test/integration/cli` `TestCLI_FIPSModeCreateAndRecoveryAddOpenWithCryptsetup` |
| FIPS import | ✓ | – | `test/integration/interop` `TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData` |
| Detached header (`--header`): read, keyslots managed | – | ✓ | `TestCompatMatrix/detached_header*`, `pkg/luks2` `TestDetachedHeaderKeyslotsAreManageable` |
| Detached header: activation | – | refused | `test/integration/header` `TestADetachedHeaderIsNeverActivated` |
| Concurrent writers: every write path against a cryptsetup write | ✓ | ✓ | `pkg/luks2` `TestCryptsetupWaitsForEveryWritePath`, `TestEveryWritePathWaitsForCryptsetup` |

cryptsetup-formatted volumes go-luks2 opens, maps and adds keyslots to
(`TestCompatCryptsetupFormats`): `--pbkdf pbkdf2` with `--hash sha256` and
`sha512`, `argon2i`, `argon2id`, `--key-size 256` and `512`, `--sector-size
512` and `4096`, `--label`/`--subsystem`, `--luks2-metadata-size 64k` with
`--luks2-keyslots-size 1m` and `1m`/`8m`, `--keyslot-cipher aes-xts-plain`,
`aes-cbc-essiv:sha256` and `aes-cbc-plain64`, a 128-bit `aes-cbc-essiv:sha256`
data cipher, persistent `--allow-discards --perf-*` flags, and LUKS1
containers converted with `cryptsetup convert`.

Out of scope, refused with a typed error and nothing written:

| Container | go-luks2 | Test |
|---|---|---|
| `--integrity` (dm-integrity) | `Volume.Unlock` (and so `AddKeyslot`'s key recovery) and activation: `ErrUnsupported`, whatever the volume key size; the container is untouched, open it with cryptsetup | `TestCompatIntegrityVolumeIsRefusedForActivation` |
| Mid-reencryption (`cryptsetup reencrypt`) | `Volume.Unlock`: `ErrUnsupportedRequirement` | `test/integration/dmcrypt` `TestAnInterruptedCryptsetupReencryptIsRefusedForActivation` |
| LUKS1 (convert it with `cryptsetup convert --type luks2`) | `ErrNotLUKS2` from `(*Volume).Header` | `pkg/luks2` `TestReadHeaderRefusesALUKS1Container` |
| Keyslot ciphers other than AES XTS/CBC | `ErrUnsupported` | `pkg/luks2` `TestParseKeyslotAreaEncryption` |

## Metadata lock

For a block device both tools flock `/run/cryptsetup/L_<major>:<minor>`,
shared to read and exclusive to write. Measured, per state of the lock
directory (`TestCompatMetadataLockDirectoryStates`; "uid 1000" is a real
setuid child in the disk group):

| State | cryptsetup 2.7.5 | go-luks2 |
|---|---|---|
| Missing, creatable | creates it 0700, proceeds | same |
| Missing, not creatable (read-only `/run`) | every command, `isLuks` and `luksDump` included: exit 5, "Failed to acquire read lock" | every operation, `Header` and `Unlock` included: `ErrMetadataLockUnavailable`, header unchanged |
| A symlink | exit 5, "Locking aborted" | every operation: `ErrMetadataLockUnavailable`, nothing created through it |
| Root's 0700, caller uid 1000 | every command: exit 5 (`isLuks` silently) | every operation, `Header` and `Unlock` included: `ErrMetadataLockUnavailable` wrapping `EACCES` |
| 0770 group `disk`, caller uid 1000 | works | works |
| Lock file held exclusively | every command waits, with no timeout | `Header`, `Unlock` and writes wait 30 s, then `ErrLockContended` |
| Lock file held shared | reads proceed; writes wait, with no timeout | same; writes stop at 30 s |

The go-luks2 rows are measured, reads and writes alike: each step opens the
device with `Open` and calls the `Volume` method a caller would (`Header`,
`Unlock`, `AddKeyslot`, `RemoveKeyslot`, `SetToken`), so it takes the lock
that call takes. The test bounds the wait with `WithLockWait`; 30 s is
`DefaultLockWait`.

A non-root caller can manage keyslots on a block device when the lock
directory admits its group, for example with a `tmpfiles.d` entry
`d /run/cryptsetup 0770 root disk -`. Both tools then work unprivileged.

## Error semantics

The errors this matrix exercises are each feature's own
(`ErrMetadataLockUnavailable`, `ErrLockContended`:
[volumes/engineering.md](../volumes/engineering.md#error-semantics);
`ErrKeyslotNotFound`:
[keyslots/architecture.md](../keyslots/architecture.md#untrusted-keyslots);
`ErrUnsupportedRequirement`, `ErrNotLUKS2`, `ErrUnsupported`:
[header/architecture.md](../header/architecture.md)).
This folder does not define new error types; it is where their
cryptsetup-interop behaviour is measured and asserted.

## Test strategy

**Unit** (`make test-unit`): none of the interop matrix is unit-level — every
row needs a real cryptsetup binary or a real kernel. **Integration**
(`make integration-test`, build tag `integration`, run in the devcontainer's
integration image as a compose service with `test/tools/docker-run`'s
privilege set): the full matrix above, plus
the metadata-lock state table, run against cryptsetup 2.7.5 and Linux 6.17 in
the integration container. The container's capability set
(`SYS_ADMIN`, `MKNOD`, `SETUID`/`SETGID`, the keyring/mount seccomp allowances,
the dm/loop device-cgroup rules) is documented and pinned flag by flag in
`test/tools/docker-run`'s `privileges` function; this folder does
not duplicate that inventory, since it is test infrastructure rather than
compatibility policy; it is in
[volumes/engineering.md](../volumes/engineering.md#the-integration-container).

`compatmatrix`, `fipsimport`, `sha1af` and `headercopies` live in
`test/integration/interop/`. `lockcompat` and `lockwait` stay in `pkg/luks2`
as `lockcompat_integration_test.go`/`lockwait_integration_test.go`, under
`//go:build integration`, because each overrides a `volumeSys` seam
(`calibratedCountFloor`, `lockHeld`) the public API must not expose; see
[architecture.md](architecture.md#component-boundaries) for the rule and the
other two files it applies to.

## Observability

No logging. The matrix above is this library's compatibility surface, not an
emitted signal.

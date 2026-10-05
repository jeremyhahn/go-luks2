# Library guide

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

How to use `github.com/jeremyhahn/go-luks2/pkg/luks2`. Signatures and field
docs are in godoc (`go doc github.com/jeremyhahn/go-luks2/pkg/luks2`); this page
says which call does what and which errors to branch on. Design and trust
boundaries: [ARCHITECTURE.md](../ARCHITECTURE.md).

| Page | Covers |
|---|---|
| [header.md](header.md) | On-disk layout, binary header, JSON metadata, header bounds |
| [keyslots.md](keyslots.md) | Keyslot structure, cost inheritance, removal |
| [kdf.md](kdf.md) | PBKDF2 and Argon2, calibration, iteration floors, the digest |
| [encryption.md](encryption.md) | AES-XTS, anti-forensic split, the dm-crypt table |
| [tokens.md](tokens.md) | Token JSON, systemd token types, the token API |
| [keyprovider.md](keyprovider.md) | Credentials from a helper program, FIDO2 |

## Rules that apply to every call

- Paths must be absolute and name a regular file or a block device, or the call
  fails with `ErrInvalidPath` or `ErrDeviceNotFound`.
- Passphrases are 8 to 512 bytes (`ErrPassphraseTooShort`,
  `ErrPassphraseTooLong`). They stay the caller's memory; the library neither
  locks nor wipes them.
- Credentials the library returns are `*enclave.MemoryEnclave` values from
  go-enclave. The caller destroys them.
- Calls that create a mapping need root, the kernel keyring and enough
  `RLIMIT_MEMLOCK`. Call `CheckKeyringAvailable` once at startup.

## API by task

| Task | Calls |
|---|---|
| Create | `Format(FormatOptions)` |
| Open and close | `Unlock`, `UnlockWithVolumeKey`, `UnlockWithProvider`, `Lock`, `IsUnlocked`, `GetMappedDevicePath` |
| Inspect | `GetVolumeInfo`, `ListKeyslots`, `IsLUKS`, `IsLUKS2` |
| Keyslots | `TestKey`, `AddKey`, `ChangeKey`, `RemoveKey` (that slot's passphrase), `KillSlot` (any passphrase), `KillKeyslot` and `WipeKeyslot` (no passphrase) |
| Recovery keys | `GenerateRecoveryKey`, `AddRecoveryKey`, `SaveRecoveryKey`, `LoadRecoveryCredential`, `RecoveryCredential`, `VerifyRecoveryKey` |
| Tokens | `ListTokens`, `GetToken`, `ImportToken`, `ImportTokenJSON`, `ExportToken`, `RemoveToken`, `FindFreeTokenSlot`, `TokenExists`, `CountTokens` |
| Key providers | `EnrollKeyProvider`, `UnlockWithProvider`, `ProviderFromToken`, `NewFIDO2KeyProvider` |
| Header | `ReadHeader`, `ReadSecondaryHeader`, `RestorePrimaryHeader`, `WriteHeader` |
| FIPS | `DefaultKDFType`, `IsFIPSCompliantKDF`, `MigrateToFIPS` ([FIPS.md](../FIPS.md)) |
| Loop devices | `SetupLoopDevice`, `DetachLoopDevice`, `FindLoopDevice` |
| Filesystems | `MakeFilesystem`, `MakeFilesystemWithOptions`, `CheckFilesystem`, `CheckFilesystemDetailed`, `GetFilesystemInfo`, `SupportedFilesystems` |
| Mount | `Mount`, `Unmount`, `IsMounted` |
| Wipe | `Wipe(WipeOptions)`, `WipeKeyslot` |

`UnlockWithVolumeKey` opens a volume with a key the caller already holds in an
enclave, for keys unsealed by a TPM, HSM or KMS in a layer above this one. It
skips the keyslots but still requires the key to match a digest bound to the
crypt segment and to have the keyslots' key size (`ErrMasterKeyVerification`).
A nil, destroyed or oversized enclave fails with `ErrInvalidVolumeKey`. The
caller keeps ownership of the enclave.

## Errors to branch on

Match with `errors.Is`. Unlock failures:

```go
err := luks2.Unlock(device, passphrase, name)
switch {
case err == nil:
case errors.Is(err, luks2.ErrMappingStillLive):
	// The unlock failed and a plaintext mapping may still exist. Lock(name).
case errors.Is(err, luks2.ErrNoKeyslots):
	// No keyslot this library can try. No passphrase will open it.
case errors.Is(err, luks2.ErrMasterKeyVerification):
	// A keyslot was tried and the key did not match the digest: a wrong
	// passphrase, or the right one over damaged key material.
case errors.Is(err, luks2.ErrInvalidKeyslot), errors.Is(err, luks2.ErrInvalidHeader):
	// Malformed keyslot or header. The passphrase may be correct.
case errors.Is(err, luks2.ErrFIPSImportRequired):
	// FIPS process, volume opens only through Argon2 or SHA-1. See FIPS.md.
case errors.Is(err, luks2.ErrKeyringUnavailable):
	// Keyring syscalls blocked or unsupported. See the table below.
case errors.Is(err, luks2.ErrVolumeAlreadyUnlocked):
	// The mapping name is taken.
}
```

There is no "wrong passphrase" error: with an unauthenticated keyslot cipher a
wrong passphrase and damaged key material look the same.

Keyring errors all match `ErrKeyring`. The unavailability causes also match
`ErrKeyringUnavailable`:

| Error | Cause | Fix |
|---|---|---|
| `ErrKeyringBlocked` | seccomp (`EPERM`) | Allow `add_key`, `keyctl`, `request_key` |
| `ErrKeyringUnsupported` | kernel without `CONFIG_KEYS` (`ENOSYS`) | Use a kernel with keyrings |
| `ErrKeyringQuotaExhausted` | per-user quota (`EDQUOT`) | Raise `/proc/sys/kernel/keys/maxkeys` and `maxbytes` |
| `ErrKeyringFailed` | any other refusal | Read the errno |
| `ErrKeyringEntryExists` | an entry for this volume already exists | Remove the leftover with `keyctl unlink` |
| `ErrKeyringKeyNotReleased` | the entry could not be confirmed gone | The volume key may still be in the keyring; investigate |

The last two do not match `ErrKeyringUnavailable`.

Other errors worth handling: `ErrMappingBusy` from `Lock` (still held after
3 s of retries), `ErrLastKeyslot` (removal would leave nothing that opens the
volume), `ErrProtectedMemory` (no locked memory), `LockTimeoutError` (another
writer held the device for 30 s).

## Behaviour to know

- `SupportedFilesystems` is ext4, xfs, zfs and vfat; ext2 and
  ext3 are refused with `ErrUnsupportedFilesystem`. `MakeFilesystem` takes a
  mapping name, not a path. `CheckFilesystem` is read-only unless `repair` is
  set; for zfs it takes a pool name and only starts `zpool scrub`. See godoc.
- A `HeaderOnly` wipe leaves keyslot areas and data intact, so a header
  backup reopens the volume, and wipe verification is skipped when the final
  pass is random. Details: [luks2 wipe](../cli/wipe.md). `WipeKeyslot` zeroes
  one keyslot area with no passphrase.
- A recovery keyslot holds the printed text, so the printed key
  opens the volume with stock cryptsetup. `RecoveryKey.Credential` is that text
  in an enclave; `FormattedString` returns it as a string. Keys enrolled before
  this was the case hold the decoded bytes: use `ParseRecoveryKey` or
  `LoadRecoveryKey` for those.
- A keyslot or token written as JSON `null` is dropped
  on read and listed in `LUKS2Metadata.DroppedNullEntries`. The next header
  write removes it from the device.

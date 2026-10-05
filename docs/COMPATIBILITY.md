# Compatibility policy

> **Status: NORMATIVE** · Last verified: 2026-10-05 against v0.4.0-alpha and cryptsetup 2.7.5
> Conflicts with this policy are defects.

## Versions

[Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html). Tags carry a
`v` (`v0.3.1-alpha`); the `VERSION` file does not (`0.3.1-alpha`). `-alpha`
builds are internal and promise nothing outside this project.

go-luks2 is pre-1.0:

| Bump | Means |
|---|---|
| PATCH (`0.3.0` → `0.3.1`) | A fix. No exported API change, no change to what is written to disk. |
| MINOR (`0.3.x` → `0.4.0`) | New API **or a breaking change**. Before 1.0 a breaking change is a MINOR bump, never a PATCH. |
| MAJOR | Reserved for `1.0.0`. After that, a breaking change is a new major version and the module path gains `/vN`. |

A breaking change is anything that can stop a correct consumer compiling or
change what it observes: a removed or renamed exported identifier, a changed
signature, a changed error a caller is documented to match, a refused input
that used to be accepted, or a change to what is written to a LUKS2 header.

## Before the first public release

Backward compatibility was not a goal. API, on-disk choices and CLI changed
when the design required it, with no shims. `CHANGELOG.md` marks those changes
with `BREAKING:` in the heading.

## From the first public release

- A breaking change bumps MINOR (pre-1.0), and its changelog heading carries
  `BREAKING:` and what a consumer must change.
- A breaking change lands with its consumers: dependent projects are updated,
  built and tested against it, bottom of the dependency graph up, before it is
  released.
- Published tags are never moved or deleted. A bad release is superseded by the
  next version.
- Versions only go up.
- The on-disk format is cryptsetup's. A header go-luks2 writes must open in
  cryptsetup and the reverse; breaking that is a defect, not a breaking change.

There is no deprecation window before 1.0: an API is removed in the MINOR
release that announces it. A deprecation policy will be stated here before 1.0.

## cryptsetup interoperability

go-luks2 is held to cryptsetup 2.7.5 and the Linux kernel in the integration
container. Each row is done by one tool and checked by the other; the tests
are in `pkg/luks2` unless a path is given.

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
| Header backup and restore (`luksHeaderBackup`/`luksHeaderRestore`; `RestorePrimaryHeader`) | ✓ | ✓ | `TestCompatMatrix/header*` |
| Wipe keyslot (`WipeKeyslot`; `luksErase`) | ✓ | ✓ | `TestCompatMatrix/wipe_keyslot*` |
| Header-only wipe | ✓ | – | `TestHeaderOnlyWipeIsACryptoEraseOnTheMedium` |
| Recovery keys (printed key; `systemd-cryptenroll` form) | ✓ | ✓ | `TestCompatMatrix/recovery_key*`, `test/integration/cli` `TestCLI_FIPSModeCreateAndRecoveryAddOpenWithCryptsetup` |
| FIPS import | ✓ | – | `test/integration/pkg` `TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData` |
| Detached header (`--header`): read, keyslots managed | – | ✓ | `TestCompatMatrix/detached_header*`, `TestDetachedHeaderKeyslotsAreManageable` |
| Detached header: activation | – | refused | `TestADetachedHeaderIsNeverActivated` |
| Concurrent writers: every write path against a cryptsetup write | ✓ | ✓ | `TestCryptsetupWaitsForEveryWritePath`, `TestEveryWritePathWaitsForCryptsetup` |

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
| `--integrity` (dm-integrity) | activation: `ErrUnsupportedSegmentLayout`. Keyslots stay manageable when the volume key is 16–64 bytes; a longer one (the integrity key appended) is `ErrInvalidKeyslot` | `TestCompatIntegrityVolumeIsRefusedForActivation` |
| Mid-reencryption (`cryptsetup reencrypt`) | `ErrUnsupportedRequirement` | `TestAnInterruptedCryptsetupReencryptIsRefusedForActivation` |
| LUKS1 (convert it with `cryptsetup convert --type luks2`) | `IsLUKS` true, `ErrUnsupportedLUKSVersion` otherwise | `TestReadHeaderRefusesALUKS1Container` |
| Keyslot ciphers other than AES XTS/CBC | `ErrUnsupportedKeyslotCipher` | `TestParseKeyslotAreaEncryption` |

## Metadata lock

For a block device both tools flock `/run/cryptsetup/L_<major>:<minor>`,
shared to read and exclusive to write. Measured, per state of the lock
directory (`TestCompatMetadataLockDirectoryStates`; "uid 1000" is a real
setuid child in the disk group):

| State | cryptsetup 2.7.5 | go-luks2 |
|---|---|---|
| Missing, creatable | creates it 0700, proceeds | same |
| Missing, not creatable (read-only `/run`) | every command, `isLuks` and `luksDump` included: exit 5, "Failed to acquire read lock" | writes: `ErrMetadataLockUnavailable`, header unchanged; reads proceed |
| A symlink | exit 5, "Locking aborted" | writes: `ErrMetadataLockUnavailable`, nothing created through it |
| Root's 0700, caller uid 1000 | every command: exit 5 (`isLuks` silently) | writes: `ErrMetadataLockUnavailable` wrapping `EACCES`; reads proceed |
| 0770 group `disk`, caller uid 1000 | works | works |
| Lock file held exclusively | every command waits, with no timeout | `ReadHeader` and `TestKey` proceed; `Unlock` and writes wait 30 s, then `ErrLockContended` |
| Lock file held shared | reads proceed; writes wait, with no timeout | same; writes stop at 30 s |

A non-root caller can manage keyslots on a block device when the lock
directory admits its group, for example with a `tmpfiles.d` entry
`d /run/cryptsetup 0770 root disk -`. Both tools then work unprivileged.

## Stricter than cryptsetup

Each is a refusal or an omission that leaves the volume as cryptsetup wrote
it; none stops a cryptsetup volume from opening.

| go-luks2 | cryptsetup | Why |
|---|---|---|
| A lock wait ends after 30 s with `ErrLockContended` | waits forever | a wait nothing will end is a hang |
| A new passphrase is 8–512 bytes (`ErrPassphraseTooShort`, `ErrPassphraseTooLong`); an existing one may be 1 byte to 8 MiB | enrolls any length, an 8 MiB key file included | a new credential is chosen now and can meet a floor |
| Persistent `allow-discards` is not passed to dm-crypt; the performance flags are | passes all of them | the header is untrusted, and discards disclose which blocks are free to anyone who can read the medium; the data is the same either way |
| Activation refused for a detached header | activates with `--header` | `Unlock` maps the device it read the header from and takes no second device; the keyslots are still managed |
| Keyslots tried only if bound to the data segment, never by priority | priority order | an unbound key maps garbage |
| Headers that fail cryptsetup's structural rules, or carry an ambiguous JSON member, are refused | refuses most of the same | see [header.md](luks/header.md#untrusted-headers) |
| SHA-1 and Argon2 refused in FIPS 140-3 mode | no FIPS mode of its own | see [FIPS.md](FIPS.md) |
| A header with more than 32 keyslots or 32 digests is refused on read; keyslot ids above 31 are never tried | reads them (measured: 200 keyslots, 40 digests) and tries every keyslot | cryptsetup writes no such header, and each entry is derivation work a crafted header adds to every unlock |
| One operation's key derivation is capped at the most a cryptsetup header can ask for (`ErrKDFBudgetExceeded`, before any derivation) | no aggregate cap | a crafted header could otherwise multiply the per-derivation ceiling; `TestCompatCryptsetupsMaximumKeyslotsAndCostsAreNotRefused`, `TestCompatAmplifiedDigestsAreRefusedByBothTools` |
| Per derivation: PBKDF2 at most 100,000,000 iterations, Argon2 at most 10,000 passes | up to 2^32 − 1 | see [header.md](luks/header.md#untrusted-headers) |

go-luks2 reads without the lock (`ReadHeader`, `TestKey`, `GetVolumeInfo`)
where cryptsetup takes it shared: a read racing a write fails its checksum or
digest and reports an error, and nothing is written.

# FIPS 140-3

> **Status: REFERENCE** · Last verified: 2026-10-04 against v0.3.1-alpha

go-luks2 runs under the Go Cryptographic Module in FIPS 140-3 mode. "FIPS
mode" below means `crypto/fips140.Enabled()` is true, which holds for both
`GODEBUG=fips140=on` and `fips140=only`; the library treats them the same.
Every policy decision goes through one unexported function, `fipsMode`, which
unit tests substitute so the policy is tested in every ordinary run.

## CI

The `FIPS` job in `.github/workflows/nightly.yml` sets `GOFIPS140=latest` and
`GODEBUG=fips140=only`, builds `./...`, runs the cross-process import tests
below, and runs `go test ./...`. `fips140=only` is used because `on` still lets
non-approved algorithms run.

## Approved KDFs

| KDF type | `IsFIPSCompliantKDF` | Notes |
|---|---|---|
| `pbkdf2` | true | SHA-256 unless a hash is given |
| `pbkdf2-sha256`, `pbkdf2-sha384` | true | |
| `pbkdf2-sha512` | true | Default in FIPS mode |
| `pbkdf2-sha1` | false | Read from old headers outside FIPS mode, never written |
| `argon2i`, `argon2id` | false | Refused in FIPS mode; `argon2id` is the default otherwise |

`DefaultKDFType()` is `pbkdf2-sha512` in FIPS mode and `argon2id` otherwise,
as cryptsetup chooses. It applies when `Format`, `AddKey`, `AddRecoveryKey` or
`CreateKDF` is given no KDF type. The FIPS default is calibrated to
`PBKDFIterTime` (2000 ms by default) and never below the SHA-512 floor for that
budget (210,000 at 2000 ms). A caller that names no type but sets an Argon2
cost gets `argon2id`, which FIPS mode refuses.

## Argon2 is refused in FIPS mode

Argon2 comes from `golang.org/x/crypto`, outside the module, so
`GODEBUG=fips140=only` cannot stop it. The library does: `requireFIPSApprovedKDF`
in `pkg/luks2/kdf.go` returns `ErrFIPSNotApproved` for `argon2i` and
`argon2id`. It runs in `deriveKeyPlain`, which every derivation reaches, so a
foreign header cannot make a FIPS process run Argon2, and in `CreateKDF`.

So a FIPS process can neither create nor open an Argon2 keyslot. Argon2id is
cryptsetup's LUKS2 default, so most existing volumes need `MigrateToFIPS`
(below) or a non-FIPS process.

The CLI follows the same default: `create`, `addkey` and `recovery add` work in
FIPS mode with no options and write PBKDF2-SHA512 keyslots. `--pbkdf argon2id`
is refused before the passphrase prompt; see [create](cli/create.md#kdf-options).

## Importing a volume: `MigrateToFIPS`

### What a FIPS process sees

When every keyslot that could not be tried was
refused only because its KDF, or the KDF of every digest attesting it, is not
approved, unlock returns `*FIPSImportRequiredError`. Its message says the
volume is intact, names each keyslot and digest with its KDF, and names
`MigrateToFIPS`. It matches `ErrFIPSImportRequired` and `ErrFIPSNotApproved`,
not `ErrInvalidKeyslot` or `ErrInvalidHeader`. If any keyslot also failed for
another reason, that failure is reported instead.

### What the import does

Run it once, in a process that is not in FIPS mode
(otherwise `ErrFIPSMigrationUnderFIPS`, with nothing touched). It changes
keyslots and digests only. It does not check or change the data segment's
cipher, which dm-crypt in the kernel runs:

```go
res, err := luks2.MigrateToFIPS("/dev/sdb1", passphrase, nil)
// res.Complete: no keyslot or digest FIPS mode cannot run remains
```

1. Unlock with the passphrase, trying approved keyslots first and only
   keyslots bound to every data segment. The key must match a digest binding
   each segment, or `ErrFIPSMigrationUnboundKey` before any write.
2. Require every non-approved digest to attest that key.
3. Add a PBKDF2 keyslot (SHA-256 by default) wrapping the same key, through
   `AddKey`'s code.
4. Rewrite each non-approved digest as PBKDF2 over the same key.
5. Verify: open through the new keyslot and approved digests only, check that
   an approved digest binds the key to every segment, and check that the normal
   unlock scan over approved keyslots and digests returns the same key.
6. Remove the non-approved keyslots, unless `KeepNonApprovedKeyslots` is set;
   then `Complete` is false and `RetainedNonApprovedKeyslots` lists them.
7. Re-read the header and check it statically and with a real open.

Nothing is removed before step 5 passes. Only the supplied passphrase carries
over; other credentials that live only in Argon2 keyslots are removed. A
failure returns `*FIPSMigrationError` naming the stage and the state the volume
was left in.

### Interrupted imports

Every state an interruption can leave opens to the
original volume key, and running `MigrateToFIPS` again finishes the job.

- Each write ends with a sync; new keyslot material is durable before a header
  names it; the primary copy is durable before the secondary is written. At
  most one header copy can be torn. A torn primary is not repaired by the
  import: it refuses, and `RestorePrimaryHeader` or cryptsetup rebuilds it.
- A rerun first rewrites the secondary from the primary, and requires the two
  copies to agree before its first removal.
- Before reading, each run syncs the device, drops its page cache, and reads
  both header copies through the cache and with `O_DIRECT`. If they differ it
  stops with `ErrDeviceCacheStale`. A loop device's backing file is compared
  too. A stack it cannot map to a backing file (device-mapper, md or a
  partition over a buffered loop device), or a device that refuses `O_DIRECT`,
  fails with `ErrDirectIOUnsupported`, except on tmpfs and ramfs.
- Every keyslot area must lie inside the keyslots area and clear of the data
  segment, or the import stops with `ErrKeyslotAreaOverlap` before reading any
  keyslot. The import never reads or writes the data segment.

### Edge cases

Approved means what strict FIPS mode will run. Under `fips140=only`,
`crypto/pbkdf2` also refuses a salt under 128 bits and an output under 112
bits. A PBKDF2 keyslot or digest below either is treated like Argon2, and
`NonApprovedKDF.Reason` names the parameter.

Argon2 digests from other writers (`time`, `memory`, `cpus` members, bounded
like keyslot KDFs) are evaluated outside FIPS mode and rewritten as PBKDF2 by the
import. In FIPS mode they are refused with `*FIPSImportRequiredError`.

Damage is not reported as a FIPS refusal. The refusal is returned only when
re-screening with approved stand-ins shows the policy is the only obstacle. A
malformed SHA-1 digest is `ErrInvalidHeader`.

### Tests

`TestMigrateToFIPSEveryCrashStateStillOpens`,
`TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume` and
`TestMigrateToFIPSResumedAfterACrashKeepsAWayIn` cover interruption.
`TestFIPSImportOfACryptsetupArgon2idVolume`,
`TestFIPSImportOfACryptsetupVolumeWithShortSalts` and
`TestFIPSImportOfACryptsetupVolumeWithAnUnboundKey` migrate a cryptsetup volume
in a `fips140=off` child and open it in a `fips140=only` child. On the kernel,
`TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData` checks that the
migrated mapping reads the same plaintext as cryptsetup's.

## SHA-1

LUKS1 split keys with SHA-1, and `cryptsetup convert --type luks2` keeps that,
so converted volumes have `af.hash: "sha1"` keyslots and a PBKDF2-SHA1 digest.

- Outside FIPS mode they open and recover the same key cryptsetup does.
- In FIPS mode they are refused before any hashing, with
  `*FIPSImportRequiredError` and `NonApprovedKDF.Reason` set to
  `anti-forensic hash sha1`. Without this gate the module's SHA-1 `Write` error
  would be discarded and the merge would produce wrong bytes.
- The import treats a SHA-1 split as non-approved whatever its KDF, writes a
  PBKDF2-SHA256 keyslot with a SHA-256 split, and rewrites the digest.
- SHA-1 is never written. The split accepts SHA-256 and SHA-512 only.
  `Format`, `AddKey`, `CreateKDF` and the digest writer refuse `pbkdf2-sha1`
  and a `sha1` hash with `ErrSHA1NotWritten` before doing anything.
- `ChangeKey` upgrades a SHA-1 keyslot to a SHA-256 split and PBKDF2-SHA256.
  The iteration count is converted, not copied: the larger of equal work and
  equal measured time, raised to the SHA-256 floor. A result over the ceiling
  fails with `ErrPBKDFIterationsTooHigh` before anything is written.

### The PBKDF2-HMAC-SHA1 exemption

`getPBKDF2HashFunc("sha1")` (`pkg/luks2/kdf.go`) and the anti-forensic merge of a
SHA-1 keyslot (`internal/af`) are the only uses of SHA-1. (Argon2, the other
non-approved primitive, is covered above.)
They exist to read headers cryptsetup wrote before 1.7.0 and LUKS1 volumes
converted to LUKS2, which cannot be opened any other way. No keyslot or digest
is created with SHA-1, and `IsFIPSCompliantKDF("pbkdf2-sha1")` is false.

Both check FIPS mode first and return `ErrFIPSNotApproved`, so SHA-1 never runs
in a FIPS process and callers get a typed error instead of the module's panic
(`use of hash functions other than SHA-2 or SHA-3 is not allowed in FIPS
140-only mode`). A runtime check covers every FIPS deployment, unlike a build
tag. Such a volume must be imported, or opened by a non-FIPS process.

## References

- Go FIPS 140-3 mode: https://go.dev/doc/security/fips140
- NIST SP 800-132, password-based key derivation
- LUKS2 on-disk format specification: keyslot `kdf.hash`, `af.hash`
- `cryptsetup(8)`: `--pbkdf`, `--hash`

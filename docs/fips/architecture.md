# FIPS 140-3 — architecture

> **Status: NORMATIVE** · Last verified: 2026-10-08 against main (bd23163)
> Conflicts with this document are defects. Fix them here first.

go-luks2 runs under the Go Cryptographic Module in FIPS 140-3 mode. "FIPS
mode" below means `crypto/fips140.Enabled()` is true, which holds for both
`GODEBUG=fips140=on` and `fips140=only`; the library treats them the same.
Every policy decision goes through one function, `fipsMode`, which unit
tests substitute so the policy is tested in every ordinary run.

## The problem and the shape chosen

Argon2 comes from `golang.org/x/crypto`, outside the Go Cryptographic Module,
so `GODEBUG=fips140=only` cannot stop it running — the runtime flag alone is
not enough. The library adds its own refusal (`requireFIPSApprovedKDF`,
raised everywhere a derivation can happen) rather than relying on the module
boundary, so a FIPS process can neither create nor open an Argon2 keyslot
regardless of how the header got there. Rejected: a public `fips` package
(see [volumes/architecture.md](../volumes/architecture.md#the-problem-and-the-shape-chosen))
— FIPS mode is a process property, and migrating a volume into compliance is
a `Volume` operation, not a separate subsystem to configure.

## Component boundaries

`internal/fips` (H3b, DECISIONS.md) owns the mode value (`fips.Mode` from
`fips.Probe()`) and the two policy predicates, `RequireKDF`/`RequireHash`,
as methods on it. Two policy sources are in play, and they differ by what
they judge:

- **Derivations** use the volume's own policy. Each `Volume` carries a
  `volumeSys`, and `volumeSys.fipsMode` (`pkg/luks2/volume.go`) is what every
  key derivation on that volume consults. It defaults to `fips.Probe`, the
  process's mode, and a test can force a different policy on one volume without
  touching the others.
- **The parameter preflight** uses the process mode. `AddKeyslot` and
  `ChangeKeyslot` call the public `KDFParams.Validate()` on an explicit KDF
  before writing, and that reads `fips.Probe` directly, not the volume's
  policy. (`Format` passes its volume's policy to the same check.) A policy
  forced on one volume therefore reaches its derivations but not the
  `AddKeyslot`/`ChangeKeyslot` preflight.

`MigrateToFIPS` itself stays in `pkg/luks2` because it needs the keyslot/
digest/header machinery that already lives there.

## Data flow: importing a volume (`MigrateToFIPS`)

Run once, in a process that is not in FIPS mode (otherwise
`*FIPSMigrationError` at the precondition stage, nothing touched). Changes keyslots and digests
only — it does not check or change the data segment's cipher, which dm-crypt
in the kernel runs.

1. Unlock with the passphrase, trying approved keyslots first and only
   keyslots bound to every data segment. The key must match a digest binding
   each segment, or `*FIPSMigrationError` before any write.
2. Require every non-approved digest to attest that key.
3. Add a PBKDF2 keyslot (SHA-256 by default) wrapping the same key, through
   the same path `AddKeyslot` uses ([keyslots](../keyslots/architecture.md)).
4. Rewrite each non-approved digest as PBKDF2 over the same key.
5. Verify: open through the new keyslot and approved digests only, check that
   an approved digest binds the key to every segment, and check that the
   normal unlock scan over approved keyslots and digests returns the same
   key.
6. Remove the non-approved keyslots, unless `KeepNonApproved` is set;
   then `Complete` is false and `RetainedNonApproved` lists them.
7. Re-read the header and check it statically and with a real open.

Nothing is removed before step 5 passes. Only the supplied passphrase carries
over; other credentials that live only in Argon2 keyslots are removed. A
failure returns `*FIPSMigrationError` naming the stage and the state the
volume was left in.

### Interrupted imports

Every state an interruption can leave opens to the original volume key, and
running `MigrateToFIPS` again finishes the job.

- Each write ends with a sync; new keyslot material is durable before a
  header names it; the primary copy is durable before the secondary is
  written. At most one header copy can be torn. A torn primary is not
  repaired by the import: it refuses, and `(*Volume).RestorePrimaryHeader` or
  cryptsetup rebuilds it ([header/architecture.md](../header/architecture.md)).
- A rerun first rewrites the secondary from the primary, and requires the two
  copies to agree before its first removal.
- Before reading, each run syncs the device, drops its page cache, and reads
  both header copies through the cache and with `O_DIRECT`. If they differ it
  stops with `ErrDeviceCacheStale`. A loop device's backing file is compared
  too. A stack it cannot map to a backing file (device-mapper, md or a
  partition over a buffered loop device), or a device that refuses `O_DIRECT`,
  fails with `ErrUnsupported`, except on tmpfs and ramfs.
- Every keyslot area must lie inside the keyslots area and clear of the data
  segment, or the import stops with `ErrKeyslotAreaOverlap`
  ([keyslots/architecture.md](../keyslots/architecture.md#untrusted-keyslots))
  before reading any keyslot. The import never reads or writes the data
  segment.

## SHA-1

LUKS1 split keys with SHA-1, and `cryptsetup convert --type luks2` keeps that,
so converted volumes have `af.hash: "sha1"` keyslots and a PBKDF2-SHA1
digest.

- Outside FIPS mode they open and recover the same key cryptsetup does.
- In FIPS mode they are refused before any hashing, with
  `*FIPSImportRequiredError` and `NonApprovedKDF.Reason` set to
  `anti-forensic hash sha1`. Without this gate the module's SHA-1 `Write`
  error would be discarded and the merge would produce wrong bytes.
- The import treats a SHA-1 split as non-approved whatever its KDF, writes a
  PBKDF2-SHA256 keyslot with a SHA-256 split, and rewrites the digest.
- SHA-1 is never written. The split accepts SHA-256 and SHA-512 only.
  `Format`, `AddKeyslot`, `ChangeKeyslot` and the digest writer refuse
  `pbkdf2-sha1` and a `sha1` hash with `ErrInvalidArgument` before doing
  anything.
- `ChangeKeyslot` upgrades a SHA-1 keyslot to a SHA-256 split and PBKDF2-SHA256.
  The iteration count is converted, not copied: the larger of equal work and
  equal measured time, raised to the SHA-256 floor. A result over the
  ceiling fails with `ErrInvalidArgument` (a `*KDFCostError`) before
  anything is written.

### The PBKDF2-HMAC-SHA1 exemption

`getPBKDF2HashFunc("sha1")` and the anti-forensic merge of a SHA-1 keyslot
(`internal/af`) are the only uses of SHA-1 (Argon2, the other non-approved
primitive, is covered above). They exist to read headers cryptsetup wrote
before 1.7.0 and LUKS1 volumes converted to LUKS2, which cannot be opened any
other way. No keyslot or digest is created with SHA-1.

Both check FIPS mode first and return `ErrFIPSNotApproved`, so SHA-1 never
runs in a FIPS process and callers get a typed error instead of the module's
panic. A runtime check covers every FIPS deployment, unlike a build tag. Such
a volume must be imported, or opened by a non-FIPS process.

## What this feature deliberately does not do

No partial FIPS compliance: a keyslot or digest the policy does not approve
is never silently accepted in FIPS mode, only refused with a typed error
naming `MigrateToFIPS`. No build-tag-gated FIPS behaviour — the check is a
runtime probe so it covers every deployment.

## References

- Go FIPS 140-3 mode: https://go.dev/doc/security/fips140
- NIST SP 800-132, password-based key derivation
- LUKS2 on-disk format specification: keyslot `kdf.hash`, `af.hash`
- `cryptsetup(8)`: `--pbkdf`, `--hash`

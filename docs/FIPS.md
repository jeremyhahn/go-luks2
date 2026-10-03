# FIPS 140-3

`go-luks2` is built and tested against the Go Cryptographic Module so that it can
be consumed from FedRAMP / PCI DSS / HIPAA regulated deployments.

## CI gate

The `FIPS` job in `.github/workflows/ci.yml` builds and runs the full test suite
with:

```
GOFIPS140=latest
GODEBUG=fips140=only
```

`fips140=on` loads the module but still *permits* non-approved algorithms, so a
regulated path using MD5 or SHA-1 would report green. `fips140=only` makes
non-approved operations return errors or panic, which is what the gate exists to
catch. The job runs `go build ./...` and `go test ./...` — full scope, no build
tags, no skipped packages.

## Approved KDFs

`IsFIPSCompliantKDF` reports which KDF types this library considers approved:

| KDF type | FIPS-approved | Notes |
|---|---|---|
| `pbkdf2` | yes | derives with SHA-256 unless `FormatOptions.HashAlgo` overrides it |
| `pbkdf2-sha256` | yes | recommended |
| `pbkdf2-sha384` | yes | |
| `pbkdf2-sha512` | yes | the library default in FIPS mode |
| `pbkdf2-sha1` | **no** | read only, to open legacy headers — never written (#239); see the exemption below |
| `argon2i` | no | refused in FIPS mode |
| `argon2id` | no | refused in FIPS mode; library default otherwise |

## The default KDF follows the mode

`DefaultKDFType()` is the KDF a keyslot is created with when the caller names
none — through `Format`, `AddKey`, `AddRecoveryKey` or `CreateKDF` — and it
follows cryptsetup's model:

| Mode | Default |
|---|---|
| FIPS 140-3 (`crypto/fips140.Enabled()`) | `pbkdf2-sha512`: the iteration count is calibrated to the time budget (`PBKDFIterTime`, 2000 ms by default) and never below the SHA-512 floor for that budget (210,000 at 2000 ms), so the keyslot gets whichever is greater |
| Otherwise | `argon2id`, unchanged |

The KDF hash is the one the type names: `Format` creates the keyslot's KDF from
the caller's `HashAlgo` (empty unless set) rather than the volume's defaulted
digest hash, and `AddKey` from `AddKeyOptions.Hash`. A caller that sets the
hash explicitly still gets it.

A caller that names no KDF but sets an Argon2 cost (`Argon2Time`,
`Argon2Memory`, `Argon2Parallel`) has chosen Argon2 by its parameters and gets
`argon2id` in either mode — refused in FIPS mode — rather than a PBKDF2
keyslot with its cost silently dropped.

Before go-luks2 #237 the default was `argon2id` in both modes, so a FIPS-mode
caller that named no KDF was refused, and the CLI could not create or enroll a
keyslot at all.

## The CLI

`luks2 create` and `luks2 recovery add` take `--pbkdf argon2id|pbkdf2` and the
matching cost options (`--hash`, `--iter-time`, `--pbkdf-force-iterations`,
`--pbkdf-memory`, `--pbkdf-parallel`); see [create](cli/create.md) and
[recovery](cli/recovery.md). With no `--pbkdf` they use the default above, so
under `GODEBUG=fips140=only` both work with no options and write PBKDF2-SHA512
keyslots that cryptsetup opens. `--pbkdf argon2id` in FIPS mode is refused
before the passphrase prompt — and, for `create`, before any file is made —
with the library's `ErrFIPSNotApproved`. `luks2 addkey` with no `--kdf` also
uses the default.

## Enforcement: Argon2 is refused in FIPS mode

Argon2 is implemented in pure Go by `golang.org/x/crypto` (BLAKE2b) and never
enters the Go Cryptographic Module, so `GODEBUG=fips140=only` cannot reject it
and the CI gate cannot fail on it. Left alone, a FIPS-mode process would derive
volume keys with a non-approved KDF — by default, as it was before the default
became mode-aware — while the gate above reported green. `GODEBUG` is not a
sufficient boundary for a KDF the module never sees, so the library enforces it:

`requireFIPSApprovedKDF` in `pkg/luks2/kdf.go` returns
`&CryptoError{Err: ErrFIPSNotApproved}` for `argon2i` and `argon2id` whenever
`crypto/fips140.Enabled()` is true. It is called from:

- `deriveKeyPlain`, before the salt is decoded — reached by every derivation
  through `DeriveKeyEnclave` — so an externally supplied header cannot make a
  FIPS-mode process run a non-approved KDF;
- `CreateKDF`, after the empty-`KDFType` default is resolved. The default is
  approved in FIPS mode, so what this refuses there is an Argon2 KDF the
  caller asked for, by name or by setting an Argon2 cost.

**Effect on callers.** A FIPS-mode process can neither format nor unlock an
Argon2-backed volume, and Argon2id has been the stock cryptsetup LUKS2 default
since 2.0, so that covers most volumes in the field. This is the compliance
position, not an oversight: a process that asked the Go runtime to reject
non-approved cryptography should not then derive regulated keys with a
non-approved KDF. Such a volume must be imported with `MigrateToFIPS` (below),
or opened by a non-FIPS process. Outside FIPS mode Argon2id remains the default
and nothing changes.

## Importing an Argon2 volume: `MigrateToFIPS` (#84)

**What a FIPS process reports.** When every keyslot a FIPS process could not try
was refused only because its KDF — or the KDF of every digest attesting it — is
not approved, the unlock returns `*FIPSImportRequiredError` instead of the bare
refusal. Its message says the volume is intact, names each keyslot and digest
and its KDF, and names `MigrateToFIPS` as the remedy. It matches
`ErrFIPSImportRequired` and `ErrFIPSNotApproved`, and deliberately not
`ErrInvalidKeyslot` or `ErrInvalidHeader`, which say "damaged". If any keyslot
also failed for another reason, that failure is reported as before: a migration
would not fix it.

**What the import does.** The KDF is a property of the keyslot, not of the
volume, and the data cipher (`aes-xts-plain64`) is already approved, so nothing
in the data area changes. `MigrateToFIPS(device, passphrase, opts)`:

1. unlocks with the passphrase — FIPS-approved keyslots are tried first, and
   only keyslots whose digests bind every data segment are tried at all; the
   key recovered must match a digest binding each segment, or the import
   refuses with `ErrFIPSMigrationUnboundKey` before any write. A LUKS2 header
   may carry unbound keys beside the volume key, and carrying one across while
   removing the keyslot holding the real one would leave a volume whose
   migrated keyslot opens and whose data does not;
2. requires every digest whose KDF is not approved to attest the recovered
   volume key, refusing before any write otherwise;
3. adds a PBKDF2 keyslot (SHA-256 by default) wrapping the same volume key,
   through `AddKey`'s own code;
4. rewrites each non-approved digest as a PBKDF2 digest over the same key —
   `verifyMasterKey` derives through the digest's KDF on every unlock, so a
   volume with PBKDF2 keyslots and a PBKDF2-SHA1 digest (what `cryptsetup
   convert` leaves on an old LUKS1 volume) is still unopenable under FIPS;
5. verifies with a real open through the new keyslot and approved digests
   only, that an approved digest binds the key it recovers to every data
   segment, and that the ordinary unlock scan — the one `Unlock` hands to
   dm-crypt — run over only the approved keyslots and digests recovers that
   same volume key. The last check is what catches a retained approved keyslot
   holding an unbound key under the same passphrase: opening the new keyslot
   directly cannot see it;
6. removes the non-approved keyslots, each through the removal gate every
   removal in the package takes — unless `KeepNonApprovedKeyslots` is set, in
   which case `FIPSMigrationResult.Complete` is false and
   `RetainedNonApprovedKeyslots` names them;
7. re-reads the header and checks it statically (no keyslot or digest that is
   not approved remains, other than those kept on request) and with a real open.

Nothing is removed until step 5 passes, so no state along the way is
unopenable; a `*FIPSMigrationError` names the failed stage and the state the
volume was left in. Only the supplied passphrase is carried across: other
credentials held only in Argon2 keyslots are removed with them unless kept.

**If the process dies or the power goes mid-import.** Every write step ends
with a sync, the new keyslot's material is durable before a header names it,
and each header write makes the primary copy durable before it touches the
secondary, so an interruption can tear at most one header copy. Every state
the device can be left in opens to the original volume key: cryptsetup picks
the newest intact copy and repairs the other itself; this library reads the
primary, and if the interruption tore it, `RestorePrimaryHeader` rebuilds it
from the secondary. Running `MigrateToFIPS` again on any such state finishes
the import. That holds for a run started from what an interrupted one left,
too: such a run can find the copies apart (a primary naming the new PBKDF2
keyslot beside a secondary that does not, or a torn secondary), so before its
first write it rewrites the secondary from the primary — first making the
primary it read durable, since an interrupted process can leave one that reads
back whole from the page cache but is not yet on the medium, then writing the
secondary alone — and before the first removal it requires the two copies to
agree. Copies that agree may still agree only in the page cache — a run stopped
after writing the secondary and before syncing it, or a writeback error after
which the kernel keeps the unwritten bytes as clean cached pages that a later
`fsync` does not rewrite — so every run, under its lock and before its first
read, syncs the device and evicts its cached pages
(`posix_fadvise(POSIX_FADV_DONTNEED)`). Eviction is advisory — a page another
process holds mapped survives it — so the run then reads the two header copies
(bounded by the primary's own `hdr_size`, so no keyslot or data byte is read)
both through the cache and past it (`O_DIRECT`) and requires them to be
identical; if they are not it stops with `ErrDeviceCacheStale`, having written
nothing. "Past it" means past every cache on the way to the medium: a loop
device without direct I/O reads its backing file through that file's page
cache, so a loop device's backing is compared too, at the loop offset, all the
way down (a direct-I/O loop device can sit on a buffered one); a
device-mapper, md or partition device with such a loop device anywhere below
it cannot be mapped to a backing-file offset in general and is refused with
`ErrDirectIOUnsupported` (`losetup --direct-io=on`, or importing the backing
file itself, is the remedy). Where `O_DIRECT` is refused the run also stops
with `ErrDirectIOUnsupported`, except on a memory filesystem (tmpfs, ramfs),
where the cache is the only copy there is. A
torn primary is not repaired by the import; it refuses before writing, and
`RestorePrimaryHeader` (or cryptsetup) rebuilds it. When a header write fails
having damaged the primary, the `*FIPSMigrationError` state says so and names
`RestorePrimaryHeader`, rather than claiming the volume opens as before. The
report judges the header copies on the MEDIUM — read past the page cache, which
after a failed writeback may still hold a primary the medium does not — and
says plainly when the medium cannot be read; it reads the secondary only where
the volume's own geometry puts it, never probing further offsets that, on a
small-metadata layout, are encrypted data.
`TestMigrateToFIPSEveryCrashStateStillOpens` enumerates those
states for a cryptsetup volume with two Argon2id keyslots and a PBKDF2-SHA1
digest — every partial write of every step — and checks all three claims
against cryptsetup and this library; `TestMigrateToFIPSFailingAtEachWriteLeavesAnOpenableVolume`
fails each write in turn and checks the reported stage and state as well, and
`TestMigrateToFIPSResumedAfterACrashKeepsAWayIn` re-runs the import from the
torn states of the header write that adds the keyslot and checks every state a
second crash could leave.

Volumes whose keyslots use a SHA-1 anti-forensic hash — `cryptsetup
luksFormat --hash sha1`, or any LUKS1 volume converted with `cryptsetup
convert` — are imported the same way: see "SHA-1 anti-forensic keyslots" below.

**Why it runs outside FIPS mode.** Step 1 executes the volume's Argon2 keyslot.
The import is therefore a non-FIPS step that produces a FIPS-ready volume, and
the FIPS process that later opens it never executes the unapproved primitive.
Called in a FIPS process, `MigrateToFIPS` returns `ErrFIPSMigrationUnderFIPS`
without touching the device.

**How the outcome is verified.** FIPS mode is fixed at process start, so the
migrating process cannot open the result "under FIPS" itself (owner ruling
2026-09-25). Steps 5 and 7 are the in-process layers; the third is
`TestFIPSImportOfACryptsetupArgon2idVolume`, which formats a volume with
cryptsetup (its defaults, at its minimum Argon2 cost), migrates it in a child
process started with
`GODEBUG=fips140=off`, and opens it in one started with `GODEBUG=fips140=only`,
checking cryptsetup still opens it and the data area is unchanged.
`TestFIPSImportOfACryptsetupVolumeWithShortSalts` does the same for approved
names over salts strict FIPS refuses, and
`TestFIPSImportOfACryptsetupVolumeWithAnUnboundKey` for a cryptsetup
`luksAddKey --unbound` keyslot sharing the passphrase: the key a
`fips140=only` process's unlock scan recovers must be the volume key cryptsetup
itself dumps. They run in the unit suite and as their own step in the nightly
FIPS job. On the real kernel, the integration suite's
`TestFIPSImportOfADefaultCryptsetupVolumeMapsTheSameData` writes plaintext
through cryptsetup's mapping of a default volume, imports it, and requires a
`GODEBUG=fips140=only` process's `Unlock` — the key it hands dm-crypt — and
cryptsetup's own mapping both to read the same plaintext back, with the
ciphertext unchanged.

**Which key the unlock scan returns.** Keyslots whose digests bind every data
segment are tried before any that do not, so a passphrase shared by the volume
key's keyslot and an unbound one opens the volume with the volume key whatever
the keyslot numbers — matching cryptsetup, which activates only through
keyslots bound to the segment. Nothing is filtered out: a keyslot outside that
group is still tried after it. A keyslot added by `AddKey` (and so by the
import) joins only the digest its key matches; it used to be appended to every
digest, which cryptsetup refuses ("Keyslot N is not assigned to exactly 1
digest").

**"Approved" means what strict FIPS mode will run, not what the header
names.** Under `GODEBUG=fips140=only`, `crypto/pbkdf2` also refuses a salt
shorter than 128 bits and an output shorter than 112 bits. A PBKDF2-SHA256
keyslot or digest below either floor has an approved name and still cannot be
opened, so the import treats it exactly as it treats Argon2: such a keyslot is
never reused as the migrated one and is removed, such a digest is rewritten, and
the static check in step 7 applies the same floors. `NonApprovedKDF.Reason`
names the parameter when the algorithm itself is approved.
`TestFIPSImportOfACryptsetupVolumeWithShortSalts` proves it across processes
in the nightly FIPS job.

**Argon2 digests.** LUKS2 digests are PBKDF2 in cryptsetup and in this package,
but a foreign writer's need not be. A digest declaring `argon2i`/`argon2id`
carries its cost in `time`, `memory` and `cpus` members, named as an Argon2
keyslot KDF names them and bounded by the same limits; with no `hash` its value
must be 32 bytes. Outside FIPS mode it is evaluated like any other digest, so
such a volume opens and can be imported; step 4 rewrites it as PBKDF2 and drops
the Argon2 cost members. In FIPS mode it is refused with
`*FIPSImportRequiredError` naming the digest.

**Damage is never reported as a FIPS refusal.** The error above is returned only
when the refusal is computed to be the FIPS policy's alone: the keyslot is
screened again with every refused KDF replaced by an approved stand-in, after
each replaced KDF has passed the structural half of the screen. A SHA-1 digest
whose value is not base64, for example, is reported as `ErrInvalidHeader`.

**What may be read or wiped.** An unlock reads a keyslot's whole declared area
and a removal randomizes it, and that area comes off the device. Before the
first keyslot is read, every keyslot's area must lie inside the container's
reserved keyslots area (`config.keyslots_size`, from twice the header size) and
clear of every data segment, and each area is checked again at its wipe;
otherwise the import refuses with `ErrKeyslotAreaOverlap`, having read no
keyslot and changed nothing. The import reads and writes header and keyslot
space only — never a byte of the data segment.

**Testing the FIPS policy without a FIPS process.** Every FIPS policy decision
in the package asks one unexported function, `fipsMode` (`crypto/fips140.Enabled`).
The unit tests substitute it so the refusal classification above runs in every
ordinary test run, not only in the nightly FIPS job; what the Go Cryptographic
Module itself enforces under `GODEBUG=fips140=only` is still proved by the
child-process tests.

## SHA-1 anti-forensic keyslots (#236)

LUKS1 split the volume key across its anti-forensic stripes with SHA-1 by
default, and `cryptsetup convert --type luks2` keeps that, so every converted
LUKS1 volume carries keyslots with `af.hash: "sha1"` — as does any volume from
`cryptsetup luksFormat --hash sha1`, together with a PBKDF2-SHA1 digest.

**Outside FIPS mode** such keyslots are read: the merge resolves SHA-1
(`getAFMergeHashFunc`) and recovers the same volume key cryptsetup does. Both
shapes are checked against real cryptsetup, on file images by
`TestSHA1AFVolumesOpenWithCryptsetupsVolumeKey` and on the kernel by the
integration suite's `TestSHA1AFVolumesMapTheSameDataOnTheKernel`, which reads
plaintext written through cryptsetup's mapping back through one `Unlock` made.

**In FIPS 140-3 mode** they are refused before any hashing runs. SHA-1 is not an
approved diffuser of key material, and under `GODEBUG=fips140=only` the Go
module makes SHA-1's `Write` return an error that `hash.Hash` callers discard,
so without the gate the merge would complete with wrong bytes rather than fail.
The refusal is the typed `*FIPSImportRequiredError` described above, naming the
keyslot's anti-forensic hash — for example `keyslot 0 uses pbkdf2-sha1
(anti-forensic hash sha1) and digest 0 uses pbkdf2-sha1` for a converted LUKS1
volume — and `NonApprovedKDF.Reason` carries `anti-forensic hash sha1`.

**The import** (`MigrateToFIPS`, run outside FIPS mode) treats a SHA-1 AF
keyslot as non-approved whatever its KDF: it is never reused as the migrated
keyslot, the new keyslot is PBKDF2-SHA256 with a SHA-256 split, the SHA-1
digest is rewritten, the original keyslots are removed by default, and the
static check refuses any SHA-1 AF hash that remains. `TestFIPSImportOfSHA1AFVolumes`
imports both shapes and opens the result in a `fips140=only` process, and the
integration test does the same on the kernel.

**SHA-1 is read, never written** — in either half of a keyslot, or in a
digest (#236, #239). The anti-forensic split accepts SHA-256 and SHA-512 only,
and no path creates a PBKDF2-SHA1 KDF: `Format`, `AddKey`, `CreateKDF` and the
digest writer refuse the `pbkdf2-sha1` type and a `sha1` hash (any case) with
`ErrSHA1NotWritten`, alongside `ErrUnsupportedKDF` or `ErrUnsupportedHash`,
before they derive or write anything — `AddKey` before it even unlocks the
existing keyslot. `ChangeKey` on a SHA-1 keyslot rewrites both halves: a
SHA-256 split of the same size, and a PBKDF2-SHA256 KDF whose iteration count
is CONVERTED from the old keyslot's cost, not copied. PBKDF2 derives its output
in blocks of the hash's length, each a full chain of iterations, so a 64-byte
key is four SHA-1 blocks but two SHA-256 blocks and the same count would halve
the work; and on CPUs with SHA extensions an HMAC-SHA256 can cost less than an
HMAC-SHA1. The count is the larger of equal work (as many SHA-256 HMACs as the
SHA-1 keyslot took) and equal time measured on the machine doing the rewrite
(slowest SHA-1 sample against fastest SHA-256 sample), raised to the SHA-256
floor; a result past the iteration ceiling is refused with
`ErrPBKDFIterationsTooHigh` before anything is written. `TestChangeKeyRewritesAPBKDF2SHA1KeyslotAsSHA256`
does it to a cryptsetup-converted LUKS1 keyslot and opens the result with
cryptsetup. This is a breaking change: code that created PBKDF2-SHA1 keyslots
now gets the error.

## Exemption: PBKDF2-HMAC-SHA1 for legacy LUKS headers

**Scope.** `getPBKDF2HashFunc("sha1")` in `pkg/luks2/kdf.go`, reachable through
`DeriveKeyEnclave` and `BenchmarkPBKDF2` when they are handed an existing SHA-1
keyslot's or digest's KDF (`CreateKDF` refuses SHA-1 since #239), and
`getAFMergeHashFunc("sha1")` in
`pkg/luks2/antiforensic.go`, the anti-forensic MERGE of a SHA-1 keyslot (see
"SHA-1 anti-forensic keyslots" below). Nothing else in this repository uses
SHA-1 or any other non-approved primitive; the anti-forensic SPLIT, which writes
keyslots, accepts only SHA-256 and SHA-512.

**Why the primitive is needed.** A LUKS keyslot records the hash its PBKDF2
digest was derived with, in the LUKS1 `hash-spec` header field and in the LUKS2
JSON keyslot `kdf.hash` field. cryptsetup used SHA-1 as the LUKS1 default until
1.7.0, so volumes formatted by older releases carry `sha1` and can only be
unlocked by recomputing PBKDF2-HMAC-SHA1 over the passphrase. This project is
required to interoperate correctly with the cryptsetup userspace tools, so the
primitive cannot simply be deleted without losing the ability to open
those volumes.

**Why it is not a compliance violation.** The exemption covers reading an
externally-defined on-disk format, not the protection of regulated data by this
library's own choices. No keyslot or digest is created with PBKDF2-SHA1 — every
creation path refuses it with `ErrSHA1NotWritten` (#239) — and
`IsFIPSCompliantKDF("pbkdf2-sha1")` returns `false` so callers cannot be told
otherwise.

**How it is isolated from the FIPS-gated path.** `getPBKDF2HashFunc` checks
`crypto/fips140.Enabled()` and returns `ErrFIPSNotApproved` before the call can
reach `golang.org/x/crypto/pbkdf2`. The Go Cryptographic Module permits PBKDF2
only with SHA-2 and SHA-3 and panics with

```
crypto/pbkdf2: use of hash functions other than SHA-2 or SHA-3 is not allowed
in FIPS 140-only mode
```

under `GODEBUG=fips140=only`. The runtime guard means the SHA-1 derivation never
executes in a FIPS-mode process — a stronger boundary than a build tag, because
it holds for every FIPS deployment of this library rather than only for binaries
built with a particular tag, and it lets the FIPS CI job keep exercising the
whole tree. Outside FIPS mode the behavior is unchanged.

`crypto/fips140.Enabled()` reports true for both `fips140=on` and `fips140=only`
and there is no exported way to distinguish them, so SHA-1 is refused under `on`
as well. That is deliberate: a process running in FIPS mode should not derive
keys with a non-approved primitive regardless of whether the module would have
tolerated it.

**Effect on callers.** A FIPS-mode process that opens a legacy `sha1` volume gets
`ErrFIPSNotApproved` (checkable with `errors.Is`) rather than a panic. Such a
volume must be re-keyed to an approved hash — or opened by a non-FIPS process —
before it can be used in a regulated deployment.

## References

- Go FIPS 140-3 mode: https://go.dev/doc/security/fips140
- `crypto/fips140` — `Enabled` reports FIPS 140-3 mode for both `on` and `only`
- `golang.org/x/crypto/pbkdf2` — rejects hashes other than SHA-2/SHA-3 in
  FIPS 140-only mode
- NIST SP 800-132 — Recommendation for Password-Based Key Derivation
- LUKS1 on-disk format specification — `hash-spec` header field
- LUKS2 on-disk format specification — keyslot `kdf.hash` JSON field
- `cryptsetup(8)` — `--hash`, `--pbkdf`

### Added

- **`MigrateToFIPS` imports an Argon2 volume into a FIPS 140-3 deployment
  without re-encrypting it (#84).** A FIPS process cannot execute Argon2, which
  is cryptsetup's default KDF, so it could not open any volume from a plain
  `cryptsetup luksFormat`. The refusal stays; this is the way in. Run once from
  a process not in FIPS mode, it adds a PBKDF2 keyslot wrapping the existing
  volume key, migrates any digest whose KDF is not approved, verifies the
  volume opens through approved KDFs alone, and then removes the Argon2
  keyslots — nothing is removed before that verification, and the data area is
  never touched. `KeepNonApprovedKeyslots` keeps the originals and the result
  reports the import incomplete. Called in a FIPS process it refuses with
  `ErrFIPSMigrationUnderFIPS`. See `docs/FIPS.md`.
  It carries across only the key a digest binds to every data segment — an
  unbound key the same passphrase opens is never mistaken for it
  (`ErrFIPSMigrationUnboundKey`) — and judges a KDF by what strict FIPS mode
  will run: a PBKDF2-SHA256 keyslot or digest whose salt is under 128 bits, or
  whose output is under 112, is migrated like Argon2 rather than kept. It
  reads and writes header and keyslot space only: every keyslot's declared
  area must be confined to the keyslots area, clear of the data, before the
  first keyslot is read (`ErrKeyslotAreaOverlap`).
- **Digests whose KDF is Argon2 are evaluated outside FIPS mode (#84).** The
  digest model gains `time`, `memory` and `cpus`, omitted when unset, so a
  foreign volume whose digest uses Argon2 opens outside FIPS mode and can be
  imported; `MigrateToFIPS` rewrites such a digest as PBKDF2.

### Fixed

- **An interrupted header write can no longer tear both header copies (#84).**
  The primary copy is synced before the secondary is written, so a crash or
  power loss at any point leaves at least one complete copy; before, both
  copies were synced only together at the end and writeback could leave both
  half-written. Every header write takes this path, including each step of
  `MigrateToFIPS`, whose every crash state is now tested to open — in
  cryptsetup, and in this library through `RestorePrimaryHeader` when the
  primary was the copy torn — and to finish importing when run again.
- **Re-running an interrupted `MigrateToFIPS` can no longer lose the last way
  in (#84).** A run that found a stale or torn secondary header copy — what an
  interrupted earlier run can leave — went on to wipe the Argon2 keyslot while
  the secondary still named only it, so one more interruption could leave no
  readable copy that opened the volume. It now repairs the secondary from the
  primary (syncing the primary it read first, then writing the secondary
  alone) before its first write — every run first syncs the device, evicts
  its cached pages, and confirms the two header copies read through the cache
  are byte-identical to the same bytes read with `O_DIRECT` past every cache
  to the medium (including every loop device's backing, all the way down),
  never reading past them, so what it
  acts on is what is on the medium and not what an interrupted or failed
  earlier write left in the page cache (`ErrDeviceCacheStale`,
  `ErrDirectIOUnsupported`) — and requires
  the copies to agree before the first removal. A header write that fails
  having damaged the primary is reported as such, naming
  `RestorePrimaryHeader`, instead of as a volume that "still opens exactly as
  it did before" — judged from the header copies on the medium, read past the
  page cache, not from what the cache still holds.

- **An unbound key no longer shadows the volume key (#84).** The unlock scan
  tries keyslots whose digests bind every data segment first, so a passphrase
  shared with an unbound keyslot of a lower number opens the volume with the
  volume key rather than handing dm-crypt the unbound one. `MigrateToFIPS`
  verifies that the scan, over approved keyslots and digests only, recovers the
  volume key before it removes anything.
- **`AddKey` assigns the new keyslot to exactly one digest (#84).** It used to
  append the keyslot to every digest, so on a header carrying an unbound key
  the result was refused by cryptsetup ("Keyslot N is not assigned to exactly 1
  digest"). It now joins only the digest its key matches.

### Changed

- **Header-reader rejections are typed (#84).** A checksum mismatch, a bad
  magic and a recorded offset or size that disagrees with where the copy was
  read all match `ErrInvalidHeader`; a header whose version is not 2 (LUKS1)
  matches the new `ErrUnsupportedLUKSVersion` and not `ErrInvalidHeader`,
  because it is not damage. A checksum mismatch used to be untyped, so a caller
  could not tell a torn header copy from an I/O failure and reach for
  `RestorePrimaryHeader`.

- **A FIPS process that cannot open a volume only because of its KDFs now says
  so (#84).** It returns `*FIPSImportRequiredError` — the volume is intact, these
  keyslots or digests use a KDF FIPS mode cannot execute, `MigrateToFIPS` is the
  remedy — instead of "invalid keyslot: argon2id: algorithm not approved", which
  read as corruption. It still matches `ErrFIPSNotApproved`; it no longer matches
  `ErrInvalidKeyslot`/`ErrInvalidHeader` in that case, because the volume is not
  damaged. A volume that is also damaged is reported as damaged, as before.

### Added

- **`ErrMetadataLockUnavailable`.** A write to a block device whose cryptsetup
  lock directory (`/run/cryptsetup`) is missing and not creatable, is a symlink
  or a file, or does not admit the caller now matches this sentinel, still
  wrapped in the `DeviceError` it was before and with the errno reachable.
  cryptsetup refuses the same states; docs/COMPATIBILITY.md has the measured
  table, and the group grant that lets a non-root caller use both tools.
- **A cryptsetup interoperability matrix in the integration suite**: every
  keyslot, token, header and data operation done by one tool and checked by
  the other, cryptsetup-formatted volumes with non-default options, the lock
  directory in each state against cryptsetup as root and as a setuid disk-group
  user, and every write path racing a cryptsetup write in both orders. The
  integration container gains `CAP_SETUID` and `CAP_SETGID` for the setuid
  child.

### Changed — BREAKING: headers with more than 32 keyslots or digests are refused, and one operation's key derivation is capped

- **An aggregate key-derivation and locked-memory budget per operation
  (#26).** A header with more than 32 keyslots or 32 digests is now refused on
  read with `ErrInvalidHeader`; cryptsetup writes no such header. A keyslot
  scan prices its derivations before the first one and fails with the new
  `ErrKDFBudgetExceeded` (also `ErrInvalidHeader`) when they add up to more
  than the most expensive header cryptsetup can write -- 32 keyslots, one
  digest each, every derivation at its ceiling -- so no cryptsetup container
  is refused. Every enclave is admitted against go-enclave's process
  `Allocator`: a binary that installs one with `enclave.SetAllocator` bounds
  this library's locked memory, and a keyslot the budget can never admit is
  refused before its derivation. A consumer needs to change nothing unless it
  opens crafted headers, or installs its own process allocator after first
  using this library (go-enclave's install is one-shot).

### Fixed

- **Volumes cryptsetup handles that go-luks2 could not open.** Keyslots
  encrypted with `aes-cbc-essiv:sha256`, `aes-cbc-plain64` or `aes-cbc-plain`
  (`--keyslot-cipher`, a CBC data cipher, or `cryptsetup convert` from LUKS1)
  are read; a passphrase change rewrites one as `aes-xts-plain64`. Volume keys
  of 16 and 24 bytes (128- and 192-bit CBC data ciphers) are accepted, and a
  new keyslot for one is wrapped with AES-256-XTS. The 20-byte digest every
  converted LUKS1 volume carries is verified. A detached header's keyslots
  can be opened, added, changed and removed; its activation is still refused.
- **Unlock mapped a `--integrity` volume without dm-integrity.** Reads were
  garbage and every write destroyed the integrity tags. Activation is now
  refused with `ErrUnsupportedSegmentLayout` before any key is derived.
- **The header's persistent performance flags reach dm-crypt.** `same-cpu-crypt`,
  `submit-from-crypt-cpus`, `no-read-workqueue` and `no-write-workqueue` are in
  the table as cryptsetup puts them; `allow-discards` deliberately is not.
- **A symlinked `/run/cryptsetup` was followed**, so the lock was taken where
  cryptsetup never looks. It is refused, as cryptsetup refuses it.
- **Concurrent `SetupLoopDevice` calls failed with `LOOP_SET_FD: EBUSY`** when
  both were handed the same free device; the loser now asks for another.

### Security

- **The last-keyslot guard no longer counts an unbound keyslot as a survivor
  (#249).** A keyslot written by `cryptsetup luksAddKey --unbound`, or bound only
  to another segment, holds a key that decrypts nothing, yet `RemoveKey`,
  `KillSlot`, `KillKeyslot` and `WipeKeyslot` counted it and destroyed the only
  keyslot holding the volume key. A survivor must now be declared bound to every
  data segment, sit at an id cryptsetup can address, and lie in keyslot space.
- **Every keyslot wipe is confined to the keyslots area (#249).** A header
  declaring a keyslot area over the header copies or the encrypted payload had
  it overwritten by `RemoveKey`, `KillSlot`, `KillKeyslot`, `ChangeKey`'s
  cleanup and `WipeKeyslot`. They now refuse with `ErrKeyslotAreaOverlap`, and
  the unlock scan no longer reads such a keyslot.
- **Keyslot operations stay on the device they locked (#249).** `AddKey`,
  `ChangeKey`, `RemoveKey`, `KillSlot`, `KillKeyslot`, `WipeKeyslot`,
  `TestKey` and `VerifyRecoveryKey` open the path once and do every read, size
  check, write, sync and wipe through that descriptor, so a path re-pointed
  mid-operation cannot redirect the writes.

### Fixed

- **`ChangeKey` on a keyslot with a non-standard stripe count no longer
  destroys it (#249).** It split into 4000 stripes but kept the old
  `af.stripes`, then wiped the old area. The rewritten keyslot now declares
  4000 stripes (growing its area if needed), and both `ChangeKey` and `AddKey`
  read the new keyslot back from the committed header and require it to open to
  the volume key before anything old is destroyed; one that does not is rolled
  back.
- **cryptsetup `--keyslot-key-size` volumes open (#249).** The passphrase is
  derived to `area.key_size`, not the volume key's size.
- **`ValidateDevicePath` accepts names containing `..`** such as
  `/dev/disk/by-label/a..b` (#249); `..` path elements are still resolved and
  relative paths still refused.

### Changed — BREAKING: existing credentials, recovery keys, Argon2 and PBKDF2 costs (#249)

- **An existing credential is no longer held to the new-passphrase policy.**
  `Unlock`, `TestKey`, `RemoveKey`, `KillSlot`, `MigrateToFIPS` and the existing
  credential of `AddKey` and `ChangeKey` accept 1 byte to 8 MiB (cryptsetup's key
  file limit), so a 4 KiB key file or a short legacy passphrase opens. Empty and
  over-long credentials return the new `ErrCredentialEmpty` and
  `ErrCredentialTooLong`; `ErrPassphraseTooShort`/`TooLong` now apply only to new
  passphrases.
- **A passphrase that opens only an unbound keyslot no longer authenticates**
  `TestKey`, `AddKey`, `KillSlot` or `VerifyRecoveryKey`; it gets
  `ErrMasterKeyVerification`, as with cryptsetup.
- **`GenerateRecoveryKey` and `AddRecoveryKey` refuse fewer than 32 random
  bytes**, a negative length, a rendering longer than 512 bytes
  (`ErrRecoveryKeyTooShort`) and an unknown format
  (`ErrInvalidRecoveryKeyFormat`) instead of rendering it dashed.
- **Argon2 creation refuses costs the reader refuses**: memory over 4 GiB, time
  over 10000, parallelism over 255. `Argon2CostError` gains `Maximum`.
- **A calibrated PBKDF2 count for a caller's passphrase is held to the OWASP
  floor at the 2000 ms reference budget**, so `PBKDFIterTime: 1` no longer
  yields ~1000 iterations.
- **The unlock scan skips keyslot ids cryptsetup cannot address** (`01`, `32`,
  `abc`).

### Added

- **`luks2 create` and `luks2 recovery add` take KDF options (#237):**
  `--pbkdf argon2id|pbkdf2`, `--hash`, `--iter-time`,
  `--pbkdf-force-iterations`, `--pbkdf-memory` and `--pbkdf-parallel`, named
  as cryptsetup names them. They are validated against the process's mode
  before the passphrase prompt and before `create` makes a file: an option
  that does not apply to the chosen KDF, an empty value, or a value that is
  not a whole number above zero is refused, and in FIPS 140-3 mode
  `--pbkdf argon2id` is refused with the library's `ErrFIPSNotApproved`. Cost
  bounds stay the library's and are checked when the keyslot is written.
  `create` reports the KDF it used.
- `luks2.DefaultKDFType()` reports the KDF a keyslot gets when the caller
  names none, and `RecoveryKeyOptions.PBKDFIterTime` sets the PBKDF2 budget of
  a recovery keyslot.

### Changed

- **The library's default KDF follows the mode, as cryptsetup's does (#237).**
  In FIPS 140-3 mode a keyslot created with no KDF named -- through `Format`,
  `AddKey`, `AddRecoveryKey` or `CreateKDF` -- is PBKDF2-SHA512, calibrated
  to the time budget and never below the SHA-512 iteration floor (210,000 at
  the default 2000 ms). Before, the default was Argon2id in every mode, so it
  was refused in FIPS mode: `luks2 create` (which hard-coded Argon2id) and
  `luks2 recovery add` could create no keyslot under `GODEBUG=fips140=only`,
  even on a volume whose keyslots were all PBKDF2. Outside FIPS mode the
  default is Argon2id, unchanged.
- A caller that names no KDF but sets an Argon2 cost gets Argon2id in either
  mode -- refused in FIPS mode -- rather than a PBKDF2 keyslot with the cost
  silently dropped.

### Fixed

- **A KDF alias's hash is honored by `Format` and `AddKey` (#237).** Both
  defaulted the hash to SHA-256 before creating the keyslot's KDF, and that
  overrode the hash an alias names, so `KDFType: "pbkdf2-sha512"` (or
  `-sha384`) wrote a PBKDF2-SHA256 keyslot. The keyslot now uses the alias's
  hash; a hash the caller sets explicitly still wins, and the volume digest
  keeps its own default.
- **`Format`'s Argon2 cost floor applies when the KDF is left to the default
  (#237).** The floor was checked only when `KDFType` was spelled `argon2id`
  or `argon2i`, so `FormatOptions{Argon2Memory: 32}` with no type passed it.
  It is now checked against the KDF the options resolve to.

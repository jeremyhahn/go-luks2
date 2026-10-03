### Changed

- **BREAKING: no keyslot or digest is created with a PBKDF2-SHA1 KDF (#239).**
  `Format`, `AddKey`, `CreateKDF` and the digest writer refuse
  `KDFTypePBKDF2SHA1` and a `sha1` hash (`FormatOptions.HashAlgo`,
  `AddKeyOptions.Hash`, in any case) with the new `ErrSHA1NotWritten`,
  alongside `ErrUnsupportedKDF` or `ErrUnsupportedHash`, before deriving or
  writing anything; `AddKey` refuses before unlocking the existing keyslot.
  Code that created PBKDF2-SHA1 keyslots must choose `pbkdf2` with sha256,
  sha384 or sha512, or Argon2. `ChangeKey` on a PBKDF2-SHA1 keyslot (a
  converted LUKS1 one, for example) now rewrites it as PBKDF2-SHA256 instead
  of preserving SHA-1, at an iteration count converted from the old keyslot's
  cost -- the larger of equal HMAC work for the key's length and equal time
  measured on the machine, raised to the SHA-256 floor -- never simply copied,
  since the same count can halve the work for a 64-byte key. Existing SHA-1 keyslots and digests still open outside
  FIPS mode, byte-compatible with cryptsetup. See docs/FIPS.md.
  The CLI's `addkey --kdf pbkdf2-sha1` (and any unknown KDF) is refused as a
  usage error before either passphrase is asked for; `--hash` and `--pbkdf`
  already accept no SHA-1 (#237).

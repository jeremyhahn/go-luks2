### Added

- **`UnlockWithVolumeKey` opens a volume with a key the caller already holds
  (#79).** The caller passes the volume key as an `*enclave.MemoryEnclave`
  instead of a passphrase. No keyslot is scanned and the keyslot KDF never
  runs, so the passphrase derivation and its unwipeable copies are not on the
  path. This is the unlock half of the owner's ruling on #79. The format half,
  with its mandatory recovery keyslot, follows as a separate change. The
  library still has no hardware code and no policy about where a key comes
  from.

  The new entry point shares its whole body with `Unlock`: path, name, in-use,
  header and segment validation, the keyring transport and the rollback. The
  key must be attested by a digest assigned to the crypt segment being mapped,
  and its length must equal the `key_size` of a keyslot that digest names.
  The length check is needed because HMAC zero-pads a short key, so the volume
  key with zero bytes appended passes the digest. A key failing either check
  is refused with `ErrMasterKeyVerification`. A nil, destroyed or oversized
  enclave is refused with the new `ErrInvalidVolumeKey`. The caller's enclave
  is never destroyed.

  The digest check runs PBKDF2 over the key, so residual exposure 2 still
  applies to this path once per digest tried. `enclave.go` and the README
  record this. Passphrase paths and `ErrLastKeyslot` are unchanged.

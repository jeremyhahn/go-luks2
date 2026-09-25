### Changed — BREAKING: a keyslot whose declared area cipher mode is not AES-XTS is refused

- **The read path now honors the whole `keyslots.<n>.area.encryption` spec,
  not only its algorithm (#106).** `unlockKeyslot` (through `screenKeyslot`,
  so the removal guard too) accepts exactly `aes-xts-plain64` and
  `aes-xts-plain` — the two spellings of the transform keyslot material
  actually goes through — and refuses every other spec with the new sentinel
  `ErrUnsupportedKeyslotCipher`, wrapped in `ErrInvalidKeyslot` so the keyslot
  scan still moves on to the next slot. Previously a keyslot declaring, say,
  `aes-cbc-essiv:sha256` was decrypted as AES-XTS regardless: it opened here
  and in no conforming implementation, and no test could notice a wrong
  declaration.
- **Who is affected:** containers formatted by v0.1.x of this package with a
  non-XTS data cipher (`CipherMode` other than `xts-plain64`) carry AES-XTS
  keyslot material under the data cipher's label. `cryptsetup` never opened
  those keyslots; after this change this package does not either, and
  `TestKey`, `Unlock`, `AddKey` and `ChangeKey` report
  `ErrUnsupportedKeyslotCipher` for them. Containers written by `cryptsetup`
  or by current `Format` are unaffected. A genuine cryptsetup CBC keyslot, which
  used to fail as `ErrMasterKeyVerification` (indistinguishable from a wrong
  passphrase), is now reported as the unsupported cipher it is.

### Added

- **`luks2 addkey` and `luks2 changekey` take the shared KDF options (#287).**
  `--pbkdf`, `--hash`, `--iter-time`, `--pbkdf-force-iterations`,
  `--pbkdf-memory` and `--pbkdf-parallel` work on `create`, `recovery add`,
  `addkey` and `changekey` alike, named as cryptsetup names them. They are
  checked before the passphrase prompt; an option that does not apply to the
  chosen KDF is refused rather than ignored. With none given, the library's
  default or inherited cost applies as before.

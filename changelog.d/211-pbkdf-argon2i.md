### Added

- **`--pbkdf argon2i` is accepted (#211).** `create`, `addkey`, `changekey`
  and `recovery add` take all three values cryptsetup's `--pbkdf` does:
  `argon2id`, `argon2i` and `pbkdf2`, so a script written for cryptsetup runs
  unchanged. `--pbkdf-memory` and `--pbkdf-parallel` apply to both Argon2
  variants. Argon2 of either kind is still refused in FIPS 140-3 mode.

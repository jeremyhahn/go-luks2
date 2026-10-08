### Fixed

- **`luks2 wipe`'s header-only warning no longer says a header backup stops
  working (#288).** A backup taken with `cryptsetup luksHeaderBackup` holds
  the keyslots, and the data is left in place, so restoring it opens the
  volume again. The warning now says so and points to `--full`.

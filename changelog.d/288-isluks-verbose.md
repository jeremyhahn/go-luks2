### Added

- **`luks2 isluks -v`/`--verbose` (#288)** prints the reason a device is not
  a LUKS (or, with `--luks2`, LUKS2) device on stderr, as `cryptsetup isLuks
  -v` does. The exit status is unchanged.

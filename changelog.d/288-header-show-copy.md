### Fixed

- **`luks2 header show` labels the copy it prints (#288).** When the primary
  header is damaged or older, `show` prints the secondary copy; it used to
  label it `Primary` at offset 0. It now prints `Secondary header:` with the
  secondary's offset and says on stderr that the secondary is shown.

### Added

- **`(*luks2.Header).Offset()` (#288)** reports which copy a `Header` was read
  from: 0 for the primary, the header area size for the secondary.

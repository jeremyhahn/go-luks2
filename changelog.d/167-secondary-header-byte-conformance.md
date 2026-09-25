### Added

- **The secondary binary header is byte-compared against cryptsetup's
  (#167).** `TestSecondaryHeaderMatchesCryptsetup` (integration tier) reads the
  second header copy of both formatted containers from the `hdr_size` their
  primaries record. It checks that each copy really is a secondary header
  (`SKUL` magic, and a `hdr_offset` naming where it was read), then diffs all
  4096 bytes. It excludes only `sequence_id`, the header salt and the checksum,
  the same exclusions `TestFormattedBinaryHeaderMatchesCryptsetup` makes for the
  primary, and it asserts the excluded salt and checksum are non-zero. A
  subtest corrupts single bytes and requires the diff to report exactly that
  offset, so the comparison is shown to be able to fail. The primary test and
  the new test now share one comparison helper.

  No production behaviour changed.

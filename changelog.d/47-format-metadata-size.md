### Added

- **`FormatOptions.MetadataSize` selects the LUKS2 metadata area size, the
  equivalent of cryptsetup's `--luks2-metadata-size` (#47).** Zero keeps the
  16 KiB default (12288 bytes of JSON). Any other value must be a power of two
  from 16 KiB to 4 MiB, the exact set cryptsetup accepts; anything else is
  refused with the new `ErrInvalidMetadataSize` before the device is touched.
  The layout follows cryptsetup's as measured against 2.7.0: the second header
  copy at `MetadataSize`, the keyslots area at `2 × MetadataSize`,
  `keyslots_size = 16 MiB − 2 × MetadataSize`, and the data segment at 16 MiB.
  Every legal size is formatted in the test suite and checked with cryptsetup's
  `luksDump` and `luksOpen --test-passphrase`. A container that needs more
  than 12288 bytes of JSON, such as one carrying large tokens, can now be
  formatted with room for it. Metadata that still does not fit is refused with
  `ErrMetadataTooLarge`, as before, and never grows into the next region.

### Fixed

- **`Format` places keyslot 0 at `2 × area` instead of a hard-coded `0x8000`,
  and a header-only `Wipe` zeroes both header copies at the area the container
  records (#47).** The fixed 32 KiB wipe covered both copies only of a 16 KiB
  area. On a container with a larger area, whether written by cryptsetup or by
  the new option, the second copy survived intact and the "wiped" volume could
  still be recovered. Only a copy whose checksum validates decides the size:
  the primary if it is valid, otherwise the smallest valid secondary. A
  damaged primary can neither understate its size and leave a valid secondary
  behind, nor overstate it and zero payload on a container whose data segment
  starts early. When no copy validates, the default 32 KiB is zeroed. Any other
  copy still recognizable as a LUKS2 header has its 4 KiB binary header zeroed,
  so no copy stays locatable.

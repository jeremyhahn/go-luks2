### Changed — BREAKING: headers are validated the way cryptsetup validates them, on read and before every write

- **One structural validator, matching cryptsetup's `LUKS2_hdr_validate` (#248).**
  It covers the five mandatory objects (present, and objects), segment offsets
  and sizes on the 512-byte sector grid, a keyslots
  area that fits between the header copies and the data, digests and tokens
  that name only keyslots and segments that exist, every luks2 keyslot named
  by exactly one digest, the online-reencryption backup segments and
  reencrypt keyslot, and the config sizes. The integration suite holds it to the
  cryptsetup binary in both directions: every header cryptsetup writes passes
  it, and every header cryptsetup refuses is refused.

  On read, a header that breaks a rule about the header as a whole is refused
  with `ErrInvalidHeader`. A damaged keyslot or token still does not cost the
  volume its other keyslots. Every **write** applies all the rules, so
  `WriteHeader`, `ImportToken` and the keyslot operations refuse to write a
  header cryptsetup would not read. A damaged entry has to be removed before
  anything else can be written. `RestorePrimaryHeader` is the exception: it
  copies the existing secondary back under the header-wide rules only, so a
  damaged entry cannot block the repair.

  A data segment that overlaps the header or keyslots area is never activated.
  That includes offset 0, which cryptsetup reads as a detached header; this
  library has no detached-header support. Previously, Unlock mapped the headers
  into the plaintext device.

- **Ambiguous JSON members are refused (#248).** A metadata object that names a
  member twice, or names one this library models in another case (`"Keyslots"`),
  is refused with `ErrAmbiguousJSONMember`. Go's JSON decoder matches member
  names case-insensitively and cryptsetup's does not, so the two read different
  values from the same header.

- **`RestorePrimaryHeader` repairs; it does not roll back (#248).** It refuses
  with `ErrPrimaryHeaderCurrent` when the primary is intact and not older than
  the secondary. Before, restoring an older secondary over a newer primary
  could bring back a passphrase that had already been removed. The restored
  header gets a sequence id one above both copies.
  `RestorePrimaryHeaderWithOptions` with `Force` restores anyway.

- **`Format` refuses bad input before it writes anything (#248).** It accepts only
  `aes-xts-plain64` (256 or 512 bits) and `aes-cbc-essiv:sha256` (256 bits),
  and refuses anything else with `ErrUnsupportedCipher`. It also refuses:
  - labels and subsystems over 47 bytes, or containing a NUL (`ErrInvalidLabel`);
  - devices with no room for at least one data sector after the keyslots area
    (`ErrDeviceTooSmall`). Before, it wrote the header and failed later, or grew
    a regular file into a container with no data.

  It opens the device with `O_EXCL`, so a mounted or mapped block device is
  refused with `ErrDeviceInUse` instead of being formatted.

### Fixed

- **`ImportToken` no longer writes `"keyslots":null` (#248).** A token naming no
  keyslot is written with an empty array. cryptsetup and systemd-cryptsetup
  refuse a whole header that carries the null.
- **The header checksum covers the bytes that are parsed (#248).** The header
  area is read once, and the checksum, the binary header and the JSON all come
  from that buffer. Before, the area was read three times, so a concurrent
  rewrite could be checksummed in one state and parsed in another.
- **`VolumeInfo.KeySize` is set (#248).** It is the volume key size in bits,
  taken from a keyslot attested for the crypt segment that Unlock maps. Cipher
  and sector size come from that same segment instead of from whichever one Go
  map iteration returned first.

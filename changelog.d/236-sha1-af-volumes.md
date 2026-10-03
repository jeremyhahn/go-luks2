### Fixed

- **Volumes whose keyslots use SHA-1 anti-forensic hashing open (#236).** Every
  LUKS1 volume converted to LUKS2 with `cryptsetup convert`, and any
  `cryptsetup luksFormat --hash sha1`, splits its keyslots with SHA-1, which
  the anti-forensic merge did not implement, so this library could not open
  them at all although cryptsetup does. Outside FIPS mode they now open, to the
  same volume key cryptsetup recovers. In FIPS 140-3 mode they are refused
  before any hashing with `*FIPSImportRequiredError` (matching
  `ErrFIPSNotApproved`), naming `anti-forensic hash sha1`, and
  `MigrateToFIPS` imports them like any other non-approved keyslot. SHA-1 is
  read and never written: the split accepts SHA-256 and SHA-512 only, `Format`
  refuses `HashAlgo: "sha1"` with `ErrUnsupportedHash` before touching the
  device, and `ChangeKey` rewrites a SHA-1 keyslot with a SHA-256 split. See
  docs/FIPS.md.

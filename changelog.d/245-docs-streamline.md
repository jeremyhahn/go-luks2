### Changed

- **The project documentation was checked against the code and rewritten
  (#245).** README.md, docs/ARCHITECTURE.md, docs/cli, docs/luks, FIPS.md,
  TESTING.md, COMPATIBILITY.md, RELEASABILITY.md and changelog.d/README.md now
  describe v0.3.1-alpha as it behaves, at about 40% of their former length.
  ARCHITECTURE.md now covers the packages, key custody, header handling, the
  device layer, FIPS mode and the trust boundaries. Corrected claims include:
  a header-only `wipe` zeroes the two header copies only, so keyslot material
  survives; `close` does not detect a mounted volume, which instead fails as
  busy after 3 s of retries; wipe verification does nothing for the `nist`,
  `dod3` and `dod7` standards; device and file paths must be absolute; key
  files over 512 bytes are refused; keyslot priority is not used by unlock;
  the dashed recovery key is 74 uppercase characters; and the FIPS job runs
  in `nightly.yml`. The CLI help no longer claims that no external tools are
  used (`create` runs `mkfs`), and its examples use absolute paths.

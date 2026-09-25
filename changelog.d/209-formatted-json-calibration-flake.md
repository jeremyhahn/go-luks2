### Fixed

- **`TestFormattedJSONMatchesCryptsetupByteForByte` no longer compares two
  wall-clock calibrations (#209).** Before it substituted the digest iteration
  count, the test checked this package's calibration against cryptsetup's and
  accepted anything within 0.5x–2x. Those were two timings taken at different
  moments on a loaded CI host, so the check measured the scheduler rather than
  the code. It failed a correct tree at 0.48x (`88224` against `182297`).

  `buildCanonicalPair` now reads the digest count cryptsetup calibrated out of
  its header and pins this package's digest to it through the
  `digestIterationsFor` seam, the same way it already mirrors the keyslot
  costs. cryptsetup still calibrates freely. The count is no longer substituted
  and is now compared byte for byte with the rest of the JSON, which is
  stricter than before. The drift guard now checks the constants that define
  the calibration (`DigestIterationTargetMs`, `DigestCalibrationKeyLen` and the
  LUKS2 floor) against cryptsetup's, so load on the host cannot fail it. The
  band was not widened.

  No production behaviour changed.

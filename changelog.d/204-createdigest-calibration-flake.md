### Fixed

- **`TestCreateDigest` no longer compares two wall-clock calibrations (#204).**
  The test checked the digest's recorded PBKDF2 iteration count against a
  *second, fresh* calibration and accepted anything within 2x. Two timing
  measurements taken moments apart are a property of how busy the host is, not
  of the code: on a loaded host the two landed five-fold apart
  (`56813` recorded against a fresh `10500`) and the test failed on a correct
  tree, which fails the unit tier's hermeticity requirement and every delivery
  that happened to run beside another build.

  The count is pinned through the existing `digestIterationsFor` seam instead,
  and the assertion is now the property that belongs to `createDigest`: it
  records *exactly* what the calibration returned, for the hash the digest
  declares. That is strictly stronger than the old band — a count rounded or
  substituted by a few hundred iterations passed the 2x check and fails this
  one. The real calibration's time target and LUKS2 iteration floor are
  unchanged and stay checked in `TestDigestCalibrationTargetsItsBudget`.

  No production behaviour changed.

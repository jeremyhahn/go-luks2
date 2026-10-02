### Fixed

- **`CheckFilesystem(dev, "ext4", true)` no longer reports a successful
  repair as a failure (#228).** `e2fsck -p` exits 1 when it corrected errors,
  and every nonzero exit used to become a `*FilesystemCommandError`, so a
  check that had just fixed the filesystem told the caller it had failed. The
  status is now read as e2fsck's bitmask: with `repair`, 0 is clean, 1 and 2
  (errors corrected; corrected and a reboot requested) are success, and any
  status with bit 4 or higher set (errors left uncorrected, operational,
  usage or shared-library error, canceled) is still an error. A signal or a
  checker that could not be started is still an error. A read-only check
  (`e2fsck -n`) is unchanged: any nonzero status means errors are present.

### Added

- **`CheckFilesystemDetailed` (#228)** runs the same check as
  `CheckFilesystem` and, on success, returns a `FilesystemCheckResult`
  reporting whether the checker wrote a repair (`Repaired`: e2fsck exit 1 or
  2, or a fsck.fat repair confirmed by its read-only recheck) and whether
  e2fsck asked for a reboot (`RebootRequired`: exit status bit 2).
  `CheckFilesystem` keeps its signature and returns only the error.

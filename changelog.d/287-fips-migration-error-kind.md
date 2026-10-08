### Changed — BREAKING: `MigrateToFIPS` errors are classified at their source

- **A migration refusal is now an `*errs.Error` whose `Kind` is the refusal's own
  sentinel, and the text of every migration error changed (#287).**
  `MigrateToFIPS` still returns a `*FIPSMigrationError` under the package's
  `*errs.Error` with `Kind` `ErrFIPSMigration`, so `errors.Is(err,
  ErrFIPSMigration)` holds as before, and the refusal's sentinel and the failure
  behind it are each reachable with `errors.Is` and `errors.As`. The message no
  longer repeats the device or the sentinel name, which the `*errs.Error` head
  already carries: it reads `at <stage>: <cause>; <state>`. Code that matched
  the old text, or read the `Kind` of the inner refusal, must use `errors.Is`.

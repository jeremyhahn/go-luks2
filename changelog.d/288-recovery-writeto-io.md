### Fixed

- **BREAKING: a failed recovery-key write is an I/O error, not a memory one
  (#288).** `(*RecoveryKey).WriteTo` reported its writer's failure as
  `ErrProtectedMemory`; it now returns `ErrIO` wrapping the writer's error.
  `luks2 recovery generate`/`add` exit 1 instead of 3 when the key cannot be
  written to stdout or the key file.

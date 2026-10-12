### Changed

- `ValidatePassphrase` now reports a passphrase that is too short or too long
  as an `*Error` of kind `ErrInvalidCredential` with `Op` set to
  `ValidatePassphrase`, the same shape as its destroyed-enclave failure, which
  now carries the `Op` too. `errors.Is(err, ErrInvalidCredential)` holds as
  before (#334).

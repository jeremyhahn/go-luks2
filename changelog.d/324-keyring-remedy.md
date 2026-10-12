### Fixed

- **The blocked-keyring remedy names `dmcrypt.CheckKeyring` (#324).** It told
  operators to call `CheckKeyringAvailable` at startup, a function removed with
  the old activation API (#268); the startup preflight is
  `dmcrypt.CheckKeyring`.

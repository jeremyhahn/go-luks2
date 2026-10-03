### Fixed

- **The nightly FIPS lane is green again (#235).** Under
  `GODEBUG=fips140=only` nine tests failed on main because they create Argon2
  keyslots, which FIPS 140-3 mode refuses: the three Argon2 cost tests in
  `pkg/luks2`, and six `cmd/luks2` tests whose fixtures enrolled Argon2
  keyslots and recovery keys. Each now states what it asserts in each mode,
  and none gained a skip guard:

  - `TestCreateArgon2KDFCarriesANegativeCostToTheDerivation` and
    `TestCreateArgon2KDFStillDefaultsAZeroCost` check the cost seam
    (`createArgon2KDF`) directly in both modes -- it is the same code either
    way -- and the public `CreateKDF` for what it does in this process's mode:
    carry or default the cost, or, under FIPS, refuse Argon2 with
    `ErrFIPSNotApproved` and build nothing.
  - `TestAddKeyReportsTheInheritedCostToTheCaller` inherits from an Argon2
    container written by cryptsetup, so the fixture exists in either mode.
    Without FIPS, AddKey inherits and reports the cost; under FIPS it is
    refused with `ErrFIPSNotApproved` and the first 2 MiB of the image -- both
    header copies and the keyslot area AddKey would write -- is unchanged.
  - The `cmd/luks2` wiring tests enroll their keyslots with the cheapest KDF the
    library writes in the mode: Argon2id at its floor, or under FIPS
    pbkdf2-sha512 (210000 iterations for a passphrase keyslot, 1000 for a
    library-generated recovery key).

  The nightly FIPS job now installs cryptsetup, as CI's unit job does: the
  conformance tests require it and fail without it.

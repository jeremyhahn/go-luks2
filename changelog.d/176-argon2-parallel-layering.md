### Fixed

- **A negative `Argon2Parallel` is refused with its siblings, not a layer later
  (#176).** `callerArgon2Options` forwarded only `Argon2Time` and
  `Argon2Memory`, so a caller's parallelism never reached the pre-check that
  bounds the other two. It was still refused — `deriveArgon2` rejects a `cpus`
  outside 1..255 — but after the pre-check had passed, further into the
  operation, and as a `CryptoError` rather than the `Argon2CostError` its
  siblings produce. The same mistake by the same caller got two error shapes at
  two moments.

  `validateArgon2CreateCost` now bounds all three, and `Argon2Parallel` is
  forwarded to it. A below-minimum parallelism returns an `Argon2CostError`
  wrapping the new `ErrInvalidArgon2Parallel`, matching time and memory exactly.

  Nothing was leaking: a bad value never reached a header. The risk was that an
  inert asymmetry becomes a hole when someone changes the code around it — which
  nearly happened, since `callerChoseArgon2Cost` had to be corrected from `> 0`
  to `!= 0` during an unrelated rebase. Under `> 0` a negative parallelism would
  have read as "the caller chose nothing" and silently inherited the container's
  cost instead of being refused at all.

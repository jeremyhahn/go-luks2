### Changed — BREAKING: `make release` cuts only final releases

- **One release target per kind (#291+).** `make release-alpha
  VERSION=vX.Y.Z-alpha` cuts an alpha, `make release-candidate
  VERSION=vX.Y.Z-rc.N` cuts a release candidate and `make release
  VERSION=vX.Y.Z` cuts a final release, and each refuses the other two kinds
  before it writes anything, naming the target that cuts the kind. Before this
  change `make release` accepted all three and `release-alpha` was an alias of
  it, so `make release VERSION=vX.Y.Z-rc.N` (how rc.3 was cut) and
  `make release-alpha VERSION=vX.Y.Z` now fail: use `make release-candidate`
  and `make release`. `VERSION` is stated explicitly for the candidate and the final
  release; `release-alpha` derives it when omitted (next entry). The guards are one recipe shared by the three targets, so they cannot drift.

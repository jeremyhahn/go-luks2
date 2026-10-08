### Changed

- **`make release-alpha` derives the next alpha when `VERSION` is omitted.** It
  takes the highest `vX.Y.Z-alpha` tag, in the checkout and on the release remote,
  adds 1 to PATCH, prints the version and then runs every existing guard on it
  (main only, the remote, the duplicate tag, a clean tree, the changelog checks,
  the `VERSION` commit, the signed tag and the atomic push). It refuses, and prints
  the explicit form, when no alpha tag exists, when the remote cannot be listed, or
  when an existing tag of any kind (an rc or a final release outranks the alpha of
  the same `X.Y.Z`) is at or above the result. `make release-alpha
  VERSION=vX.Y.Z-alpha` stays valid for a hand-picked MINOR bump;
  `release-candidate` and `release` still require `VERSION`. This follows the
  company release-versioning standard.

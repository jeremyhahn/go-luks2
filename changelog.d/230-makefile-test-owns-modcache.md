### Fixed

- **`test/makefile` passes on any host, including one whose fallback go is
  older than `go.mod` (#230).** `TestGoFallbackWhenNotOnPATH` runs the
  Makefile with no go on `PATH`, so it uses the `/usr/local/go/bin/go`
  fallback. Where that install is older than `go.mod`'s go line,
  `GOTOOLCHAIN=auto` downloads the required toolchain into the module cache
  under the test's temporary `GOPATH`, and the go command writes the module
  cache read-only. The test's directory cleanup then failed with
  "permission denied" and failed the test, which also failed `make ci`. Each
  test's `GOPATH` is now created by `ownedGOPATH`, with `GOMODCACHE` pinned
  inside it, and is made writable before removal. The assertions are
  unchanged, so the test still fails if the fallback it pins breaks.

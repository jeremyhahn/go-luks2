### Changed

- **The unit suite has a runtime budget and a separate ceiling, and runs well
  inside both (#92).** `go test -race ./pkg/luks2` had a hard `-timeout 300s`
  that was also its budget, and a loaded runner killed healthy runs at exactly
  5m0s. Per the owner's amended ruling the two are now separate Makefile
  variables that CI reads through `make test-unit`: `UNIT_TEST_TIMEOUT=10m`, the
  ceiling, which fails the run, and `UNIT_TEST_TARGET=240` (seconds), the budget,
  which `make test-unit` prints beside the measured time on every run and flags
  when exceeded.

  The suite was made faster at the cause, not by trimming it -- no test was
  removed or skipped. Profiled, it was entirely sequential (the sum of its
  tests' times was its wall time) on a 112-core runner, and its cost is real
  work in the code under test that `-race` instruments roughly fivefold. So:
  tests that cost real time and write no package-level state now run in
  parallel, and the testing package's ordering -- every sequential test before
  any parallel one -- keeps the seam-swapping tests apart from them; test
  fixtures are closed rather than fsynced, which on a loaded disk cost ~330ms a
  call (14.8s across three tests); and the digest-scan tests stopped
  re-deriving and re-encoding the same digests 64 times over. Measured on one
  8-core workstation, main and this change run back to back under the same
  load: `./pkg/luks2` with `-race` 282s → 104s, without `-race` 118s → 41s;
  `./cmd/luks2` with `-race` 32s → 14s; `go test -race ./...` 258s → 138s. Every
  test on main is still present -- the change adds tests, it removes none.

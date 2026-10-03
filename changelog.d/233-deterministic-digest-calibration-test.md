### Fixed

- **No unit test's verdict depends on the wall clock any more (#233).**
  `TestDigestCalibrationTargetsItsBudget` timed a real PBKDF2 derivation and
  failed under host load -- 410ms against a 400ms bound at load 35 on 8 cores
  -- while the calibration it checked was correct. It was one of a class: every
  unit test that asserted a wall-clock bound, or used a deadline as pass/fail,
  has been converted.

  The code that waits or measures now takes its time source as a parameter,
  and the system clock is what every exported entry point passes, so no
  production behavior changed:

  - the PBKDF2 calibration takes a `pbkdf2Timer` (the wall-clock derivation by
    default), so its arithmetic is tested against a known hashing rate -- with
    exact expected counts, including the sub-millisecond probe that was #52 and
    that `-race` used to hide;
  - `AcquireFileLockTimeout` and the loop node and loop detach waits take an
    unexported `clock`, and `test/harness`'s reaper and release waits use a
    package `waitClock`; their tests run on a clock that only moves when the
    wait sleeps, so bounds, pacing and backoff are asserted exactly;
  - the KDF-cost tests observe that the derivation is never entered, rather
    than how long the refusal took;
  - two 30-second hang guards became direct calls: a hang is ended by the test
    binary's own `-timeout`, which names the test.

  Every converted test fails on a mutation of what it pins -- the
  extrapolation, the target, the benchmark length, the probe floor, a
  deadline, a poll interval, the backoff -- and load cannot fail it. The
  real-machine checks, whose answer does move with the hardware, are now
  benchmarks: `BenchmarkPBKDF2CalibrationCostsItsBudget` and
  `BenchmarkDigestCalibrationCostsItsBudget`, timed in thread CPU time, and
  `BenchmarkSystemClockIsTheRealClock`, which checks the production clock
  against the time package. The unit suite never runs them; `make
  test-calibration` (CI's unit job and `make ci`) runs each once and fails the
  build on them.

- **The parallel unit tests stay inside the process's locked-memory limit
  (#233).** The integration job runs the unit suite inside the devcontainer,
  whose memlock limit is Docker's default 8 MiB, and `go test` ran up to
  GOMAXPROCS parallel tests at once. On a 112-core runner that was enough
  concurrent keyslot operations to exhaust the limit: twenty tests failed with
  `mlock: cannot allocate memory` (Gitea run 22601). Parallel tests now call
  `defer parallel(t)()`, which holds one of a number of slots sized from the
  process's actual RLIMIT_MEMLOCK (1 MiB a test, after a 1 MiB reserve, at most
  GOMAXPROCS) for the test's body. Reproduced in the container with
  GOMAXPROCS=112 -- 41 such failures before, none after.

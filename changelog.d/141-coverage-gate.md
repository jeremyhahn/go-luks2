### Added

- **Coverage is a gate now, not a printed number (#141).** `project-scaffold.md`
  §6 requires that *"the `coverage` target enforces a hard threshold that fails
  the build, never a warning."* It did not: `COVERAGE_THRESHOLD=90.0` was
  compared in exactly one target -- `ci-full` -- that `ci.yml` never invoked,
  while the CI step that looked like the gate printed a percentage and exited 0.

  `test/covergate` is the gate, reached through `make coverage-gate` (CI's unit
  job and `make ci`) and `make coverage-combined` (the devcontainer's default
  command, so CI's integration job and `make ci-full`). It compares **every
  package against its own floor, exactly** -- in integer arithmetic, so 89.99%
  is below 90 where `go tool cover` prints 90.0% and the old comparison
  truncated to an integer. It fails on a missing, empty or unreadable profile,
  on a package `go list ./...` reports with no floor, on a floor for a package
  that no longer exists, and on a floors file that holds a package to 90% in no
  tier, so a floor cannot be lowered past the target without the gate saying
  so.

  Every package is held to **90%**. `pkg/luks2` and `test/harness` are held to it
  in the **combined** tier -- unit and integration suites measured together in
  the devcontainer, the integration suite instrumenting both through
  `-coverpkg` -- because part of each only runs against a real kernel. Each also
  carries a unit floor at its measured unit level. Measured at the tip of this
  change (unit before → after): `pkg/luks2` combined 91.37% (unit 81.7% →
  87.71%), `test/harness` combined 91.12% (unit 76.2% → 84.60%), `cmd/luks2`
  94.23%, `test/harness/cmd/luks2-testreap` 0% → 95.45%, `test/covergate`
  99.10%. The
  new tests pin behavior that had none: the argv every filesystem creator hands
  its mkfs, `IsLUKS`/`IsLUKS2` on every header shape, the refusals at the front
  door of every keyslot operation and of `Wipe`/`WipeKeyslot`, and the reaper's
  dm and loop removals against the real kernel.

### Fixed

- **No coverage merge fails open any more (#141).** CI's merge ended in
  `grep ... || true` three times, so a leg that produced no profile contributed
  nothing and the total was computed over the legs that did report --
  **losing a whole package made the reported number go UP**. The devcontainer
  merged its profiles the same way, CI's extraction of the integration profile
  warned and passed when the copy failed, and `ci-full` printed a yellow line
  and reported success when its profile was missing. Each is now a failure.
  `ci-full` also no longer calls three targets removed in #184.

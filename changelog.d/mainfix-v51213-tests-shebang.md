### Fixed

- **The code-review v5.12.13 regression tests no longer fail the releasability gate (#509).**
  The test file opened with a `#!` line, which the gate refuses as an
  executable script; CI already runs it with `python3 -I`, so the line is
  dropped.

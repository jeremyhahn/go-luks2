### Fixed

- **Integration images are labelled and reaped, and `ITEST_IMAGE`/`ITEST_CONTAINER`
  now respect the environment (#146).** Since the tags became unique per
  invocation (#105) nothing replaced the previous image, so a standalone
  `make docker-build-integration` left hundreds of MB behind on every run, and
  a run killed between its build and the line that arms its trap left one too.
  On a shared runner that presents as unrelated jobs failing to pull. Every
  integration image now carries `go-luks2-itest=1`; `make docker-prune-itest`
  (run automatically at the start of each integration build, and by CI) reaps
  labelled images that no container references and that are older than
  `ITEST_PRUNE_AGE` (2h), which is the only mechanism that survives a SIGKILL;
  and a build whose image nothing can consume removes it. Export `ITEST_ID` or
  `ITEST_IMAGE` to keep a built image for as long as `ITEST_PRUNE_AGE`. `ITEST_IMAGE` and `ITEST_CONTAINER`
  changed from `:=` to `?=`, matching `ITEST_ID`: a `make` integration target
  called from CI now uses the job's names instead of silently building under
  its own and leaving the real container running while the cleanup reported
  success.

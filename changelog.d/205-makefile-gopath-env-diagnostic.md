### Fixed

- **`make` no longer prints `env: can't execute 'GOPATH'` under GNU make 4.4+
  (#205).** `GO` and `GOPATH` were recursively expanded. GNU make 4.4 exports
  environment-origin variables into `$(shell ...)`, so with `GOPATH` in the
  environment, expanding `GO` first re-expanded the Makefile's `GOPATH`, whose
  `$(GO)` was still empty: the command became `env GOPATH` on every
  invocation. The build still succeeded, but the line led every failing
  verification's output and was twice diagnosed as the failure. Both are now
  simply expanded (`:=`), evaluated once in order; the `which` fallback that
  `sudo make` relies on is unchanged.

  `test/makefile` pins the fix: it runs make against the real Makefile with
  `GOPATH` set, unset, and with no go on `PATH`, asserts the diagnostic is
  absent and the resolved values are right, and checks that both variables are
  simply expanded, which fails against the defect on any make version. It runs
  in `make test-unit` and in CI's unit job.

### Changed

- **go-enclave v0.4.0-alpha → v0.5.0-alpha, and the module floor rises to Go
  1.27.0 with it (#201).** go-enclave raised its own floor to `go 1.27.0`, so
  adopting it raises this module's; `GO_VERSION` in the three workflows, both
  `golang:` base images and the README's build requirement move in lockstep.
  golangci-lint v2.13.2, the floor for linting Go 1.27, was already the pinned
  version. The 2026-08-20 block on 1.27.0 named a transitive dependency that
  failed to compile under it; measured on adoption, nothing in this module's
  graph does, and the workflow comment records that rather than the stale
  block.

  The Makefile now binds every target to exactly the toolchain `go.mod`'s
  `go` directive names (`export GOTOOLCHAIN := go<floor>`, derived from the
  file). Measured on this adoption: a host with Go 1.26.7 and
  `GOTOOLCHAIN=local` — the review harness — could neither build nor test the
  change it was verifying, the same failure the handbook recorded on
  2026-08-27 when thirteen repos moved past the shared image. With the
  binding, an older host fetches the pinned version through GOPROXY once and
  builds. The directive is read with make's own text functions (no external
  tool) and exported with `override`, so a stripped `PATH`, `make -e` or a
  `GOTOOLCHAIN=` on make's command line cannot silently leave the pin unset;
  `make TOOLCHAIN_PIN=0 ...` is the explicit opt-out for a host that must
  not fetch.

  `copySecret`'s read-only contract carries execution evidence:
  `TestCopySecretPagesAreReadOnly` runs the write in a child process that
  must first report the copy read back intact, then die with the runtime's
  fault signature and never print its survival marker, with the same store
  into `copySecretWritable` as the in-process control. Reverting `copySecret`
  to the writable composition turns it red (measured).

  The API change this library takes is `enclave.NewMemoryEnclaveCopy`.
  `copySecret` was the hand-rolled sized-region + fill-borrow +
  Destroy-on-error composition that constructor replaces, and it now calls the
  constructor through a third test seam (`copyIntoLockedRegion`), so the
  fail-closed tests refuse it alongside the other two. Its result is therefore
  **frozen read-only**, like `adoptSecret`'s: a write through a slice retained
  past its borrow faults instead of silently corrupting a credential. The one
  caller that normalises its copy in place — the recovery-key body lower-cased
  before the hex test — moves to the new `copySecretWritable`, which keeps the
  writable composition and says why; `copySecretFiltered` stays writable for
  the same reason. The test fixture helper takes the constructor too.

  Behavioural changes in go-enclave v0.5.0 — a kept mapping reads as destroyed
  once wiped, `Freeze` on sized enclaves, `RLIMIT_MEMLOCK` discovered at
  `NewAllocatorWithinRLimit` — are all in the direction the borrow contract
  here already assumes; the suite ran green against the new version before any
  code moved, and again after.

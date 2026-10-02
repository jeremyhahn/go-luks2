### Changed — BREAKING: go-enclave v0.5.0-alpha → v0.7.0-alpha; enclaves this library returns now report their release

- **go-enclave v0.5.0-alpha → v0.7.0-alpha (#227).** Go resolves one
  go-enclave per build, and the rest of the stack has moved to v0.7, so a
  consumer taking both could not build until this library moved too.
  `golang.org/x/sys` rises to v0.48.0 with it, and `github.com/awnumar/memcall`
  leaves the module graph: go-enclave now owns its OS memory layer.

  **Why BREAKING here.** This library's own signatures are unchanged, but the
  `*enclave.MemoryEnclave` values it returns — from `LoadRecoveryCredential`,
  `RecoveryCredential`, `ParseRecoveryKey`, `LoadRecoveryKey`,
  `DeriveKeyEnclave` and `KeyProvider.Passphrase` — are
  go-enclave v0.7's type, whose `Destroy()` now returns `error` (`DestroyErr`
  is gone). `defer key.Destroy()` still compiles; code that passes
  `key.Destroy` as a `func()` (for example `t.Cleanup(key.Destroy)`) does not,
  and code that matched `ErrLockedMemoryUnavailable` on an unwiped release
  must now match `ErrReleasedWithoutWipe`, which v0.7 no longer overlaps with
  it. See go-enclave's "Upgrading from v0.6 to v0.7".

  **What this library does with the report.** Every enclave it creates is now
  released through one helper, `releaseSecret`, which is the single place the
  report is received and the single place it is deliberately dropped, with the
  reasons on the helper: neither outcome lets key material reach ordinary
  memory (an unwiped release is an unmap the kernel zeroes; a refused one
  leaves the pages mapped on go-enclave's `WipeAll` ledger, holding zeroes or
  still-mlock'd material, because go-enclave wipes before it unlocks); the
  library can
  remedy neither and may not log; and every release happens after the
  operation's outcome is decided, so returning it would make a completed
  `Format` or `Unlock` look failed and invite a destructive retry. Detected
  canary corruption still panics and is not recovered.

  **Behavior change on a refused release.** Under v0.5 the two outcomes were
  handled differently, and neither on purpose. An unwiped release was dropped
  implicitly: every call site used the void `Destroy` and never asked
  `DestroyErr`. A refused `munlock` or `munmap` PANICKED out of `Destroy`,
  contrary to go-enclave's own contract (fixed in go-enclave v0.6.2-alpha), so
  a host at `vm.max_map_count` crashed a go-luks2 operation at the release —
  possibly between writing a keyslot and releasing the stripes that wrote it.
  Now that refusal is a report, dropped at `releaseSecret`, and the operation
  completes with the pages left on go-enclave's ledger.

  Test code checks every release it makes: a `mustDestroy` helper fails the
  test on a report (on a healthy host every release is clean), and the
  golden-container setup joins a report into its error.

  The `luks2` CLI is the application, so it acts on the report it can see:
  `recovery verify` prints a warning to stderr when releasing the recovery
  credential is reported, without changing the command's exit status.

  The normative raw-bytes boundary list (`pkg/luks2/enclave.go`, README
  Protected Memory) gains a **Release** note qualifying "zeroized on release"
  for the unwiped-release case, and entry 4 records that go-enclave v0.7's
  `runtime/secret` key-schedule erasure covers only go-enclave's own sealing,
  not this library's XTS ciphers. go-enclave's other v0.6/v0.7 changes —
  context-first sealing, read-only `Open` plaintext, `WipeAll(ctx)`,
  `ErrSealerWiped` — touch API this library does not use.

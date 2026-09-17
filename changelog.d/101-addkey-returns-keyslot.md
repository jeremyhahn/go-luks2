### Changed — BREAKING: `AddKey` returns `(int, error)`

- **`AddKey` reports the keyslot it used (#101).** It used to return only
  `error`, so a caller that needed the slot — to record it, or to revoke it
  later — had to infer it from the header afterwards, and inferring it is how
  #42 destroyed the wrong credential: "the highest-numbered slot" and "the first
  free slot" agree only while the active slots are contiguous from zero. The
  slot is now the first return value, read from where `AddKey` chose it under
  the device lock; on error it is `-1`. The unexported out-parameter variant
  that #42 added as a workaround is deleted.

  Migration: `if err := luks2.AddKey(...)` becomes
  `if _, err := luks2.AddKey(...)`. The CLI's `LuksOperations.AddKey` widens
  the same way. A consumer gets a compile error rather than a silently wrong
  integer, which is the point. go-trusted-platform is the only consumer; at its
  `main` of 2026-09-14 (`892c15d`, pinned to `go-luks2 v0.1.7-alpha`) its two
  call sites — `pkg/storage/luks/handler.go:150` and
  `pkg/storage/luks/manager.go:214` — both discard the result, so its
  migration is `_, err :=` in two places. Per the breaking-change protocol
  that consumer is walked up against the tag carrying this change; the
  companion go-trusted-platform issue must be filed and linked from #101 before
  this change merges.

### Changed

- **The policy for a loop device no ledger recorded is written down: an
  operator clears it, not this repository (#114).** The reaper handles recorded
  state completely and unrecorded state not at all, by design. `docs/TESTING.md`
  now carries the owner's 2026-09-22 ruling — such a device is attributed and
  detached by hand with stock `losetup -a` / `losetup -d`, per device, and no
  command for it ships here.

  Any sweep, prefix match or "looks like ours" branch is refused permanently.
  It is worst at exactly the cases that cost: it matches the well-behaved
  leftovers the record-based reaper already reclaims, and misses the rest —
  measured on the six orphans that exhausted a runner's loop pool on 2026-09-02,
  five were backed directly under `/tmp/` and a prefix-bounded sweep would have
  matched none of them.

  The doc comments on `test/harness/system.go` and
  `test/harness/cmd/luks2-testreap` now say that their missing sweep is ruled
  policy rather than an omission, so removing it is an owner decision and not a
  cleanup. No behaviour changes.

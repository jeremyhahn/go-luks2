# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **The integration container no longer runs `--privileged` (#80).** It runs
  under a set that was measured flag by flag, and that set now lives in one
  file, `test/integration/docker-run.sh`, which the four Makefile targets and
  the CI workflow all call. There were five copies of `docker run
  --privileged`; five copies of a security-critical invocation is how one of
  them quietly grows a flag the others do not have.

  `--privileged` is not a privilege setting. It is the absence of every
  restriction Docker has — all capabilities, seccomp off, AppArmor off, and the
  host's whole `/dev` bind-mounted in, which on the machine this was measured on
  meant the test container could open the root NVMe, an unrelated RAID array and
  every dm mapping on the box. This library holds volume keys for a trusted computing
  platform, and a test rig is not where that gets handed away for convenience
  (owner direction, 2026-08-31).

  What replaces it: `--cap-drop ALL` plus `CAP_SYS_ADMIN` and `CAP_MKNOD`;
  a seccomp profile; `apparmor=unconfined`; `--device /dev/mapper/control` and
  `--device /dev/loop-control`; and a device-cgroup rule for the loop and
  device-mapper majors, the latter read from `/proc/devices` rather than
  hard-coded. Each was established by removing it and recording what broke
  first — the table is in `docs/TESTING.md`.

  **Capabilities were the wrong suspect.** Docker's default seccomp profile
  denies `add_key`, `keyctl` and `request_key` outright, because kernel
  keyrings are not namespaced, and no capability lifts a seccomp denial:
  `add_key` fails under the default profile *with* `CAP_SYS_ADMIN` and succeeds
  under the new profile with *no* capabilities added at all.

- **A reviewable seccomp profile, `test/integration/seccomp.json`.** Docker's
  own default profile byte for byte, plus one appended block allowing exactly
  `add_key`, `keyctl` and `request_key`. Upstream is `default.json` from
  `github.com/moby/profiles/seccomp v0.1.0` — the version the local daemon
  links, read out of the binary rather than guessed — and the file header
  carries its sha256. `make seccomp-diff` re-fetches it through the Go module
  proxy, so the checksum database vouches for the comparison, and prints the
  difference.

  `seccomp=unconfined` would also have made the suite pass and is deliberately
  not used: it re-admits every syscall the default profile denies, including
  the `mount`, `kexec`, `bpf` and namespace calls the profile exists for, to
  solve a three-syscall problem.

### Removed

- **The repository guards and the `scripts/` directory (#183).** 2,418 lines of
  shell and Python across nine files, plus every Makefile target and CI step
  that invoked them: the disclosure scanner, the ownership-blind device-teardown
  scanner, the error-collapse scanner, the dm-scope guard test, the build-tag
  and race-package enumerators, and the two suites that tested the other
  scripts.

  These concerns move to **development and review time**, as part of the SDLC
  process and conventions. A code-based scanning solution is planned separately;
  until it lands this repository implements none (owner ruling 2026-09-13). The
  guards were deliberately NOT ported to Go tests, which was the obvious move and
  is not what is wanted.

  What review now carries, stated plainly rather than lost quietly: this
  repository is publicly mirrored and keeps the forge address out of the tree, so
  internal-detail disclosure is now a review property; and an ownership-blind
  device teardown — a global `dmsetup` wipe once reached
  `nvme0n1p3_crypt -> vgmint-root` on a real machine and survived only because
  those devices were busy — is now a review property too.

  `.github/require-tool.sh` and `test/integration/docker-run.sh` are NOT removed.
  Neither scans the tree: the first installs the pinned analysis tools three CI
  steps depend on, and the second holds the integration container's eight
  privilege flags in one place, which is the arrangement #80 put there so five
  copies of a security-critical invocation cannot drift apart.

  `make vet` now runs `go vet` directly for the default and `integration`
  configurations rather than deriving the tag list, and the race-leg package list
  in `.github/workflows/ci.yml` is maintained by hand.

- **BREAKING: `AFSplit`, `AFMerge` and `DeriveKey` are removed (#11).** All
  three were `Deprecated:`-marked exported wrappers around plain, unprotected
  heap memory, kept only for consumers that turned out not to exist — a
  repository-wide search, including `cmd/`, `test/` and both build-tag sets,
  found none. `AFSplit`/`AFMerge` are superseded by the unexported
  `afSplitEnclave`/`afMergeEnclave`, which perform the same anti-forensic
  split and merge entirely inside `go-enclave` locked memory. `DeriveKey` is
  superseded by `DeriveKeyEnclave`, which returns the derived key held in an
  enclave rather than as a plain `[]byte`. Callers that still reference any of
  the three get a compile error, which is the point: this is pre-1.0 alpha
  software, and there is no compatibility shim to remove them into (owner
  ruling, 2026-09-11).

### Changed

- **BREAKING: `Config.Requirements` is `*Requirements`, not `[]string` (#152).**
  LUKS2 spells `config.requirements` as an OBJECT carrying a `mandatory` array;
  both `mandatory` and `online-reencrypt-v3` are literals in libcryptsetup. The
  flat slice did not merely lose detail — the decode failed outright with
  `cannot unmarshal object into Go struct field Config.config.requirements of
  type []string`, so **this package could not read any container
  mid-reencryption at all.** cryptsetup sets a requirement flag for the
  duration of an online reencryption, which made every interrupted volume
  opaque to go-luks2 until the reencryption finished.

  That inverted the mechanism. `requirements` exists so an implementation that
  does not understand a feature refuses the container instead of damaging it;
  failing to parse the member carrying the warning meant not being able to read
  the flag that says "do not touch this".

  Migration: `cfg.Requirements` becomes `cfg.Requirements.Mandatory`, and is
  `nil` when the container declares none. Nothing in this repository read the
  field, and no container carrying one could be decoded, so no working caller
  can have depended on the old shape.

- **A mandatory requirement this package does not implement refuses WRITES and
  permits READS (#152, owner ruling 2026-09-13).** `ReadHeader` parses the
  container and exposes the requirement, because a flag whose purpose is to warn
  is useless if reading it is what fails, and an operator diagnosing an
  interrupted reencryption needs to see it. Every mutation refuses with an
  `UnsupportedRequirementError` (`errors.Is(err, ErrUnsupportedRequirement)`),
  naming the offending entry and carrying the whole declared list.

  The guard sits in `encodeMetadataForHeader`, the one chokepoint every write in
  this package passes through — `Format`, `AddKey`, `ChangeKey`, `KillKeyslot`,
  the token writes and `WriteHeader` all reach the device through
  `writeHeaderInternal`, which encodes first — so it runs before anything
  touches the device, and `checkHeaderWritable` lets a caller ask in advance.
  `implementedRequirements` is the named set to add to when support for one of
  these features lands; it is currently empty, which is the honest state.

- **The container entrypoint creates its own loop device nodes and no longer
  starts udevd.** Without `--privileged` the host `/dev` is not bind-mounted
  in, so `/dev` is a bare tmpfs and nothing creates `/dev/loopN`. udev cannot
  fill the gap — without `--privileged` Docker mounts `/sys` read-only, so
  `udevadm trigger` cannot write the uevent and no node is ever made (measured)
  — and nothing is lost with it: `pkg/luks2` mknods its own dm nodes, the
  fallback `unlock.go` has always carried for environments without udev, and
  `cryptsetup` skips the udev cookie wait when no udevd is running.

- **The host-state guard's advice was wrong and has been corrected.** It used
  to say "Scope the container device access (see issue #80)". Scoping device
  access does not help and cannot: device-mapper is not namespaced, so
  `dmsetup ls` reports every mapping on the machine whatever `/dev` the
  container was given — measured, the unprivileged container sees exactly what
  the privileged one did. The guard's logic is unchanged; only the sentence
  that sent readers down a dead end is gone.


## [0.3.0-alpha] - 2026-10-03

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

### Changed — BREAKING: a keyslot whose declared area cipher mode is not AES-XTS is refused

- **The read path now honors the whole `keyslots.<n>.area.encryption` spec,
  not only its algorithm (#106).** `unlockKeyslot` (through `screenKeyslot`,
  so the removal guard too) accepts exactly `aes-xts-plain64` and
  `aes-xts-plain` — the two spellings of the transform keyslot material
  actually goes through — and refuses every other spec with the new sentinel
  `ErrUnsupportedKeyslotCipher`, wrapped in `ErrInvalidKeyslot` so the keyslot
  scan still moves on to the next slot. Previously a keyslot declaring, say,
  `aes-cbc-essiv:sha256` was decrypted as AES-XTS regardless: it opened here
  and in no conforming implementation, and no test could notice a wrong
  declaration.
- **Who is affected:** containers formatted by v0.1.x of this package with a
  non-XTS data cipher (`CipherMode` other than `xts-plain64`) carry AES-XTS
  keyslot material under the data cipher's label. `cryptsetup` never opened
  those keyslots; after this change this package does not either, and
  `TestKey`, `Unlock`, `AddKey` and `ChangeKey` report
  `ErrUnsupportedKeyslotCipher` for them. Containers written by `cryptsetup`
  or by current `Format` are unaffected. A genuine cryptsetup CBC keyslot, which
  used to fail as `ErrMasterKeyVerification` (indistinguishable from a wrong
  passphrase), is now reported as the unsupported cipher it is.

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

### Added

- **CI evaluates the tree a merge would produce, not just the branch head
  (#117).** Every other check reads the PR head; Gitea publishes only
  `refs/pull/N/head`, so there is no `/merge` ref to check out, and
  `git merge-tree` answers *"do these conflict?"* rather than *"is the result
  correct?"*. That left one state invisible to the whole pipeline: **branch
  green, `main` green, the merge of the two red.**

  The `Merged Tree` job constructs the merge, extracts it, and compiles it. It
  runs `go vet`, in both build-tag configurations, because `vet` compiles the
  test files and that is where the real breakages were — `go build` alone passes
  over them.

  Measured on the two that happened: #173 removed the exported `DeriveKey` while
  #158 still called it from a test, and #180 added four marshalers while #158
  changed the encoder they use. Both branches green, `main` green, both merges
  red, both found by hand one command before merging.

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

### Added

- **The secondary binary header is byte-compared against cryptsetup's
  (#167).** `TestSecondaryHeaderMatchesCryptsetup` (integration tier) reads the
  second header copy of both formatted containers from the `hdr_size` their
  primaries record. It checks that each copy really is a secondary header
  (`SKUL` magic, and a `hdr_offset` naming where it was read), then diffs all
  4096 bytes. It excludes only `sequence_id`, the header salt and the checksum,
  the same exclusions `TestFormattedBinaryHeaderMatchesCryptsetup` makes for the
  primary, and it asserts the excluded salt and checksum are non-zero. A
  subtest corrupts single bytes and requires the diff to report exactly that
  offset, so the comparison is shown to be able to fail. The primary test and
  the new test now share one comparison helper.

  No production behaviour changed.

### Fixed

- **A negative `Argon2Parallel` is refused with its siblings, not a layer later
  (#176).** `callerArgon2Options` forwarded only `Argon2Time` and
  `Argon2Memory`, so a caller's parallelism never reached the pre-check that
  bounds the other two. It was still refused — `deriveArgon2` rejects a `cpus`
  outside 1..255 — but after the pre-check had passed, further into the
  operation, and as a `CryptoError` rather than the `Argon2CostError` its
  siblings produce. The same mistake by the same caller got two error shapes at
  two moments.

  `validateArgon2CreateCost` now bounds all three, and `Argon2Parallel` is
  forwarded to it. A below-minimum parallelism returns an `Argon2CostError`
  wrapping the new `ErrInvalidArgon2Parallel`, matching time and memory exactly.

  Nothing was leaking: a bad value never reached a header. The risk was that an
  inert asymmetry becomes a hole when someone changes the code around it — which
  nearly happened, since `callerChoseArgon2Cost` had to be corrected from `> 0`
  to `!= 0` during an unrelated rebase. Under `> 0` a negative parallelism would
  have read as "the caller chose nothing" and silently inherited the container's
  cost instead of being refused at all.

### Fixed

- **The CLI no longer acts on a mount check that could not run (#185).**
  `IsMounted` fails only when `/proc/mounts` cannot be read — an absent mapper
  node is simply not listed and returns `false, nil` — so an error from it means
  the mount state is UNKNOWN, never "not mounted".

  Three commands treated the unknown as the permissive answer. `luks2 close`
  read `if err == nil && mounted`, which skipped the check entirely when it
  could not run and went on to **lock a volume whose filesystem may still be
  mounted**, tearing it out from under its writers. `luks2 mount` discarded the
  error and would **mount over a mountpoint that may be in use**, hiding
  whatever was there. `luks2 unmount` discarded it too and reported a false
  "Not mounted", which is safe but sends an operator looking in the wrong place.

  Each now distinguishes mounted, not mounted, and could-not-determine, and
  refuses on the third with the underlying cause.

### Added

- **`changelog.d/` fragments replace the shared `## [Unreleased]` section
  (#186).** Each PR now adds `changelog.d/<issue>-<slug>.md` holding only its
  own entry, carrying the Keep a Changelog heading it will land under.

  A shared section makes every open sibling PR conflict on one file, and each
  resulting rebase changes the head SHA — invalidating a reviewer's approval and
  re-queueing CI. Measured here: on 2026-09-13 two PRs edited that section and
  one could not merge until it was rebased, costing a full CI cycle for a
  docs-only collision.

  `make changelog-assemble VERSION=vX.Y.Z-alpha` folds the fragments into a new
  `CHANGELOG.md` section and deletes them. It does not commit: the changelog is
  the one release artefact a human should read before it is published.
  `release-alpha` refuses to tag while unassembled fragments remain, so a
  release cannot silently omit them.

  Adoption is additive per the convention — the existing `## [Unreleased]`
  content stays where it is and releases normally at the next tag.

### Changed — BREAKING: `Token` no longer models TPM2 members

- **go-luks2 carries no TPM2 knowledge (#189).** go-xkms owns all hardware and
  cloud crypto — TPM2, PKCS#11, the KMS backends — and this is a Layer 0
  library. The nine `TPM2*` fields on `Token` and the `TokenTypeSystemdTPM2`
  constant are removed.

  **No data is lost.** The unknown-member passthrough carries a `systemd-tpm2`
  token through a read-modify-write byte for byte, so a token written by
  `systemd-cryptenroll` survives a header rewrite exactly as systemd wrote it —
  read it back with `GetToken` and every member is there. Only `type` and
  `keyslots`, which LUKS2 itself defines, remain typed.

  A consumer that needs to *interpret* such a token supplies it through
  `KeyProvider`: go-xkms returns the unsealed credential and the token that
  identifies it, and this package enrolls the one and writes the other without
  understanding either.

  Migration: read the members off the token's JSON rather than from typed
  fields. The removed fields were never populated from a real systemd token
  anyway — several named members systemd does not write (#150).

### Removed — BREAKING: ext2 and ext3 can no longer be created

- **`MakeFilesystem` and `MakeFilesystemWithOptions` refuse ext2 and ext3
  (#195).** They now return `ErrUnsupportedFilesystem` where they used to run
  `mkfs.ext2` / `mkfs.ext3`. ext2 has no journal, and this library does not
  offer either filesystem on an encrypted volume. The owner ruled on this in
  #195. Use ext4 instead. The `FilesystemExt2` and `FilesystemExt3` constants
  remain so that callers can name the types being refused, and their comments
  say why. The `luks2 create` CLI no longer offers them, and the README and
  `docs/cli` no longer list them.
- **`luks2 create` offers ext4, xfs and vfat.** Its help is derived from
  `SupportedFilesystems()` less zfs: the command calls `MakeFilesystem`, which
  cannot pass the pool name ZFS requires, so it does not advertise zfs.
- **`luks2 create` refuses any other filesystem before touching anything.**
  `create <file> <size> ext2` (or ext3, zfs, or an unknown type) now exits 1
  with "Unsupported filesystem" before the file is created, formatted,
  attached or unlocked. Previously a type the library refused was only
  discovered at the last step, leaving an unlocked, unformatted volume and
  exiting 0.

### Fixed

- **`SupportedFilesystems()` is now the single source of truth for the
  supported set (#195).** Before this, three places each gave a different
  answer. `SupportedFilesystems()` said ext4, xfs, zfs and vfat. The
  `MakeFilesystemWithOptions` switch added ext2 and ext3. The
  `CheckFilesystem` switch left out vfat. As a result,
  `IsFilesystemSupported` said no to ext2 and ext3 even though creating them
  worked, and `CheckFilesystem` refused vfat even though the library
  advertised and created it. Both functions now dispatch through one table,
  and a unit test run by `make ci` checks that table against the list in
  both directions. A type added to the list without a make and a check
  implementation fails that test. Types outside the set are refused with the
  new sentinel `ErrUnsupportedFilesystem` before any device is touched,
  as an `*UnsupportedFilesystemError` naming the refused type.
- **`MakeFilesystemWithOptions` and `CheckFilesystem` return typed errors.**
  A volume that is not unlocked is a `*DeviceError` wrapping
  `ErrVolumeNotUnlocked`; a failed checker is a `*FilesystemCommandError`
  carrying the command, device and output. Callers that matched the old
  message text should use `errors.Is` / `errors.As`.
- **`CheckFilesystem` supports vfat (#195).** It runs `fsck.fat -n` for a
  read-only check, or `fsck.fat -a` with `repair` set. `fsck.fat` comes from
  the same dosfstools package as the `mkfs.fat` that creates the filesystem.
  A repair that `fsck.fat` reports by exiting 1 is confirmed with a
  read-only `fsck.fat -n` recheck, and counts as success when the recheck
  is clean. `fsck.fat` exits 1 both after writing repairs and after stopping
  on an internal inconsistency, so the exit status alone cannot tell them
  apart.
- **`CheckFilesystem` documents that ZFS is not read-only.** For zfs the
  device argument is a pool name, and the call only starts `zpool scrub`
  without waiting for its result. On a pool with redundancy the scrub repairs
  damaged data whether or not `repair` is set. This behaviour is unchanged;
  it is now written down.

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

### Fixed

- **`TestCreateDigest` no longer compares two wall-clock calibrations (#204).**
  The test checked the digest's recorded PBKDF2 iteration count against a
  *second, fresh* calibration and accepted anything within 2x. Two timing
  measurements taken moments apart are a property of how busy the host is, not
  of the code: on a loaded host the two landed five-fold apart
  (`56813` recorded against a fresh `10500`) and the test failed on a correct
  tree, which fails the unit tier's hermeticity requirement and every delivery
  that happened to run beside another build.

  The count is pinned through the existing `digestIterationsFor` seam instead,
  and the assertion is now the property that belongs to `createDigest`: it
  records *exactly* what the calibration returned, for the hash the digest
  declares. That is strictly stronger than the old band — a count rounded or
  substituted by a few hundred iterations passed the 2x check and fails this
  one. The real calibration's time target and LUKS2 iteration floor are
  unchanged and stay checked in `TestDigestCalibrationTargetsItsBudget`.

  No production behaviour changed.

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

### Fixed

- **`TestFormattedJSONMatchesCryptsetupByteForByte` no longer compares two
  wall-clock calibrations (#209).** Before it substituted the digest iteration
  count, the test checked this package's calibration against cryptsetup's and
  accepted anything within 0.5x–2x. Those were two timings taken at different
  moments on a loaded CI host, so the check measured the scheduler rather than
  the code. It failed a correct tree at 0.48x (`88224` against `182297`).

  `buildCanonicalPair` now reads the digest count cryptsetup calibrated out of
  its header and pins this package's digest to it through the
  `digestIterationsFor` seam, the same way it already mirrors the keyslot
  costs. cryptsetup still calibrates freely. The count is no longer substituted
  and is now compared byte for byte with the rest of the JSON, which is
  stricter than before. The drift guard now checks the constants that define
  the calibration (`DigestIterationTargetMs`, `DigestCalibrationKeyLen` and the
  LUKS2 floor) against cryptsetup's, so load on the host cannot fail it. The
  band was not widened.

  No production behaviour changed.

### Changed

- **The repository ships no shell scripts (#211).** `.github/require-tool.sh`
  is now the Go command `test/ci/cmd/require-tool`, and CI calls it with
  `go run`. `test/integration/docker-run.sh` is now
  `test/integration/cmd/docker-run`, which every Makefile integration target
  and the CI workflow build (`make docker-run-bin`) and run as
  `build/docker-run`, so docker's own exit status reaches the caller.
  Behaviour is unchanged: the same fail-closed version assertion, and the same measured privilege set for the integration
  container, which a unit test now pins flag by flag. For an interactive shell
  under that set, run `make docker-run-bin` and then
  `build/docker-run --rm -it -- bash`.
- **`CLAUDE.md` is no longer tracked (#211).** Agent instructions stay out of
  the published tree. The file is gitignored, so it can still exist in a
  working checkout.

### Added

- **A public-releasability gate, `make releasability` (#211).** It runs in
  `make ci` and in CI, over the staged content of the checkout's git index, not the working tree. It fails on any tracked
  file that names a fleet address, fleet hostname or owner path, in its content
  or in its path. It also fails on any tracked file the public release must not
  carry: a shell script, agent instructions, or any workflow other than
  `ci.yml`, `nightly.yml` and `release.yml`. Each half has a test that plants
  a violation and checks that it is caught. The gate's package tests need no
  checkout, so `go test ./...` still passes in the integration image, which
  carries no `.git`. One workflow, `automerge.yml`, is pending a ruling: the
  gate lists it as an open item on every run and does not call the tree
  publishable while it is tracked, but does not fail on it. See
  `docs/RELEASABILITY.md`.
- **Binary and oversize files fail the gate unless `releasability-exempt.txt`
  lists them (#211),** each with the reason a person accepted it. The list is
  read from the index; a stale entry, a missing reason or a duplicate stops
  the gate, and every exemption is printed on every run.
- **`docs/COMPATIBILITY.md` (#211)** states the compatibility policy from the
  first public release on: what a version number promises, how a breaking
  change is announced, and that published tags are immutable.
- The release and CI tooling packages (`test/labstrings`, the gate command,
  `test/ci/cmd/require-tool`, `test/integration/cmd/docker-run`) are held to
  the 90% coverage floor like every other package.

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

### Fixed

- **`CheckFilesystem(dev, "ext4", true)` no longer reports a successful
  repair as a failure (#228).** `e2fsck -p` exits 1 when it corrected errors,
  and every nonzero exit used to become a `*FilesystemCommandError`, so a
  check that had just fixed the filesystem told the caller it had failed. The
  status is now read as e2fsck's bitmask: with `repair`, 0 is clean, 1 and 2
  (errors corrected; corrected and a reboot requested) are success, and any
  status with bit 4 or higher set (errors left uncorrected, operational,
  usage or shared-library error, canceled) is still an error. A signal or a
  checker that could not be started is still an error. A read-only check
  (`e2fsck -n`) is unchanged: any nonzero status means errors are present.

### Added

- **`CheckFilesystemDetailed` (#228)** runs the same check as
  `CheckFilesystem` and, on success, returns a `FilesystemCheckResult`
  reporting whether the checker wrote a repair (`Repaired`: e2fsck exit 1 or
  2, or a fsck.fat repair confirmed by its read-only recheck) and whether
  e2fsck asked for a reboot (`RebootRequired`: exit status bit 2).
  `CheckFilesystem` keeps its signature and returns only the error.

### Fixed

- **`luks2 create` fails when the filesystem cannot be created (#229).**
  When `MakeFilesystem` failed for a supported type, for example because
  `mkfs.ext4` is missing, `create` printed a warning followed by "Volume is
  ready" and exited 0. That left an unlocked mapping with no filesystem on
  it, and a script that checked the exit status took it as a usable volume.
  `create` now exits 1 and prints the cause. It closes the `luks-auto`
  mapping it opened and then detaches the loop device it attached, and it
  says that the LUKS2 container file is valid and was kept. If the mapping
  cannot be closed, it says the volume is still unlocked and prints the
  `luks2 close` and `losetup -d` commands to finish the cleanup.

### Fixed

- **`test/makefile` passes on any host, including one whose fallback go is
  older than `go.mod` (#230).** `TestGoFallbackWhenNotOnPATH` runs the
  Makefile with no go on `PATH`, so it uses the `/usr/local/go/bin/go`
  fallback. Where that install is older than `go.mod`'s go line,
  `GOTOOLCHAIN=auto` downloads the required toolchain into the module cache
  under the test's temporary `GOPATH`, and the go command writes the module
  cache read-only. The test's directory cleanup then failed with
  "permission denied" and failed the test, which also failed `make ci`. Each
  test's `GOPATH` is now created by `ownedGOPATH`, with `GOMODCACHE` pinned
  inside it, and is made writable before removal. The assertions are
  unchanged, so the test still fails if the fallback it pins breaks.

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

### Fixed

- **The nightly FIPS lane is green again (#235).** Under
  `GODEBUG=fips140=only` nine tests failed on main because they create Argon2
  keyslots, which FIPS 140-3 mode refuses: the three Argon2 cost tests in
  `pkg/luks2`, and six `cmd/luks2` tests whose fixtures enrolled Argon2
  keyslots and recovery keys. Each now states what it asserts in each mode,
  and none gained a skip guard:

  - `TestCreateArgon2KDFCarriesANegativeCostToTheDerivation` and
    `TestCreateArgon2KDFStillDefaultsAZeroCost` check the cost seam
    (`createArgon2KDF`) directly in both modes -- it is the same code either
    way -- and the public `CreateKDF` for what it does in this process's mode:
    carry or default the cost, or, under FIPS, refuse Argon2 with
    `ErrFIPSNotApproved` and build nothing.
  - `TestAddKeyReportsTheInheritedCostToTheCaller` inherits from an Argon2
    container written by cryptsetup, so the fixture exists in either mode.
    Without FIPS, AddKey inherits and reports the cost; under FIPS it is
    refused with `ErrFIPSNotApproved` and the first 2 MiB of the image -- both
    header copies and the keyslot area AddKey would write -- is unchanged.
  - The `cmd/luks2` wiring tests enroll their keyslots with the cheapest KDF the
    library writes in the mode: Argon2id at its floor, or under FIPS
    pbkdf2-sha512 (210000 iterations for a passphrase keyslot, 1000 for a
    library-generated recovery key).

  The nightly FIPS job now installs cryptsetup, as CI's unit job does: the
  conformance tests require it and fail without it.

### Fixed

- **Volumes whose keyslots use SHA-1 anti-forensic hashing open (#236).** Every
  LUKS1 volume converted to LUKS2 with `cryptsetup convert`, and any
  `cryptsetup luksFormat --hash sha1`, splits its keyslots with SHA-1, which
  the anti-forensic merge did not implement, so this library could not open
  them at all although cryptsetup does. Outside FIPS mode they now open, to the
  same volume key cryptsetup recovers. In FIPS 140-3 mode they are refused
  before any hashing with `*FIPSImportRequiredError` (matching
  `ErrFIPSNotApproved`), naming `anti-forensic hash sha1`, and
  `MigrateToFIPS` imports them like any other non-approved keyslot. SHA-1 is
  read and never written: the split accepts SHA-256 and SHA-512 only, `Format`
  refuses `HashAlgo: "sha1"` with `ErrUnsupportedHash` before touching the
  device, and `ChangeKey` rewrites a SHA-1 keyslot with a SHA-256 split. See
  docs/FIPS.md.

### Added

- **`luks2 create` and `luks2 recovery add` take KDF options (#237):**
  `--pbkdf argon2id|pbkdf2`, `--hash`, `--iter-time`,
  `--pbkdf-force-iterations`, `--pbkdf-memory` and `--pbkdf-parallel`, named
  as cryptsetup names them. They are validated against the process's mode
  before the passphrase prompt and before `create` makes a file: an option
  that does not apply to the chosen KDF, an empty value, or a value that is
  not a whole number above zero is refused, and in FIPS 140-3 mode
  `--pbkdf argon2id` is refused with the library's `ErrFIPSNotApproved`. Cost
  bounds stay the library's and are checked when the keyslot is written.
  `create` reports the KDF it used.
- `luks2.DefaultKDFType()` reports the KDF a keyslot gets when the caller
  names none, and `RecoveryKeyOptions.PBKDFIterTime` sets the PBKDF2 budget of
  a recovery keyslot.

### Changed

- **The library's default KDF follows the mode, as cryptsetup's does (#237).**
  In FIPS 140-3 mode a keyslot created with no KDF named -- through `Format`,
  `AddKey`, `AddRecoveryKey` or `CreateKDF` -- is PBKDF2-SHA512, calibrated
  to the time budget and never below the SHA-512 iteration floor (210,000 at
  the default 2000 ms). Before, the default was Argon2id in every mode, so it
  was refused in FIPS mode: `luks2 create` (which hard-coded Argon2id) and
  `luks2 recovery add` could create no keyslot under `GODEBUG=fips140=only`,
  even on a volume whose keyslots were all PBKDF2. Outside FIPS mode the
  default is Argon2id, unchanged.
- A caller that names no KDF but sets an Argon2 cost gets Argon2id in either
  mode -- refused in FIPS mode -- rather than a PBKDF2 keyslot with the cost
  silently dropped.

### Changed — BREAKING: an explicit KDF alias's hash is honored, and an Argon2 cost with no KDF type meets the floor

- **A KDF alias's hash is honored by `Format` and `AddKey` (#237).** Both
  defaulted the hash to SHA-256 before creating the keyslot's KDF, and that
  overrode the hash an alias names, so `KDFType: "pbkdf2-sha512"` (or
  `-sha384`) wrote a PBKDF2-SHA256 keyslot. The keyslot now uses the alias's
  hash; a hash the caller sets explicitly still wins, and the volume digest
  keeps its own default.
- **`Format`'s Argon2 cost floor applies when the KDF is left to the default
  (#237).** The floor was checked only when `KDFType` was spelled `argon2id`
  or `argon2i`, so `FormatOptions{Argon2Memory: 32}` with no type passed it.
  It is now checked against the KDF the options resolve to.

### Changed — BREAKING: no keyslot or digest is created with a PBKDF2-SHA1 KDF

- **No keyslot or digest is created with a PBKDF2-SHA1 KDF (#239).**
  `Format`, `AddKey`, `CreateKDF` and the digest writer refuse
  `KDFTypePBKDF2SHA1` and a `sha1` hash (`FormatOptions.HashAlgo`,
  `AddKeyOptions.Hash`, in any case) with the new `ErrSHA1NotWritten`,
  alongside `ErrUnsupportedKDF` or `ErrUnsupportedHash`, before deriving or
  writing anything; `AddKey` refuses before unlocking the existing keyslot.
  Code that created PBKDF2-SHA1 keyslots must choose `pbkdf2` with sha256,
  sha384 or sha512, or Argon2. `ChangeKey` on a PBKDF2-SHA1 keyslot (a
  converted LUKS1 one, for example) now rewrites it as PBKDF2-SHA256 instead
  of preserving SHA-1, at an iteration count converted from the old keyslot's
  cost -- the larger of equal HMAC work for the key's length and equal time
  measured on the machine, raised to the SHA-256 floor -- never simply copied,
  since the same count can halve the work for a 64-byte key. Existing SHA-1 keyslots and digests still open outside
  FIPS mode, byte-compatible with cryptsetup. See docs/FIPS.md.
  The CLI's `addkey --kdf pbkdf2-sha1` (and any unknown KDF) is refused as a
  usage error before either passphrase is asked for; `--hash` and `--pbkdf`
  already accept no SHA-1 (#237).

### Added

- **`FormatOptions.MetadataSize` selects the LUKS2 metadata area size, the
  equivalent of cryptsetup's `--luks2-metadata-size` (#47).** Zero keeps the
  16 KiB default (12288 bytes of JSON). Any other value must be a power of two
  from 16 KiB to 4 MiB, the exact set cryptsetup accepts; anything else is
  refused with the new `ErrInvalidMetadataSize` before the device is touched.
  The layout follows cryptsetup's as measured against 2.7.0: the second header
  copy at `MetadataSize`, the keyslots area at `2 × MetadataSize`,
  `keyslots_size = 16 MiB − 2 × MetadataSize`, and the data segment at 16 MiB.
  Every legal size is formatted in the test suite and checked with cryptsetup's
  `luksDump` and `luksOpen --test-passphrase`. A container that needs more
  than 12288 bytes of JSON, such as one carrying large tokens, can now be
  formatted with room for it. Metadata that still does not fit is refused with
  `ErrMetadataTooLarge`, as before, and never grows into the next region.

### Fixed

- **`Format` places keyslot 0 at `2 × area` instead of a hard-coded `0x8000`,
  and a header-only `Wipe` zeroes both header copies at the area the container
  records (#47).** The fixed 32 KiB wipe covered both copies only of a 16 KiB
  area. On a container with a larger area, whether written by cryptsetup or by
  the new option, the second copy survived intact and the "wiped" volume could
  still be recovered. Only a copy whose checksum validates decides the size:
  the primary if it is valid, otherwise the smallest valid secondary. A
  damaged primary can neither understate its size and leave a valid secondary
  behind, nor overstate it and zero payload on a container whose data segment
  starts early. When no copy validates, the default 32 KiB is zeroed. Any other
  copy still recognizable as a LUKS2 header has its 4 KiB binary header zeroed,
  so no copy stays locatable.

### Added

- **`UnlockWithVolumeKey` opens a volume with a key the caller already holds
  (#79).** The caller passes the volume key as an `*enclave.MemoryEnclave`
  instead of a passphrase. No keyslot is scanned and the keyslot KDF never
  runs, so the passphrase derivation and its unwipeable copies are not on the
  path. This is the unlock half of the owner's ruling on #79. The format half,
  with its mandatory recovery keyslot, follows as a separate change. The
  library still has no hardware code and no policy about where a key comes
  from.

  The new entry point shares its whole body with `Unlock`: path, name, in-use,
  header and segment validation, the keyring transport and the rollback. The
  key must be attested by a digest assigned to the crypt segment being mapped,
  and its length must equal the `key_size` of a keyslot that digest names.
  The length check is needed because HMAC zero-pads a short key, so the volume
  key with zero bytes appended passes the digest. A key failing either check
  is refused with `ErrMasterKeyVerification`. A nil, destroyed or oversized
  enclave is refused with the new `ErrInvalidVolumeKey`. The caller's enclave
  is never destroyed.

  The digest check runs PBKDF2 over the key, so residual exposure 2 still
  applies to this path once per digest tried. `enclave.go` and the README
  record this. Passphrase paths and `ErrLastKeyslot` are unchanged.

### Added

- **`MigrateToFIPS` imports an Argon2 volume into a FIPS 140-3 deployment
  without re-encrypting it (#84).** A FIPS process cannot execute Argon2, which
  is cryptsetup's default KDF, so it could not open any volume from a plain
  `cryptsetup luksFormat`. The refusal stays; this is the way in. Run once from
  a process not in FIPS mode, it adds a PBKDF2 keyslot wrapping the existing
  volume key, migrates any digest whose KDF is not approved, verifies the
  volume opens through approved KDFs alone, and then removes the Argon2
  keyslots — nothing is removed before that verification, and the data area is
  never touched. `KeepNonApprovedKeyslots` keeps the originals and the result
  reports the import incomplete. Called in a FIPS process it refuses with
  `ErrFIPSMigrationUnderFIPS`. See `docs/FIPS.md`.
  It carries across only the key a digest binds to every data segment — an
  unbound key the same passphrase opens is never mistaken for it
  (`ErrFIPSMigrationUnboundKey`) — and judges a KDF by what strict FIPS mode
  will run: a PBKDF2-SHA256 keyslot or digest whose salt is under 128 bits, or
  whose output is under 112, is migrated like Argon2 rather than kept. It
  reads and writes header and keyslot space only: every keyslot's declared
  area must be confined to the keyslots area, clear of the data, before the
  first keyslot is read (`ErrKeyslotAreaOverlap`).
- **Digests whose KDF is Argon2 are evaluated outside FIPS mode (#84).** The
  digest model gains `time`, `memory` and `cpus`, omitted when unset, so a
  foreign volume whose digest uses Argon2 opens outside FIPS mode and can be
  imported; `MigrateToFIPS` rewrites such a digest as PBKDF2.

### Fixed

- **An interrupted header write can no longer tear both header copies (#84).**
  The primary copy is synced before the secondary is written, so a crash or
  power loss at any point leaves at least one complete copy; before, both
  copies were synced only together at the end and writeback could leave both
  half-written. Every header write takes this path, including each step of
  `MigrateToFIPS`, whose every crash state is now tested to open — in
  cryptsetup, and in this library through `RestorePrimaryHeader` when the
  primary was the copy torn — and to finish importing when run again.
- **Re-running an interrupted `MigrateToFIPS` can no longer lose the last way
  in (#84).** A run that found a stale or torn secondary header copy — what an
  interrupted earlier run can leave — went on to wipe the Argon2 keyslot while
  the secondary still named only it, so one more interruption could leave no
  readable copy that opened the volume. It now repairs the secondary from the
  primary (syncing the primary it read first, then writing the secondary
  alone) before its first write — every run first syncs the device, evicts
  its cached pages, and confirms the two header copies read through the cache
  are byte-identical to the same bytes read with `O_DIRECT` past every cache
  to the medium (including every loop device's backing, all the way down),
  never reading past them, so what it
  acts on is what is on the medium and not what an interrupted or failed
  earlier write left in the page cache (`ErrDeviceCacheStale`,
  `ErrDirectIOUnsupported`) — and requires
  the copies to agree before the first removal. A header write that fails
  having damaged the primary is reported as such, naming
  `RestorePrimaryHeader`, instead of as a volume that "still opens exactly as
  it did before" — judged from the header copies on the medium, read past the
  page cache, not from what the cache still holds.

- **An unbound key no longer shadows the volume key (#84).** The unlock scan
  tries keyslots whose digests bind every data segment first, so a passphrase
  shared with an unbound keyslot of a lower number opens the volume with the
  volume key rather than handing dm-crypt the unbound one. `MigrateToFIPS`
  verifies that the scan, over approved keyslots and digests only, recovers the
  volume key before it removes anything.
- **`AddKey` assigns the new keyslot to exactly one digest (#84).** It used to
  append the keyslot to every digest, so on a header carrying an unbound key
  the result was refused by cryptsetup ("Keyslot N is not assigned to exactly 1
  digest"). It now joins only the digest its key matches.

### Changed

- **Header-reader rejections are typed (#84).** A checksum mismatch, a bad
  magic and a recorded offset or size that disagrees with where the copy was
  read all match `ErrInvalidHeader`; a header whose version is not 2 (LUKS1)
  matches the new `ErrUnsupportedLUKSVersion` and not `ErrInvalidHeader`,
  because it is not damage. A checksum mismatch used to be untyped, so a caller
  could not tell a torn header copy from an I/O failure and reach for
  `RestorePrimaryHeader`.

- **A FIPS process that cannot open a volume only because of its KDFs now says
  so (#84).** It returns `*FIPSImportRequiredError` — the volume is intact, these
  keyslots or digests use a KDF FIPS mode cannot execute, `MigrateToFIPS` is the
  remedy — instead of "invalid keyslot: argon2id: algorithm not approved", which
  read as corruption. It still matches `ErrFIPSNotApproved`; it no longer matches
  `ErrInvalidKeyslot`/`ErrInvalidHeader` in that case, because the volume is not
  damaged. A volume that is also damaged is reported as damaged, as before.

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

## [0.2.0-alpha] - 2026-09-03

MINOR rather than PATCH: this release both **removes** two exported error
sentinels and **adds** exported API. Pre-1.0, MINOR is where breakage lives,
and announcing a breaking change in a changelog without bumping the minor is
not announcing it. The removals are detailed under *Removed* below; no
repository in the portfolio references either symbol, so nothing outside this
one has to change to adopt the release.

### Fixed

- **`Lock` no longer fails on a transient device-mapper `EBUSY` (#122).**
  Closing a mapping intermittently failed with
  `dm ioctl: device or resource busy` because something holds the target open
  for a moment after the activity preceding the close — in practice a process
  started by a udev rule. There was **no `EBUSY` retry anywhere** in the
  package; the only mentions of retrying were comments explaining why other
  conditions are *not* retryable. Traced from go-blockstore #45, where it cost
  roughly one failure per full integration run.

  The remedy is device-mapper's own rather than ours: `dmsetup(8)` documents the
  same condition and ships `remove --retry`, which retries *"for a few seconds"*
  when *"a process run from a udev rule is temporarily using the device"* — so
  the 3-second budget is anchored to that rather than chosen.

  **Only `EBUSY` is retried.** A device that is gone will still be gone and a
  permission refusal will be refused again; retrying those would spend the whole
  budget turning a fast, correct failure into a slow one.

  **What it says when it gives up is the substance, not the loop.** On
  exhaustion `Lock` returns the new `ErrMappingBusy`, naming the mapping, the
  attempt count, the budget spent, and how to find the holder (`lsof`,
  `mount`, `dmsetup info -c`, and `dmsetup remove --deferred` for a device that
  will free later); the underlying `EBUSY` stays reachable via `errors.Is`. A
  retry that ended in the same bare errno would only be a slower way to say the
  same unhelpful thing.

  The rollback path, `removeCreatedMapping`, shares the retry and **keeps its
  verdict unchanged**: a target it still cannot remove is `ErrMappingStillLive`,
  because a plaintext device the caller does not know exists is a different and
  louder problem than a close that failed. It gains only the absence of false
  alarms on a hold that clears.

  The rollback confirms the target is **ours by UUID before every attempt**, not
  once before the first. Retrying a removal by name alone would have widened a
  one-ioctl race into a three-second one: during a backoff another actor can
  remove our target and create a different mapping under the same name, and the
  next attempt would remove theirs. Whatever a caller must be sure of before
  removing belongs inside the unit being retried.

- **`AddRecoveryKey` reported a keyslot it had not used — a failed revocation
  that destroys a live credential (#42).** It inferred the slot after the fact
  as the **highest-numbered** one in the header, while `AddKey` fills the
  **first free** one. The two agree only while the active slots are contiguous
  from zero, which stops being true the moment any credential is revoked.
  Measured on a container holding slots `{0, 2}`: the recovery key landed in
  slot 1 and was reported as slot **2**.

  The number is written into the saved recovery-key file, so it outlives the
  process. An operator retiring the recovery key months later reads slot 2,
  revokes slot 2, and **destroys a different credential while the recovery key
  stays live** — both halves wrong in the dangerous direction.

  The inference is deleted rather than corrected: `AddKey` now reports the slot
  it chose, at the point it chooses it and under the device lock, and
  `AddRecoveryKey` records that. Any rule that reconstructs the choice instead
  of reading it drifts from `AddKey` again the next time either moves. The
  exported `AddKey` signature is unchanged — it has a consumer outside this
  repository — so the reporting variant is unexported.

  The old code also swallowed its own failure: on a `ListKeyslots` error it left
  `Keyslot` at its zero value, reporting **slot 0**, which on almost every
  volume is the operator's primary passphrase.

- **PBKDF2 keyslots were formatted with roughly 1/50th of the requested work
  (#52).** `BenchmarkPBKDF2` calibrated the iteration count by timing 1000
  iterations once and gating the extrapolation on `elapsed.Milliseconds() > 0`.
  A thousand iterations of PBKDF2 is a few hundred *micro*seconds on any modern
  CPU, so that comparison was always false, the extrapolation never ran, and
  every pbkdf2 keyslot this library formatted received a hardcoded **100000** —
  about 20–50 ms of work against a documented 2000 ms target, one to two orders
  of magnitude off. On the reference workstation the correctly calibrated counts
  at the 2000 ms default are ~4.7M (SHA-256) and ~2.5M (SHA-512).

  Three defects, not one, and fixing any of them alone leaves a broken
  calibration:

  - **Resolution.** The measurement now uses the full `time.Duration`. Even on
    the path where the old comparison did pass, truncating a sub-millisecond
    measurement to an integer left the extrapolated count wrong by up to ~3x,
    unpredictably, per machine.
  - **Probe size.** The probe starts at 1000 iterations and **doubles** until it
    clears a floor of tens of milliseconds, so the measurement is meaningful on
    a fast server and on a slow board alike. One fixed probe size cannot be.
  - **The silent fallback.** `return 100000, nil` was a fail-open: a
    weak-but-plausible count with a `nil` error, so no caller could tell
    calibration had failed. Calibration now fails closed with a typed
    `*KDFCalibrationError` (matching the new `ErrKDFCalibration`), and a
    `PBKDFIterTime` outside 1..600000 is refused rather than silently floored.

  A second, hardware-independent floor was added with it: the count is never
  below the OWASP recommendation for the hash, scaled to the requested budget
  (600,000 SHA-256, 210,000 SHA-384/512, 1,300,000 SHA-1 at the 2000 ms
  default). A calibrated count measures the *defender's* hardware; the
  attacker's is unrelated and is not slow, so formatting on a low-end board
  would otherwise produce a header that is weak everywhere and that outlives
  the board. The result is also clamped to the same iteration ceiling
  `validateKDFCost` enforces on read-back, so a calibrated count can never
  produce a keyslot this library would then refuse to open.

  **This does not reach volumes that are already formatted.** The iteration
  count lives in the LUKS2 header, so every pbkdf2 keyslot written by an
  affected release stays at 100000 until it is re-keyed. Argon2 keyslots — the
  library default — are unaffected; only pbkdf2, which is what FIPS deployments
  are required to use.

  The three tests that existed asserted only `iterations >= 1000`, which 100000
  satisfies, which is why this survived five merges and three releases of green
  suites. They are replaced by tests that run the returned count and measure it,
  that check the count scales with the requested budget, and that pin the
  recommended minimum without depending on machine speed.

- **A keyslot whose every attesting digest is unusable is a header fault, not a
  credential verdict (#41).** With the CORRECT passphrase over a container whose
  only digest decodes to 64 bytes under a `sha256` label, `TestKey` reported
  `master key verification failed` — a judgement that never happened, because no
  digest ever reached a comparison. `verifyMasterKey` now counts *evaluated*
  digests separately from *applicable* ones and reports `ErrInvalidHeader` when
  digests attest the keyslot and not one of them could be compared.

  The distinction is deliberately narrow. `ErrMasterKeyVerification` remains one
  value for every cause: an attacker holding the device can craft a header, and
  an error separating "digest 2 uses a KDF I refuse" from "digest 2 did not
  match" would tell them which keyslot to work on. That reasoning covers
  outcomes of comparisons that ran; this branch is the one place where none did,
  so there is no outcome to leak and the statement is about the header the
  attacker wrote. The message names the keyslot and the count, never the cause.

- **A permission failure has a type, not just a message (#31).**
  `ErrPermissionDenied` was declared and returned by nothing, and nothing
  inspected `os.ErrPermission`. The message was already accurate; what was
  missing was the contract a consumer branches on to tell "you need privileges"
  from "this device is broken". Classified in one place — `openDevice` is now
  the only way `header.go`, `format.go` and `unlock.go` open a device — with the
  original `*fs.PathError` kept in the chain, so `errors.Is(err,
  os.ErrPermission)` remains true of the same value. The keyslot, wipe,
  loop-device and recovery-file paths do not classify yet; the sentinel's doc
  comment names them.

- **`IsMounted` no longer misses a mount point whose path contains a space, tab,
  newline or backslash.** `/proc/mounts` escapes those four bytes, because its
  fields are space-delimited — a real mount at `/mnt/my disk` is written there
  as `/mnt/my\040disk` — and the comparison was made against the raw field. So
  `IsMounted("/mnt/my disk")` answered **false** for a mount that exists. The
  CLI branches on it in three places. The escapes are now decoded before
  comparing.

- **Every inert error sentinel is now a decision (#70).** Six were missing
  returns and are wired: `ErrVolumeAlreadyUnlocked` (`Unlock` refusing a name
  already in use), `ErrVolumeNotUnlocked` (`Lock` and `Mount`), `ErrNotMounted`
  (`Unmount`), `ErrUnsupportedKDF` (`DeriveKey`, `CreateKDF`) and
  `ErrUnsupportedHash` (the KDF and anti-forensic hash dispatches). `Lock`'s was
  the sharpest: closing a name nothing has opened reported a *device-mapper*
  failure, sending an operator to look at device-mapper when the actual state
  was that there was nothing to close.

  `Unmount` classifies the KERNEL'S answer rather than pre-empting it: the
  flags are validated first, which leaves "the target is not a mount point" as
  the only remaining reading of an `EINVAL` from `umount2(2)`. A first draft
  consulted `IsMounted` before the syscall and inherited the escaping defect
  above, refusing mount points it should have unmounted; that never shipped.

- **`nextPowerOf2` is deleted (#48).** It had no production caller after #36
  removed the header-area rounding, and `unused` could never have said so —
  `.golangci.yml` sets `tests: true`, so a function referenced only by its own
  test is indistinguishable from a helper the suite uses. It is removed rather
  than left because it is the mechanism of #36, which rounded the JSON region
  past the fixed backup-header offset and destroyed keyslot key material.
  `isPowerOf2` beside it was checked the same way and is live.



- **A container with no usable keyslot is no longer reported as a wrong
  passphrase (#30).** The keyslot scan fell through its loop without executing
  the body and ended at a bare credential verdict, so an operator whose header
  carried no openable keyslot was told their passphrase was wrong — sending
  them to retype a credential that was never the problem and that no passphrase
  would replace. `getMasterKey` now returns `ErrNoKeyslots`, naming which of the
  two reachable states it is: a keyslots object that is empty or absent, or one
  whose every entry has a type the unlock path will not try (a container left
  partway through a reencryption, which still looks populated in
  `ListKeyslots`). `ErrNoKeyslots` was declared and returned by nothing; the
  path that should have raised it raised something misleading instead.

  `TestKey` and `KillSlot` carry the distinction through instead of flattening
  it: their wrappers name the OPERATION ("could not open ...", "could not
  authenticate against ...") rather than asserting a verdict on the credential
  that, in this state, was never reached. `KillSlot` also drops its private copy
  of the keyslot scan in favour of `getMasterKey` — the copy had no keyslot-type
  filter and one message for every outcome, which is the same defect in a second
  place.

### Security

- **A crypt segment's `sector_size`, `iv_tweak` and `encryption` are validated
  where the header is read (#40).** All three were handed straight to a
  device-mapper ioctl with nothing between them and the kernel. Measured by
  crafting a segment through this library's own writer and driving the real
  unlock path: `sector_size: -1` was accepted and reached the dm-crypt table as
  `18446744073709551615` (which devmapper renders into the target flag
  `sector_size:-1`); `iv_tweak: "not-a-number"` was accepted and reached the
  table as `0`, a valid-looking tweak, so the mapping was created at the wrong
  IV offset rather than refused; and an `encryption` string containing a SPACE
  reached the table verbatim **and the unlock succeeded**. devmapper joins the
  crypt target specification as `<cipher> <key> <iv_offset> <device> <start>`
  with spaces and the cipher is field zero, so a space inside a header-supplied
  cipher string shifts every field after it and lets the header nominate the key
  reference the kernel resolves and the device the target is backed by.

  The conversion carried `#nosec G115 - sector size is validated (512 or 4096)`.
  That validation is `ValidateFormatOptions`, which checks what a caller passes
  to `Format`, and never applied to a segment read off a device. The suppression
  is deleted rather than reworded: the conversion is gone, replaced by a lookup
  in a whitelist whose values are already `uint64`. Bounds are measured against
  cryptsetup 2.7.0 — `--sector-size` accepts 512, 1024, 2048 and 4096, so the
  read path accepts all four even though this package's writer still emits only
  512 or 4096, because narrowing the read path to the writer's range would
  refuse containers cryptsetup can create.



- **A digest can no longer authenticate a keyslot it does not name.**
  `verifyMasterKey` tried EVERY digest in the header against a key recovered
  from ONE keyslot, ignoring the digest's `keyslots` array. A LUKS2 container
  can hold more than one volume key — that is the ordinary state of one being
  reencrypted — and each digest attests exactly one of them, so accepting a key
  on the strength of an attestation made about a different keyslot is a
  verification that does not verify what it claims to. The unlock would treat
  the key as authenticated for this keyslot's segments, and `KillSlot` would
  authorize a destructive operation through an association the header never
  made. The digest set is now filtered to those naming the keyslot being opened,
  before any derivation; a keyslot no digest names is reported as
  `ErrInvalidHeader` — a broken container, not a failed credential — and so is a
  header with no digests at all, which previously reported a verification
  failure for a key nothing had judged.

  `unlockKeyslot` takes the keyslot's ID for this reason; it is an unexported
  function and no exported signature changed.

### Removed

- **BREAKING: `ErrInvalidPassphrase` is removed (#70).** No path in the package
  returned it and none honestly could: the passphrase derives only the key that
  *decrypts* the anti-forensic material, the merge is unauthenticated, and a
  wrong credential, the **correct** credential over damaged key material, and a
  semantically wrong digest all reach the digest comparison indistinguishably
  (#68). `ErrMasterKeyVerification` says what happened without claiming why.
  Callers branching on the removed symbol get a compile error, which is the
  point — the branch never ran and never could.

- **BREAKING: `ErrAlreadyMounted` is removed (#70).** Linux permits stacking a
  mount over an existing mount point, so "already mounted" is a legal state
  rather than a condition this package can honestly refuse; refusing it would
  reject something the kernel allows. Callers that want to know call
  `IsMounted`.

  No repository in the portfolio references either symbol, or any other luks2
  error sentinel, so neither removal breaks a build outside this one.

### Changed

- **The FIPS activation boundary is keyslot CREATION, not key ACCESS (#15).**
  `v0.1.8-alpha` put the Argon2 refusal on the derivation path, so a
  FIPS-activated build could not open **any** Argon2 volume — and argon2id is
  cryptsetup's own on-disk default, which makes that every volume cryptsetup
  formatted with default settings. That is a data-availability failure that
  buys no compliance: the keyslot was enrolled long before the process started,
  refusing to read it removes no Argon2 material from the disk, and it made the
  migration path unreachable, since re-keying to an approved KDF requires first
  authenticating with the keyslot you already have.

  `DeriveKey`, `DeriveKeyEnclave` and every internal derivation now open an
  existing `argon2i`/`argon2id` keyslot in FIPS 140-3 mode. `CreateKDF` still
  refuses to **create** one with `ErrFIPSNotApproved`, including its
  empty-`KDFType` default, and `Format`, `AddKey` and `ChangeKey` all route
  through it — so no FIPS-mode process can enroll a non-approved keyslot.
  `requireFIPSApprovedKDF` is renamed `requireFIPSApprovedKDFForNewKeyslot` so
  that re-introducing it on a derivation path reads as wrong at the call site.
  Owner ruling 2026-08-20: in FIPS mode a non-approved KDF may not be
  ENROLLED, and enrollment is the operation that gets refused.

  PBKDF2-HMAC-SHA1 remains refused **while deriving**, and that is a different
  kind of rule: the Go Cryptographic Module panics on SHA-1 under
  `GODEBUG=fips140=only`, so the derivation cannot run at all. No exported
  signature changed; `ErrFIPSNotApproved` and `CryptoError` are unchanged, and
  only the set of situations that produce them narrowed.

## [0.1.10-alpha] - 2026-08-31

### Security

- **The volume key is given to `dm-crypt` by kernel-keyring reference instead of
  inside the device-mapper table (#78).** This closes the largest remaining hole
  in the library's key-custody story — residual exposure 5 in
  `pkg/luks2/enclave.go` — and it was unbounded rather than merely transient.
  `devmapper.CryptTable` with a `Key` set is hex-encoded with
  `hex.EncodeToString` and joined into the target spec, producing **two
  immutable Go strings holding the master key in hex** (a Go string cannot be
  wiped by anybody) plus an ordinary heap buffer for the ioctl that is never
  cleared — all three inside a third-party package this library cannot reach
  into, all three outliving the mapping's creation by however long the collector
  takes to reclaim them. In a long-lived storage daemon that is one process
  accumulating every volume key it has ever opened.

  The key now goes from its `go-enclave` locked memory straight into the kernel
  via `add_key` — the borrowed slice is handed to the syscall with no
  intermediate copy — and the table carries only a `:<size>:logon:<description>`
  reference. This is what `cryptsetup` itself does. The `logon` key type is used
  deliberately: its payload is write-only, so `KEYCTL_READ` cannot fetch it
  back, not even by root.

  **There is no fallback.** Nothing in the package assigns `CryptTable.Key`, on
  any path, under any option, which makes the hex encoding structurally
  unreachable rather than conditionally avoided — and a test parses the
  package's own source to keep it that way.

  The entry lives in the **session keyring**, is named by a **SHA-256 digest of
  the volume's dm UUID**, and is **revoked, unlinked and verified gone** as soon
  as the activation ioctl returns — on the success path and on every failure path.
  That lifetime is narrower than the mapping's on purpose: dm-crypt copies the
  key during construction and never consults the keyring again, so nothing can
  outlive its mapping and neither `Lock` nor the unlock rollback has anything
  keyring-shaped it could forget.

- **Residual exposure 5 was rewritten, not deleted.** Closing the device-mapper
  exposure moved the key somewhere else, and the honest statement of where is:
  for the duration of one activation ioctl the volume key is in the kernel's
  keyring, and **kernel keyrings are not namespaced by container** — they are
  scoped by uid and by session on the host. Three things bound it: the `logon`
  payload is write-only, so a same-uid neighbor could *use* the entry by
  reference but never *learn* the key; the ring is the session keyring, never
  the uid-wide user keyring, and container runtimes give each container its own;
  and the entry exists for one ioctl.

- **Untrusted input cannot reach the device-mapper target specification.** A dm
  target spec is space-delimited and positional
  (`<cipher> <key> <iv_offset> <device> <start>`) and `devmapper.go` builds it
  with `strings.Join(args, " ")`, so the keyring reference is one token in a
  parsed grammar. The dm UUID it is derived from is built from the LUKS2
  header's 40-byte `uuid` field — read straight off the device, charset
  unconstrained, and with the checksum equally under a hostile header author's
  control — plus a caller-supplied mapping name that nothing validated.

  Before this change those bytes only reached the fixed-width `DmIoctl`
  name/uuid fields, which are not grammar-parsed, so making them reach a parsed
  grammar would have been a new parser-confusion primitive. The description is
  therefore a **SHA-256 digest**: 64 characters of `[0-9a-f]` whatever went in,
  which closes the charset **by construction** rather than by validation — the
  same move as leaving `CryptTable.Key` unassigned instead of defaulting it off.
  Determinism is preserved, so the collision guard still works. Demonstrated
  against the unhashed revision, where a mapping name of
  `victim 0 crypt injected` produced a reference containing three spaces.

### Added

- **`ValidateMappingName` / `ErrInvalidMappingName`.** `Unlock` validated the
  device path and the passphrase and never the name, though the name becomes
  `/dev/mapper/<name>`, the dm ioctl name field, and part of the dm UUID the
  rollback uses to prove a target is its own. Those routes are not covered by
  the digest above. The charset is a whitelist (`[A-Za-z0-9]` first, then
  `[A-Za-z0-9_.+-]`) bounded at 127 bytes, which is `DM_NAME_LEN` minus the NUL
  — a truncated name would let two mappings share an identity.
- `CheckKeyringAvailable()` — a **startup preflight**. `Unlock` fails closed
  when the keyring is unavailable, which is correct but arrives at the first
  unlock of a real volume, turning a boot-time configuration error into a
  mid-service outage. The preflight performs one add and one release of a
  throwaway probe and returns the same typed error `Unlock` would, so a
  long-lived consumer fails at launch instead. It also exercises the release
  path, so a kernel that can add but not revoke is caught at startup rather than
  at teardown.
- Seven typed keyring errors, because four causes with four different fixes must
  not collapse into one useless message. **`ErrKeyring` is the root** and the
  only safe catch-all — every keyring condition matches it.
  `ErrKeyringUnavailable` covers *unavailability* only, and each unavailability
  also matches exactly one of `ErrKeyringBlocked` (seccomp, `EPERM`),
  `ErrKeyringUnsupported` (no `CONFIG_KEYS`, `ENOSYS`),
  `ErrKeyringQuotaExhausted` (`EDQUOT`) or `ErrKeyringFailed`.
  `ErrKeyringEntryExists` and `ErrKeyringKeyNotReleased` are the two anomalies
  and deliberately do **not** match `ErrKeyringUnavailable`, which is why the
  root exists: a caller using the unavailability umbrella as a catch-all would
  silently miss the one that reports a possibly-resident master key.
  `KeyringUnavailableError` carries the **remedy in the message** — it names
  `add_key`, `keyctl` and `request_key` so a seccomp profile can be written from
  a log line — and the errno stays reachable through `Unwrap`. The release path
  classifies its errno the same way, because that is the path that reports a
  master key may still be resident and is the last place to hand back a bare
  errno.

### Changed

- **`Unlock` now FAILS CLOSED when the kernel keyring is unavailable**, with no
  fallback and no opt-out (owner ruling 2026-08-31: *"we should fail closed, we
  dont support legacy kernels that are insecure"*). The alternative is the
  volume master key in memory this library cannot wipe, for an unbounded time,
  while the caller believes a guarantee that did not hold.

  **This is a behavior change for containers.** Measured 2026-08-31 with the
  exact syscall sequence the library uses: `add_key` works on the host
  unprivileged and under `--privileged` or `seccomp=unconfined`, and **fails
  under Docker's default seccomp profile even with `--cap-add SYS_ADMIN`**. The
  constraint is seccomp, not capabilities — which is the opposite of the usual
  intuition, and means the least-privilege choice for dm-crypt
  (`--cap-add SYS_ADMIN` rather than `--privileged`) needs a seccomp change too.
  The fix is a narrow custom profile allowing those three syscalls, not
  `seccomp=unconfined`. See the README's *Kernel keyring requirement*.

- **A pre-existing keyring entry now fails the unlock** (`ErrKeyringEntryExists`)
  instead of being silently overwritten. `add_key` updates a key of the same
  type and description in place rather than failing, so a leftover from a
  crashed process — or an entry planted by another process of the same uid —
  would otherwise be adopted or clobbered without a word. The description is
  deterministic and derived from the volume's identity precisely so that a
  collision is a real signal rather than routine.

- **Releasing a keyring entry is verified, not trusted.** `revoke` and `unlink`
  returning `nil` is a claim; the ring is searched again and the answer has to
  be "not there". An entry that is still resolvable — or whose absence cannot be
  confirmed — is reported as `ErrKeyringKeyNotReleased` rather than swallowed as
  cleanup noise, the same conservative direction `ErrMappingStillLive` takes for
  a plaintext mapping that cannot be inspected.

## [0.1.9-alpha] - 2026-08-31

## [0.1.8-alpha] - 2026-08-30

### Fixed

- **LUKS2 conformance, write side (#28).** A container this library wrote was
  refused outright by cryptsetup — `cryptsetup isLuks` exited 1 and `luksDump`
  reported "is not a valid LUKS device", so `luksDump`, `luksHeaderBackup`,
  `luksChangeKey` and `luksOpen` were all unavailable and a volume had **no
  recovery path**. Three defects, each measured against cryptsetup 2.7.0:
  - `tokens` was omitted from the JSON metadata when empty. LUKS2 requires the
    object to be PRESENT (`{}` when there are none); cryptsetup reported
    `JSON area "" is missing "tokens" (object) specification` and failed
    validation. `tokens` no longer carries `omitempty`, and every mandatory
    LUKS2 object is guaranteed non-nil before the metadata is encoded, so none
    of them can reach the disk as `null` either
  - `config.keyslots_size` stored the keyslots area's END OFFSET instead of its
    SIZE. cryptsetup reads it as a size and rejected the header with
    `keyslots_size is too large 16777216 (bytes). Data offset: 16777216,
    keyslots offset: 32768`. The correct value for this library's geometry is
    16744448. `AddKey` carried the same defect and additionally SHRANK the
    reserved area to the end of the slot it had just added; it now leaves the
    field alone
  - the secondary header at offset 0x4000 carried the PRIMARY magic
    (`LUKS\xba\xbe`) where LUKS2 requires `SKUL\xba\xbe` (#64). Measured: this
    alone does not stop cryptsetup from opening a container whose primary
    header is intact, but it destroys the backup — with the primary header
    destroyed, a correct secondary still opens the volume and a
    primary-magic secondary is "not a valid LUKS device"
- **LUKS2 conformance, read side (#73).** `verifyMasterKey` derived the digest
  to a hardcoded 32 bytes, so a cryptsetup-written `--hash sha512` volume —
  which stores a 64-byte digest — returned "incorrect passphrase" FOR THE
  CORRECT PASSPHRASE. The verifier now derives to the length ACTUALLY STORED in
  the header, which is what cryptsetup does. Containers written by earlier
  versions of this library (32-byte digest labeled `sha512`) therefore keep
  opening. Which lengths are derived to is a **whitelist**, not a range: the
  length the digest's declared hash implies, plus a single 32-byte carve-out for
  those older containers. A crafted header therefore cannot drive a degenerate
  or unbounded derivation, and a 16-byte digest labeled `sha512` — which nothing
  legitimate writes — is refused rather than tolerated
- **Digest scanning no longer depends on map iteration order (#58).**
  `verifyMasterKey` returned on the first digest whose derivation or decode
  errored instead of trying the next. Under `GODEBUG=fips140=only`, where
  `DeriveKey` refuses an argon2 KDF, whether a volume opened depended on which
  digest Go's randomized map iteration happened to visit first. Every digest is
  now tried, and one indistinguishable failure is returned once the set is
  exhausted
- **The second header copy could be written on top of the first.**
  `writeHeaderInternal` sized the header area from the metadata
  (`nextPowerOf2(len(jsonData)+1)`, floored at 12288) while writing the backup
  copy at a hardcoded 0x4000. MEASURED: a keyslot costs 514 bytes of indented
  JSON, so at **15 keyslots** — well inside the 32 LUKS2 permits, and reachable
  with a single moderately sized token — the JSON passes 8192, the area grows to
  20480, and the backup lands *inside* the primary and overwrites its own JSON
  tail. The result could not be read back by this library either
  (`header checksum mismatch`), and 4096+16384 = 20480 is not a power of two, so
  it was not a legal LUKS2 metadata size to begin with.
  The area is now taken as **fixed by the container** and metadata that does not
  fit is refused with the new `ErrMetadataTooLarge`. It is deliberately not
  grown: the keyslots begin at 2 × area and the data segment after them, both
  already fixed on disk, so enlarging the area would move the second copy onto
  the keyslot key material at 0x8000 and destroy every key on the device. The
  secondary offset is now derived from the area for both the write and
  `ReadSecondaryHeader`, and `config.json_size` is written from the same area
  instead of a hardcoded constant
- **The documented recovery flow corrupted the container it was repairing.**
  `ReadSecondaryHeader` returns a *secondary* header — `SKUL` magic, nonzero
  `hdr_offset` — and writing it back, which is how its own documentation said to
  repair a damaged primary, wrote those secondary-only fields at offset zero.
  MEASURED: `SKUL` ended up at both 0 and 0x4000, leaving no valid primary, and
  the volume no longer opened. The corruption was **asymmetric** — cryptsetup
  shrugs it off (`isLuks` still exits 0; it silently falls back to the intact
  secondary) while this library, whose reader looks only at offset 0, could not
  open the container at all.
  Root cause was an asymmetry in the writer: it stamped the *backup* copy's
  magic and offset itself but took the *primary*'s from whatever the caller
  passed, because the only place setting `LUKS2Magic` was `CreateBinaryHeader`
  on the format path. `writeHeaderInternal` now owns both copies' identities —
  the writer decides what each copy *is*, the caller supplies only content
- **`ReadSecondaryHeader` could not recover a container with a non-default
  metadata area.** It fell back to a hardcoded 0x4000 when the primary header
  was unreadable — which is the only situation the second copy exists for — so
  recovery was impossible for exactly the larger-metadata-area containers this
  release taught the reader to accept. It now probes the nine legal area sizes
  (16 KiB…4 MiB, powers of two), accepting a candidate only when its secondary
  magic, recorded `hdr_offset`, header size and checksum all validate. A
  secondary copy is additionally required to record a header size equal to its
  own offset, since the second copy begins where the first one ends
- **`AddKey` did not respect the container's declared keyslots area.**
  `calculateNextKeyslotOffset` started from a hardcoded 0x8000 — right only for
  a 16 KiB metadata area — and no path bounded a new keyslot against
  `config.keyslots_size` at all. On a conformant container whose data offset
  sits past its keyslots area, keyslots were placed in the gap between the two:
  MEASURED on a cryptsetup container with a 1 MiB keyslots area ending at
  1114112 and data at 4194304, **12 keyslots were written outside the declared
  area**, out to the data segment. The keyslots area is now read from the
  header (start = 2 × metadata area, length = `config.keyslots_size`) and a new
  keyslot must fit inside it as well as before every data segment; the new
  `ErrKeyslotsAreaFull` reports which boundary was hit
- **`readHeaderCopy` no longer trusts `hdr.HeaderOffset` over the offset it was
  told to read.** The field is attacker-controlled and the caller already knows
  where it read the copy from; the downstream checksum and JSON reads now take
  the offset as a parameter, and the field is required to agree with it. Without
  this, a header read at 0x4000 could be paired with the JSON at 0
- **`hdr.HeaderOffset` is bounded (#63).** The sibling of the `HeaderSize`
  field bounded in #65 was converted for overflow but never range-checked,
  despite feeding every header-area read. It is now accepted only as 0 or a
  16 KiB-aligned offset up to `LUKS2HeaderMaxOffset`

### Added

- `ReadSecondaryHeader` reads and validates the second header copy, so the
  spec-correct backup this library now writes is one it can also read (#64)
- `RestorePrimaryHeader` rebuilds a damaged primary header from the secondary
  copy under a single lock, making the documented recovery flow a real
  operation instead of a sequence the caller has to assemble correctly
- `LUKS2SecondaryMagic`, `LUKS2PrimaryHeaderOffset` and
  `LUKS2SecondaryHeaderOffset` constants
- `ErrMasterKeyVerification` typed error, returned once no digest in a header
  verifies a candidate master key
- `ErrMetadataTooLarge` typed error, returned when JSON metadata does not fit
  the container's fixed header area
- `ErrKeyslotsAreaFull` typed error, returned when a new keyslot would fall
  outside the container's declared keyslots area or past its data segment
- **Bidirectional cryptsetup conformance suite** (`pkg/luks2/conformance_test.go`).
  It asserts against cryptsetup rather than against this library's own output —
  a round trip through `Format` and `Unlock` agrees with itself whether or not
  either agrees with LUKS2, which is how #28 and #73 survived a green suite. It
  covers both directions, header mutation via `AddKey`/`RemoveToken`, recovery
  from the secondary header, a 16-keyslot header past the size at which the old
  writer corrupted itself, and the pre-fix 32-byte-digest container. It runs
  unprivileged on file images and skips LOUDLY when cryptsetup is absent

### Changed

- FIPS CI gate now runs with `GODEBUG=fips140=only` instead of `fips140=on`, so
  non-approved cryptography fails the gate instead of being merely permitted
- `IsFIPSCompliantKDF("pbkdf2-sha1")` now returns `false`. The Go Cryptographic
  Module permits PBKDF2 only with SHA-2/SHA-3, so the previous `true` was wrong
- PBKDF2-HMAC-SHA1 is refused with the new `ErrFIPSNotApproved` while the
  process runs in FIPS 140-3 mode, instead of panicking inside
  `golang.org/x/crypto/pbkdf2` under `fips140=only`. It remains available
  outside FIPS mode for LUKS headers written by older cryptsetup releases
- **Breaking in FIPS mode:** `DeriveKey` and `CreateKDF` now refuse `argon2i`
  and `argon2id` with `ErrFIPSNotApproved` while the process runs in FIPS 140-3
  mode, including `CreateKDF`'s empty-`KDFType` default. Argon2 is pure Go, so
  `GODEBUG=fips140=only` cannot reject it; a FIPS-mode process would otherwise
  derive volume keys with a non-approved KDF. A FIPS caller must now select an
  approved KDF explicitly. Outside FIPS mode Argon2id remains the default and
  behavior is unchanged

### Added

- `ErrFIPSNotApproved` typed error for algorithms the Go Cryptographic Module
  does not approve
- `docs/FIPS.md` recording the FIPS policy, the approved KDF table, and the
  cited PBKDF2-HMAC-SHA1 legacy-header exemption

## [0.1.5-alpha] - 2026-02-03

### Added

- Wipe standards: `--standard nist|dod3|dod7` (NIST SP 800-88, DoD 5220.22-M)
- Verification pass: `--verify` / `--no-verify` flags
- `WipePattern`, `WipeStandard` types and `WipeProgressFunc` callback

### Changed

- Zero/negative passes default to 1 instead of error

## [0.1.4-alpha] - 2025-12-31

### Added

- **CLI Wipe Command Options**
  - `--full` - Wipe entire device instead of headers only
  - `--passes N` - Multi-pass overwrite support
  - `--random` - Use random data instead of zeros
  - `--trim` - Issue TRIM/DISCARD after wipe for SSDs

- **Unit Tests**
  - Added 9 new CLI unit tests for wipe command options

### Changed

- **Documentation Overhaul**
  - Complete README rewrite with concise, accurate API documentation
  - Added Recovery Key API documentation (GenerateRecoveryKey, AddRecoveryKey, etc.)
  - Added Filesystem utilities (CheckFilesystem, GetFilesystemInfo, SupportedFilesystems)
  - Added Header validation functions (IsLUKS, IsLUKS2, WriteHeader)
  - Updated CLI wipe documentation with new options

## [0.1.3-alpha] - 2025-12-31

### Added

- **Cryptsetup Compatibility**
  - `IsLUKS()` - Check if device contains any LUKS header (v1 or v2)
  - `IsLUKS2()` - Check if device contains a LUKS2 header specifically
  - `TestKey()` - Verify passphrase without unlocking (like `cryptsetup luksOpen --test-passphrase`)
  - `KillSlot()` - Remove keyslot using any valid passphrase (like `cryptsetup luksKillSlot`)

- **LUKS2 Header Constants** (matching cryptsetup defaults)
  - `LUKS2HeaderMinSize`, `LUKS2HeaderDefaultSize`, `LUKS2MaxKeyslotsSize`, `LUKS2MaxKeyslots`
  - `LUKS2DefaultKeyslotsSize` - 16 MiB default keyslots area

- **Device Handling Improvements**
  - Symlink resolution for device paths (dm-crypt requires actual block device)
  - `waitForDeviceReady()` for udev compatibility in containerized environments
  - Keyslot overlap protection when adding keys

### Changed

- Format now uses cryptsetup-compatible 16 MiB default metadata area
- Removed all debug `fmt.Fprintf` statements from library code
- Library returns errors instead of logging; added `SaveError` field to `RecoveryKey`

### Fixed

- Fixed gosec G115 integer overflow warnings in device-mapper code
- Fixed gosec G301 directory permissions (0755 → 0750)
- Fixed `TestSmallVolumeMinimumSize` minimum volume size (16MB → 32MB)

## [0.1.2-alpha] - 2025-12-22

### Added

- **Token Management API**
  - New `Token` type with support for FIDO2 and TPM2 tokens
  - Functions: `GetToken`, `ListTokens`, `ImportToken`, `ImportTokenJSON`, `ExportToken`, `RemoveToken`, `FindFreeTokenSlot`, `TokenExists`, `CountTokens`
  - Full LUKS2 token slot management (slots 0-31)

- **DevContainer Support**
  - Added `.devcontainer/` configuration for VS Code development
  - Privileged container setup for LUKS operations during development
  - Pre-configured Go tools (gopls, delve, golangci-lint, gosec)

- **CLI Testability Refactoring**
  - Dependency injection interfaces: `LuksOperations`, `Terminal`, `FileSystem`
  - Comprehensive CLI unit tests with mock implementations
  - Separated CLI logic from main.go for better testability

- **Integration Test Reorganization**
  - New `test/integration/pkg/` for package-level integration tests
  - New `test/integration/cli/` for CLI integration tests
  - Common test helpers in `test/integration/pkg/common_test.go`

- **Additional Unit Tests**
  - `pkg/luks2/format_test.go` - encrypt/decrypt key material tests
  - `pkg/luks2/mount_test.go` - mount operation tests
  - `pkg/luks2/unlock_test.go` - unlock helper function tests

### Changed

- Updated Makefile with new targets: `test-cli`, `integration-test-pkg`, `integration-test-cli`, `devcontainer`
- Improved CI workflow to test both `pkg/luks2` and `cmd/luks2` with merged coverage
- Updated `Dockerfile.integration` to run CLI and package integration tests separately
- Coverage threshold set to 90%

## [0.1.1-alpha] - 2025-12-17

### Added

- **FIPS-Compatible KDF Support**
  - Added KDF type constants (`KDFTypePBKDF2`, `KDFTypePBKDF2SHA256`, etc.)
  - Added `IsFIPSCompliantKDF()` function to check FIPS compliance
  - Added support for SHA-1, SHA-384 hash algorithms in PBKDF2
  - PBKDF2 with SHA-1/SHA-256/SHA-384/SHA-512 are FIPS-approved

- **SSD TRIM/DISCARD Support**
  - Added `Trim` option to `WipeOptions` for SSD optimization
  - Implemented `BLKDISCARD` ioctl for secure SSD erasure
  - TRIM is issued after data wipe for additional security on SSDs

- **Keyslot Hash Algorithm Selection**
  - Added `Hash` field to `AddKeyOptions` for PBKDF2 hash selection
  - Allows specifying hash algorithm when adding new keyslots

- **Comprehensive Test Coverage**
  - Added extensive unit tests for KDF functions
  - Added unit and integration tests for wipe operations
  - Improved test coverage for edge cases and error handling

### Changed

- Improved device size detection for block devices in wipe operations
- Added input validation for size parameters in wipe functions
- Added defense-in-depth buffer clearing in wipe operations
- Refactored hash function selection into reusable `getPBKDF2HashFunc()`

### Fixed

- Fixed potential issues with negative size values in wipe operations

## [0.1.0-alpha] - 2025-12-06

### Added

- **LUKS2 Volume Management**
  - Format new LUKS2 encrypted volumes
  - Unlock/lock volumes using device-mapper
  - Read and validate LUKS2 headers
  - Support for volume labels and UUIDs

- **Key Derivation Functions**
  - Argon2id (recommended, memory-hard)
  - Argon2i (side-channel resistant)
  - PBKDF2-SHA256/SHA512

- **Cryptography**
  - AES-256-XTS encryption
  - Anti-forensic information splitting (4000 stripes)
  - Secure random key generation
  - Constant-time key comparison

- **Filesystem Operations**
  - Create ext2, ext3, ext4 filesystems on unlocked volumes
  - Mount and unmount encrypted volumes
  - Loop device management for file-based volumes

- **Security Features**
  - Memory clearing of sensitive data
  - Input validation and path traversal protection
  - File locking for concurrent access protection
  - Passphrase length validation (8-512 bytes)

- **Secure Wipe**
  - Header-only wipe (fast)
  - Full device wipe with configurable passes
  - Individual keyslot wiping

- **CLI Tool (`luks2`)**
  - `create` - Create new encrypted volumes (block devices or files)
  - `open` - Unlock volumes
  - `close` - Lock volumes
  - `mount` - Mount unlocked volumes
  - `unmount` - Unmount volumes
  - `info` - Display volume information
  - `wipe` - Securely destroy volumes

- **Typed Error Handling**
  - Sentinel errors for common conditions
  - Typed errors (DeviceError, VolumeError, KeyslotError, CryptoError)
  - Full support for `errors.Is()` and `errors.As()`

- **Compatibility**
  - Full LUKS2 specification compliance
  - Interoperable with cryptsetup
  - Tested with cryptsetup 2.3+, Linux kernel 5.x+

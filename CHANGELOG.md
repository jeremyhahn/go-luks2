# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **Go toolchain 1.27.4 for GO-2026-6859, net/http (#441).** govulncheck
  reports GO-2026-6859 in the go1.27.3 standard library, fixed in go1.27.4
  (2026-11-02). Every Go version pin moves to 1.27.4: the `go` directive in
  `go.mod`, `GO_VERSION` in the release workflow, the CLI image `golang:` tag,
  the devcontainer `golang:` image tag and digest, and the README build
  requirement.

### Changed

- **In FIPS mode a SHA-1 PBKDF2 is refused as not approved.**
  `KDFParams.Validate` now judges the PBKDF2 hash: under FIPS 140-3 mode a
  PBKDF2 KDF naming SHA-1 fails with an error matching `ErrFIPSNotApproved`.
  The write paths that refuse a SHA-1 PBKDF2 (`Format`, `AddKeyslot`,
  `ChangeKeyslot`, `Enroll`) return an error matching `ErrFIPSNotApproved` in
  FIPS mode, where they returned `ErrInvalidArgument`. Outside FIPS mode
  nothing changes: SHA-1 creation is still refused with `ErrInvalidArgument`.
- **`MigrateToFIPS` refuses Argon2 parameters instead of dropping them.** A
  `MigrateParams.KDF` naming Argon2 (`KDFArgon2id`, `KDFArgon2i`, or a
  non-zero `Time`, `MemoryKiB` or `Parallel`) was silently ignored and a
  PBKDF2 keyslot written. It is now refused before anything is written, as a
  `*FIPSMigrationError` at stage `precondition` matching both
  `ErrFIPSMigration` and `ErrFIPSNotApproved` and naming the field, and the
  volume is left unchanged. A PBKDF2 `KDF` migrates as before.
- **A short PBKDF2 salt in strict FIPS mode asks for an import.** Under
  `GODEBUG=fips140=only`, unlocking a volume whose PBKDF2 keyslot or digest has
  a salt under 128 bits failed with `ErrInvalidHeader`, as if the header were
  damaged. It now fails with `*FIPSImportRequiredError`, like any other keyslot
  refused only by FIPS; the open is still refused, and `MigrateToFIPS` imports
  the volume. A keyslot one of whose attesting digests is malformed (a value
  that is not base64, a length no hash gives) still fails with
  `ErrInvalidHeader`, beside a short-salt digest or not, and also when the
  keyslot's own KDF is refused (Argon2 under the FIPS policy, a short PBKDF2
  salt under strict mode), where it failed with `ErrFIPSNotApproved` or
  `ErrInvalidArgument`; `MigrateToFIPS`
  refuses that volume at the plan stage with `ErrInvalidHeader`, where it
  returned the not-approved-digest refusal.
- **`MigrateToFIPS` no longer keeps a malformed digest that looks approved.**
  A PBKDF2-SHA256 digest with a full-length salt but a value no hash gives
  (48 bytes, say) passed the approval check, so planning skipped it and the
  migration wrote, reported `Complete` and kept the damage. Planning now
  screens every digest's structure first, and such a volume is refused at the
  plan stage with `ErrInvalidHeader`, writing nothing.
- **A malformed digest no keyslot consults is no longer called an import.**
  In FIPS mode, a volume refused only for non-approval but carrying a
  malformed digest that covers no tried keyslot, or binds no data segment,
  failed unlock with `*FIPSImportRequiredError`, though `MigrateToFIPS`
  refuses that volume at the plan stage. Unlock now fails with
  `ErrInvalidHeader`, as the import does.
- **A damaged Argon2 keyslot KDF is header damage under FIPS too.** In FIPS
  mode, unlocking a volume whose Argon2 keyslot declares a salt that is not
  base64 failed with an error matching `ErrFIPSNotApproved` and not
  `ErrInvalidHeader`, so the damage read as a policy refusal. The keyslot
  KDF's structure is now screened before the FIPS policy judges it, and unlock
  fails with `ErrInvalidHeader` in FIPS mode as outside it.

### Fixed

- **The `pkg/luks2` race run stays well inside its memory bound.** The
  migration crash-matrix tests built every torn 16 MiB header image up front
  and held it in each queued subtest, and their helpers read whole 64 MiB
  images to compare or hash them; under `-race` the peak crossed the Race
  job's container bound and the test binary was killed. Torn states are now
  built by the subtest that checks them, the helpers stream, and the
  whole-image tests share a fixed four-slot semaphore. No test, subtest or
  assertion changed.
- **An unsupported mandatory requirement is readable from `luks2.Error`.**
  Unlock, activation and every header write on a container declaring a
  mandatory requirement this library does not implement (such as
  `inline-hw-tags`) return a `*luks2.Error` whose `Kind` is
  `ErrUnsupportedRequirement` and whose `Detail` names the requirement and the
  container's mandatory set. A header write used to report it with Kind
  `ErrIO` and no Detail, and unlock's Detail did not name it. No named
  requirement type is exported. A requirement that stops `MigrateToFIPS`
  keeps the migration's Kind `ErrFIPSMigration`, with the requirement in
  `Detail` and `errors.Is(err, ErrUnsupportedRequirement)` still true. The
  same holds when `AddKeyslot`, `ChangeKeyslot` or `RemoveKeyslot` meets the
  requirement while repairing a damaged or older header copy: that used to
  report Kind `ErrIO` with Detail "failed to read header", and now reports
  the requirement, with `errors.Is(err, ErrIO)` still true underneath.

- **A concurrent build of the same toolchain image tag no longer fails the
  job.** Two jobs on one Docker daemon could build the content-addressed
  toolchain tag at once, and BuildKit refused the slower export with `image
  "…": already exists`. The tag is a hash of the image's inputs, so the image
  the faster job left is the one the slower job would have built.
  `make docker-build-toolchain` and `make docker-build-integration` now pass
  when the build fails with exactly that refusal of their own content tag and
  the tag resolves, and they print a line saying so. Every other build failure
  still fails, with the build's output and exit status. Before this change,
  `docker-build-integration` accepted any failed build whose tag resolved
  afterwards; it now needs the refusal too.

### Changed

- **golang.org/x/sys is v0.50.0, so every direct dependency is at its latest
  release again.** `make deps-check` reported v0.49.0 as behind the latest
  release. golang.org/x/crypto and golang.org/x/term still require v0.49.0;
  the module now selects v0.50.0 for all three.

## [1.0.3-alpha] - 2026-11-10

### Changed

- **go-luks2 requires go-enclave v0.11.1-alpha (#411).** The release adds the
  linux-secretmem backend (`enclave.NewSecretMemory`), `Sealed.OpenIn` and an
  arm-trustzone harness behind the `optee` tag, and changes no API go-luks2
  calls. Nothing changes for go-luks2 callers.

### Removed

- **The merge-on-green and batch workflows are gone.** Landing is the forge's
  native auto-merge on green, with the required checks set by a ruleset, so the
  self-merging workflow and the dispatch-only batch-runner workflow (fuzz, race,
  soak, benchmarks) are retired, with the strip-at-publish entries and tests
  that named them.

## [1.0.2-alpha] - 2026-11-07

The `v1.0.2-alpha` tag names the same commit as `v1.0.1-alpha`: it carries the
changes of the `[1.0.1-alpha]` section below and nothing else.

## [1.0.1-alpha] - 2026-10-28

### Fixed

- **A nil Volume or Key is refused with `ErrInvalidArgument` instead of
  panicking (#211).** `dmcrypt.Activate` checks both before it consults the
  device-mapper or the kernel keyring, so the refusal is the same as root and
  as an unprivileged user; before, root reached the nil Volume and the process
  died. `Volume.AddKeyslot`, `Volume.ChangeKeyslot` and `Volume.Enroll` refuse
  a nil Key, and a zero `Key{}` that holds no key, the same way. A caller
  that passes a value it got from `Open` and `Unlock` sees no change.

### Changed — BREAKING: credentials and keys are `enclave.ByteAccess`, from go-enclave v0.9.0-alpha

- **Credentials and keys are `enclave.ByteAccess`, and callers require go-enclave v0.9.0-alpha.** Every export that took or returned an `*enclave.MemoryEnclave` (`Format`, `Unlock`, `UnlockKeyslot`, `UnlockWithVolumeKey`, `AddKeyslot`, `ChangeKeyslot`, `MigrateToFIPS`, `ParseRecoveryKey`, `ValidatePassphrase`, `KeyProvider.Passphrase` and the `pkg/keyprovider` providers) now takes or returns go-enclave's `enclave.ByteAccess` interface. go-enclave moves from v0.8.0-rc.2 to v0.9.0-alpha. On the way, v0.8.0-rc.1 renamed `MemoryEnclave` to `Memory` with no deprecated aliases, and v0.9.0-alpha replaced `Memory` with interfaces: `NewMemory`, `NewMemoryCopy`, `NewMemorySized`, `Allocator.New`, `Allocator.NewSized` and `Sealed.Open` return `enclave.ByteAccess`, and `NewAllocator`, `NewAllocatorWithinRLimit` and `ProcessAllocator` return the `enclave.Allocator` interface. Callers must require go-enclave v0.9.0-alpha and follow its upgrading guide. Every handle that crosses the API, or that this library creates, is go-enclave locked memory: a handle that reports any other backend is now refused with `ErrNotLockedMemory`, whose chain carries a `*NotLockedMemoryError` naming the reported backend, before it is read, and the handle is not destroyed. The check reads the backend the handle reports; go-enclave has no unforgeable provenance check, so a handle that misreports its backend is outside the guarantee, like any caller that already holds the key. Key material is still borrowed only through `WithBytes`, and a refused allocation still fails the operation. A read-only copy is frozen through go-enclave's `Freezer` capability, and a handle without it fails the operation and is destroyed rather than being used writable.
- **Applications that embed the library must call `enclave.HardenProcess` from `main` (#211).** go-enclave v0.8.0-rc.1 no longer lowers `RLIMIT_CORE` when the package is imported. The plain heap copies the KDF, AES and hash code make, and the CLI's prompt buffer, are outside go-enclave's protected pages, so a process that can dump core can write them to a core file. Call `enclave.HardenProcess` from `main`, before handling a secret, and treat its error as fatal. This library's packages never call it, and importing them changes no process state.
- **The `luks2` CLI hardens itself before reading any credential (#211).** `internal/cli.Run` calls `enclave.HardenProcess` first (`RLIMIT_CORE` 0/0, and the process non-dumpable), and exits non-zero with a "cannot disable core dumps" error if that fails. There is no unhardened fallback. A non-dumpable process's `/proc/<pid>` entries are root-owned and a same-uid debugger cannot attach to it; programs it executes, such as cryptsetup, are unaffected.

- **LUKS2 On-Disk Format 1.1.4.** The pinned specification moves from 1.1.3 to 1.1.4 (LUKS2-docs commit `a81aa2fe`). A segment's optional `integrity.key_size` is validated as an integer and re-encoded exactly as read; an integrity segment is still refused for unlocking. The `inline-hw-tags` requirement is kept through every read and re-encode, and unlock, activation and header writes refuse it with `ErrUnsupportedRequirement` naming it.

- **`CI Gate` runs on the reserved `ci-gate` runners, and a label change no longer starts a CI run.** The gate job runs on its own 1-CPU slots, so it does not queue behind the jobs it waits for; it has no checkout and no action, only the step that reads each job's result. `.github/actionlint.yaml` (fleet template v5) lists the `ci-gate` label. `ci.yml` drops `labeled` from its `pull_request` types: the forge reports every label add and remove as `labeled`, so each review or task label started a run that cancelled the one in progress. `ci:full` is still read when a run starts, so a `ci:full` added to an open pull request takes effect on its next push or update-branch, or through `workflow_dispatch`.

- **Six feature designs list the alternatives they rejected (#319).** The
  `architecture.md` of `header`, `keyslots`, `recovery-keys`, `tokens`, `wipe`
  and `cryptsetup-interop` gains a "Rejected alternatives" section, each entry
  with its reason and the recorded decision it comes from, so a settled design
  is not relitigated.

- **`ROADMAP.md` names the `docs/<feature>/` folder behind every Now and Next item (#330).** Each item now links its issue, or the milestone for the `v1.0.0` cut, and carries the status the issue has on the tracker, so a reader can go from a roadmap line to the specification it delivers.

- `ValidatePassphrase` now reports a passphrase that is too short or too long
  as an `*Error` of kind `ErrInvalidCredential` with `Op` set to
  `ValidatePassphrase`, the same shape as its destroyed-enclave failure, which
  now carries the `Op` too. `errors.Is(err, ErrInvalidCredential)` holds as
  before (#334).

- **CI is split into a PR tier and a full tier behind one `CI Gate` (#341, #343).** Every pull request runs Lint, Security Scan, Build, Merged Tree and Unit Tests, now without `-race` (`make test-unit-norace`), still with the coverage, calibration, releasability and API-diff gates. FIPS, Integration Tests and Race (`make test-unit`, `-race`, with its `pkg/luks2` time budget) run on every push to `main`, on `workflow_dispatch`, and on a pull request labelled `ci:full`; the label is read when a run starts, so a `ci:full` added to an open pull request takes effect on its next push or update-branch, or through `workflow_dispatch`. `CI Gate` stays the single required check: it needs every job and reads each by name, tagged `pr` or `full`; a `full` job may be skipped only while the full tier does not run, and any other skip, failure or cancellation fails it. FIPS moved from `nightly.yml` into `ci.yml` unchanged and now runs on every push to `main` instead of once a night. `nightly.yml` has no schedule any more; it is dispatch-only and carries trivy.

- **The feature folders now hold the design content that was only in `docs/design/DESIGN.md` (#347).** The new sections are:
  - **Cancellation** (`docs/keyslots/architecture.md`, `docs/volumes/engineering.md`). A key derivation is never interrupted. `ctx` is checked before and after each derivation, between keyslots in a scan, between digest checks and before each PBKDF2 calibration probe, so a cancellation takes effect within one derivation.
  - **Portability** (`docs/volumes/architecture.md`). `pkg/luks2` and `pkg/keyprovider` build on Linux and darwin; `pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`, `pkg/wipe` and the CLI are Linux-only; Windows is out of scope.
  - **The `MigrateToFIPS` example**, moved from the user guide to `docs/fips/api.md`.
  - **A FIDO2 enrollment example** in `docs/tokens/api.md`.

  `docs/volumes/cli.md` now also states that `SIGINT` and `SIGTERM` cancel the running `luks2` command, that a write in progress stops at its next consistent step boundary, and that the command exits with the resulting error's status, 1 for a cancellation. Look for these topics in the feature folders, not in `docs/design/`.

- **Internal-only files are `export-ignore`, so `git archive` and a forge's tag tarball leave them out (#357).** The new `.gitattributes` export-ignores agent instruction files and tool state at any depth, the internal workflows `automerge.yml`, `code-review.yml`, `qwen-review.yml` and `batch.yml`, and `test/ci/workflows/batch_test.go`. The public workflows are `ci.yml`, `nightly.yml` and `release.yml`. `.dockerignore` excludes the same list, so a broad `COPY` does not bake those files into an image layer. The new `docs/release/public-releasability.md` lists the strip-at-publish set and what it does not cover: the Go module zip is clean only because the public tag's tree is the export, and pushing history publishes every file, because every commit contains them. To publish or mirror this repository, publish the release commit's archive export, not its history.

- **The public tree is the release commit's archive export, and `make releasability` in a published tree checks file rules only (#358).** The release tag on the development trunk points at a commit that still tracks the internal-only files. The public tree is that commit's export: every export-ignored path is removed, and every other tracked file is published byte-for-byte. The gate's pattern set and its tests are now stripped at publish too (export-ignored, and excluded by `.dockerignore`), because they contain the values the gate bans. A published tree therefore has no pattern set to scan with. There, `make releasability` checks the file rules, exits 0, and prints on every run that content was not scanned. A development tree that tracks a strip-at-publish file but has no pattern set fails instead of reporting clean. If you run the gate on the published tree, a clean result there does not mean the content was scanned.

### Added

- **A feature folder for loop devices (#315).** `docs/loop-devices/` holds the five files for `pkg/loop`: attaching a regular file as a block device, which you need in order to open a LUKS2 volume kept in an image file, and detaching it. It states the prerequisites: root and a kernel with loop support (`/dev/loop-control` exists), and in a container, access to `/dev/loop-control` and to the loop devices themselves.

- **The feature docs now cover the last undocumented `pkg/luks2` exports, and list the cryptsetup operations this library does not provide (#316).** `ErrClosed`, `ErrReadOnly`, `ValidatePassphrase`, `MinPassphraseLength`/`MaxPassphraseLength`, `(*FIPSMigrationError).MigrationStage` and `Token`'s JSON codec are documented, including when each one returns which error. The volumes and header architecture docs list resize, suspend/resume, KDF benchmark, LUKS1-to-LUKS2 convert, UUID/label changes and header backup to a file as not provided, each with its reason. Use cryptsetup for any of these.

- **Feature folders for dm-crypt activation, filesystems and the kernel keyring (#325).** `docs/dm-crypt-activation/`, `docs/filesystems/` and `docs/kernel-keyring/` each hold the five files (`architecture.md`, `engineering.md`, `cli.md`, `api.md`, `user.md`). They cover turning an unlocked volume into a `/dev/mapper/<name>` device and removing it, putting a filesystem on an unlocked volume and mounting and unmounting it, and how the key is handed to dm-crypt through the kernel keyring rather than written into the device-mapper table. `pkg/dmcrypt` and `pkg/filesystem` are now specified there, and `docs/volumes/engineering.md` links to them. Read these folders before you use `pkg/dmcrypt` or `pkg/filesystem`.

- **CI reviews a pull request labelled `code-review` and `task:ready` with
  Codex (#327).** `.github/workflows/code-review.yml` adopts the fleet template
  v4 verbatim: it posts the verdict as the `codex` user on the head commit,
  which `automerge.yml` waits for before it merges a `code-review` pull request.
  `.github/actionlint.yaml` (fleet template v3) lists the self-hosted runner
  labels, so `make lint` accepts `runs-on: codex` and still catches a
  misspelled label.

- **A unit-test gate now fails when an export of a `pkg/...` package is not named in any feature doc (#335).** `TestEveryPkgExportIsNamedInAFeatureDoc` (`apidump documented`) requires every exported constant, variable, function, type and method to appear, as a whole identifier in code, in a `docs/<feature>/*.md`. A method counts as `Type.Method`, or as `Method` in a doc that also names `Type`. Deliberate exceptions go in `test/tools/apidump/doc-exceptions.tsv`, one reason per row, and an exception that no longer applies fails too. The exports the gate found undocumented are now documented: the `pkg/dmcrypt` keyring error family and mapping-name limits, the `pkg/loop` detach states and sentinels, the `pkg/filesystem` types, params, errors and inspection calls, `keyprovider.SaltLength`/`SecretLength`, and the `Unwrap` behaviour of `HelperError`, `FIPSImportRequiredError`, `FIPSMigrationError` and `OrphanedKeyslotError`.

### Removed

- **`docs/design/` is gone (#349).** `docs/design/DESIGN.md` and `docs/design/DECISIONS.md` are deleted, and no doc, Makefile comment or code comment cites them any more. The feature folders are the documentation: the `docs/README.md` index lists all of them, including `dm-crypt-activation`, `kernel-keyring`, `loop-devices` and `filesystems`. It also names the two checks that hold the exported surface, `make api-diff` and `TestEveryPkgExportIsNamedInAFeatureDoc`. The `api.md` files now say directly that go-luks2 is an embedded Go library with no REST, gRPC, QUIC, MCP or Unix-socket transport. Replace any link into `docs/design/` with a link to the feature folder that covers that topic.

### Fixed

- **The FIPS and volumes docs name code that exists and give the real keyring activation order (#317).** `docs/fips/architecture.md` named a refusal function, `requireFIPSApprovedKDF`, that the API redesign removed. It now names `fips.Mode.RequireKDF`, which refuses Argon2 in FIPS mode with `ErrFIPSNotApproved`, and lists every place it is called: `KDFParams.validateWith` (behind `KDFParams.Validate`, `FormatParams.Validate` and the `Volume` methods that take a `KDFParams`), `createKDF`, `screenKDFParameters` and `kdf.Deriver`. `docs/volumes/architecture.md` had the activation steps in the wrong order. The order is: the dm target is created with no table, the key is added to the session keyring, the table naming the key is loaded and the target resumed, and the key is then revoked, unlinked and checked gone whether or not the load succeeded. If the key cannot be confirmed gone, activation fails with `dmcrypt.ErrKeyringKeyNotReleased` and the target is rolled back. Stale paths and references in `docs/volumes/` are corrected too. If you used the old docs to reason about when the key is in the keyring, reread them: it is there only while the table loads.

- **`luks2 open` and `luks2 close` now exit 5, not 1, when the mapping already exists or is busy (#322).** `dmcrypt.ErrActive` and `dmcrypt.ErrBusy` were missing from the exit-status table, so a script testing for cryptsetup(8)'s "exists or busy" status never saw it. Scripts that treated exit 1 as the signal for these two cases must now check for 5.

- **The blocked-keyring remedy names `dmcrypt.CheckKeyring` (#324).** It told
  operators to call `CheckKeyringAvailable` at startup, a function removed with
  the old activation API (#268); the startup preflight is
  `dmcrypt.CheckKeyring`.

- `make releasability` passes again: the internal review workflows
  `code-review.yml` is tracked on main and stripped from the public release
  (as `qwen-review.yml` will be when it returns through its own PR), and
  `.github/actionlint.yaml` names roles instead of lab hosts and addresses
  (#336).

### Security

- **The toolchain is Go 1.27.3.** It carries the standard-library fix for
  advisory GO-2026-6809 (`crypto/x509`), so `govulncheck` reports nothing
  against this module. Consumers building with an older Go release should move
  to 1.27.3 to get the same fix in their binaries.
- **golang.org/x/crypto is v0.58.0, golang.org/x/sys v0.49.0 and golang.org/x/term v0.47.0, so every direct dependency is at its latest release again.** Nothing this module uses changes behaviour: argon2 and blake2b gain only a loong64 vector implementation, and xts, x/term and the x/sys/unix calls used here are unchanged.
- **github.com/jeremyhahn/go-enclave is v0.10.0-alpha, its latest release.** Callers now resolve at least v0.10.0-alpha. Its API and behaviour are unchanged from v0.9.0-alpha: the release moves its toolchain to Go 1.27.3, which this module already requires, and changes only its own build, CI and test tooling. Key custody here is unchanged.

## [1.0.0-rc.4] - 2026-10-09

### Changed — BREAKING: `make release` cuts only final releases

- **One release target per kind (#291+).** `make release-alpha
  VERSION=vX.Y.Z-alpha` cuts an alpha, `make release-candidate
  VERSION=vX.Y.Z-rc.N` cuts a release candidate and `make release
  VERSION=vX.Y.Z` cuts a final release, and each refuses the other two kinds
  before it writes anything, naming the target that cuts the kind. Before this
  change `make release` accepted all three and `release-alpha` was an alias of
  it, so `make release VERSION=vX.Y.Z-rc.N` (how rc.3 was cut) and
  `make release-alpha VERSION=vX.Y.Z` now fail: use `make release-candidate`
  and `make release`. `VERSION` is stated explicitly for the candidate and the final
  release; `release-alpha` derives it when omitted (next entry). The guards are one recipe shared by the three targets, so they cannot drift.

### Added

- **`ROADMAP.md` states the project's mission, current milestone and queue (#295).** Documentation
  only; no behaviour changes.

### Changed

- **`make lint` runs actionlint over `.github/workflows/`, and the trivy targets
  fail when trivy is missing (#296).** Workflow syntax, expressions and runner
  labels are now checked locally before CI parses them; `.github/actionlint.yaml`
  is read when it exists. A missing actionlint fails `make lint` with the
  `go install` line for the pinned version. `trivy-fs`, `trivy-sarif` and
  `trivy-misconfig` no longer skip or fail obscurely without trivy: they exit
  non-zero and point at `make trivy-install`, so `make security` can no longer
  pass on a scan that never ran. Scanners, severities and exit codes are
  unchanged when trivy is present.

### Security

- **The toolchain is Go 1.27.2 (#297).** It carries the standard-library fixes
  for advisories GO-2026-6603 through GO-2026-6617, so `govulncheck` reports
  nothing against this module. Consumers building with an older Go release
  should move to 1.27.2 to get the same fixes in their binaries.

### Changed

- **`make release-alpha` derives the next alpha when `VERSION` is omitted.** It
  takes the highest `vX.Y.Z-alpha` tag, in the checkout and on the release remote,
  adds 1 to PATCH, prints the version and then runs every existing guard on it
  (main only, the remote, the duplicate tag, a clean tree, the changelog checks,
  the `VERSION` commit, the signed tag and the atomic push). It refuses, and prints
  the explicit form, when no alpha tag exists, when the remote cannot be listed, or
  when an existing tag of any kind (an rc or a final release outranks the alpha of
  the same `X.Y.Z`) is at or above the result. `make release-alpha
  VERSION=vX.Y.Z-alpha` stays valid for a hand-picked MINOR bump;
  `release-candidate` and `release` still require `VERSION`. This follows the
  company release-versioning standard.

## [1.0.0-rc.3] - 2026-10-08

### Added

- **`--pbkdf argon2i` is accepted (#211).** `create`, `addkey`, `changekey`
  and `recovery add` take all three values cryptsetup's `--pbkdf` does:
  `argon2id`, `argon2i` and `pbkdf2`, so a script written for cryptsetup runs
  unchanged. `--pbkdf-memory` and `--pbkdf-parallel` apply to both Argon2
  variants. Argon2 of either kind is still refused in FIPS 140-3 mode.

### Changed — BREAKING: `Priority` zero value is `PriorityDefault`

- **`PriorityIgnore` can now be requested, and the zero `Priority` means
  "default" (#211).** `PriorityDefault` is the new zero value of `Priority`.
  It makes a new keyslot normal and leaves a changed keyslot's priority as it
  was. `PriorityIgnore`, `PriorityNormal` and `PriorityPrefer` are now 1/2/3,
  the LUKS2 on-disk value plus one, and each is written when it is asked for.
  Before this change an unset priority and an explicit ignore were the same
  value, so there was no way to create an ignored keyslot. Code that converts
  a `Priority` to or from the LUKS2 integer must add or subtract one. An
  undeclared `Priority` is refused with `ErrInvalidArgument`.

### Added

- **`luks2 addkey` and `luks2 changekey` take the shared KDF options (#287).**
  `--pbkdf`, `--hash`, `--iter-time`, `--pbkdf-force-iterations`,
  `--pbkdf-memory` and `--pbkdf-parallel` work on `create`, `recovery add`,
  `addkey` and `changekey` alike, named as cryptsetup names them. They are
  checked before the passphrase prompt; an option that does not apply to the
  chosen KDF is refused rather than ignored. With none given, the library's
  default or inherited cost applies as before.

### Changed: `ChangeKeyslot` and `luks2 changekey` honor KDF options

- **An explicit KDF re-costs the changed keyslot.** `(*Volume).ChangeKeyslot`
  with a non-zero `KeyslotParams.KDF` now writes that KDF, validated and
  resolved exactly as `AddKeyslot` does (Argon2 is refused in FIPS mode).
  `luks2 changekey --pbkdf`, `--hash`, `--iter-time`,
  `--pbkdf-force-iterations`, `--pbkdf-memory` and `--pbkdf-parallel` now
  take effect, as they do for cryptsetup's luksChangeKey. Before this change
  they were accepted and ignored. A zero `KDF` still keeps the keyslot's
  existing type and cost.

### Changed — BREAKING: `MigrateToFIPS` errors are classified at their source

- **A migration refusal is now an `*errs.Error` whose `Kind` is the refusal's own
  sentinel, and the text of every migration error changed (#287).**
  `MigrateToFIPS` still returns a `*FIPSMigrationError` under the package's
  `*errs.Error` with `Kind` `ErrFIPSMigration`, so `errors.Is(err,
  ErrFIPSMigration)` holds as before, and the refusal's sentinel and the failure
  behind it are each reachable with `errors.Is` and `errors.As`. The message no
  longer repeats the device or the sentinel name, which the `*errs.Error` head
  already carries: it reads `at <stage>: <cause>; <state>`. Code that matched
  the old text, or read the `Kind` of the inner refusal, must use `errors.Is`.

### Removed — BREAKING: `luks2 addkey --kdf` is gone

- **`addkey` takes the same KDF options as `create` (#287).** The combined
  `--kdf pbkdf2-sha512` spelling is removed, with no replacement flag of that
  name. Use `--pbkdf`, `--hash`, `--iter-time`, `--pbkdf-force-iterations`,
  `--pbkdf-memory` and `--pbkdf-parallel`. A script that passed `--kdf` now
  fails with a usage error instead of being silently accepted.

### Fixed

- **`luks2 header show` labels the copy it prints (#289).** When the primary
  header is damaged or older, `show` prints the secondary copy; it used to
  label it `Primary` at offset 0. It now prints `Secondary header:` with the
  secondary's offset and says on stderr that the secondary is shown.

### Added

- **`(*luks2.Header).Offset()` (#289)** reports which copy a `Header` was read
  from: 0 for the primary, the header area size for the secondary.

### Security

- **A key helper must be a file only root or the caller could have written
  (#289).** `keyprovider.Command` (and the FIDO2 helpers it runs) now applies
  the trusted-executable checks every system tool gets before it runs the
  helper: a regular executable file owned by root or the calling user, not
  group- or world-writable, reached only through directories that are the same
  or sticky and through symlinks owned by root or the caller. A helper that
  fails them is refused with `ErrHelperFailed` and is not run. Install helpers
  where only root can replace them.
- **A helper or system tool runs from the file that was checked (#289).** The
  path is walked from `/` one descriptor at a time, so every directory and
  symlink it passes through is judged, including those a symlink later leads
  away from, and the program is executed from the checked descriptor rather
  than reopened by path. Running a key helper now needs Linux with `/proc`
  mounted; elsewhere it is refused.

### Added

- **`luks2 isluks -v`/`--verbose` (#289)** prints the reason a device is not
  a LUKS (or, with `--luks2`, LUKS2) device on stderr, as `cryptsetup isLuks
  -v` does. The exit status is unchanged.

### Changed

- **BREAKING: `Unlock` honours keyslot priority (#289).** The scan tries every
  `prefer` keyslot before any `normal` one and no longer tries an `ignore`
  keyslot at all, as cryptsetup does when no keyslot is named. A passphrase
  that opens only an `ignore` keyslot now fails `Unlock` (and `luks2 open`)
  with `ErrWrongKey`, or with `ErrNoKeyslots` when every bound keyslot is
  `ignore`; `UnlockKeyslot` still opens it by number. `Key.Keyslot()` reports
  a `prefer` keyslot when one opens.

### Fixed

- **`(*loop.Device).Detach` no longer detaches a loop device that was
  reassigned in between (#289).** It checks, on the descriptor it clears,
  that the device is still backed by the file recorded when the `Device` was
  obtained, and refuses with the new `loop.ErrDeviceReassigned` otherwise, or
  with an I/O error when nothing is attached any more. A `Device` from
  `Lookup` is held to the file attached when it was looked up.

### Fixed

- **`luks2 recovery verify` help states the exit status it uses (#289).** The
  help said a key that does not open the volume exits 1; it exits 2, the
  wrong-passphrase status, as documented. The `does NOT open` line is now
  printed only when the key was tried and refused, not for a failure that
  never reached it.

### Fixed

- **BREAKING: a failed recovery-key write is an I/O error, not a memory one
  (#289).** `(*RecoveryKey).WriteTo` reported its writer's failure as
  `ErrProtectedMemory`; it now returns `ErrIO` wrapping the writer's error.
  `luks2 recovery generate`/`add` exit 1 instead of 3 when the key cannot be
  written to stdout or the key file.

### Security

- **Activation re-verifies the key against the header it maps (#289).**
  `(*Volume).Target`, and so `dmcrypt.Activate`, used to re-read the header
  but check only the key's size, so a header rewritten between `Unlock` and
  activation, or a key from another volume, was mapped anyway. The key is now
  verified against the re-read header's digest for the mapped segment, and a
  key it does not verify is refused with `ErrWrongKey`.

### Fixed

- **`UnlockWithProvider` tries a token's keyslots by priority (#289).** The
  keyslots the provider's token names are tried `prefer` first, then `normal`,
  then `ignore`, each group in the token's order, as cryptsetup does for a
  token named with `--token-id`. A `normal` keyslot listed first no longer
  wins over a `prefer` one.

### Fixed

- **`luks2 wipe`'s header-only warning no longer says a header backup stops
  working (#289).** A backup taken with `cryptsetup luksHeaderBackup` holds
  the keyslots, and the data is left in place, so restoring it opens the
  volume again. The warning now says so and points to `--full`.

## [1.0.0-rc.2] - 2026-10-08

### Changed — BREAKING: go-enclave v0.7.0-alpha → v0.8.0-alpha (#285)

- **go-enclave v0.7.0-alpha → v0.8.0-alpha (#285).** Go resolves one
  go-enclave per build, and every consumer moves to the latest so it carries
  the hardening: a zero-value `Sealer` no longer panics, enclave pages are
  excluded from forked children on Linux, and the residue sweep sees keys
  outside anonymous memory.

  **Why BREAKING here.** This library's own signatures are unchanged, but the
  `*enclave.MemoryEnclave` values it returns are go-enclave v0.8's type:
  `EqualTo` returns `(bool, error)` and reports `ErrEnclaveDestroyed` for a
  destroyed enclave instead of a bare `false`, `EqualToErr`, `Open`,
  `OpenString` and `NewMemoryEnclaveFromString` are gone (read through
  `WithBytes`), and `Destroy` returns `ErrEnclaveCorrupted` instead of
  panicking. See go-enclave's changelog for v0.8.0-alpha.

  **What this library does with it.** Its own key comparisons treat an
  `EqualTo` error as "not equal": an unusable digest is skipped like a refused
  KDF, and a failed keyslot comparison reports a mismatch. `secret.Custody.Release`
  drops the corruption report with the others, because go-enclave reports it
  again in the next `WipeAll`'s `SweepError`; it no longer lets a panic through.

### Changed

- **CI tool pins moved to the upstream latest (#282).** golangci-lint v2.13.2 →
  v2.14.0, govulncheck v1.7.0 → v1.8.0, and Go 1.27.0 → 1.27.1 in `go.mod`, the
  workflows and the Dockerfiles, and trivy v0.74.0 → v0.75.0 with its four
  SHA-256s; gosec stays at v2.29.0, already the latest. The
  pins move in step with the shared runner image, which asserts that the baked
  tool matches. Building now needs Go 1.27.1.

## [1.0.0-rc.1] - 2026-10-07

### Changed — BREAKING: the public API is now a `*Volume` handle, not device-path free functions

- **`pkg/luks2.Open(ctx, path, ...Option) (*Volume, error)` replaces most
  free functions.** A `*Volume` pins one descriptor; every method takes the
  lock it needs, does its I/O and releases it — no lock is held between
  calls. `Volume` is safe for concurrent use (an internal `sync.RWMutex`), and
  the lock order (node flock, then cryptsetup's lock, then an O_EXCL claim) is
  now a type property (`internal/device`'s `Pinned`/`Locked`/`Claimed`), not a
  calling convention.
- **Credentials are `*enclave.MemoryEnclave`, not `[]byte`.** Every secret
  crossing the API — `Format`'s passphrase, `Unlock`'s, a recovery key's text
  — is a caller-owned enclave. The volume key is no longer extractable: `*Key`
  (`= volkey.Key`) is obtained only from `Unlock`/`UnlockKeyslot`/
  `UnlockWithProvider`/`UnlockWithVolumeKey`, and its bytes cannot be read
  through the public API at all.
- **Activation split out of `Unlock`.** `(*Volume).Unlock` derives and
  verifies the key without touching dm-crypt; `pkg/dmcrypt.Activate(ctx, v,
  key, name)` maps it. `pkg/dmcrypt`, `pkg/loop`, `pkg/filesystem`,
  `pkg/keyprovider` and `pkg/wipe` are now separate packages, split along the
  root/exec trust boundary (`depguard`-enforced): `pkg/luks2` itself has no
  root and no exec.
- **Params structs replace option structs; a zero value means library
  policy.** `FormatParams`, `KDFParams`, `KeyslotParams`, `MigrateParams`,
  `filesystem.MakeParams`/`MountParams`, `wipe.Params` take the place of
  `FormatOptions`, `AddKeyOptions`, `FIPSMigrationOptions`, and so on.
- **Keyslot removal is guarded, not authenticated.**
  `(*Volume).RemoveKeyslot(ctx, slot)` keeps every data-safety guard
  (`ErrLastKeyslot`, `ErrKeyslotAreaOverlap`) but drops the
  `RemoveKey`/`KillSlot`/`KillKeyslot` authentication distinction; who may
  remove a slot is now the caller's policy.
- **One error shape.** Every failure is `*errs.Error{Op, Path, Kind, Detail,
  Err}` (aliased `luks2.Error`, `filesystem.Error`, `keyprovider.Error`), with
  `Kind` enforced non-nil across the module. `ErrInvalidArgument`,
  `ErrInvalidCredential` and `ErrIO` are now module-wide kinds
  (`internal/errs`, re-exported by value). `VolumeError`, `KeyslotError`,
  `CryptoError`, `InvalidKeyslotError` and `UnlockError` are deleted;
  `ErrMasterKeyVerification` is renamed `ErrWrongKey`; `Argon2CostError`/
  `PBKDFIterationsError` unify into `KDFCostError{Param, Value, Min, Max}`.
- **Errors are typed across the packages (#277).** Failures in `pkg/dmcrypt`,
  `pkg/loop`, `pkg/wipe`, `pkg/keyprovider` and `pkg/luks2` carry a sentinel
  kind that `errors.Is` matches, with the specific cause in the error's
  detail, so a caller branches on the kind instead of on message text.
- **The CLI (`internal/cli`) is rewritten** on this API, split by command
  group, with a map-based dispatch, cryptsetup-compatible exit codes
  (`cryptsetup(8)`: 1 usage, 2 wrong passphrase/no permission, 3 out of
  memory, 4 wrong device, 5 exists/busy), and root-only operations tested
  through fake host interfaces. `cmd/luks2` is now `main.go` only.

**Migration map.** DESIGN.md §B.6 is the exhaustive, per-identifier
disposition (KEEP/RENAME/MOVE/UNEXPORT/DELETE) for every one of
`pkg/luks2`'s 401 pre-redesign exported identifiers, cross-checked against
`test/tools/apidump`'s baseline. `make api-diff` reports that `pkg/luks2`
honours every disposition in that baseline: the free-function API is gone, not
deprecated. That covers the keyslot writes (`AddKey`, `ChangeKey`, `RemoveKey`,
`KillSlot`), the token cluster (`GetToken`, `ListTokens`, `ImportToken`,
`ExportToken`, `RemoveToken`, `FindFreeTokenSlot`, `TokenExists`,
`CountTokens`, `ImportTokenJSON`), `EnrollKeyProvider`, the recovery-key free
functions, `Format(FormatOptions)`, `RestorePrimaryHeader(device)`/
`RestorePrimaryHeaderWithOptions`, `MigrateToFIPS(device, ...)` and the
low-level helpers. Errors follow DESIGN.md §C.3's consolidation, and
`pkg/luks2`'s seam-variable allowlist is empty: its seams live on `Volume`'s
`volumeSys`.

**Retained exports.** Four identifiers outside the new shape stay exported on
purpose, each recorded in DESIGN.md §B.6:

- `luks2.DefaultKDFSpec`, the LUKS2 spelling of `DefaultKDFType()`.
- `luks2.LegacyToken`, the on-disk token codec with its typed FIDO2 members;
  callers use the generic `Token`.
- `dmcrypt.ErrIntegerOverflow`, raised when a segment size or offset does not
  fit the device-mapper table.
- `dmcrypt.ErrDeviceChanged`, the same value as `luks2.ErrDeviceChanged`.

See `docs/design/DECISIONS.md` for what each step did.

### Changed — BREAKING: `luks2 mount` defaults to `nosuid,nodev`, and `wipe` refuses full-wipe options without `--full`

- `luks2 mount` mounts a decrypted volume `nosuid,nodev`. `--allow-suid` and
  `--allow-dev` opt back in. A relative mount point is resolved first, so a
  second mount no longer stacks on the first.
- `luks2 wipe` refuses `--random`, `--passes`, `--standard`, `--verify` and
  `--trim` unless `--full` is given. Before, they were ignored, and a
  header-only wipe reported success.

### Fixed

- **Multi-pass wipes reached the medium as one pass.** `wipe.Sanitize` now
  syncs after every pass, so DoD3 and DoD7 write each pattern to the device,
  not only the last one through the page cache. Unknown patterns and
  standards are refused before the first write.
- **A torn primary header made a volume unopenable that cryptsetup opens.**
  Reads use the valid header copy with the higher sequence id, as cryptsetup
  does, and the next write repairs the stale copy. Token writes read the
  current copy too, so an older primary can no longer overwrite a newer
  token.
- **Crash and cancellation safety of keyslot writes.** Format writes keyslot
  material before the header that names it, and zeroes the previous
  container's header copies first. `AddKeyslot` and `ChangeKeyslot` honour
  cancellation only before their first write, so a cancelled call no longer
  leaves wrapped key material in an area no header names. Rollbacks run to
  completion under a cancelled context. `ChangeKeyslot` checks the key
  against the volume's digest before writing anything, and keeps the
  slot's priority unless one is given.
- **Concurrent reads on one `Volume` dropped each other's lock.** The shared
  lock is held until the last reader releases it, so cryptsetup cannot
  write in the middle of a read.
- **Key providers ran under the volume's locks.** `Enroll` and
  `UnlockWithProvider` obtain the credential before locking, so a slow
  FIDO2 touch no longer blocks cryptsetup. `Enroll` applies the same KDF and
  credential checks as `AddKeyslot`.
- **Token operations and `Enroll` failed on a mapped or mounted volume**
  with `ErrDeviceInUse`; they now work there, as `cryptsetup token import`
  does. `MigrateToFIPS` uses the volume's open descriptor and its lock
  options instead of reopening the path.
- **CLI cleanup after Ctrl-C.** `luks2 create` removes its mapping and loop
  device even when interrupted.
- In FIPS 140-3 mode an AES-XTS keyslot key whose two halves are equal is
  refused.

## [0.5.0-alpha] - 2026-10-05

### Changed

- **CI jobs all start at once (#258).** ci.yml moves to ci-template v1.15:
  security and integration no longer wait for lint, build and unit tests, and
  the CI Gate still needs every job and fails on any result but success.

- **automerge.yml is the shared v7 template.** It runs only from the base
  branch (`pull_request_target`, `workflow_run` and a schedule sweep), so a PR
  can no longer rewrite the check that merges it. It replaces the per-repo
  hold from 0.4.0-alpha, where PRs changing CI definitions needed an approval
  (#247). That hold and its tests (`test/ci/workflows/automerge_test.go`) are
  removed, because a per-repo copy of the template is a defect; the template
  is tested where it is maintained.

### Added

- **`ErrMetadataLockUnavailable`.** A write to a block device whose cryptsetup
  lock directory (`/run/cryptsetup`) is missing and not creatable, is a symlink
  or a file, or does not admit the caller now matches this sentinel, still
  wrapped in the `DeviceError` it was before and with the errno reachable.
  cryptsetup refuses the same states; docs/COMPATIBILITY.md has the measured
  table, and the group grant that lets a non-root caller use both tools.
- **A cryptsetup interoperability matrix in the integration suite**: every
  keyslot, token, header and data operation done by one tool and checked by
  the other, cryptsetup-formatted volumes with non-default options, the lock
  directory in each state against cryptsetup as root and as a setuid disk-group
  user, and every write path racing a cryptsetup write in both orders. The
  integration container gains `CAP_SETUID` and `CAP_SETGID` for the setuid
  child.

### Changed — BREAKING: headers with more than 32 keyslots or digests are refused, and one operation's key derivation is capped

- **An aggregate key-derivation and locked-memory budget per operation
  (#26).** A header with more than 32 keyslots or 32 digests is now refused on
  read with `ErrInvalidHeader`; cryptsetup writes no such header. A keyslot
  scan prices its derivations before the first one and fails with the new
  `ErrKDFBudgetExceeded` (also `ErrInvalidHeader`) when they add up to more
  than the most expensive header cryptsetup can write -- 32 keyslots, one
  digest each, every derivation at its ceiling -- so no cryptsetup container
  is refused. Every enclave is admitted against go-enclave's process
  `Allocator`: a binary that installs one with `enclave.SetAllocator` bounds
  this library's locked memory, and a keyslot the budget can never admit is
  refused before its derivation. A consumer needs to change nothing unless it
  opens crafted headers, or installs its own process allocator after first
  using this library (go-enclave's install is one-shot).

### Fixed

- **Volumes cryptsetup handles that go-luks2 could not open.** Keyslots
  encrypted with `aes-cbc-essiv:sha256`, `aes-cbc-plain64` or `aes-cbc-plain`
  (`--keyslot-cipher`, a CBC data cipher, or `cryptsetup convert` from LUKS1)
  are read; a passphrase change rewrites one as `aes-xts-plain64`. Volume keys
  of 16 and 24 bytes (128- and 192-bit CBC data ciphers) are accepted, and a
  new keyslot for one is wrapped with AES-256-XTS. The 20-byte digest every
  converted LUKS1 volume carries is verified. A detached header's keyslots
  can be opened, added, changed and removed; its activation is still refused.
- **Unlock mapped a `--integrity` volume without dm-integrity.** Reads were
  garbage and every write destroyed the integrity tags. Activation is now
  refused with `ErrUnsupportedSegmentLayout` before any key is derived.
- **The header's persistent performance flags reach dm-crypt.** `same-cpu-crypt`,
  `submit-from-crypt-cpus`, `no-read-workqueue` and `no-write-workqueue` are in
  the table as cryptsetup puts them; `allow-discards` deliberately is not.
- **A symlinked `/run/cryptsetup` was followed**, so the lock was taken where
  cryptsetup never looks. It is refused, as cryptsetup refuses it.
- **Concurrent `SetupLoopDevice` calls failed with `LOOP_SET_FD: EBUSY`** when
  both were handed the same free device; the loser now asks for another.

## [0.4.0-alpha] - 2026-10-05

### Changed

- **The project documentation was checked against the code and rewritten
  (#245).** README.md, docs/ARCHITECTURE.md, docs/cli, docs/luks, FIPS.md,
  TESTING.md, COMPATIBILITY.md, RELEASABILITY.md and changelog.d/README.md now
  describe v0.3.1-alpha as it behaves, at about 40% of their former length.
  ARCHITECTURE.md now covers the packages, key custody, header handling, the
  device layer, FIPS mode and the trust boundaries. Corrected claims include:
  a header-only `wipe` zeroes the two header copies only, so keyslot material
  survives; `close` does not detect a mounted volume, which instead fails as
  busy after 3 s of retries; wipe verification does nothing for the `nist`,
  `dod3` and `dod7` standards; device and file paths must be absolute; key
  files over 512 bytes are refused; keyslot priority is not used by unlock;
  the dashed recovery key is 74 uppercase characters; and the FIPS job runs
  in `nightly.yml`. The CLI help no longer claims that no external tools are
  used (`create` runs `mkfs`), and its examples use absolute paths.

### Changed — BREAKING: `luks2 create` on a block device asks for `YES` and refuses existing data

- **Formatting a block device needs confirmation (#246).** `create /dev/X` asks
  for `YES`. `--batch-mode` (or `--yes`) skips the question for scripts. Before
  this, it formatted the device without asking. It now refuses a device that
  already holds a LUKS header (either copy) or a filesystem, RAID, LVM or
  partition-table signature unless `--force` is given. It always refuses a
  device the kernel reports in use. Scripts that create volumes on block
  devices must add `--batch-mode`.

### Changed — BREAKING: an unconfirmed `wipe` or `header restore` exits 1

- **A canceled destructive command now fails (#246).** Any answer other than
  `YES`, end of input, or a read error used to print "canceled" and exit 0, so
  a script read a wipe that never happened as done. These now exit 1.
  `--batch-mode` (or `--yes`) skips the question.

### Changed — BREAKING: a header-only wipe also erases the keyslots area

- **`Wipe` with `HeaderOnly` is now a crypto-erase (#246).** It used to zero
  only the two header copies, plus the 4 KiB binary header of any stray copy.
  The keyslot material stayed on the device, and so did a stray copy's JSON,
  salts included. Anyone holding a pre-wipe copy of the header could put it
  back and open the volume with the old passphrase. The wipe now zeroes the
  whole keyslots area, every declared keyslot area, and every other
  recognizable header copy's JSON. It stops at the start of the data segment.

### Changed — BREAKING: key-provider helpers need absolute paths, a clean environment and a FIDO2 device

- **Helpers are never looked up on PATH (#246).** A `CommandKeyProvider` or
  `ExecConfig` helper path that is not absolute is refused with
  `ErrHelperPathNotAbsolute`. The docs already said PATH was not searched, but
  `exec` searched it for any bare name. Helpers no longer inherit the
  process environment. They get a system `PATH` plus the new
  `CommandKeyProvider.Env`.
- **`ExecConfig.Device` is required (#246).** An empty device used to reach
  the helper as an empty argument. It is now refused with `ErrNoFIDO2Device`,
  and the device is passed after `--`.

### Changed — BREAKING: the device lock also takes cryptsetup's lock

- **go-luks2 and cryptsetup now exclude each other (#246).** For a block
  device, `AcquireFileLock` (used by every header write) now also takes
  cryptsetup's own lock, `flock` on `/run/cryptsetup/L_<major>:<minor>`, the
  way cryptsetup does. Before, cryptsetup could change a header this package
  held locked. A process that cannot create or open that file (normally
  anything but root) can no longer lock a block device. Image files are
  unchanged: cryptsetup locks the file itself, which this package already did.

### Fixed

- **`--no-verify` turns off a standard's verification (#246).** It only hid
  the "Verify" line and the DoD standards still verified. The new
  `WipeOptions.NoVerify` is what it sets.
- **Wipe verification reads the medium (#246).** It reads back with
  `O_DIRECT`, including a loop device's backing file. The random pass is now
  AES-256-CTR under a per-pass key, so the DoD sequences, which end with a
  random pass, are actually verified. Before, verification read the page cache
  and skipped random passes.
- **`Wipe` and `WipeKeyslot` refuse a device in use (#246).** They open block
  devices with `O_EXCL` and return `ErrDeviceInUse` for a mounted, mapped or
  held device.
- **Concurrent enrollments no longer overwrite each other's token (#246).**
  `EnrollKeyProvider` and `AddRecoveryKey` hold one device lock from choosing
  the token slot to writing the token.
- **FIDO2 tokens keep their PIN and user-verification requirements (#246).**
  They are written as `fido2-clientPin-required` and `fido2-uv-required` and
  read back by `ProviderFromToken`.
- **A helper's output read ends with `ctx` (#246).** It also ends if the
  helper exits while a process it started still holds the pipe.
- **`create <file>` creates the file safely (#246).** It uses `O_EXCL` and
  `O_NOFOLLOW` at mode 0600, instead of a stat-then-create that raced, followed
  symlinks, and made the file 0644. Cleanup removes only the file this run
  made.
- **Relative paths work in every command (#246).** The documentation shows
  them, and the CLI now resolves them.
- **Strict size and `--passes` parsing (#246).** `10x`, `1.5G` and overflowing
  values are refused instead of silently truncated.
- **An empty `--key-file ""` is refused (#246).** It no longer falls back to
  the prompt or to standard input.
- **Passphrase buffers are wiped on every path (#246).** This covers a failed
  confirmation read and a piped line whose buffer grew.
- **`recovery add` rolls back a key it could not show (#246).** If the key
  cannot be displayed, the CLI removes its keyslot and token. If that fails, it
  names the slot to remove.
- **The integration suite runs when its state directory belongs to the
  invoking user (#246).** The launcher mounts a root-owned `root-ledger`
  subdirectory in that case instead of the directory itself, which the root
  reaper must not trust. Before, every run refused until the directory was
  removed by hand.

### Security

- **golang.org/x/crypto is v0.57.0, and every direct dependency is at its
  latest (#247).** v0.55.0 carried GO-2026-6355 and GO-2026-6354, two
  x/crypto/ssh denial-of-service advisories fixed in v0.56.0. This module never
  imports x/crypto/ssh, so neither was reachable, but a consumer's govulncheck
  reported both. golang.org/x/term is v0.46.0 and
  github.com/anatol/devmapper.go is at its 2026-03-15 commit, which copies a
  caller's crypt flags instead of appending to them. govulncheck now reports
  only GO-2026-5932: x/crypto/openpgp is unmaintained, has no fixed version, and
  is not imported here.
- **A release waits for CI and runs the security suite (#247).** A `v*` tag
  used to publish on its own: it had no dependency on CI, tested only
  ./pkg/luks2, ran no scanner, and built without `-trimpath`. release.yml now
  publishes only when every one of these passes:
  - the tagged commit is on main;
  - CI's gate passed for that exact commit. `test/ci/cmd/release-gate` waits
    for the gate's result and refuses on anything but a pass.
  - the ./pkg/luks2 and ./cmd/luks2 tests;
  - `make security` with `TOOLS_REQUIRED=1`, so no scanner can skip.

  The publish step then builds with `-trimpath`. The tag name is treated as
  data and is never spliced into a script.
- **Every workflow action is pinned to a full commit SHA, and trivy is installed
  from a checksummed archive (#247).** `aquasecurity/trivy-action@master` and
  `curl …/install.sh | sh` are gone. `make trivy-install` downloads the pinned
  v0.74.0 archive and checks its SHA-256 before unpacking. It then checks the
  binary's SHA-256 before installing it, and again before reusing an installed
  copy. The Makefile no longer claims trivy gates every push: it gates the
  nightly workflow and every release.
- **Automerge requires an approval for a PR that changes CI definitions
  (#247).** CI_DEFINITIONS covers `.github/`, `.gitea/`, the Makefile,
  `test/ci/`, `test/covergate/`, `test/labstrings/`, `coverage-floors.txt`,
  `releasability-exempt.txt`, `.golangci.yml`, and the integration job's
  `test/integration/Dockerfile`, `test/integration/cmd/`,
  `test/integration/seccomp.json` and `.dockerignore`. A PR touching any of them,
  whether by adding, editing, deleting or renaming, now needs the same
  approval as a `code-review` PR. Before, it could change
  its own gate and merge on that green. automerge.yml reads the changed files
  from the forge and refuses to merge if it cannot read the whole list.

### Fixed

- **Test harness hardening (#247).** These changes affect only the
  integration harness:
  - The reaper no longer detaches under a recorded root unless the root is
    named like a run root.
  - The state directory is used only through the handle it was validated by.
  - A run's temp root is named `go-luks2-run-<run id>-<n>`. A root is reaped
    only for the run whose ledger carries that id, so a dead run's root can no
    longer share a name with a live sibling's and have the sibling's loop
    devices detached.
  - A pre-#247 ledger whose root still has loop devices under it fails the reap
    and must be cleared by hand (docs/TESTING.md).

### Changed — BREAKING: headers are validated the way cryptsetup validates them, on read and before every write

- **One structural validator, matching cryptsetup's `LUKS2_hdr_validate` (#248).**
  It covers the five mandatory objects (present, and objects), segment offsets
  and sizes on the 512-byte sector grid, a keyslots
  area that fits between the header copies and the data, digests and tokens
  that name only keyslots and segments that exist, every luks2 keyslot named
  by exactly one digest, the online-reencryption backup segments and
  reencrypt keyslot, and the config sizes. The integration suite holds it to the
  cryptsetup binary in both directions: every header cryptsetup writes passes
  it, and every header cryptsetup refuses is refused.

  On read, a header that breaks a rule about the header as a whole is refused
  with `ErrInvalidHeader`. A damaged keyslot or token still does not cost the
  volume its other keyslots. Every **write** applies all the rules, so
  `WriteHeader`, `ImportToken` and the keyslot operations refuse to write a
  header cryptsetup would not read. A damaged entry has to be removed before
  anything else can be written. `RestorePrimaryHeader` is the exception: it
  copies the existing secondary back under the header-wide rules only, so a
  damaged entry cannot block the repair.

  A data segment that overlaps the header or keyslots area is never activated.
  That includes offset 0, which cryptsetup reads as a detached header; this
  library has no detached-header support. Previously, Unlock mapped the headers
  into the plaintext device.

- **Ambiguous JSON members are refused (#248).** A metadata object that names a
  member twice, or names one this library models in another case (`"Keyslots"`),
  is refused with `ErrAmbiguousJSONMember`. Go's JSON decoder matches member
  names case-insensitively and cryptsetup's does not, so the two read different
  values from the same header.

- **`RestorePrimaryHeader` repairs; it does not roll back (#248).** It refuses
  with `ErrPrimaryHeaderCurrent` when the primary is intact and not older than
  the secondary. Before, restoring an older secondary over a newer primary
  could bring back a passphrase that had already been removed. The restored
  header gets a sequence id one above both copies.
  `RestorePrimaryHeaderWithOptions` with `Force` restores anyway.

- **`Format` refuses bad input before it writes anything (#248).** It accepts only
  `aes-xts-plain64` (256 or 512 bits) and `aes-cbc-essiv:sha256` (256 bits),
  and refuses anything else with `ErrUnsupportedCipher`. It also refuses:
  - labels and subsystems over 47 bytes, or containing a NUL (`ErrInvalidLabel`);
  - devices with no room for at least one data sector after the keyslots area
    (`ErrDeviceTooSmall`). Before, it wrote the header and failed later, or grew
    a regular file into a container with no data.

  It opens the device with `O_EXCL`, so a mounted or mapped block device is
  refused with `ErrDeviceInUse` instead of being formatted.

### Fixed

- **`ImportToken` no longer writes `"keyslots":null` (#248).** A token naming no
  keyslot is written with an empty array. cryptsetup and systemd-cryptsetup
  refuse a whole header that carries the null.
- **The header checksum covers the bytes that are parsed (#248).** The header
  area is read once, and the checksum, the binary header and the JSON all come
  from that buffer. Before, the area was read three times, so a concurrent
  rewrite could be checksummed in one state and parsed in another.
- **`VolumeInfo.KeySize` is set (#248).** It is the volume key size in bits,
  taken from a keyslot attested for the crypt segment that Unlock maps. Cipher
  and sector size come from that same segment instead of from whichever one Go
  map iteration returned first.

### Security

- **The last-keyslot guard no longer counts an unbound keyslot as a survivor
  (#249).** A keyslot written by `cryptsetup luksAddKey --unbound`, or bound only
  to another segment, holds a key that decrypts nothing, yet `RemoveKey`,
  `KillSlot`, `KillKeyslot` and `WipeKeyslot` counted it and destroyed the only
  keyslot holding the volume key. A survivor must now be declared bound to every
  data segment, sit at an id cryptsetup can address, and lie in keyslot space.
- **Every keyslot wipe is confined to the keyslots area (#249).** A header
  declaring a keyslot area over the header copies or the encrypted payload had
  it overwritten by `RemoveKey`, `KillSlot`, `KillKeyslot`, `ChangeKey`'s
  cleanup and `WipeKeyslot`. They now refuse with `ErrKeyslotAreaOverlap`, and
  the unlock scan no longer reads such a keyslot.
- **Keyslot operations stay on the device they locked (#249).** `AddKey`,
  `ChangeKey`, `RemoveKey`, `KillSlot`, `KillKeyslot`, `WipeKeyslot`,
  `TestKey` and `VerifyRecoveryKey` open the path once and do every read, size
  check, write, sync and wipe through that descriptor, so a path re-pointed
  mid-operation cannot redirect the writes.

### Fixed

- **`ChangeKey` on a keyslot with a non-standard stripe count no longer
  destroys it (#249).** It split into 4000 stripes but kept the old
  `af.stripes`, then wiped the old area. The rewritten keyslot now declares
  4000 stripes (growing its area if needed), and both `ChangeKey` and `AddKey`
  read the new keyslot back from the committed header and require it to open to
  the volume key before anything old is destroyed; one that does not is rolled
  back.
- **cryptsetup `--keyslot-key-size` volumes open (#249).** The passphrase is
  derived to `area.key_size`, not the volume key's size.
- **`ValidateDevicePath` accepts names containing `..`** such as
  `/dev/disk/by-label/a..b` (#249); `..` path elements are still resolved and
  relative paths still refused.

### Changed — BREAKING: existing credentials, recovery keys, Argon2 and PBKDF2 costs (#249)

- **An existing credential is no longer held to the new-passphrase policy.**
  `Unlock`, `TestKey`, `RemoveKey`, `KillSlot`, `MigrateToFIPS` and the existing
  credential of `AddKey` and `ChangeKey` accept 1 byte to 8 MiB (cryptsetup's key
  file limit), so a 4 KiB key file or a short legacy passphrase opens. Empty and
  over-long credentials return the new `ErrCredentialEmpty` and
  `ErrCredentialTooLong`; `ErrPassphraseTooShort`/`TooLong` now apply only to new
  passphrases.
- **A passphrase that opens only an unbound keyslot no longer authenticates**
  `TestKey`, `AddKey`, `KillSlot` or `VerifyRecoveryKey`; it gets
  `ErrMasterKeyVerification`, as with cryptsetup.
- **`GenerateRecoveryKey` and `AddRecoveryKey` refuse fewer than 32 random
  bytes**, a negative length, a rendering longer than 512 bytes
  (`ErrRecoveryKeyTooShort`) and an unknown format
  (`ErrInvalidRecoveryKeyFormat`) instead of rendering it dashed.
- **Argon2 creation refuses costs the reader refuses**: memory over 4 GiB, time
  over 10000, parallelism over 255. `Argon2CostError` gains `Maximum`.
- **A calibrated PBKDF2 count for a caller's passphrase is held to the OWASP
  floor at the 2000 ms reference budget**, so `PBKDFIterTime: 1` no longer
  yields ~1000 iterations.
- **The unlock scan skips keyslot ids cryptsetup cannot address** (`01`, `32`,
  `abc`).

### Security

- **`Unlock` maps only a key bound to the data segment (#250).** A passphrase
  that opened only an unbound keyslot had its key handed to dm-crypt, and the
  mapping returned garbage. Only keyslots bound to the segment are tried now,
  and the key must verify against that segment's digest. Otherwise the result is
  `ErrMasterKeyVerification`, which is also what cryptsetup does. `AddKey`
  checks the existing passphrase the same way.
- **A rolled-back `Unlock` no longer removes another caller's mapping (#250).**
  When two unlocks raced for one name, the loser's rollback matched the winner's
  dm UUID and removed the live mapping. The rollback now runs only after this
  call's own create succeeded, and is pinned to the device number that create
  returned.
- **Filesystem programs no longer run from `PATH` (#250).** mkfs, fsck, zpool,
  zfs and blkid run from fixed system directories with a two-variable
  environment, and every operand follows `--`. A program, or a symlink to
  one, is run only if the file and every directory above it are writable by
  nobody but root or the current user.

### Changed — BREAKING: activation refuses reencrypting and multi-segment containers

- **(#250)** A container with a mandatory requirement this library does not
  implement, such as `online-reencrypt-v2` from an interrupted
  `cryptsetup reencrypt`, is refused with `ErrUnsupportedRequirement`. It used to
  be mapped with one key over one segment. A header with more than one segment
  is refused with `ErrUnsupportedSegmentLayout`.

### Changed — BREAKING: mapping names are validated and nodes verified everywhere

- **(#250)** `MakeFilesystem`, `MakeFilesystemWithOptions`, `Mount`, `Lock`,
  `IsUnlocked` and `GetMappedDevicePath` reject an invalid mapping name with
  `ErrInvalidMappingName` (`IsUnlocked` returns false). `control` is no longer
  a valid name: `/dev/mapper/control` is device-mapper's control node. Before this,
  `MakeFilesystem("../sdb", ...)` ran mkfs on `/dev/sdb`. Device-mapper decides
  whether a mapping exists: `IsUnlocked` no longer answers true from a
  `/dev/mapper` node alone. `GetMappedDevicePath` returns a node only if its
  device number matches the mapping's, and returns `ErrDeviceNodeUnverified`
  otherwise. `Unlock` replaces a stale `/dev/mapper/<name>` instead of
  trusting it.

### Changed — BREAKING: `Unlock` requires a block device

- **(#250)** `Unlock` opens the device once, reads the header, the size and the
  keyslots through that descriptor, and gives dm-crypt its `major:minor`. A
  regular file is refused with `ErrNotBlockDevice`; attach it with
  `SetupLoopDevice` first. dm-crypt could never map a regular file anyway.

### Changed — BREAKING: ZFS names are validated, tools come from fixed directories

- **(#250)** ZFS pool, dataset, feature and property names that do not follow
  zpool's naming rules are refused with `ErrInvalidFilesystemOption`. A
  filesystem program that is only on `PATH`, or that sits in a directory
  writable by others, is refused with `ErrFilesystemTool`.

### Added

- **`IsMappingMounted(name)` (#250)** reports whether a filesystem on a mapping
  is mounted, by device number. `luks2 close` uses it. The old check asked
  whether `/dev/mapper/<name>` was a mount point, which it never is, so `close`
  never refused a mounted volume.

### Fixed

- **`Unlock` works under a mapping name of any valid length (#250).** The dm
  UUID is now cut to the 128 bytes the kernel stores before the create, as
  cryptsetup does. With a name over about 83 bytes the kernel used to cut it
  and every later identity check compared the uncut string.
- **`FindLoopDevice` matches by device and inode (#250)**, so a file named
  through a symlink or a bind mount finds its loop device. It now returns a
  `DeviceError` for a file that does not exist.
- **The keyring thread is discarded after an unlock (#250).** Resolving the
  session keyring can install one on the calling OS thread, and that thread used
  to return to the scheduler. The keyring work now runs on a locked thread that
  exits when it finishes.
- **Unlock errors name the real command (#250).** The remedy for a name in use
  or a mapping left live said `luks close <name>`; the CLI is `luks2`.

### Changed

- **`CLAUDE.md` and the new `AGENTS.md` are tracked; agent files are stripped
  at publish (#252).** The releasability gate no longer fails on `CLAUDE.md`,
  `AGENTS.md` or `.claude/` at any depth. It lists them, with
  `automerge.yml`, as files the public release strips (#211), and does not call
  the tree publishable while one is tracked. Their content is still scanned, and
  shell scripts, binaries and unpublished workflows still fail.
  `PendingWorkflows` and `Pending` are replaced by `DefaultStripAtPublish` and
  `StripAtPublish`, and `ScanUnpublishable` takes the strip list.
  Only local tool state (`.claude/settings.local.json`) stays gitignored, per
  the standards' project-scaffold §7.

### Security

- **`MigrateToFIPS` stays on the device it locked (#255).** It opened the
  device path again for every read, write, wipe and medium check, so a path
  re-pointed mid-import could send the new keyslot, the header rewrites and the
  wipes of the old keyslots to a device that was never locked or read. It now
  opens the path once, locks that descriptor, and does everything through it;
  the reads past the page cache reopen the same inode through `/proc/self/fd`.

### Added

- **`DetectFilesystem` and type detection in `Mount`.** `DetectFilesystem(name)`
  reports the filesystem on an open mapping from `blkid -p` (never blkid's
  cache). `Mount` with an empty `FSType` mounts what it finds. Nothing found,
  more than one signature, or one that is not a filesystem is refused with
  `ErrFilesystemNotDetected`.
- **`ParseRecoveryKeyFormat`** turns a format name into a `RecoveryKeyFormat`,
  refusing anything but `dashed`, `hex` and `base64` (an empty name included)
  with `ErrInvalidRecoveryKeyFormat`.
- **`luks2 header restore --force`** passes `RestoreHeaderOptions.Force`
  through, so the CLI can restore over an intact primary that is not older. It
  still asks for `YES` unless `--batch-mode` is given, and warns that it rolls
  the volume back.

### Changed — BREAKING: `luks2 mount` mounts the detected filesystem, not ext4

- `luks2 mount` used to mount every volume as ext4, so the xfs and vfat volumes
  `create` makes could not be mounted with it. It now takes `--type`/`-t` and
  otherwise detects the type. A mapping with no recognizable filesystem is
  refused (exit 1) instead of being handed to `mount(2)` as ext4.

### Changed — BREAKING: `luks2 create` fails when it cannot open the new volume

- If `create` cannot attach a loop device to the new file volume or unlock it,
  it now prints the error on stderr, detaches a loop device it attached, keeps
  the container and **exits 1**. It used to print a warning and exit 0, so a
  script went on to mount a volume that was never opened.

### Changed — BREAKING: a header checksum algorithm other than sha256 is refused

- The binary header's `csum_alg` field was ignored and SHA-256 computed
  regardless, so a header claiming `sha1` over a SHA-256 checksum was read here
  and refused by cryptsetup. A header naming anything but `sha256` (the only
  algorithm cryptsetup writes) is now refused with
  `ErrUnsupportedHeaderChecksum`, which also matches `ErrInvalidHeader`.

### Security

- **Writers no longer reopen the device path after locking it.** `Wipe` and
  `WipeKeyslot` took their `O_EXCL` in-use claim on a second open of the path
  and never checked it was the locked device: a symlink re-pointed in between
  had `Wipe` overwrite a different disk, and `WipeKeyslot` claim an idle disk
  and then zero a keyslot on the in-use one. `ImportToken`, `RemoveToken` and
  `WriteHeader` read and wrote the header by reopening the path. The token
  and header writers now read and write through the locked descriptor; the
  wipes' `O_EXCL` claim is refused with the new `ErrDeviceChanged`, before
  anything is written, unless its device, inode and rdev match the locked
  descriptor, and `Wipe` then writes through that proven claim.
  `AddRecoveryKey` took the `VolumeUUID` it reports (and saves) from a second
  read of the path after enrolling; it now comes from the header read under
  the enrollment's lock. Format's same-file refusal now also returns
  `ErrDeviceChanged`.

### Fixed

- **`Unlock` reads the metadata under cryptsetup's read lock.** It takes
  `LOCK_SH` on the device and on `/run/cryptsetup/L_<maj>:<min>` before reading
  the header and holds them through the keyslot scan, releasing them before the
  device-mapper work. A cryptsetup command (or this library) writing the header
  is waited for, up to `DefaultLockWait`, instead of being read mid-rewrite;
  other readers are not delayed. Releasing cryptsetup's lock file now unlinks
  it only when no other holder remains, as cryptsetup does.
- **`luks2 recovery` refuses an unknown `--format` as a usage error**, before
  reading the passphrase. An empty `--format=` used to produce a dashed key.
- **Polling waits use the package clock.** The device-mapper readiness and
  busy-retry waits run on the injectable clock with a deadline.
- Stale comments and examples: the dashed recovery key is 74 characters, not
  71; `RecoveryKeyOptions.KDFType` describes the PBKDF2/1000 path that now
  exists; `create`'s usage examples use an absolute path.

### Tests

- Keyslot removal is held to `cryptsetup luksKillSlot`'s token update on the
  same header for every removal path (the keyslot is dropped from every token;
  a token left naming none is kept).
- The last `t.Skip` guards are gone: missing cryptsetup or VmLck fails the
  test, and the harness hostname is injected.
- The integration image installs `strace`, used to make real cryptsetup hold
  its write lock while `Unlock` reads.
- **`pkg/luks2` under `-race` is back inside its budget (#92):** 322 s to
  108 s on the same host. The FIPS-import child processes use the suite's
  calibrated-count seam and run in parallel, and the AF XOR, `clearBytes` and
  the ones-pattern fill no longer loop per byte (the coverage build counted
  every byte atomically).

## [0.3.1-alpha] - 2026-10-04

This is the first published release of the `0.3.0-alpha` code: `v0.3.0-alpha` was tagged, but its release job failed (#243), so it was never published. Every change listed under [0.3.0-alpha] below ships in this release, including the BREAKING ones.

### Fixed

- **The release workflow can publish again** (#243). Its test step ran `./pkg/luks2` without cryptsetup, and the cryptsetup conformance and FIPS-import tests fail closed on a missing cryptsetup. So `v0.3.0-alpha`'s release job failed and no Gitea release was created. The job now installs `cryptsetup-bin` exactly as CI's unit job does, and fails if it is still absent. `v0.3.0-alpha` remains a tag without a published release; `v0.3.1-alpha` carries the same code.
- **Released binaries report their version** (#243). Both release builds passed `-X main.version`, but the variable is `main.Version`; the linker silently ignored the mismatch, so every released binary called itself `dev`. The flag is corrected, and the release now runs the built amd64 binary and fails unless it reports the tag.

## [0.3.0-alpha] - 2026-10-03

> Recorded late: the entries down to the next note shipped in this release but were left under `[Unreleased]` when it was cut.

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

> End of the late entries.

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

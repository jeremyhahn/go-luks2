# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

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
  Owner ruling 2026-08-20 (`docs/04-security-model.md` product rulings 5-8).

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

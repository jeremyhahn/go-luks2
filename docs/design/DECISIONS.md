# API redesign: decisions log (phase 1, H0-H4)

Branch `refactor/api-redesign`, from g50/main 6d9332f (v0.5.0-alpha).

## H0

- **Baseline (6d9332f, this host, `make ci`):** green in 4:42 wall. `go test -race ./pkg/luks2` 216 s (224 s measured by test-unit; target 240 s). Unit coverage: pkg/luks2 90.85% (6091/6704, floor 87.50), cmd/luks2 95.79% (1776/1854), test/harness 87.80%.
- **Inventory drift from DESIGN.md.** DESIGN.md counted 401 pkg/luks2 identifiers at 7d40045 + g-compat. The released tree exports 406: g-compat added `KDFBudgetError` (+ `.Error`, `.Is`), `ErrKDFBudgetExceeded` and `ErrMetadataLockUnavailable`. Dispositions chosen:
  - `ErrMetadataLockUnavailable` KEEP (it is already in §C.3's shared list; defined once in internal/device).
  - `KDFBudgetError` DELETE: Error with Kind `ErrInvalidHeader`, need and budget in Detail. A caller cannot act on the numbers differently from any other invalid header (§C.2 rule 2).
  - `ErrKDFBudgetExceeded` RENAME to `ErrInvalidHeader`. Every error matching it already matches `ErrInvalidHeader`.
  - Counts are now KEEP 55, RENAME 134, MOVE 47, UNEXPORT 73, DELETE 97 (406).
- **The API-diff tool is Go, not Python.** `test/tools/apidump` reimplements astdump.go plus disp.py's coverage check. The disposition table is data (`baseline/disposition-luks2.tsv`), generated once from disp.py plus the three rows above. The repository ships no scripts (owner ruling on #211, as require-tool records).
- **What gates, and from when.** H0 gates that the dispositions cover the released API exactly: none missing, none extra, none twice. This is a unit test of the tool, so test-unit runs it. `make api-diff` reports the drift from the baseline; that is a report, not a gate. H13 turns it into the gate that checks every disposition is honoured.
- **cmd/luks2 is recorded but not disposed.** B.7 says nothing stays exported, and H11 checks that directly (cmd/luks2 becomes main.go). A per-identifier table would add nothing to that check.

## H1

- **detailError is deleted, not aliased.** Every `&detailError{...}` literal became `&errs.Error{...}` in the same commit. The fields are the same, so an alias would only have postponed a sed. internal/errs has no constructors yet: struct literals are as short and say what they set. `Op` and `Path` (and `errs.At`) come in H9, together with the boundary that fills them in. Adding them now would leave fields with no writer.
- **Kind stays nil where no existing sentinel fits.** H1 is "existing sentinels, no API change". About 70 converted `fmt.Errorf` sites and about 110 former `detailError` sites had no classifying sentinel, and they keep a nil Kind (errs.Error renders that exactly as detailError did). They fall into two groups:
  - context wrappers around an error that is already classified ("failed to read header: %w");
  - unclassified I/O failures and argument checks.
  H13 assigns §C.3 kinds to them (`ErrIO`, `ErrInvalidArgument`, ...) and replaces the context wrappers with Op/Path set at the boundary. That is when "Kind is never nil" becomes enforceable. Adding `ErrIO` or `ErrInvalidArgument` now would be an API change, and a site may only be classified once (§C.2 rule 4).
- **Three sites gained an existing sentinel** where the sentinel names the condition exactly and the message is unchanged or still reads correctly:
  - the out-of-range keyslot in findAvailableKeyslot (`ErrInvalidKeyslot`);
  - the missing keyslot in WipeKeyslot (`ErrInvalidKeyslot`);
  - the negative size in zeroRange (`ErrInvalidSize`).
  No production code branches on those kinds, so control flow is unchanged.
- **Messages are byte-identical except at 8 sites**, where `fmt.Errorf` put a `%w` in the middle of the message:
  - The five mkfs/zpool/zfs failures now return the existing `*FilesystemCommandError` (Command, Device, Output, Err), which the check paths already returned. They gain the device; the unit tests now assert the typed fields instead of the message text.
  - `ErrPermissionDenied`, `ErrKeyringKeyNotReleased` and `ErrMappingBusy`: the remedy stays in Detail (§C.2 rule 3) and the cause moves to the end of the message.
- **Every `errors.New` outside an `errors.go` moved into errors.go**, in labelled blocks. This covers the external-key, wipe, format, recovery, calibration-cause, metadata-JSON, primary-header and token sentinels. `ErrTokenNotFound` and `ErrNoFreeTokenSlot` were `fmt.Errorf` values with no verb and became `errors.New` with the same text.
- **forbidigo** is on for `fmt.Errorf` and `errors.New`. `errors.New` is excluded only in files named `errors.go`. `_test.go` files and `test/` are excluded, because errors.md §2 permits `fmt.Errorf` in tests. I checked that the rule fires: golangci's uniq-by-line hides a forbidigo finding that shares a line with an `unused` one. time.Sleep is added in H2, with the clock.

## H2

- **clock.Fake advances on wait; it does not wait for Advance.** DESIGN.md §D.3 names `Advance` and `BlockUntilWaiters`, which is the goroutine-driven fake shape (clockwork's). The 33 wait tests in this tree depend on a stronger property: the clock moves *only* when the code under test waits, and a hook (`OnWait`) changes the world at a chosen fake instant without a second goroutine racing the wait. That is deterministic on any machine. The goroutine shape adds a scheduler to every one of those tests and buys nothing, because a ctx cancellation (H8) can be triggered from OnWait too. So `NewTimer(d)` advances the fake by d, runs OnWait, and returns a timer that has already fired. `Advance` exists, for moving time without a wait. `BlockUntilWaiters` does not exist, because nothing ever blocks.
- **Fake is non-test code with no `testing` import.** It reports a runaway wait through a two-method `TB` interface, so a production binary that links internal/clock does not link `testing`.
- **The sweep covers every `time.Sleep` outside test files.** That is pkg/luks2 (6 waits), test/harness (3) and test/ci/cmd/release-gate (1). release-gate's private fake clock is gone too (DRY). forbidigo now bans `time.Sleep` outside `_test.go` files and `test/`. The 26 `time.Sleep` calls in `*_integration_test.go` files are left to H12, which relocates and rewrites those tests against the new API. One unit-test poll remains (activation_test.go, waiting for a discarded OS thread to exit). It re-checks real state on every pass, which is go-style's permitted form.
- **Waits are `<-clk.NewTimer(d).C()` until H8.** There is no ctx yet to select on. H8 turns each one into the `select` on `ctx.Done()` and the timer that §D.2 specifies; this is the single shape it has to find.
- `BenchmarkSystemClockIsTheRealClock` became `TestSystemIsTheRealClock` in internal/clock. Both of its assertions are lower bounds, so the test cannot fail on a loaded machine. It left `CALIBRATION_BENCHMARKS`.

## H3a (secret)

- **Five seam variables became one value.** `newLockedRegion`, `moveIntoLockedRegion`, `copyIntoLockedRegion`, `lockedMemoryAllocator` and `destroyEnclave` are now the fields of `secret.Custody` (Sized, Moved, Copied, Destroy, Allocator). `secret.System()` admits through go-enclave's process allocator, and `secret.Admitted(allocator)` builds the same custody over any allocator. The helpers are methods: `New`, `Adopt`, `Random(op, n, rand)`, `Clone`, `CloneWritable`, `CloneFiltered`, `Release(...)` and `Admissible`. `Borrow` is a function because it allocates nothing. pkg/luks2 holds one transitional `custody` variable until Volume.sys exists (H9). The fail-closed and peak-measuring tests replace that one value instead of five globals.
- **`releaseSecret` and `destroySecrets` merged into `Release(...)`.** Release skips nils instead of handing them to Destroy; go-enclave's Destroy was already a no-op on nil. `CloneWritable` is `CloneFiltered` with a keep-all filter, so the copy loop exists once.
- **`ProtectedMemoryError` is deleted now, not at H13.** Its only producers moved into internal/secret, which cannot return a pkg/luks2 type. B.6 already disposes it as DELETE, replaced by an Error with Kind `ErrProtectedMemory`. The message is unchanged ("key material could not be held in protected memory: <op>: <cause>"), and so is `errors.Is(err, ErrProtectedMemory)`. Only `errors.As(&ProtectedMemoryError{})` stops matching. Its documentation (fail-closed rationale, RLIMIT_MEMLOCK sizing, aggregate bounds) moved to `secret.ErrProtectedMemory`, and luks2 re-exports the sentinel by value.
- **The canonical residual-exposure list is now internal/secret's package documentation** (§A.1). CLAUDE.md, AGENTS.md and docs/ARCHITECTURE.md point there in the same commit, because those files call the list normative and a dangling pointer would be an inaccuracy. The feature-folder rewrite stays in H15. The one nested bullet list became prose, because gofmt flattens nested lists in doc comments.
- `randomSecret`'s read failure used to be `&CryptoError{Op, Err}` and is now an unclassified `*errs.Error` (Detail op, Err cause). Nothing branched on CryptoError there.

## H3b (fips)

- **The mode is a value.** It is `fips.Mode` (a bool type) from `fips.Probe()`. The policy checks are methods on it: `RequireKDF(kdfType)` refuses Argon2, and `RequireHash(use, crypto.Hash)` refuses any hash that is not SHA-2 or SHA-3. pkg/luks2's seam is now `var fipsMode = fips.Probe` (type `func() fips.Mode`) until Volume.sys exists. Tests force the mode with `func() fips.Mode { return true }`, as before.
- **The approval predicate is positive.** `fips.ApprovedHash(h)` is "SHA-2 or SHA-3 family", not "not SHA-1". Behaviour is unchanged, because the only names this module resolves are sha1, sha256, sha384 and sha512. A future hash then cannot slip through by not being SHA-1.
- **Refusals are `*errs.Error{Kind: fips.ErrNotApproved, Detail: <kdf or use>}`, not `&CryptoError{Op, Err: ErrFIPSNotApproved}`.** `errors.Is(err, ErrFIPSNotApproved)` holds as before (luks2 re-exports the sentinel by value). The detail still names the algorithm, because the SHA-1 tests assert "sha1" in the message. cmd/luks2's own pre-flight refusal still builds a `luks2.CryptoError`, until H11.
- `IsFIPSCompliantKDF` stays in pkg/luks2 (B.6: DELETE at H13). It depends on the public KDF-type constants that move in H4/H9, and nothing in the internal packages needs it.

## H3c (af)

- **API.** `af.Params{Stripes, Hash}` mirrors the on-disk `af` object. `af.Codec{Custody, Rand, FIPS}` carries the three seams as fields (§E: internal seams are parameters or fields). The operations are `Split(key, Params)` and `Merge(split, keySize, Params)`. The structural and policy questions are `ValidateWriteHash`, `ValidateReadHash` and `RequireApprovedHash(mode, name)`. pkg/luks2 builds its codec at each call with `afCodec()`, reading its custody, cryptoRand and fipsMode seams, so a test that substitutes one of them is honored.
- **Merge lost its `splitLen` parameter.** Every caller passed `keySize*stripes`, which Merge can compute itself. Merge consumes exactly that many bytes and refuses a shorter split (ErrInvalidKeyslot); a longer one, the sector-aligned area, is trimmed. Production behaviour is unchanged. The tests that asserted "a splitLen inconsistent with the geometry is refused" now assert that a short split is refused and that trailing alignment never reaches the key.
- **Shared kinds live in internal/errs.** `ErrUnsupportedHash`, `ErrSHA1NotWritten` and `ErrInvalidKeyslot` are raised by af now, and by kdf and the header code from H4/H5. No internal package sits below all of those except internal/errs, so `errs/errors.go` holds these module-wide kinds and pkg/luks2 re-exports them by value. A kind raised by only one package stays in that package (secret.ErrProtectedMemory, fips.ErrNotApproved). This is §C.2 rule 6 generalised from the device kinds, and it is where H13's consolidated generic kinds (`ErrUnsupported`, `ErrInvalidArgument`, ...) will live.
- `clearBytes` in util.go stays: about 20 pkg/luks2 sites still use it. af calls the `clear` builtin directly.

## H3d (areacipher)

- **API.** `areacipher.Parse(spec) (Transform, bool)` owns the closed spec table, which was format.go's XTS half plus keyslotarea.go plus keyslotscreen's spec map. The other entry points are `Specs()`, `Default()` (the transform `WriteSpec` names), `Transform.XTS()` and `Transform.ValidateKeySize`, and the two custody-aware operations `Transform.EncryptEnclave(c, data, key)` and `Transform.DecryptEnclave(c, data, key)`. There are also the size validators `ValidateXTSKeySize`, `ValidateVolumeKeySize` and `WritableAreaKeySize`. pkg/luks2 keeps `parseKeyslotAreaEncryption` because it builds the public `*UnsupportedKeyslotCipherError`, which goes at H13.
- **The `cipherAlgo` parameter is gone.** Every write passed "aes" (DefaultCipher, or `opts.Cipher`, which Format's allow-list pins to "aes"), and the read path never consulted it. A cipher-name parameter that can only be one value is a validation of a constant. The two tests that passed "twofish"/"invalid" to it went with it.
- **The sector size is fixed at `areacipher.SectorSize` (512) in the exported API.** A LUKS2 keyslot area is always processed in 512-byte sectors. The unexported transform still takes a sector size so that its tests can cover other geometries. pkg/luks2's `keyslotSectorSize` is now `areacipher.SectorSize`.
- **Direction is a typed enum, not a bool** (clean-code §3.4). The exported surface is the two named operations, and the bool flag stays inside `xtsSectors`/`cbcSectors` as `direction`.
- **The plain-slice `encryptKeyMaterial`/`decryptKeyMaterial` are gone from production.** One was a test-only wrapper (it carried a `//nolint:unused`). The other existed only to back `encryptKeyMaterialEnclave`. The areacipher tests use local helpers over the unexported transform.
- **The scratch for a partial final XTS sector now comes from the caller's custody**, not a hidden `secret.System()`, so a refusing custody covers that path too.
- **`EncryptEnclave` now pads the AF split up to a whole `SectorSize` sector before transforming it, in custody, rather than sizing its output to `len(data)`** (local Codex review, PR #279). A keyslot's AF split is `keySize*AFStripes` (4000) bytes, which is a sector multiple for every `keySize` this package's writers can use (16, 32, 48, 64) except 24 -- a cryptsetup AES-192 volume. For that one case the old code wrote only the real, truncated ciphertext and let `writeArea`'s zero padding stand in for the rest of the final sector, instead of writing the whole encrypted padded sector cryptsetup writes for the same bytes.
  **Pre-existing, not a regression from this move**: `main`'s pre-H3d `encryptKeyMaterial` (format.go) sized its output the same way (`make([]byte, len(data))`) and called the same `xtsPartialSector`, byte-for-byte, before any code here existed. The move carried the defect forward; it did not introduce it.
  **Why it did not already show up as a merge failure**: `AFStripes` (4000) is a multiple of 32, so `keySize*4000`'s remainder mod `SectorSize` is always a multiple of 16 -- a whole number of AES blocks. XTS encrypts each block independently of its neighbors (no chaining within a sector), and `af.Codec.Merge` reads only the first `keySize*stripes` bytes of whatever it is given. Together those meant the REAL AF-split bytes always decrypted correctly despite the truncation; only the padding bytes beyond `afSplitSize` (which nothing reads) differed from what cryptsetup would have written there. A unit-level reproduction of the unfixed write-then-read shape (`TestKeyslotAreaRoundTripAES192CBCVolumeKey`, internal/areacipher) and a full `AddKey`-then-unlock reproduction on an AES-192-CBC-shaped fixture (`TestAddKeyAndUnlockRoundTripOnAES192CBCVolume`, pkg/luks2) both passed even before the fix; the discriminating assertion is the ciphertext's own length, not round-trip correctness. Confirmed against real cryptsetup 2.7.5 too: a `cryptsetup luksFormat --cipher aes-cbc-essiv:sha256 --key-size 192` image, with a second keyslot added by this library's `AddKey`, opens under both passphrases via `cryptsetup open --test-passphrase`.
  Fixed anyway, because the on-disk bytes are still wrong relative to cryptsetup's for the same AF split, and the only reason it is harmless today is `AFStripes` staying fixed at a multiple of 16 -- a coincidence of the current constant, not a guarantee the write path should depend on.

## H3e (recoverykey)

- **API.** `recoverykey.Format` is a uint8 enum with `Dashed` as its zero value, as §B.2's final `RecoveryKeyFormat` has it. The operations are `Len(n, f)`, `Render(c, key, f)`, `Hash(credential)`, `Credential(c, text)` (trim surrounding whitespace, refuse an empty or multi-line text, nothing else), `FirstLine(contents)` and `Decode(c, rendered)` (the tolerant decode for pre-text-credential volumes). The public string `RecoveryKeyFormat` stays in pkg/luks2 until H9, and maps to the enum through one table (`recoveryRenderings`) that also answers `known()`.
- `RecoveryCredential`'s refusal of a multi-line text no longer names `LoadRecoveryCredential` (an internal package cannot point at a public function that H13 deletes). It now says "read a saved file line by line". No test or caller matched the old text.
- The file reading (`readRecoveryKeyLine`, `SaveRecoveryKey`, ...) stays in pkg/luks2. B.6 moves recovery-key file I/O to internal/cli (H11) and deletes it from the library at H13, so moving it into internal/recoverykey now would just move it twice.

## H3f (command)

- **API.** `command.Tools{Dirs, Env}`, with `System()` giving the fixed system directories, PATH and LC_ALL=C. The operations are `Resolve`, `Command` and `Run` (combined output). The two seams `toolDirs` and `toolEnv` are now that value's fields. pkg/luks2 holds one transitional `tools` variable, which the fake-tool tests substitute, until the per-package sys struct exists (H9/H10c).
- `ErrFilesystemTool` is now defined as `command.ErrTool` (same text) and re-exported by value. H10c renames it to `filesystem.ErrTool`.
- The package keeps systemtool.go's `//go:build linux`. A.3 requires internal/command to build on darwin once pkg/keyprovider imports it (H10d). Stat_t.Uid exists on every unix, so that change is `//go:build unix`; it is deferred to H10d, where it can be tested with the darwin cross-build.
- The ownership rule (owner, group/other write, sticky directory) is unit-tested with constructed `os.FileInfo` values, not by chown'ing real files: "owned by another user" cannot be produced without root, and the rule only reads Lstat's result. The tests that chmod real directories to 0777 are not fault injection; they are the condition being checked.
- The duplicate resolver test left pkg/luks2; the pkg/luks2 tests that run real mkfs/blkid stand-ins through filesystem code stay.

## H4 (kdf)

- **API.** `kdf.Params` mirrors the on-disk KDF object: `Type`, `Hash`, `Salt`, and `Iterations`/`Time`/`Memory`/`CPUs` as the same optional `*int`s the JSON gives. **Deviation from the plan's "salt decoded":** `Salt` is carried as the stored base64 string, not pre-decoded bytes. The plan's single `*KDF → kdf.Params` conversion would otherwise have to fail on a bad salt, and `validateKDFCost` never inspected `Salt` at all -- routing it through a salt-decoding conversion would make a cost-only check newly sensitive to a field it has no reason to read. Only `DerivePlain` decodes it, at the point it is needed. `kdf.Deriver{Custody, FIPS}` carries the two seams, matching `af.Codec`; its operations are `Derive`, `DeriveFromSecret`, `DerivePlain`, `Calibrate`, `CalibrateWithTimer` and `SHA1Iterations`. `ValidateCost`, `DerivationWork`, `OperationBudget`, `PBKDF2FloorFor`, `ForcedPBKDF2Iterations`, `CalibratePBKDF2` and `ScalePBKDF2Iterations` are plain functions: none of them touch custody or FIPS.
- **`OperationBudget(maxKeyslots int) Work`** takes the keyslot count as a parameter rather than importing `LUKS2MaxKeyslots`, because kdf sits below internal/header in the import DAG. pkg/luks2's `operationKDFBudget` is now `kdf.OperationBudget(LUKS2MaxKeyslots)`.
- **Every moved unexported identifier stays in pkg/luks2 under its original name, as a one-line forward into kdf**, rather than being deleted at the call site. `deriveKeyPlain`, `DeriveKeyEnclave`, `deriveKeySecret`, `validateKDFCost`, `derivationWork`, `BenchmarkPBKDF2`, `calibratePBKDF2`, `scalePBKDF2Iterations`, `pbkdf2IterationFloor`, `pbkdf2FloorFor`, `forcedPBKDF2Iterations`, `sha256IterationsForSHA1`, `pbkdf2Hash`, `getPBKDF2HashFunc`, `hashOutputLen`, `deriveArgon2i`, `deriveArgon2id` and the probe/floor/ceiling constants are all thin wrappers now. This is stricter than the plan asked for, but dozens of existing unit tests (kdf_test, kdfcost_test, kdfcalibration_test, kdfbudget_test, sha1kdf_test, digestcalibration_test, keyslotcostpolicy_test, kdfiterations_test, kdfpanic_test, and production call sites in keyslot.go, format.go, keyslotscreen.go, fipsmigrate.go) call these by their unexported name or reassign them as seams; keeping the name and signature exactly as they were means none of that had to change, and the real logic still only has one definition, in internal/kdf. `keyslotCostPolicy`, `callerSuppliedCredential`, `libraryGeneratedCredential`, `minPBKDF2Iterations`, `maxKDFIterations`, `minArgon2Time/Memory/Parallel`, `maxArgon2Time/Memory/Parallel`, `pbkdf2ReferenceTargetMs`, `maxPBKDF2IterTimeMs` and `pbkdf2RecommendedIterations` are likewise now const/type/var aliases onto the kdf package values, for the same reason. `u32` and the three-argument `deriveArgon2` had no caller outside `deriveKeyPlain`'s own dispatch and are deleted rather than aliased.
- **Public types.** `KDFCalibrationError = kdf.CalibrationError`, `PBKDFIterationsError = kdf.PBKDF2IterationsError`, `Argon2CostError = kdf.Argon2CostError` (all type aliases; their Error/Unwrap/Is methods moved with them -- a method cannot be added to an alias of a foreign type). `ErrKDFCalibration`, `ErrUnsupportedKDF`, `ErrPBKDFIterationsTooLow/High` are re-exported by value. `KDFBudgetError` stays in pkg/luks2 (it reads the header-derived `scanPlan`); its `Need`/`Budget` fields are now `kdf.Work`, whose fields are exported (`PBKDF2Blocks`, `Argon2KiBPasses`) since they now cross a package boundary — `KDFBudgetError.Error()` and the two test files that construct a `kdfWork` literal were updated for the new field names and the `.Add`/`.Exceeds` method names.
- **The `CryptoError` wraps inside kdf.go became `*errs.Error`**, exactly the H3 precedent. One test, `kdfpanic_test.go`'s `TestDeriveKeyDoesNotPanicOnHeaderControlledParameters`, asserted `errors.As(err, &cryptoErr)` against the old wrap; it now asserts `*errs.Error`, which is what every one of these panic-guard refusals is now. No other test depended on the `CryptoError` text these paths used to produce.
- **Makefile `test-calibration`** now also runs `$(CALIBRATION_TESTS)` against `./internal/kdf` (no `-bench`: the two calibration benchmarks stayed in pkg/luks2, unmoved, since their own callers are the pkg/luks2-level wrappers).
- **Coverage.** `internal/kdf` has its own test suite (kdf_test.go, cost_test.go, calibration_test.go, budget_test.go, sha1_test.go, errors_test.go) rather than ports of the pkg/luks2 files named in the plan -- those files' tests kept working unchanged against the pkg/luks2-level wrappers (see above) and did not need to move; `internal/kdf`'s own suite covers the same branches directly against `Params`. Measured 95.5%, floor set at 90 in coverage-floors.txt. pkg/luks2 unit coverage measured 90.6% afterward (floor stays 87.50; was 90.78 before this step, a sampling-noise difference of the same order as across calibration runs, not a loss of tested branches).
- **A package registers the hash implementations it resolves.** The move left `internal/kdf` resolving `crypto.SHA384`/`crypto.SHA512` by name (`PBKDF2Hash`, `PBKDF2HashFunc`, `HashOutputLen`) while only pkg/luks2's blank `crypto/sha512` import registered them with the stdlib `crypto` registry; a caller of `internal/kdf` that did not also import pkg/luks2 got `crypto.Hash.New` panicking with "requested hash function is unavailable". `crypto.Hash` registration is per-package-import, not transitive through an unrelated importer, so each package that calls `.New()`/`.Size()`/`.Available()` on a `crypto.Hash` it resolves must import the matching `crypto/shaNNN` implementation itself (`internal/kdf/kdf.go` now does). pkg/luks2's now-redundant blank imports were removed.

## H5 (header)

- **API.** The on-disk model (`BinaryHeader`, `Metadata`, `Keyslot`, `KeyslotArea`, `KDF`, `AntiForensic`, `Token`, `Segment`, `Digest`, `Config`, `Requirements`, `DroppedEntry`), the JSON passthrough (`MetadataJSONError`, `unknownFields` and the `Marshal`/`UnmarshalJSON` methods), the structural validator (`ValidateHeaderStructure`, `ValidateHeaderWideStructure`), the checksum and binary-header codec (`CreateBinaryHeader`, `ReadHeaderCopyFrom`, `ReadSecondaryHeaderFrom`, `WriteHeaderTo`, `EncodeMetadata(ForHeader)`, `MarshalCanonicalJSON`), the keyslot and crypt-segment geometry checks (`ValidateKeyslot`, `ValidateKDFCost`, `CryptTableParams`) and the keyslot scan order (`CanonicalKeyslotID`, `KeyslotIDsInScanOrder`, `VolumeKeyScanOrder`, `VolumeKeyDigestsView`) all moved to internal/header. pkg/luks2's on-disk types are now aliases of internal/header's; every moved function pkg/luks2 or its tests still call under an unexported name is a one-line forward (var or thin wrapper), exactly H4's precedent.
- **`ErrInvalidHeader` joins `ErrInvalidKeyslot` and `ErrUnsupportedHash` in internal/errs**, per H3c's rule: it is raised by both internal/header and pkg/luks2 (kdfbudget.go, keyslot.go, keyslotscreen.go, keyprovider.go, unlock.go), so it has no single owner below the public API. `ErrAmbiguousJSONMember`, `ErrMetadataJSON`, `ErrMetadataTooLarge`, `ErrPrimaryHeaderCurrent`, `ErrUnsupportedLUKSVersion` and `ErrUnsupportedHeaderChecksum` are raised by internal/header alone and stay declared there, re-exported by value exactly as the shared kind is.
- **`UnsupportedRequirementError` and its `CheckRequirementsImplemented` method moved together.** A method cannot be forwarded through a package-level var the way a function can, so the one real external caller -- unlock.go's activation-time requirements check -- was updated to the exported name; everywhere else (internal/header's own `EncodeMetadata`) already calls the exported form. `UnsupportedRequirementError` is a type alias, same as the KDF error types in H4.
- **`CreateBinaryHeader`'s `MetadataSize` validation moved to the pkg/luks2 wrapper, ahead of the call into internal/header.** internal/header cannot return `ErrInvalidMetadataSize` (a pkg/luks2 sentinel), and the original order -- generate the salt, then validate the size -- has no test depending on it: `TestFormatMetadataSizeRefusesIllegalSizes` only checks the sentinel and that nothing was written. internal/header's `CreateBinaryHeader` documents that its caller must validate first and trusts the bound.
- **`WriteHeaderTo` and `WriteEncodedHeader` take `sync func(*os.File) error` as a parameter, not a package var.** internal/header defines no package-level mutable seam (the H5 done-when requirement), and pkg/luks2's `syncDevice` seam -- substituted by `fipsmigrate_crash_test.go`'s crash-safety suite to fail sync at a chosen point -- still works unchanged: the pkg/luks2-level forwards (`writeHeaderTo`, `writeEncodedHeader`) read `syncDevice` at call time and pass it through.
- **`EncodeMetadataIgnoringRequirements` is new**, factored out of `EncodeMetadata` (which now just calls it after the requirements guard). It exists because the old pattern -- a pkg/luks2 test mutates the package-level `implementedRequirements` map to get a crafted fixture with an unimplemented requirement past the guard, writes it, then deletes the entry -- no longer reaches across the package boundary: `implementedRequirements` is internal/header-private. `activation_test.go`'s `writeRequirement` now calls `EncodeMetadataIgnoringRequirements` directly instead. `requirements_test.go`'s own `TestAnImplementedRequirementIsAccepted`, which mutates the same map, moved to internal/header with it, where the mutation is same-package again.
- **Small pure helpers are duplicated rather than threaded across the layering boundary**: `parseSize`/`formatSize`/`isPowerOf2` (pkg/luks2's util.go versions are unreachable from internal/header, which must not import pkg/luks2), the two `Safe*ToInt*` overflow conversions (security.go's versions, for the same reason), and `dataSegmentIDs`/`digestCovers`/`keyslotDeclaredForAllSegments` (fipsmigrate.go and keyslotscreen.go still need their own copies for FIPS migration and keyslot screening, which did not move). Each is one to six lines; duplicating them is cheaper and less coupled than exporting pkg/luks2 internals or threading extra parameters through the whole call chain for a helper this small.
- **Test relocation.** Whole test files that were purely about logic that moved went with it, mirroring H4's "internal/kdf has its own suite" choice over porting pkg/luks2's test files unchanged: `headervalidation_test.go` (the structural-validator table), the non-conformance half of `unknownfields_test.go` (the JSON passthrough), `requirements_test.go`, the non-device half of `canonicaljson_test.go`, one test each out of `conformance_test.go` (`TestEnsureRequiredObjects`) and `header_test.go` (`TestValidateHeaderChecksumRefusesABufferTooShortForTheChecksumField`). Device-level and cryptsetup-conformance tests stayed in pkg/luks2 against the forwards; `activation_test.go` and `volumeinfo_test.go` lost their direct references to the now-foreign `unknownFields`/`structureFixture` and gained small adjustments (`Segment.SetUnknownMember`/`ClearUnknownMembers`, a local fixture) instead.
- **Coverage.** internal/header has its own suite (no production code reused from pkg/luks2's test files beyond the relocations above) and measured 93.4%, floor set at 90 in coverage-floors.txt. pkg/luks2 unit coverage measured 89.6% (floor stays 87.50).
- **Pre-existing, out of scope**: `make gosec` reports one finding, a G115 int->uint64 conversion in `internal/kdf/budget.go` (H4a, untouched by this step -- `git diff` against it is empty). Scoped to `./internal/header/... ./pkg/luks2/...` alone, gosec reports zero issues. (Coordinator note: fixed on train 1 by `fix/train-redesign-1-ci`, which clamps the negative keyslot count in `OperationBudget`.)

## H7 (dm, keyring)

- **Both packages take their seams as parameters, not as package-level
  state.** internal/dm's functions (`CreateTarget`, `RetryWhileBusy`,
  `PollUntil`, `NodePath`/`MapperPath`/`MapperDir`, `IsOurNode`,
  `RemoveMappingNodes`, `PlaceNode`, `IsDanglingSymlink`, `IsNoSuchDevice`)
  take the clock, the device directory and the block-node stat function as
  arguments. internal/keyring's `Syscalls{SessionRing, Add, Search, Revoke,
  Unlink}` is the one seam value, threaded through `AddVolumeKey` and
  `(*VolumeKey).Release` rather than held in a package var. Neither package
  has a mutable package-level var of func or interface type outside its
  errors.go (§E's enforcement test is not on until H13, but there is no
  reason to write code it will later flag).
- **pkg/luks2 keeps its transitional seams exactly where they were** --
  `dm` (the `deviceMapper` struct), `devDir`, `nodeRdev`/`statRdev`,
  `blockNodeRdev`/`statBlockRdev`, `makeBlockNode`, `dmClock`, and the
  `keyring` var (now typed `keyringpkg.Syscalls`) -- because `devDir` and
  `nodeRdev` are also read by medium.go and loopdev.go, which H7 does not
  touch, and because `dm` and `keyring` are reassigned directly by a few
  dozen existing tests. Every pkg/luks2-level function that used to hold the
  logic (`createTarget`, `retryWhileBusy`, `pollUntil`, `isOurNode`,
  `removeMappingNodes`, `placeNode`, `ensureDeviceNode`, `waitForDeviceReady`,
  `mappedDevicePath`, `removeCreatedMapping`, `isNoSuchDevice`,
  `addVolumeKeyToKeyring`, `keyringDescription`, `pinToOSThread`,
  `runOnDiscardedThread`, `keyringFailure`) keeps its name and signature and
  becomes a thin forward, the H3f/H4 precedent. No caller outside
  devicemapper.go and keyring.go -- not unlock.go, not mount.go, not a single
  test -- needed to change.
- **`keyringVolumeKey` wraps `keyringpkg.VolumeKey` by embedding** rather than
  by alias, so the struct keeps its lowercase `release()`/`tableKeyID()`
  methods (callers: unlock.go, CheckKeyringAvailable, a dozen tests) while the
  embedded type's fields (`ID`, `Ring`, `Description`, `KeySize`) are
  necessarily exported, since they now cross a package boundary. The handful
  of tests that poked the old lowercase fields directly were updated to the
  exported names; everything that only called `.release()`/`.tableKeyID()`
  was not.
- **Sentinels and error types that are used only from the moving code are
  moved and re-exported by value** (§C.2 rule 6 / H3c): `ErrKeyring`,
  `ErrKeyringUnavailable`, `ErrKeyringBlocked`, `ErrKeyringUnsupported`,
  `ErrKeyringQuotaExhausted`, `ErrKeyringFailed`, `ErrKeyringEntryExists`,
  `ErrKeyringKeyNotReleased` are now `= keyringpkg.ErrXxx`, and
  `KeyringUnavailableError` is now `= keyringpkg.UnavailableError` (the H4
  type-alias precedent). **Sentinels used by code that stays in pkg/luks2 are
  not moved**: `ErrInvalidMappingName` (security.go's `ValidateMappingName`),
  `ErrMappingBusy`, `ErrVolumeNotUnlocked`, `ErrNotBlockDevice` are raised by
  more than the moving code, so they stay pkg/luks2 sentinels unchanged.
  internal/dm instead gets two sentinels of its own, `ErrNameTooLong` and
  `ErrNodeUnverified`, that exist purely so `createTarget`'s and
  `placeNode`'s pkg/luks2-level forwards can tell "the belt-and-suspenders
  check fired" apart from "the syscall failed" and attach the right
  pkg/luks2 sentinel (`ErrInvalidMappingName`, `ErrDeviceNodeUnverified`) at
  the boundary -- the errs.At translation §C.2 rule 4 describes, one layer
  early because dm cannot hold the pkg/luks2 type it would otherwise wrap.
- **`DeviceError`/`VolumeError` stay in pkg/luks2, unmoved.** They are
  generic wrap-with-an-Op-and-a-device-name structs used across the whole
  package, not something internal/dm raises on its own account, and
  internal/dm cannot construct a pkg/luks2 type regardless. The pkg/luks2
  forwards build them from whatever internal/dm returns, exactly where the
  original code did.
- **Coverage.** internal/dm measured 72.3% (68/94); CreateTarget's happy path
  issues a real DM_DEV_CREATE ioctl and needs root, so it is 19% covered by
  the unit suite and the rest by the combined tier. Per coverage-floors.txt's
  rounding rule, the half-point floor (72.0) has zero statements of slack, so
  the unit floor is 70 with the combined floor at 90. internal/keyring
  measured 90.4% (75/83) entirely from fakes -- none of its moved functions
  issue a real add_key/keyctl syscall, Live() is the only uncovered line --
  but the brief holds it to the same root-only treatment as dm (a sandboxed
  CI unit job cannot be assumed to have the keyring syscalls either, the same
  reasoning ErrKeyringBlocked documents), so its floors are unit 87.50 (the
  half-point, with 2 statements of slack) and combined 90.

## Phase-wide gotchas

- FIPS strict suite and 386/arm/amd64/arm64 cross-vet: NOT yet run for this phase (they were scheduled for the end of H4). The cryptsetup interop/integration suite was not run either: no ◆ step is in H0–H4.
- forbidigo: golangci's uniq-by-line hides a finding that shares a line with another linter's.
- pkg/luks2 unit -race runtime moved between 142 and 177 s across runs against the 240 s target, because of host load.

## H6 (device)

- **Pinned/Locked/Claimed, without ctx.** `internal/device` gets §B.1's three
  types now, ahead of H8/H9: `Pinned` is an opened, unlocked descriptor
  (`OpenPinned`); `(*Pinned).Lock(mode, wait, clk, lockDir, openLockFile,
  held)` takes the node flock then cryptsetup's lock and returns `*Locked`;
  `(*Locked).Claim(op, flag, openFile)` returns `*Claimed`. None of the four
  takes a ctx -- H8 is out of this lane's scope -- so `Lock`'s wait is still
  `<-clk.NewTimer(d).C()`, exactly as `acquireFileLock` already did. `Locked`
  also has `Unlock` (releases both locks, does NOT close the descriptor) and
  `Release`-equivalent is composed by the caller (`Unlock` then close), which
  is what lets `LockExisting` share the same type for the shared read lock an
  activation takes on a descriptor it already owns and must not close.
- **`requireSameDevice` is deleted, not replaced.** The exclusive claim used
  to reopen the operator's PATH a second time and then fstat-compare the two
  descriptors, refusing with `ErrDeviceChanged` on a mismatch. `Claim` instead
  reopens the LOCKED descriptor's own `/proc/self/fd/<fd>` entry -- the same
  trick `keyslotDevice.mediumPath` already used for O_DIRECT reads -- so a
  retargeted symlink cannot reach a different file: there is no comparison to
  make, because the path is never resolved again. Two tests that exercised
  the old comparison (`TestFormatWritesOnlyTheFileItLocked`,
  `TestTheExclusiveClaimMustBeTheLockedDevice`) asserted `ErrDeviceChanged` on
  a retarget; they are rewritten (the first renamed
  `TestFormatClaimsTheLockedDescriptorRegardlessOfASymlinkRetarget`, the
  second `TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget`) to
  assert the new invariant instead: the operation SUCCEEDS on the file that
  was locked, and the file the symlink now names is never touched. `ErrDeviceChanged`
  stays declared (device.ErrChanged, re-exported) because B.6 keeps it; nothing
  in this lane's code raises it any more.
- **Shared sentinels, `LockTimeoutError` and `DeviceError` move to
  internal/device.** `ErrDeviceNotFound`, `ErrPermissionDenied`,
  `ErrDeviceInUse`, `ErrDeviceChanged`, `ErrDeviceCacheStale`,
  `ErrLockContended`, `ErrMetadataLockUnavailable` are re-exported by value
  (owner ruling on `ErrMetadataLockUnavailable`, H0, generalised to the rest:
  C.2 rule 6). `LockTimeoutError` and `DeviceError` become type ALIASES
  (`type LockTimeoutError = device.LockTimeoutError`, `type DeviceError =
  device.Error`) rather than new types, so every existing `&DeviceError{...}`
  literal across the package -- devicemapper.go, filesystem.go, loopdev.go,
  unlock.go, none of them this lane's files -- keeps compiling unchanged.
  `ErrDirectIOUnsupported` also becomes a device-owned kind
  (`device.ErrUnsupported`), one step ahead of C.3, which folds it into the
  generic `ErrUnsupported` only at H13: it is raised from code that now lives
  in internal/device, and A.3's own wording for the off-Linux fallback is
  "fails closed with ErrUnsupported".
- **No package-level mutable seam vars in internal/device, by construction
  rather than by a lint.** Every fault-injection point (`openFileFunc`,
  the cryptsetup lock-file opener, `sysDevBlockRoot`, the rdev lookup, the
  read-past-cache function, the lock-held test hook) is a PARAMETER of the
  internal/device function that needs it. pkg/luks2 keeps its existing
  package vars of the same names and passes their current value in at each
  call, so every one of that package's existing fault-injection tests
  (`openFileFunc`, `dropDeviceCache`, `fileLockHeld`, `cryptsetupLockDir`,
  `sysDevBlockRoot`, `readDeviceDirect`) keeps compiling and passing
  UNCHANGED -- the H3/H4 precedent of "keep the old name, forward the call"
  generalises from functions to call-site parameters here. `openCryptsetupLockFile`
  is the one exception: nothing outside its own test used it, so that test moved
  to internal/device entirely instead of keeping a forwarding var.
- **`CompareRegion` takes the read-past-cache function as a parameter, not a
  call to `ReadPastCache`.** Early draft had it call `ReadPastCache` directly;
  that silently stopped routing through pkg/luks2's `readDeviceDirect` seam,
  which two tests (`TestRequireCacheMatchesMedium`,
  `TestMigrateToFIPSNeverReadsTheDataSegmentToCompare`) depend on to track how
  far a comparison reads. Fixed by threading the function through as a
  parameter (`readPastCache func(path string, off int64, n int) ([]byte,
  error)`), which pkg/luks2's `requireCacheMatchesMediumOf` satisfies with its
  own `readDeviceDirect` var.
- **medium.go splits at the header-size boundary, not before.** The O_DIRECT
  read, the sysfs loop-device stack walk and the byte comparison
  (`MediumSources`, `CompareRegion`, `ReadPastCache`) move to internal/device
  wholesale. `requireCacheMatchesMediumOf` -- the part that knows
  `LUKS2HeaderSize`/`LUKS2HeaderMinSize`/`LUKS2HeaderMaxSize` and
  `isPowerOf2` -- stays in pkg/luks2, because internal/device sits below
  internal/header in the import DAG (A.2) and H5 (header) has not landed in
  this lane's base. H5 is expected to let this move the rest of the way by
  switching these three constants to the header package's, per the lane
  brief.
- **A.3's Linux/unix split, where the identifiers genuinely differ.**
  `size_linux.go`/`size_other.go` (BLKGETSIZE64 does not exist off Linux),
  `medium_linux.go`/`medium_other.go` (O_DIRECT and `Statfs_t.Type` do not
  either; `ReadPastCache` fails closed with `ErrUnsupported` off Linux, and
  `MediumSources`/the sysfs walk stay unsplit because they are ordinary
  os/filepath calls that simply find nothing off Linux), `drop_linux.go`/`drop_other.go`
  (Fadvise). The node flock, the cryptsetup lock-file protocol and the O_EXCL
  claim needed no split: every unix call they use (`Flock`, `Openat`,
  `Mkdir`, `Fstatat`, `Major`/`Minor`) exists for darwin too, confirmed by
  `GOOS=darwin go vet ./internal/device/`.
- **BLKDISCARD stays in pkg/luks2's wipe.go, unmoved.** A.3 lists it beside
  the other Linux-only facilities, but the lane brief's own enumeration of
  what this lane owns does not include it, and nothing else in this lane
  touches trim/discard. Left for whichever lane absorbs the rest of wipe.go.
- **Coverage.** `internal/device` has its own test suite, ported from and
  extending pkg/luks2's `cryptsetuplock_test.go` (moved in full -- its
  `openCryptsetupLockFile` substitution became a parameter passed directly at
  the call site) and `medium_test.go` (ported, `newFakeSysfs` passes its root
  and rdev map as `MediumSources` parameters instead of substituting package
  vars). Measured 91.9%, floor set at 90 in coverage-floors.txt. pkg/luks2
  unit coverage measured 90.7%/91.0% afterward (floor stays 87.50).
- **The integration tier's pinned-path tests were missed by the rewrite
  above and caught up separately (fix-train1-pinned).**
  `pinnedpaths_integration_test.go` runs the same retargeted-symlink
  scenarios against real loop devices and still asserted the deleted
  `requireSameDevice`/`ErrDeviceChanged` pairing on two tests. One of them
  (`TestWipeKeyslotDoesNotClaimOneDeviceAndZeroAnother`, renamed
  `TestWipeKeyslotRefusesAnActiveDeviceDespiteARetarget`) combines the
  retarget with an ACTIVE device, so it does not exercise H6's success path
  at all: `Locked.Claim`'s O_EXCL reopen is always against the device that
  was locked, and that device is busy, so the pre-existing, independent #246
  check (`ErrDeviceInUse`, predates H6) refuses it regardless of the
  retarget -- confirmed by `TestWipeRefusesADeviceInUse`, which asserts the
  identical refusal with no symlink involved at all. The fix is to expect
  `ErrDeviceInUse`, not `ErrDeviceChanged`, with A and B both untouched; this
  is not the "operation succeeds on the locked device" invariant and should
  not be changed to assert success. The other
  (`TestWipeAndTokenWritesStayOnTheLockedLoopDevice`, kept its name) uses two
  IDLE devices, so it does exercise the success path and is rewritten to
  match `TestTheExclusiveClaimTargetsTheLockedDescriptorDespiteARetarget`:
  `Wipe` now succeeds on the locked device (checked via `ReadHeader` no
  longer reading as LUKS2 after a header-only wipe), exactly like
  `ImportToken` already did.

## H8 (ctx)

- **The deterministic shape for every clock-based wait is "select, then
  check."** Every wait that used to be `<-clk.NewTimer(d).C()` is now:

  ```go
  t := clk.NewTimer(d)
  select {
  case <-ctx.Done():
  case <-t.C():
  }
  t.Stop()
  if err := ctx.Err(); err != nil {
      return ..., err
  }
  ```

  Not the more obvious `select { case <-ctx.Done(): return ctx.Err(); case
  <-t.C(): }`. `clock.Fake.NewTimer` runs its `OnWait` hook and pre-fills the
  timer's channel *before* returning the timer (H2), so if `OnWait` cancels
  ctx, both channels are ready by the time the `select` runs, and Go's
  `select` picks among ready cases at random. A test using `OnWait` to cancel
  mid-wait would then be deterministic only up to a coin flip. Checking
  `ctx.Err()` unconditionally after the `select` -- rather than inside a
  `case` -- removes the coin flip: whichever case the runtime happens to
  pick, the explicit check immediately afterward reports the cancellation
  every time. This is the one shape used in `internal/device` (the node
  flock and cryptsetup lock polls), `internal/dm` (`RetryWhileBusy`,
  `PollUntil`), and `pkg/luks2/loopdev.go` (`waitForLoopNode`,
  `waitForDetach`), and it is what makes every one of those cancellation
  tests a plain `clk.OnWait(func(time.Time) { cancel() })` with no second
  goroutine.
- **`PollUntil` gained a second return value.** It used to be `func(clk,
  timeout, interval, done) bool`; a cancelled ctx is not "the condition never
  held," so it is now `(met bool, err error)`, with `err` non-nil only when
  ctx ended the wait. Every pkg/luks2-level caller (`pollUntil`,
  `waitForDeviceReady`, `mappedDevicePath`) was updated to check `err` before
  `met`.
- **KDF derivation and calibration are checked before, not during.**
  `crypto/pbkdf2.Key` and `argon2.IDKey` have no interruption point, and
  wrapping either in a goroutine racing ctx would leave an unsupervised
  derivation running after this function returned -- exactly the orphaned
  goroutine go-style forbids. So `kdf.Deriver.DerivePlain` checks `ctx.Err()`
  once immediately before dispatching to the KDF, and once more immediately
  after it returns: cancelled-before skips the derivation entirely;
  cancelled-during lets the derivation finish and then destroys the output
  (`clear(key)`) instead of handing it back. `kdf.CalibratePBKDF2`'s probe
  loop applies the same "check, then one uninterruptible unit of work" shape
  once per probe. `internal/kdf`'s own suite proves both halves
  deterministically (a pre-cancelled ctx for the "before" case); proving the
  "destroy after" case needs ctx to go Done() *while* a real derivation is
  running, which no clock seam reaches, so that one test
  (`TestDerivePlainCancelledDuringDerivationDestroysOutput`) uses a real
  `context.WithTimeout` against a derivation sized to outlast it by roughly
  two orders of magnitude -- generous enough that it is not a flake risk, in
  the same spirit as the exec cancellation tests below.
- **The keyslot scan's "between keyslots" check lives in the scan loop, not
  in the KDF.** `getMasterKeySlot`'s loop checks `ctx.Err()` once at the top
  of every iteration, before even looking at that iteration's keyslot. A
  keyslot skipped for cause (wrong type, an id cryptsetup cannot address) is
  free, so cancelling right after one is skipped and before the next is
  examined is what `TestGetMasterKeySlotCancelledBetweenKeyslotsReturnsCtxErr`
  drives, with a `context.Context` double whose `Err()` counts its own calls
  and starts reporting `Canceled` after a chosen one -- deterministic,
  without a clock, because this loop has nothing to do with time.
- **Write transactions are cancellable at exactly one place:
  `keyslotWriteStep`.** It already ran before every write a keyslot
  operation makes (material, header, secondary-header repair, a wipe) for
  the crash-safety suite's benefit (H6); it is now also the only place ctx is
  consulted inside a write transaction (`return ctx.Err()`, nothing else).
  Every write-path function (`writeArea`, `writeHeader`,
  `wipeKeyslotArea`, `addKeyslotWithMasterKey`, `removeKeyslotOn`, …) takes
  ctx and threads it to this one checkpoint and nowhere else inside the
  transaction, so "ctx is consulted only at consistent on-disk states" is
  true by construction rather than by a rule every call site has to remember.
  `TestAddKeyslotWithMasterKeyCancelledBeforeWriteLeavesNoPartialKeyslot`
  drives it with a pre-cancelled ctx and reads the header back to confirm no
  keyslot was written at all.
- **Rollback and cleanup run under `context.WithoutCancel(ctx)`, matching
  the dm-rollback rule in §D.2 exactly, generalised to keyslot rollback.**
  `rollBackAddedKeyslot` and `rollBackChangedKeyslot` each do
  `ctx = context.WithoutCancel(ctx)` as their first line: a keyslot already
  written has to come back out whether or not the ctx that asked for the
  write is still live.
  `TestRollBackAddedKeyslotRunsDespiteACancelledCtx` adds a keyslot, cancels
  ctx, and asserts the rollback still runs to completion. `Locked.Unlock`,
  `Claimed.Close`, `keyringpkg.VolumeKey.Release` and `Pinned.Close` take no
  ctx at all, by the same reasoning one step further: a release that could
  be skipped by cancellation is not a release.
- **`internal/command` gained the exec row of §D.2 that this lane's brief
  said already existed.** It did not: `Tools.Command` built its `*exec.Cmd`
  with plain `exec.Command`. It now uses `exec.CommandContext`, runs the
  program in its own process group (`SysProcAttr{Setpgid: true}`), and its
  `Cancel` sends `SIGTERM` to the whole group (`syscall.Kill(-pid, …)`) so a
  cancelled `mkfs.*`/`fsck.*`/`zpool`/`zfs` cannot leave a forked helper
  behind, bounded by a `WaitDelay`. One Go stdlib wrinkle this ran into:
  `Cmd.Wait` only substitutes `ctx.Err()` for the process's own exit error
  when `Cancel` succeeds **and** the process happens to exit 0 afterward --
  never true for a SIGTERM-killed program -- so `Tools.Run` checks
  `ctx.Err()` itself once `CombinedOutput` returns and prefers it over the
  raw "signal: terminated", which is what makes
  `errors.Is(err, context.Canceled)` hold for a caller the way §D.2
  requires. `TestRunKillsTheWholeProcessGroupOnCancel` proves the group-kill
  with a real grandchild process; the one portability note it leaves behind
  is that a terminated grandchild can sit as a zombie under a container's
  PID 1 that never reaps orphans, so the test reads `/proc/<pid>`'s `State`
  (`Z` or gone) rather than `kill(pid, 0)`, which a zombie still answers.
- **Where ctx was NOT threaded, and why.** The brief's own rule --
  "every internal function that does I/O, takes a lock, runs a KDF, waits,
  or execs" -- is read here as the objective, not as a mandate to add a ctx
  parameter to every single-syscall helper reached only through an
  already-ctx-checked caller. Left unchanged, deliberately:
  - Single-stat/single-read helpers with no wait and no seam of their own
    (`device.StatRdev`, `device.Size`, `device.CacheIsTheStorage`,
    `device.MediumSources` and its sysfs-walk helpers, `dm.IsOurNode`,
    `dm.IsDanglingSymlink`, `openCryptsetupLockDir`). Each is reached only
    from a function that already checks ctx at its own entry or wait point;
    a stat(2) cannot be meaningfully cancelled mid-flight, and D.1 already
    exempts pure accessors for the same reason.
  - `pkg/luks2.openDevice`, `DeriveKeyEnclave`, `deriveKeySecret`,
    `deriveKeyPlain`, and the `passphraseKDF`/`importToken`/`killKeyslot`
    seam variables keep their pre-H8 signatures and pass
    `context.Background()` to the internal package underneath. Every one of
    them is a test-substitution seam with upwards of a dozen existing
    `_test.go` call sites that assign a bare function literal to it
    (`passphraseKDF = func(p []byte, kdf *KDF, keySize int) (...)  {...}`
    fifteen times over, across nine files); changing the seam's shape for
    H8 would mean rewriting all of them for a derivation path that
    `internal/kdf`'s own suite already proves cancels correctly in
    isolation. The real ctx reaches `kdf.Deriver` through every call that
    does carry it (`passphraseKDF`'s caller, `unlockKeyslotFrom`, does); only
    this one forwarding seam still pins it to `Background()`, and H9's new
    API is where these seams are rebuilt anyway.
  - `keyring.RunOnDiscardedThread` takes no ctx: it hands `fn` to a goroutine
    on a thread that is deliberately never returned to the scheduler (H7's
    rationale), so there is no safe point to interrupt it from outside, and
    nothing it calls (`AddVolumeKey`, the keyring syscalls) blocks long
    enough to need one.
  - `internal/dm.CreateTarget`, `RemoveMappingNodes`, `PlaceNode` and
    `internal/device.CompareRegion`/`ReadPastCache` take ctx and check it
    once at entry, but do not `select` on it: each is a single ioctl or a
    single bounded read, not a retry loop, so there is no second point
    inside them where a wait could be observed.
- **pkg/luks2's exported functions pass `context.Background()` internally
  and keep their current signatures**, exactly as the brief scopes this
  step: `Format`, `AddKey`/`ChangeKey`/`RemoveKey`/`KillSlot`/`KillKeyslot`,
  `Unlock`/`UnlockWithVolumeKey`, `Lock`, `Wipe`/`WipeKeyslot`,
  `MigrateToFIPS`, `ImportToken`/`RemoveToken`, `Mount`,
  `MakeFilesystem`/`MakeFilesystemWithOptions`,
  `CheckFilesystem`/`CheckFilesystemDetailed`, `SetupLoopDevice`,
  `DetachLoopDevice`/`DetachLoopDeviceState`. A few already took ctx ahead
  of this lane (`EnrollKeyProvider`, `UnlockWithProvider`,
  `CommandKeyProvider.Passphrase`) from the KeyProvider work; those pass
  their caller's ctx through unchanged. H9 is where `context.Background()`
  at these boundaries becomes the caller's own ctx.

## H12a (test-infrastructure relocation)

- **The API-independent half of §E's relocation table, done.** `test/harness`
  -> `test/internal/harness`, `test/labstrings` -> `test/internal/labstrings`
  (both now importable only from inside test/, via Go's own `internal/`
  visibility rule -- DESIGN.md's "only test/ may import them" is enforced by
  the compiler, not by convention). `test/covergate`, `test/*/cmd/*` and
  `test/integration/cmd/docker-run` -> `test/tools/<name>/`:
  `luks2-testreap`, `release-gate`, `require-tool`, `releasability-gate`,
  `docker-run`, `covergate`, alongside `apidump` which was already there.
  Every import, Makefile target, CI workflow path, `coverage-floors.txt` row,
  `test/integration/Dockerfile` build/entrypoint line and doc reference
  (`ARCHITECTURE.md`, `TESTING.md`, `RELEASABILITY.md`) that named a moved
  path is updated, including the self-referential ones (`DefaultAllowList`'s
  own fixture pattern in `allowlist.go`, the `require-tool`/`release-gate`
  usage comments, `workflows_test.go`'s asserted `release.yml` string,
  `releasability-gate`'s own no-checkout test, which copies and re-runs
  `test/internal/labstrings` under its new path).
- **No `*_integration_test.go` file was moved or converted** (wave B's job,
  per the lane brief): the 15 black-box and 11 white-box pkg/luks2 files, the
  g-compat files and `test/integration/pkg/*`'s split are untouched in
  location and API usage. Where one of those files only needed its `test/harness`
  IMPORT STRING updated to the new path (`leakledger_integration_test.go`,
  `volumename_integration_test.go`), that one-line update was made, same as
  every other import of the moved package.
- **That import update, in those two files only, cannot build.** Go's
  `internal/` visibility is enforced by the toolchain: a package rooted at
  `.../test/internal/harness` may only be imported from a package whose own
  import path starts with `.../test/`. `pkg/luks2/leakledger_integration_test.go`
  and `pkg/luks2/volumename_integration_test.go` live under `pkg/luks2`, outside
  that tree, so `GOWORK=off go vet -tags integration ./...` fails on exactly
  those two files with "use of internal package ... not allowed" -- a direct,
  unavoidable consequence of the relocation DESIGN.md asks for, not a defect
  introduced here. Both files are named by the relocation table's "15
  black-box" (`volumename`) and "11 white-box" (`leakledger`) rows, so wave B's
  move of each into `test/integration/{luks2,dmcrypt,loop,wipe}/` or
  `test/integration/{dm,keyring,header,kdf,device,filesystem}/` resolves it:
  once they live under `test/`, the same import is legal. Until wave B lands,
  `go vet -tags integration ./...` is red on these two files alone; every
  other check in this lane's list is green.

## H9 (new pkg/luks2 API: Volume, Key/volkey, Header, Target -- partial)

- **`internal/volkey` is a thin wrapper over `internal/secret`, not a new
  custody mechanism.** `Key{enclave, keyslot}` and `New(e, keyslot) *Key`;
  `Keyslot() int`, `Size() int`, `Destroy()` (nil-safe, idempotent,
  outcome dropped -- the `secret.Custody.Release` precedent). `Borrow(op,
  k, fn)` is `secret.Borrow` under the key's own name, so the
  `ErrProtectedMemory` translation is inherited rather than reimplemented.
  Measured 100%, floor 90 in coverage-floors.txt.
- **`errs.Error` gains `Op`, `Path` and the unexported `pkg` prefix field,
  plus `errs.At(pkg, op, path, err)`, deferred from H1 to exactly here**
  (H1's own note: "Op and Path (and errs.At) come in H9, together with the
  boundary that fills them in"). `At` fills Op/Path only on an `*Error`
  that does not have them yet (a direct type assertion, not
  `errors.As` -- every internal package already returns `*errs.Error`
  undecorated, never wrapped a second time) and passes anything else
  through unchanged, so it never stacks a second wrapper. `Error()` only
  emits the pkg/Op/Path head when one of them is set; since every one of
  the 235+ existing call sites leaves them unset, every existing error
  string is byte-identical to before this change (checked: full-module
  build and the complete pkg/luks2 unit suite, unchanged). Rule 3's
  sentinel-text prefixing ("luks2: no room...") is NOT done here --
  nothing yet needs `Error()` to strip it back out, and that is explicitly
  H13's sentinel consolidation.
- **`pkg/luks2`'s `Volume` is new, additive, and reuses -- never replaces
  -- the package's existing transitional seam vars.** `Volume.sys` is a
  private struct read ONCE, in `Open`, from the CURRENT value of
  `openFileFunc`, `cryptsetupLockDir`, `fileLockHeld`, `custody`,
  `cryptoRand` and `fipsMode` (plus a new `clock.System{}` and
  `DefaultLockWait`, overridable per-Volume by `WithLockWait`). This is
  deliberately NOT the full seam-to-`Volume.sys` migration DESIGN.md §E
  describes and the lane brief asks for: the other ~30 seam vars
  (`dm`, `keyring`, `devDir`, `tools`, `syncDevice`, the kdf/header
  forwarding vars, ...) back code this step does not touch or reimplement
  (format internals, token, recovery, FIPS migration, mount, filesystem,
  loop, keyring, device-mapper), and moving them now, unused by anything,
  would be churn against code a later step still owns under its current
  shape. What IS true now: every new `Volume` method reads its seams
  through `v.sys`, never a bare package var, so nothing in THIS step
  reintroduces global mutable state. The remaining vars stay exactly where
  H3-H7 left them, transitional, until the step that actually rewrites
  their callers absorbs them.
- **`Open` validates the path through the existing `ValidateDevicePath`**
  (absolute path, exists, regular-file-or-block-device) rather than
  inventing a second check: this is also what makes `ErrDeviceNotFound`
  reachable from `Open` at all -- `device.OpenPinned`'s own failure path
  (`ClassifyOpen`) does not classify `ENOENT` itself, only
  `EPERM`/`EBUSY`, so without this call a missing path would surface as a
  bare `*fs.PathError`.
- **Header is a deliberately PARTIAL read model.** `UUID`, `Label`,
  `Subsystem`, `SequenceID`, `Requirements`, `Dropped` and `MarshalJSON`
  are implemented, backed by `(*Volume).Header`/`SecondaryHeader` (shared
  lock) and `RestorePrimaryHeader`/`ReplacePrimaryHeader` (exclusive lock
  + claim; `RestorePrimaryHeaderWithOptions`'s core is extracted into
  `restorePrimaryHeaderCore(f, path, force)` so the old function and the
  two new methods share one implementation, byte-identical behavior
  checked against the full existing `RestorePrimaryHeader*` test set).
  `Segments()`, `Tokens()` and `Keyslots()` are NOT implemented. Each
  needs a type DESIGN.md §B.2 names `Segment`, `Token` and `KeyslotInfo`
  respectively -- and all three names are ALREADY exported, alive
  identifiers in this package with a DIFFERENT shape than the new API
  needs:
  - `Segment` and `Token` are currently `= header.Segment` / `=
    header.Token` (H5's alias precedent): the raw on-disk JSON shape, not
    the clean value DESIGN.md's dispositions (B.6) ask for. `Segment`'s
    blast radius is small (one production site in `format.go`, a dozen
    test literals) and could plausibly be repointed in a follow-up. `Token`
    cannot be touched here: `keyprovider.go`'s existing `KeyProvider`
    interface, `fido2Provider`, `enrollWithToken`, `importTokenLocked` and
    every FIDO2 helper are built on the OLD `Token` shape (FIDO2 fields and
    all), and that code is explicitly another lane's (pkg/keyprovider,
    H10d) to move, not this one's to break first.
  - `KeyslotInfo` already exists (`keyslot.go`) with `Priority int`,
    `KDFType string`, `PBKDF2Iterations`, `Argon2Time`, `Argon2MemoryKB`,
    `Argon2Parallel` -- fields the new `KeyslotInfo{..., Priority
    Priority, KDF KDFParams}` replaces outright, not extends. Redefining
    it in place would break every existing `AddKey`/`ChangeKey`/
    `ListKeyslots` test that reads those fields, for code this step does
    not touch.
  - `KeyProvider` (the interface) has the same problem one level up: its
    method set would have to change (`Token() Token` with the new shape,
    ctx-first `Passphrase`), and Go does not allow redeclaring an
    interface under one name with two method sets. `UnlockWithProvider`,
    `AddToken`/`SetToken`/`RemoveToken` and `Enroll` are blocked
    transitively by this and by the `Token`/`KeyslotInfo` blocks above and
    are NOT implemented.
  - `DefaultKDFType` already exists (`kdf.go`) as `func() string`; the
    new API's `func DefaultKDFType() KDFType` cannot be declared beside it
    (Go has no overloading by return type). Not implemented; nothing calls
    for it internally since `Format`/`KDFParams` are not implemented
    either (see below).
  - `ValidatePassphrase` already exists as `func([]byte) error`; the new
    API's `func(*enclave.MemoryEnclave) error` cannot be declared beside
    it either. Not implemented.
  - `RecoveryKey` already has an exported FIELD named `Format`
    (`RecoveryKeyFormat`); a method `(*RecoveryKey) Format()` cannot share
    that name with the field. Not attempted.
  This is a genuine, structural finding, not a scheduling gap: B.6 disposes
  each of `Segment`, `Token`, `KeyslotInfo` and several sentinel renames as
  though the old identifier's shape changes IN PLACE at the same moment the
  new API arrives, but the lane brief holds every other lane's code (and
  this lane's own un-rewritten `format.go`/`keyslot.go`/`keyprovider.go`/
  `token.go`/`recovery.go`/`fipsmigrate.go`) frozen on its current shape
  until ITS OWN step touches it. The two cannot both be true for an
  identifier two steps need under conflicting shapes at once. Flagged for
  the coordinator / owner: either these specific renames move earlier
  (coordinated with H10d/keyprovider and whichever step rewrites
  `keyslot.go`), or H9's "beside" scope is understood to exclude exactly
  the identifiers B.6 marks KEEP-with-a-different-shape, same as it
  already excludes RENAME/MOVE/DELETE ones by construction.
- **`Key`/`Unlock`/`Target` have no such collision** (new names, or a
  method on `*Volume` beside an unrelated package-level function of the
  same name -- Go methods and package-level identifiers do not share a
  namespace) and are implemented in full against real formatted temp
  files, no mocks: `Unlock`, `UnlockKeyslot`, `UnlockWithVolumeKey`,
  `Target`. `unlockHeader` factors the lock + header read + requirements
  check + activation-segment selection every one of them needs; the
  dm-crypt activation half of the old `unlockVolume` (table load, keyring,
  node readiness) is NOT reachable from here by construction -- pkg/luks2
  must not import `internal/dm` or `internal/keyring` (DESIGN.md §A.2),
  and that half is `pkg/dmcrypt.Activate`'s, out of this lane's scope.
  `UnlockKeyslot` refuses a keyslot not bound to the volume's data segment
  rather than deriving a key the data segment was never encrypted with,
  the same guard the scanning path (`getVolumeKey`) already has (#250).
  `UnlockWithVolumeKey` clones the caller's enclave (`custody.Clone`)
  before wrapping it in a `*Key`, so the returned `Key` and the caller's
  own enclave are destroyable independently -- the caller keeps ownership
  of what it passed in, per DESIGN.md §B.1.
- **Not done, and explicitly out of this step's delivered scope**:
  `FormatParams`/`KDFParams`/`Format` (`DefaultHash`, `DefaultKDFType` are
  blocked per above; converting `FormatParams` to the existing
  `FormatOptions` and extracting `Format`'s core without disturbing its
  several historically-hard-won fixes -- the kdfOpts/HashAlgo-default
  ordering for #237, the AF-sector-padding fix the H3d entry documents --
  was judged higher-risk than this step's remaining budget justified);
  `KeyslotParams`/`AddKeyslot`/`ChangeKeyslot`/`RemoveKeyslot`; `Token`
  operations, `KeyProvider`, `Enroll` (blocked, see above);
  `RecoveryKeyOption`/`NewRecoveryKey`/`AddRecoveryKey` (new
  constructor is free, but is not useful alone without `KeyslotParams`);
  `MigrateParams`/`Migration`/`MigrateToFIPS` v2 (names are free, not
  attempted for time); `Erase`; `ValidatePassphrase` v2 (blocked, see
  above). No old exported function was reimplemented as a thin call into
  the new API -- every old function this step could have rewired
  (`ReadHeader`, `RestorePrimaryHeader`, `Unlock`, `UnlockWithVolumeKey`)
  stays exactly as it was, sharing only the one extracted core
  (`restorePrimaryHeaderCore`) that both old and new now call.
- **Coverage.** `internal/volkey` 100% (new package, floor 90).
  `internal/errs` 97.4% (floor 90, unchanged by this entry's addition of
  `At`). `pkg/luks2` unit 89.7-90.0% across runs (floor 87.50, unchanged
  file-count-wise from before this step; the new files more than cover
  their own lines).
## H14 (Makefile, docker, coverage floors)

- **Scoped to what does not depend on the final package list.** The lane
  brief for #276 is explicit that the public packages DESIGN.md B.5 names
  (dmcrypt, loop, filesystem, keyprovider, wipe) do not exist on this branch
  yet, and this lane does not create them or their test/integration/<pkg>
  directories (DESIGN.md A.1) -- that is H9/H10's and H12a's work. The
  per-package quartet is built so a later lane adds one of those with two
  Makefile lines and nothing else.
- **`make build` does NOT cross-compile pkg/luks2 for darwin yet, despite
  G.2 naming it.** Measured: `GOOS=darwin GOARCH=arm64 go build ./pkg/luks2`
  fails today, independent of the Makefile -- pkg/luks2 still imports
  `internal/keyring` and the vendored `github.com/anatol/devmapper.go`
  directly (keyring.go, devicemapper.go, unlock.go, errors.go), both
  Linux-only syscalls with no darwin build-tag split. A.3's portability claim
  holds only once H9/H10a move that activation code out of pkg/luks2 into
  dmcrypt, which has not landed on this branch. Wiring the cross-compile into
  `build` now would break `make build` and therefore `make ci` for every
  lane on the train the moment this merges -- the opposite of this lane's
  job. Left undone rather than added behind a feature flag (no half-finished
  switches); whichever lane lands H9/H10a's dmcrypt extraction adds the two
  `GOOS=darwin GOARCH=... go build ./pkg/luks2` lines to `build:` once it is
  true.
- **PKG_<name> is keyed by the package's last path element** (`kdf`, `luks2`,
  not `internal/kdf`, `pkg/luks2`), one variable per CURRENT pkg/ and
  internal/ package (14 today). `test-%`, `coverage-%` and `bench-%` resolve
  `PKG_$*` generically; an unmapped name fails with the exact variable name
  to add, rather than running `go test` against an empty import path.
  test/makefile's `TestPerPackageQuartetCoversEveryCurrentPackage` walks
  `go list ./pkg/... ./internal/...` and fails if a future package lands
  without its line.
- **integration-test-% reuses test/integration/pkg (today's only
  kernel-touching integration suite) for exactly the three names it already
  measures through COVERAGE_COMBINED_PKGS** -- luks2, dm, keyring, via
  `ITEST_DIR_<name> := pkg` -- and says "no integration suite yet" for every
  other name rather than claiming a false pass. DESIGN.md A.1's real
  per-package test/integration/<name> tree is later work; this rule picks it
  up for free once that tree exists, by directory presence alone.
- **The recursive `$(MAKE) docker-build-integration` call is hidden behind a
  variable (`ITEST_BUILD_IMAGE`), not spelled directly in the pattern rule's
  recipe.** integration-test-%'s skip branch ("no suite yet, exit 0 before
  touching docker") only works if it shares ONE shell with the build/run
  steps, and GNU make force-executes any recipe LINE whose own text contains
  the literal string `$(MAKE)` even under `-n` -- the exact #146 mechanism by
  which a dry run once started a real container. Confirmed empirically with a
  throwaway Makefile: a recipe referencing a variable whose value contains
  `$(MAKE)` is not force-run under `-n`; one that spells `$(MAKE)` directly,
  is. `TestIntegrationTestPatternRuleDryRunNeverInvokesDocker` pins it with a
  stand-in `docker` on PATH that a dry run must never reach.
- **coverage-report is coverage's trailing two lines, split out.** It never
  gates -- coverage-gate already does, over the separate per-leg profiles
  (#141) -- and reads only the already-written merged `$(COVERAGE_FILE)`, so
  it can be rerun (e.g. in CI, right after coverage-gate) without paying for
  test-unit again. Refuses with a named next step when the profile is
  missing or empty, rather than letting `go tool cover` fail on it unexplained.
- **docker-build/docker-run build and run build/docker/cli's image with the
  same launcher the integration suite uses** (test/integration/cmd/docker-run,
  built as `docker-run-bin`), because the CLI needs the identical
  device-mapper/loop access either way; that is where the seccomp profile and
  device scoping G.2 asks `docker-run` to carry actually live. The CLI image
  itself is a new, separate, multi-stage Dockerfile (build/docker/cli) so the
  shipped image carries no Go toolchain or test dependencies, unlike
  build/docker/integration's single-stage one, which IS the toolchain by
  design.
- **The Dockerfile move is a straight relocation, not a rewrite.** Content of
  build/docker/devcontainer/Dockerfile and build/docker/integration/Dockerfile
  is byte-for-byte what `.devcontainer/Dockerfile` and
  `test/integration/Dockerfile` held, `git mv`'d. Every reference followed:
  `.devcontainer/devcontainer.json`'s `dockerfile` path, the Makefile's two
  `-f` flags, `.github/workflows/ci.yml`'s one `-f` flag (the only line this
  lane touches there, per the lane brief), and the comment-only mentions in
  test/integration/cmd/docker-run and five pkg/luks2 `*_integration_test.go`
  files. test/labstrings/published_test.go's `"test/integration/Dockerfile"`
  fixture and CHANGELOG.md's historical entries are untouched: the former is
  a generic path exercising the releasability scanner, not a reference to the
  real file; the latter is a record of the past, not a pointer to the present.
## H10b (loop)

- **No `loop.Option` yet.** B.6's disposition row for `SetupLoopDevice`
  reads "`loop.Attach(ctx, file, ...loop.Option)`", but B.5's own code block
  -- the authoritative signature list this lane's brief enumerates -- gives
  `Attach(ctx, file) (*Device, error)` with no variadic. Nothing in this
  tree ever attached read-only or otherwise parameterized, so there is no
  existing behavior an `Option` would configure. Built B.5's signature as
  written; a future lane that needs an option (read-only attach, say) adds
  `loop.Option` then, against a real caller.
- **`sys` struct, this package's first.** DESIGN.md E's "fields of an
  unexported per-package sys struct" lands here for the first public
  package (H9/H10c were the other named sites). `sys` carries the clock,
  the sysfs root, the device directory, `openFile`, `readDir` and
  `loopBackingIdentity`; `defaultSys()` is read once by `Attach`, `Find` and
  `Lookup` and handed to the `Device` they return, so `Device.Detach` reads
  the same seams its constructor did. The lower-level wait functions
  (`waitForLoopNode`, `waitForDetach`, `detachDevice`) keep taking their
  clock, reader and durations as plain parameters, exactly the H7 precedent
  ("both packages take their seams as parameters") -- `sys` is the thing
  that assembles those parameters at the four public entry points, not a
  replacement for passing them explicitly. The one package-level mutable
  func var this lane removes is loopdev.go's `loopBackingIdentity`; it is
  now `loopBackingIdentityIoctl`, a plain function, assigned into `sys` once.
- **`Lookup` is new, not a rename.** Nothing in the old API built a handle
  from a bare `/dev/loopN` path without either attaching or searching for
  it; `DetachLoopDeviceState` took the path directly. Introduced so
  `Device.Detach` has exactly one receiver type reachable from a known
  path, per B.5. `Lookup` does not require the device to be currently
  attached -- `Device.BackingFile()` reports "" for one that is not -- since
  a caller naming a device by path plausibly wants to detach an idle one.
- **Sentinel text gets the "loop: " prefix (C.2 rule 3) from day one.**
  `ErrNotFound`, `ErrDetachIncomplete` and `ErrNodeAbsent` are new
  declarations (B.6: RENAME/MOVE, so pkg/luks2's `ErrLoopNodeAbsent` and
  `ErrDetachIncomplete` become re-exports of these, not the reverse) and
  nothing elsewhere in this tree depends on their exact text, so there was
  no reason to carry the old unprefixed strings forward. `ErrNotFound`
  keeps the substring "no loop device found" intentionally:
  `loopidentity_test.go`-style callers and this lane's own
  `loopdev_integration_test.go` (kept, unmoved -- H12's job) assert it.
- **`ErrDetachIncomplete` and `ErrLoopNodeAbsent` moved out of
  pkg/luks2/errors.go into loopdev.go, under its `//go:build linux`.** They
  were previously declared in the unguarded errors.go, meaning they existed
  on a hypothetical darwin build of pkg/luks2 even though the feature they
  classify never has. Keeping them there while re-exporting `pkg/loop`
  values would require pkg/loop to build on darwin too, which it has never
  needed to (A.3 names only pkg/luks2 and pkg/keyprovider as cross-platform,
  and loop's own ioctls --`LOOP_CTL_GET_FREE`, `SYS_IOCTL`-- do not exist on
  darwin's `x/sys/unix`). No test or production code outside loopdev.go /
  loopdev_test.go / loopdev_integration_test.go referenced either sentinel,
  so the move is invisible to everything but a darwin build nothing
  currently performs (`make build` builds only `./cmd/luks2`, for the host
  GOOS; A.3's cross-compile claim is H14's, not yet wired up).
- **The C8 loop-identity tests moved out of `activation_test.go`** (they
  tested `findLoopDeviceIn`/`loopBackingIdentity`, which moved) into
  `pkg/loop/find_test.go`, now built on a `sys` literal instead of
  reassigning a package var. `writeFakeNode` is duplicated as a five-line
  local helper rather than shared, the H5 precedent for a helper this small.
- **Coverage.** pkg/loop measured 56.73% (118/208) unit-only, as expected
  for a root-only package whose attach/find/detach ioctl paths need a real
  loop device: `attachFreeLoopDevice`, `loopBackingIdentityIoctl` and the
  `Attach`/`Find`/`Lookup`/`Detach` wrappers themselves are 0% here and
  covered by `loopdev_integration_test.go`'s `make coverage-combined` tier
  through the pkg/luks2 forwards, unchanged by this move. Per
  coverage-floors.txt's rounding rule, 56.50 (the half point) and 56.00 (the
  next whole point) both leave fewer than two statements of slack (0 and 1);
  the unit floor is 55.50, with combined at 90. Not run here: this
  container has no `/dev/loop-control` and no `CAP_SYS_ADMIN` (confirmed via
  `/proc/self/status`), so `make coverage-combined` cannot be exercised in
  this lane; CI's integration job is the gate for that tier, unchanged by
  this move.
## H10c (filesystem)

- **API.** `pkg/filesystem` is created per §B.5: `Type`, `Supported()`,
  `MakeParams`/`Ext4Params`/`XFSParams`/`ZFSParams`, `Make`, `CheckResult`,
  `Check`/`Repair` (the old `repair bool` parameter becomes two functions,
  per the disposition table), `Detect`, `Info`/`Inspect`, `MountParams`,
  `Mount`, `UnmountFlags`/`Unmount`, `IsMounted`, `DeviceMounted`, `Error`
  (a public alias of `errs.Error`) and `CommandError{Command, ExitCode,
  Output, Err}`. Every exported function takes `ctx` first and checks
  `ctx.Err()` once at the top; internal/command has no ctx parameter yet
  (H8 is adding it in parallel), so the check is the boundary the brief
  describes, not threaded further in.
- **Seams are one unexported `sys sysT` package value** (`tools
  command.Tools`, `mount`/`unmount` func fields, `mountInfoPath` and
  `procMountsPath`), replacing the four separate pkg/luks2-level vars this
  code used (`tools`, `mountInfoPath`-for-Mount, `unmountFunc`,
  `probeOutput`). `pkg/luks2/util.go`'s `tools` var is deleted outright: it
  had no caller left outside the code that just moved.
- **`UnsupportedFilesystemError` and `FilesystemCommandError` are DELETED
  from the new package, per the disposition table** (`filesystem.Error` with
  `Kind: ErrUnsupported` stands in for the first; `CommandError` for the
  second, minus the `Device` field -- the caller already has the device or
  pool name it passed in, so `CommandError` only adds `ExitCode`, matching
  `HelperError`'s shape elsewhere in the design). pkg/luks2's OLD API keeps
  both types, unchanged, and its forwards reconstruct them at the boundary
  (`unsupportedFilesystemErr`, `commandErr` in filesystem.go) -- the H4/H5/H7
  precedent of a thin forward preserving the old shape while the new package
  underneath is the clean one.
- **Sentinels are re-exported by value, not duplicated**:
  `ErrUnsupportedFilesystem`, `ErrFilesystemNotDetected`,
  `ErrInvalidFilesystemOption`, `ErrFilesystemTool` and `ErrNotMounted` in
  pkg/luks2 are now `= filesystem.ErrUnsupported` /
  `ErrNotDetected`/`ErrInvalidArgument`/`ErrTool`/`ErrNotMounted` (H3f had
  already pointed `ErrFilesystemTool` at `command.ErrTool`; it now points
  one layer up, at the public package). None of the five had a caller
  outside the code that moved.
- **`Unmount`'s flags become a typed `UnmountFlags` (`Force`, `Detach`,
  `Expire`), not the raw `unix.MNT_*` bitmask**, per §B.5's signature.
  `UMOUNT_NOFOLLOW` is dropped: nothing in this module ever set it (grepped
  across cmd/luks2 and pkg/luks2), and the design's enum does not name it.
  pkg/luks2's old `Unmount(mountPoint string, flags int) error` keeps its
  raw-int signature and gains a translation step
  (`unmountFlagsFromRaw`) that maps the three recognized bits and refuses
  anything else, including `UMOUNT_NOFOLLOW` -- a narrowing of the old
  signature's accepted range, consistent with the owner ruling that no
  backward compatibility is required and covered by
  `TestUnmountTranslatesRawFlags`.
- **`IsMappingMounted`, `mountInfoPath` (the one it reads) and
  `deviceListedInMountInfo` are deliberately NOT moved**, even though the
  disposition table's final target is `filesystem.DeviceMounted(ctx, devNo)
  with dmcrypt.Lookup`. `IsMappingMounted` resolves a device-mapper MAPPING
  NAME to a device number itself (`dm.infoByName`, `decodeDevNo`), and
  pkg/filesystem's allowed imports are internal/command and internal/errs
  only -- it cannot reach internal/dm, and the `dmcrypt` package the final
  design routes this through does not exist yet (a later wave). `mountInfoPath`
  is also reassigned directly by `activation_test.go`'s
  `TestIsMappingMountedMatchesTheDeviceNumber` and read by
  `TestMountInfoParsingIgnoresOtherFields`, outside this lane's file set --
  the H7 precedent for a seam left in place because other tests reach it
  directly. `filesystem.DeviceMounted(ctx, major, minor)` is still built,
  exactly as §B.5 specifies, with its own ~15-line device-number match
  against mountinfo -- a small pure helper duplicated rather than threaded
  across the layering boundary, the H5 precedent (`parseSize` et al.).
  Retiring `IsMappingMounted` in favor of `DeviceMounted` plus a `dmcrypt`
  lookup is left to whichever later wave adds `pkg/dmcrypt`.
- **The C7 security-review tests were misplaced in `activation_test.go`**
  (`TestFilesystemToolsAreNotResolvedThroughPATH`,
  `TestFilesystemToolsRunWithAMinimalEnvironment`,
  `TestUntrustedToolsAreRefused`, `TestZFSNamesCannotBeOptions`,
  `TestZFSAcceptsOrdinaryNames`,
  `TestToolSymlinksAreFollowedOnlyIntoTrustedDirectories`) -- they called
  `makeExt4`, `checkZFS`, `GetFilesystemInfo` and the old `tools` var
  directly, which is exactly the code this step moves. All six moved to
  pkg/filesystem's suite, adapted to the new names and `sys`. The
  `TestMappingNameEntriesRefuseTraversal` traversal-name test in the same
  file keeps its `ErrInvalidMappingName` assertions but drops the
  `fakeTools`/"mkfs.ext4 never ran" insurance check: tool execution now
  happens behind pkg/filesystem's unexported `sys`, unreachable from a
  pkg/luks2 test, and the early-return assertions already prove the mapping
  name is refused before any device or tool is touched.
- **Coverage.** pkg/filesystem measured 91.19% (352/386 statements); the
  half-point floor (91.0) left zero slack (352 of 352 needed), so the floor
  steps down to 90.50 (350 needed, 2 slack), with combined held to 90 per
  the root-only rule (real mkfs/fsck/blkid/zpool and mount(2)/umount(2) need
  a real kernel and installed tools for their happy paths). Both entries are
  in coverage-floors.txt. pkg/luks2 unit coverage measured ~89.2% afterward
  (floor stays 87.50, the H4 precedent: a floor is raised only when raising
  it is the point, not as a side effect of code moving out).
## H10e (wipe)

- **`pkg/wipe` has no handle type, so its seams are a parameter struct, not a
  package var.** B.5 makes `Sanitize` a free function, not a method, and
  DESIGN.md §E's "no package-level mutable func/interface vars" still applies.
  The exported `Sanitize(ctx, path, p)` calls unexported `sanitize(ctx, path,
  p, sys)`, where `sys` collects every filesystem, clock and lock-protocol
  seam (`openFile`, `clk`, `lockWait`, `lockDir`, `openLockFile`, `lockHeld`,
  `sysDevBlockRoot`, `statRdev`), defaulted by `defaultSys()` at `Sanitize`'s
  one call site. This package's own tests call `sanitize`/`verifyWrite`
  directly with a `sys` literal built on `baseSys()`, overriding one field
  (usually `openFile`) rather than substituting a package var and restoring
  it in `t.Cleanup`.
- **The lock-and-claim sequence is internal/device's directly, not
  pkg/luks2's keyslotDevice/FileLock wrapped a second time.** pkg/wipe cannot
  import pkg/luks2 (that would cycle: pkg/luks2 imports pkg/wipe for the
  forward), and the lane brief's allowed imports are internal/device,
  internal/clock, internal/errs. `sanitize` therefore calls
  `device.OpenPinned` -> `(*Pinned).Lock` -> `(*Locked).Claim` itself, exactly
  as pkg/luks2's `acquireFileLock`/`openForWipe` do, rather than going through
  either. `ctx` is checked once, right after `OpenPinned` and before `Lock`
  (D.2's lock row is H8's and lands separately; this is the "check it
  yourself at the boundary" the brief asks for), so a caller that cancelled
  before calling `Sanitize` does not spend the lock-wait budget. The H6
  invariant holds unchanged: `Claim` reopens the locked descriptor's own
  `/proc/self/fd/<fd>` entry, and verification's `mediumPath` is built from
  that SAME descriptor's fd, never from `path` again.
- **Verification reuses `device.ReadPastCache`/`MediumSources` per chunk,
  not a bespoke `directReader`/mmap-reuse reader.** The old `directReader`
  opened one O_DIRECT descriptor and one aligned mmap buffer and reused both
  across every verification chunk; `internal/device.ReadPastCache` (landed at
  H6) opens, mmaps and closes fresh on every call. pkg/wipe's `verifyWrite`
  calls it once per 1 MiB chunk per `MediumSource` rather than reintroducing
  the old reader stack: more syscalls per verification, but it is the
  already-tested H6 primitive and the only one `pkg/wipe`'s allowed imports
  reach, and verification runs once per `Sanitize` call, not on a hot path.
  `mediumReader`, `directReader` and `openMediumReader` are deleted outright,
  not moved.
- **BLKDISCARD moves to `internal/device` (`Discard`), closing the H6 note
  that left it in pkg/luks2's wipe.go "for whichever lane absorbs the rest of
  wipe.go."** A.3 lists BLKDISCARD beside the other Linux-only facilities
  that live in `internal/device/*_linux.go`; `discard_other.go` is a silent
  no-op off Linux, matching `DropCache`'s precedent (TRIM is advisory, not a
  correctness requirement, so unlike `ReadPastCache` it does not fail
  closed). `pkg/wipe.Sanitize` calls `device.Discard(f, size)` best-effort for
  `Params.Discard`; pkg/luks2 has no remaining caller (`HeaderOnly` never used
  Trim) and its own `BLKDISCARD`/`issueDiscard` are deleted, not kept as a
  compatibility shim.
- **`Pattern`/`Standard`'s numeric values are NOT the old
  `WipePattern`/`WipeStandard`'s.** B.5 fixes `Standard`'s order as
  `NoStandard, DoD3Pass, DoD7Pass, NIST` (0-3), where the old
  `WipeStandard` was `StandardCustom, StandardNIST, StandardDoD3Pass,
  StandardDoD7Pass` (0-3) -- NIST moves from 1 to 3. `Pattern` keeps the old
  order (`Zeros, Ones, Random` = `PatternZeros, PatternOnes, PatternRandom`),
  so pkg/luks2's `toWipePatterns` casts element-wise
  (`wipe.Pattern(p)`) while `toWipeStandard` is a full switch. Getting this
  backwards silently wipes with the wrong standard's pass count, so it is
  covered by `TestToWipeParams`, not left to the end-to-end `Wipe` tests to
  notice.
- **The old `WipeOptions`/`Wipe`/`WipePattern`/`WipeStandard`/`WipeProgress`
  stay in pkg/luks2, unrenamed; only their engine moves.** The lane brief asks
  for a thin forward, not B.6's eventual deletion of the whole old surface
  (that is a later step, downstream of H9's new pkg/luks2 API). `Wipe` now
  branches on `HeaderOnly` first -- unchanged, still pkg/luks2's own
  lock/claim/header-plan machinery, because it needs the LUKS2 header to
  decide what to zero -- and otherwise calls `wipe.Sanitize` through
  `toWipeParams`. `WipeKeyslot` is untouched for the same reason (B.6 deletes
  it into `RemoveKeyslot` eventually; not this lane's scope).
- **The empty-device refusal is no longer `ErrInvalidSize`.** The check moves
  from a pre-flight `measureDeviceSize` in pkg/luks2's old `Wipe` to
  `device.Size` inside `pkg/wipe.sanitize`, which has no sentinel for it:
  C.3's sentinel list for `wipe` is deliberately just `ErrVerification` plus
  the four shared device kinds, on the "a sentinel exists iff a caller can
  act on it differently" rule (C.2.2) -- an empty device is a caller
  precondition, not something to retry around. `TestWipeRefusesWhatItCannotWipe`
  (pkg/luks2) is updated to assert only that the empty device IS refused, not
  which sentinel; the owner ruling waiving backward compatibility for this
  redesign covers the change.
- **Tests split along the same line as the code.** pkg/luks2/wipe_test.go
  keeps `wipePass`/`wipeHeaders`/`WipeKeyslot` (unmoved) and the `Wipe`
  forward's own behaviour (legacy Passes/Random, Standard/Patterns/Verify/
  NoVerify, Trim, HeaderOnly, the crypto-erase tests, HeaderOnly's exclusivity
  via `busyExclusiveOpens`/`openFileFunc`). Everything that exercised the
  moved engine directly (`passStream`, `wipePassWithStream`, `verifyWipe`/
  `compareMedium`, `resolvePatternSequence`, `directReader`/
  `openDirectReader`, `issueDiscard`/`BLKDISCARD`) is deleted from pkg/luks2
  and re-created against the new API in pkg/wipe's own test files, not
  ported line-by-line: pkg/wipe's seam is a `sys` struct field, not a package
  var, so the old `useStaleMedium`/`busyExclusiveOpens`-style
  substitute-and-`t.Cleanup` pattern does not carry over unchanged.
  `resolvePatternSequence`'s old tests are replaced by `TestToWipeParams`
  (pkg/luks2, the legacy-mapping half) and `TestResolvePatterns` (pkg/wipe,
  the Standard/Patterns/Verify half), since the one function's job is now
  split across the two layers. `TestWipeOpensTheDeviceExclusively` keeps only
  the `HeaderOnly` case; the data-wipe case is
  `TestSanitizeOpensTheDeviceExclusively` in pkg/wipe, because the data path's
  O_EXCL claim no longer goes through pkg/luks2's `openFileFunc` var at all.
  `pkg/luks2/wipe_integration_test.go` and `test/integration/pkg/wipe_test.go`
  are black-box against the old `Wipe`/`WipeOptions` API and need no change;
  the lane brief asks that they keep compiling and asserting what they did.
- **Coverage.** pkg/wipe measured 94.2% unit, floor set at 90 in
  coverage-floors.txt (a new row; pkg/wipe is not root-only, so it gates on
  unit alone). internal/device measured 91.8% after `Discard`/`discard_test.go`
  (was 91.9%; floor stays 90). pkg/luks2 measured 90.3% unit after the
  deletions and additions (floor stays 87.50/90 combined, both already more
  than cleared).

- **fix-t2-harness: the prescribed move alone does not resolve it, and the
  fix is a scoped, temporary duplication rather than the move.**
  `volumename_integration_test.go` is where `runSuite`/`runVolume` are
  DEFINED, and `leakledger_integration_test.go`'s `TestMain` is where
  `dm.create` and `calibratedCountFloor` are wired; 15 of this package's other
  25 `*_integration_test.go` files call `runVolume`/`runSuite` by package-level
  reference, not by import, and do not themselves import harness (confirmed by
  grep, not assumed). Moving only the two harness-importing files out of
  `package luks2` undefines those symbols for the other 15 -- wave B's own
  move is for ALL of them together, which this lane's brief explicitly
  excluded ("do not start it"). It also would not have been sufficient alone:
  a `TestMain` relocated to `test/integration/luks2` runs in a DIFFERENT test
  binary and cannot wire `pkg/luks2`'s own `go test` run's `dm.create` seam for
  the files that stay behind, regardless of where the two files end up.
  Verified by actually building both ways, not inferred.
  Exposing the seam as "exported-within-internal API" the way the OTHER 9
  white-box files can was also checked and rejected here specifically:
  `internal/dm` is documented (H7, #265) as holding no package-level state of
  its own, by design, and a hookable var on it would be exactly that; and an
  exported, integration-tag-gated observer on `pkg/luks2` itself would not
  help either, for the same cross-binary reason `TestMain` does not.
  **What shipped instead:** `pkg/luks2/intstate_integration_test.go`, a
  package-private copy of `test/internal/harness`'s ledger and trusted
  state-directory logic (`ledger.go`, `statedir.go`, the pure parts of
  `volumename.go`), ported in full including the symlink/ownership hardening
  -- not a weakened version of it. It writes to the SAME `LUKS2_TEST_STATE_DIR`
  location in the SAME `<runID>.ledger` tab-separated format `test/internal/harness`
  uses, so a `pkg/luks2` run killed before `Finish` is still reaped by the
  existing cross-run reap (`test/tools/luks2-testreap` via the container
  entrypoint, or a sibling suite's own `BeginSuite` later in the same
  sequence) exactly as a harness-written ledger would be -- no change to that
  tool or to its two other callers. NOT duplicated: harness's `reap.go`
  (cross-run scanning, already covered by the existing external reap) and
  `system.go` (the generic `SystemRemover`); the suite's own end-of-run check
  is built on this package's own, already-reviewed `releaseVolumeErr` and
  `DetachLoopDevice` instead of a second copy of the sysfs scan. Run (not just
  vetted) in this lane's own sandbox: `TestLedgerRecordsAMappingBeforeTheKernelIsAsked`,
  `TestSuiteTempRootIsRecordedBeforeAnyTestRuns`, `TestRunVolumeIsScopedToTheRun`,
  `TestSanitizeNameTermKeepsNamesLegal`, `TestEveryMappingNameIsRunScoped` and
  `TestTheGateCatchesEveryCallItCovers` all pass; the overall run reports
  non-zero only because this sandbox has no `/dev/mapper/control` at all (not
  merely no permission), so `releaseVolumeErr`'s identity check cannot
  classify the selftest's never-created mapping as ABSENT and fails closed --
  the same way the original, harness-backed version would have in the same
  sandbox. A real CI runner's identical check will see ENXIO and pass.
  **This is deliberately a duplication, not a reconciliation**, and it should
  not survive wave B unmodified: when wave B eventually moves this package's
  OWN integration tests out of `pkg/luks2` entirely, `pkg/luks2` stops needing
  any of this and `intstate_integration_test.go` should be deleted rather than
  carried forward as a second copy to keep in sync with harness's. Until then,
  a change to `test/internal/harness`'s ledger file format or state-directory
  validation must be mirrored here by hand; nothing enforces that
  automatically, and this note is the only place that says so.

## H10d (pkg/keyprovider: Command and FIDO2, moved out of pkg/luks2)

- **This is a MOVE, not the `KeyProvider`/`Token` shape fix H9 flagged.**
  H9's entry says the collision is real: the new `luks2.KeyProvider{Token()
  Token}` and the new, generic `luks2.Token{Type, Keyslots, Members}` cannot
  be declared beside the OLD interface and the OLD `Token = header.Token`
  (FIDO2 fields and all) that `EnrollKeyProvider`, `UnlockWithProvider` and
  `importTokenLocked` are built on -- those three stay in `pkg/luks2`,
  un-rewritten, because rewriting them is blocked on exactly that collision
  and is not this step's to force open. Consequently `keyprovider.Command`
  and `keyprovider.FIDO2` implement the interface that ACTUALLY EXISTS in
  `pkg/luks2` today: `Passphrase(ctx) (*enclave.MemoryEnclave, error)`,
  `Token() *Token` (a pointer, the old shape). `disposition-luks2.tsv`'s
  `KeyProvider | KEEP | luks2.KeyProvider{Passphrase(ctx); Token() Token}`
  row (value-returning `Token`) is the end state, still blocked; this step
  does not move it closer, and flags that it is still open, same as H9 did.
- **The split line is "does it exec."** `CommandKeyProvider`, `ExecConfig`,
  `fido2Provider`, `NewFIDO2KeyProvider`, `NewFIDO2Credential`,
  `NewFIDO2Salt`, `ProviderFromToken`, `HelperError` and every FIDO2 helper
  moved. `KeyProvider` (the interface), `EnrollKeyProvider`,
  `enrollWithToken`, `importTokenLocked`, `freeTokenSlot`,
  `killKeyslotLocked`, the `importToken`/`killKeyslot` seam vars,
  `UnlockWithProvider`, `KeyProviderError` and `OrphanedKeyslotError` stay:
  they are `Volume`-adjacent bookkeeping (device lock, token slot, keyslot
  rollback) that does not exec and must not move into a package that execs.
  `recoveryTokenType` (used by `recovery.go`, declared beside the moved
  `fido2TokenType`) stays in `pkg/luks2/keyprovider.go`; `fido2TokenType`
  becomes the exported `keyprovider.TokenTypeFIDO2`, used nowhere else.
- **Sentinels split the same way.** `ErrHelperNotConfigured`,
  `ErrHelperPathNotAbsolute`, `ErrNoFIDO2Device`, `ErrHelperFailed`,
  `ErrHelperOutput`, `ErrInvalidFIDO2Binding` were used ONLY by the moving
  code (checked against every non-test and test file first) and are DELETED
  from `pkg/luks2/errors.go` outright, not aliased: `keyprovider/errors.go`
  declares its own `ErrInvalidArgument`, `ErrHelperFailed`, `ErrHelperOutput`,
  `ErrNoDevice`, `ErrInvalidBinding`, `ErrUnsupportedToken`, per
  `disposition-luks2.tsv`. `ErrUnsupportedTokenType`, `ErrNoKeyProvider` and
  `ErrKeyProvider` stay in `pkg/luks2`: `importTokenLocked` still raises the
  first, and `EnrollKeyProvider`/`UnlockWithProvider` the other two. The
  table's `ErrNoKeyProvider -> luks2.ErrInvalidArgument` and
  `ErrUnsupportedTokenType -> keyprovider.ErrUnsupportedToken` RENAME/MOVE
  rows describe the end state of code this step does not touch; `luks2`
  keeps its own sentinel under its own name until the step that rewrites
  those three functions runs.
- **`keyprovider.Error` is `= errs.Error`, used directly as `&errs.Error{Kind:
  ..., Detail: ...}`**, the `volume.go`/`key_v2.go` precedent (bare literal
  plus one `errAt(pkg, op, path, err)` boundary call per exported entry
  point) rather than the old `KeyProviderError{Op, Err}` wrapper, which is
  itself marked DELETE in the disposition table and stays alive only in
  `pkg/luks2`, where the functions that raise it are frozen. `HelperError`
  moved with a shape change the table's `HelperError.Is | DELETE |
  Unwrap() []error {Kind, Err} replaces hand-written Is` row calls for: it
  now carries `Kind error` (`ErrHelperFailed` on every path that builds one,
  including "the helper never started" -- broadened from the old doc
  comment's "ran and exited non-zero" to cover both, since no sentinel for
  "could not be run" is in the package's vocabulary and inventing a second
  one for one call site was not worth it) and an `Unwrap() []error`
  returning `{Kind, Err}`, so `errors.Is` reaches `ErrHelperFailed` or the
  cause through the same multi-error path `errs.Error` uses, with no
  type-specific `Is`.
- **Seams are fields of `Command`'s own `commandSys`, not package vars.**
  `helperBaseEnv`, `helperWaitDelay` and `fido2SecretEncoding` were
  package-level `var`s swapped by tests. `commandSys{env, waitDelay, clock}`
  is read once in `NewCommand`, defaulted to `command.System().Env`
  (REPLACING the ad hoc `"PATH=/usr/sbin:/usr/bin:/sbin:/bin"` with the
  shared primitive DESIGN.md's dependency table already names for this
  package -- the helper's environment now also carries `LC_ALL=C` and the
  two `/usr/local` directories `command.System()` adds), 2s and
  `clock.System{}`; a test shortens `waitDelay` on the one `*Command` it
  built, not on every Command live in the process. `fido2SecretEncoding`
  stays a single documented `var` (nothing production reads implicitly: it
  is passed into `FIDO2{encoding: ...}` once, at `NewFIDO2`, and
  `normalizeFIDO2Secret`/`fido2EncodingName` take the encoding as a
  parameter) because there is no object to hang it on and no test needs a
  second value at runtime -- tests call the parameterized functions with a
  different encoding directly instead of mutating shared state.
  `NewCommand` also validates EAGERLY (empty path, non-absolute path,
  negative line) rather than lazily at `Passphrase`, now that it returns
  `(*Command, error)`; this is the one behavioral improvement over a literal
  move, and every call site that used to construct `&CommandKeyProvider{}`
  and discover the problem at `Passphrase` now discovers it at construction.
- **`internal/command` is `//go:build unix`, not `//go:build linux`**,
  deferred from H3f to exactly here: `pkg/keyprovider` is the first consumer
  that must build on darwin (§A.3), and `syscall.Stat_t.Uid` the package's
  one platform-specific read exists on every unix. Checked with
  `GOOS=darwin GOWORK=off go build ./internal/command/...` and
  `./pkg/keyprovider/...` in isolation -- both succeed.
  `GOOS=darwin GOWORK=off go build ./pkg/luks2/...` does NOT: `keyring.go`
  and `devicemapper.go` still import `internal/keyring` and
  `github.com/anatol/devmapper.go` directly (pre-existing, unrelated to this
  step), and extracting them is `pkg/dmcrypt`'s (H10a's) move, running in
  the same wave, not yet merged. `pkg/keyprovider` importing `pkg/luks2`
  for `Token`/`KeyProvider` therefore cannot itself cross-build until H10a
  lands on the train; building each package independently is what this
  step's own darwin check can assert today.
- **`pkg/luks2`'s own tests no longer construct a `CommandKeyProvider`.**
  `EnrollKeyProvider`/`UnlockWithProvider`'s tests needed SOME
  `luks2.KeyProvider`, and reaching for `pkg/keyprovider` from `pkg/luks2`'s
  test binary would make the newly one-directional dependency round-trip
  through the test graph for no reason -- those tests exercise enrollment
  bookkeeping, not exec mechanics. A four-field `fakeKeyProvider` (same
  file, `keyprovider_test.go`) replaces it; the helper-script fixture
  builders (`helperScript`, `echoingHelper`, ...) moved to
  `pkg/keyprovider`'s own tests with the code they drove, except
  `shellQuote`, which `activation_test.go` and `filesystem_test.go` also use
  for unrelated fixtures and which stays in `pkg/luks2`.
- **Coverage.** `pkg/keyprovider` unit 93.9% (new package, floor 90).
  `pkg/luks2` unit 89.3% (floor raised 87.50 -> 89.00: coverage ROSE because
  the removed code's own branches -- helper exec failure modes now covered
  by `pkg/keyprovider`'s tests instead -- were a larger share of what the
  floor was discounting than the bookkeeping tests this step rewrote cover
  on their own; raised to measured minus slack, per this file's rule, never
  lowered). `internal/command` unit 94.4% (floor 90, unchanged).
- **Not done.** The `KeyProvider`/`Token` shape (blocked, see above, still
  flagged for the coordinator/owner); `(*Volume).Enroll`,
  `(*Volume).UnlockWithProvider` (DECISIONS table's target for
  `EnrollKeyProvider`/`UnlockWithProvider`, blocked by the same collision);
  `ErrNoKeyProvider -> luks2.ErrInvalidArgument` and `ErrUnsupportedTokenType
  -> keyprovider.ErrUnsupportedToken` (the luks2-side halves; not touched
  while the functions that raise them are frozen).

## H11 (internal/cli rewrite -- partial)

- **The lane brief's dependency assumption did not hold, and the scope
  actually deliverable is much smaller than §F's file list.** The brief
  treats H9 (new `pkg/luks2` API) as a finished dependency of this step; H9's
  own entry above says otherwise -- "partial" -- and an `apidump dump
  ./pkg/luks2` run at the start of this lane confirmed it line for line.
  `(*Volume)` has exactly eleven methods: `Close`, `Path`, `Header`,
  `SecondaryHeader`, `RestorePrimaryHeader`, `ReplacePrimaryHeader`,
  `Target`, `Unlock`, `UnlockKeyslot`, `UnlockWithVolumeKey`, plus the free
  function `Open`. `Format`, `KDFParams`, `KeyslotParams`,
  `AddKeyslot`/`ChangeKeyslot`/`RemoveKeyslot`, every `Token` operation,
  `KeyProvider`/`Enroll`/`UnlockWithProvider`, the new `RecoveryKeyOption`/
  `NewRecoveryKey`/`AddRecoveryKey`, `MigrateToFIPS` (new shape), `Erase` and
  `ValidatePassphrase` (new shape) do not exist. `(*Header)` has `UUID`,
  `Label`, `Subsystem`, `SequenceID`, `Requirements`, `Dropped` and
  `MarshalJSON`; it does NOT have `Keyslots`, `Segments`, `Tokens` or
  `Size`. §F's command list assumes every one of these; most of it names a
  symbol that is not there to call. This is not a scheduling gap this step
  can work around -- `pkg/luks2`/`format.go`/`keyslot.go`/`token.go`/
  `recovery.go`/`fipsmigrate.go`/`keyprovider.go` are explicitly another
  lane's to rewrite (H9's own entry), and the lane brief holds pkg/luks2
  frozen outside this lane's scope, so inventing the missing methods here
  would be out-of-scope surgery on a file another step owns, on top of
  guessing at a shape H9 hasn't committed to.
- **What was built instead: the full §F architecture, for the commands the
  CURRENT API supports end to end, nothing stubbed.** `internal/cli` has
  `cli.go` (`Run`, `env`, `dispatch`, the registry, top-level usage),
  `command.go`, `exit.go` (the cryptsetup(8) exit-code table, `errors.Is`
  over a slice), `flags.go` (the interspersed parser, ported from
  `cmd/luks2/options.go`), `confirm.go` (YES confirmation, ported from
  `destructive.go`'s non-signature-probe half), `keyinput.go` +
  `enclavebuffer.go` (passphrase / `--key-file` / stdin -> `*enclave.
  MemoryEnclave`, never a plain `[]byte` -- see below), and `host.go` (the
  `activator`/`mounter` boundary). Registered commands: `open`, `close`,
  `mount`, `unmount`, `testkey`, `wipe` (`--full` only), `header restore`,
  `isluks`. Every one of those is implemented against the real library
  call it needs -- no command here returns a canned "not implemented"
  error -- and every one is unit-tested through its `run` function (most
  also reachable through `Run`) against a REAL formatted temp-file volume
  (`luks2.Format`, the OLD free function, which still exists and writes
  the same on-disk format `Volume.Open`/`Unlock` read -- using it to build
  a fixture is not the same as building the CLI on it) or a plain temp
  file for `wipe`, with `host.activator`/`host.mounter` faked for the
  root-only half exactly as the brief asks. Unit coverage 90.2% (floor 90,
  `coverage-floors.txt` row added).
- **`create`, `keyslots`/`addkey`/`changekey`/`removekey`/`killslot`,
  `recovery generate`/`add`, every `token` verb, `header show`/`secondary`,
  `info`, and `wipe`'s default header-only mode are NOT implemented.**
  Each needs a `pkg/luks2` symbol from the list above. `recovery verify`
  is also not implemented: it is Unlock-shaped and would be buildable, but
  not usefully so without `ParseRecoveryKey`'s new signature to normalize
  typed input first, and that is blocked by the same gap. `wipe`'s
  `--full` mode IS implemented, because it needs only `wipe.Sanitize`
  (`pkg/wipe`, H10e, already landed) and no `Volume` method at all.
- **`pkg/dmcrypt` (H10a, #268) and `pkg/keyprovider` (H10d, #271) are a
  smaller, already-anticipated version of the same gap, and the brief's
  own answer for it is followed as given.** `host.go`'s `activator`
  interface mirrors `pkg/dmcrypt`'s `Activate`/`Deactivate`/`Lookup` 1:1,
  with no production implementation in this change -- `open`, `close` and
  `mount`'s mapping-name resolution are implemented and unit-tested
  entirely against a fake `activator`. `mounter` DOES have a production
  implementation (`realMounter`), because `pkg/filesystem` already exists
  (H10b/H10c, wave A). No `keyprovider`-shaped command (`UnlockWithProvider`,
  `Enroll`, FIDO2) is attempted; it is blocked by the `pkg/luks2`-side gap
  above before it would ever reach `pkg/keyprovider`.
- **`cmd/luks2` is UNCHANGED, on purpose.** §F's "`cmd/luks2` shrinks to the
  ~25-line `main.go`" is not done. Pointing `main.go` at `internal/cli.Run`
  now would remove `create`, every keyslot and token verb, recovery
  enrollment, default-mode wipe and full `header`/`info` output from the
  compiled binary -- not a partial rewrite but a regression users of the
  tool would feel immediately, for the sake of matching a line count. The
  old `CLI`/`LuksOperations`/`Terminal`/`DeviceProber` stack (B.7's
  disposition table) is left exactly as it was; none of it is touched or
  deleted by this change. Wiring `main.go` to `internal/cli` is left for
  whichever step finishes the `pkg/luks2` methods above (plausibly a
  continuation of H9, or H9b) and can therefore complete the remaining
  `internal/cli` command files without inventing their target's shape.
- **Credential handling follows B.7's `ClearBytes` disposition literally:
  "input is read straight into an enclave; `enclave.Wipe` for the one
  terminal buffer."** `keyinput.go`'s `readKeyFile`/`readKeyLine` grow a
  credential directly inside locked memory, one byte at a time
  (`enclavebuffer.go`), doubling by allocating a new, larger enclave and
  copying under a borrow of both -- the only way to grow one without a
  plain-heap intermediate. `golang.org/x/term.ReadPassword` is the one
  terminal buffer the design names: its return is moved into an enclave
  immediately through `secret.Custody.Adopt`, which wipes it as part of
  taking ownership. Growing a credential this way needs, briefly, both the
  old and the new backing enclave locked at once; a test that pushed this
  all the way to `maxKeyFileSize` (8 MiB) hit this sandbox's own locked-
  memory budget purely from that doubling overhead, which is why
  `readKeyFile`/`readKeyLine` take `limit` as a parameter (production
  always passes `maxKeyFileSize`; the too-large unit tests pass a limit of
  16 bytes and prove the same boundary logic without allocating anywhere
  near 8 MiB).
- **`isluks` keeps its own 0/1 exit contract (§F) by construction, not by
  convention.** Its negative answer is `errNotLUKSDevice`, a sentinel with
  no `Unwrap`, so `exitCode`'s `errors.Is` table cannot walk through it to
  whatever `pkg/luks2` sentinel actually failed and land it on exit 2-5;
  it falls through to the same default (1) a positive usage error gets.
  `TestRunIsLUKSOnANonLUKSFile` checks `exitCode(err) == 1` directly so a
  future change to the table cannot regress this silently.
- **The exit-code table (`exit.go`) names today's sentinels, not §C.3's
  final ones.** `luks2.ErrMasterKeyVerification`/`ErrInvalidVolumeKey`
  (wrong key), not the `ErrWrongKey`/`ErrInvalidCredential` B.6 renames
  those to -- §C.3's sentinel consolidation is explicitly H13's. `dmcrypt.
  ErrActive`/`ErrBusy` are absent from the "exists or busy" row for the
  same reason `pkg/dmcrypt` is absent everywhere else in this change. The
  table is a `[]struct{ code int; is []error }` tried in order under
  `errors.Is`, so adding or renaming a row is additive and the comment
  above it says so.
- **Coverage.** `internal/cli` unit 90.2% (floor 90, row added to
  `coverage-floors.txt`). `make lint` and `make gosec` both pass across the
  whole module with this change in place (0 issues each).

## H10a (pkg/dmcrypt)

- **API.** `Activate`, `Deactivate`, `Lookup`, `Mapping{Name, UUID, Major,
  Minor}` plus `(*Mapping).Path`, `ValidateName`/`MaxNameLength`, `CheckKeyring`
  and `KeyringError{Op, Kind, Err}` with `Remedy() string` -- exactly §B.3.
  `Activate` calls `v.Header(ctx)` for the dm UUID and `v.Target(ctx, key)`
  for the table geometry (two independent locked reads, where the pre-split
  `Unlock` held one lock across both; DESIGN.md's "no lock held between
  calls" rule makes that the correct shape, not a regression), builds the
  dm-crypt table, and runs the create/keyring-add/load/resume sequence on a
  discarded OS thread exactly as the pre-split `unlockLoadTable` did.
  Rollback (`rollback`, unexported) is pinned to the create's own device
  number, matches the pre-split `removeCreatedMapping` byte for byte in
  its reasoning, and takes a `ctx` parameter it never reads: `Activate`
  calls it with `context.WithoutCancel(ctx)`, so the signature is already
  ctx-first for H8 to thread through without this boundary changing, and
  "never cancellable" holds today by the simpler fact that nothing in the
  call chain selects on `ctx.Done()` yet.
- **Seams are one package-level `seams` struct (`sys`), not the dozen
  separate vars pkg/luks2's pre-split `dm`/`keyring` were.** It is built by
  `init()`, not by the `var sys = liveSeams()` the obvious spelling would
  be: `liveSeams` stores `ensureDeviceNode`/`waitForDeviceReady`, whose
  bodies read `sys.devDir`/`sys.blockNodeRdev`, and the compiler's
  initialization-cycle check is conservative about a var initializer
  calling a function that (transitively) reads the var being initialized
  -- even though nothing runs those functions until long after `sys`
  exists. `init()` runs after every package var has its zero value, so the
  assignment there is ordinary imperative code and the check does not
  apply. Tests substitute `sys` wholesale or one field at a time with the
  same save/restore idiom pkg/luks2's `dm`/`keyring` vars used.
- **internal/dm's mechanics are called directly, not re-wrapped.**
  `CreateTarget`, `RetryWhileBusy`, `PollUntil`, `IsOurNode`,
  `IsNoSuchDevice`, `RemoveMappingNodes`, `PlaceNode`, `NodePath`/
  `MapperPath`/`MapperDir` are internal/dm's own, already covered by its
  own suite (H7); this package does not duplicate those tests, only the
  orchestration on top: `Activate`/`Deactivate`/`rollback`/
  `ensureDeviceNode`/`waitForDeviceReady`. Same division for
  internal/keyring's `AddVolumeKey`/`VolumeKey.Release`/`Classify`/
  `Remedy`/`RunOnDiscardedThread`.
- **`KeyringError` is a new type, not an alias of
  `internal/keyring.UnavailableError`**, for the H4 precedent: `Remedy()
  string` is a method this package's own callers need, and a method
  cannot be added to an alias of a foreign type. `classifyKeyringErr`
  (keyring.go) converts an `*internal/keyring.UnavailableError` into a
  `*KeyringError` at every point this package calls into
  `AddVolumeKey`/`Release` directly, so a caller branches on a type this
  package owns. `ErrEntryExists`/`ErrKeyNotReleased` need no translation:
  they already arrive as `*errs.Error` carrying one of this package's own
  re-exported sentinels.
- **`ValidateName` calls `luks2.ValidateMappingName` rather than
  duplicating its ~50-line whitelist.** pkg/dmcrypt legitimately imports
  pkg/luks2 (§A.2's one-directional edge), and the validator's reasoning
  -- the name reaches the dm ioctl, `/dev/mapper/<name>`, the dm UUID and
  the keyring description -- is unchanged by the split. `MaxNameLength` is
  `luks2.MaxMappingNameLength` by value. Both stay declared in pkg/luks2
  too (next bullet), so this is delegation, not a second copy of the
  behaviour with the name translated at the boundary (`ErrInvalidName`).
- **pkg/luks2 keeps a read-only device-mapper seam, not none at all.**
  `mappedDevicePath`/`IsMappingMounted` (mount.go, filesystem.go,
  fsdetect.go -- out of this lane's scope to move) only ever INSPECT an
  already-active mapping; they create, load, resume and remove nothing.
  So `devicemapper.go` keeps a trimmed `deviceMapper{infoByName}`,
  `devDir`, `dmNodePath`/`mapperNodePath`, `decodeDevNo`,
  `blockNodeRdev`/`statBlockRdev`, `isOurNode`, `pollUntil`,
  `isNoSuchDevice` and `mappedDevicePath` itself -- small, local
  reimplementations of exactly the internal/dm mechanics this read path
  needs, rather than an import of internal/dm for a handful of pure
  functions. `ValidateMappingName`/`MaxMappingNameLength`/
  `ErrInvalidMappingName` stay for the same reason (H7's "sentinels used
  by code that stays are not moved" precedent), and `IsUnlocked`/
  `GetMappedDevicePath` -- pure readers, never a write -- are UNCHANGED:
  B.6 marks them DELETE/RENAME for H13, but nothing about this lane's
  depguard proof requires removing them now, and they have no activation
  dependency to remove. Everything WRITE-side -- `Unlock`,
  `UnlockWithVolumeKey`, `Lock`, `unlockLoadTable`, `activateCreated`,
  `confirmCreated`, `mappingUUID`, `createTarget`, `ensureDeviceNode`,
  `waitForDeviceReady`, `placeNode`, `makeBlockNode`, `removeMappingNodes`,
  `retryWhileBusy`/`dmClock` (the write-retry one), all of keyring.go, and
  the now-dead metadata-read-lock half of cryptsetuplock.go -- is deleted,
  not forwarded: pkg/dmcrypt depends on pkg/luks2, so pkg/luks2 cannot
  import it back, and a "thin forward" living inside pkg/luks2 itself is
  therefore not constructible for these three. Verified: `go list -deps
  ./pkg/luks2/...` names neither internal/dm nor internal/keyring.
  `pkg/keyprovider.UnlockWithProvider` is deleted outright rather than
  forwarded for the same reason, compounded: its new-API replacement
  (`(*Volume).UnlockWithProvider` + `dmcrypt.Activate`) is blocked on
  `KeyProvider`/`Token` moving to the new shape first (H9's own recorded
  finding), so there is, right now, nothing on either side of the import
  boundary for a forward to call.
- **The forward DOES exist, one layer up, in `cmd/luks2/cli.go`.**
  `DefaultLuksOperations.Unlock`/`.Lock` -- the CLI's `open`/`close`
  implementation -- import both pkg/luks2 and pkg/dmcrypt (cmd/luks2 is
  neither package, so the cycle that blocks pkg/luks2 does not apply) and
  are rewritten as `Open` + `Volume.Unlock` + `dmcrypt.Activate` /
  `dmcrypt.Deactivate`, keeping the pre-split method signatures so nothing
  else in the CLI's `LuksOperations` interface or its tests had to change.
  This is a stopgap, not a design position: H11 deletes
  `LuksOperations`/`DefaultLuksOperations` entirely and replaces them with
  internal/cli calling the libraries directly, per B.7.
- **Rollback's dm UUID comes from `(*Header).UUID()`, not from a second
  copy of the raw-header-bytes dance.** The pre-split `mappingUUID` cut the
  header's `[40]byte` UUID field at its first NUL before stripping dashes,
  because it read the field directly. `Header.UUID()` already returns that
  NUL-trimmed string (H9's `trimmedField`), so pkg/dmcrypt's own
  `mappingUUID(headerUUID, name string) string` only strips dashes and
  cuts to `dmUUIDMaxLength` -- the NUL handling doesn't need repeating
  because the new API already did it, one layer down.
- **Not done, and explicitly out of this step's scope: converting the
  integration-tagged test suites that called the deleted
  `Unlock`/`Lock`/`UnlockWithVolumeKey`/`CheckKeyringAvailable`.** `go vet
  -tags integration ./...` fails in exactly two packages:
  `pkg/luks2` (14 `*_integration_test.go` files -- compatmatrix, laned,
  lockcompat, mount, persistence, pinnedpaths, wipe, workflow,
  volumename, and others whose own subject is unrelated to activation but
  whose setup or teardown called it) and `test/integration/pkg_test` (7 of
  11 files, plus the package's shared `common_test.go` teardown helper).
  `pkg/luks2/release_test.go` (untagged, so it also affected the unit
  build) and its integration counterpart were deleted outright: their
  entire content was `releaseVolumeErr`, a teardown helper built on `Lock`,
  with no part reusable without it. Converting the rest means rewriting
  roughly 2,000 lines across both locations, for feature areas (FIPS
  import, wipe, tokens, workflow, loop identity) this lane has no context
  on, and it is DESIGN.md §E's and the H-table's own H12 ("test
  relocation... Convert black-box tests to the new API"), which runs
  after H10a-e and H11 land specifically so it can convert against the
  finished split API once, rather than each H10 lane guessing at it
  against its own partial slice. `go vet ./...` (no integration tag) and
  `go vet -tags integration ./pkg/dmcrypt/... ./cmd/luks2/...` are clean;
  pkg/dmcrypt ships its own `activate_integration_test.go` (root, real
  loop device via pkg/luks2's still-present `SetupLoopDevice` --
  pkg/loop is H10b's, not yet landed) covering the Activate/Lookup/
  Deactivate round trip, a real read/write through the mapping,
  ErrActive/ErrNotActive on the real control node, and CheckKeyring; it
  could not be run in this lane's sandbox (no root, no devcontainer) and
  needs `make integration-test` to actually execute.
- **Coverage.** `pkg/dmcrypt` measured 81.3% (222/273 statements) across
  repeated runs. The remaining gap is almost entirely `Activate`'s own
  body from `v.Header`/`v.Target` onward (needs a real block device:
  `(*Volume).Target` refuses a regular file with `ErrNotBlockDevice`,
  which this lane's unit tests exercise as a NEGATIVE case but cannot get
  past without root) and the live closures in `liveSeams` (`devmapper.
  Load`/`Resume`/`InfoByName`, never invoked by a fake). Per
  coverage-floors.txt's root-only convention (internal/dm and
  internal/keyring's own precedent): unit floor 80.50 (the half point
  below 81.3%, which leaves exactly 2 statements of slack), combined
  floor 90. `pkg/luks2` unit measured 88.9% afterward (floor unchanged at
  87.50).

## H9b (format.go, kdf.go, erase.go, passphrase.go: the §B.2 identifiers H9
left not implemented because they collide with an old exported identifier
under a different shape)

- **Three collisions, resolved by moving the OLD identifier's shape to a new
  name and giving the OLD name to the §B.2 definition**, per the lane brief's
  rule that the §B.2 shape wins and this step adapts callers:
  - `DefaultKDFType() string` (the detailed, hash-aliased default --
    `"pbkdf2-sha512"` in FIPS mode, `"argon2id"` otherwise) is renamed
    `DefaultKDFSpec`. `DefaultKDFType` now has the §B.2 shape, `func()
    KDFType`, carrying no hash. `cmd/luks2/kdfflags.go`'s `resolveFor` needs
    the detailed string (`pbkdf2Choice` extracts the hash suffix from it) and
    now calls `DefaultKDFSpec`; `kdfdefault_test.go` and
    `cmd/luks2/kdfflags_test.go`'s direct callers follow the same rename.
  - `ValidatePassphrase(passphrase []byte) error` is renamed
    `validatePassphraseBytes` (unexported: nothing outside this package calls
    it directly, unlike `DefaultKDFType`). `ValidateFormatOptions` and
    `ChangeKeyslot`'s two legacy call sites (`keyslot.go`) follow the rename;
    `security_test.go`'s two direct test functions are renamed
    `TestValidatePassphraseBytes`/`_EdgeCases` to match. `ValidatePassphrase`
    now has the §B.2 shape, `func(*enclave.MemoryEnclave) error`, in the new
    `passphrase.go`, implemented as one `secret.Borrow` around
    `validatePassphraseBytes` -- the length check is one policy, applied to
    the caller's enclave through the one window DESIGN.md §B.1 allows.
    `MinPassphraseLength`/`MaxPassphraseLength` already carry the exact
    values (8, 512) and shape §B.2's passphrase.go wants; they are left in
    `security.go` rather than moved, since moving a correct, unchanged
    constant block is churn with no behavior or API attached to it.
  - `DefaultCipher = "aes"` (the bare algorithm half of the old
    `Cipher`/`CipherMode` pair; cryptsetup's full spec was
    `DefaultCipher+"-"+DefaultCipherMode`) is renamed `defaultCipherAlgo`
    (unexported: both of its two call sites are inside `format.go` itself).
    `DefaultCipher` now has the §B.2 shape, the single spec string
    `"aes-xts-plain64"`. `DefaultKeySize` (512) and `DefaultSectorSize` (512)
    needed no rename: both pre-existing values already equal what §B.2 asks
    for under the same name, the one case where "the old identifier" and "the
    §B.2 definition" were never in conflict.
- **`FormatParams`/`KDFParams` give the legacy `FormatOptions`'s `HashAlgo`
  field the two independent hashes DESIGN.md gives the new API** --
  `FormatParams.Hash` (digest + anti-forensic) and `KDFParams.Hash` (PBKDF2
  PRF) -- rather than reproducing the old single-field double duty
  (`HashAlgo` named the digest/AF hash AND, unless a `KDFType` alias named
  one, the PBKDF2 hash; `kdfOpts := opts` captured before `opts.HashAlgo`
  defaulted was the historical fix for the ordering trap this produced,
  #237). `FormatParams.toFormatOptions` builds two independent
  `FormatOptions` values, `opts` (digest/AF) and `kdfOpts` (the KDF), each
  with its own already-resolved `HashAlgo`, so the alias-vs-override
  ordering the old single-field design needed never arises for this path.
  `KDFParams.resolved(fipsMode)` is the one place a hash is defaulted FROM a
  type: a `Type` left empty and defaulted to `KDFPBKDF2` (FIPS mode, no
  Argon2 cost given) defaults `Hash` to SHA-512, matching `DefaultKDFSpec`'s
  `"pbkdf2-sha512"`; a `Type` that is `KDFPBKDF2` for any other reason (named
  explicitly, or the non-FIPS no-cost default landing on `KDFArgon2id`
  instead) defaults `Hash` to SHA-256, matching `getHashAlgoForKDFType`'s
  plain-`"pbkdf2"` default. Both existing behaviors, reached from the typed
  side rather than a hash-aliased `KDFType` string.
- **`formatCore` is the Format/`(*Volume).Format` shared core, the same
  precedent `restorePrimaryHeaderCore` set for H9's header methods.** It is
  the body of the old `Format` from the point every option is resolved
  (layout, master key, KDF, digest, AF split, the write) through `f.Sync()`,
  taking `f`, `device` and the two already-resolved `FormatOptions` as
  parameters; the old `Format` is otherwise untouched (same
  `AcquireFileLock`/claim sequence, same defaulting, same SHA-1 and
  `af.ValidateWriteHash` pre-checks) and still reads this package's bare
  `custody`/`cryptoRand`/`fipsMode` seam vars directly, as it always has.
  `(*Volume).Format` does NOT thread `v.sys.custody`/`v.sys.cryptoRand`
  through `formatCore` to replace those bare reads: `CreateKDF`,
  `CreateBinaryHeader` and the rest of the format internals `formatCore`
  calls already read the bare vars unconditionally (H9's own scope note:
  "format internals" are explicitly not part of this round's seam
  migration), so threading the Volume's own seams into only the
  master-key-generation step would produce a half-migrated function that
  reads two different `custody`/`cryptoRand` sources depending on which
  nested call is asked. `(*Volume).Format` DOES resolve `FormatParams`
  against the bare `fipsMode()` (`toFormatOptions(v.path, fipsMode())`), not
  `v.sys.fipsMode()`, for a narrower reason: `FormatParams.Validate` (a
  value method with no `Volume` to draw a seam from) already judged `p`
  against that same bare seam one call earlier, and resolving the defaults
  against a different source could approve, moments later, what `Validate`
  had just refused.
- **`(*Volume).Erase` reuses `wipeHeaders` unchanged**, the same core
  `Wipe(WipeOptions{HeaderOnly: true})` already calls -- zeroing both header
  copies and the keyslot area, the crypto-erase `TestWipeHeaderOnlyIsACryptoErase`
  (#246 D3) holds `Wipe` to. `(*Volume).Erase` only supplies the exclusive
  lock and claim through `v`'s own pinned descriptor, the same pattern
  `(*Volume).RestorePrimaryHeader` set.
- **Tests.** New: `format_v2_test.go` (`(*Volume).Format`: PBKDF2 at the
  iteration floor and Argon2id at the lane's floor cost (m=64MiB, t=1, p=1),
  defaults, the FIPS-mode Argon2 refusal, an unsupported cipher/key-size
  combination, `ErrClosed`/`ErrReadOnly`, a canceled context -- each of the
  last four checked to write nothing), `erase_test.go`
  (`(*Volume).Erase`: the crypto-erase property, `ErrClosed`/`ErrReadOnly`),
  `kdfparams_test.go` (`KDFParams.Validate`, `FormatParams.Validate`,
  `DefaultKDFType`, `hashAlgoName`, `splitCipherSpec`), `passphrase_test.go`
  (the enclave `ValidatePassphrase`; no empty-passphrase case, unlike the
  renamed `TestValidatePassphraseBytes` --
  `enclave.NewMemoryEnclaveCopy` itself refuses empty material, so that input
  can never reach `ValidatePassphrase` through the enclave boundary).
  `pkg/luks2` unit coverage 89.9% (floor 87.50, unchanged).
- **Checks run**: `GOWORK=off go build ./...`, `go vet ./...` (also
  `GOOS=linux` under `GOARCH=386/arm/arm64`), `go test -race -count=1
  ./pkg/... ./internal/... ./cmd/...`, `make lint`, `make gosec` -- all
  clean. `go run ./test/tools/apidump dump ./pkg/luks2` shows every
  identifier this step owns (`FormatParams`, `FormatParams.Validate`,
  `Volume.Format`, `DefaultCipher`, `DefaultKeySize`, `DefaultHash`,
  `DefaultSectorSize`, `KDFType`, `KDFArgon2id`/`KDFArgon2i`/`KDFPBKDF2`,
  `KDFParams`, `KDFParams.Validate`, `DefaultKDFType`, `Volume.Erase`,
  `ValidatePassphrase`, `MinPassphraseLength`, `MaxPassphraseLength`) with
  the §B.2 signature.
- **Not done.** `RestorePrimaryHeaderWithOptions`'s caller-facing shape and
  every other H9b-adjacent gap H9's own entry already lists (`Header`'s
  `Segments`/`Tokens`/`Keyslots`, `KeyslotParams`/`AddKeyslot`/
  `ChangeKeyslot`/`RemoveKeyslot`, `Token`/`KeyProvider`/`Enroll`,
  `RecoveryKey`/`MigrateToFIPS` v2) are H9c/H9d/H9e's, not touched here.

## H12b (test relocation, #274)

- **`intstate_integration_test.go` is deleted, as H12a's own note said it
  should be.** 24 of the 29 `pkg/luks2/*_integration_test.go` files (plus
  `release_integration_test.go`'s `releaseVolume`,
  `root_integration_test.go`'s `requireRoot`,
  `volumename_integration_test.go`'s `runVolume`/mapping-name audit, and
  `leakledger_integration_test.go`'s `TestMain`) moved to
  `test/integration/<pkg>/`: `luks2` (argon2interop, format, header, info,
  keyslotpriority, keyslotsafety, persistence, token, unlock, workflow --
  10 files, plus the retired three's content folded into shared
  `common_test.go`/`runvolume_test.go`/`volumename_test.go`), `loop`
  (loopdev, converted to `pkg/loop`'s `Attach`/`Find`/`Lookup`/
  `Device.Detach` rather than pkg/luks2's forwarding names, since that
  package IS what moved), `wipe` (wipe, split between `pkg/wipe.Sanitize`
  for the whole-device passes `Wipe`'s own doc says forward there, and
  `luks2.Wipe`/`WipeKeyslot` for `HeaderOnly` and per-keyslot, which have no
  new-API equivalent yet), `dm` (activation, using `internal/dm`'s exported
  `MapperPath`/`MapperDir`/`IsOurNode` and the third-party `devmapper.go`'s
  `InfoByName` directly rather than pkg/luks2's unexported wrappers of the
  same names), `keyring` (keyring, using `internal/keyring`'s exported
  `Syscalls`/`Live`/`AddVolumeKey`/`Description`/`PinOSThread`/`KeyType`/
  `DescriptionPrefix` directly), `header` (headervalidation, using
  `internal/header`'s exported `ValidateHeaderStructure`/
  `MarshalCanonicalJSON`/`WriteEncodedHeader`), `kdf` (kdfiterations, using
  `internal/kdf`'s exported `PBKDF2IterationFloor`/`PBKDF2ReferenceTargetMs`/
  `MinPBKDF2Iterations`), `device` (laned, using `internal/device`'s
  exported `ReadPastCache` and `internal/header.HeaderAreaSize` in place of
  pkg/luks2's unexported `readDirectAt`/`keyslotsAreaBounds`), `filesystem`
  (mount, filesystem -- both already called only pkg/luks2's exported API
  despite DESIGN.md's white-box label; kept on `luks2.Mount`/
  `MakeFilesystem` rather than `pkg/filesystem`'s own, because those
  resolve a MAPPING NAME through device-mapper (`mappedDevicePath`, the
  C3/C5 fix) before forwarding, which is exactly what these tests are
  about and `pkg/filesystem.Mount`/`Make` do not do), and `interop`
  (compatmatrix only -- see below). Every moved file's `TestMain` is
  `harness.BeginSuite`/`Suite.Finish`, the same pattern
  `test/integration/pkg` and `test/integration/cli` already use; none
  needed a new one invented. `internal/header`, `internal/kdf`,
  `internal/dm`, `internal/keyring`, `internal/device` needed NO new
  exported surface for any of this -- H5-H7 had already exported what the
  former white-box files touched, which is the one assumption under this
  whole step that turned out true across the board.
- **27 unexported identifiers DESIGN.md §E expected to need
  exported-within-internal API turned out to be at most a handful.** Most
  of what looked white-box from inside `pkg/luks2` was already a one-line
  alias of an internal/* package's exported function (`pbkdf2IterationFloor`
  = `kdf.PBKDF2IterationFloor`, `validateHeaderStructure` =
  `header.ValidateHeaderStructure`, `mapperNodePath` = `dm.MapperPath(devDir,
  name)`, `keyringKeyType` = `keyringpkg.KeyType`, and so on) or a
  third-party library call pkg/luks2 does not wrap at all (`dm.infoByName` =
  `devmapper.InfoByName`). The exceptions below are the ONLY identifiers
  that are not: a bare, unexported, no-setter `pkg/luks2` package var, never
  moved to an internal/* package, with the test's whole point being to
  substitute it.
- **Five files stay in `pkg/luks2`, each for a seam with no path out,
  flagged for the owner the same way `test/integration/pkg`'s own
  `TestMain` already flagged the `dm.create` write-ahead-ledger gap on
  2026-09-01: an integration-build-tagged EXPORTED observer on pkg/luks2
  would close each of these too, and new exported surface on a Layer-0
  library is an owner's decision, not a lane's.**
  - `canonicalconformance_integration_test.go`: byte-for-byte header
    comparison needs `cryptoRand`/`newUUID`/`digestIterationsFor` pinned
    DURING a real `Format` call, through the exact seams `format.go` and
    `determinism_test.go` already define and never export. (Its own
    `marshalCanonicalJSON` helper is now literally `internal/header`'s
    exported `MarshalCanonicalJSON` -- that part was not the blocker.)
  - `pinnedpaths_integration_test.go`: drives `relinkAfterFirstOpen`
    (`relink_test.go`), which re-points a symlink from inside the
    unexported `openFileFunc` seam at the exact moment the locked-descriptor
    reopen (`Locked.Claim`) makes its first writable open.
  - `unlockreadlock_integration_test.go`: substitutes `readUnlockHeader`
    (`unlock.go`), the unexported seam for the header read `Unlock`
    performs under its shared lock.
  - `lockwait_integration_test.go`: `TestCryptsetupWaitsForEveryWritePath`
    substitutes `fileLockHeld` (`security.go`) to catch a write path just
    after it takes its locks. (Its sibling
    `TestEveryWritePathWaitsForCryptsetup` has no such dependency and could
    move alone, but splitting one file's two tests across two packages for
    one owner-flagged exception was judged not worth the churn.)
  - `lockcompat_integration_test.go`: `TestCompatMetadataLockDirectoryStates`
    re-execs this package's OWN test binary (`os.Args[0]`) and, in the
    child, sets `calibratedCountFloor` and `keyslotLockWait` -- both
    unexported package vars -- before running a go-luks2 operation. Moved
    out, the re-exec'd binary would be `test/integration/interop`'s own,
    unable to reach either var.
  These five keep `requireRoot`, `laneDLoop`, `lockFileFor`, `flockWaiterOn`,
  `deviceDigest` and `boolPtr` (token_test.go's untagged copy needs one for
  the integration build too) in one new file, `pinnedfixtures_test.go`, and
  a per-process atomic counter (`fixtureVolume`/`releaseFixture`) stands in
  for the full run-scoped ledger/suite machinery `intstate_integration_test.go`
  provided: with only five tests left creating at most one mapping each,
  cross-run collision protection is no longer earning its complexity.
  `canonicalconformance_integration_test.go` needs none of the above --
  confirmed by grep, not assumed -- so its presence here does not block
  anything.
- **`compatmatrix_integration_test.go` moved; its two interop siblings did
  not, for the identical seam reasons above**: `lockcompat`'s scenario
  re-exec and `lockwait`'s `fileLockHeld` substitution. `compatmatrix` was
  checked for the same class of dependency and has none -- it is pure
  black-box plus two test-local helpers (`parallel`, a locked-memory
  throttle; `mustCryptsetupPassphrase`/`cryptsetupWithStdin`) reimplemented
  in `test/integration/interop/main_test.go` rather than shared with
  `pkg/luks2`'s copies, since they cannot be imported across the package
  boundary either way.
- **Not done, and flagged rather than silently skipped:**
  - **CLI parity (DESIGN.md §E's `CommandDefinition`/`ArgDefinition` table,
    runner, enumerating test).** `internal/cli` (H11, #273) has not merged
    into this branch: `cmd/luks2` is still the pre-H11 `cli.go`/
    `operations.go` shape. Building the table against a registry that is
    about to be rewritten would be thrown away at the merge and risks a
    conflict in exactly the files #273 owns. This step is blocked on #273,
    not skipped by choice.
  - **`test/integration/pkg/*` fully retired.** DESIGN.md §E says its
    content splits into `test/integration/<pkg>/`, and the black-box
    counterparts this step wrote supersede `format_test.go`,
    `keyring_test.go`, `leakledger_test.go`, `loopidentity_test.go`,
    `runvolume_test.go`, `unlock_test.go`, `wipe_test.go` and
    `workflow_test.go` there -- but `fipsimport_test.go` and
    `sha1af_test.go` are NOT part of this issue's 29-file table and still
    need `runvolume_test.go`/`leakledger_test.go`'s `TestMain` for their own
    suite, so deleting the superseded files was not attempted this step:
    doing it half right (removing the infra two files out from under the
    two that stay) would be worse than leaving the duplication for the
    lane that moves `fipsimport`/`sha1af`.
  - **Makefile / coverage-floors.txt**: `ITEST_DIR_luks2`/`_dm`/`_keyring`
    overrides removed now that those are real directories;
    `COVERAGE_COMBINED_PKGS`/`_COVERPKG` gained `./pkg/loop` (it already
    carried a `combined 90` floor but was never actually in the instrumented
    set); `coverage-combined`'s integration invocation lists every new
    `test/integration/<pkg>/...` path. No `coverage-floors.txt` rows were
    added or changed: no new production package was created by this step,
    and `internal/header`/`internal/kdf`/`internal/device`/
    `pkg/filesystem`'s existing unit floors already clear 90% without a
    combined tier.

## H12c (finish the test relocation, #274)

- **Merged H12b off the shared object store, not a fetch.** This lane's
  `origin` is a bare mirror holding objects only -- no refs, no `HEAD` --
  so `git fetch origin issue/274-integration-tests` could not reach it.
  H12b's tip (`d45755b4`) was present as a dangling commit in the same
  object store the clone borrows read-only (`git fsck --unreachable`),
  parented on a commit already in this branch's history, with a message
  and diff matching the brief's description exactly; a local branch ref
  was pointed at it and merged (`git merge --no-ff`) in place of the
  fetch. Conflicts were exactly the three the brief predicted (Makefile,
  DECISIONS.md, the dm/luks2 rename-vs-delete pair) and resolved as
  directed.
- **Every integration test calling a deleted activation function
  (`Unlock`/`Lock`/`IsUnlocked`/`GetMappedDevicePath`/
  `CheckKeyringAvailable`) converts to the same two-package forward
  `cmd/luks2/cli.go`'s `DefaultLuksOperations` already uses (#268): open
  + `Volume.Unlock` derives the key, `dmcrypt.Activate` maps it.** Rather
  than rewrite each of the ~20 affected files' call sites individually,
  every `test/integration/<pkg>` package gained a local, capitalized
  `Unlock`/`Lock`/`IsUnlocked`/`GetMappedDevicePath` quartet with the OLD
  free functions' exact signatures, so each call site's fix is deleting
  the `luks2.` qualifier -- confirmed file by file with a grep for the
  five names after each edit. The capitalization is not cosmetic:
  `test/integration/luks2/volumename_test.go`'s mapping-name audit keys
  on the bare selector names `"Unlock"`/`"Lock"`, and a lowercase helper
  would have silently stopped it from auditing its own package's biggest
  caller of the pattern.
- **`test/integration/dmcrypt/` is new**, carrying the real-kernel safety
  assertions the old (pre-#268) `pkg/luks2/activation_integration_test.go`
  made that `pkg/dmcrypt/activate_integration_test.go` (H10a, #268) does
  not already cover: mapping-name traversal refusal, concurrent
  activations leaving exactly one winner, the longest legal name, a stale
  `/dev/mapper` node not being trusted, an interrupted cryptsetup
  reencrypt refused for activation, and an unbound keyslot not activating.
  Two of the old file's assertions moved elsewhere instead of here, because
  they were never really about activation: `FindLoopDevice` through a
  symlink is `pkg/loop`'s own concern (`test/integration/loop/loopdev_test.go`),
  and `IsMappingMounted` seeing a mounted mapping is `pkg/luks2.Mount`'s
  own C3/C5 fix (`test/integration/filesystem/mount_test.go`). The
  conflicting `test/integration/luks2/unlock_test.go` keeps only the
  unlock-WITHOUT-activation parts (key derivation: right passphrase,
  wrong passphrase, a nonexistent device) -- the full-round-trip and
  mapping-name-validation assertions it carried moved to `dmcrypt` and
  are now `pkg/dmcrypt`'s own `TestDeactivateReportsErrNotActiveOnTheRealKernel`
  and `ValidateName`, not duplicated.
- **`test/integration/pkg` is gone.** `format`/`keyring`/`leakledger`/
  `loopidentity`/`runvolume`/`unlock`/`wipe`/`workflow`_test.go and
  `common_test.go` are deleted, superseded exactly as H12b's own note
  said. `fipsimport_test.go` and `sha1af_test.go` (FIPS import and SHA-1
  anti-forensic volumes against the real kernel, #84/#236) moved to
  `test/integration/interop/`, the closest existing suite with the same
  cryptsetup-both-directions shape (DESIGN.md §E), taking `run`,
  `lockWithRetry` and `createTestFile` from `keyring_test.go`/
  `common_test.go` with them -- the infrastructure H12b's own note
  flagged as still needed. `interop`'s pre-existing `runVolume`/
  `releaseVolume`/`requireCryptsetupDeclared` covered the rest.
- **Of the five white-box `pkg/luks2` files DESIGN.md §E names, one
  moved cleanly and four did not.**
  - `unlockreadlock_integration_test.go` moved to
    `test/integration/luks2/unlockreadlock_test.go` outright. Its seam
    (`readUnlockHeader`) turned out not to exist any more -- the H9
    rewrite folded that read into `header.ReadHeaderCopyFrom`, called
    directly from `(*Volume).unlockHeader` with no package-level var left
    to substitute, which is why `go vet -tags integration` failed on it
    after the merge rather than on anything H12c touched. What the seam
    proved (the read does not race ahead of cryptsetup's write lock) is
    now proven by TIMING instead: `Volume.Unlock`'s first step is an
    `flock(2)` that must itself block behind cryptsetup's held `LOCK_EX`,
    so a call started inside the measured hold window either returns in
    microseconds (raced ahead, a failure) or only once the hold's
    remainder has elapsed (waited, the pass case). It also no longer
    creates a mapping at all -- `fixtureVolume`/`releaseFixture` were
    deleted from `pinnedfixtures_test.go` as dead code once nothing used
    them.
  - `pinnedpaths_integration_test.go`'s compile break (`undefined: Lock`,
    via `pinnedfixtures_test.go`'s `releaseFixture`) is fixed WITHOUT a
    mapping: `TestWipeKeyslotRefusesAnActiveDeviceDespiteARetarget` only
    needed device A to be `O_EXCL`-busy to the kernel, which an exclusive
    open this test takes directly produces identically to a real dm-crypt
    mapping (`internal/device.Open`'s own comment: EBUSY is "mounted,
    mapped, OR held open exclusively" -- the file's own header comment
    already named O_EXCL, not dm-crypt specifically, as the mechanism
    under test). The file otherwise STAYS in `pkg/luks2`: it still drives
    `relinkAfterFirstOpen` (`relink_test.go`), which substitutes
    `openFileFunc`, a production seam `volumeSys.openFile` already reads
    at `Open` time and that every other pkg/luks2 production call site
    (`format.go`, `medium.go`, `security.go`, `wipe.go`) and seven
    existing unit test files reassign. Relocating it into an
    exported-within-internal var (DESIGN.md §E) is a real production
    change to a Layer-0 library's open-file path, not a test-only one.
  - `canonicalconformance_integration_test.go` (`cryptoRand`/`newUUID`/
    `digestIterationsFor`), `lockwait_integration_test.go`
    (`fileLockHeld`), and `lockcompat_integration_test.go`
    (`calibratedCountFloor`/`keyslotLockWait`, plus its own re-exec of
    `os.Args[0]`) never called a deleted activation function and so never
    broke this merge -- they are exactly where H12b left them, still
    compiling and passing.
  - **All four are flagged for the owner, not attempted, for one
    reason: DESIGN.md §E says these become "exported-within-internal
    API" but not WHICH internal package or WHAT shape, and every
    candidate seam here is security- or determinism-relevant
    (the RNG source, a lock-held observer, a KDF iteration floor) in a
    Layer-0 library every Layer 1-3 library consumes.** Guessing a shape
    and being wrong costs the owner a second pass at code already
    exercising fault injection in a cryptography package; this is the
    same call H12b's own entry already made for `lockwait`/`lockcompat`,
    extended to `canonicalconformance`/`pinnedpaths` now that H12c has
    actually tried the alternative on `unlockreadlock` and `pinnedpaths`'
    other half and found it answerable only sometimes. Consequently
    `ls pkg/luks2/*_integration_test.go` is NOT empty at the end of this
    step -- four files, down from five.
- **CLI parity (DESIGN.md §E).** `internal/cli` gained
  `RegisteredVerbs() []string` (exported-within-internal, the registry's
  keys only, not the unexported `command` type) so a test outside the
  package can enumerate it. `test/integration/cli/commands` holds the
  `CommandDefinition`/`ArgDefinition` table for the 8 verbs it answers to
  today (`open`, `close`, `mount`, `unmount`, `testkey`, `wipe`,
  `header restore`, `isluks` -- H11b adds the rest as the registry grows
  past #273's partial state). `test/integration/cli`'s
  `TestEveryRegistryVerbHasADefinition` fails on a registry verb with no
  table entry; `TestCommandParityRefusesMissingArgumentsIdentically`
  crosses the table against {CLI binary (the built `cmd/luks2`, exec'd),
  embedded (`internal/cli.Run`, in-process)} and asserts both refuse a
  call missing its required arguments with the same exit code (1,
  DESIGN.md §F). Both tests run and pass WITHOUT root in this lane's
  sandbox -- every case here is a `UsageError` raised during flag
  parsing, before either path touches a device -- unlike the rest of
  `test/integration/cli`, which needs loop/dm access this sandbox does
  not have.
- **Makefile.** `integration-test-pkg` (ran the now-deleted
  `test/integration/pkg/...`) is removed, along with its `.PHONY` entry.
  `coverage-combined`'s integration invocation drops
  `./test/integration/pkg/...` and renames `./test/integration/dm/...` to
  `./test/integration/dmcrypt/...`. `COVERAGE_COMBINED_PKGS`/`_COVERPKG`
  gain `./pkg/filesystem` (already carrying a `combined 90` floor, like
  `./pkg/loop` before H12b, but never actually in the instrumented set --
  the "the profile records no statements" CI failure this step's brief
  named). No `coverage-floors.txt` rows added or changed.
- **Not done, flagged above rather than silently skipped:** the four
  `pkg/luks2` white-box files' internal-API exposure. Everything else
  the brief's "Done when" list names was run and is green in this
  sandbox: `go build ./...`, `go vet ./...` and `go vet -tags integration
  ./...` (also cross-compiled for `GOOS=linux` `GOARCH=386/arm/arm64`,
  with and without the integration tag), `go test -race -count=1
  ./internal/... ./pkg/... ./cmd/... ./test/...` (green except the two
  trivy tests the brief names as expected to fail on busybox), `make
  lint`, `make gosec`, and `make -n coverage-combined` showing every
  combined-floor package (`pkg/luks2`, `pkg/dmcrypt`, `pkg/loop`,
  `pkg/filesystem`, `test/internal/harness`, `internal/dm`,
  `internal/keyring`).

## H9c (pkg/luks2 API: Header read model's remaining methods, keyslot.go)

- **`KeyslotInfo` and `Priority` are redefined in place, exactly as DESIGN.md
  §B.2 writes them, resolving the collision H9's own entry flagged
  (`KeyslotInfo` already existed with `Priority int`, `KDFType string`,
  `PBKDF2Iterations`, `Argon2Time`, `Argon2MemoryKB`, `Argon2Parallel` --
  fields the new `KeyslotInfo{ID, Type, KeySize, Priority Priority,
  Encryption, KDF KDFParams}` replaces outright).** `Priority`'s three
  constants (`PriorityIgnore/Normal/Prefer`, values 0/1/2) are new names
  beside the OLD untyped `KeyslotPriorityIgnore/Normal/Prefer` constants
  (same values, different names) -- no collision there, both are kept, and
  every existing caller of the old names is unaffected. `listKeyslotsFrom`
  (shared by the old package-level `ListKeyslots` and the new
  `(*Header).Keyslots`) is rewritten to build the new shape directly, so
  the two can never report a different one for the same container. Callers
  that read the OLD KeyslotInfo fields were adapted in place rather than
  left to break: `cmd/luks2/keyslotcmd.go`'s listing (`s.KDFType` ->
  `s.KDF.Type`) and the test literals/assertions across
  `pkg/luks2/keyslot_test.go`, `keyslotvalidation_test.go`,
  `keyslotcostpolicy_test.go`, `argon2interop_integration_test.go`,
  `keyslotpriority_test.go`, `keyslotpriority_integration_test.go`,
  `cmd/luks2/keyslotcmd_test.go` and `cmd/luks2/mockops_test.go`.
- **`KDFParams`/`KDFType` are H9b's to define, per the lane brief's shared-
  type rule ("define it exactly as §B.2 writes it, in the file §B.2 puts it
  in... the train merge takes one identical copy"): added to `kdf.go`,
  text-for-text against the §B.2 block, since `KeyslotInfo.KDF` and
  `KeyslotParams.KDF` need the type to exist.** The free-standing
  `func DefaultKDFType() KDFType` from that same §B.2 block is deliberately
  NOT added here: it collides with the existing `func DefaultKDFType()
  string` (same name, Go has no return-type overloading), and resolving
  that collision means rewiring `cmd/luks2/kdfflags.go` and several
  `DefaultKDFType`-reading tests -- `format.go`/`kdf.go`'s own rewrite,
  which is H9b's full scope, not a byproduct of defining one struct here.
  AddKeyslot/ChangeKeyslot resolve a zero `KDFParams.Type` through the
  existing private `resolveKDFType`/`defaultKDFTypeFor` machinery instead
  (via `KeyslotParams.toAddKeyOptions` leaving `AddKeyOptions.KDFType`
  empty), so nothing here depends on the public function existing.
  `KDFParams.Validate` is new (not in H9b's conflict set: no existing
  `(KDFParams) Validate` to collide with) and checks exactly what its
  doc comment promises -- a known `Type` and, under FIPS 140-3 mode, that
  an Argon2 `Type` is refused with `ErrFIPSNotApproved` -- leaving the
  numeric cost floors to the existing `CreateKDF`/`forcedPBKDF2Iterations`
  machinery AddKeyslot and ChangeKeyslot already call through.
- **`Segment` is redefined in place, replacing the `Segment = header.Segment`
  alias H5 left**, the migration H9's entry considered and deferred as "a
  dozen test literals." The dozen (and more: 15 `pkg/luks2` files plus one
  in `cmd/luks2`, counting the ones using `*Segment` as a bare function
  parameter type as well as a map value type) were adapted in place to name
  the on-disk type directly, `*header.Segment` -- the only place it still
  needs to exist, since `(*Header).Segments()` now returns the clean value
  type and nothing in this package other than `format.go` and
  `unlock.go`'s `activationSegment` writes or reads the raw on-disk shape
  anymore. `SizeDynamic` is new, in `header_v2.go` beside `Segment`, per
  §B.2.
- **`(*Header).Size`, `.Keyslots` and `.Segments` are implemented, closing
  two of the three gaps H9's entry left open.** `Size` is the binary
  header's own `hdr_size` field (`internal/header.BinaryHeader.HeaderSize`),
  bounded by `header.HeaderMaxSize` (4 MiB) -- `#nosec G115` on the
  `uint64->int64` conversion names that bound rather than silencing the
  finding blind. `Segments` converts every entry in
  `metadata.Segments` (`header.SortedIDs` order) through the same
  string-offset/size parsing `unlock.go`'s `Target` and
  `addKeyslotWithMasterKeyAndPriority` already do, tolerating a
  non-canonical id or an unparsable field by omitting or zeroing it rather
  than failing the whole listing -- `Segments` has no error return in
  §B.2, and a listing is an inspection operation, the same principle
  `listKeyslotsFrom`'s own tolerance comment already states for keyslots.
- **`(*Header).Tokens` is NOT implemented, and this is the same structural
  finding H9's entry made about `Keyslots`/`Segments`, not a new one.**
  `Token` (DESIGN.md §B.2's clean value: `Type`, `Keyslots`, `Members`) is
  explicitly H9d's to define ("H9d: token.go and provider.go (Token as a
  value...)"), and the Rules section's own collision example -- "the old
  `Token` struct against the new `Token` value" -- is this exact
  identifier. Unlike `KeyslotInfo`/`Segment`, resolving it is not a bounded,
  in-package rename: the OLD `Token = header.Token` alias (FIDO2 fields and
  all) is load-bearing for `pkg/keyprovider` (`Command`, `FIDO2`,
  `FromToken`) and `cmd/luks2`'s token commands, none of which are in this
  lane's file list, and H9d's own brief is explicitly building the new
  `KeyProvider` interface and `Enroll` against the new shape with those
  callers in mind. Attempting it here would race H9d's own redefinition of
  the same identifier on the same train head. Flagged, as H9's entry
  flagged the equivalent gap, for the coordinator: `Header.Tokens` lands
  whenever H9d's `Token` does.
- **`AddKeyslot`/`ChangeKeyslot` reuse the existing write paths rather than
  re-implement them, per the lane brief.** `addKeyslotWithMasterKey` is
  kept as a thin forward to a new `addKeyslotWithMasterKeyAndPriority`,
  which is the same function with one added parameter (`priority *int`,
  nil for every existing caller -- byte-identical behavior for `AddKey`).
  `ChangeKey` is split at the point it already held the master key:
  everything after is `changeKeyslotCore(ctx, dev, hdr, metadata,
  slotIDStr, keyslot, targetKeyslot, masterKey, newPassphrase) error`, and
  `ChangeKey` itself is now five lines calling it. `KillKeyslot` is split
  the same way into `removeKeyslotCore`. `(*Volume).RemoveKeyslot` takes no
  credential, matching `KillKeyslot` (not `KillSlot`/`RemoveKey`, which
  require one) -- the owner ruling the lane brief names.
- **The volume key reaches these write paths without ever leaving protected
  memory in this package's own hands.** `key *Key`'s bytes are reachable
  only through `volkey.Borrow`'s window (DESIGN.md §B.1); `cloneKeyEnclave`
  borrows them once, into a NEW enclave via `v.sys.custody.Clone`, the same
  pattern `(*Volume).UnlockWithVolumeKey` already uses to hand back an
  independently destroyable copy. That clone is what `
  addKeyslotWithMasterKeyAndPriority`/`changeKeyslotCore` receive as
  `masterKey`, and it is released (`v.sys.custody.Release`) when the method
  returns. `pass *enclave.MemoryEnclave` (the new credential) is borrowed
  with `secret.Borrow` for exactly the one call that must see its raw
  bytes, never copied out past that closure.
- **`ChangeKeyslot`'s `p KeyslotParams` does not consult `p.KDF` or
  `p.Priority`.** `p.Slot` is never consulted either (DESIGN.md §B.2's own
  comment: "the slot key came from"). This matches `changeKeyslotCore`'s
  (and the old `ChangeKey`'s) documented contract verbatim: "a passphrase
  change is not a request to re-cost the keyslot," and nothing in that
  contract mentions priority. A caller that wants a different cost or
  priority still has `RemoveKeyslot` + `AddKeyslot`.
- **Tests are real temp-file volumes, built on `formattedVolumeImage`
  (`PBKDF2IterTime: 1`, floored to 1000 iterations by this package's own
  `TestMain` override of `calibratedCountFloor`) -- no mocks.** The one
  cost-preservation test that needs a cost ABOVE the floor to prove
  "preserved, not recalibrated" (`TestVolumeChangeKeyslotPreservesThe
  ExistingPBKDF2Cost`) formats with an explicit `PBKDFIterations: 700_000`
  instead, since an explicit count is checked against the real
  caller-credential floor (`forcedPBKDF2Iterations`), not the overridable
  one calibration uses.
- **Coverage.** `pkg/luks2` unit 89.3-89.4% across runs (floor 87.50,
  unchanged file-count-wise from H9; the new files' own lines are covered
  above what they added). `make lint` and `make gosec` both pass across
  the whole module (0 issues each after one `#nosec G115` annotation on
  `(*Header).Size`).

## H9d (token.go and provider.go: Token, KeyProvider, Enrollment, Enroll, UnlockWithProvider)

- **The `Token`/`KeyProvider` collision H9 and H10d both flagged is resolved
  here, per the lane brief's direct owner ruling** ("no backward
  compatibility is required... the §B.2 definition wins. Replace the old one
  in place and adapt its callers"), superseding H9's "flagged for the
  coordinator/owner" posture. `pkg/luks2.Token` is now the generic,
  value-returning `Token{Type string; Keyslots []int; Members
  map[string]json.RawMessage}` (token.go), with its own `MarshalJSON`/
  `UnmarshalJSON`: Type and Keyslots (re-encoded as the canonical
  decimal-string array LUKS2's wire format requires) are merged with every
  entry of Members, so a token type this package does not model -- FIDO2's
  fields, a systemd-tpm2 token -- survives a read-modify-write untouched, the
  same passthrough guarantee `internal/header.Token`'s own unknown-field
  handling already gives the old shape.
- **The retired shape did not disappear: it is `LegacyToken` now
  (types.go), a straight rename of the `Token = header.Token` alias.**
  Every pre-existing consumer of the old on-disk shape -- `token.go`'s own
  `GetToken`/`ListTokens`/`ImportToken`/`ImportTokenJSON`/`RemoveToken`/
  `FindFreeTokenSlot`/`TokenExists`/`CountTokens` (free functions, so no
  collision with the new `(*Volume)` methods of three of those names --
  methods and package-level functions do not share a namespace, the same
  rule H9's entry used for `Unlock`/`Target`), `keyprovider.go`'s
  `enrollWithToken`/`importTokenLocked`/`recoveryToken` (recovery.go), and
  every test building an old-shape token literal, is repointed from `Token`
  to `LegacyToken` with NO logic change -- `format.go`'s `createMetadata`,
  `keyprovider.go`'s `EnrollKeyProvider`/old free `UnlockWithProvider`, and
  every existing `ImportToken`/`GetToken` test keep their exact prior
  behavior and still pass unmodified in substance. `Token.toLegacyToken`/
  `tokenFromLegacy` (token.go) are the one conversion boundary, built by
  round-tripping through each type's own JSON codec rather than hand-copying
  fields, so `LegacyToken`'s typed FIDO2 members and unknown-field
  passthrough are reached by `encoding/json`, not reimplemented.
  `EnrollKeyProvider` converts `p.Token()`'s new shape to `*LegacyToken`
  (nil for a zero-Type, anonymous provider) at exactly the point it used to
  read `p.Token()` directly; nothing downstream of that line changed.
- **`KeyProvider` is replaced in place**: `Token() Token` (value), a zero
  Type meaning anonymous, replacing `Token() *Token` (nil meaning
  anonymous). `pkg/keyprovider.Command`/`FIDO2` (H10d's) are adapted to the
  new interface they were built one collision away from (per H10d's own
  entry and doc comments, now removed): `Command.token` is a `Token` value,
  not a `*Token`; `fido2Token`/`fido2ParamsFromToken` (fido2.go) no longer
  read or write typed `FIDO2Credential`/`FIDO2Salt`/`FIDO2RP`/
  `FIDO2*Required` fields, which do not exist on the new `Token` -- they
  build/read `Members["fido2-credential"]` etc. as `json.RawMessage`
  instead, the comment at the top of that section ("EVERY read and write of
  a Token's FIDO2 fields... happens in the two functions below") holding
  exactly as promised: no other line in `pkg/keyprovider` needed to change
  for the shape move. `FromToken` takes `Token` by value, matching §B.4.
  `TestFIDO2TokenRoundTripsEveryRequirement` (lane_test.go) -- which decodes
  `fido2Token`'s output and greps the encoded JSON for the two requirement
  members -- passes unmodified in intent, because `Token.MarshalJSON` merges
  `Members` into the top-level object rather than nesting it.
- **`pkg/luks2`'s own old enrollment tests are adapted, not deleted,
  because the collision does not reach their actual subject.**
  `keyprovider_test.go`'s `fakeKeyProvider.token` becomes a `Token` value.
  Two tests (`TestEnrollKeyProviderRollsBackAKeyslotItCannotIdentify`,
  `TestEnrollKeyProviderReportsAnOrphanItCannotRemove`) used to inject their
  failure with a non-nil `*Token{}` of empty type -- a distinction ("there
  is a token, but it is malformed") the value-returning interface cannot
  express, since a zero Type is now unconditionally anonymous. Both are
  rewritten to give the provider a real, valid token type and force the
  failure through the `importToken` package-var seam instead -- the seam
  `importToken`'s own doc comment names for exactly this purpose ("there is
  no argument a test can pass that makes the write fail... reached through a
  variable so the rollback itself can be exercised"). The behavior under
  test (an unwritable token rolls the keyslot back; an unremovable orphan is
  reported) is unchanged.
- **`KeyslotInfo` collides too, forced by `Enrollment.Keyslot KeyslotInfo`
  (§B.2, this lane's own type) needing the new shape to exist at all.**
  This identifier is explicitly H9c's (header.go, the Header read model) and
  H9c has not landed on this branch -- the two lanes run from the same train
  head in parallel. Per the same owner ruling, the new shape (`header_v2.go`:
  `KeyslotInfo{ID, Type, KeySize, Priority Priority, Encryption, KDF
  KDFParams}`, with `Priority`/`PriorityIgnore`/`PriorityNormal`/
  `PriorityPrefer` beside it) replaces the old one in keyslot.go in place,
  and `listKeyslotsFrom` -- the one production constructor -- is adapted:
  its scan-order walk, its "an absent priority is normal, not ignore"
  reasoning (MEASURED against cryptsetup, #35/#57 precedent) and its
  "kdf/area are optional" handling are UNCHANGED; only the final struct
  literal and the four-field-to-`KDFParams` conversion (factored out as
  `keyslotInfoFromEntry`, shared with `Enroll`) moved. `AddKeyslot`/
  `ChangeKeyslot`/`RemoveKeyslot` -- the new methods that go with the new
  shape -- are NOT implemented here; that remains H9c's, same division the
  lane brief states. `KeyslotParams{Slot, Priority, KDF KDFParams}`
  (keyslot.go, replacing the removed old `KeyslotInfo`'s file position) and
  `KDFType`/`KDFParams` (kdf.go, H9b's identifiers) are added as minimal,
  field-only stand-ins for exactly the same reason: `Enroll`'s signature
  needs them. `KDFParams.Validate()` and `func DefaultKDFType() KDFType` are
  NOT implemented -- the latter collides with the existing `DefaultKDFType()
  string` (kept for #237's FIPS-default ordering) exactly as H9's entry
  documented, and resolving that FIPS-approval logic is H9b's
  (`FormatParams`/`Format`), not forced open by anything this lane's own
  code needs. The train merge is expected to reconcile whichever of this
  lane's and H9c's/H9b's copies of these shared types land second; all three
  are written to match §B.2's field list exactly so the reconciliation is a
  duplicate-definition removal, not a shape negotiation.
- **`KeyslotParams.Priority` is accepted but not wired to a write.**
  `addKeyslotWithMasterKey`, the internal `Enroll` is built on, has no
  priority parameter -- a keyslot it creates always carries LUKS2's
  absent-member default (normal). Wiring a priority through is a change to
  that internal, shared with the not-yet-written `AddKeyslot`, and is left
  to whichever step gives it a write path (plausibly H9c, since it owns
  `AddKeyslot`). Noted on `KeyslotParams` itself so a caller does not infer
  the field works from its presence.
- **`Enroll` is built on `enrollWithToken`'s own internals, not a copy of
  its logic**: `addKeyslotWithMasterKey` (which re-verifies the supplied key
  against the header's digests via `digestAttestingKey`/`evaluateDigest`
  under THIS call's own exclusive lock -- DESIGN.md §B.1's "re-verify
  because the header may have changed since Unlock" requirement, satisfied
  by the internal Enroll already calls rather than a separate check) and
  `importToken`/`killKeyslot` (the same seams) for the token write and its
  rollback. The one real difference from `enrollWithToken` is the credential
  source: `Enroll` receives an already-recovered `*Key` rather than an
  `existing` passphrase to re-derive one from, so it clones the key's bytes
  into a fresh enclave (`v.sys.custody.Clone`, the same pattern
  `UnlockWithVolumeKey` uses for the opposite direction) instead of calling
  `getVolumeKey`. The lock, claim and header I/O go through `v.lockFor`/
  `Locked.Claim`/a `keyslotDevice` literal built directly from the claimed
  file -- DESIGN.md §B.1's type-enforced lock order -- rather than
  `lockKeyslotDevice`'s path-based open, which would reopen the path Volume
  already pinned (the exact problem `Volume`'s own design note in H9's
  `Open` entry describes).
- **`UnlockWithProvider` (the new `(*Volume)` method) does not collide with
  the old free `UnlockWithProvider`** (keyprovider.go) -- methods and
  package-level functions do not share a namespace, as above -- and the old
  one is untouched: its body never calls `p.Token()`, so the interface
  shape change does not reach it. The new method tries only
  `p.Token().Keyslots`, passed to the existing `getMasterKeySlot` as the
  candidate id list (the same internal `UnlockKeyslot` uses for one slot),
  after checking each is bound to the volume's data segment -- the same
  `ErrInvalidKeyslot` guard `UnlockKeyslot` gives a single slot (#250).
- **Tests.** New: `token_v2_test.go` (`AddToken`/`SetToken`/`RemoveToken`,
  real temp-file volumes, including the read-only/closed/invalid-id/
  empty-type error paths), `token_v2_json_test.go` (`Token`'s own
  `MarshalJSON`/`UnmarshalJSON`, the keyslots-never-null rule, the
  `LegacyToken` conversion round trip), `provider_v2_test.go` (`Enroll` --
  success, anonymous provider, token-write rollback via the `importToken`
  seam, nil-provider and read-only refusals -- and `UnlockWithProvider` --
  success, no-keyslots refusal, unbound-keyslot refusal, nil-provider
  refusal). Adapted: `keyprovider_test.go`, `keyprovider_lane_test.go`,
  `recovery_test.go`, `recovery.go`, `format.go`, `keyslot.go`,
  `keyslot_test.go`, `keyslotpriority_test.go`,
  `keyslotpriority_integration_test.go`, `keyslotvalidation_test.go`,
  `keyslotcostpolicy_test.go`, and every token-literal test the `Token` ->
  `LegacyToken` rename reached (`token_test.go`, `token_integration_test.go`,
  `tokenimport_test.go`, `unmodeledmembers_test.go`, `headerarea_test.go`,
  `canonicaljson_test.go`, `compatmatrix_integration_test.go`,
  `conformance_test.go`, `header_test.go`, `headerrestore_test.go`,
  `headersingleread_test.go`, `headervalidation_helpers_test.go`,
  `headervalidation_integration_test.go`, `nullkeyslot_test.go`,
  `pinnedpaths_integration_test.go`, `pinnedpaths_test.go`); in
  `pkg/keyprovider`, `command.go`, `fido2.go`, `fido2_test.go`,
  `lane_test.go`; in `cmd/luks2`, `operations.go`, `cli.go`,
  `keyslotcmd.go` (display: `s.KDFType` -> `s.KDF.Type`), and the mock/test
  files that construct a `luks2.Token`/`luks2.KeyslotInfo` literal
  (`mockops_test.go`, `failurepaths_test.go`, `destructive_test.go`,
  `operations_test.go`, `keyslotcmd_test.go`). One rename genuinely did NOT
  belong to this collision and was reverted after the first blanket pass
  caught it: `encoding/json.Decoder.Token()` (`unknownfields_test.go`) is
  the standard library's own, unrelated method of the same bare name.
- **Checks.** `GOWORK=off go build ./...`, `go vet ./...` and `go vet -tags
  integration ./...` clean; `GOOS=linux GOARCH={386,arm,arm64} go vet ./...`
  clean; `go test -race -count=1 ./pkg/... ./internal/... ./cmd/...`
  green (`pkg/luks2` 146s, `internal/cli` 52s, both include real
  cryptsetup-backed conformance tests in this environment); `make lint`
  (0 issues) and `make gosec` (0 issues, 163 files) both pass across the
  whole module; `pkg/luks2` unit coverage measured 89.5%, floor 87.50
  (not raised: already measured comfortably above floor before this
  entry's additions, so there is no new slack to bank -- see this file's
  rule on raising only from a measured reason). `apidump dump ./pkg/luks2`
  shows `Token{Type,Keyslots,Members}`, `MaxTokens`, `TokenTypeRecovery`,
  `KeyProvider{Passphrase,Token}`, `Enrollment{Keyslot,Token}`,
  `Volume.AddToken`/`SetToken`/`RemoveToken`/`Enroll`/`UnlockWithProvider`,
  all under this lane's own names.
- **Not done.** `(*Volume).AddKeyslot`/`ChangeKeyslot`/`RemoveKeyslot` and
  the rest of the Header read model's `Keyslots()`/`Segments()`/`Tokens()`
  (H9c's, not landed on this branch); `KDFParams.Validate()` and
  `DefaultKDFType() KDFType` (H9b's, blocked on the pre-existing
  `DefaultKDFType() string`); `KeyslotParams.Priority` wired to an actual
  keyslot write (blocked on `addKeyslotWithMasterKey` gaining a parameter
  for it, noted above); `FormatParams`/`Format` v2, `RecoveryKeyOption`/
  `NewRecoveryKey`/`AddRecoveryKey` v2, `MigrateParams`/`MigrateToFIPS` v2,
  `Erase`, `ValidatePassphrase` v2 -- none of these were in this lane's
  file list (token.go, provider.go) and none were touched.

## H9e (recovery.go, fips.go)

- **Scope.** DESIGN.md §B.2's `recovery.go` (`RecoveryKeyFormat`,
  `RecoveryKey`, `RecoveryKeyOption`/`WithRecoveryFormat`/
  `WithRecoveryLength`, `NewRecoveryKey`, `ParseRecoveryKey`,
  `(*Volume).AddRecoveryKey`) and `fips.go` (`MigrateParams`, `Migration`,
  `(*Volume).MigrateToFIPS`, `NonApprovedKDF`, `FIPSMigrationStage`). Built
  on the package's existing internals -- `enrollWithToken`'s underlying
  `addKeyslotWithMasterKey`/`freeTokenSlot`/`importToken`/`killKeyslot`
  for `AddRecoveryKey`, and `migrateToFIPS` (the ctx-threaded core
  extracted from the free `MigrateToFIPS`, same precedent as H9's
  `restorePrimaryHeaderCore`) for `MigrateToFIPS` -- not reimplemented.
- **Shared types this step needed but does not own**: `KDFType`/`KDFParams`
  (kdf.go, H9b's), `Priority`/`KeyslotParams`/`KeyslotInfo` (keyslot.go,
  H9c's), `Enrollment` (provider.go, H9d's -- the rest of that file,
  `KeyProvider`/`Enroll`/`UnlockWithProvider`, is NOT implemented here).
  Each is defined exactly as §B.2 writes it, in the file §B.2 puts it in,
  per the lane brief; the train merge is expected to take one identical
  copy of each. `DefaultKDFType() KDFType` is deliberately NOT added:
  H9's own entry already records that name colliding with the existing
  `func DefaultKDFType() string` (kdf.go), owned by H9b and depended on by
  `cmd/luks2/kdfflags.go` and several `pkg/luks2`/`cmd/luks2` tests outside
  this step's files. `AddRecoveryKey` and `MigrateToFIPS` do not need it:
  an empty `KDFParams.Type`/`AddKeyOptions.KDFType` already means "library
  default" to every internal that resolves it.
- **Collisions resolved, per the lane brief's "no backward compatibility
  required" ruling** (old identifier renamed via Serena's reference-aware
  `rename_symbol`, so every caller -- including `cmd/luks2` and test files
  this step does not otherwise touch -- moved with it in one atomic change):
  - `RecoveryKeyFormat` (type `string`, consts `RecoveryKeyFormatHex`/
    `Dashed`/`Base64`) -> `LegacyRecoveryKeyFormat`. The new
    `RecoveryKeyFormat` is `uint8` with `RecoveryDashed`/`RecoveryHex`/
    `RecoveryBase64`, as §B.2 writes it.
  - `RecoveryKey` (exported fields, including a `Format` field that
    collides with the new API's `(*RecoveryKey) Format()` method -- the
    exact collision H9's entry already flagged as blocking) ->
    `LegacyRecoveryKey`. The new `RecoveryKey` has unexported fields and
    accessor methods, obtainable only from `NewRecoveryKey`.
  - `ParseRecoveryKeyFormat(string) (RecoveryKeyFormat, error)` ->
    `ParseLegacyRecoveryKeyFormat`. The new function of the same exported
    name returns the new `RecoveryKeyFormat`.
  - `ParseRecoveryKey(string) (*enclave.MemoryEnclave, error)` ->
    `ParseLegacyRecoveryKey`. The new `ParseRecoveryKey(*enclave.
    MemoryEnclave) (*enclave.MemoryEnclave, error)` normalizes a credential
    the caller has already placed in protected memory (via
    `internal/recoverykey.Credential`, reused, not reimplemented) and never
    passes it through a Go string -- unlike `RecoveryCredential`, kept
    as-is since it has no name collision.
  - `KeyslotInfo` (fields `Priority int`, `KDFType string`, ... -- the
    on-disk-shaped struct `ListKeyslots`/`AddKey`/`ChangeKey` and
    `cmd/luks2` already return/consume) -> `LegacyKeyslotInfo`. The new
    `KeyslotInfo{ID, Type, KeySize, Priority Priority, Encryption, KDF
    KDFParams}` is built fresh, read back from on-disk metadata after a
    write (`keyslotInfoFromMetadata`, `kdfParamsFromDisk`).
  - `NonApprovedKDF.ID` (`string`, a canonical keyslot/digest ID) ->
    `int`, converted at its two construction sites
    (`keyslotFIPSRefusal`/`digestFIPSRefusal`, `strconv.Atoi` on an ID that
    is always a small decimal integer) and its handful of consumers
    (`fipsmigrate.go`'s final-check formatting, `FIPSImportRequiredError.
    Error`, and the six test files that construct or compare `.ID`
    directly). `NonApprovedKDF` already existed as an exported type with
    the `Type`/`Hash`/`Reason` fields and `String()` method §B.2 asks for;
    only `ID`'s type needed to change.
  - `AddRecoveryKey` (free function) and `(*Volume).AddRecoveryKey`
    (method), and `MigrateToFIPS` (free function) and
    `(*Volume).MigrateToFIPS` (method), do NOT collide: a method and a
    package-level function of the same name do not share a namespace (the
    same non-collision H9's entry already notes for `Key`/`Unlock`/
    `Target`).
- **`Priority`'s zero value is a genuine DESIGN.md defect, not something
  this step resolved by reordering the enum.** §B.2 writes `const
  (PriorityIgnore Priority = iota; PriorityNormal; PriorityPrefer)`,
  literally making `PriorityIgnore` the zero value -- while this package's
  own existing convention, stated on the on-disk `KeyslotPriorityIgnore`
  block (keyslot.go) and unchanged by this step, is the opposite: an
  ABSENT/zero priority means NORMAL, specifically so a caller who never
  touches it does not get an unlock that silently skips the slot. Since
  `KeyslotParams{}`'s zero value is supposed to mean "library policy"
  (DESIGN.md §B.1's options-style convention, which names `KeyslotParams`
  by name), `(*Volume).AddRecoveryKey` resolves the tension by writing an
  explicit on-disk priority only for `PriorityPrefer`; `PriorityIgnore` and
  `PriorityNormal` both leave the member absent, i.e. normal. A caller
  cannot currently ask this method for an actually-ignored recovery
  keyslot. Flagged for the owner/H9c, since the clean fix -- reordering the
  enum so `PriorityNormal` is the zero value -- changes a type H9c also
  depends on.
- **Tests.** `recovery_v2_test.go` and `fips_v2_test.go` (new, following the
  `header_v2.go`/`key_v2.go` naming precedent for new-API files alongside
  old same-named ones), against real temp-file volumes at the Argon2id
  floor (m=64MiB, t=1, p=1) DESIGN.md's lane brief asks for:
  `NewRecoveryKey`'s options and errors, `ParseRecoveryKey`/
  `ParseRecoveryKeyFormat`, `(*Volume).AddRecoveryKey` (a working keyslot
  that actually unlocks, `PriorityPrefer`, nil-key/nil-recovery-key/
  read-only-volume refusals, and the token-write rollback path via the
  `importToken` seam), and `(*Volume).MigrateToFIPS` (importing an Argon2id
  volume, `KeepNonApproved`, the FIPS-mode and read-only-volume refusals).
  All pass, including under `-race`; the pre-existing full `pkg/luks2`,
  `internal/...` and `cmd/luks2` suites are unchanged by the renames above
  (`go test -race -count=1 ./pkg/... ./internal/... ./cmd/...` is green).
- **Not done, out of this step's scope**: `KeyProvider`, `Enroll`,
  `UnlockWithProvider`, `AddToken`/`SetToken`/`RemoveToken` (H9d's);
  `FormatParams`/`Volume.Format`/`DefaultKDFType() KDFType` (H9b's, and
  blocked exactly as H9's own entry records); `AddKeyslot`/`ChangeKeyslot`/
  `RemoveKeyslot`, `Header.Keyslots()` (H9c's -- `keyslotInfoFromMetadata`
  and `kdfParamsFromDisk`, added here because `Enrollment.Keyslot` needs
  them, are available for that method to reuse). `FIPSMigrationStage`'s
  five values are declared as §B.2 writes them but are not wired into
  `FIPSMigrationError.Stage` (still the existing 8-value string); DESIGN.md
  §B.2 does not show that wiring on any function signature, and the
  mapping is not 1:1, so inventing one was judged out of scope here.
- **Coverage.** `pkg/luks2` unit 89.3-89.4% (floor 87.50, measured via
  `make coverage-luks2`). `make lint` and `make gosec` pass across the
  whole module (0 issues each after a `gofmt` pass `cmd/luks2/
  destructive_test.go` needed once `LegacyKeyslotInfo`'s longer name moved
  a struct literal's alignment).

## H9 train merge (H9c, H9d, H9e integration, closing §B.2)

- **`KeyslotInfo`/`Priority`/`KeyslotParams` exist exactly once, at H9c's
  placement (keyslot.go), with no `Legacy` alias for the pre-§B.2 shape.**
  All three lanes forked from the same pre-H9c base and each independently
  redefined these identifiers to resolve the same collision: H9c redefined
  `KeyslotInfo`/`Priority` in place (no rename); H9d added its own copy in
  header_v2.go; H9e renamed the OLD shape to `LegacyKeyslotInfo` and defined
  a fresh `KeyslotInfo` elsewhere, and additionally changed `ListKeyslots`'s
  own signature to return `[]LegacyKeyslotInfo`. None of these collided
  textually (each lane inserted at a slightly different, non-overlapping
  point in a growing file), so `git merge` applied all three silently --
  every one surfaced only as a `go build`/`go vet` failure after the H9d and
  H9e merges, not as a conflict. H9c's resolution wins: it is the lane the
  brief names as this group's owner, and it is what `ListKeyslots`,
  `listKeyslotsFrom`, `AddKey`, `ChangeKey` and every cmd/luks2 and test call
  site were already adapted to via H9c's own commit, before H9d or H9e ever
  merged. H9d's and H9e's own duplicate type blocks are deleted; their
  non-colliding helpers stay where used (H9d's `keyslotInfoFromEntry` is now
  `listKeyslotsFrom`'s body; H9e's `keyslotInfoFromMetadata`/
  `kdfParamsFromDisk` stay for `AddRecoveryKey`, which refuses an
  unparseable on-disk KDF type rather than defaulting it). Every
  `LegacyKeyslotInfo` reference the silent merges left in cmd/luks2 and test
  files (operations.go, cli.go, mockops_test.go, keyslotcmd_test.go,
  destructive_test.go, failurepaths_test.go, keyslot_test.go) is reverted to
  `KeyslotInfo`.
- **The same silent-duplicate pattern recurred for `KDFType`/`KDFParams`
  (H9d's and H9e's own copies in kdf.go, on top of H9c's already-merged
  one, which is itself on top of H9b's canonical pair) and for
  `hashAlgoName`/`hashNameFor` (H9c's and H9e's own near-identical
  crypto.Hash-to-name helpers).** Same resolution throughout: one canonical
  definition survives (H9b's `KDFType`/`KDFParams`/`DefaultKDFType()
  KDFType`; H9b's `hashAlgoName`), every duplicate is deleted, and the
  duplicate's own non-colliding callers are repointed to the survivor
  (`fips.go`'s `hashNameFor` call -> `hashAlgoName`).
- **`DefaultKDFType() KDFType` already exists and already replaced the old
  `DefaultKDFType() string`** -- this was H9b's own rename (`DefaultKDFSpec`
  taking the old shape), landed before H9c/H9d/H9e ever merged. No gap to
  close; verified no caller anywhere still expects the old signature under
  this name.
- **`KeyslotParams.Priority` reaches disk from all four callers the lane
  brief names (`AddKeyslot`, `ChangeKeyslot`, `Enroll`, `AddRecoveryKey`),
  through one shared rule, `onDiskPriority`: an explicit on-disk member is
  written ONLY for `PriorityPrefer`.** `AddKeyslot` already called this
  correctly. `ChangeKeyslot` was changed to call it too (H9c's own decision
  had been "`ChangeKeyslot` does not consult `p.Priority`" -- superseded
  here per this lane's brief; `p.KDF` is still not consulted, since a
  passphrase rotation is still not a request to re-cost the slot).
  `Enroll` was changed from `addKeyslotWithMasterKey` to
  `addKeyslotWithMasterKeyAndPriority`. `AddRecoveryKey` already had its own
  special case (manually writing a second header update, but ONLY for
  `PriorityPrefer`, with the same reasoning now centralized in
  `onDiskPriority`'s own doc comment); it was changed to call
  `addKeyslotWithMasterKeyAndPriority` directly instead, for one atomic
  write rather than two.
- **Why only `PriorityPrefer` is ever written explicitly, universally, and
  not just for `AddRecoveryKey`:** DESIGN.md §B.2 makes `PriorityIgnore`
  `Priority`'s zero value (the literal enum order), while this package's
  own, pre-existing convention reads an ABSENT on-disk member as NORMAL.
  Every caller that leaves `KeyslotParams.Priority` unset therefore produces
  the Go zero value `PriorityIgnore` -- indistinguishable from an explicit
  request to ignore the slot. Before this round, `onDiskPriority` wrote an
  explicit member for anything `!= PriorityNormal`, which means a plain
  `KeyslotParams{}` passed to `AddKeyslot` would have silently written an
  IGNORED keyslot the moment `ChangeKeyslot`/`Enroll` started consulting
  Priority too (not previously exercised by any test, since none called
  `AddKeyslot`/`Enroll` with a zero-value `KeyslotParams{}` and then checked
  Priority). `onDiskPriority` is narrowed to write only for `PriorityPrefer`
  -- both `PriorityIgnore` and `PriorityNormal` now mean "leave it absent" --
  which is the safe side of the ambiguity: no call through this field can
  ever create a silently-skipped keyslot. This is still the same DESIGN.md
  defect H9e flagged, not resolved by reordering the `Priority` enum
  unilaterally; a caller that wants `PriorityIgnore` has no way to ask for
  it through `KeyslotParams` today. Tests added (`Header.Keyslots()`
  read-back, not just the return value): `TestVolumeChangeKeyslotWith
  PriorityPreferWritesIt`, `TestVolumeEnrollWithPriorityPreferWritesIt`;
  `TestVolumeAddRecoveryKeyHonorsPriorityPrefer` (already existed) is
  extended with the same read-back.
- **`FIPSMigrationStage` is wired into `FIPSMigrationError` via a new
  method, `MigrationStage() FIPSMigrationStage`, rather than by changing the
  existing `Stage string` field's type.** The string stays -- it is the
  detailed, already-documented 10-value set (`"precondition"`, `"sync"`,
  `"unlock"`, `"plan"`, `"reconcile header copies"`, `"add keyslot"`,
  `"migrate digest"`, `"verify"`, `"remove keyslot"`, `"final check"`) --
  and the method maps it onto the five §B.2 values:

  | `Stage` string | `FIPSMigrationStage` |
  | --- | --- |
  | `"precondition"`, `"sync"` | `StagePreflight` |
  | `"unlock"`, `"plan"`, `"verify"` | `StageVerify` |
  | `"reconcile header copies"`, `"add keyslot"`, `"migrate digest"` | `StageWrite` |
  | `"remove keyslot"` | `StageRemove` |
  | `"final check"` | `StageVerifyWritten` |

  `"unlock"`/`"plan"` and `"verify"` share `StageVerify` because
  `StageVerify`'s own doc comment already groups them: unlocking and
  planning (before any write) and the post-write opens that prove the
  result are the two halves of "making sure the migration is sound" that
  bracket `StageWrite`. An unrecognized `Stage` maps to `StagePreflight`,
  the conservative choice (implies nothing was written yet). Test:
  `TestFIPSMigrationErrorMigrationStageMapsEveryStageString`, one subtest
  per `Stage` string.
- **Checks run (after all three merges and the above)**: `GOWORK=off go
  build ./...`, `go vet ./...` (also `GOOS=linux` under
  `GOARCH=386/arm/arm64`), `go test -race -count=1 ./pkg/... ./internal/...
  ./cmd/...` -- all clean. `go vet -tags integration ./...` still shows
  exactly the two pre-existing, previously-documented gaps (H10a's entry):
  `pkg/luks2`'s and `test/integration/pkg_test`'s untagged suites calling
  the dm-crypt activation functions H10a moved to pkg/dmcrypt -- unchanged
  by this merge, deferred to H12 as before.

## H11b (internal/cli completes DESIGN.md §F; cmd/luks2 becomes main.go)

- **The dependency H11's entry flagged as missing has landed.** This lane's
  base, `integrate/redesign-2-h9`, carries the full §B.2 `Volume` API (H9's
  train merge): `Format`, `KDFParams`, `KeyslotParams`/`AddKeyslot`/
  `ChangeKeyslot`/`RemoveKeyslot`, every `Token` operation, `KeyProvider`/
  `Enroll`/`UnlockWithProvider`, `NewRecoveryKey`/`AddRecoveryKey`/
  `ParseRecoveryKey`, `Erase`, and `(*Header).Keyslots`/`Segments`/`Tokens`/
  `Size`. `pkg/dmcrypt` (H10a) and `pkg/loop` (H10b) are also present. Every
  command H11 deferred for exactly this reason is implemented here:
  `create` (file and block device), `info`, `keyslots`, `addkey`,
  `changekey`, `removekey`, `killslot`, `recovery generate`/`add`/`verify`,
  every `token` verb, `header show`/`secondary`, and `wipe`'s default
  header-only mode (`Volume.Erase`). `cmd/luks2` is now `main.go` only (24
  lines) plus a small `run` seam for testing; the old `CLI`/
  `LuksOperations`/`Terminal`/`DeviceProber` stack (H11's note on B.7's
  disposition table) is deleted in full, all 24 of its files.
- **`KeyslotParams.Priority`'s zero value is `PriorityIgnore`, not
  `PriorityNormal` -- a trap `changekey` and `addkey` both had to avoid
  explicitly.** `Priority`'s three constants are declared
  `PriorityIgnore, PriorityNormal, PriorityPrefer = iota, iota+1, iota+2`
  (DESIGN.md §B.2's literal enum order, also flagged in the H9 train-merge
  entry), so a `KeyslotParams{}` passed to `AddKeyslot` or `ChangeKeyslot`
  with Priority left unset writes an IGNORED keyslot, not a normal one.
  `addkey` sets `Priority: luks2.PriorityNormal` explicitly on every call.
  `changekey` cannot default to Normal -- the slot being rewritten may
  already be Prefer or Ignore, and silently resetting it would be its own
  bug -- so it reads the slot's current `Priority` off `Header.Keyslots()`
  before calling `ChangeKeyslot` and passes that back unchanged. Covered by
  `TestRunChangeKeyReplacesPassphrase`, which checks the new passphrase
  actually opens the volume (a wrong priority on a single-keyslot container
  would still pass a check that only inspected the header).
  `recovery add`'s `AddRecoveryKey` takes the same `KeyslotParams` and gets
  `PriorityNormal` for the same reason as `addkey`.
- **KDF option resolution (`kdfflags.go`) is shared between `create` and
  `recovery add` (the `--pbkdf`/`--hash`/`--iter-time`/
  `--pbkdf-force-iterations`/`--pbkdf-memory`/`--pbkdf-parallel` set,
  docs/volumes/cli.md#kdf-options) and built once as a `luks2.KDFParams`,
  then validated by calling `KDFParams.Validate()` directly** -- no
  process-mode probe of this package's own (`DefaultKDFType()` already
  reflects the mode, and `Validate()` is pure, so calling it before any
  device is touched gets the same fail-fast guarantee H11's `create` had
  with `crypto/fips140.Enabled()`, without duplicating the FIPS check.
  `addkey`'s single `--kdf` flag (cryptsetup's combined spelling,
  `pbkdf2-sha512`) is a separate, smaller parser (`parseAddKeyKDF`):
  passing no cost fields through on an Argon2 request is what lets the
  library's existing inherited-cost policy
  (`addKeyFormatOptions`/`containerArgon2Cost`, pkg/luks2/keyslot.go) take
  over, which is how "a new Argon2 keyslot takes the cost of the volume's
  first Argon2 keyslot" (docs/keyslots/cli.md#addkey) is satisfied without
  this package reimplementing that policy.
- **`isluks` gained `--luks2` and a `version` command, closing two gaps
  docs/header/cli.md and the pre-H11b `cmd/luks2/main.go` usage text
  already documented but H11's `runIsLUKS` never implemented.** `--luks2`
  was previously swallowed as a positional argument (read as the device
  path, which then failed to open) because `runIsLUKS` read `args[0]`
  directly with no flag parser. It now declares `--luks2` with `newFlags`
  and, without it, answers "yes" for a header this package cannot fully
  parse because it is LUKS1 (`errors.Is(err, luks2.ErrUnsupportedLUKSVersion)`)
  as well as for one it opens outright -- the question asked without
  `--luks2` is about the magic, not the version. `version`/`--version`/`-v`
  is handled in `dispatch` next to `help`, printing `cli.Version`; `main.go`
  sets that from its own `Version` (which `-ldflags -X main.Version=...`
  still sets, see below) before calling `Run`.
- **DESIGN.md §B.7 says `cmd/luks2`'s `Version` should be unexported to
  `main.version`. Left as `Version` (capitalized) on purpose.** The ldflags
  target is referenced by name in `Makefile`, `build/docker/cli/Dockerfile`
  and both `.github/workflows/*.yml`, none of which are this lane's to
  rewrite for a cosmetic rename with no behavioral difference -- `-X`
  works identically either way. Flagged here rather than silently matched
  or silently dropped, for whichever step next touches that casing
  on purpose.
- **`host.go` grows a `looper` interface (`attach`/`detach`,
  `pkg/loop`-shaped) and `mounter` grows a `make` method
  (`pkg/filesystem.Make`), alongside production implementations for
  `activator` (`realActivator`, wrapping `pkg/dmcrypt`) and `looper`
  (`realLooper`).** `Run` now wires `host{activator: realActivator{},
  looper: realLooper{}, mounter: realMounter{}}`, where H11 left
  `activator` as a nil interface (no `pkg/dmcrypt` to wrap yet).
  `create`'s file-volume flow is `looper`'s only caller: format the
  regular file directly (no block device needed for that), attach a loop
  device, re-`Open` the Volume on the loop device's path (a regular file
  has no major:minor for `Target` to report), `Unlock`, then activate
  through the existing `activator`. `realLooper.detach` re-resolves the
  device by path through `loop.Lookup` rather than holding the `*loop.
  Device` `Attach` returned, the same pattern `activator.lookup` already
  uses for `pkg/dmcrypt.Lookup` by name -- consistent with the rest of
  `host.go`, and it means the `looper` interface's `loopDevice` is a bare
  path, not a live handle, so a fake in a test can be a plain struct.
- **Typed errors only, including for the "this answer is the failure"
  cases `keyslots`/`token free`/`token exists`/`claimDevice`'s busy/
  signature refusals didn't have a natural `UsageError` for.** `make lint`
  enforces `forbidigo` against bare `fmt.Errorf`; every such site in the
  new files builds an `*errs.Error` (`internal/errs`) instead -- `Kind` for
  a sentinel that needs `errors.Is` to reach it (`claimDevice`'s EBUSY path
  sets `Kind: luks2.ErrDeviceInUse` so `exitCode`'s table still lands it on
  5), `Detail`/`Err` otherwise. This also incidentally fixed a double
  intent: these call sites previously read `fmt.Errorf("cli: <command>:
  ...")`, hand-rolling the same `"pkg: message"` shape `errs.Error.Error()`
  already produces from a bare `Detail`.
- **Coverage.** `internal/cli` unit 90.1% (floor 90, unchanged -- H11's row
  already covers it). `cmd/luks2` unit 100% (floor raised from 90 to 100,
  `coverage-floors.txt`): `main` is a two-line `osExit(run(...))`, with
  `osExit` a package-level seam a test overrides so `main` itself runs
  in-process without ending the test binary -- the same "seams become
  structure" rule DESIGN.md §E states for everything below `main`, applied
  to `main` itself because `go test`'s coverage instrumentation cannot
  attribute statements a subprocess executes. `make lint` and `make gosec`
  both pass (0 issues each) across the whole module with this change in
  place.
- **Docs updated for this lane's behavioral changes** (the brief's
  instruction to fix docs where §F changes behaviour): `docs/header/cli.md`
  dropped the `Digests:` line from `header show`'s example output --
  `(*Header)` has no digest count in DESIGN.md §B.2's shape, so the
  normative example asked for something the new command cannot print, not
  something `header.go` got wrong. `header show`/`secondary`'s `Header
  offset:` line is computed, not read from a published constant: the
  primary is always `luks2.LUKS2PrimaryHeaderOffset` (0), but the
  secondary's offset depends on `MetadataSize` and so is read back as the
  secondary copy's own `Header.Size()` -- DESIGN.md's "the secondary's
  header offset equals the header size" made literal. `docs/volumes/
  architecture.md`'s component table had `cmd/luks2` described by the
  deleted `LuksOperations` interface; its row is corrected and a row for
  `internal/cli` added. The rest of that table (`pkg/luks2` as "one
  package" owning device-mapper and loop devices directly) is still stale
  from before the pkg/dmcrypt/pkg/loop/pkg/filesystem split and is left
  for whoever next revisits that file -- correcting the one row this
  lane's change actually falsified is in scope; a general pass over an
  architecture doc several redesign steps have now outrun is not.
- **CLI parity.** `test/integration/cli/commands/`, where DESIGN.md §E
  says the real `CommandDefinition`/`ArgDefinition` table and its
  enumerating test belong, does not exist in this lane's base (H12c, which
  creates it, is a sibling lane). `internal/cli/parity_defs_test.go` holds
  a `CommandDefinition` for every verb in `registry()` -- the ones H11
  already had and every one this lane added -- plus
  `TestEveryRegistryVerbHasAParityDefinition`, a local enumerating test
  with the same "a verb with no definition fails CI" property the real
  table's is specified to have. The train merge folds these definitions
  into the real table once H12c lands; until then this file's own test is
  the gate.
- **Checks run**: `GOWORK=off go build ./...`, `go vet ./...` and `go vet
  -tags integration ./...` (also `GOOS=linux` under `GOARCH=386/arm/arm64`
  for `./internal/cli/... ./cmd/...`), `go test -race -count=1
  ./internal/cli/... ./cmd/... ./pkg/...` -- all clean except the same two
  pre-existing `-tags integration` gaps H10a's and the H9 train-merge
  entries already name (`pkg/luks2` and `test/integration/pkg_test` calling
  the dm-crypt activation functions `pkg/dmcrypt` moved out of `pkg/luks2`;
  confirmed unchanged by diffing against this lane's base). `make lint` and
  `make gosec`: 0 issues each.

## H13 (delete the old API and transitional aliases; turn the gates on)

- **`make api-diff` is now a real gate, not a report.** It runs
  `apidump honor` against `baseline/disposition-luks2.tsv`, which fails
  the build the moment any §B.6 disposition stops being honored --
  KEEP-disposed identifiers must still exist, DELETE/RENAME/MOVE/UNEXPORT
  identifiers must not. A new "alias" `apidump` Entry kind (`ast.TypeSpec
  .Assign.IsValid()`) keeps a KEEP-disposed method inherited through a
  `type X = pkg.Y` alias from being a false violation. Wired into `make ci`
  right after `releasability`.
- **The old `test/integration/*` tree turned out to be a second, external
  consumer of exactly the identifiers §B.6 disposes, which the brief did
  not name.** It cannot see unexported names, so deleting old free
  functions it calls is not a rename -- it is an API break for a consumer
  this repo also owns. `test/internal/harness` is the fix: real (not
  test-only) wrapper functions with the OLD functions' exact shapes,
  backed by calls into the actual new API (`luks2.Open`+`Unlock`/`Header`/
  `Erase`/`RemoveKeyslot`, `pkg/loop.Attach`, `pkg/filesystem.Make`/
  `Mount`/`Check`, `pkg/dmcrypt.Lookup`), so every `test/integration/*`
  call site's fix is `luks2.OldName(` -> `harness.OldName(`, mechanical
  and reviewable. This is the same shape of decision H12c already made for
  `DefaultLuksOperations`'s two-package forward, extended to the rest of
  §B.6.
- **Inside `pkg/luks2` itself, an old EXPORTED free function used by dozens
  of white-box tests as a convenience the new API cannot cheaply
  replicate (raw on-disk header access, the full keyslot list, directly
  dialing a KDF) is renamed to an unexported `xxxForTest` name, not
  deleted.** `ReadHeader`/`ReadSecondaryHeader`/`IsLUKS`/`IsLUKS2`/
  `TestKey`/`ListKeyslots`/`GetVolumeInfo` all move this way. §B.6 disposes
  the export; the function's logic, which the white-box tests still
  legitimately need, is untouched. `KillKeyslot` did not get this
  treatment -- its real logic (`removeKeyslotCore`) was already shared
  with `(*Volume).RemoveKeyslot`, so its ~12 call sites across the test
  tree became a `killKeyslotForTest` helper that calls the real
  `RemoveKeyslot`, and the free function was deleted outright.
- **The token cluster (`GetToken`/`ListTokens`/`ImportToken`/`ExportToken`/
  `CountTokens`/`FindFreeTokenSlot`/`TokenExists`/`ImportTokenJSON`/
  `LegacyToken`) was unexported, then reverted.** `ImportToken`'s write
  path needs `lockKeyslotDevice`/`dev.writeHeader`, which a harness in a
  separate package cannot reach without reimplementing header-write
  locking. The correct fix is porting its tests onto `(*Volume).SetToken`/
  `AddToken`; that is a larger, separate change, so all nine stay exported
  and §B.6's disposition for this cluster is NOT YET HONORED -- left for
  the next lane, not silently dropped.
- **`EnrollKeyProvider` (the old free function) is also not yet deleted**,
  for the same reason: its call sites still use `AddKeyOptions`/
  `KeyProviderError`/`LegacyToken`/`ErrNoKeyProvider`, which are themselves
  undeleted pending this. `make api-diff` reports both gaps; it is a real
  gate, so this is visible there rather than only in this file.
- **`depguard` needed zero production-code changes.** Once this lane's own
  deletions (`devicemapper.go`, `mount.go`, `filesystem.go`, `fsdetect.go`,
  `loopdev.go`, old `wipe.go`) landed, the codebase was already fully
  DESIGN.md §A.2-compliant; the 21 depguard rules (one per import-DAG row,
  plus `pkg-luks2`'s explicit `os/exec` deny, which wins over the
  `$gostd`-derived `os` allow in depguard's "original" list-mode semantics)
  encode the DAG as data without moving a single import. `golangci-lint
  run ./...`: 0 issues.
- **The seam-var test (§E) is real and enforcing for every package except
  pkg/luks2, which carries a documented, shrinkable allowlist.**
  `test/makefile/seamvars_test.go` type-checks every non-test,
  build-tag-filtered file in each `pkg/*`/`internal/*` directory
  (`go/types` + `importer.ForCompiler(..., "source", ...)` +
  `build.Context.MatchFile`, so a `_linux.go`/`_other.go` pair is not a
  false "redeclared" error) and fails on any package-level var whose
  underlying type is a function signature or an interface, outside
  `errors.go`. Every package but pkg/luks2 came back clean once
  pkg/dmcrypt's one straggler (`makeBlockNode`, folded into the existing
  `seams` struct) was fixed. pkg/luks2 keeps 21 real seams
  (`cryptoRand`, `fipsMode`, `passphraseKDF`, `openFileFunc`, and 17
  others) named in an explicit `seamAllowlist`: each is reached, in
  production code, from package-level helpers (`afCodec`, `kdfDeriver` in
  util.go; `format.go`, `header.go`, `recovery.go`, `kdf.go`,
  `fipsmigrate.go`, `keyslotscreen.go`) shared between the still-undeleted
  old free-function API and the new `Volume` methods, so neither takes a
  `*Volume`/`sys` parameter today. Folding these into `Volume.sys` needs
  either finishing the old-API deletion above or a separate
  parameter-threading refactor across dozens of functions -- not
  attempted here. `TestSeamAllowlistNamesOnlyRealSeams` keeps the
  allowlist from going stale in the other direction: it fails if an
  allowlisted name stops being a seam, so the list is pulled toward
  shrinking rather than accreting silently.
- **Darwin build** (`GOOS=darwin go build ./pkg/luks2 ./pkg/keyprovider`,
  deferred here by H14) needed two fixes, found in that order:
  `pkg/filesystem` (linux-only, mount syscalls) was imported by
  `wipe.go`'s now-deleted old API, so it fell away with that deletion; and
  `internal/device`'s `CacheIsTheStorage`/`IsMemoryFilesystemMagic` are
  Linux-only (`/proc`, `statfs` magic numbers) but were called from
  `pkg/luks2/medium.go` unconditionally. The two functions move to a new
  `pkg/luks2/medium_linux.go` (`//go:build linux`); darwin builds without
  them because nothing on that platform calls the pinned-device-cache path
  this early. Wired into `make build` as an additional cross-compile
  check, not a new build mode.
- **Sentinel consolidation to §C.3 is started, not finished.**
  `ErrMasterKeyVerification` is renamed to `ErrWrongKey`, the name §C.3
  settles on (rename only -- `ErrInvalidVolumeKey` keeps its own meaning
  and is NOT folded into it; the two are deliberately distinct, per
  errors.go's own comment: one is a caller argument refused before the
  device is read, the other is a comparison that ran and matched nothing,
  and conflating them would blur the anti-oracle boundary #41 fixed).
  `VolumeError`, `KeyslotError` and `CryptoError` are deleted outright: all
  three had zero production construction sites, kept alive only by tests
  of their own `Error()`/`Unwrap()`/`errors.As()` behavior, and §C.4 names
  all three for disposal. `InvalidKeyslotError` and `UnlockError` are NOT
  touched -- both are used pervasively in production (`keyslotscreen.go`,
  `unlock.go`, `key_v2.go`) and migrating them is real work, not a rename.
  The `KDFCostError{Param, Value, Min, Max}` unification of
  `Argon2CostError`/`PBKDF2IterationsError` has a real design question this
  lane did not resolve: the unified type's `Is(ErrInvalidArgument)` needs
  `ErrInvalidArgument` to live in pkg/luks2 (sentinels are not shared
  across packages per §C.3's own table -- filesystem and keyprovider each
  define their own), but `PBKDF2IterationsError` is currently constructed
  inside internal/kdf, which cannot import pkg/luks2 to reference its
  sentinel (§A.2's DAG). Resolving it means either moving the type's
  construction to the pkg/luks2 boundary (internal/kdf keeps returning
  something simpler, pkg/luks2 converts) or re-deriving the sentinel
  differently; attempting it without that decided risked exactly the kind
  of wrong classification §C.2's anti-oracle rules exist to prevent, so it
  is left for the next lane. The nil-Kind backfill ("Kind is never nil")
  is the largest remaining piece and was measured, not attempted: a
  `go/ast`-based scan of every `Error{}`/`errs.Error{}` composite literal
  in non-test pkg/internal/cmd code found 528 total, 275 without a `Kind:`
  key (127 in pkg/luks2 alone, 52 across the other pkg/* packages, 96 in
  internal/*). Assigning each one its correct classification is a
  per-site judgment call at a scale this lane could not safely clear, and
  a "Kind is never nil" test turned on today would either need a
  275-entry allowlist (indistinguishable from the dark suite the
  standards repository's conventions forbid) or fail on sight; neither is
  honest. No such test is added. `make api-diff`'s violation count and
  this file are where the gap is tracked instead.
- **H8's kdf ctx-cancellation gap is NOT fixed.** DECISIONS.md's own H8
  entry already notes `passphraseKDF`/`DeriveKeyEnclave` pass
  `context.Background()` by design, to be rebuilt once H9's seam work
  reached them; H9 landed the API but not that rebuild, and this lane's
  seam audit above confirms `passphraseKDF` is still one of pkg/luks2's 21
  allowlisted seams for the same underlying reason (it is reached from
  helpers shared with the undeleted old API). Not attempted here.
- **H10d/H9 collision renames are already done**, per H9d's own entries;
  nothing here found a collision still open.
- **H12c's four flagged white-box integration files
  (`canonicalconformance_integration_test.go`,
  `lockcompat_integration_test.go`, `lockwait_integration_test.go`,
  `pinnedpaths_integration_test.go`) are re-confirmed, not re-attempted.**
  H12c's own entry already explains why: each candidate seam
  (`cryptoRand`/`newUUID`/`digestIterationsFor`, `fileLockHeld`,
  `calibratedCountFloor`) is security- or determinism-relevant in a
  Layer-0 library, and DESIGN.md §E says these become
  "exported-within-internal API" without saying which package or what
  shape. Nothing this lane learned changes that call; `ls
  pkg/luks2/*_integration_test.go` is still exactly those four.
- **pkg/luks2-must-not-import-sibling-packages** is covered by the
  depguard `pkg-luks2` rule's deny list (`pkg/dmcrypt`, `pkg/loop`,
  `pkg/filesystem`, `pkg/wipe`, `pkg/keyprovider`, plus `os/exec`,
  `internal/dm`, `internal/keyring`, `internal/command`) -- enforced by
  `make lint`, not a separate mechanism.
- **`TestCompatIntegrityVolumeIsRefusedForActivation`'s 96-byte-key case
  expected the pre-redesign error kind.** With the new API (§B.6: TestKey ->
  `Volume.Unlock` then `Key.Destroy`), `harness.TestKey` now refuses an
  integrity-segment volume the same way `Unlock` already does earlier in the
  same subtest: `ErrUnsupportedSegmentLayout`, raised before the key-size
  screen ever runs. The library's behaviour is correct -- the volume is
  refused for activation, just earlier and by a stricter check -- so the
  case's expected error changed from `ErrInvalidKeyslot` to
  `ErrUnsupportedSegmentLayout`. No other case in the table asserted the old
  ordering.
- **Checks run**: `GOWORK=off go build ./...`, `go build -tags integration
  ./...`, `go vet ./...`, `go vet -tags integration ./...`, `gofmt -l .`
  (all clean); `go test ./pkg/... ./internal/... ./cmd/... -count=1`
  (clean except `TestEnrollKeyProviderWritesTheKeyslotAndTheTokenThatNamesIt`,
  reproduced failing under the full parallel suite and passing in
  isolation at `-count=5` -- a global-seam flake a separate, already-known
  fix lane owns, not a regression from this one); `go test
  ./test/makefile/...` (clean except the two busybox-`sha256sum` trivy
  tests the brief names as expected to fail in this sandbox);
  `golangci-lint run ./...` and `make gosec`: 0 issues each.
- **Not done, flagged above rather than silently skipped:** most of §B.6's
  old-API deletion (the token cluster, `EnrollKeyProvider` and its
  supporting types, `FormatOptions`/`AddKeyOptions` unexporting --
  `make api-diff` reports the exact remaining count); the
  `ErrInvalidArgument`/`ErrInvalidCredential`/`KDFCostError` sentinel work
  and the nil-Kind backfill; H8's ctx-cancellation rebuild; H12c's four
  files. `make api-diff`, now a real gate, fails in this lane's own tree
  for exactly the first of these, which is expected and tracked rather
  than worked around.

## H13c (errors, §C -- Kind backfill, sentinel consolidation)

- **Every `errs.Error` literal in `pkg/` and `internal/` now sets Kind.** A
  scratch `go/ast` census (not committed) found 259 composite literals
  missing it at the start of this lane -- close to, not identical to, H13's
  528/275 estimate, because H13's own consolidation moved some sites in
  between. All 259 are now classified, chosen per site from §C.3's
  vocabulary or the package's own existing kinds, never invented fresh where
  an existing one already named the condition.
- **`errs.KindOf(err, fallback)` is new**, in `internal/errs/errs.go`
  alongside `At`: it returns `ctx.Err()` when err is a cancellation or
  deadline (§C.2 rule 5), the inner `*errs.Error`'s own Kind when err is
  already classified (§C.2 rule 4, "a context wrapper around an
  already-classified error takes that error's kind"), or fallback otherwise.
  Most of the 259 sites are plain wraps around a lower-layer call, and
  writing each one's Kind by hand -- duplicating or silently disagreeing
  with whatever the callee already decided -- was exactly the anti-pattern
  §C.2 rule 4 exists to prevent. `TestKindOfTakesTheInnerClassificationOverTheFallback`,
  `TestKindOfFallsBackWhenErrIsNotClassified` and
  `TestKindOfPrefersCtxErrOverAnythingElse` cover the three branches.
- **`ErrInvalidArgument`, `ErrInvalidCredential` and `ErrIO` are now in
  `internal/errs`**, re-exported by value from `pkg/luks2` -- the coordinator
  decision this lane's brief gave, generalising the H3c rule exactly as
  `ErrInvalidHeader`/`ErrInvalidKeyslot`/`ErrUnsupportedHash`/`ErrSHA1NotWritten`
  already do: no single package below the public API owns "bad argument",
  "bad credential" or "I/O failed", so `internal/errs` does. Other packages
  (`dmcrypt`, `filesystem`, `loop`, `wipe`, `keyprovider`) are NOT changed to
  share these three values -- each keeps its own local sentinels exactly as
  §C.3's table lists them; only `pkg/luks2` and `internal/kdf`'s cost
  refusal (the coordinator's example) use the shared ones.
- **`KDFCostError{Param, Value, Min, Max}` unifies `Argon2CostError` and
  `PBKDF2IterationsError`**, resolving the open question H13 measured and
  deferred. It lives in `pkg/luks2` (not `internal/kdf`): neither
  constructor needs to cross the layering boundary any more, because
  `validateArgon2CreateCost` was already pkg/luks2-level code, and
  `internal/kdf.ForcedPBKDF2Iterations` -- which had no production caller,
  confirmed by grep, only its own test suite -- now returns a plain
  `*errs.Error{Kind: errs.ErrInvalidArgument}` instead of constructing a
  type pkg/luks2 would have to re-wrap. `Is` reports `ErrInvalidArgument`.
  `ErrInvalidArgon2Memory/Time/Parallel` and
  `ErrPBKDFIterationsTooLow/TooHigh` are deleted (§B.6's own disposition for
  all four is exactly this fold); every site that constructed or matched
  them is updated, including the integration suite
  (`test/integration/luks2/argon2interop_test.go`) and `internal/kdf`'s own
  tests.
- **`InvalidKeyslotError` and `UnlockError` are deleted**, per §B.6:
  `luks2.Error{Op, Path, Kind, Detail, Err}` now carries what they carried.
  `InvalidKeyslotError{Keyslot, Reason, Err}` becomes
  `Error{Kind: ErrInvalidKeyslot, Detail: "luks2 keyslot %q: <reason>", Err}`
  at each of its 9 call sites (`keyslotscreen.go`'s `screenKeyslot`,
  `keyslot.go`'s `getMasterKeySlot`). `UnlockError{Op, Detail, Err}` splits
  on what its `Err` field actually held at each of its ~14 sites: where it
  was already a classifying sentinel (`ErrInvalidVolumeKey`,
  `ErrUnsupportedSegmentLayout`, `ErrInvalidHeader`, `ErrWrongKey` --
  `unlock.go`'s doc comment for the type said as much), it becomes `Kind`
  directly; where it wrapped a genuine lower-layer cause
  (`key_v2.go`'s `Target`/`unlockHeader`), it becomes
  `Kind: errs.KindOf(err, <fallback>)`. `Op` is folded into `Detail` as a
  prefix (`"<op>: <detail>"`) rather than into `Error.Op`, which §C.1
  reserves for the exported-entry-point boundary `errAt` fills once, not an
  inner step label. The three tests that asserted the deleted types'
  `Error()`/`Is()`/`Unwrap()` shapes directly
  (`TestInvalidKeyslotErrorKeepsItsCause`, `TestScreenKeyslotRefusalsAreTypedAndAttributed`,
  `TestUnlockErrorMessageShapes`) are rewritten against `*Error` instead of
  deleted, because the behavior they pin (classification survives the wrap,
  the message shape with and without a cause) still has to hold.
- **`type Error = errs.Error` is now declared in `pkg/luks2`**, matching
  `filesystem` and `keyprovider`, which already had it; `dmcrypt`, `loop`
  and `wipe` do NOT get it in this lane -- nothing in their own production
  code or tests needed `errors.As(&Error{})` the way the rewritten
  `InvalidKeyslotError`/`UnlockError` tests did, and adding an unused public
  alias for symmetry alone is exactly the premature surface §C.1 does not
  ask for.
- **The "Kind is never nil" test is on**, `test/makefile/errkind_test.go`'s
  `TestKindIsNeverNil`: a `go/ast` scan of every non-test, build-tag-matched
  file under `pkg/` and `internal/`, one package directory at a time (the
  `seamvars_test.go` precedent), reporting any `errs.Error` composite
  literal -- qualified, or a package's own `Error` alias of it, detected by
  parsing for `type Error = errs.Error` rather than a hardcoded package
  list -- with no `Kind:` key or an explicit `Kind: nil`. No allowlist, as
  the brief requires: the backfill above is what makes zero the right
  number. Verified both ways: a deliberately reintroduced nil-Kind literal
  in `pkg/wipe/sanitize.go` failed the test with the exact file:line, then
  passed again once reverted.
- **`errors.Is` tests for the two sentinels this lane introduced with no
  existing coverage**: `TestAddKeyRefusesAnEmptyExistingPassphraseAsInvalidCredential`
  and `TestLoadRecoveryKeyOnAMissingFileIsErrIO` (`pkg/luks2/errskind_test.go`),
  each driving a real call path rather than constructing the classified
  error directly. An audit of all six §C.3 packages' existing `_test.go`
  files (separate from this lane's own additions) found several further
  sentinels with no `errors.Is` test anywhere -- `pkg/loop.ErrNotFound` and
  `ErrPermissionDenied`, `pkg/wipe.ErrDeviceChanged`/`ErrPermissionDenied`/`ErrLockContended`,
  `pkg/dmcrypt.ErrPermissionDenied`/`ErrKeyringFailed`,
  `pkg/filesystem.ErrInvalidArgument`/`ErrTool` -- every one of them
  pre-existing, not touched by this lane's changes. Closing that gap is a
  general test-coverage audit across the whole module, not sentinel
  consolidation; left for whichever lane owns it, flagged here rather than
  silently expanded into.
- **Not done, flagged rather than silently skipped**: the full §C.3
  consolidation sweep the disposition table
  (`test/tools/apidump/baseline/disposition-luks2.tsv`) lists beyond this
  lane's explicit coordinator decision -- `ErrInvalidSize`,
  `ErrPassphraseTooShort`/`TooLong`, `ErrUnsupportedCipher`,
  `ErrInvalidKeyslot`'s rename to `ErrKeyslotNotFound`, and the rest of the
  RENAME/DELETE rows naming `ErrInvalidArgument`/`ErrInvalidCredential`/`ErrUnsupported`/`ErrNoSpace`
  as their target. The coordinator's brief scoped this lane's sentinel work
  to the four items above (`ErrInvalidArgument`, `ErrInvalidCredential`,
  the KDF cost refusal, `KDFCostError`) plus `InvalidKeyslotError`/`UnlockError`;
  attempting the rest without a lane-level ruling on each rename repeats the
  exact risk H13's own entry already named for `KDFCostError` -- a wrong
  classification standing in for a real design decision. `docs/volumes/engineering.md`
  (and `keyslots`/`fips`/`recovery-keys` `engineering.md`, which referenced
  the now-deleted types) are updated to describe the current, not the
  fully-consolidated, state, and name the disposition table as where the
  remaining gap is tracked.
- **Checks run**: `GOWORK=off go build ./...`, `go vet ./...`,
  `go vet -tags integration ./...` (all clean); `GOARCH={386,arm,arm64} go
  vet ./...` (clean); `GOOS=darwin go build ./pkg/luks2 ./pkg/keyprovider`
  (clean); `go test -tags integration -c -o /dev/null ./test/integration/...`
  (clean); `GOWORK=off go test -race -count=1 ./pkg/... ./internal/... ./cmd/... ./test/...`
  (clean except the two busybox-`sha256sum` trivy tests this sandbox is
  expected to fail, per H13's own note); `gofmt -l .` (clean);
  `golangci-lint run ./...` and `make gosec`: 0 issues each; coverage
  measured above floor on every package this lane touched (`pkg/luks2`
  89.3%/87.50 floor, `internal/errs` 97.9%/90, `internal/kdf` 95.2%/90,
  `pkg/dmcrypt` 81.8%/80.50, `pkg/loop` 56.7%/55.50, `internal/dm`
  73.1%/70, `internal/keyring` 89.4%/87.50, the rest at or above 90 -- no
  floor needed raising or was put at risk). `make api-diff` was not run as
  a gate (H13b's), but checked informally: no violation in its output names
  any identifier this lane added, renamed or deleted, confirming the
  deletions line up with the disposition table's existing rows rather than
  drifting from them.

## H15b (final docs pass, #277)

- **The feature-folder docs' PENDING markers were stale in both directions,
  not just behind.** H15 wrote them against DESIGN.md's target shape before
  H9–H13 landed. By the time this lane ran, `go doc`/`apidump` showed the
  target `*Volume`/`*Header` API (Open, Format, Unlock*, AddKeyslot,
  ChangeKeyslot, RemoveKeyslot, AddToken, SetToken, RemoveToken, Enroll,
  AddRecoveryKey, MigrateToFIPS, Header, SecondaryHeader,
  RestorePrimaryHeader, ReplacePrimaryHeader, Target, Erase) fully landed,
  matching DESIGN.md §B.2 signature-for-signature; `pkg/dmcrypt`,
  `pkg/loop`, `pkg/filesystem`, `pkg/keyprovider` and `pkg/wipe` fully landed
  as separate packages (§A.4, §B.3–B.5) with no transitional forward left in
  `pkg/luks2` for most of their old free functions (`Unlock`/`Lock`/
  `UnlockWithProvider`/`UnlockWithVolumeKey`, `GetVolumeInfo`, every loop/
  filesystem/mount function, `CheckKeyringAvailable`, `ListKeyslots`,
  `TestKey`, `KillKeyslot`, `WipeKeyslot`, `Wipe`/`WipeOptions`, `ReadHeader`,
  `ReadSecondaryHeader`, `IsLUKS`, `IsLUKS2`, `CommandKeyProvider`,
  `NewFIDO2KeyProvider`, `ProviderFromToken`, `NewFIDO2Credential`,
  `NewFIDO2Salt`) -- all gone, not merely renamed with a forward. What is
  actually still outstanding, confirmed the same way, is narrower than the
  brief's own framing suggested: the token free-function cluster
  (`GetToken`/`ListTokens`/`ImportToken`/`ExportToken`/`RemoveToken`/
  `FindFreeTokenSlot`/`TokenExists`/`CountTokens`/`ImportTokenJSON`),
  `EnrollKeyProvider`, `Format(FormatOptions)`,
  `AddKey`/`ChangeKey`/`RemoveKey`/`KillSlot`,
  `RestorePrimaryHeader(device)`/`RestorePrimaryHeaderWithOptions`,
  `MigrateToFIPS(device, ...)`, the recovery-key free functions, and a
  handful of low-level helpers B.6 marks UNEXPORT/DELETE
  (`WriteHeader`/`CreateBinaryHeader`/`CreateKDF`/`DeriveKeyEnclave`/
  `BenchmarkPBKDF2`/`OpenFileSecure`/`TrimRight`/`ConstantTimeEqual`/
  `CheckOverflow`/the `SafeXToY` trio/`AcquireFileLock(Timeout)`/
  `ValidateDevicePath`/`ValidateFormatOptions`/`ValidateMappingName`/
  `IsFIPSCompliantKDF`/`DefaultKDFSpec`). Every feature folder's
  architecture.md/engineering.md now says exactly this, under an "Old API"
  heading per folder rather than a blanket PENDING banner, with
  `volumes/architecture.md#old-api` as the one place the full inventory
  lives and every other folder pointing at it instead of repeating it.
- **The §C.3 error-sentinel table is also not fully consolidated**, confirmed
  against `internal/errs`' and `pkg/luks2`'s actual sentinel declarations:
  `ErrInvalidArgument`/`ErrInvalidCredential`/`ErrIO` are shared (H13c);
  `ErrMasterKeyVerification` is `ErrWrongKey`; `KDFCostError` is unified;
  `InvalidKeyslotError`/`UnlockError`/`VolumeError`/`KeyslotError`/
  `CryptoError` are gone. A generic `ErrUnsupported` does not exist yet, and
  `ErrInvalidKeyslot`'s rename to `ErrKeyslotNotFound` has not happened; docs
  now say this explicitly (`header/engineering.md#error-semantics`,
  `volumes/engineering.md#error-semantics`) instead of the generic "target"
  wording H15 left.
- **Every documented signature in the eight feature folders, the root
  README's library quick start, and the CLI reference was checked against
  `go doc` and, for the CLI, the actual `usage`/`synopsis` string literals in
  `internal/cli` (`cli.go`'s `registry()`, each command's `*Command()`
  constructor)** -- not against DESIGN.md's target text, which this lane
  treats as the plan, not the ground truth (DESIGN.md's own status line is
  updated to say so). The CLI docs (`cli.md` per folder) needed only two
  corrections: `luks2 open`'s "volume already unlocked"/"volume not
  unlocked" failure-table entries were the OLD `dmcrypt`-predecessor
  sentinel text; the CLI's `open`/`close` now go through
  `dmcrypt.Activate`/`Lookup`, so the real messages are "mapping is already
  active"/"mapping is not active" (`dmcrypt.ErrActive`/`ErrNotActive`).
  Otherwise the `cli.md` files, `api.md` files (all just the Layer-0
  transport-exemption boilerplate) and `user.md` files were already accurate
  against the landed CLI and needed no change.
- **`CLAUDE.md`/`AGENTS.md` gained the `cmd/` and `test/integration/` levels
  DESIGN.md §G.1 calls for**, now that the test-infrastructure relocation
  (#274, H12a-c) they were blocked on has landed
  (`test/internal/harness`, `test/internal/labstrings`,
  `test/integration/<pkg>/` are the real paths). The root pair already
  pointed at `internal/secret`'s `doc.go` as the canonical raw-bytes list
  (H3a's own change did that); nothing there needed to move.
- **`changelog.d/277-api-redesign.md`** summarizes the redesign with a
  `BREAKING:` heading and names DESIGN.md §B.6 as the exhaustive migration
  map, rather than restating all ~400 dispositions. **`VERSION`** is
  `1.0.0-rc.1` (unprefixed; release-versioning puts the `v` on the tag).
  **`docs/design/DESIGN.md`**'s status line is `IMPLEMENTED in v1.0.0-rc.1`,
  with a note that DECISIONS.md, not DESIGN.md, is where drift from the plan
  is recorded.
- **Checks run**: `GOWORK=off go build ./...`, `go vet ./...` (clean, as
  expected for a docs-only change touching no `.go` files); `make
  releasability` (0 findings; `CLAUDE.md`/`AGENTS.md` at all three levels and
  `.github/workflows/automerge.yml` report as strip-at-publish, 7 files, once
  the new files were staged -- the gate reads the tracked tree, so an
  unstaged new file is invisible to it, which cost one otherwise-confusing
  dry run); `make lint`: 0 issues. No docs link-check target exists in the
  Makefile. `make api-diff` was not re-run as a gate (unchanged from H13c's
  last run; this lane touched no Go source), but its prior output is what
  the "Old API" inventory above is cross-checked against.
- **Not done, flagged rather than silently skipped**: `docs/TESTING.md` and
  `docs/RELEASABILITY.md` are still not folded into each folder's
  `engineering.md#test-strategy` / `test/internal/labstrings`'s package
  documentation (DESIGN.md §G.1) -- the relocation they were blocked on has
  landed, so the blocker named in `docs/README.md`'s migration-state section
  is gone, but doing that fold is a separate pass this lane's brief did not
  scope. A full `api.md`/`user.md` line-by-line audit beyond the spot checks
  above was not attempted given the scope already covered; both appeared
  accurate wherever checked.
## H13b (api-diff to zero: the token cluster, EnrollKeyProvider, and everything else H13 left open)

- **182 violations down to 39 over 24 commits.** Disposed of, each its own
  commit: the token free-function cluster (`GetToken`/`ListTokens`/
  `ImportToken`/`ExportToken`/`CountTokens`/`FindFreeTokenSlot`/
  `TokenExists`/`ImportTokenJSON`/`LegacyToken` -- H13 left these exported,
  reverted after finding `ImportToken`'s write path needed
  `lockKeyslotDevice`/`dev.writeHeader`; this lane ported their tests onto
  `(*Volume).AddToken`/`SetToken`/`RemoveToken` and `Header.Tokens()`
  instead, fixing two bugs on the way: `(*Header).Dropped()` returned the
  wrong element type, and `Header.Tokens()` used bare `strconv.Atoi` where
  `canonicalTokenID` was needed, both regressions the old free functions'
  tests had guarded against and the new ones had not inherited);
  `Format`/`FormatOptions`; `AddKey`/`AddKeyOptions`; the recovery-key
  cluster (`AddRecoveryKey`/`GenerateRecoveryKey`/`RecoveryKeyOptions`/
  `SaveRecoveryKey`/`LoadRecoveryKey`/`LoadRecoveryCredential`/
  `RecoveryCredential`/`VerifyRecoveryKey`, plus the
  `RecoveryKeyFormatHex`/`Base64`/`Dashed`/`RecoveryKeyLength` consts that
  existed only to support them); `EnrollKeyProvider`;
  `ErrVolumeNotUnlocked`/`ErrDeviceNodeUnverified`; the legacy
  `KDFTypePBKDF2`/`Argon2i`/`Argon2id` and `KDFTypePBKDF2SHA1`/`256`/`384`/
  `512` string constants; `KeyslotPriorityIgnore`/`Normal`/`Prefer`;
  `DefaultCipherMode`/`LUKS2MaxKeyslots`/`IsFIPSCompliantKDF`/
  `TokenTypeSystemdFIDO2`/`TokenTypeSystemdRecovery`/
  `ErrUnsupportedTokenType`/`ValidateFormatOptions`; the FIPS-migration
  free-function cluster (`MigrateToFIPS`/`FIPSMigrationOptions`/
  `FIPSMigrationResult`) and its four sentinels, consolidated behind a new
  `ErrFIPSMigration`; `KillSlot`/`RemoveKey` (deleted outright) and
  `ChangeKey` (renamed).
- **The recurring shape, once Format/AddKey established it**: where the
  old free function shared real implementation with its §B.2 replacement
  (`formatCore`, `addKeyslotWithMasterKeyAndPriority`,
  `changeKeyslotCore`, `migrateToFIPS`), the free function and its
  option/result types were renamed to unexported `xxxForTest` shapes
  rather than deleted, so pkg/luks2's own white-box tests keep exercising
  the shared core directly. Where they did NOT share an implementation --
  `AddRecoveryKey`/`GenerateRecoveryKey`/`SaveRecoveryKey`/`LoadRecoveryKey`/
  `RecoveryCredential`/`VerifyRecoveryKey`, `EnrollKeyProvider`,
  `KillSlot`/`RemoveKey` -- the free function was deleted outright and its
  tests ported onto the real §B.2 API (`Open`+`Unlock`/`UnlockKeyslot`
  +the method), following `killKeyslotForTest`'s precedent from H13. Each
  port kept the regression coverage the free function's own tests carried
  (the #42 keyslot-reporting tests, the systemd-recovery token content
  check, the orphan-rollback and no-free-token-slot refusals, the
  credential-normalization guarantees) and dropped only what the new API
  structurally cannot regress: an empty-credential check once the enclave
  boundary itself refuses empty material before `Unlock` ever classifies
  it (`RemoveKey`/`KillSlot`'s `existingEmpty` table entries, matching the
  already-absent one on `KillKeyslot`), and a save-failure-does-not-undo-
  enrollment test once saving is no longer a step the library takes at all
  (`RecoveryKeyOptions.OutputPath` has no successor; two-phase
  generate-then-enroll is now the caller's sequencing, DESIGN.md §B.2).
- **External `test/integration/*` callers port onto the real public API
  directly, not through `test/internal/harness`.** H13's harness-forward
  decision (`luks2.OldName(` -> `harness.OldName(`) covered the
  identifiers that existed when H13 ran; checked again here,
  `test/internal/harness` has zero remaining calls to anything this lane
  disposed of -- it already only calls `luks2.Open`/`WithReadOnly` and
  §B.2 methods, so there was nothing to delete there. Every external port
  this lane did instead follows the `Unlock`/`Lock` shim pattern
  `test/integration/luks2/common_test.go` established for #268: a small
  package-local forwarding function (`Open`+`Unlock`/`UnlockKeyslot`+the
  real method), one per cluster per package, reusing the same shim file
  where one already existed.
- **Two production bugs found and fixed while porting, both because a
  test exercising the new path for the first time caught what no test
  had**: `(*Volume).AddRecoveryKey` built its internal
  `addKeyOptionsForTest` from `KeyslotParams` via `toAddKeyOptions()` but
  never copied `Slot` across (`AddKeyslot`, keyslot_v2.go, already does
  this copy correctly), so an explicit `KeyslotParams.Slot` was silently
  ignored and the keyslot was always auto-selected; six integration test
  packages' `releaseVolume`-style teardown retry loops compared `Lock`'s
  error against `luks2.ErrVolumeNotUnlocked`, which `Lock` (= `dmcrypt.
  Deactivate` since #268) can never return, so the loop's "ignore an
  already-torn-down mapping" branch never fired and every teardown
  failure's logged cause was wrong.
- **`ErrUnsupportedTokenType` (MOVE, to `keyprovider.ErrUnsupportedToken`)
  turned out to guard a different condition in pkg/luks2 than the one
  that moved.** keyprovider's sentinel is for a token naming a mechanism
  it cannot drive; pkg/luks2's three sites (`AddToken`/`SetToken`/
  `importTokenLocked`) are a generic "a token must have a type"
  header-validity check, the same family as the out-of-range token ID
  check immediately beside it in `importTokenLocked`. Reclassified to
  `ErrInvalidHeader` to match that neighbor, rather than inventing a
  cross-package reference `pkg/luks2` cannot make (keyprovider depends on
  luks2, not the reverse) for a condition that was never keyprovider's.
  `TokenTypeSystemdFIDO2` (MOVE, same target package) had no production
  dependency left and is deleted outright, its one external caller using
  the literal `"systemd-fido2"` for the same import-direction reason.
- **39 violations remain, and this lane's own read is that 38 of them are
  H13's deferred sentinel work, confirmed still correctly deferred, and
  one is a tool limitation, not a code defect.** `Argon2CostError`/
  `PBKDFIterationsError`/`ErrInvalidArgon2Memory`/`Parallel`/`Time`/
  `ErrPBKDFIterationsTooHigh`/`Low` (6) are exactly the `KDFCostError`
  unification H13's entry named and deferred, for the reason H13 gave:
  the unified type's `Is(ErrInvalidArgument)` needs `ErrInvalidArgument`
  to exist in pkg/luks2 first, which it does not, and `PBKDF2Iterations
  Error` is constructed inside internal/kdf, which cannot import pkg/luks2
  to reference it. The other 31 (`ErrCredentialEmpty`/`TooLong`,
  `ErrDeviceTooSmall`, `ErrDirectIOUnsupported`, `ErrIntegerOverflow`,
  `ErrInvalidKeySize`/`Keyslot`/`Label`/`MetadataSize`/`Path`/
  `RecoveryKeyFormat`/`SectorSize`/`Size`/`VolumeKey`,
  `ErrKeyslotsAreaFull`, `ErrMetadataTooLarge`, `ErrNoFreeTokenSlot`,
  `ErrNoKeyProvider`, `ErrNoKeyslots`, `ErrNotBlockDevice`,
  `ErrPassphraseTooLong`/`Short`, `ErrRecoveryKeyTooShort`,
  `ErrSHA1NotWritten`, `ErrUnsupportedCipher`/`Hash`/`HeaderChecksum`/
  `KDF`/`KeyslotCipher`/`LUKSVersion`/`SegmentLayout`) all rename to
  `ErrInvalidArgument`/`ErrInvalidCredential`/`ErrUnsupported`/
  `ErrNoSpace`/`ErrWrongKey`/`ErrNotLUKS2` -- the same unresolved-sentinel
  and nil-Kind-backfill problem, at the same scale H13 measured (528 error
  composite literals, 275 with no `Kind:`) and declined to attempt without
  the design question settled. Attempting either here would have been the
  same wrong-classification risk §C.2's anti-oracle rules exist to
  prevent, so neither was.
- **`Segment` cannot be satisfied by `make api-diff` as written, and this
  is not this lane's defect to fix.** H9's entry already redefined
  `Segment` in place -- the exact target the disposition row names,
  `luks2.Segment` as "a typed read-only value (Offset/Size int64)" -- and
  the type at `header_v2.go:24` matches that description exactly today.
  `CheckHonored` (`test/tools/apidump/disposition.go`) compares base and
  current identifiers by `Kind+"\t"+Name` only, with no structural
  comparison; a `type Segment struct{...}` in `base` and a *different*
  `type Segment struct{...}` in `current` are the same tuple
  (`"type\tSegment"`) either way, so any RENAME disposition whose target
  text keeps the OLD name -- as this one deliberately does, since the
  clean value was always going to be called `Segment` too -- can never
  be seen as honored by this tool, regardless of what the type's fields
  are. Renaming the type away from `Segment` to silence the gate would
  contradict both the disposition's own target and H9's prior, deliberate
  decision; left as a known gate limitation rather than worked around.
- **`test/internal/harness` has no compatibility wrappers to delete.**
  The brief's premise -- that H13 left wrappers in harness forwarding
  `luks2.OldName(` calls that this lane would need to remove -- did not
  hold for anything this lane disposed of: checked at the start and
  re-checked at the end, every harness function already forwards onto
  `luks2.Open` plus a §B.2 method, never onto anything this lane deleted
  or renamed. Nothing was done here because there was nothing to do.
- **Checks run**: `GOWORK=off go build ./...`, `go build -tags integration
  ./...`, `go vet ./...`, `go vet -tags integration ./...`, `gofmt -l .`,
  `GOOS={386,arm,arm64} go vet ./...`, `GOOS=darwin go build ./pkg/luks2
  ./pkg/keyprovider` (all clean); `go test -tags integration -c -o
  /dev/null ./...` (compiles clean, every package); `go test -race
  -count=1 ./pkg/... ./internal/... ./cmd/... ./test/...` (clean except
  the two busybox-`sha256sum` trivy tests H13's entry already names as
  expected to fail in this sandbox, and `TestSeamAllowlistNamesOnlyRealSeams`
  catching this lane's own stale `removeFile` allowlist entry -- fixed in
  a follow-up commit, re-run clean); `golangci-lint run ./...` and `make
  gosec`: 0 issues each, after fixing one `forbidigo` finding this lane
  introduced (`pkg/dmcrypt/activate.go`'s `safeInt64ToUint64` used an
  inline `errors.New` instead of a package sentinel); `make coverage-gate`:
  every package at or above its floor except `test/internal/harness`,
  whose floor (Makefile:515) is explicitly calibrated against `make
  coverage-combined`'s unit+integration union and is not meetable by the
  unit-only gate in a non-root sandbox with no real kernel -- the same
  class of environment limitation as the trivy failures, not a regression.
- **Not done, flagged above rather than silently skipped:** the
  `ErrInvalidArgument`/`ErrInvalidCredential`/`KDFCostError` sentinel work
  and the nil-Kind backfill (31 + 6 of the 39 remaining violations, for
  the reasons given above -- unchanged from H13's own assessment); H8's
  ctx-cancellation rebuild; H12c's four files -- neither named in this
  lane's brief and neither revisited. `make api-diff` still fails in this
  lane's own tree, now for 39 rows instead of 182, 38 of them the deferred
  sentinel work and one (`Segment`) a tool limitation rather than an
  outstanding disposition.

## H13 train merge (H13b into H13c's tree, api-diff to 1, #275)

- **H13b and H13c merged on `integrate/redesign-2-h13b`, resolved by one
  rule applied file by file across `DECISIONS.md` and 18 `pkg/luks2`
  files:** H13b's deletions win for API shape (no old free function,
  option struct or token/recovery/FIPS-migration cluster survives); H13c's
  Kind classification wins wherever both touched the same construction
  (no Kind-less `*errs.Error` literal reappears). Concretely: `errors.go`
  keeps H13c's `type Error`, `KDFCostError` and the Kind-backfilled
  comments, but loses `UnsupportedKeyslotCipherError` and `DeviceError` --
  both already dead weight once H13c's own call sites (`keyslotscreen.go`)
  turned out to construct the generic `*errs.Error{Kind: ...}` already,
  unconditionally, on both sides of the merge; `header.go` drops
  `RestorePrimaryHeaderWithOptions` (H13c kept it, H13b's
  `(*Volume).RestorePrimaryHeader` already covers it); `keyslot.go` drops
  `RemoveKey`/`KillSlot`, keeps `ChangeKey` renamed to `changeKeyForTest`;
  `keyprovider.go` and `recovery.go` drop the free-function clusters
  entire, including `AddRecoveryKey`'s `addOpts.Keyslot = p.Slot` fix
  (H13b's #2 bug); `token.go` drops the token free-function cluster.
  `DECISIONS.md` keeps both lanes' entries rather than picking one.
- **`test/tools/apidump`'s `CheckHonored` now treats a RENAME whose target
  text names the identifier itself as honored** (`disposition.go`'s
  `renameKeepsName`, word-boundary matched against the disposition's own
  `Target` column): `Segment` (H9) was redefined in place, not moved to a
  new name, and the tool's Kind+Name comparison -- which the tool has no
  structural fallback for -- could never read that as anything but a
  forgotten rename. `Segment` itself is unchanged; `TestCheckHonouredTreatsARenameInPlaceAsHonored`
  covers both the match and the word-boundary refusal (a target that
  merely contains the name, like `SegmentGroup`, does not count).
- **29 of the remaining 31 api-diff violations (`Segment` disposed above,
  `ErrInvalidKeyslot` a pure rename to `ErrKeyslotNotFound`) folded into
  their disposition-table targets**: `ErrInvalidArgument` (device paths,
  sizes, labels, recovery-key format/length, SHA-1-write refusals,
  no-provider, not-a-block-device, integer overflow), `ErrInvalidCredential`
  (empty/too-long/too-short passphrases and credentials, invalid volume
  keys), a new `ErrNoSpace` (`device.ErrUnsupported`'s sibling pattern:
  keyslots-area-full, metadata-too-large, no-free-token-slot) and a new
  `ErrUnsupported` (`= device.ErrUnsupported`, covering what were seven
  separate cipher/KDF/hash/checksum/segment-layout sentinels).
- **Four of those seven were transparent re-exports of a lower-layer
  sentinel, propagated unchanged through thin pkg/luks2 forwarding
  functions** (`errs.ErrUnsupportedHash`, `kdf.ErrUnsupportedKDF`,
  `header.ErrUnsupportedHeaderChecksum`, `header.ErrMetadataTooLarge`):
  renaming the local alias alone would have silently broken every
  caller's `errors.Is`, since the propagated error's `Kind` was still the
  old lower-layer value. `reclassifyUnsupportedKDF`,
  `reclassifyUnsupportedChecksum` and `reclassifyMetadataTooLarge` wrap
  the propagated error at each such boundary -- `kdf.go`'s
  `deriveKeyPlain`/`deriveKeySecret`/`deriveKeyEnclave`/`getPBKDF2HashFunc`,
  `header.go`'s `readHeaderCopyFrom`/`readSecondaryHeaderForTest`/
  `restorePrimaryHeaderCore`/`checkHeaderWritable`/`writeHeaderTo`/
  `encodeMetadata`/`encodeMetadataForHeader`, and the new-API callers
  (`header_v2.go`'s `Header`/`SecondaryHeader`, `key_v2.go`'s
  `unlockHeader`, `token.go`'s `AddToken`/`SetToken`/`RemoveToken`) that
  had started calling `header.ReadHeaderCopyFrom` directly rather than
  through the pkg/luks2 wrapper -- keeping the inner sentinel reachable
  through `Err` while `Kind` becomes the new shared one. A FIPS refusal
  (`fips.ErrNotApproved`) is deliberately left unreclassified: it is a
  different condition from "not implemented" ("the algorithm IS
  implemented and the mode refuses it"), and `ErrUnsupported`'s own doc
  comment already says so.
- **`ErrNoKeyslots` is the one disposition-table row NOT followed.** It
  names `ErrWrongKey` as the fold target; `TestAVolumeWithNoUsableKeyslotIsNotReportedAsAWrongPassphrase`
  (#30) exists specifically because the two were, at one point, the same
  answer, and that was the bug -- a container with no usable keyslot read
  as a wrong passphrase, sending an operator to retype a credential that
  was never tried. Merging them back would reintroduce exactly that.
  `errors.go`'s `ErrNoKeyslots` comment states the conflict and that it is
  deliberate; `make api-diff` therefore still reports this one row, and
  this is an owner-level call this lane did not have the standing to make
  unilaterally against a pinned regression test -- flagged rather than
  worked around, in the idiom H13/H13b's own entries use for the rows they
  left open.
- **Two pre-existing Kind-less `*errs.Error` literals, unrelated to this
  rename, surfaced once the full suite ran** (`TestKindIsNeverNil`
  catches both): `format.go`'s device-measure/lock/seek/write/
  fill-keyslots-area paths (4 sites) and `keyslotdevice.go`'s
  `requireLockableDevice` stat, plus `wipe.go`'s `wipeHeaders` zero-range
  -- all already present in the merged tree before this lane's own
  renames touched any of these files. Each now carries
  `errs.KindOf(err, errs.ErrIO)`.
- **Checks run**: `GOWORK=off go build ./...`, `go build -tags integration
  ./...`, `go vet ./...`, `go vet -tags integration ./...`,
  `GOOS={386,arm,arm64} go vet ./...`, `GOOS=darwin go build ./pkg/luks2
  ./pkg/keyprovider` (all clean); `go test -tags integration -c -o
  /dev/null ./...` (compiles clean, every package); `go test ./...`
  and `go test -race -count=1 ./pkg/... ./internal/... ./cmd/...
  ./test/...` (clean except the two busybox-`sha256sum` trivy tests
  H13's entry already names as expected to fail in this sandbox);
  `golangci-lint run ./...` and `make gosec`: 0 issues each. `make
  api-diff`: 1 row (`ErrNoKeyslots`, flagged above, not a silent miss).
- **Not done, flagged rather than silently skipped**: `ErrNoKeyslots`'s
  disposition-table fold (above, needs an owner ruling against #30's
  pinned test, not a rename this lane can make alone); `make
  coverage-gate` was not re-run as a numbered gate in this sandbox (H13b's
  own entry already names `test/internal/harness`'s floor as unmeetable
  here without a real kernel); prose docs this lane did not touch
  (`docs/design/DESIGN.md`, `CHANGELOG.md`, the per-folder
  `engineering.md`/`architecture.md` files, and
  `test/tools/apidump/baseline/*`) still name several of the folded
  identifiers by their old spelling and are now one step further from
  the landed API than H15b left them; left for whichever lane next
  touches error-semantics docs, since editing them here risked the kind
  of drive-by rename this entry's own §C.3 work was trying to avoid.

## H13 (noslots lane): ErrNoKeyslots disposition corrected (#30)

- **Coordinator ruling on the one row H13's train merge flagged rather
  than followed:** `disposition-luks2.tsv`'s `ErrNoKeyslots` row named
  `ErrWrongKey` as its fold target; the H13 entry above already explains
  why that was never applied -- `TestAVolumeWithNoUsableKeyslotIsNotReportedAsAWrongPassphrase`
  (#30) pins the opposite behavior, because a container with no usable
  keyslot reading as a wrong passphrase was itself the bug #30 fixed.
  The disposition table, not the code or the test, was wrong: it is
  corrected to KEEP (pkg/luks2; target `luks2.ErrNoKeyslots`), reason
  "distinct from ErrWrongKey (#30)". No library change -- `ErrNoKeyslots`
  was already KEEP-shaped in `errors.go`, which is exactly why the row
  was a false violation rather than an undone rename.
- **DESIGN.md follows the same correction**: §C.3's luks2 sentinel list
  gains `ErrNoKeyslots` alongside `ErrWrongKey`; §B.6 splits the row that
  used to read `ErrMasterKeyVerification`, `ErrNoKeyslots` | RENAME |
  `luks2.ErrWrongKey` into `ErrMasterKeyVerification`'s own RENAME row
  and a new `ErrNoKeyslots` KEEP row with the same reason text, and the
  section's KEEP/RENAME counts move from 54/133 to 55/132.
- **`make api-diff` now exits 0.** This was the last standing row.
## H13d (seams into sys; the KDF cancellation gap; the white-box files)

- **`seamAllowlist` is now empty, not deleted.** All 21 of pkg/luks2's
  package-level seam vars H13 named (`blockDeviceOf`, `calibratedCountFloor`,
  `cryptoRand`, `digestIterationsFor`, `dropDeviceCache`, `fileLockHeld`,
  `fipsMode`, `importToken`, `keyslotWriteStep`, `killKeyslot`,
  `measureDeviceSize`, `newUUID`, `nodeRdev`, `openFileFunc`,
  `passphraseKDF`, `pinnedDeviceReader`, `readDeviceDirect`, `removeFile`,
  `sha1CostTimer`, `syncDevice`, `syncKeyslotArea`) are gone from production
  code: each is now a field of `volumeSys` (or of `keyslotDevice.sys`),
  defaulted in `defaultVolumeSys()` and overridden only by in-package tests
  that now return a `volumeSys` value instead of mutating a global. The
  "shared by the still-undeleted old free-function API and the new `Volume`
  methods" blocker H13 named is resolved by the pattern already used
  elsewhere in this codebase: a thin public wrapper (`Format`, `AddKey`,
  `DeriveKeyEnclave`, ...) builds `defaultVolumeSys()` and calls an
  unexported `*WithSys`/`*Core` sibling that both the old API and the new
  `Volume` methods share. `TestSeamAllowlistNamesOnlyRealSeams` (H13's own
  anti-staleness test) is what proves the allowlist is not just emptied but
  correctly so: it fails if any entry is NOT a real seam, and every one of
  the 21 now fails that check, confirming each was actually migrated rather
  than merely removed from the list. The mechanism (the map and both tests)
  stays rather than being deleted, per the lane brief's own stated
  alternative, so a seam that genuinely cannot be migrated yet has somewhere
  sanctioned to go.
- **A second regression surfaced while running the full suite to verify
  the above: `screenKeyslot`/`screenKDFParameters` (and
  the digest-side `keyslotDigestCounts`) call the real `fips.Probe()`
  rather than an injected policy, so `sys.fipsMode`/`keyslotRefusedByFIPS`'s
  own `fipsMode` parameter never reached the one place that actually
  decides whether a keyslot's or digest's KDF is FIPS-approved.** This is a
  defect H13d's own seam-into-struct migration above introduced, not a
  pre-existing one: the "pervasive leaf functions resolved by calling
  `fips.Probe()` directly" choice (used, correctly, for `DefaultKDFType`,
  `resolveKDFType` and others with dozens of test call sites) was applied to
  `screenKeyslot`/`screenKDFParameters` too, on the assumption that their
  handful of callers had no test depending on an injected policy reaching
  them -- an assumption running the full suite disproved. It broke every
  test that forces FIPS mode through `sys.fipsMode`/an explicit `fipsMode`
  parameter rather than the real process state: `TestFIPSPolicyClassifiesWhatItRefuses`,
  `TestKeyslotRefusedByFIPSIsComputed`, `TestSHA1AFKeyslotFIPSClassification`,
  `TestSHA1AFVolumesAreRefusedUnderTheFIPSPolicy`. Fixed by giving
  `screenKeyslot`, `screenKDFParameters`, `screenDigest`, `evaluateDigest`
  and `keyslotDigestCounts` an explicit `fipsMode func() fips.Mode`
  parameter (small, auditable caller counts: 8, 2, 1, 4 and 1
  respectively), with a new `verifyMasterKeyWithFIPS` sibling so
  `recoverKeyslotKey` -- the one production call site reachable from
  `sys.fipsMode` -- can pass it down through `verifyKeyAgainstDigests`
  without changing `verifyMasterKey`'s signature, which has roughly twenty
  existing test call sites that have no sys to draw a policy from and
  correctly want the real one. Every other call site (the removal guard,
  the keyslot scan budget, the FIPS-migration digest walk, production and
  test alike) passes `fips.Probe` explicitly, so none of their behaviour
  changed; `TestSHA1AFVolumesAreRefusedUnderTheFIPSPolicy` additionally had
  to be rewritten to call `testKeyForTestWithSys` with a forced `sys`
  instead of the package-level `testKeyForTest`, which has no sys to force
  anything through -- it called `forceFIPSPolicy(t)` and discarded the
  result, which never did anything once that helper stopped mutating a
  global.
- **`TestVolumeFormatRefusesArgon2InFIPSMode`, `TestCreateKDFDefaultUnderTheFIPSPolicy`,
  `TestDefaultKDFTypeUnderTheFIPSPolicy` and `TestKDFParamsValidateRefusesArgon2UnderFIPS`
  were broken by H13d's own seam move, and are fixed.** An earlier draft of
  this entry called them a pre-existing two-leg split; that was wrong -- they
  pass on the train in a plain run. The move replaced the package-level
  `fipsMode` var with `fips.Probe()` in `KDFParams.Validate`,
  `DefaultKDFType`, `resolveKDFType` (inside `createKDF`) and
  `(*Volume).Format`, and left `forceFIPSPolicy(t)` returning a func nothing
  consumed, so the four tests forced nothing. Production enforcement was
  never weakened: the public entry points consult the real probe, which is
  what `fips140.Enabled()` reports, and `Volume.sys.fipsMode` defaults to it.
  What was lost was the seam: a policy forced on a `Volume` reached neither
  `Format`'s validation nor `createKDF`'s type resolution nor AddKey's
  default. Fixed by making the unexported cores take the policy --
  `KDFParams.validateWith`, `FormatParams.validateWith`, `defaultKDFTypeWith`,
  `baseAddKeyFormatOptionsWith`, a `fipsMode` parameter on
  `addKeyFormatOptions`, and `createKDF` resolving with its own `fipsMode` --
  with the public wrappers passing `fips.Probe`, `Volume.Format` and
  `addKeyslotWithMasterKeyAndPriority` passing their `sys.fipsMode`, and the
  four tests calling the cores with `forceFIPSPolicy(t)`'s func.
  `TestProductionEntryPointsRefuseArgon2InTheProcessFIPSMode` pins the real
  path (Validate, CreateKDF, `Volume.Format`, no injection): it expects a
  refusal exactly when `fips140.Enabled()`, so it asserts enforcement in a
  plain run (nothing refused) and under `GODEBUG=fips140=on` (Argon2 refused).
- **H8's KDF cancellation gap (DESIGN.md §D.2's KDF row) is closed for
  `passphraseKDF`, `DeriveKeyEnclave` and `deriveKeySecret`**, which H8 and
  H13 both left pinned to `context.Background()` for exactly the reason H8's
  entry gives: pre-H13d, pkg/luks2 had on the order of a dozen `_test.go`
  call sites assigning a bare `func(passphrase []byte, kdf *KDF, keySize
  int) (...)` literal to the `passphraseKDF` seam var, and changing its
  shape meant rewriting every one for a cancellation path `internal/kdf`'s
  own suite already proved correct in isolation. H13d's seam-to-struct
  migration (above) already had to touch every one of those call sites to
  turn them into `volumeSys` field assignments, so the added cost of giving
  them a `ctx context.Context` first parameter at the same time was the
  override literal's signature line, not a second pass across the suite.
  `DeriveKeyEnclave(ctx, passphrase, k, keySize)` and
  `deriveKeySecret(ctx, material, k, keySize, sys)` now forward their ctx
  into `kdf.Deriver.Derive`/`DeriveFromSecret`, which already destroys a
  mid-flight derivation's output and returns `ctx.Err()`'s kind
  (`internal/kdf`'s own suite, unchanged by this lane). New pkg/luks2-level
  tests (`kdfcancellation_test.go`) prove the wiring, not the primitive:
  `TestDeriveKeyEnclaveCancelledDuringDerivationDestroysOutput` and
  `TestDeriveKeySecretCancelledDuringDerivationDestroysOutput` race a real
  PBKDF2 derivation against a 1ms timeout (the same technique
  `internal/kdf`'s `TestDerivePlainCancelledDuringDerivationDestroysOutput`
  already uses) and assert both an error matching `context.DeadlineExceeded`
  and a nil enclave; `TestUnlockKeyslotCancelledDuringThePassphraseKDFDestroysTheOutput`
  drives the same race through a real keyslot's `sys.passphraseKDF` seam
  (`unlockKeyslot` on a fixture formatted with a deliberately high PBKDF2
  iteration count), proving the caller's ctx -- not one pinned to
  `Background()` -- is what reaches the deriver in production, not only in
  a direct unit call.
- **Digest derivation (`createDigest`, `evaluateDigest` and everything
  reachable from them -- `digestAttestingKey`, `unboundSegments`,
  `recoveredKeyBoundToSegment`) deliberately does NOT receive the write
  path's ctx, even though `deriveKeySecret` underneath it now accepts one.**
  Tried first, and reverted after it broke
  `TestAddKeyslotWithMasterKeyCancelledBeforeWriteLeavesNoPartialKeyslot`: an
  already-cancelled ctx made the preliminary "which digest does this key
  attest" check (`digestAttestingKey`, run before anything is written,
  specifically so it can run to completion) refuse early with a
  classification error instead of letting `addKeyslotWithMasterKey` reach
  its own, correctly-cancellable `DeriveKeyEnclave` call and report
  `context.Canceled` the way the test -- and DESIGN.md §D.2's "ctx is
  checked before each derivation... between digest checks" -- actually
  wants. A digest check decides WHICH key a keyslot or digest holds and
  must always run to completion once started, exactly like the keyslot scan
  loop's own "checked between, not during" shape (H8); only the slow,
  cancellable, user-facing passphrase KDF is the "KDF row" H8/H13d's gap was
  about. `evaluateDigest`/`createDigest` keep calling `deriveKeySecret` with
  `context.Background()`, unchanged from H13's behaviour; the ctx parameter
  H13d added to `deriveKeySecret` is for `DeriveKeyEnclave`'s own callers (above) and
  for any future caller that does want a cancellable digest derivation, not
  a signal that every existing call site should start passing one.
- **The four white-box integration files H12c and H13 both flagged and
  deferred (`canonicalconformance_integration_test.go`,
  `lockcompat_integration_test.go`, `lockwait_integration_test.go`,
  `pinnedpaths_integration_test.go`) are ratified as a permanent exception
  to DESIGN.md §E's "integration tests live under `test/integration/`",
  not revisited for further migration.** Each needs direct access to a
  hook the public API must never expose for the reasons H12c already gave
  (security- or determinism-relevant in a Layer 0 library) --
  `cryptoRand`/`newUUID`/`digestIterationsFor` for byte-for-byte conformance
  against a cryptsetup-written golden image, `calibratedCountFloor` for a
  real-cryptsetup-interop lock test's budget, `fileLockHeld` to simulate a
  lock already held, `openFileFunc` to retarget a symlink the instant it is
  first opened. DESIGN.md §E is updated in the same commit (the table's two
  affected rows, plus a new paragraph naming the four files and the test).
  They stay `//go:build integration`, inside pkg/luks2, and now inject their
  seam through the same `volumeSys` mechanism the unit suite uses
  (`withTestSys`, the `*WithSys` unexported cores) rather than through the
  package vars H13d's migration removed.
- **`pinnedpaths_integration_test.go` had its own latent bug, found while
  deciding the above: both its tests called `relinkAfterFirstOpen(t, link,
  loopB)` and discarded the returned `volumeSys`.** Before H13d,
  `relinkAfterFirstOpen` mutated the package-level `openFileFunc` seam
  directly, so calling it for its side effect was sufficient; H13d's
  migration (done earlier, in a file this one borrows the helper from) made
  it return a `volumeSys` value instead, and this file's two tests were not
  among the ones a compiler error would catch, since Go does not require a
  return value to be used. The retargeted-symlink scenario these tests exist
  to prove therefore silently stopped happening: `Open`/`ImportToken`/
  `Erase` were called with no custom sys, so the real `openFileFunc` default
  (plain `os.OpenFile`) ran and the symlink was never re-pointed. Fixed by
  threading the returned `sys` into `Open(ctx, link, withTestSys(sys))` and
  a new `importTokenWithSys` call, matching the pattern this lane's other
  three white-box integration files and `pinnedpaths_test.go`'s own
  (`!integration`) tests already use. **Not verified by running the fixed
  tests**: both require root and real loop devices (`laneDLoop`), neither
  available in this lane's container (`uid 1000`, confirmed by the
  "THIS INTEGRATION TEST REQUIRES ROOT" skip message both tests print
  under `go test -tags integration`). The fix is verified by
  construction -- it is now byte-for-byte the same wiring the sibling files'
  already-passing equivalents use -- and by `go build -tags integration
  ./...`/`go vet -tags integration ./...`, not by execution.
- **Checks run**: `GOWORK=off go build ./...`, `go vet ./...` and `go vet
  -tags integration ./...` (all clean, including `GOOS=linux` under
  `GOARCH=386/arm/arm64` and `GOOS=darwin go build ./pkg/luks2
  ./pkg/keyprovider`); `go test -tags integration -c -o /dev/null
  ./test/integration/...` (compiles clean); `GOWORK=off go test -count=1
  ./pkg/luks2/...` and, separately, `GOWORK=off go test -race -count=1
  -timeout=30m ./pkg/... ./internal/... ./cmd/... ./test/...` -- both clean
  except (in the first, pre-fix run) the four FIPS-policy tests corrected above, which now pass in a plain run and under `GODEBUG=fips140=on`; the final `GOWORK=off go test -race -count=1 -timeout=40m ./pkg/luks2/` passed with no failures (1072s); and the two busybox-`sha256sum` trivy-install tests in
  `test/makefile` H13's own entry already names as expected to fail in this
  sandbox. `pkg/luks2` under `-race` measured 1040.568s against the
  default `go test` 600s per-package timeout -- over budget on this host
  (unrelated to this lane's changes: the same run without `-race` measured
  comparably to H13's own baseline), run instead with an explicit
  `-timeout=30m`, as `make test-unit`'s own `UNIT_TEST_TIMEOUT` variable
  already allows overriding. `golangci-lint run ./...` (`make lint`) and
  `make gosec`: 0 issues each, after `gofmt -w` on the handful of files
  this lane's edits left with an unsorted import or an unformatted
  blank line, and fixing one `misspell` finding ("honour" -> "honor") in a
  comment this lane added.
- **Coverage.** `make coverage`'s own `test-unit` prerequisite aborts
  before `coverage-gate` runs at all, because its pkg/luks2 leg's `go test
  || rc=$?; ...; exit $rc` treated the four FIPS-policy failures above as
  fatal to the whole target (they are fixed; the pkg/luks2 leg now exits 0). Worked around by writing both legs' profiles
  directly (the pkg/luks2 leg's `-coverprofile` is written even though
  those four tests fail) and running `coverage-gate` against them: pkg/luks2
  measured 89.40% (3461/3871), above its 87.50 floor. Every other package's
  floor passes except `test/internal/harness`, 72.35% against its 87.00
  floor -- a file this lane did not touch, in a package whose floor note
  already documents "a sandboxed CI unit job cannot be assumed to have
  root," consistent with fewer of its root/kernel-dependent branches
  running in this container than wherever 87.00 was measured, not with a
  regression in an untouched file. Flagged, not fixed: out of this lane's
  scope (H13d's own files all pass their floors) and not reproducible by
  inspection without the root access this sandbox lacks.

## cr-docs (release docs for v1.0.0-rc.1)

- **DESIGN §G.1 fold of `TESTING.md` and `RELEASABILITY.md` is deferred past
  rc.1.** Folding `TESTING.md` into each feature folder's
  `engineering.md#test-strategy`, and `RELEASABILITY.md`'s gate and waiver
  rules into `test/internal/labstrings`'s package documentation, is a
  restructuring pass with no effect on the API or the release gate, and
  rc.1 is not the place to take it. Instead both files were re-verified
  against the tree and re-stamped (2026-10-07, v1.0.0-rc.1). `TESTING.md`'s
  combined-coverage package list now matches `coverage-floors.txt`, and its
  per-package integration target is `make integration-test-luks2`:
  `integration-test-pkg` names the former `test/integration/pkg` catch-all,
  which #274 removed, and fails with "no package mapped to 'pkg'".
  `docs/README.md` states the deferral.
- **The `release` target takes `-alpha`, `-rc.N` and final versions.** The
  recipe only matched `-alpha`, so the rc.1 tag could not be cut. The
  `VERSION` write is idempotent: when `VERSION` already reads the release
  version (it is bumped ahead of the tag for a release candidate) no version
  commit is made, instead of failing on an empty commit. Every other guard is
  unchanged, and `release-alpha` stays as an alias. `test/makefile/release_test.go`
  runs the real recipe against a throwaway repository.
- **`ParseLegacyRecoveryKey` is still exported.** DESIGN §B.6 disposes it as
  unexported; the code at this commit still exports it from `pkg/luks2`
  (`recovery.go`). The §B.6 row records the disposition as written; the
  export is a code change outside this lane.

## H13e (last transitional forwards removed, #275)

H5 left `pkg/luks2` forwarding to `internal/header` under the old names so the
package kept compiling, each marked "removed at H13". H13b deleted the token
cluster those names waited for, so nothing was left to wait for. Owner ruling
2026-10-05 (no backward compatibility): every caller, tests included, now says
`header.X`. No behaviour or public identifier changed.

- **Deleted.** `headervalidation.go`, `keyslotvalidation.go` and
  `unknownfields.go` (whole files of forwards and constant aliases); in
  `segmentvalidation.go` the `maxSegmentEncryptionLength`,
  `segmentSectorSizes` and `cryptTableParams` forwards; in `header.go` the
  pure forwards (`legalHeaderAreaSizes`, `expectedMagic`, `headerCopiesAgree`,
  `headerAreaSize*`, `headerAreaOffset`, `calculateHeaderChecksum`,
  `readJSONMetadata`, `forgetKeyslotID`, `withoutID`, `volumeKeyBits`,
  `marshalCanonicalJSON`, `canonicalKeyslotID`, `keyslotIDsInScanOrder`,
  `volumeKeyScanOrder`, `volumeKeyDigestsView`, `validateHeaderChecksum`,
  `writeEncodedHeader`, the `checksumFieldOffset` and
  `headerChecksumAlgorithm` constants and the `readerAt` alias, now
  `io.ReaderAt`); in `types.go` the `rawKDF`, `rawDigest`, `rawConfig` and
  `rawRequirements` aliases.
- **Kept.** `readHeaderCopyFrom`, `checkHeaderWritable`, `encodeMetadata`,
  `encodeMetadataForHeader` and `writeHeaderTo` each fold an `internal/header`
  sentinel into the public `ErrUnsupported` or `ErrNoSpace` (§C.3), so they
  are real functions, not forwards. `DroppedEntry` (public, KEEP in B.6),
  `LegacyToken`, `segmentLabel` (a private copy of an unexported helper) and
  pkg/luks2's own policy constants stay.
- **Comments.** `internal/dm` and `pkg/dmcrypt` no longer call pkg/luks2's
  seams transitional. `internal/dm` now says its callers supply the state
  through `pkg/dmcrypt`'s `sys`; `pkg/dmcrypt` contrasts that with
  pkg/luks2's per-Volume `Volume.sys` (§E).

## p-fips — FIPS migration error text, Volume-scoped derivation

- **One migration error, said once.** A `MigrateToFIPS` failure renders
  `luks2: Volume.MigrateToFIPS <path>: FIPS 140-3 migration failed: at
  <stage>: <cause>; <state>`. `errAt` classifies every `*FIPSMigrationError`
  as `ErrFIPSMigration` (context errors still win), so a stage failure caused
  by, say, a wrong passphrase now has `Kind` `ErrFIPSMigration` rather than
  `ErrWrongKey`; the cause is still matched by `errors.Is`.
  `FIPSMigrationError.Error()` no longer names the device or the phrase, and
  the migration's own refusals carry their sentinel as `Kind` (no second
  `ErrFIPSMigration`, no `fipsRefusalCause` type).
- **A Volume derives under its own sys.** `volumeSys.passphraseKDF` is now a
  method that derives under the sys's `fipsMode` and `custody`, and tests use
  the `passphraseKDFOverride` field to replace it. PBKDF2 calibration
  (`benchmarkPBKDF2`) takes the caller's FIPS mode. `kdfDeriver` uses
  `sys.custody`. Production does not change: the defaults are `fips.Probe` and
  the package custody.

## Priority zero value (pre-1.0)

Polish for #211. Supersedes the H9e note that `PriorityIgnore` is
`Priority`'s zero value and cannot be requested through `KeyslotParams`.

- **Shape.** `const (PriorityDefault Priority = iota; PriorityIgnore;
  PriorityNormal; PriorityPrefer)`. The zero value means "not asked for": a
  new keyslot (`AddKeyslot`, `Enroll`, `AddRecoveryKey`) is normal, and
  `ChangeKeyslot` keeps the slot's existing priority. Ignore, normal and
  prefer are explicit requests, and all three are now written: ignore as `0`,
  prefer as `2`, normal as no member (cryptsetup's encoding).
- **Why a fourth value, not `PriorityNormal` as the zero value.**
  `ChangeKeyslot` needs a "keep" that differs from every real priority, or a
  rotation would reset prefer/ignore to normal. Making normal the zero value
  only moves the gap. A zero value that means "default" is what
  `KDFParams{}` already means, so the two fields of `KeyslotParams` now read
  the same way. A `*Priority` would also work, but the `Slot *int` style is
  meant for "pick for me" choices, not for an enum that can name its own
  default.
- **Values are the on-disk number plus one.** `priorityFromDisk` (absent →
  normal, `v` → `Priority(v+1)`) and `onDiskPriority` are inverses with one
  rule each way. Nothing is lost for an out-of-range on-disk value either.
  `KeyslotInfo.Priority` never reports `PriorityDefault`. A `Priority`
  outside the four declared values is refused with `ErrInvalidArgument`
  before any write: by `AddKeyslot`/`ChangeKeyslot` up front, and by
  `addKeyslotWithMasterKeyAndPriority` for `Enroll` and `AddRecoveryKey`.
- **CLI.** `changekey` no longer reads the slot's priority back to pass it
  through. It sends `KeyslotParams{}`, which keeps the priority. The CLI has
  no `--priority` flag. `addkey` still passes `PriorityNormal`, which gives
  the same result as the default.
- **Breaking.** The numeric values of `PriorityIgnore/Normal/Prefer` changed
  (0/1/2 → 1/2/3). Code that converts a `Priority` to or from the LUKS2
  integer has to add or subtract one. No compatibility shim (owner ruling
  2026-10-05). On-disk behaviour is unchanged except that ignore can now be
  written.

## p-cli

- **`addkey` and `changekey` take the shared KDF options.** `addkey`'s
  combined `--kdf pbkdf2-sha512` flag and `parseAddKeyKDF` are removed; one
  spelling (`--pbkdf`, `--hash`, `--iter-time`, `--pbkdf-force-iterations`,
  `--pbkdf-memory`, `--pbkdf-parallel`) now serves `create`, `recovery add`,
  `addkey` and `changekey`. With none given, both commands pass a zero
  `KDFParams`, keeping the library's default/inherited-cost policy (unlike
  `create`, which always resolves a KDF). `argon2i` is no longer selectable
  from the CLI, as it already was not on `create` (reversed below, p-final).
  No compatibility shim (owner ruling 2026-10-05). The FIPS hint "use --pbkdf pbkdf2" is now true
  for every command that prints it.

## p-docs (versioning text; TESTING/RELEASABILITY fold)

- **DESIGN §G.1 fold done, with one deviation.** `TESTING.md` is now
  `docs/volumes/engineering.md#test-strategy` (the other folders link to it)
  rather than being split across every folder: its content is project-wide
  test infrastructure, and `volumes/` owns the device layer it runs against.
  `test/integration/CLAUDE.md`/`AGENTS.md` keep their rules and were not
  duplicated with it. `RELEASABILITY.md` is folded into `test/internal/labstrings`
  package documentation as designed. The releasability gate scans the whole
  index and has no fixed docs path, so nothing needed to stay. This supersedes
  the cr-docs deferral above.
- **Versioning text states the 1.0 policy.** Post-1.0 follows the standards
  `release-versioning.md` §1: PATCH fix, MINOR backward-compatible API, MAJOR
  breaking with `/vN`. No deprecation policy is stated because the standards
  have none (§5); the docs say so rather than invent one.

## Corrections (2026-10-08, polish/p-comments)

Older entries above are left as written. Two statements in them no longer
hold:

- The cr-docs entry saying `ParseLegacyRecoveryKey` is still exported was
  true at its commit only. It was unexported in 37078b0 (`parseLegacyRecoveryKey`);
  `ParseRecoveryKey` is the one public parse, as DESIGN §B.6 says.
- DESIGN.md's status line listed the token free functions, `EnrollKeyProvider`
  and the seam-variable cleanup as outstanding. H13b and H13d finished them
  and H13e (#284) removed the last transitional forwards. DESIGN.md's header
  now says so.

## MigrateToFIPS: the primary header is authoritative

`MigrateToFIPS` treats the primary header copy as the authority. Before its
first write it reconciles the secondary to the primary, and it never repairs a
torn primary itself: a primary that does not read back is refused before any
write, because rebuilding it from the secondary would mean trusting a copy the
migration's own ordering never makes the survivor. The remedy is outside the
migration: `RestorePrimaryHeader`, or cryptsetup, which repairs on its own,
rebuilds the primary from the secondary, after which the migration can be run
again. This is deliberate, stricter than a silent repair, and intended
behavior. See `pkg/luks2/fipsmigrate.go:72-104`,
`pkg/luks2/keyslotdevice.go:143-151` and `docs/fips/architecture.md:66-71`.

## p-review-fix

- **`ChangeKeyslot` re-costs the slot when `p.KDF` is non-zero.** This
  supersedes H9c's and the priority lane's "`p.KDF` is not consulted". A zero
  `KDFParams` still keeps the slot's KDF type and cost (a PBKDF2-SHA1 slot is
  still rewritten as PBKDF2-SHA256). A non-zero one is validated and resolved
  exactly as `AddKeyslot` resolves it: the same SHA-1 and Argon2 cost checks,
  Argon2 refused under FIPS, and a benchmark when only `IterTime` is given.
  Rationale: cryptsetup's luksChangeKey honors `--pbkdf`, `--iter-time` and
  `--pbkdf-force-iterations`, and `luks2 changekey` accepted the same flags
  and silently ignored them. A CLI flag that does nothing is a defect.

## p-final

- **`--pbkdf` accepts `argon2i`.** `create`, `recovery add`, `addkey` and
  `changekey` take `argon2id`, `argon2i` and `pbkdf2`, the three values
  cryptsetup's `--pbkdf` takes. This reverses the p-cli entry that dropped
  `argon2i`. Owner ruling 2026-10-05: stricter than cryptsetup is fine,
  incompatibility is not, and a script doing `--pbkdf argon2i` must work.
  `--pbkdf-memory` and `--pbkdf-parallel` apply to both Argon2 variants;
  FIPS refusal is unchanged.
- **CLI unit tests format with the cheapest KDF.** PBKDF2 cannot go below its
  iteration floor, which costs seconds per derivation under `-race`, so the
  shared fixtures use Argon2id at the library minimum (64 MiB, time 1,
  parallel 1). The one test that asserts PBKDF2 iteration counts has its own
  PBKDF2 template.

## p-bugs

- **A key helper is held to the system-tool trust checks.**
  `keyprovider.Command` opens its absolute helper path through
  `command.Open`, which applies `internal/command`'s checks: a regular
  executable file owned by root or the caller, not group- or world-writable,
  reached only through directories owned the same way or sticky (see the
  pinned-descriptor entry below). A helper that fails them is refused with
  `ErrHelperFailed` before it runs. The helper produces the unlock credential
  and runs with this process's privileges, so it needs the same trust a
  `mkfs` does.
- **`(*Volume).Target` re-verifies the key against the header it re-reads.**
  It runs the same digest check `UnlockWithVolumeKey` does, against the
  digest of the segment being mapped, on every call, and refuses a key that
  does not verify with `ErrWrongKey`. A header rewritten between Unlock and
  activation, or a key from another volume, used to be mapped with only its
  size checked. The check costs one digest derivation per activation, as
  cryptsetup's own activation by volume key does. It binds the key to the
  header Target reads under its shared lock; that lock is released before
  `dmcrypt.Activate` loads the table, so a rewrite in that last window is not
  covered. Re-verifying always was chosen over re-verifying only when
  `SequenceID` changed (the earlier DESIGN.md wording): a header rewritten
  by another tool need not advance it.
- **`(*loop.Device).Detach` refuses a device no longer backed by its file.**
  A `Device` records the backing file's device and inode when it is obtained
  (`Attach` from the descriptor it hands LOOP_SET_FD, `Find` from the match,
  `Lookup` from LOOP_GET_STATUS64, or none if nothing is attached). Detach
  reads the identity with LOOP_GET_STATUS64 on the descriptor it then sends
  LOOP_CLR_FD on, and refuses with the new `loop.ErrDeviceReassigned` when it
  differs, or with an `ErrIO` error when nothing is attached any more. Loop
  numbers are host-global and reused as soon as they are free, so a path is
  not an identity. The CLI's file-volume flow now detaches the `Device`
  `Attach` returned instead of rebuilding one with `Lookup`, which would have
  recorded whatever the number held at that later moment. The check and the
  clear are two ioctls, so a reassignment between them remains possible.
- **The unlock scan honours keyslot priority.** Every path that scans for the
  volume key (`Unlock`, `AddKey`'s existing credential, the passphrase test)
  tries the bound `prefer` keyslots first, then the `normal` ones, each group
  in ascending id order, and never an `ignore` keyslot, matching cryptsetup's
  `CRYPT_ANY_SLOT` open. `UnlockKeyslot` still opens an `ignore` keyslot,
  because it names it. A header whose bound keyslots are all `ignore` returns
  `ErrNoKeyslots`, cryptsetup's "no usable keyslot", rather than
  `ErrWrongKey`: the passphrase was never judged. Before this change,
  priority was written and reported but never read, so a keyslot an operator
  had set to `ignore` still opened the volume.
- **A provider's token keyslots are tried by priority.** `UnlockWithProvider`
  tries the keyslots its token names `prefer` first, then `normal`, then
  `ignore`, each group in the token's order, as cryptsetup's
  `LUKS2_keyslot_open_by_token` does for a token named with `--token-id`
  (`luks2_token.c`: a specific token runs the prefer, normal and ignore
  passes). It used to take the token's order as written, so a `normal`
  keyslot listed first won over a `prefer` one. cryptsetup skips `ignore`
  keyslots only when it scans every token itself; this library never picks a
  token for the caller, so that case does not arise, and an `ignore` keyslot
  a token names stays reachable, last, as it is under `--token-id`.
- **A volume's KDF preflight reads the volume's FIPS policy.** `AddKeyslot`,
  `ChangeKeyslot` and `Enroll` now check an explicit KDF with
  `validateWith(v.sys.fipsMode)`, as `Format` and `AddRecoveryKey` already did,
  so a policy forced on a volume refuses an Argon2 KDF before the lock instead
  of after it; the public `Validate()` keeps the process mode. In production
  both sources are `fips.Probe`; the on-disk screening H13d left on
  `fips.Probe` is unchanged.
- **A program runs from the descriptor its checks were made on.**
  `command.Open` replaces the path-based check (`Trusted`, and `Resolve`'s
  copy of it), which judged the directories left once `EvalSymlinks` had
  resolved the path, so a directory or link on the path as named was never
  judged, and which let `exec` reopen the path afterwards. `Open` walks the
  path from `/` one component at a time with
  `openat(O_PATH|O_NOFOLLOW|O_CLOEXEC)` relative to the directory before it,
  judges each by `fstat` of its descriptor (directories: owned by root or the
  caller, not group- or world-writable unless sticky; the file: a regular,
  executable file owned the same way and writable by neither), and returns the
  file's descriptor. `Program.Cmd` executes `/proc/self/fd/3` with that
  descriptor as `ExtraFiles[0]`, so the file that runs is the file checked. The
  descriptor stays open in the program because a script's interpreter reopens
  it by that name; it refers only to the program's own file. `Resolve` (system
  tools) and `keyprovider.Command` (key helpers) both go through `Open`, so the
  two cannot drift.
  Symlinks are resolved through the same walk, not refused: a link must be
  owned by root or the caller (in a sticky directory anyone can create one,
  and only its owner can replace it), is read from its own descriptor, and its
  target is walked with the same checks from `/` or from the checked directory
  holding it; `..` climbs only to a directory already checked, and more than
  40 links are refused. Refusing every symlink would be stricter, but merged
  `/usr` layouts (`/sbin` → `usr/sbin`) and the `mkfs.ext4` → `mke2fs` links
  some distributions ship are symlinks, and a helper installed as a link into
  `/opt` is ordinary; the walk judges every directory such a path passes
  through, which is what the refusal would have protected. Off Linux, with no
  `O_PATH` or `/proc/self/fd`, `Open` fails closed with `ErrTool`.

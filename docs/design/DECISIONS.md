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

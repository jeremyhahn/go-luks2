// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"crypto"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/fips"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
)

// FIPS-compatible KDF type constants
// These provide convenience aliases for PBKDF2 with specific hash algorithms
const (
	// kdfTypePBKDF2 is the base PBKDF2 KDF type (uses HashAlgo option for hash selection)
	kdfTypePBKDF2 = "pbkdf2"

	// kdfTypePBKDF2SHA1 names PBKDF2 with SHA-1; never written (ErrInvalidArgument), but existing SHA-1 keyslots open outside FIPS mode.
	kdfTypePBKDF2SHA1 = "pbkdf2-sha1"

	// kdfTypePBKDF2SHA256 is PBKDF2 with SHA-256 (FIPS-approved, recommended)
	kdfTypePBKDF2SHA256 = "pbkdf2-sha256"

	// kdfTypePBKDF2SHA384 is PBKDF2 with SHA-384 (FIPS-approved)
	kdfTypePBKDF2SHA384 = "pbkdf2-sha384"

	// kdfTypePBKDF2SHA512 is PBKDF2 with SHA-512 (FIPS-approved)
	kdfTypePBKDF2SHA512 = "pbkdf2-sha512"

	// kdfTypeArgon2i is the Argon2i KDF type. It is NOT FIPS-approved and is
	// refused while the process runs in FIPS 140-3 mode. See docs/fips/architecture.md.
	kdfTypeArgon2i = "argon2i"

	// kdfTypeArgon2id is the Argon2id KDF type and the library default outside
	// FIPS 140-3 mode. It is NOT FIPS-approved and is refused while the process
	// runs in FIPS 140-3 mode. See DefaultKDFSpec and docs/fips/architecture.md.
	kdfTypeArgon2id = "argon2id"
)

// DefaultKDFSpec returns the KDF a keyslot is created with when the caller
// names none, and it depends on the mode the process runs in, as cryptsetup's
// default does:
//
//   - In FIPS 140-3 mode it is "pbkdf2-sha512". The iteration count is
//     calibrated to the time budget (PBKDFIterTime, 2000 ms by default) and
//     never falls below the policy floor for SHA-512, so the keyslot gets
//     whichever of the two is greater.
//   - Otherwise it is "argon2id", as it always has been.
//
// A FIPS default of Argon2id would refuse every caller that names no KDF with
// ErrFIPSNotApproved.
//
// A caller that names no KDF but supplies an Argon2 cost has chosen Argon2 by
// its parameters, and gets "argon2id" in either mode rather than having
// the cost silently dropped; see resolveKDFType.
func DefaultKDFSpec() string {
	return defaultKDFTypeFor(fips.Probe())
}

// KDFType names a keyslot's key-derivation function in the Volume
// API: the DESTINATION of a resolved KDFParams, as opposed to kdfTypePBKDF2
// and its aliases above, which are the on-disk strings this package's
// header-level internals read and write. The two constant sets are deliberately
// distinct: KDFType carries no hash, because KDFParams.Hash says that
// separately, and a Volume API caller never needs the alias spellings
// ("pbkdf2-sha512") the internal formatOptionsForTest.KDFType field
// overloads.
type KDFType string

const (
	KDFArgon2id KDFType = "argon2id"
	KDFArgon2i  KDFType = "argon2i"
	KDFPBKDF2   KDFType = "pbkdf2"
)

// KDFParams is the KDF a keyslot is created or re-derived with. Hash and the cost fields apply to exactly one of Type's two
// families and are ignored for the other: Hash and IterTime are PBKDF2's
// (Iterations overrides IterTime's calibration when it is non-zero, and is
// held to the same floor a calibrated count is); Time, MemoryKiB
// and Parallel are Argon2's.
type KDFParams struct {
	Type KDFType // zero: DefaultKDFType()

	Hash     crypto.Hash   // PBKDF2 PRF
	IterTime time.Duration // calibration target; zero: 2s

	Iterations int // exact PBKDF2 count (floors still apply)

	Time, MemoryKiB, Parallel int // Argon2
}

// Validate refuses a KDFParams this package cannot create: a Type outside
// the three KDFType constants, an Argon2 cost (named or implied by a nonzero
// Time/MemoryKiB/Parallel) outside the floors and ceilings
// validateArgon2CreateCost enforces, and -- the FIPS approval check -- an
// Argon2 KDF, named or implied, while the process runs in
// FIPS 140-3 mode (ErrFIPSNotApproved). An empty Type is judged by what it
// resolves to, the same way Format and AddKeyslot resolve it, so a
// FIPS-mode caller that gives no Type but an Argon2 cost sees the refusal
// here rather than after a device is claimed.
func (p KDFParams) Validate() error {
	return p.validateWith(fips.Probe)
}

// validateWith is Validate against a given FIPS policy source, the volume's sys's for Volume methods.
func (p KDFParams) validateWith(fipsMode func() fips.Mode) error {
	switch p.Type {
	case "", KDFArgon2id, KDFArgon2i, KDFPBKDF2:
	default:
		return &errs.Error{Kind: ErrUnsupported, Detail: string(p.Type)}
	}
	if p.Iterations < 0 {
		return &errs.Error{Kind: ErrKeyslotNotFound, Detail: "KDFParams: Iterations is negative"}
	}

	argon2CostGiven := p.Time != 0 || p.MemoryKiB != 0 || p.Parallel != 0
	resolved := resolveKDFTypeFor(string(p.Type), argon2CostGiven, fipsMode())
	if err := fipsMode().RequireKDF(resolved); err != nil {
		return err
	}
	// The PBKDF2 PRF is judged too: SHA-1 is not FIPS-approved, so in FIPS
	// mode a PBKDF2 KDF naming it is refused here, not later at creation.
	if isPBKDF2Type(resolved) && p.Hash != 0 {
		if err := fipsMode().RequireHash("pbkdf2 hash "+p.Hash.String(), p.Hash); err != nil {
			return err
		}
	}

	return validateArgon2CreateCost(formatOptionsForTest{
		KDFType:        resolved,
		Argon2Time:     p.Time,
		Argon2Memory:   p.MemoryKiB,
		Argon2Parallel: p.Parallel,
	})
}

// DefaultKDFType returns the KDFType a keyslot is created with when
// KDFParams names none: KDFPBKDF2 in FIPS 140-3 mode, KDFArgon2id otherwise.
// It carries no hash -- KDFParams.Hash says that separately -- unlike
// DefaultKDFSpec, which returns this package's internal combined alias
// ("pbkdf2-sha512", "argon2id") instead. On disk a PBKDF2 keyslot spells
// that as "type":"pbkdf2" plus "hash":"sha512".
func DefaultKDFType() KDFType {
	return defaultKDFTypeWith(fips.Probe)
}

func defaultKDFTypeWith(fipsMode func() fips.Mode) KDFType {
	if fipsMode() {
		return KDFPBKDF2
	}
	return KDFArgon2id
}

// resolved is p with zero fields defaulted against fipsMode; a defaulted PBKDF2 hash is SHA-512 in FIPS mode and SHA-256 otherwise, never SHA-1.
func (p KDFParams) resolved(fipsMode fips.Mode) (kdfType KDFType, hash crypto.Hash) {
	argon2CostGiven := p.Time != 0 || p.MemoryKiB != 0 || p.Parallel != 0
	kdfType = p.Type
	typeWasDefaulted := false
	if kdfType == "" {
		typeWasDefaulted = !argon2CostGiven
		kdfType = KDFArgon2id
		if typeWasDefaulted && bool(fipsMode) {
			kdfType = KDFPBKDF2
		}
	}

	hash = p.Hash
	if kdfType == KDFPBKDF2 && hash == 0 {
		hash = crypto.SHA256
		if typeWasDefaulted && bool(fipsMode) {
			hash = crypto.SHA512
		}
	}
	return kdfType, hash
}

// defaultKDFTypeFor is DefaultKDFSpec for a given mode, so both answers are testable in one process.
func defaultKDFTypeFor(fipsMode fips.Mode) string {
	if fipsMode {
		return kdfTypePBKDF2SHA512
	}
	return kdfTypeArgon2id
}

// resolveKDFType returns kdfType if named, "argon2id" if an Argon2 cost is given, and DefaultKDFSpec otherwise.
func resolveKDFType(kdfType string, argon2CostGiven bool) string {
	return resolveKDFTypeFor(kdfType, argon2CostGiven, fips.Probe())
}

// resolveKDFTypeFor is resolveKDFType for a given mode; see defaultKDFTypeFor.
func resolveKDFTypeFor(kdfType string, argon2CostGiven bool, fipsMode fips.Mode) string {
	if kdfType != "" {
		return kdfType
	}
	if argon2CostGiven {
		return kdfTypeArgon2id
	}
	return defaultKDFTypeFor(fipsMode)
}

// formatArgon2CostGiven reports whether opts carries any Argon2
// cost, including a negative one -- != 0 for the reason callerChoseArgon2Cost
// gives: a negative is still a deliberate choice, and must reach the refusal.
func formatArgon2CostGiven(opts formatOptionsForTest) bool {
	return opts.Argon2Time != 0 || opts.Argon2Memory != 0 || opts.Argon2Parallel != 0
}

// isFIPSCompliantKDF reports whether the KDF type is FIPS-approved; "pbkdf2-sha1" is not, plain "pbkdf2" (SHA-256) is.
func isFIPSCompliantKDF(kdfType string) bool {
	switch normalizeKDFType(kdfType) {
	case kdfTypePBKDF2, kdfTypePBKDF2SHA256, kdfTypePBKDF2SHA384, kdfTypePBKDF2SHA512:
		return true
	default:
		return false
	}
}

// normalizeKDFType normalizes a KDF type string to lowercase
func normalizeKDFType(kdfType string) string {
	return strings.ToLower(strings.TrimSpace(kdfType))
}

// toKDFParams copies k's fields into a kdf.Params, keeping Salt as base64; callers check k for nil.
func toKDFParams(k *header.KDF) kdf.Params {
	return kdf.Params{
		Type:       k.Type,
		Hash:       k.Hash,
		Salt:       k.Salt,
		Iterations: k.Iterations,
		Time:       k.Time,
		Memory:     k.Memory,
		CPUs:       k.CPUs,
	}
}

// deriveKeyEnclave derives a keyslot key from a passphrase under sys's FIPS mode and custody, returning it in protected memory; Argon2 is refused in FIPS mode. The stdlib KDFs still copy the input and return the result on the heap.
func deriveKeyEnclave(ctx context.Context, passphrase []byte, k *header.KDF, keySize int, sys volumeSys) (enclave.ByteAccess, error) {
	if k == nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}
	key, err := kdfDeriver(sys).Derive(ctx, passphrase, toKDFParams(k), keySize)
	return key, reclassifyUnsupportedKDF(err)
}

// reclassifyUnsupportedKDF maps errs.ErrUnsupportedHash and kdf.ErrUnsupportedKDF to ErrUnsupported; FIPS refusals are left as they are.
func reclassifyUnsupportedKDF(err error) error {
	if err != nil && (errors.Is(err, errs.ErrUnsupportedHash) || errors.Is(err, kdf.ErrUnsupportedKDF)) {
		return &errs.Error{Kind: ErrUnsupported, Err: err}
	}
	return err
}

// passphraseKDF is the keyslot derivation under s's FIPS mode and custody; passphraseKDFOverride replaces it in tests. The digest derivation does not use it.
func (s volumeSys) passphraseKDF(ctx context.Context, passphrase []byte, k *header.KDF, keySize int) (enclave.ByteAccess, error) {
	if s.passphraseKDFOverride != nil {
		return s.passphraseKDFOverride(ctx, passphrase, k, keySize)
	}
	return deriveKeyEnclave(ctx, passphrase, k, keySize, s)
}

// deriveKeySecret derives from material already in protected memory without copying it here; crypto/pbkdf2 still copies it into an unwipeable string (exposure 2 in internal/secret).
func deriveKeySecret(ctx context.Context, material enclave.ByteAccess, k *header.KDF, keySize int, sys volumeSys) (enclave.ByteAccess, error) {
	return deriveKeySecretIn(ctx, material, k, keySize, sys.fipsMode())
}

// deriveKeySecretIn is deriveKeySecret under an explicit FIPS mode, for a
// caller that is handed the operation's mode rather than its whole volumeSys
// (evaluateDigest). It is the mode the caller's sys reports, never a default.
func deriveKeySecretIn(ctx context.Context, material enclave.ByteAccess, k *header.KDF, keySize int, mode fips.Mode) (enclave.ByteAccess, error) {
	if k == nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}
	key, err := kdf.Deriver{Custody: custody, FIPS: mode}.DeriveFromSecret(ctx, material, toKDFParams(k), keySize)
	return key, reclassifyUnsupportedKDF(err)
}

// getPBKDF2HashFunc returns the hash function for PBKDF2 key derivation
// Supported: sha256, sha384, sha512 (FIPS-approved) and sha1 (legacy LUKS
// headers only, refused in FIPS 140-3 mode)
func getPBKDF2HashFunc(hashAlgo string, fipsMode func() fips.Mode) (func() hash.Hash, error) {
	f, err := kdf.PBKDF2HashFunc(fipsMode(), hashAlgo)
	return f, reclassifyUnsupportedKDF(err)
}

// pbkdf2Hash resolves a LUKS2 PBKDF2 hash name to a crypto.Hash without the FIPS gate; getPBKDF2HashFunc adds the gate.
func pbkdf2Hash(hashAlgo string) (crypto.Hash, error) {
	return kdf.PBKDF2Hash(hashAlgo)
}

// legacyDigestLen is a digest length accepted for containers that stored 32 bytes under "sha512"; accepted lengths are the hash output, this, and luks1DigestLen.
const legacyDigestLen = 32

// luks1DigestLen is the LUKS1 digest length (LUKS_DIGESTSIZE), kept unchanged by cryptsetup convert.
const luks1DigestLen = 20

// hashOutputLen returns the output length in bytes of a LUKS2 hash name, resolved through getPBKDF2HashFunc.
func hashOutputLen(hashAlgo string) (int, error) {
	return kdf.HashOutputLen(fips.Probe(), hashAlgo)
}

// deriveArgon2i derives a key using Argon2i.
func deriveArgon2i(passphrase, salt []byte, k *header.KDF, keySize int) ([]byte, error) {
	return kdf.DeriveArgon2i(passphrase, salt, toKDFParams(k), keySize)
}

// deriveArgon2id derives a key using Argon2id.
func deriveArgon2id(passphrase, salt []byte, k *header.KDF, keySize int) ([]byte, error) {
	return kdf.DeriveArgon2id(passphrase, salt, toKDFParams(k), keySize)
}

// PBKDF2 iteration calibration: the probe doubles until it runs past a floor, timed with full Duration resolution, then extrapolates.
const (
	// pbkdf2ProbeStart is where the doubling begins -- the count the old
	// implementation used as its entire measurement.
	pbkdf2ProbeStart = kdf.ProbeStart

	// pbkdf2ProbeFloor is how long a probe must run before its measurement is trusted, long enough to absorb a preemption.
	pbkdf2ProbeFloor = kdf.ProbeFloor

	// pbkdf2ProbeCeiling bounds the doubling so a clock that never advances fails instead of looping.
	pbkdf2ProbeCeiling = kdf.ProbeCeiling

	// maxPBKDF2IterTimeMs bounds the requested budget so Duration arithmetic cannot overflow.
	maxPBKDF2IterTimeMs = kdf.MaxPBKDF2IterTimeMs

	// minPBKDF2Iterations is the floor for a keyslot this package writes; header.MinKDFIterations governs what it reads.
	minPBKDF2Iterations = kdf.MinPBKDF2Iterations

	// pbkdf2ReferenceTargetMs is the budget the recommended minima below are
	// stated against, and is this library's own default (see createPBKDF2KDF).
	pbkdf2ReferenceTargetMs = kdf.PBKDF2ReferenceTargetMs
)

// pbkdf2RecommendedIterations is OWASP's recommended count per hash at pbkdf2ReferenceTargetMs, a floor scaled by the requested budget.
var pbkdf2RecommendedIterations = kdf.PBKDF2RecommendedIterations

// benchmarkPBKDF2 returns the iteration count costing about targetMs here, clamped to [floor, header.MaxKDFIterations]; a failed calibration returns a *KDFCalibrationError, never a default.
func benchmarkPBKDF2(fipsMode fips.Mode, hashAlgo string, keySize, targetMs int) (int, error) {
	return kdf.Deriver{Custody: custody, FIPS: fipsMode}.Calibrate(context.Background(), hashAlgo, keySize, targetMs)
}

// pbkdf2Timer times one PBKDF2 derivation; a parameter so the arithmetic can be tested against a known rate.
type pbkdf2Timer = kdf.Timer

// wallClockPBKDF2 times a real derivation on the wall clock; its inputs and output are not key material.
func wallClockPBKDF2(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	return kdf.WallClockPBKDF2(hashFunc, iterations, keySize)
}

// calibratePBKDF2 is the calibration, with the probe bounds and timer as parameters.
func calibratePBKDF2(hashFunc func() hash.Hash, hashAlgo string, keySize, targetMs int, probeFloor time.Duration, probeCeiling int, timer pbkdf2Timer) (int, error) {
	return kdf.CalibratePBKDF2(context.Background(), hashFunc, hashAlgo, keySize, targetMs, probeFloor, probeCeiling, timer)
}

// scalePBKDF2Iterations extrapolates a timed probe to the requested budget and
// clamps the result into the range this package is willing to write.
func scalePBKDF2Iterations(hashAlgo string, probe int, elapsed time.Duration, targetMs int) int {
	return kdf.ScalePBKDF2Iterations(hashAlgo, probe, elapsed, targetMs)
}

// pbkdf2IterationFloor returns the smallest count written for a hash and budget, unrounded.
func pbkdf2IterationFloor(hashAlgo string, targetMs int) float64 {
	return kdf.PBKDF2IterationFloor(hashAlgo, targetMs)
}

// keyslotCostPolicy selects the PBKDF2 floor for a new keyslot: strict for caller-supplied credentials, minPBKDF2Iterations for 256-bit credentials this package generated. Unexported, zero value strict.
type keyslotCostPolicy int

const (
	// callerSuppliedCredential is the strict policy and the zero value.
	callerSuppliedCredential keyslotCostPolicy = iota

	// libraryGeneratedCredential relaxes the floor to minPBKDF2Iterations for a credential drawn from custody.Random; used by AddRecoveryKey.
	libraryGeneratedCredential
)

// pbkdf2FloorFor returns the smallest iteration count a policy permits.
func pbkdf2FloorFor(hashAlgo string, policy keyslotCostPolicy) int {
	if policy == libraryGeneratedCredential {
		return minPBKDF2Iterations
	}
	// Rounded UP. pbkdf2IterationFloor returns a float because its other caller
	// compares it against an unrounded extrapolation; truncating here would
	// admit a count one iteration below the floor.
	return int(math.Ceil(pbkdf2IterationFloor(hashAlgo, pbkdf2ReferenceTargetMs)))
}

// forcedPBKDF2Iterations validates an explicit iteration count against the same hash-dependent floor calibration applies under policy, and returns it unchanged.
func forcedPBKDF2Iterations(hashAlgo string, iterations int, policy keyslotCostPolicy) (int, error) {
	minimum := pbkdf2FloorFor(hashAlgo, policy)
	param := fmt.Sprintf("pbkdf2 iterations (%s)", hashAlgo)

	if iterations < minimum {
		return 0, &KDFCostError{
			Param: param,
			Value: iterations,
			Min:   minimum,
			Max:   header.MaxKDFIterations,
		}
	}

	if iterations > header.MaxKDFIterations {
		return 0, &KDFCostError{
			Param: param,
			Value: iterations,
			Min:   minimum,
			Max:   header.MaxKDFIterations,
		}
	}

	return iterations, nil
}

// createKDF creates a KDF from options and the keyslot's cost policy; pbkdf2-sha1 is refused, Argon2 is refused in FIPS mode, and an empty type resolves through resolveKDFType.
func createKDF(opts formatOptionsForTest, keySize int, policy keyslotCostPolicy, fipsMode func() fips.Mode, calibratedCountFloor func(string, keyslotCostPolicy) int, cryptoRand io.Reader) (*header.KDF, error) {
	kdfType := resolveKDFTypeFor(normalizeKDFType(opts.KDFType), formatArgon2CostGiven(opts), fipsMode())

	// No keyslot is created with SHA-1, before any other choice is judged.
	if err := refuseSHA1ForCreation(kdfType, opts.HashAlgo, fipsMode()); err != nil {
		return nil, err
	}

	// Checked after the default is resolved: refuses an Argon2 KDF the caller asked for in FIPS mode.
	if err := fipsMode().RequireKDF(kdfType); err != nil {
		return nil, err
	}

	salt, err := randomBytes(32, cryptoRand)
	if err != nil {
		return nil, err
	}

	saltB64 := encodeBase64(salt)

	// Handle PBKDF2 variants (including convenience aliases)
	if isPBKDF2Type(kdfType) {
		return createPBKDF2KDF(kdfType, opts, saltB64, keySize, policy, fipsMode(), calibratedCountFloor)
	}

	// Handle Argon2 variants
	switch kdfType {
	case kdfTypeArgon2i, kdfTypeArgon2id:
		return createArgon2KDF(kdfType, opts, saltB64)
	default:
		return nil, &errs.Error{Kind: ErrUnsupported, Detail: kdfType + " (supported: pbkdf2, pbkdf2-sha256, pbkdf2-sha384, pbkdf2-sha512, argon2i, argon2id)"}
	}
}

// refuseSHA1ForCreation refuses a KDF type or hash that would write SHA-1; reading is unaffected.
func refuseSHA1ForCreation(kdfType, hashAlgo string, mode fips.Mode) error {
	// In FIPS mode the refusal is a FIPS one: SHA-1 is not an approved PBKDF2
	// PRF, so the error matches ErrFIPSNotApproved, as KDFParams.Validate's
	// does. Outside FIPS mode it is a plain invalid argument.
	kind := ErrInvalidArgument
	if mode {
		kind = ErrFIPSNotApproved
	}
	if normalizeKDFType(kdfType) == kdfTypePBKDF2SHA1 {
		return &errs.Error{Kind: kind, Err: ErrUnsupported,
			Detail: "pbkdf2-sha1: new keyslots use pbkdf2 with sha256, sha384 or sha512, or argon2"}
	}
	if strings.EqualFold(strings.TrimSpace(hashAlgo), "sha1") {
		return &errs.Error{Kind: kind, Err: ErrUnsupported,
			Detail: "sha1: new keyslots and digests use sha256, sha384 or sha512"}
	}
	return nil
}

// isPBKDF2Type returns true if the KDF type is a PBKDF2 variant
func isPBKDF2Type(kdfType string) bool {
	switch kdfType {
	case kdfTypePBKDF2, kdfTypePBKDF2SHA1, kdfTypePBKDF2SHA256, kdfTypePBKDF2SHA384, kdfTypePBKDF2SHA512:
		return true
	default:
		return false
	}
}

// createPBKDF2KDF creates a PBKDF2 KDF structure
func createPBKDF2KDF(kdfType string, opts formatOptionsForTest, saltB64 string, keySize int, policy keyslotCostPolicy, fipsMode fips.Mode, calibratedCountFloor func(string, keyslotCostPolicy) int) (*header.KDF, error) {
	// Determine hash algorithm from KDF type or HashAlgo option
	hashAlgo := getHashAlgoForKDFType(kdfType, opts.HashAlgo)

	// An explicit count takes precedence over the time budget; forcedPBKDF2Iterations still applies the floor.
	var (
		iterations int
		err        error
	)
	if opts.PBKDFIterations != 0 {
		iterations, err = forcedPBKDF2Iterations(hashAlgo, opts.PBKDFIterations, policy)
	} else {
		iterTime := opts.PBKDFIterTime
		if iterTime == 0 {
			iterTime = pbkdf2ReferenceTargetMs
		}
		iterations, err = benchmarkPBKDF2(fipsMode, hashAlgo, keySize, iterTime)
		// A calibrated count is held to the same floor as an explicit one.
		if err == nil {
			iterations = max(iterations, calibratedCountFloor(hashAlgo, policy))
		}
	}
	if err != nil {
		return nil, err
	}

	return &header.KDF{
		Type:       kdfTypePBKDF2, // Always store as "pbkdf2" for LUKS2 compatibility
		Hash:       hashAlgo,
		Salt:       saltB64,
		Iterations: &iterations,
	}, nil
}

// getHashAlgoForKDFType returns the hash algorithm for a KDF type
func getHashAlgoForKDFType(kdfType, hashAlgoOverride string) string {
	// If explicit hash algo is provided, use it
	if hashAlgoOverride != "" {
		return strings.ToLower(hashAlgoOverride)
	}

	// Extract hash from KDF type alias
	switch kdfType {
	case kdfTypePBKDF2SHA1:
		return "sha1"
	case kdfTypePBKDF2SHA256:
		return "sha256"
	case kdfTypePBKDF2SHA384:
		return "sha384"
	case kdfTypePBKDF2SHA512:
		return "sha512"
	default:
		// Default to SHA-256 for plain "pbkdf2"
		return "sha256"
	}
}

// createArgon2KDF creates an Argon2 KDF structure
func createArgon2KDF(kdfType string, opts formatOptionsForTest, saltB64 string) (*header.KDF, error) {
	time := opts.Argon2Time
	if time == 0 {
		time = 4 // Default
	}
	memory := opts.Argon2Memory
	if memory == 0 {
		memory = 1048576 // 1GB default
	}
	cpus := opts.Argon2Parallel
	if cpus == 0 {
		cpus = 4 // Default
	}

	kdf := &header.KDF{
		Type:   kdfType,
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   &cpus,
	}

	// Hold the KDF to header.ValidateKDFCost, so nothing written is refused on read.
	if err := header.ValidateKDFCost(kdf); err != nil {
		return nil, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidArgument), Detail: "refusing to write an Argon2 keyslot the read path would refuse", Err: err}
	}
	return kdf, nil
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 string to bytes
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// cryptoHashNames maps the crypto.Hash values the KDF paths use to their LUKS2 names.
var cryptoHashNames = []struct {
	hash crypto.Hash
	name string
}{
	{crypto.SHA1, "sha1"},
	{crypto.SHA256, "sha256"},
	{crypto.SHA384, "sha384"},
	{crypto.SHA512, "sha512"},
}

// cryptoHashFromName looks up a hash by its LUKS2 name, returning the zero crypto.Hash (unset) for an unknown name.
func cryptoHashFromName(name string) crypto.Hash {
	for _, e := range cryptoHashNames {
		if e.name == name {
			return e.hash
		}
	}
	return 0
}

// cryptoHashName is cryptoHashFromName's inverse.
func cryptoHashName(h crypto.Hash) string {
	for _, e := range cryptoHashNames {
		if e.hash == h {
			return e.name
		}
	}
	return ""
}

// addKeyOptionsFromKeyslotParams converts a KeyslotParams into the
// addKeyOptionsForTest addKeyslotWithMasterKey takes, so Enroll (provider.go)
// is built on that existing internal rather than a second cost-handling path.
func addKeyOptionsFromKeyslotParams(kp KeyslotParams) *addKeyOptionsForTest {
	opts := &addKeyOptionsForTest{
		Keyslot:         kp.Slot,
		KDFType:         string(kp.KDF.Type),
		Hash:            cryptoHashName(kp.KDF.Hash),
		Argon2Time:      kp.KDF.Time,
		Argon2Memory:    kp.KDF.MemoryKiB,
		Argon2Parallel:  kp.KDF.Parallel,
		PBKDFIterations: kp.KDF.Iterations,
	}
	if kp.KDF.IterTime > 0 {
		opts.PBKDFIterTime = int(kp.KDF.IterTime.Milliseconds())
	}
	return opts
}

// kdfParamsFromHeaderKDF converts a keyslot's on-disk KDF into KDFParams for listing; an unknown hash reports the zero crypto.Hash.
func kdfParamsFromHeaderKDF(k *header.KDF) KDFParams {
	var p KDFParams
	switch k.Type {
	case kdfTypeArgon2id:
		p.Type = KDFArgon2id
	case kdfTypeArgon2i:
		p.Type = KDFArgon2i
	default:
		p.Type = KDFPBKDF2
	}
	p.Hash = cryptoHashFromName(k.Hash)
	if k.Iterations != nil {
		p.Iterations = *k.Iterations
	}
	if k.Time != nil {
		p.Time = *k.Time
	}
	if k.Memory != nil {
		p.MemoryKiB = *k.Memory
	}
	if k.CPUs != nil {
		p.Parallel = *k.CPUs
	}
	return p
}

// kdfParamsFromDisk is kdfParamsFromHeaderKDF for a caller (Enrollment's
// AddRecoveryKey/MigrateToFIPS path) that needs to refuse an unparseable
// on-disk KDF type rather than silently defaulting it to KDFPBKDF2.
func kdfParamsFromDisk(k *header.KDF) (KDFParams, error) {
	switch k.Type {
	case kdfTypeArgon2id, kdfTypeArgon2i, kdfTypePBKDF2:
	default:
		return KDFParams{}, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "unknown on-disk KDF type " + strconv.Quote(k.Type)}
	}
	return kdfParamsFromHeaderKDF(k), nil
}

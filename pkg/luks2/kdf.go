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

	// kdfTypePBKDF2SHA1 names PBKDF2 with SHA-1. It is NOT a type a keyslot
	// can be created with: every creation path refuses it with
	// ErrInvalidArgument (#239, a breaking change). Existing PBKDF2-SHA1
	// keyslots -- on disk, type "pbkdf2" with hash "sha1", as cryptsetup and
	// converted LUKS1 volumes carry -- still open outside FIPS 140-3 mode.
	// See docs/fips/architecture.md.
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
// default does (#237):
//
//   - In FIPS 140-3 mode it is "pbkdf2-sha512". The iteration count is
//     calibrated to the time budget (PBKDFIterTime, 2000 ms by default) and
//     never falls below the policy floor for SHA-512, so the keyslot gets
//     whichever of the two is greater.
//   - Otherwise it is "argon2id", as it always has been.
//
// Before #237 the default was Argon2id in both modes, so in FIPS mode every
// caller that named no KDF -- the CLI's recovery add among them -- was refused
// with ErrFIPSNotApproved and a FIPS deployment could create no keyslot
// without choosing one explicitly.
//
// A caller that names no KDF but supplies an Argon2 cost has chosen Argon2 by
// its parameters, and gets "argon2id" in either mode rather than having
// the cost silently dropped; see resolveKDFType.
func DefaultKDFSpec() string {
	return defaultKDFTypeFor(fips.Probe())
}

// KDFType names a keyslot's key-derivation function in the DESIGN.md §B.2
// API: the DESTINATION of a resolved KDFParams, as opposed to kdfTypePBKDF2
// and its aliases above, which are the on-disk strings this package's
// pre-§B.2 internals read and write. The two constant sets are deliberately
// distinct: KDFType carries no hash, because KDFParams.Hash says that
// separately, and a §B.2 caller never needs the alias spellings
// ("pbkdf2-sha512") the internal formatOptionsForTest.KDFType field
// overloads.
type KDFType string

const (
	KDFArgon2id KDFType = "argon2id"
	KDFArgon2i  KDFType = "argon2i"
	KDFPBKDF2   KDFType = "pbkdf2"
)

// KDFParams is the KDF a keyslot is created or re-derived with (DESIGN.md
// §B.2). Hash and the cost fields apply to exactly one of Type's two
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
// validateArgon2CreateCost enforces, and -- the FIPS approval DESIGN.md §B.2
// calls out -- an Argon2 KDF, named or implied, while the process runs in
// FIPS 140-3 mode (ErrFIPSNotApproved). An empty Type is judged by what it
// resolves to, the same way Format and AddKeyslot resolve it, so a
// FIPS-mode caller that gives no Type but an Argon2 cost sees the refusal
// here rather than after a device is claimed.
func (p KDFParams) Validate() error {
	return p.validateWith(fips.Probe)
}

// validateWith is Validate against a given FIPS policy source. Every Volume
// method that takes a KDFParams -- Format, AddKeyslot, ChangeKeyslot, Enroll,
// AddRecoveryKey -- passes its sys's, so the preflight judges a KDF by the
// policy the volume's derivation will apply; only the public Validate, which
// has no volume, reads the process's mode.
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

// resolved is p with its zero fields defaulted against fipsMode, mirroring
// resolveKDFTypeFor/defaultKDFTypeFor: an empty Type with no Argon2 cost
// becomes DefaultKDFType(); a PBKDF2 Type (named or defaulted to) with a
// zero Hash becomes SHA-512 when the default put it there (matching
// DefaultKDFSpec's FIPS-mode "pbkdf2-sha512") and SHA-256 otherwise
// (matching getHashAlgoForKDFType's plain-"pbkdf2" default) -- never SHA-1,
// which no path here can select.
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

// defaultKDFTypeFor is DefaultKDFSpec for a given mode. The mode is a parameter
// so both answers are tested in every run: a process cannot leave FIPS mode, or
// enter it, once it has started. DefaultKDFSpec asks fipsMode, the seam every
// FIPS policy decision in this package goes through.
func defaultKDFTypeFor(fipsMode fips.Mode) string {
	if fipsMode {
		return kdfTypePBKDF2SHA512
	}
	return kdfTypeArgon2id
}

// resolveKDFType returns the KDF type a keyslot is created with: kdfType when
// the caller named one, "argon2id" when the caller named none but supplied
// an Argon2 cost, and DefaultKDFSpec otherwise.
//
// The middle case is what keeps a caller's parameter from being ignored. In
// FIPS mode the default is PBKDF2, and resolving to it would discard the Argon2
// cost the caller gave without a word; resolving to Argon2id instead reaches
// the FIPS refusal, which says what is wrong. Outside FIPS mode the default is
// Argon2id anyway, so nothing there changes.
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

// isFIPSCompliantKDF returns true if the KDF type is FIPS-approved.
//
// "pbkdf2-sha1" returns false: the Go Cryptographic Module permits PBKDF2 only
// with SHA-2 and SHA-3, and rejects SHA-1 outright under GODEBUG=fips140=only.
// See docs/fips/architecture.md.
//
// "pbkdf2" returns true because it derives with SHA-256 by default. Overriding
// that with KDFParams.Hash = crypto.SHA1 yields a KDF that is not
// FIPS-approved, and that createKDF refuses for any new keyslot.
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

// toKDFParams copies k's fields into a kdf.Params. Salt is carried as the
// stored base64 string, so this conversion cannot fail: only the derive path
// decodes it, and a cost-only caller (header.ValidateKDFCost, derivationWork) never
// touches it at all. Callers check k for nil themselves, matching each
// original function's own nil handling.
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

// deriveKeyEnclave derives a key from a passphrase under sys's FIPS mode and
// custody, and returns it held in protected memory. It is the keyslot
// derivation volumeSys.passphraseKDF runs.
//
// In FIPS 140-3 mode an Argon2 KDF is refused with ErrFIPSNotApproved before
// any derivation is attempted, so an externally supplied header cannot make a
// FIPS-mode process run a non-approved KDF.
//
// # The exposure this cannot close
//
// passphrase is the CALLER'S buffer. On every production path it is the
// window a secret.Borrow opened onto the caller's protected enclave
// (AddKeyslot, ChangeKeyslot, Unlock and the rest), valid only for that
// borrow; this function neither copies nor wipes it, because the enclave
// owns it. Where the bytes do leave protected memory is the derivation
// below: kdfDeriver hands the slice to crypto/pbkdf2.Key or argon2.IDKey,
// the stdlib KDF-input boundary internal/secret's package documentation
// lists, and what those functions copy into their own state is beyond this
// package's reach.
//
// The derived key spends the width of one return statement on the heap, and
// that is not closable in Go: crypto/pbkdf2.Key and argon2.IDKey allocate their result
// internally and return it, with no variant that writes into a provided buffer.
// enclave.NewMemoryEnclave takes ownership of that slice and wipes it -- on the
// failure path too -- so what survives is whatever copy the compiler or the
// collector made in between, plus the KDF's own scratch, which is unreachable
// from here. See ErrProtectedMemory for why a failure here is fatal.
func deriveKeyEnclave(ctx context.Context, passphrase []byte, k *header.KDF, keySize int, sys volumeSys) (*enclave.MemoryEnclave, error) {
	if k == nil {
		return nil, &errs.Error{Kind: errs.ErrInvalidHeader, Detail: "no KDF object"}
	}
	key, err := kdfDeriver(sys).Derive(ctx, passphrase, toKDFParams(k), keySize)
	return key, reclassifyUnsupportedKDF(err)
}

// reclassifyUnsupportedKDF folds errs.ErrUnsupportedHash and
// kdf.ErrUnsupportedKDF -- internal/kdf's and internal/errs' own sentinels
// for a hash algorithm or KDF type this package does not implement -- into
// the public ErrUnsupported (DESIGN.md §C.3), at every place a derivation
// crosses the package boundary. A FIPS-mode refusal (fips.ErrNotApproved)
// is a different condition -- the algorithm IS implemented -- and is
// deliberately left unreclassified.
func reclassifyUnsupportedKDF(err error) error {
	if err != nil && (errors.Is(err, errs.ErrUnsupportedHash) || errors.Is(err, kdf.ErrUnsupportedKDF)) {
		return &errs.Error{Kind: ErrUnsupported, Err: err}
	}
	return err
}

// passphraseKDF is the keyslot derivation: the passphrase-to-keyslot-key
// step unlockKeyslot runs for every keyslot it tries, and the one Format,
// AddKeyslot and ChangeKeyslot run for the keyslot they write. It derives
// under s's own FIPS mode and custody, so a Volume's derivation follows the
// Volume's sys rather than a package default.
//
// passphraseKDFOverride, when set, replaces it: a test proves that
// UnlockWithVolumeKey never reaches it (#79) by setting it on a Volume it
// constructs, rather than on the whole package's derivation. The receiver is
// a value, so a test that wraps the derivation (real := sys.passphraseKDF)
// captures sys as it was before the override and does not call itself.
//
// Only the keyslot derivation goes through it. The digest derivation in
// deriveKeySecret does not, because the injected-key path DOES run that one
// and a test forbidding this seam must not forbid it too.
func (s volumeSys) passphraseKDF(ctx context.Context, passphrase []byte, k *header.KDF, keySize int) (*enclave.MemoryEnclave, error) {
	if s.passphraseKDFOverride != nil {
		return s.passphraseKDFOverride(ctx, passphrase, k, keySize)
	}
	return deriveKeyEnclave(ctx, passphrase, k, keySize, s)
}

// deriveKeySecret derives a key from material ALREADY held in protected memory,
// borrowing the input in place rather than copying it out.
//
// It exists for the master-key digest, which derives from the master key rather
// than from a passphrase, and it keeps THIS package from making a copy.
//
// It does NOT keep the input inside the enclave for the derivation, which is
// what this comment used to claim. The borrow is handed to internal/kdf's
// DeriveFromSecret and from there to pbkdf2.Key, whose first act is string(password) -- an immutable
// Go string nobody can wipe -- followed by hmac.New taking another copy. So on
// this path the VOLUME MASTER KEY is materialized in unprotected, unwipeable
// memory once per derivation, on every unlock (verifyMasterKey, once per digest
// tried) and every format (createDigest).
//
// It is a validated-module boundary with no way around it that is permitted:
// crypto/pbkdf2 takes a string, and implementing PBKDF2 over crypto/hmac to
// avoid that is prohibited outright by the owner ruling of 2026-08-25, which
// rules that the protected-memory mandate yields here.
// Recorded as exposure 2 in internal/secret.
func deriveKeySecret(ctx context.Context, material *enclave.MemoryEnclave, k *header.KDF, keySize int, sys volumeSys) (*enclave.MemoryEnclave, error) {
	return deriveKeySecretIn(ctx, material, k, keySize, sys.fipsMode())
}

// deriveKeySecretIn is deriveKeySecret under an explicit FIPS mode, for a
// caller that is handed the operation's mode rather than its whole volumeSys
// (evaluateDigest). It is the mode the caller's sys reports, never a default.
func deriveKeySecretIn(ctx context.Context, material *enclave.MemoryEnclave, k *header.KDF, keySize int, mode fips.Mode) (*enclave.MemoryEnclave, error) {
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

// pbkdf2Hash resolves a LUKS2 PBKDF2 hash name to the algorithm, with NO FIPS
// 140-3 gate. It is the one table of names this package derives with:
// getPBKDF2HashFunc is it plus the gate, and the screen asks it alone when the
// question is whether a header is well formed rather than whether this process
// may run it -- see screenDigestStructure.
//
// Resolving to a crypto.Hash rather than a constructor means a length can be
// read (crypto.Hash.Size is a table lookup) without instantiating SHA-1 in a
// process where the module refuses it.
func pbkdf2Hash(hashAlgo string) (crypto.Hash, error) {
	return kdf.PBKDF2Hash(hashAlgo)
}

// legacyDigestLen is the ONE digest length this package accepts that the LUKS2
// format does not imply.
//
// A LUKS2 digest is the master key run through the digest KDF to the output
// length of the hash the digest declares: 20 bytes for sha1, 32 for sha256, 48
// for sha384, 64 for sha512. verifyMasterKey derives to the length actually
// stored in the header, and that length comes off an untrusted device, so the
// set of lengths it will derive to is a whitelist rather than a range --
// PBKDF2 will produce a gigabyte if asked, and a zero-length digest would make
// an all-zero constant-time comparison succeed against every key.
//
// The whitelist is {hashOutputLen(declared hash), legacyDigestLen,
// luks1DigestLen}. The second entry exists for containers written by earlier
// versions of this package, which stored 32 bytes under a "sha512" label; the
// third for LUKS1 containers converted by `cryptsetup convert`. Nothing else
// legitimately writes a digest whose length disagrees with its hash, so a
// 16-byte digest labeled sha512 is refused rather than merely tolerated.
const legacyDigestLen = 32

// luks1DigestLen is the length of every LUKS1 master-key digest
// (LUKS_DIGESTSIZE), whatever hash the container declares. `cryptsetup convert`
// carries it into the LUKS2 digest unchanged, so a converted sha256 or sha512
// volume holds a 20-byte digest under that label, and cryptsetup verifies it
// at the stored length.
const luks1DigestLen = 20

// hashOutputLen returns the output length in bytes of a LUKS2 hash algorithm
// name -- 32 for sha256, 64 for sha512, and so on.
//
// It resolves the name through getPBKDF2HashFunc rather than a second table, so
// the set of algorithms whose length is known here cannot drift from the set
// that can actually be derived with, and so an algorithm refused in FIPS mode
// is refused here too instead of reporting a length for a hash that will not
// run.
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

// PBKDF2 iteration calibration.
//
// The iteration count is MEASURED, never assumed. It is the entire cost an
// offline attacker pays per passphrase guess, and it is written into the LUKS2
// header at format time -- so a count that is too low is permanent for that
// volume and no later fix reaches it.
//
// What this package shipped until issue #52 timed 1000 iterations once and
// gated the extrapolation on elapsed.Milliseconds() > 0. A thousand iterations
// of PBKDF2 is a few hundred MICROseconds on any modern CPU, so that comparison
// was false, the extrapolation never ran, and every pbkdf2 keyslot got a
// hardcoded 100000 -- about 20-50ms of work against a documented 2000ms target.
//
// Two separate things were wrong, and fixing only the first would leave a
// calibration still wrong by a large factor:
//
//  1. RESOLUTION. elapsed.Milliseconds() truncates. Even on the path where the
//     comparison did pass, a measurement reported as 1ms is anywhere in
//     [0.5ms, 1.5ms), so the extrapolated count was off by up to 3x,
//     unpredictably, per machine. The measurement now uses the full
//     time.Duration.
//  2. PROBE SIZE. One fixed 1000-iteration probe cannot be right for both a
//     fast server and a slow embedded board. The probe now DOUBLES until it
//     clears a floor that dwarfs timer noise and scheduler jitter, and the
//     extrapolation runs from that measurement.
const (
	// pbkdf2ProbeStart is where the doubling begins -- the count the old
	// implementation used as its entire measurement.
	pbkdf2ProbeStart = kdf.ProbeStart

	// pbkdf2ProbeFloor is how long a probe must run before its measurement is
	// trusted.
	//
	// The floor is not about clock resolution: time.Now is a vDSO read with
	// nanosecond granularity. It is about SCHEDULING. One preemption costs a
	// probe on the order of a millisecond, so a 50ms probe absorbs one at a few
	// percent error while a 1ms probe would be wrong by half. Calibration
	// therefore costs at most two floors' worth of work -- roughly 100ms, once
	// per format -- against a default budget of 2000ms of derivation.
	pbkdf2ProbeFloor = kdf.ProbeFloor

	// pbkdf2ProbeCeiling bounds the doubling so that a clock which never
	// advances FAILS instead of looping forever. Reaching it means over sixteen
	// million iterations completed inside 50ms, roughly a hundred times faster
	// than current hardware: the clock is broken, not the CPU fast.
	pbkdf2ProbeCeiling = kdf.ProbeCeiling

	// maxPBKDF2IterTimeMs bounds the requested budget. Ten minutes is already
	// far past any iteration time anyone means, and the bound is what keeps
	// time.Duration arithmetic on the request from overflowing into a negative
	// duration -- which would silently return the floor instead of the very
	// large count that was asked for.
	maxPBKDF2IterTimeMs = kdf.MaxPBKDF2IterTimeMs

	// minPBKDF2Iterations is the absolute floor for a keyslot this package
	// WRITES: cryptsetup's own minimum, and the smallest count any LUKS
	// implementation should be handed.
	//
	// It is deliberately not header.MinKDFIterations (internal/header/keyslot.go), which is 1
	// and governs what this package will READ out of a header someone else
	// wrote. Being liberal about a header we did not create and strict about one
	// we are creating are different decisions.
	minPBKDF2Iterations = kdf.MinPBKDF2Iterations

	// pbkdf2ReferenceTargetMs is the budget the recommended minima below are
	// stated against, and is this library's own default (see createPBKDF2KDF).
	pbkdf2ReferenceTargetMs = kdf.PBKDF2ReferenceTargetMs
)

// pbkdf2RecommendedIterations is OWASP's recommended PBKDF2 iteration count per
// hash for password-derived keys, at pbkdf2ReferenceTargetMs.
//
// It is a SECOND floor, and it exists because calibration alone has a blind
// spot. A calibrated count answers "how much work fits in 2 seconds of THIS
// machine's time" -- a statement about the DEFENDER's hardware. The attacker's
// hardware is unrelated and is not slow. Formatting on a low-end board
// therefore yields a header that is weak everywhere, and the header long
// outlives the board.
//
// The floor is scaled by the requested budget rather than applied flat, so a
// caller that deliberately asks for a cheap keyslot still gets one (bounded
// below by minPBKDF2Iterations), while the DEFAULT path cannot fall below the
// recommendation whatever it is formatted on. On current hardware the
// calibrated count at 2000ms is several million and this floor never binds; it
// binds on hardware about ten times slower, which is exactly where it should.
var pbkdf2RecommendedIterations = kdf.PBKDF2RecommendedIterations

// benchmarkPBKDF2 returns the number of PBKDF2 iterations that costs
// approximately targetMs milliseconds on this machine, for the given hash and
// derived-key size.
//
// It NEVER returns a default. A calibration that cannot be performed returns a
// *KDFCalibrationError (matching ErrKDFCalibration) and no count; the block
// comment above says why a plausible-looking constant is the wrong answer here.
//
// The result is clamped into [floor, header.MaxKDFIterations]. The floor is the larger
// of minPBKDF2Iterations and the budget-scaled recommendation for the hash; the
// ceiling is the same one header.ValidateKDFCost enforces when the header is read back,
// so a count this function returns can never produce a header this package
// would go on to reject.
//
// Supported hash algorithms: sha256, sha384, sha512 and, outside FIPS 140-3
// mode, sha1. fipsMode is the caller's sys's, never a default.
func benchmarkPBKDF2(fipsMode fips.Mode, hashAlgo string, keySize, targetMs int) (int, error) {
	return kdf.Deriver{Custody: custody, FIPS: fipsMode}.Calibrate(context.Background(), hashAlgo, keySize, targetMs)
}

// pbkdf2Timer runs one PBKDF2 derivation of the given iteration count and
// output size and reports how long it took.
//
// It is a parameter of the calibration so the ARITHMETIC can be tested against
// a known rate: with a real clock the measured rate depends on whatever else
// the machine is doing, and a test asserting on it fails under host load for a
// reason that has nothing to do with the code (#233).
type pbkdf2Timer = kdf.Timer

// wallClockPBKDF2 is the timer the package calibrates with: the real
// derivation, timed on the wall clock.
//
// Neither the passphrase nor the salt is key material or becomes any. PBKDF2's
// cost depends on the iteration count, the hash and the output length, not on
// their contents, and nothing derived here is returned, stored, or compared
// against anything.
func wallClockPBKDF2(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	return kdf.WallClockPBKDF2(hashFunc, iterations, keySize)
}

// calibratePBKDF2 is the calibration itself. The probe bounds and the timer
// are parameters so that the fail-closed path and the extrapolation can be
// exercised by a test without needing a broken or an idle clock;
// benchmarkPBKDF2 supplies the real ones.
func calibratePBKDF2(hashFunc func() hash.Hash, hashAlgo string, keySize, targetMs int, probeFloor time.Duration, probeCeiling int, timer pbkdf2Timer) (int, error) {
	return kdf.CalibratePBKDF2(context.Background(), hashFunc, hashAlgo, keySize, targetMs, probeFloor, probeCeiling, timer)
}

// scalePBKDF2Iterations extrapolates a timed probe to the requested budget and
// clamps the result into the range this package is willing to write.
func scalePBKDF2Iterations(hashAlgo string, probe int, elapsed time.Duration, targetMs int) int {
	return kdf.ScalePBKDF2Iterations(hashAlgo, probe, elapsed, targetMs)
}

// pbkdf2IterationFloor returns the smallest iteration count this package will
// write for a hash and a budget: minPBKDF2Iterations, or the budget-scaled
// OWASP recommendation when that is larger.
//
// It returns a float64 because its only caller compares it against an
// unrounded extrapolation, and rounding twice would be the sort of small
// discrepancy that makes a floor look off by one for no reason.
func pbkdf2IterationFloor(hashAlgo string, targetMs int) float64 {
	return kdf.PBKDF2IterationFloor(hashAlgo, targetMs)
}

// keyslotCostPolicy says which PBKDF2 floor applies to a keyslot being created,
// and it exists because ONE FLOOR WAS SERVING TWO POPULATIONS.
//
// # THE DISTINCTION
//
// A PBKDF2 iteration count buys exactly one thing: it multiplies the cost of
// each guess in an offline SEARCH. That makes it decisive for a credential
// whose entropy is unknown -- a human-chosen passphrase is drawn from a space
// an attacker can enumerate, and pbkdf2RecommendedIterations is the floor that
// keeps enumeration expensive. It stays, unchanged, for everything a caller
// hands in.
//
// It makes no difference at all for a credential THIS LIBRARY GENERATED. A
// recovery key or an enrolled provider key is 256 bits straight from
// custody.Random; there is no candidate list, so there is no search, so there is
// nothing for the multiplier to multiply. Stretching it defends against no
// attack that exists, while the floor makes systemd's own parameters
// unwritable: systemd enrolls pbkdf2/sha512/1000, and the sha512 floor is
// 210000, so this package could not reproduce a systemd-enrolled header even
// when told exactly what to write.
//
// # WHY THIS SHAPE RECURS, AND WHERE IT IS INVALID
//
// The same argument -- "the input is a full-entropy CSPRNG secret, so the
// iteration count defends nothing" -- was made about the master-key DIGEST
// earlier in this package's history. It was ACTED ON AND REVERTED, because the
// premise about cryptsetup's behavior was measured with a flag that wrote the
// answer into the measurement (see DigestIterationTargetMs, security.go).
//
// The reasoning is sound HERE and was sound there; what failed there was the
// evidence, not the logic. The lesson is not to distrust the argument but to
// check what is actually being enumerated: here it is nothing, because the
// credential is 256 CSPRNG bits this package drew itself. The same number under
// a human passphrase would be catastrophic, and that is precisely why the
// exemption is not reachable from outside this package.
//
// # WHY IT IS A TYPE AND NOT A BOOL ON AN OPTIONS STRUCT
//
// The exemption must be reachable only BECAUSE the library produced the
// credential, never because a caller asked for it. A public Force or SkipFloor
// field is a floor that can be argued around, which is not a floor. So this
// type is unexported, its zero value is the STRICT policy, and no exported API
// carries it: a caller holding a weak passphrase has no route to the exempt
// path even by mistake.
type keyslotCostPolicy int

const (
	// callerSuppliedCredential is the strict policy and the ZERO VALUE, so
	// anything that forgets to choose gets the floor rather than the exemption.
	callerSuppliedCredential keyslotCostPolicy = iota

	// libraryGeneratedCredential relaxes the hash-dependent floor to
	// minPBKDF2Iterations for a credential this package drew from custody.Random.
	// Only a caller that generated the bytes it is enrolling may select it.
	// AddRecoveryKey is that caller and currently the only one; enrolling an
	// external provider's secret has the same shape and is expected to join it,
	// but no such path exists in this package yet.
	libraryGeneratedCredential
)

// pbkdf2FloorFor returns the smallest iteration count a policy permits.
//
// The exempt path KEEPS A FLOOR; it does not lose one. minPBKDF2Iterations is
// LUKS2's own minimum and is exactly what systemd writes, so honoring it costs
// nothing and still refuses zero, negative and absurd values.
func pbkdf2FloorFor(hashAlgo string, policy keyslotCostPolicy) int {
	if policy == libraryGeneratedCredential {
		return minPBKDF2Iterations
	}
	// Rounded UP. pbkdf2IterationFloor returns a float because its other caller
	// compares it against an unrounded extrapolation; truncating here would
	// admit a count one iteration below the floor.
	return int(math.Ceil(pbkdf2IterationFloor(hashAlgo, pbkdf2ReferenceTargetMs)))
}

// calibratedCountFloor (volumeSys.calibratedCountFloor) is the floor a
// CALIBRATED iteration count is raised to for a new keyslot (#249, A8):
// pbkdf2FloorFor, under the keyslot's policy.
// forcedPBKDF2Iterations validates an explicit PBKDF2 iteration count -- the
// one a caller supplies through KDFParams.Iterations -- and returns it unchanged if it is one this
// package is willing to write.
//
// WHY AN EXPLICIT COUNT EXISTS AT ALL. Calibration answers "how much work fits
// in N milliseconds of THIS machine's time", so it produces a different number
// on every host and on the same host under different load. That is the right
// default and the wrong thing for reproducible provisioning, where two
// containers built from one specification must be identical, and for a
// conformance test that has to compare bytes with cryptsetup. It is the
// analog of cryptsetup's --pbkdf-force-iterations.
//
// WHY IT STILL RESPECTS THE FLOOR. cryptsetup's --pbkdf-force-iterations
// bypasses its own minimum. This package deliberately does not copy that: a
// floor any caller can argue around is not a floor, and unlike a slow benchmark
// the mistake is permanent -- nothing can strengthen a keyslot that is already
// on disk. The bound applied is exactly the one calibration would have applied
// at the reference budget, so an explicit count and a calibrated one are held
// to the same standard and the option cannot be used to obtain a keyslot
// benchmarkPBKDF2 would have refused to return.
//
// The floor is hash-dependent (pbkdf2IterationFloor): 600000 for sha256,
// 210000 for sha384 and sha512, and minPBKDF2Iterations for a hash with no
// published recommendation -- unless the policy says this package generated the
// credential itself, in which case see keyslotCostPolicy for what changes and
// why.
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

// createKDF creates a KDF structure based on options and the keyslot's cost
// policy. Supported KDF types:
//   - "pbkdf2" - PBKDF2 with hash from HashAlgo option (default: sha256) [FIPS-approved]
//   - "pbkdf2-sha1" - REFUSED with ErrInvalidArgument: SHA-1 is never written (#239)
//   - "pbkdf2-sha256" - PBKDF2 with SHA-256 [FIPS-approved, recommended]
//   - "pbkdf2-sha384" - PBKDF2 with SHA-384 [FIPS-approved]
//   - "pbkdf2-sha512" - PBKDF2 with SHA-512 [FIPS-approved]
//   - "argon2i" - Argon2i [NOT FIPS-approved, refused in FIPS mode]
//   - "argon2id" - Argon2id [NOT FIPS-approved, refused in FIPS mode]
//
// An empty KDFType resolves through resolveKDFType: to DefaultKDFSpec --
// "pbkdf2-sha512" in FIPS 140-3 mode, "argon2id" otherwise -- unless an Argon2
// cost is set, which selects "argon2id".
func createKDF(opts formatOptionsForTest, keySize int, policy keyslotCostPolicy, fipsMode func() fips.Mode, calibratedCountFloor func(string, keyslotCostPolicy) int, cryptoRand io.Reader) (*header.KDF, error) {
	kdfType := resolveKDFTypeFor(normalizeKDFType(opts.KDFType), formatArgon2CostGiven(opts), fipsMode())

	// No keyslot is created with SHA-1, before any other choice is judged.
	if err := refuseSHA1ForCreation(kdfType, opts.HashAlgo); err != nil {
		return nil, err
	}

	// Checked after the default is resolved. The default itself is approved in
	// FIPS mode (DefaultKDFSpec), so what this refuses there is an Argon2 KDF
	// the caller asked for -- by name, or by supplying an Argon2 cost; see
	// docs/fips/architecture.md.
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

// refuseSHA1ForCreation refuses a KDF type or hash that would WRITE SHA-1
// into a new keyslot or digest: the pbkdf2-sha1 alias, or a "sha1" hash for
// any KDF -- a format's hash is also its digest's and its anti-forensic
// split's, and an AddKey hash names the new keyslot's. Reading is unaffected:
// existing PBKDF2-SHA1 keyslots and digests open outside FIPS mode (#239).
func refuseSHA1ForCreation(kdfType, hashAlgo string) error {
	if normalizeKDFType(kdfType) == kdfTypePBKDF2SHA1 {
		return &errs.Error{Kind: ErrInvalidArgument, Err: ErrUnsupported,
			Detail: "pbkdf2-sha1: new keyslots use pbkdf2 with sha256, sha384 or sha512, or argon2"}
	}
	if strings.EqualFold(strings.TrimSpace(hashAlgo), "sha1") {
		return &errs.Error{Kind: ErrInvalidArgument, Err: ErrUnsupported,
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

	// AN EXPLICIT COUNT TAKES PRECEDENCE OVER THE TIME BUDGET, and the two are
	// not combined: PBKDFIterations names the number to write, PBKDFIterTime
	// names a budget to calibrate against, and there is nothing for calibration
	// to contribute once the number is given. A caller that sets both gets the
	// explicit one, which is what "skips calibration when non-zero" means.
	//
	// Ignoring a caller's parameter is normally how a silent defect starts --
	// see addKeyFormatOptions on PBKDFIterTime -- and it is safe here for one
	// reason: the explicit count is BOUNDED by forcedPBKDF2Iterations, so the
	// path that skips calibration cannot skip the floor calibration applies.
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
		// A CALIBRATED count is held to the same floor an explicit one is
		// (#249, A8). benchmarkPBKDF2 scales the OWASP floor by the budget, so
		// PBKDFIterTime: 1 calibrated a caller's passphrase down to ~1000
		// iterations -- the exact outcome forcedPBKDF2Iterations refuses for
		// PBKDFIterations: 1000 on the same path. The budget is a way to ask
		// for MORE than the floor on fast hardware, never a way under it.
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

	// WHAT IS WRITTEN MUST BE WHAT THE READER ACCEPTS (#249, A5). The KDF is
	// held to header.ValidateKDFCost -- the very check screenKeyslot applies when the
	// header is read back -- so no creation path, whether the cost came from a
	// caller, a default or a container ChangeKey inherited it from, can write a
	// keyslot this package then refuses to open. Consumed rather than
	// restated, for the reason the screen gives.
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

// cryptoHashNames maps the crypto.Hash values this package's KDF paths
// actually produce or consume to and from the lowercase name LUKS2's JSON
// carries, so KDFParams.Hash and the internal addKeyOptionsForTest.Hash
// string can be converted without a dependency on every crypto.Hash the
// standard library knows about.
var cryptoHashNames = []struct {
	hash crypto.Hash
	name string
}{
	{crypto.SHA1, "sha1"},
	{crypto.SHA256, "sha256"},
	{crypto.SHA384, "sha384"},
	{crypto.SHA512, "sha512"},
}

// cryptoHashFromName is cryptoHashNames' lookup by LUKS2's on-disk spelling.
// The zero crypto.Hash is returned, deliberately, for a name this table does
// not carry: the caller sites (addKeyOptionsFromKeyslotParams) treat that the
// same as "unset", which is what addKeyOptionsForTest.Hash's own empty
// string means.
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

// kdfParamsFromHeaderKDF converts a keyslot's on-disk KDF into KDFParams, for
// KeyslotInfo's KDF field (header_v2.go's listKeyslotsFrom and provider.go's
// Enroll). It is lossy in exactly the way KeyslotInfo's old PBKDF2Iterations/
// Argon2* fields already were not: a hash name this package's own KDF paths
// never write (cryptoHashFromName's empty-table case) reports the zero
// crypto.Hash rather than refusing the whole listing, because listing is an
// inspection operation that must report what is there (see
// listKeyslotsFrom's own reasoning for kdf being optional).
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

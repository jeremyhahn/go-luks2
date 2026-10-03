// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto"
	"crypto/fips140"
	"crypto/pbkdf2"
	// The hashes pbkdf2Hash resolves to, linked in so crypto.Hash.New can
	// construct them.
	_ "crypto/sha1" // #nosec G505 - legacy LUKS interop only; refused in FIPS mode (docs/FIPS.md)
	_ "crypto/sha256"
	_ "crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"math"
	"strings"
	"time"

	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/crypto/argon2"
)

// FIPS-compatible KDF type constants
// These provide convenience aliases for PBKDF2 with specific hash algorithms
const (
	// KDFTypePBKDF2 is the base PBKDF2 KDF type (uses HashAlgo option for hash selection)
	KDFTypePBKDF2 = "pbkdf2"

	// KDFTypePBKDF2SHA1 names PBKDF2 with SHA-1. It is NOT a type a keyslot
	// can be created with: every creation path refuses it with
	// ErrSHA1NotWritten (#239, a breaking change). Existing PBKDF2-SHA1
	// keyslots -- on disk, type "pbkdf2" with hash "sha1", as cryptsetup and
	// converted LUKS1 volumes carry -- still open outside FIPS 140-3 mode.
	// See docs/FIPS.md.
	KDFTypePBKDF2SHA1 = "pbkdf2-sha1"

	// KDFTypePBKDF2SHA256 is PBKDF2 with SHA-256 (FIPS-approved, recommended)
	KDFTypePBKDF2SHA256 = "pbkdf2-sha256"

	// KDFTypePBKDF2SHA384 is PBKDF2 with SHA-384 (FIPS-approved)
	KDFTypePBKDF2SHA384 = "pbkdf2-sha384"

	// KDFTypePBKDF2SHA512 is PBKDF2 with SHA-512 (FIPS-approved)
	KDFTypePBKDF2SHA512 = "pbkdf2-sha512"

	// KDFTypeArgon2i is the Argon2i KDF type. It is NOT FIPS-approved and is
	// refused while the process runs in FIPS 140-3 mode. See docs/FIPS.md.
	KDFTypeArgon2i = "argon2i"

	// KDFTypeArgon2id is the Argon2id KDF type and the library default outside
	// FIPS 140-3 mode. It is NOT FIPS-approved and is refused while the process
	// runs in FIPS 140-3 mode. See DefaultKDFType and docs/FIPS.md.
	KDFTypeArgon2id = "argon2id"
)

// DefaultKDFType returns the KDF a keyslot is created with when the caller
// names none, and it depends on the mode the process runs in, as cryptsetup's
// default does (#237):
//
//   - In FIPS 140-3 mode it is KDFTypePBKDF2SHA512. The iteration count is
//     calibrated to the time budget (PBKDFIterTime, 2000 ms by default) and
//     never falls below the policy floor for SHA-512, so the keyslot gets
//     whichever of the two is greater.
//   - Otherwise it is KDFTypeArgon2id, as it always has been.
//
// Before #237 the default was Argon2id in both modes, so in FIPS mode every
// caller that named no KDF -- the CLI's recovery add among them -- was refused
// with ErrFIPSNotApproved and a FIPS deployment could create no keyslot
// without choosing one explicitly.
//
// A caller that names no KDF but supplies an Argon2 cost has chosen Argon2 by
// its parameters, and gets KDFTypeArgon2id in either mode rather than having
// the cost silently dropped; see resolveKDFType.
func DefaultKDFType() string {
	return defaultKDFTypeFor(fipsMode())
}

// defaultKDFTypeFor is DefaultKDFType for a given mode. The mode is a parameter
// so both answers are tested in every run: a process cannot leave FIPS mode, or
// enter it, once it has started. DefaultKDFType asks fipsMode, the seam every
// FIPS policy decision in this package goes through.
func defaultKDFTypeFor(fipsMode bool) string {
	if fipsMode {
		return KDFTypePBKDF2SHA512
	}
	return KDFTypeArgon2id
}

// resolveKDFType returns the KDF type a keyslot is created with: kdfType when
// the caller named one, KDFTypeArgon2id when the caller named none but supplied
// an Argon2 cost, and DefaultKDFType otherwise.
//
// The middle case is what keeps a caller's parameter from being ignored. In
// FIPS mode the default is PBKDF2, and resolving to it would discard the Argon2
// cost the caller gave without a word; resolving to Argon2id instead reaches
// the FIPS refusal, which says what is wrong. Outside FIPS mode the default is
// Argon2id anyway, so nothing there changes.
func resolveKDFType(kdfType string, argon2CostGiven bool) string {
	return resolveKDFTypeFor(kdfType, argon2CostGiven, fipsMode())
}

// resolveKDFTypeFor is resolveKDFType for a given mode; see defaultKDFTypeFor.
func resolveKDFTypeFor(kdfType string, argon2CostGiven, fipsMode bool) string {
	if kdfType != "" {
		return kdfType
	}
	if argon2CostGiven {
		return KDFTypeArgon2id
	}
	return defaultKDFTypeFor(fipsMode)
}

// formatArgon2CostGiven reports whether a FormatOptions carries any Argon2
// cost, including a negative one -- != 0 for the reason callerChoseArgon2Cost
// gives: a negative is still a deliberate choice, and must reach the refusal.
func formatArgon2CostGiven(opts FormatOptions) bool {
	return opts.Argon2Time != 0 || opts.Argon2Memory != 0 || opts.Argon2Parallel != 0
}

// IsFIPSCompliantKDF returns true if the KDF type is FIPS-approved.
//
// "pbkdf2-sha1" returns false: the Go Cryptographic Module permits PBKDF2 only
// with SHA-2 and SHA-3, and rejects SHA-1 outright under GODEBUG=fips140=only.
// See docs/FIPS.md.
//
// "pbkdf2" returns true because it derives with SHA-256 by default. Overriding
// that with FormatOptions.HashAlgo = "sha1" yields a KDF that is not
// FIPS-approved and that CreateKDF refuses in FIPS mode.
func IsFIPSCompliantKDF(kdfType string) bool {
	switch normalizeKDFType(kdfType) {
	case KDFTypePBKDF2, KDFTypePBKDF2SHA256, KDFTypePBKDF2SHA384, KDFTypePBKDF2SHA512:
		return true
	default:
		return false
	}
}

// normalizeKDFType normalizes a KDF type string to lowercase
func normalizeKDFType(kdfType string) string {
	return strings.ToLower(strings.TrimSpace(kdfType))
}

// fipsMode reports whether this process runs in FIPS 140-3 mode. It is
// crypto/fips140.Enabled, and every FIPS policy decision in this package --
// the KDF gates, the SHA-1 gate, MigrateToFIPS's refusal, and the
// classification of a refusal as an import rather than damage -- asks it here.
//
// It is a seam because FIPS mode is fixed at process start: without it, the
// policy branches run only in a process started with GODEBUG=fips140=only, so
// the ordinary unit run would exercise none of them and a regression there
// would wait for the nightly FIPS job. This package's tests substitute it to
// run those branches in-process; what the Go Cryptographic Module itself
// enforces in strict mode is still proved by the child-process and nightly
// tests. Unexported, no setter, substituted only by this package's tests.
var fipsMode = fips140.Enabled

// requireFIPSApprovedKDF returns an error when kdfType is not FIPS-approved and
// the process is running in FIPS 140-3 mode.
//
// Argon2 is implemented in pure Go by golang.org/x/crypto (BLAKE2b) and never
// enters the Go Cryptographic Module, so GODEBUG=fips140=only cannot reject it.
// Without this check a FIPS-mode process would derive volume keys with a
// non-approved KDF while the FIPS gate reported green. See docs/FIPS.md.
//
// PBKDF2 hash selection is enforced separately, in getPBKDF2HashFunc.
func requireFIPSApprovedKDF(kdfType string) error {
	if !fipsMode() {
		return nil
	}

	normalized := normalizeKDFType(kdfType)
	switch normalized {
	case KDFTypeArgon2i, KDFTypeArgon2id:
		return &CryptoError{Op: normalized, Err: ErrFIPSNotApproved}
	default:
		return nil
	}
}

// DeriveKeyEnclave derives a key from a passphrase and returns it held in
// protected memory. This is the derivation every path inside this package uses.
//
// In FIPS 140-3 mode an Argon2 KDF is refused with ErrFIPSNotApproved before
// any derivation is attempted, so an externally supplied header cannot make a
// FIPS-mode process run a non-approved KDF.
//
// # The exposure this cannot close
//
// passphrase is the CALLER'S memory, ordinary and unlocked. This function
// borrows it for the derivation and never wipes it: wiping a buffer this
// package does not own would corrupt the caller. Bringing it into protected
// memory at this depth would not help either -- the bytes were already on the
// heap before the call.
//
// The derived key spends the width of one return statement on the heap, and
// that is not closable in Go: crypto/pbkdf2.Key and argon2.IDKey allocate their result
// internally and return it, with no variant that writes into a provided buffer.
// enclave.NewMemoryEnclave takes ownership of that slice and wipes it -- on the
// failure path too -- so what survives is whatever copy the compiler or the
// collector made in between, plus the KDF's own scratch, which is unreachable
// from here. See ProtectedMemoryError for why a failure here is fatal.
func DeriveKeyEnclave(passphrase []byte, kdf *KDF, keySize int) (*enclave.MemoryEnclave, error) {
	key, err := deriveKeyPlain(passphrase, kdf, keySize)
	if err != nil {
		return nil, err
	}

	// adoptSecret wipes key on every path, so there is no clearBytes here and
	// no path on which the derived key outlives this statement in the clear.
	return adoptSecret("derived key", key)
}

// passphraseKDF is the keyslot derivation: the passphrase-to-keyslot-key step
// unlockKeyslot runs for every keyslot it tries. It is DeriveKeyEnclave, and it
// is reached through this variable for one reason -- so a test can prove that
// UnlockWithVolumeKey never reaches it (#79). A path that must not run a KDF is
// a claim nothing checks unless the KDF can be observed.
//
// Only the keyslot derivation goes through it. The digest derivation in
// deriveKeySecret calls DeriveKeyEnclave directly, because the injected-key path
// DOES run that one and a test forbidding this seam must not forbid it too.
var passphraseKDF = DeriveKeyEnclave

// deriveKeySecret derives a key from material ALREADY held in protected memory,
// borrowing the input in place rather than copying it out.
//
// It exists for the master-key digest, which derives from the master key rather
// than from a passphrase, and it keeps THIS package from making a copy.
//
// It does NOT keep the input inside the enclave for the derivation, which is
// what this comment used to claim. The borrow is handed to DeriveKeyEnclave and
// from there to pbkdf2.Key, whose first act is string(password) -- an immutable
// Go string nobody can wipe -- followed by hmac.New taking another copy. So on
// this path the VOLUME MASTER KEY is materialized in unprotected, unwipeable
// memory once per derivation, on every unlock (verifyMasterKey, once per digest
// tried) and every format (createDigest).
//
// It is a validated-module boundary with no way around it that is permitted:
// crypto/pbkdf2 takes a string, and implementing PBKDF2 over crypto/hmac to
// avoid that is prohibited outright by the owner ruling of 2026-08-25, which
// rules that the protected-memory mandate yields here.
// Recorded as exposure 2 in enclave.go.
func deriveKeySecret(secret *enclave.MemoryEnclave, kdf *KDF, keySize int) (*enclave.MemoryEnclave, error) {
	var derived *enclave.MemoryEnclave
	err := borrowSecret("derive from secret", secret, func(b []byte) error {
		var err error
		derived, err = DeriveKeyEnclave(b, kdf, keySize)
		return err
	})
	if err != nil {
		return nil, err
	}
	return derived, nil
}

// deriveKeyPlain is the derivation itself. It is the ONE place in this package
// that produces key material outside an enclave, and it exists because the
// stdlib KDFs give no other shape: every caller adopts the result into an
// enclave immediately, via DeriveKeyEnclave.
func deriveKeyPlain(passphrase []byte, kdf *KDF, keySize int) ([]byte, error) {
	if kdf == nil {
		return nil, &CryptoError{Op: "derive", Err: fmt.Errorf("no KDF was given")}
	}

	// The requested length is checked ONCE, here, ahead of every KDF rather
	// than inside each of them. It is a PANIC GUARD and nothing more:
	// crypto/pbkdf2 refuses a non-positive keyLength with an error that
	// x/crypto used to turn into a panic, and argon2 dereferences nil on one.
	// No caller of any kind has a use for a zero-length key.
	//
	// It deliberately carries no UPPER bound any more. An earlier version
	// capped it at MaxKeyslotKeySize, which looked like defense in depth and was
	// misplaced for the same reason validateKDFCost is not enforced here: this
	// function serves two TRUST DOMAINS. Format, AddKey and ChangeKey derive
	// from parameters the CALLER chose, and an untrusted-input ceiling applied
	// to all of them rejects a caller's own deliberate choice with an error
	// shaped like a malformed header. What a HEADER may declare is bounded
	// where headers are read -- validateKeyslot for the key size,
	// validateKDFCost for the work factors.
	if keySize <= 0 {
		return nil, &CryptoError{
			Op:  "derive",
			Err: fmt.Errorf("requested key length must be positive"),
		}
	}

	if err := requireFIPSApprovedKDF(kdf.Type); err != nil {
		return nil, err
	}

	salt, err := decodeBase64(kdf.Salt)
	if err != nil {
		return nil, fmt.Errorf("invalid salt: %w", err)
	}

	switch kdf.Type {
	case "pbkdf2":
		return derivePBKDF2(passphrase, salt, kdf, keySize)
	case "argon2i":
		return deriveArgon2i(passphrase, salt, kdf, keySize)
	case "argon2id":
		return deriveArgon2id(passphrase, salt, kdf, keySize)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedKDF, kdf.Type)
	}
}

// derivePBKDF2 derives a key using PBKDF2
// It calls the STANDARD LIBRARY's crypto/pbkdf2, not
// golang.org/x/crypto/pbkdf2.
//
// The x/crypto wrapper is a two-line shim that calls the same validated
// implementation and then does panic(err) on any error it returns -- so a
// keyLength the module refuses became a process crash reached through a
// function whose signature promises an error. That wrapper was the entire
// mechanism behind the key_size panics; the guard in validateKeyslot keeps a
// header from reaching it, and calling the erroring API keeps the next caller
// from having to.
//
// It is also the API the owner ruling names: "use crypto/pbkdf2; accept the
// bounded transient copy; document it" -- the resolution of this exact case
// under the rule against hand-rolled cryptography (owner ruling 2026-08-25).
// The reasoning is spelled out in enclave.go and in the README's Protected
// Memory section, which are in this repository and travel with it.
func derivePBKDF2(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	if kdf.Iterations == nil {
		return nil, &CryptoError{Op: "pbkdf2", Err: fmt.Errorf("PBKDF2 requires iterations")}
	}

	hashFunc, err := getPBKDF2HashFunc(kdf.Hash)
	if err != nil {
		return nil, err
	}

	// string(passphrase) is the unwipeable copy exposure 2 in enclave.go
	// records. It is made HERE now rather than inside the x/crypto wrapper,
	// which changes who makes it and not whether it is made: crypto/pbkdf2
	// takes a string, and the module copies it again into the HMAC state
	// regardless. The ruling above is what settles that.
	key, err := pbkdf2.Key(hashFunc, string(passphrase), salt, *kdf.Iterations, keySize)
	if err != nil {
		return nil, &CryptoError{Op: "pbkdf2", Err: err}
	}
	return key, nil
}

// getPBKDF2HashFunc returns the hash function for PBKDF2 key derivation
// Supported: sha256, sha384, sha512 (FIPS-approved) and sha1 (legacy LUKS
// headers only, refused in FIPS 140-3 mode)
func getPBKDF2HashFunc(hashAlgo string) (func() hash.Hash, error) {
	h, err := pbkdf2Hash(hashAlgo)
	if err != nil {
		return nil, err
	}
	// PBKDF2-HMAC-SHA1 is needed to open LUKS headers written by cryptsetup
	// releases that defaulted to SHA-1, but the Go Cryptographic Module
	// permits PBKDF2 only with SHA-2/SHA-3 and panics on SHA-1 under
	// GODEBUG=fips140=only. Refuse it here so a FIPS build reports a typed
	// error instead of crashing, and so the call never reaches the module.
	// See docs/FIPS.md.
	if h == crypto.SHA1 && fipsMode() {
		return nil, &CryptoError{Op: "pbkdf2-hmac-sha1", Err: ErrFIPSNotApproved}
	}
	return h.New, nil
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
	switch strings.ToLower(hashAlgo) {
	case "sha1":
		return crypto.SHA1, nil
	case "sha256":
		return crypto.SHA256, nil
	case "sha384":
		return crypto.SHA384, nil
	case "sha512":
		return crypto.SHA512, nil
	default:
		return 0, &detailError{Kind: ErrUnsupportedHash, Detail: hashAlgo + " (supported: sha1, sha256, sha384, sha512)"}
	}
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
// The whitelist is {hashOutputLen(declared hash), legacyDigestLen}. The second
// entry exists for exactly one artifact: containers written by earlier versions
// of this package, which stored 32 bytes under a "sha512" label. Nothing else
// legitimately writes a digest whose length disagrees with its hash, so a
// 16-byte digest labeled sha512 is refused rather than merely tolerated.
const legacyDigestLen = 32

// hashOutputLen returns the output length in bytes of a LUKS2 hash algorithm
// name -- 32 for sha256, 64 for sha512, and so on.
//
// It resolves the name through getPBKDF2HashFunc rather than a second table, so
// the set of algorithms whose length is known here cannot drift from the set
// that can actually be derived with, and so an algorithm refused in FIPS mode
// is refused here too instead of reporting a length for a hash that will not
// run.
func hashOutputLen(hashAlgo string) (int, error) {
	hashFunc, err := getPBKDF2HashFunc(hashAlgo)
	if err != nil {
		return 0, err
	}
	return hashFunc().Size(), nil
}

// u32 converts a cost or size to the uint32 the argon2 interface takes,
// refusing what that type cannot represent.
//
// REPRESENTATION ONLY. A policy ceiling on a caller's deliberate choice is
// deriveKeyPlain's business, and it declines them for a reason that is sound: an
// untrusted-input bound applied to a caller's own decision rejects it with an
// error shaped like a malformed header. That argument is about what is WISE.
// This is about what the call can HOLD -- above MaxUint32 the conversion does
// not reject a value, it changes one.
//
// # Why a helper rather than a checked conversion at each site
//
// Four conversions shared ONE BLANKET G115 SUPPRESSION. Round one justified
// one of them;
// round two justified all four; round three found that the fourth
// justification was FALSE -- keySize was said to exhaust memory before it could
// truncate, and it does not. MEASURED: a request for 4294967300 bytes returns
// a FOUR BYTE KEY and no error, because the truncation happens before argon2
// allocates anything.
//
// Each round produced a better justification for a suppression that should not
// exist. The helper makes the unchecked conversion unwritable instead: the
// compiler forces every call site to handle the error, so the enumeration is
// ENFORCED rather than described, and there is no suppression left to get right.
//
// The directive is not written out anywhere in this comment on purpose: gosec
// acts on that text wherever it appears in one, so quoting it here would
// suppress the very findings this helper exists to surface. Same defect as a
// guard that flags a pattern quoted in its own documentation.
func u32(op, field string, v int) (uint32, error) {
	if v < 0 {
		return 0, &CryptoError{Op: op, Err: fmt.Errorf(
			"%s must not be negative (got %d); the conversion below would turn it into a very large one",
			field, v)}
	}
	if uint64(v) > math.MaxUint32 {
		return 0, &CryptoError{Op: op, Err: fmt.Errorf(
			"%s %d exceeds what the argon2 interface can represent (uint32); the conversion would "+
				"silently truncate it rather than fail", field, v)}
	}
	return uint32(v), nil
}

// deriveArgon2 is the ONE implementation behind both Argon2 variants.
//
// It exists because the two derivations were 63 lines that differed on exactly
// TWO: the name in their error messages, and `argon2.Key` versus
// `argon2.IDKey`. Everything else -- the three nil checks, the parallelism
// bound, the round-count bound, the memory floor and its reasoning, the three
// checked uint32 conversions -- was duplicated verbatim, including an
// eighteen-line comment. Duplication of a VALIDATION sequence is the dangerous
// kind: a bound added to one copy and not the other is invisible, and the
// memory floor below is itself a bound that was missing from a copy for
// exactly that reason.
//
// `keyFn` is the variant. `argon2.Key` and `argon2.IDKey` share a signature
// exactly, so no adapter is needed and no behavior is reinterpreted here.
//
// `op` is lower case because it is the CryptoError.Op vocabulary the rest of
// this file uses; `name` is the human spelling that appears in the
// missing-parameter message, kept distinct so neither message changes.
func deriveArgon2(
	op, name string,
	keyFn func(password, salt []byte, time, memory uint32, threads uint8, keyLen uint32) []byte,
	passphrase, salt []byte, kdf *KDF, keySize int,
) ([]byte, error) {
	if kdf.Time == nil || kdf.Memory == nil || kdf.CPUs == nil {
		return nil, fmt.Errorf("%s requires time, memory, and cpus parameters", name)
	}

	// Validate CPUs fits in uint8 (Argon2 parallelism is 1-255)
	cpus := *kdf.CPUs
	if cpus < 1 || cpus > 255 {
		return nil, &CryptoError{Op: op, Err: fmt.Errorf("cpus must be between 1 and 255")}
	}

	// And the round count, which x/crypto/argon2 PANICS on rather than
	// refusing: "argon2: number of rounds too small" for time < 1. The cpus
	// bound directly above was checked and this one was not, which is what made
	// the omission easy to miss -- both are panics in the same function, from
	// the same header fields, three lines apart.
	if *kdf.Time < 1 {
		return nil, &CryptoError{Op: op, Err: fmt.Errorf("time cost must be at least 1")}
	}

	// AND THE MEMORY COST, which was the third field and the one still
	// unchecked. Time and CPUs were bounded here; Memory was not, and it is the
	// one whose failure is silent rather than a panic: these are signed ints
	// out of JSON and the call below converts with uint32, so -1 becomes
	// 4294967295 KiB and argon2 is asked for a FOUR TERABYTE matrix. Not an
	// error -- an allocation.
	//
	// minArgon2Memory is validateKDFCost's own constant rather than a second
	// copy, because two spellings of one bound drift. Only the floor is
	// enforced here, matching the Time check directly above: the ceiling is the
	// read path's job, and applying it here could refuse a foreign volume that
	// currently unlocks.
	if *kdf.Memory < minArgon2Memory {
		return nil, &CryptoError{Op: op, Err: fmt.Errorf(
			"memory cost %d is below the %d KiB floor; a negative value becomes ~4 TiB after the uint32 conversion",
			*kdf.Memory, minArgon2Memory)}
	}

	// A representation limit, NOT the policy ceiling this file deliberately
	// declines (see deriveKeyPlain: an untrusted-input ceiling applied to a
	// caller's own deliberate choice rejects it with an error shaped like a
	// malformed header). Above MaxUint32 the conversion below does not reject
	// the value, it SILENTLY CHANGES it -- 2^32+4 becomes 4 -- so the guard is
	// about what the call can represent rather than about what is a sensible
	// cost.

	t32, err := u32(op, "time cost", *kdf.Time)
	if err != nil {
		return nil, err
	}
	m32, err := u32(op, "memory cost", *kdf.Memory)
	if err != nil {
		return nil, err
	}
	k32, err := u32(op, "key length", keySize)
	if err != nil {
		return nil, err
	}

	// cpus is the one conversion still written inline: it is bounded 1..255
	// directly above, which is narrower than uint8 itself, so there is nothing
	// for a checked conversion to add.
	return keyFn(passphrase, salt, t32, m32, uint8(cpus), k32), nil
}

// deriveArgon2i derives a key using Argon2i.
func deriveArgon2i(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	return deriveArgon2("argon2i", "Argon2i", argon2.Key, passphrase, salt, kdf, keySize)
}

// deriveArgon2id derives a key using Argon2id.
func deriveArgon2id(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	return deriveArgon2("argon2id", "Argon2id", argon2.IDKey, passphrase, salt, kdf, keySize)
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
	pbkdf2ProbeStart = 1000

	// pbkdf2ProbeFloor is how long a probe must run before its measurement is
	// trusted.
	//
	// The floor is not about clock resolution: time.Now is a vDSO read with
	// nanosecond granularity. It is about SCHEDULING. One preemption costs a
	// probe on the order of a millisecond, so a 50ms probe absorbs one at a few
	// percent error while a 1ms probe would be wrong by half. Calibration
	// therefore costs at most two floors' worth of work -- roughly 100ms, once
	// per format -- against a default budget of 2000ms of derivation.
	pbkdf2ProbeFloor = 50 * time.Millisecond

	// pbkdf2ProbeCeiling bounds the doubling so that a clock which never
	// advances FAILS instead of looping forever. Reaching it means over sixteen
	// million iterations completed inside 50ms, roughly a hundred times faster
	// than current hardware: the clock is broken, not the CPU fast.
	pbkdf2ProbeCeiling = 1 << 24

	// maxPBKDF2IterTimeMs bounds the requested budget. Ten minutes is already
	// far past any iteration time anyone means, and the bound is what keeps
	// time.Duration arithmetic on the request from overflowing into a negative
	// duration -- which would silently return the floor instead of the very
	// large count that was asked for.
	maxPBKDF2IterTimeMs = 600_000

	// minPBKDF2Iterations is the absolute floor for a keyslot this package
	// WRITES: cryptsetup's own minimum, and the smallest count any LUKS
	// implementation should be handed.
	//
	// It is deliberately not minKDFIterations (keyslotvalidation.go), which is 1
	// and governs what this package will READ out of a header someone else
	// wrote. Being liberal about a header we did not create and strict about one
	// we are creating are different decisions.
	minPBKDF2Iterations = 1000

	// pbkdf2ReferenceTargetMs is the budget the recommended minima below are
	// stated against, and is this library's own default (see createPBKDF2KDF).
	pbkdf2ReferenceTargetMs = 2000
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
var pbkdf2RecommendedIterations = map[string]int{
	"sha1":   1_300_000,
	"sha256": 600_000,
	"sha384": 210_000,
	"sha512": 210_000,
}

var (
	// errCalibrationTargetInvalid is the cause reported when the requested
	// iteration time is not a usable number of milliseconds. The rejected value
	// itself is carried on the KDFCalibrationError.
	errCalibrationTargetInvalid = errors.New("the iteration-time target must be positive and within the supported range")

	// errCalibrationImmeasurable is the cause reported when no probe up to the
	// ceiling ran long enough to be timed.
	errCalibrationImmeasurable = errors.New("no probe ran long enough to be timed; the clock is not advancing")
)

// BenchmarkPBKDF2 returns the number of PBKDF2 iterations that costs
// approximately targetMs milliseconds on this machine, for the given hash and
// derived-key size.
//
// It NEVER returns a default. A calibration that cannot be performed returns a
// *KDFCalibrationError (matching ErrKDFCalibration) and no count; the block
// comment above says why a plausible-looking constant is the wrong answer here.
//
// The result is clamped into [floor, maxKDFIterations]. The floor is the larger
// of minPBKDF2Iterations and the budget-scaled recommendation for the hash; the
// ceiling is the same one validateKDFCost enforces when the header is read back,
// so a count this function returns can never produce a header this package
// would go on to reject.
//
// Supported hash algorithms: sha256, sha384, sha512 and, outside FIPS 140-3
// mode, sha1.
func BenchmarkPBKDF2(hashAlgo string, keySize, targetMs int) (int, error) {
	hashFunc, err := getPBKDF2HashFunc(hashAlgo)
	if err != nil {
		return 0, err
	}

	return calibratePBKDF2(hashFunc, hashAlgo, keySize, targetMs, pbkdf2ProbeFloor, pbkdf2ProbeCeiling, wallClockPBKDF2)
}

// pbkdf2Timer runs one PBKDF2 derivation of the given iteration count and
// output size and reports how long it took.
//
// It is a parameter of the calibration so the ARITHMETIC can be tested against
// a known rate: with a real clock the measured rate depends on whatever else
// the machine is doing, and a test asserting on it fails under host load for a
// reason that has nothing to do with the code (#233).
type pbkdf2Timer func(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error)

// wallClockPBKDF2 is the timer the package calibrates with: the real
// derivation, timed on the wall clock.
//
// Neither the passphrase nor the salt is key material or becomes any. PBKDF2's
// cost depends on the iteration count, the hash and the output length, not on
// their contents, and nothing derived here is returned, stored, or compared
// against anything.
func wallClockPBKDF2(hashFunc func() hash.Hash, iterations, keySize int) (time.Duration, error) {
	const calibrationPassphrase = "calibration"
	calibrationSalt := make([]byte, 32)

	start := time.Now()
	if _, err := pbkdf2.Key(hashFunc, calibrationPassphrase, calibrationSalt, iterations, keySize); err != nil {
		return 0, &CryptoError{Op: "pbkdf2 benchmark", Err: err}
	}
	return time.Since(start), nil
}

// calibratePBKDF2 is the calibration itself. The probe bounds and the timer
// are parameters so that the fail-closed path and the extrapolation can be
// exercised by a test without needing a broken or an idle clock;
// BenchmarkPBKDF2 supplies the real ones.
func calibratePBKDF2(hashFunc func() hash.Hash, hashAlgo string, keySize, targetMs int, probeFloor time.Duration, probeCeiling int, timer pbkdf2Timer) (int, error) {
	if targetMs <= 0 || targetMs > maxPBKDF2IterTimeMs {
		return 0, &KDFCalibrationError{
			Hash:     hashAlgo,
			TargetMs: targetMs,
			Err:      errCalibrationTargetInvalid,
		}
	}

	for probe := pbkdf2ProbeStart; ; probe *= 2 {
		elapsed, err := timer(hashFunc, probe, keySize)
		if err != nil {
			return 0, err
		}

		// Compared as a Duration, never as elapsed.Milliseconds(). Truncating a
		// sub-millisecond measurement to an integer is what made the original
		// extrapolation unreachable; truncating a 1ms one is what made it wrong
		// by up to 3x on the occasions it was reached.
		if elapsed >= probeFloor {
			return scalePBKDF2Iterations(hashAlgo, probe, elapsed, targetMs), nil
		}

		// Checked after the probe rather than before, so the ceiling bounds the
		// largest probe actually RUN. Doubling past it would double the work
		// again for a measurement that has already failed to be timeable.
		if probe > probeCeiling/2 {
			return 0, &KDFCalibrationError{
				Hash:     hashAlgo,
				TargetMs: targetMs,
				Probe:    probe,
				Elapsed:  elapsed,
				Err:      errCalibrationImmeasurable,
			}
		}
	}
}

// scalePBKDF2Iterations extrapolates a timed probe to the requested budget and
// clamps the result into the range this package is willing to write.
func scalePBKDF2Iterations(hashAlgo string, probe int, elapsed time.Duration, targetMs int) int {
	perIteration := elapsed.Seconds() / float64(probe)
	scaled := (time.Duration(targetMs) * time.Millisecond).Seconds() / perIteration

	// Floor first, ceiling second: a budget large enough to push the floor past
	// the ceiling must land on the ceiling, not above it.
	if floor := pbkdf2IterationFloor(hashAlgo, targetMs); scaled < floor {
		scaled = floor
	}

	// maxKDFIterations is the ceiling validateKDFCost applies when the header is
	// read back, so exceeding it here would write a keyslot this package would
	// then refuse to open. Clamping is also what keeps the conversion below
	// defined -- Go leaves an out-of-range float-to-int conversion
	// implementation-specific.
	if scaled > maxKDFIterations {
		scaled = maxKDFIterations
	}

	return int(scaled)
}

// pbkdf2IterationFloor returns the smallest iteration count this package will
// write for a hash and a budget: minPBKDF2Iterations, or the budget-scaled
// OWASP recommendation when that is larger.
//
// It returns a float64 because its only caller compares it against an
// unrounded extrapolation, and rounding twice would be the sort of small
// discrepancy that makes a floor look off by one for no reason.
func pbkdf2IterationFloor(hashAlgo string, targetMs int) float64 {
	floor := float64(minPBKDF2Iterations)

	recommended, ok := pbkdf2RecommendedIterations[strings.ToLower(hashAlgo)]
	if !ok {
		return floor
	}

	if scaled := float64(recommended) * float64(targetMs) / pbkdf2ReferenceTargetMs; scaled > floor {
		return scaled
	}
	return floor
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
// randomSecret; there is no candidate list, so there is no search, so there is
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
	// minPBKDF2Iterations for a credential this package drew from randomSecret.
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

// forcedPBKDF2Iterations validates an explicit PBKDF2 iteration count -- the
// one a caller supplies through FormatOptions.PBKDFIterations or
// AddKeyOptions.PBKDFIterations -- and returns it unchanged if it is one this
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
// BenchmarkPBKDF2 would have refused to return.
//
// The floor is hash-dependent (pbkdf2IterationFloor): 600000 for sha256,
// 210000 for sha384 and sha512, and minPBKDF2Iterations for a hash with no
// published recommendation -- unless the policy says this package generated the
// credential itself, in which case see keyslotCostPolicy for what changes and
// why.
func forcedPBKDF2Iterations(hashAlgo string, iterations int, policy keyslotCostPolicy) (int, error) {
	minimum := pbkdf2FloorFor(hashAlgo, policy)

	if iterations < minimum {
		return 0, &PBKDFIterationsError{
			Hash:       hashAlgo,
			Iterations: iterations,
			Minimum:    minimum,
			Maximum:    maxKDFIterations,
			Err:        ErrPBKDFIterationsTooLow,
		}
	}

	if iterations > maxKDFIterations {
		return 0, &PBKDFIterationsError{
			Hash:       hashAlgo,
			Iterations: iterations,
			Minimum:    minimum,
			Maximum:    maxKDFIterations,
			Err:        ErrPBKDFIterationsTooHigh,
		}
	}

	return iterations, nil
}

// CreateKDF creates a KDF structure based on options
// Supported KDF types:
//   - "pbkdf2" - PBKDF2 with hash from HashAlgo option (default: sha256) [FIPS-approved]
//   - "pbkdf2-sha1" - REFUSED with ErrSHA1NotWritten: SHA-1 is never written (#239)
//   - "pbkdf2-sha256" - PBKDF2 with SHA-256 [FIPS-approved, recommended]
//   - "pbkdf2-sha384" - PBKDF2 with SHA-384 [FIPS-approved]
//   - "pbkdf2-sha512" - PBKDF2 with SHA-512 [FIPS-approved]
//   - "argon2i" - Argon2i [NOT FIPS-approved, refused in FIPS mode]
//   - "argon2id" - Argon2id [NOT FIPS-approved, refused in FIPS mode]
//
// An empty KDFType resolves through resolveKDFType: to DefaultKDFType --
// "pbkdf2-sha512" in FIPS 140-3 mode, "argon2id" otherwise -- unless an Argon2
// cost is set, which selects "argon2id".
func CreateKDF(opts FormatOptions, keySize int) (*KDF, error) {
	// The EXPORTED entry point is always strict. The exemption has no route
	// through the public API by construction -- see keyslotCostPolicy.
	return createKDF(opts, keySize, callerSuppliedCredential)
}

func createKDF(opts FormatOptions, keySize int, policy keyslotCostPolicy) (*KDF, error) {
	kdfType := resolveKDFType(normalizeKDFType(opts.KDFType), formatArgon2CostGiven(opts))

	// No keyslot is created with SHA-1, before any other choice is judged.
	if err := refuseSHA1ForCreation(kdfType, opts.HashAlgo); err != nil {
		return nil, err
	}

	// Checked after the default is resolved. The default itself is approved in
	// FIPS mode (DefaultKDFType), so what this refuses there is an Argon2 KDF
	// the caller asked for -- by name, or by supplying an Argon2 cost; see
	// docs/FIPS.md.
	if err := requireFIPSApprovedKDF(kdfType); err != nil {
		return nil, err
	}

	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}

	saltB64 := encodeBase64(salt)

	// Handle PBKDF2 variants (including convenience aliases)
	if isPBKDF2Type(kdfType) {
		return createPBKDF2KDF(kdfType, opts, saltB64, keySize, policy)
	}

	// Handle Argon2 variants
	switch kdfType {
	case KDFTypeArgon2i, KDFTypeArgon2id:
		return createArgon2KDF(kdfType, opts, saltB64)
	default:
		return nil, &detailError{Kind: ErrUnsupportedKDF, Detail: kdfType + " (supported: pbkdf2, pbkdf2-sha256, pbkdf2-sha384, pbkdf2-sha512, argon2i, argon2id)"}
	}
}

// refuseSHA1ForCreation refuses a KDF type or hash that would WRITE SHA-1
// into a new keyslot or digest: the pbkdf2-sha1 alias, or a "sha1" hash for
// any KDF -- a format's hash is also its digest's and its anti-forensic
// split's, and an AddKey hash names the new keyslot's. Reading is unaffected:
// existing PBKDF2-SHA1 keyslots and digests open outside FIPS mode (#239).
func refuseSHA1ForCreation(kdfType, hashAlgo string) error {
	if normalizeKDFType(kdfType) == KDFTypePBKDF2SHA1 {
		return &detailError{Kind: ErrSHA1NotWritten, Err: ErrUnsupportedKDF,
			Detail: "pbkdf2-sha1: new keyslots use pbkdf2 with sha256, sha384 or sha512, or argon2"}
	}
	if strings.EqualFold(strings.TrimSpace(hashAlgo), "sha1") {
		return &detailError{Kind: ErrSHA1NotWritten, Err: ErrUnsupportedHash,
			Detail: "sha1: new keyslots and digests use sha256, sha384 or sha512"}
	}
	return nil
}

// isPBKDF2Type returns true if the KDF type is a PBKDF2 variant
func isPBKDF2Type(kdfType string) bool {
	switch kdfType {
	case KDFTypePBKDF2, KDFTypePBKDF2SHA1, KDFTypePBKDF2SHA256, KDFTypePBKDF2SHA384, KDFTypePBKDF2SHA512:
		return true
	default:
		return false
	}
}

// createPBKDF2KDF creates a PBKDF2 KDF structure
func createPBKDF2KDF(kdfType string, opts FormatOptions, saltB64 string, keySize int, policy keyslotCostPolicy) (*KDF, error) {
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
		iterations, err = BenchmarkPBKDF2(hashAlgo, keySize, iterTime)
	}
	if err != nil {
		return nil, err
	}

	return &KDF{
		Type:       KDFTypePBKDF2, // Always store as "pbkdf2" for LUKS2 compatibility
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
	case KDFTypePBKDF2SHA1:
		return "sha1"
	case KDFTypePBKDF2SHA256:
		return "sha256"
	case KDFTypePBKDF2SHA384:
		return "sha384"
	case KDFTypePBKDF2SHA512:
		return "sha512"
	default:
		// Default to SHA-256 for plain "pbkdf2"
		return "sha256"
	}
}

// createArgon2KDF creates an Argon2 KDF structure
func createArgon2KDF(kdfType string, opts FormatOptions, saltB64 string) (*KDF, error) {
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

	return &KDF{
		Type:   kdfType,
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   &cpus,
	}, nil
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 string to bytes
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

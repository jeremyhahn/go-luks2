// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/fips140"
	"crypto/pbkdf2"
	"crypto/sha1" // #nosec G505 - legacy LUKS interop only; refused in FIPS mode (docs/FIPS.md)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
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

	// KDFTypePBKDF2SHA1 is PBKDF2 with SHA-1. It is NOT FIPS-approved and is
	// refused while the process runs in FIPS 140-3 mode; it exists only to open
	// LUKS headers written by cryptsetup releases that defaulted to SHA-1.
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

	// KDFTypeArgon2id is the Argon2id KDF type and the library default. It is
	// NOT FIPS-approved and is refused while the process runs in FIPS 140-3
	// mode, including when it is reached as the default. See docs/FIPS.md.
	KDFTypeArgon2id = "argon2id"
)

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
	if !fips140.Enabled() {
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
// avoid that is prohibited outright by the owner ruling of 2026-08-25 (resolved
// case #155), which rules that the protected-memory mandate yields here.
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

// DeriveKey derives a key from a passphrase using the specified KDF and returns
// it as plain, unprotected bytes.
//
// Deprecated: the returned key is ordinary heap memory -- swappable,
// core-dumpable, and not zeroized until a caller remembers to do it. Nothing
// inside this package calls it any more; every internal derivation goes through
// DeriveKeyEnclave, which returns the key held in locked memory. It remains
// exported only so that existing consumers and the conformance fixtures keep
// building, and it will be removed once none depend on it.
//
// In FIPS 140-3 mode an Argon2 KDF is refused with ErrFIPSNotApproved before
// any derivation is attempted, so an externally supplied header cannot make a
// FIPS-mode process run a non-approved KDF.
func DeriveKey(passphrase []byte, kdf *KDF, keySize int) ([]byte, error) {
	return deriveKeyPlain(passphrase, kdf, keySize)
}

// deriveKeyPlain is the derivation itself. It is the ONE place in this package
// that produces key material outside an enclave, and it exists because the
// stdlib KDFs give no other shape: every caller either adopts the result into
// an enclave immediately (DeriveKeyEnclave) or is the deprecated exported
// wrapper above.
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
	// function serves two TRUST DOMAINS. Format, AddKey, ChangeKey and the
	// exported DeriveKey derive from parameters the CALLER chose, and an
	// untrusted-input ceiling applied to all of them rejects a caller's own
	// deliberate choice with an error shaped like a malformed header. What a
	// HEADER may declare is bounded where headers are read -- validateKeyslot
	// for the key size, validateKDFCost for the work factors.
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
// bounded transient copy; document it" (conventions/security-review.md, NEVER
// hand-roll cryptography, owner ruling 2026-08-25, resolved case #155).
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
	switch strings.ToLower(hashAlgo) {
	case "sha1":
		// PBKDF2-HMAC-SHA1 is needed to open LUKS headers written by cryptsetup
		// releases that defaulted to SHA-1, but the Go Cryptographic Module
		// permits PBKDF2 only with SHA-2/SHA-3 and panics on SHA-1 under
		// GODEBUG=fips140=only. Refuse it here so a FIPS build reports a typed
		// error instead of crashing, and so the call never reaches the module.
		// See docs/FIPS.md.
		if fips140.Enabled() {
			return nil, &CryptoError{Op: "pbkdf2-hmac-sha1", Err: ErrFIPSNotApproved}
		}
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha384":
		return sha512.New384, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("%w: %s (supported: sha1, sha256, sha384, sha512)", ErrUnsupportedHash, hashAlgo)
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

// deriveArgon2i derives a key using Argon2i
func deriveArgon2i(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	if kdf.Time == nil || kdf.Memory == nil || kdf.CPUs == nil {
		return nil, fmt.Errorf("Argon2i requires time, memory, and cpus parameters")
	}

	// Validate CPUs fits in uint8 (Argon2 parallelism is 1-255)
	cpus := *kdf.CPUs
	if cpus < 1 || cpus > 255 {
		return nil, &CryptoError{Op: "argon2i", Err: fmt.Errorf("cpus must be between 1 and 255")}
	}

	// And the round count, which x/crypto/argon2 PANICS on rather than
	// refusing: "argon2: number of rounds too small" for time < 1. The cpus
	// bound directly above was checked and this one was not, which is what made
	// the omission easy to miss -- both are panics in the same function, from
	// the same header fields, three lines apart.
	if *kdf.Time < 1 {
		return nil, &CryptoError{Op: "argon2i", Err: fmt.Errorf("time cost must be at least 1")}
	}

	// #nosec G115 - bounds checked above (cpus is 1-255)
	key := argon2.Key(passphrase, salt, uint32(*kdf.Time), uint32(*kdf.Memory), uint8(cpus), uint32(keySize))
	return key, nil
}

// deriveArgon2id derives a key using Argon2id
func deriveArgon2id(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	if kdf.Time == nil || kdf.Memory == nil || kdf.CPUs == nil {
		return nil, fmt.Errorf("Argon2id requires time, memory, and cpus parameters")
	}

	// Validate CPUs fits in uint8 (Argon2 parallelism is 1-255)
	cpus := *kdf.CPUs
	if cpus < 1 || cpus > 255 {
		return nil, &CryptoError{Op: "argon2id", Err: fmt.Errorf("cpus must be between 1 and 255")}
	}

	// And the round count, which x/crypto/argon2 PANICS on rather than
	// refusing: "argon2: number of rounds too small" for time < 1. The cpus
	// bound directly above was checked and this one was not, which is what made
	// the omission easy to miss -- both are panics in the same function, from
	// the same header fields, three lines apart.
	if *kdf.Time < 1 {
		return nil, &CryptoError{Op: "argon2id", Err: fmt.Errorf("time cost must be at least 1")}
	}

	// #nosec G115 - bounds checked above (cpus is 1-255)
	key := argon2.IDKey(passphrase, salt, uint32(*kdf.Time), uint32(*kdf.Memory), uint8(cpus), uint32(keySize))
	return key, nil
}

// BenchmarkPBKDF2 determines the number of iterations for target time
// Supported hash algorithms: sha256, sha384, sha512 and, outside FIPS 140-3
// mode, sha1
func BenchmarkPBKDF2(hashAlgo string, keySize, targetMs int) (int, error) {
	testPass := []byte("test")
	testSalt := make([]byte, 32)

	hashFunc, err := getPBKDF2HashFunc(hashAlgo)
	if err != nil {
		return 0, err
	}

	// Start with 1000 iterations and measure
	iterations := 1000
	start := time.Now()
	if _, err := pbkdf2.Key(hashFunc, string(testPass), testSalt, iterations, keySize); err != nil {
		return 0, &CryptoError{Op: "pbkdf2 benchmark", Err: err}
	}
	elapsed := time.Since(start)

	// Extrapolate to target time
	if elapsed.Milliseconds() > 0 {
		targetIterations := int(float64(iterations) * (float64(targetMs) / float64(elapsed.Milliseconds())))
		if targetIterations < 1000 {
			targetIterations = 1000 // Minimum iterations
		}
		return targetIterations, nil
	}

	// If too fast to measure, default to higher value
	return 100000, nil
}

// CreateKDF creates a KDF structure based on options
// Supported KDF types:
//   - "pbkdf2" - PBKDF2 with hash from HashAlgo option (default: sha256) [FIPS-approved]
//   - "pbkdf2-sha1" - PBKDF2 with SHA-1 [NOT FIPS-approved, legacy headers only]
//   - "pbkdf2-sha256" - PBKDF2 with SHA-256 [FIPS-approved, recommended]
//   - "pbkdf2-sha384" - PBKDF2 with SHA-384 [FIPS-approved]
//   - "pbkdf2-sha512" - PBKDF2 with SHA-512 [FIPS-approved]
//   - "argon2i" - Argon2i [NOT FIPS-approved, refused in FIPS mode]
//   - "argon2id" - Argon2id [NOT FIPS-approved, refused in FIPS mode, default]
func CreateKDF(opts FormatOptions, keySize int) (*KDF, error) {
	kdfType := normalizeKDFType(opts.KDFType)
	if kdfType == "" {
		kdfType = KDFTypeArgon2id // Default
	}

	// Checked after the default is resolved, so that FormatOptions{} does not
	// silently create an Argon2id keyslot in a FIPS-mode process. A FIPS caller
	// must select an approved KDF explicitly; see docs/FIPS.md.
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
		return createPBKDF2KDF(kdfType, opts, saltB64, keySize)
	}

	// Handle Argon2 variants
	switch kdfType {
	case KDFTypeArgon2i, KDFTypeArgon2id:
		return createArgon2KDF(kdfType, opts, saltB64)
	default:
		return nil, fmt.Errorf("%w: %s (supported: pbkdf2, pbkdf2-sha1, pbkdf2-sha256, pbkdf2-sha384, pbkdf2-sha512, argon2i, argon2id)", ErrUnsupportedKDF, kdfType)
	}
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
func createPBKDF2KDF(kdfType string, opts FormatOptions, saltB64 string, keySize int) (*KDF, error) {
	iterTime := opts.PBKDFIterTime
	if iterTime == 0 {
		iterTime = 2000 // 2 seconds default
	}

	// Determine hash algorithm from KDF type or HashAlgo option
	hashAlgo := getHashAlgoForKDFType(kdfType, opts.HashAlgo)

	iterations, err := BenchmarkPBKDF2(hashAlgo, keySize, iterTime)
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

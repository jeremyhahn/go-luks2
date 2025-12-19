// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/sha1" // #nosec G505 - SHA-1 is FIPS-approved for HMAC (used in PBKDF2)
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

// FIPS-compatible KDF type constants
// These provide convenience aliases for PBKDF2 with specific hash algorithms
const (
	// KDFTypePBKDF2 is the base PBKDF2 KDF type (uses HashAlgo option for hash selection)
	KDFTypePBKDF2 = "pbkdf2"

	// KDFTypePBKDF2SHA1 is PBKDF2 with SHA-1 (FIPS-approved for HMAC, legacy compatibility)
	KDFTypePBKDF2SHA1 = "pbkdf2-sha1"

	// KDFTypePBKDF2SHA256 is PBKDF2 with SHA-256 (FIPS-approved, recommended)
	KDFTypePBKDF2SHA256 = "pbkdf2-sha256"

	// KDFTypePBKDF2SHA384 is PBKDF2 with SHA-384 (FIPS-approved)
	KDFTypePBKDF2SHA384 = "pbkdf2-sha384"

	// KDFTypePBKDF2SHA512 is PBKDF2 with SHA-512 (FIPS-approved)
	KDFTypePBKDF2SHA512 = "pbkdf2-sha512"

	// KDFTypeArgon2i is the Argon2i KDF type (NOT FIPS-approved)
	KDFTypeArgon2i = "argon2i"

	// KDFTypeArgon2id is the Argon2id KDF type (NOT FIPS-approved, but recommended for non-FIPS)
	KDFTypeArgon2id = "argon2id"
)

// IsFIPSCompliantKDF returns true if the KDF type is FIPS-approved
func IsFIPSCompliantKDF(kdfType string) bool {
	switch normalizeKDFType(kdfType) {
	case KDFTypePBKDF2, KDFTypePBKDF2SHA1, KDFTypePBKDF2SHA256, KDFTypePBKDF2SHA384, KDFTypePBKDF2SHA512:
		return true
	default:
		return false
	}
}

// normalizeKDFType normalizes a KDF type string to lowercase
func normalizeKDFType(kdfType string) string {
	return strings.ToLower(strings.TrimSpace(kdfType))
}

// DeriveKey derives a key from a passphrase using the specified KDF
func DeriveKey(passphrase []byte, kdf *KDF, keySize int) ([]byte, error) {
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
		return nil, fmt.Errorf("unsupported KDF type: %s", kdf.Type)
	}
}

// derivePBKDF2 derives a key using PBKDF2
func derivePBKDF2(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	if kdf.Iterations == nil {
		return nil, fmt.Errorf("PBKDF2 requires iterations")
	}

	hashFunc, err := getPBKDF2HashFunc(kdf.Hash)
	if err != nil {
		return nil, err
	}

	key := pbkdf2.Key(passphrase, salt, *kdf.Iterations, keySize, hashFunc)
	return key, nil
}

// getPBKDF2HashFunc returns the hash function for PBKDF2 key derivation
// Supported: sha1, sha256, sha384, sha512 (all FIPS-approved)
func getPBKDF2HashFunc(hashAlgo string) (func() hash.Hash, error) {
	switch strings.ToLower(hashAlgo) {
	case "sha1":
		// SHA-1 is FIPS-approved for HMAC (used in PBKDF2)
		// Note: SHA-1 is deprecated for signatures but still valid for HMAC
		return sha1.New, nil
	case "sha256":
		return sha256.New, nil
	case "sha384":
		return sha512.New384, nil
	case "sha512":
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported hash algorithm: %s (supported: sha1, sha256, sha384, sha512)", hashAlgo)
	}
}

// deriveArgon2i derives a key using Argon2i
func deriveArgon2i(passphrase, salt []byte, kdf *KDF, keySize int) ([]byte, error) {
	if kdf.Time == nil || kdf.Memory == nil || kdf.CPUs == nil {
		return nil, fmt.Errorf("Argon2i requires time, memory, and cpus parameters")
	}

	// Validate CPUs fits in uint8 (Argon2 parallelism is 1-255)
	cpus := *kdf.CPUs
	if cpus < 1 || cpus > 255 {
		return nil, fmt.Errorf("Argon2i cpus must be between 1 and 255")
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
		return nil, fmt.Errorf("Argon2id cpus must be between 1 and 255")
	}

	// #nosec G115 - bounds checked above (cpus is 1-255)
	key := argon2.IDKey(passphrase, salt, uint32(*kdf.Time), uint32(*kdf.Memory), uint8(cpus), uint32(keySize))
	return key, nil
}

// BenchmarkPBKDF2 determines the number of iterations for target time
// Supported hash algorithms: sha1, sha256, sha384, sha512
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
	_ = pbkdf2.Key(testPass, testSalt, iterations, keySize, hashFunc)
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
//   - "pbkdf2-sha1" - PBKDF2 with SHA-1 [FIPS-approved, legacy]
//   - "pbkdf2-sha256" - PBKDF2 with SHA-256 [FIPS-approved, recommended]
//   - "pbkdf2-sha384" - PBKDF2 with SHA-384 [FIPS-approved]
//   - "pbkdf2-sha512" - PBKDF2 with SHA-512 [FIPS-approved]
//   - "argon2i" - Argon2i [NOT FIPS-approved]
//   - "argon2id" - Argon2id [NOT FIPS-approved, default]
func CreateKDF(opts FormatOptions, keySize int) (*KDF, error) {
	kdfType := normalizeKDFType(opts.KDFType)
	if kdfType == "" {
		kdfType = KDFTypeArgon2id // Default
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
		return nil, fmt.Errorf("unsupported KDF type: %s (supported: pbkdf2, pbkdf2-sha1, pbkdf2-sha256, pbkdf2-sha384, pbkdf2-sha512, argon2i, argon2id)", kdfType)
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

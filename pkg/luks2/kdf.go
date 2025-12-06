// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"hash"
	"time"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

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

	var hashFunc func() hash.Hash
	switch kdf.Hash {
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	default:
		return nil, fmt.Errorf("unsupported hash: %s", kdf.Hash)
	}

	key := pbkdf2.Key(passphrase, salt, *kdf.Iterations, keySize, hashFunc)
	return key, nil
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
func BenchmarkPBKDF2(hashAlgo string, keySize, targetMs int) (int, error) {
	testPass := []byte("test")
	testSalt := make([]byte, 32)

	var hashFunc func() hash.Hash
	switch hashAlgo {
	case "sha256":
		hashFunc = sha256.New
	case "sha512":
		hashFunc = sha512.New
	default:
		return 0, fmt.Errorf("unsupported hash: %s", hashAlgo)
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
func CreateKDF(opts FormatOptions, keySize int) (*KDF, error) {
	kdfType := opts.KDFType
	if kdfType == "" {
		kdfType = "argon2id" // Default
	}

	salt, err := randomBytes(32)
	if err != nil {
		return nil, err
	}

	saltB64 := encodeBase64(salt)

	switch kdfType {
	case "pbkdf2":
		iterTime := opts.PBKDFIterTime
		if iterTime == 0 {
			iterTime = 2000 // 2 seconds default
		}

		hashAlgo := opts.HashAlgo
		if hashAlgo == "" {
			hashAlgo = "sha256"
		}

		iterations, err := BenchmarkPBKDF2(hashAlgo, keySize, iterTime)
		if err != nil {
			return nil, err
		}

		return &KDF{
			Type:       "pbkdf2",
			Hash:       hashAlgo,
			Salt:       saltB64,
			Iterations: &iterations,
		}, nil

	case "argon2i", "argon2id":
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

	default:
		return nil, fmt.Errorf("unsupported KDF type: %s", kdfType)
	}
}

// encodeBase64 encodes bytes to base64 string
func encodeBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// decodeBase64 decodes base64 string to bytes
func decodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

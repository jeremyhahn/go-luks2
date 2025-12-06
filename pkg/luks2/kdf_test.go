// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"testing"
)

// TestDeriveKeyPBKDF2 tests PBKDF2 key derivation
func TestDeriveKeyPBKDF2(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       saltB64,
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	key1, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, len(key1))
	}

	// Derive again with same parameters - should produce identical key
	key2, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("Derived keys should be identical for same inputs")
	}

	// Different passphrase should produce different key
	key3, err := DeriveKey([]byte("different"), kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey with different passphrase failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Fatal("Different passphrases should produce different keys")
	}
}

// TestDeriveKeyPBKDF2SHA512 tests PBKDF2 with SHA512
func TestDeriveKeyPBKDF2SHA512(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha512",
		Salt:       saltB64,
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")
	keySize := 64

	key, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey with SHA512 failed: %v", err)
	}

	if len(key) != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, len(key))
	}
}

// TestDeriveKeyArgon2i tests Argon2i key derivation
func TestDeriveKeyArgon2i(t *testing.T) {
	time := 1
	memory := 64 * 1024 // 64 MB
	cpus := 1
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:   "argon2i",
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   &cpus,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	key1, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, len(key1))
	}

	// Derive again with same parameters - should produce identical key
	key2, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("Derived keys should be identical for same inputs")
	}

	// Different passphrase should produce different key
	key3, err := DeriveKey([]byte("different"), kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey with different passphrase failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Fatal("Different passphrases should produce different keys")
	}
}

// TestDeriveKeyArgon2id tests Argon2id key derivation
func TestDeriveKeyArgon2id(t *testing.T) {
	time := 1
	memory := 64 * 1024 // 64 MB
	cpus := 1
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:   "argon2id",
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   &cpus,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	key1, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key1) != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, len(key1))
	}

	// Derive again with same parameters - should produce identical key
	key2, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key1, key2) {
		t.Fatal("Derived keys should be identical for same inputs")
	}

	// Different passphrase should produce different key
	key3, err := DeriveKey([]byte("different"), kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey with different passphrase failed: %v", err)
	}

	if bytes.Equal(key1, key3) {
		t.Fatal("Different passphrases should produce different keys")
	}
}

// TestDeriveKeyInvalidType tests error handling for unsupported KDF type
func TestDeriveKeyInvalidType(t *testing.T) {
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type: "unsupported",
		Salt: saltB64,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for unsupported KDF type")
	}
}

// TestDeriveKeyInvalidSalt tests error handling for invalid base64 salt
func TestDeriveKeyInvalidSalt(t *testing.T) {
	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       "!!!invalid-base64!!!",
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for invalid base64 salt")
	}
}

// TestDerivePBKDF2MissingIterations tests error handling when iterations is nil
func TestDerivePBKDF2MissingIterations(t *testing.T) {
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       saltB64,
		Iterations: nil, // Missing iterations
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for missing iterations")
	}
}

// TestDerivePBKDF2UnsupportedHash tests error handling for unsupported hash
func TestDerivePBKDF2UnsupportedHash(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "md5", // Unsupported
		Salt:       saltB64,
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for unsupported hash algorithm")
	}
}

// TestDeriveArgon2iMissingTime tests error handling when time is nil
func TestDeriveArgon2iMissingTime(t *testing.T) {
	memory := 64 * 1024
	cpus := 1
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:   "argon2i",
		Salt:   saltB64,
		Time:   nil, // Missing
		Memory: &memory,
		CPUs:   &cpus,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for missing time parameter")
	}
}

// TestDeriveArgon2iMissingMemory tests error handling when memory is nil
func TestDeriveArgon2iMissingMemory(t *testing.T) {
	time := 1
	cpus := 1
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:   "argon2i",
		Salt:   saltB64,
		Time:   &time,
		Memory: nil, // Missing
		CPUs:   &cpus,
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for missing memory parameter")
	}
}

// TestDeriveArgon2iMissingCPUs tests error handling when cpus is nil
func TestDeriveArgon2iMissingCPUs(t *testing.T) {
	time := 1
	memory := 64 * 1024
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:   "argon2i",
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   nil, // Missing
	}

	passphrase := []byte("testpassphrase")
	keySize := 32

	_, err := DeriveKey(passphrase, kdf, keySize)
	if err == nil {
		t.Fatal("Expected error for missing cpus parameter")
	}
}

// TestDeriveArgon2idMissingParams tests error handling for Argon2id missing params
func TestDeriveArgon2idMissingParams(t *testing.T) {
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	tests := []struct {
		name   string
		time   *int
		memory *int
		cpus   *int
	}{
		{
			name:   "missing_time",
			time:   nil,
			memory: func() *int { i := 64 * 1024; return &i }(),
			cpus:   func() *int { i := 1; return &i }(),
		},
		{
			name:   "missing_memory",
			time:   func() *int { i := 1; return &i }(),
			memory: nil,
			cpus:   func() *int { i := 1; return &i }(),
		},
		{
			name:   "missing_cpus",
			time:   func() *int { i := 1; return &i }(),
			memory: func() *int { i := 64 * 1024; return &i }(),
			cpus:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kdf := &KDF{
				Type:   "argon2id",
				Salt:   saltB64,
				Time:   tt.time,
				Memory: tt.memory,
				CPUs:   tt.cpus,
			}

			passphrase := []byte("testpassphrase")
			keySize := 32

			_, err := DeriveKey(passphrase, kdf, keySize)
			if err == nil {
				t.Fatal("Expected error for missing parameter")
			}
		})
	}
}

// TestBenchmarkPBKDF2SHA256 tests PBKDF2 benchmarking with SHA256
func TestBenchmarkPBKDF2SHA256(t *testing.T) {
	iterations, err := BenchmarkPBKDF2("sha256", 32, 100)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 failed: %v", err)
	}

	if iterations < 1000 {
		t.Fatalf("Expected at least 1000 iterations, got %d", iterations)
	}
}

// TestBenchmarkPBKDF2SHA512 tests PBKDF2 benchmarking with SHA512
func TestBenchmarkPBKDF2SHA512(t *testing.T) {
	iterations, err := BenchmarkPBKDF2("sha512", 64, 100)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 failed: %v", err)
	}

	if iterations < 1000 {
		t.Fatalf("Expected at least 1000 iterations, got %d", iterations)
	}
}

// TestBenchmarkPBKDF2InvalidHash tests error handling for unsupported hash
func TestBenchmarkPBKDF2InvalidHash(t *testing.T) {
	_, err := BenchmarkPBKDF2("md5", 32, 100)
	if err == nil {
		t.Fatal("Expected error for unsupported hash algorithm")
	}
}

// TestBenchmarkPBKDF2MinimumIterations tests minimum iteration enforcement
func TestBenchmarkPBKDF2MinimumIterations(t *testing.T) {
	// Use very short target time to trigger minimum iterations logic
	iterations, err := BenchmarkPBKDF2("sha256", 32, 1)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 failed: %v", err)
	}

	if iterations < 1000 {
		t.Fatalf("Expected minimum 1000 iterations, got %d", iterations)
	}
}

// TestCreateKDFPBKDF2 tests creating a PBKDF2 KDF with defaults
func TestCreateKDFPBKDF2(t *testing.T) {
	opts := FormatOptions{
		KDFType: "pbkdf2",
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Type != "pbkdf2" {
		t.Fatalf("Expected type pbkdf2, got %s", kdf.Type)
	}

	if kdf.Hash != "sha256" {
		t.Fatalf("Expected default hash sha256, got %s", kdf.Hash)
	}

	if kdf.Iterations == nil {
		t.Fatal("Iterations should not be nil")
	}

	if *kdf.Iterations < 1000 {
		t.Fatalf("Expected at least 1000 iterations, got %d", *kdf.Iterations)
	}

	if kdf.Salt == "" {
		t.Fatal("Salt should not be empty")
	}

	// Verify salt can be decoded
	_, err = decodeBase64(kdf.Salt)
	if err != nil {
		t.Fatalf("Failed to decode salt: %v", err)
	}
}

// TestCreateKDFPBKDF2CustomHash tests creating PBKDF2 with custom hash
func TestCreateKDFPBKDF2CustomHash(t *testing.T) {
	opts := FormatOptions{
		KDFType:  "pbkdf2",
		HashAlgo: "sha512",
	}

	kdf, err := CreateKDF(opts, 64)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Hash != "sha512" {
		t.Fatalf("Expected hash sha512, got %s", kdf.Hash)
	}
}

// TestCreateKDFPBKDF2CustomIterTime tests creating PBKDF2 with custom iteration time
func TestCreateKDFPBKDF2CustomIterTime(t *testing.T) {
	opts := FormatOptions{
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100, // Short time for fast test
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Iterations == nil {
		t.Fatal("Iterations should not be nil")
	}

	// Should have some reasonable number of iterations
	if *kdf.Iterations < 1000 {
		t.Fatalf("Expected at least 1000 iterations, got %d", *kdf.Iterations)
	}
}

// TestCreateKDFArgon2i tests creating an Argon2i KDF
func TestCreateKDFArgon2i(t *testing.T) {
	opts := FormatOptions{
		KDFType: "argon2i",
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Type != "argon2i" {
		t.Fatalf("Expected type argon2i, got %s", kdf.Type)
	}

	if kdf.Time == nil || *kdf.Time != 4 {
		t.Fatal("Expected default time of 4")
	}

	if kdf.Memory == nil || *kdf.Memory != 1048576 {
		t.Fatal("Expected default memory of 1048576")
	}

	if kdf.CPUs == nil || *kdf.CPUs != 4 {
		t.Fatal("Expected default cpus of 4")
	}

	if kdf.Salt == "" {
		t.Fatal("Salt should not be empty")
	}
}

// TestCreateKDFArgon2id tests creating an Argon2id KDF with defaults
func TestCreateKDFArgon2id(t *testing.T) {
	opts := FormatOptions{
		KDFType: "argon2id",
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Type != "argon2id" {
		t.Fatalf("Expected type argon2id, got %s", kdf.Type)
	}

	if kdf.Time == nil || *kdf.Time != 4 {
		t.Fatal("Expected default time of 4")
	}

	if kdf.Memory == nil || *kdf.Memory != 1048576 {
		t.Fatal("Expected default memory of 1048576")
	}

	if kdf.CPUs == nil || *kdf.CPUs != 4 {
		t.Fatal("Expected default cpus of 4")
	}

	if kdf.Salt == "" {
		t.Fatal("Salt should not be empty")
	}
}

// TestCreateKDFArgon2idCustomParams tests creating Argon2id with custom params
func TestCreateKDFArgon2idCustomParams(t *testing.T) {
	opts := FormatOptions{
		KDFType:        "argon2id",
		Argon2Time:     2,
		Argon2Memory:   65536, // 64 MB
		Argon2Parallel: 2,
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Time == nil || *kdf.Time != 2 {
		t.Fatalf("Expected time of 2, got %v", kdf.Time)
	}

	if kdf.Memory == nil || *kdf.Memory != 65536 {
		t.Fatalf("Expected memory of 65536, got %v", kdf.Memory)
	}

	if kdf.CPUs == nil || *kdf.CPUs != 2 {
		t.Fatalf("Expected cpus of 2, got %v", kdf.CPUs)
	}
}

// TestCreateKDFDefaultArgon2id tests that default KDF type is argon2id
func TestCreateKDFDefaultArgon2id(t *testing.T) {
	opts := FormatOptions{} // No KDFType specified

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	if kdf.Type != "argon2id" {
		t.Fatalf("Expected default type argon2id, got %s", kdf.Type)
	}
}

// TestCreateKDFInvalidType tests error handling for unsupported KDF type
func TestCreateKDFInvalidType(t *testing.T) {
	opts := FormatOptions{
		KDFType: "unsupported",
	}

	_, err := CreateKDF(opts, 32)
	if err == nil {
		t.Fatal("Expected error for unsupported KDF type")
	}
}

// TestCreateKDFInvalidHashAlgo tests error handling for invalid hash in PBKDF2
func TestCreateKDFInvalidHashAlgo(t *testing.T) {
	opts := FormatOptions{
		KDFType:  "pbkdf2",
		HashAlgo: "md5", // Invalid
	}

	_, err := CreateKDF(opts, 32)
	if err == nil {
		t.Fatal("Expected error for unsupported hash algorithm")
	}
}

// TestDeriveKeyDifferentKeySizes tests key derivation with different key sizes
func TestDeriveKeyDifferentKeySizes(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       saltB64,
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")

	keySizes := []int{16, 32, 64, 128}
	for _, size := range keySizes {
		t.Run(formatSize(int64(size)), func(t *testing.T) {
			key, err := DeriveKey(passphrase, kdf, size)
			if err != nil {
				t.Fatalf("DeriveKey failed for size %d: %v", size, err)
			}

			if len(key) != size {
				t.Fatalf("Expected key size %d, got %d", size, len(key))
			}
		})
	}
}

// TestArgon2iVsArgon2id tests that Argon2i and Argon2id produce different keys
func TestArgon2iVsArgon2id(t *testing.T) {
	time := 1
	memory := 64 * 1024
	cpus := 1
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)
	passphrase := []byte("testpassphrase")
	keySize := 32

	kdfI := &KDF{
		Type:   "argon2i",
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   &cpus,
	}

	kdfID := &KDF{
		Type:   "argon2id",
		Salt:   saltB64,
		Time:   &time,
		Memory: &memory,
		CPUs:   &cpus,
	}

	keyI, err := DeriveKey(passphrase, kdfI, keySize)
	if err != nil {
		t.Fatalf("DeriveKey for Argon2i failed: %v", err)
	}

	keyID, err := DeriveKey(passphrase, kdfID, keySize)
	if err != nil {
		t.Fatalf("DeriveKey for Argon2id failed: %v", err)
	}

	if bytes.Equal(keyI, keyID) {
		t.Fatal("Argon2i and Argon2id should produce different keys")
	}
}

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

// =============================================================================
// FIPS-Compliant KDF Tests
// =============================================================================

// TestKDFTypeConstants tests that KDF type constants are defined correctly
func TestKDFTypeConstants(t *testing.T) {
	tests := []struct {
		name     string
		constant string
		expected string
	}{
		{"PBKDF2", KDFTypePBKDF2, "pbkdf2"},
		{"PBKDF2-SHA1", KDFTypePBKDF2SHA1, "pbkdf2-sha1"},
		{"PBKDF2-SHA256", KDFTypePBKDF2SHA256, "pbkdf2-sha256"},
		{"PBKDF2-SHA384", KDFTypePBKDF2SHA384, "pbkdf2-sha384"},
		{"PBKDF2-SHA512", KDFTypePBKDF2SHA512, "pbkdf2-sha512"},
		{"Argon2i", KDFTypeArgon2i, "argon2i"},
		{"Argon2id", KDFTypeArgon2id, "argon2id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.constant != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, tt.constant)
			}
		})
	}
}

// TestIsFIPSCompliantKDF tests the FIPS compliance checker
func TestIsFIPSCompliantKDF(t *testing.T) {
	tests := []struct {
		kdfType     string
		expectFIPS  bool
		description string
	}{
		// FIPS-compliant types
		{KDFTypePBKDF2, true, "pbkdf2 should be FIPS compliant"},
		{KDFTypePBKDF2SHA1, true, "pbkdf2-sha1 should be FIPS compliant"},
		{KDFTypePBKDF2SHA256, true, "pbkdf2-sha256 should be FIPS compliant"},
		{KDFTypePBKDF2SHA384, true, "pbkdf2-sha384 should be FIPS compliant"},
		{KDFTypePBKDF2SHA512, true, "pbkdf2-sha512 should be FIPS compliant"},
		// Case insensitivity
		{"PBKDF2", true, "uppercase PBKDF2 should be FIPS compliant"},
		{"PBKDF2-SHA256", true, "uppercase PBKDF2-SHA256 should be FIPS compliant"},
		{"Pbkdf2-Sha512", true, "mixed case should be FIPS compliant"},
		// Non-FIPS compliant types
		{KDFTypeArgon2i, false, "argon2i should NOT be FIPS compliant"},
		{KDFTypeArgon2id, false, "argon2id should NOT be FIPS compliant"},
		{"ARGON2ID", false, "uppercase argon2id should NOT be FIPS compliant"},
		// Invalid types
		{"scrypt", false, "scrypt should NOT be FIPS compliant"},
		{"bcrypt", false, "bcrypt should NOT be FIPS compliant"},
		{"", false, "empty string should NOT be FIPS compliant"},
		{"unknown", false, "unknown type should NOT be FIPS compliant"},
	}

	for _, tt := range tests {
		t.Run(tt.description, func(t *testing.T) {
			result := IsFIPSCompliantKDF(tt.kdfType)
			if result != tt.expectFIPS {
				t.Errorf("IsFIPSCompliantKDF(%q) = %v, expected %v", tt.kdfType, result, tt.expectFIPS)
			}
		})
	}
}

// TestNormalizeKDFType tests the KDF type normalization function
func TestNormalizeKDFType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"pbkdf2", "pbkdf2"},
		{"PBKDF2", "pbkdf2"},
		{"Pbkdf2", "pbkdf2"},
		{"pbkdf2-sha256", "pbkdf2-sha256"},
		{"PBKDF2-SHA256", "pbkdf2-sha256"},
		{"  pbkdf2  ", "pbkdf2"},
		{" ARGON2ID ", "argon2id"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeKDFType(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeKDFType(%q) = %q, expected %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestIsPBKDF2Type tests the PBKDF2 type checker
func TestIsPBKDF2Type(t *testing.T) {
	tests := []struct {
		kdfType  string
		expected bool
	}{
		{KDFTypePBKDF2, true},
		{KDFTypePBKDF2SHA1, true},
		{KDFTypePBKDF2SHA256, true},
		{KDFTypePBKDF2SHA384, true},
		{KDFTypePBKDF2SHA512, true},
		{KDFTypeArgon2i, false},
		{KDFTypeArgon2id, false},
		{"scrypt", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.kdfType, func(t *testing.T) {
			result := isPBKDF2Type(tt.kdfType)
			if result != tt.expected {
				t.Errorf("isPBKDF2Type(%q) = %v, expected %v", tt.kdfType, result, tt.expected)
			}
		})
	}
}

// TestGetHashAlgoForKDFType tests hash algorithm extraction from KDF type
func TestGetHashAlgoForKDFType(t *testing.T) {
	tests := []struct {
		kdfType      string
		hashOverride string
		expected     string
	}{
		// With override
		{KDFTypePBKDF2, "sha512", "sha512"},
		{KDFTypePBKDF2SHA256, "sha512", "sha512"}, // Override takes precedence
		// From KDF type alias
		{KDFTypePBKDF2SHA1, "", "sha1"},
		{KDFTypePBKDF2SHA256, "", "sha256"},
		{KDFTypePBKDF2SHA384, "", "sha384"},
		{KDFTypePBKDF2SHA512, "", "sha512"},
		// Default for plain pbkdf2
		{KDFTypePBKDF2, "", "sha256"},
		{"unknown", "", "sha256"}, // Default fallback
	}

	for _, tt := range tests {
		name := tt.kdfType
		if tt.hashOverride != "" {
			name += "_override_" + tt.hashOverride
		}
		t.Run(name, func(t *testing.T) {
			result := getHashAlgoForKDFType(tt.kdfType, tt.hashOverride)
			if result != tt.expected {
				t.Errorf("getHashAlgoForKDFType(%q, %q) = %q, expected %q",
					tt.kdfType, tt.hashOverride, result, tt.expected)
			}
		})
	}
}

// TestDeriveKeyPBKDF2SHA1 tests PBKDF2 with SHA-1 (FIPS-approved for HMAC)
func TestDeriveKeyPBKDF2SHA1(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha1",
		Salt:       saltB64,
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")
	keySize := 20 // SHA-1 produces 20 bytes

	key, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey with SHA-1 failed: %v", err)
	}

	if len(key) != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, len(key))
	}

	// Derive again with same parameters - should produce identical key
	key2, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Fatal("Derived keys should be identical for same inputs")
	}
}

// TestDeriveKeyPBKDF2SHA384 tests PBKDF2 with SHA-384
func TestDeriveKeyPBKDF2SHA384(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)

	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha384",
		Salt:       saltB64,
		Iterations: &iterations,
	}

	passphrase := []byte("testpassphrase")
	keySize := 48 // SHA-384 produces 48 bytes

	key, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("DeriveKey with SHA-384 failed: %v", err)
	}

	if len(key) != keySize {
		t.Fatalf("Expected key size %d, got %d", keySize, len(key))
	}

	// Derive again with same parameters - should produce identical key
	key2, err := DeriveKey(passphrase, kdf, keySize)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Fatal("Derived keys should be identical for same inputs")
	}
}

// TestBenchmarkPBKDF2SHA1 tests PBKDF2 benchmarking with SHA-1
func TestBenchmarkPBKDF2SHA1(t *testing.T) {
	iterations, err := BenchmarkPBKDF2("sha1", 20, 100)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 with SHA-1 failed: %v", err)
	}

	if iterations < 1000 {
		t.Fatalf("Expected at least 1000 iterations, got %d", iterations)
	}
}

// TestBenchmarkPBKDF2SHA384 tests PBKDF2 benchmarking with SHA-384
func TestBenchmarkPBKDF2SHA384(t *testing.T) {
	iterations, err := BenchmarkPBKDF2("sha384", 48, 100)
	if err != nil {
		t.Fatalf("BenchmarkPBKDF2 with SHA-384 failed: %v", err)
	}

	if iterations < 1000 {
		t.Fatalf("Expected at least 1000 iterations, got %d", iterations)
	}
}

// TestCreateKDFPBKDF2SHA1Alias tests creating PBKDF2 with SHA-1 using type alias
func TestCreateKDFPBKDF2SHA1Alias(t *testing.T) {
	opts := FormatOptions{
		KDFType:       KDFTypePBKDF2SHA1,
		PBKDFIterTime: 100, // Short time for fast test
	}

	kdf, err := CreateKDF(opts, 20)
	if err != nil {
		t.Fatalf("CreateKDF with pbkdf2-sha1 failed: %v", err)
	}

	// Should be stored as "pbkdf2" for LUKS2 compatibility
	if kdf.Type != KDFTypePBKDF2 {
		t.Fatalf("Expected type %s, got %s", KDFTypePBKDF2, kdf.Type)
	}

	if kdf.Hash != "sha1" {
		t.Fatalf("Expected hash sha1, got %s", kdf.Hash)
	}

	if kdf.Iterations == nil || *kdf.Iterations < 1000 {
		t.Fatal("Expected at least 1000 iterations")
	}
}

// TestCreateKDFPBKDF2SHA256Alias tests creating PBKDF2 with SHA-256 using type alias
func TestCreateKDFPBKDF2SHA256Alias(t *testing.T) {
	opts := FormatOptions{
		KDFType:       KDFTypePBKDF2SHA256,
		PBKDFIterTime: 100,
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF with pbkdf2-sha256 failed: %v", err)
	}

	if kdf.Type != KDFTypePBKDF2 {
		t.Fatalf("Expected type %s, got %s", KDFTypePBKDF2, kdf.Type)
	}

	if kdf.Hash != "sha256" {
		t.Fatalf("Expected hash sha256, got %s", kdf.Hash)
	}
}

// TestCreateKDFPBKDF2SHA384Alias tests creating PBKDF2 with SHA-384 using type alias
func TestCreateKDFPBKDF2SHA384Alias(t *testing.T) {
	opts := FormatOptions{
		KDFType:       KDFTypePBKDF2SHA384,
		PBKDFIterTime: 100,
	}

	kdf, err := CreateKDF(opts, 48)
	if err != nil {
		t.Fatalf("CreateKDF with pbkdf2-sha384 failed: %v", err)
	}

	if kdf.Type != KDFTypePBKDF2 {
		t.Fatalf("Expected type %s, got %s", KDFTypePBKDF2, kdf.Type)
	}

	if kdf.Hash != "sha384" {
		t.Fatalf("Expected hash sha384, got %s", kdf.Hash)
	}
}

// TestCreateKDFPBKDF2SHA512Alias tests creating PBKDF2 with SHA-512 using type alias
func TestCreateKDFPBKDF2SHA512Alias(t *testing.T) {
	opts := FormatOptions{
		KDFType:       KDFTypePBKDF2SHA512,
		PBKDFIterTime: 100,
	}

	kdf, err := CreateKDF(opts, 64)
	if err != nil {
		t.Fatalf("CreateKDF with pbkdf2-sha512 failed: %v", err)
	}

	if kdf.Type != KDFTypePBKDF2 {
		t.Fatalf("Expected type %s, got %s", KDFTypePBKDF2, kdf.Type)
	}

	if kdf.Hash != "sha512" {
		t.Fatalf("Expected hash sha512, got %s", kdf.Hash)
	}
}

// TestCreateKDFCaseInsensitive tests that KDF type is case-insensitive
func TestCreateKDFCaseInsensitive(t *testing.T) {
	tests := []string{
		"PBKDF2-SHA256",
		"Pbkdf2-Sha256",
		"PBKDF2-sha256",
		"pbkdf2-SHA256",
	}

	for _, kdfType := range tests {
		t.Run(kdfType, func(t *testing.T) {
			opts := FormatOptions{
				KDFType:       kdfType,
				PBKDFIterTime: 100,
			}

			kdf, err := CreateKDF(opts, 32)
			if err != nil {
				t.Fatalf("CreateKDF with %s failed: %v", kdfType, err)
			}

			if kdf.Hash != "sha256" {
				t.Fatalf("Expected hash sha256, got %s", kdf.Hash)
			}
		})
	}
}

// TestCreateKDFWithHashOverride tests that explicit HashAlgo overrides type alias
func TestCreateKDFWithHashOverride(t *testing.T) {
	opts := FormatOptions{
		KDFType:       KDFTypePBKDF2SHA256, // Would normally use sha256
		HashAlgo:      "sha512",            // Override to sha512
		PBKDFIterTime: 100,
	}

	kdf, err := CreateKDF(opts, 64)
	if err != nil {
		t.Fatalf("CreateKDF with hash override failed: %v", err)
	}

	if kdf.Hash != "sha512" {
		t.Fatalf("Expected hash sha512 (override), got %s", kdf.Hash)
	}
}

// TestPBKDF2HashFunctionsDifferent tests that different hash functions produce different keys
func TestPBKDF2HashFunctionsDifferent(t *testing.T) {
	iterations := 1000
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)
	passphrase := []byte("testpassphrase")
	keySize := 32

	hashAlgos := []string{"sha1", "sha256", "sha384", "sha512"}
	keys := make(map[string][]byte)

	for _, hashAlgo := range hashAlgos {
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       hashAlgo,
			Salt:       saltB64,
			Iterations: &iterations,
		}

		key, err := DeriveKey(passphrase, kdf, keySize)
		if err != nil {
			t.Fatalf("DeriveKey with %s failed: %v", hashAlgo, err)
		}

		keys[hashAlgo] = key
	}

	// Verify all keys are different
	for algo1, key1 := range keys {
		for algo2, key2 := range keys {
			if algo1 != algo2 && bytes.Equal(key1, key2) {
				t.Errorf("Keys for %s and %s should be different but are equal", algo1, algo2)
			}
		}
	}
}

// TestGetPBKDF2HashFunc tests the hash function getter directly
func TestGetPBKDF2HashFunc(t *testing.T) {
	tests := []struct {
		hashAlgo    string
		expectError bool
	}{
		{"sha1", false},
		{"SHA1", false},
		{"sha256", false},
		{"SHA256", false},
		{"sha384", false},
		{"SHA384", false},
		{"sha512", false},
		{"SHA512", false},
		{"md5", true},    // Not supported
		{"sha224", true}, // Not supported
		{"", true},
		{"unknown", true},
	}

	for _, tt := range tests {
		t.Run(tt.hashAlgo, func(t *testing.T) {
			hashFunc, err := getPBKDF2HashFunc(tt.hashAlgo)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for hash %q, got nil", tt.hashAlgo)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for hash %q: %v", tt.hashAlgo, err)
				}
				if hashFunc == nil {
					t.Errorf("Expected non-nil hash function for %q", tt.hashAlgo)
				}
			}
		})
	}
}

// TestArgon2CPUsBoundsValidation tests Argon2 CPUs bounds checking
func TestArgon2CPUsBoundsValidation(t *testing.T) {
	salt := []byte("testsalt12345678")
	saltB64 := encodeBase64(salt)
	passphrase := []byte("testpassphrase")
	time := 1
	memory := 64 * 1024

	tests := []struct {
		name        string
		cpus        int
		expectError bool
	}{
		{"cpus_0", 0, true},
		{"cpus_1", 1, false},
		{"cpus_128", 128, false},
		{"cpus_255", 255, false},
		{"cpus_256", 256, true},
		{"cpus_negative", -1, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpus := tt.cpus
			kdf := &KDF{
				Type:   "argon2id",
				Salt:   saltB64,
				Time:   &time,
				Memory: &memory,
				CPUs:   &cpus,
			}

			_, err := DeriveKey(passphrase, kdf, 32)
			if tt.expectError && err == nil {
				t.Error("Expected error, got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
			}
		})
	}
}

// TestFIPSCompliantKDFWorkflow tests a complete FIPS-compliant workflow
func TestFIPSCompliantKDFWorkflow(t *testing.T) {
	// Step 1: Verify the KDF type is FIPS-compliant
	kdfType := KDFTypePBKDF2SHA256
	if !IsFIPSCompliantKDF(kdfType) {
		t.Fatalf("%s should be FIPS compliant", kdfType)
	}

	// Step 2: Create a KDF with FIPS-compliant settings
	opts := FormatOptions{
		KDFType:       kdfType,
		PBKDFIterTime: 100, // Short time for test
	}

	kdf, err := CreateKDF(opts, 32)
	if err != nil {
		t.Fatalf("CreateKDF failed: %v", err)
	}

	// Step 3: Verify the created KDF has expected properties
	if kdf.Type != KDFTypePBKDF2 {
		t.Fatalf("Expected type %s, got %s", KDFTypePBKDF2, kdf.Type)
	}

	if kdf.Hash != "sha256" {
		t.Fatalf("Expected hash sha256, got %s", kdf.Hash)
	}

	// Step 4: Use the KDF to derive a key
	passphrase := []byte("FIPS-compliant-passphrase")
	key, err := DeriveKey(passphrase, kdf, 32)
	if err != nil {
		t.Fatalf("DeriveKey failed: %v", err)
	}

	if len(key) != 32 {
		t.Fatalf("Expected 32-byte key, got %d bytes", len(key))
	}

	// Step 5: Verify deterministic derivation
	key2, err := DeriveKey(passphrase, kdf, 32)
	if err != nil {
		t.Fatalf("Second DeriveKey failed: %v", err)
	}

	if !bytes.Equal(key, key2) {
		t.Fatal("Key derivation should be deterministic")
	}
}

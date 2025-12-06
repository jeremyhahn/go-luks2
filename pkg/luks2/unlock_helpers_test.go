// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"testing"
)

// TestParseIVTweak tests parsing IV tweak values from strings
func TestParseIVTweak(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected uint64
	}{
		{
			name:     "zero value",
			input:    "0",
			expected: 0,
		},
		{
			name:     "small positive value",
			input:    "42",
			expected: 42,
		},
		{
			name:     "typical sector offset",
			input:    "4096",
			expected: 4096,
		},
		{
			name:     "large value",
			input:    "1048576",
			expected: 1048576,
		},
		{
			name:     "max uint64",
			input:    "18446744073709551615",
			expected: 18446744073709551615,
		},
		{
			name:     "empty string",
			input:    "",
			expected: 0, // strconv.ParseUint returns 0 on error
		},
		{
			name:     "invalid characters",
			input:    "invalid",
			expected: 0, // strconv.ParseUint returns 0 on error
		},
		{
			name:     "negative value",
			input:    "-1",
			expected: 0, // strconv.ParseUint returns 0 on error
		},
		{
			name:     "overflow uint64",
			input:    "18446744073709551616", // max uint64 + 1
			expected: 18446744073709551615,   // strconv.ParseUint returns max uint64 on overflow
		},
		{
			name:     "hexadecimal notation",
			input:    "0x100",
			expected: 0, // parseIVTweak uses base 10, not hex
		},
		{
			name:     "whitespace",
			input:    "  123  ",
			expected: 0, // strconv.ParseUint fails with whitespace
		},
		{
			name:     "leading zeros",
			input:    "000123",
			expected: 123,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseIVTweak(tt.input)
			if result != tt.expected {
				t.Errorf("parseIVTweak(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

// TestVerifyMasterKey tests master key verification against digests
func TestVerifyMasterKey(t *testing.T) {
	// Create a known master key for testing
	testMasterKey := []byte("test-master-key-32-bytes-long!!!")

	t.Run("valid master key with pbkdf2 digest", func(t *testing.T) {
		// Derive the expected digest from the test master key
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		expectedDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(expectedDigest),
			},
		}

		err = verifyMasterKey(testMasterKey, digests)
		if err != nil {
			t.Errorf("verifyMasterKey failed with valid key: %v", err)
		}
	})

	t.Run("invalid master key", func(t *testing.T) {
		invalidKey := []byte("wrong-master-key-32-bytes-long!!")
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		// Derive digest from correct key
		correctDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(correctDigest),
			},
		}

		err = verifyMasterKey(invalidKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid key")
		}
		if err.Error() != "master key verification failed" {
			t.Errorf("Expected 'master key verification failed', got: %v", err)
		}
	})

	t.Run("empty master key", func(t *testing.T) {
		emptyKey := []byte{}
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(emptyKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with empty key")
		}
	})

	t.Run("nil master key", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(nil, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with nil key")
		}
	})

	t.Run("empty digests map", func(t *testing.T) {
		digests := map[string]*Digest{}

		err := verifyMasterKey(testMasterKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with empty digests map")
		}
		if err.Error() != "master key verification failed" {
			t.Errorf("Expected 'master key verification failed', got: %v", err)
		}
	})

	t.Run("nil digests map", func(t *testing.T) {
		err := verifyMasterKey(testMasterKey, nil)
		if err == nil {
			t.Error("verifyMasterKey should fail with nil digests map")
		}
	})

	t.Run("multiple digests, first invalid, second valid", func(t *testing.T) {
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		validDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64([]byte("invalid-digest-value-32-bytes!!")),
			},
			"1": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(validDigest),
			},
		}

		err = verifyMasterKey(testMasterKey, digests)
		if err != nil {
			t.Errorf("verifyMasterKey failed with at least one valid digest: %v", err)
		}
	})

	t.Run("invalid base64 in digest", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     "!!!invalid-base64!!!",
			},
		}

		err := verifyMasterKey(testMasterKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid base64 digest")
		}
	})

	t.Run("invalid hash algorithm", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "invalid-hash",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(testMasterKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid hash algorithm")
		}
	})

	t.Run("sha512 hash algorithm", func(t *testing.T) {
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha512",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		expectedDigest, err := DeriveKey(testMasterKey, kdf, 32)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha512",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(expectedDigest),
			},
		}

		err = verifyMasterKey(testMasterKey, digests)
		if err != nil {
			t.Errorf("verifyMasterKey failed with sha512: %v", err)
		}
	})

	t.Run("zero iterations", func(t *testing.T) {
		iterations := 0

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       encodeBase64([]byte("test-salt-16byte")),
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(testMasterKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should handle zero iterations")
		}
	})

	t.Run("invalid base64 in salt", func(t *testing.T) {
		iterations := 1000

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       "!!!invalid-base64!!!",
				Iterations: iterations,
				Digest:     encodeBase64([]byte("some-digest-value-32-bytes!!!!!")),
			},
		}

		err := verifyMasterKey(testMasterKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with invalid base64 salt")
		}
	})

	t.Run("mismatched digest length", func(t *testing.T) {
		iterations := 1000
		kdf := &KDF{
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       encodeBase64([]byte("test-salt-16byte")),
			Iterations: &iterations,
		}

		// Derive with different length than expected (64 bytes instead of 32)
		wrongLengthDigest, err := DeriveKey(testMasterKey, kdf, 64)
		if err != nil {
			t.Fatalf("Failed to derive test digest: %v", err)
		}

		digests := map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Hash:       "sha256",
				Salt:       kdf.Salt,
				Iterations: iterations,
				Digest:     encodeBase64(wrongLengthDigest),
			},
		}

		err = verifyMasterKey(testMasterKey, digests)
		if err == nil {
			t.Error("verifyMasterKey should fail with mismatched digest length")
		}
	})
}

// TestVerifyMasterKeyDoesNotModifyInput tests that verifyMasterKey doesn't modify the input
func TestVerifyMasterKeyDoesNotModifyInput(t *testing.T) {
	testMasterKey := []byte("test-master-key-32-bytes-long!!!")
	originalKey := make([]byte, len(testMasterKey))
	copy(originalKey, testMasterKey)

	iterations := 1000
	kdf := &KDF{
		Type:       "pbkdf2",
		Hash:       "sha256",
		Salt:       encodeBase64([]byte("test-salt-16byte")),
		Iterations: &iterations,
	}

	expectedDigest, err := DeriveKey(testMasterKey, kdf, 32)
	if err != nil {
		t.Fatalf("Failed to derive test digest: %v", err)
	}

	digests := map[string]*Digest{
		"0": {
			Type:       "pbkdf2",
			Hash:       "sha256",
			Salt:       kdf.Salt,
			Iterations: iterations,
			Digest:     encodeBase64(expectedDigest),
		},
	}

	_ = verifyMasterKey(testMasterKey, digests)

	if !bytes.Equal(testMasterKey, originalKey) {
		t.Error("verifyMasterKey modified the input master key")
	}
}

/*
 * Note: The following functions in unlock.go are not easily testable in unit tests
 * because they require actual device I/O or system resources:
 *
 * - unlockKeyslot: Requires reading from a real LUKS device
 * - getBlockDeviceSize: Requires a real block device or file descriptor
 * - Unlock: Requires a real LUKS device and device-mapper interaction
 * - Lock: Requires device-mapper interaction
 * - IsUnlocked: Requires checking /dev/mapper
 *
 * These functions should be tested in integration tests with a real or mocked
 * LUKS device in a containerized environment.
 */

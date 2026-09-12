// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"testing"
)

// afSplitPlain runs afSplitEnclave over a copy of data held in a throwaway
// test enclave and returns the stripes as a plain slice, so the table-driven
// tests below can assert on bytes the same way they always have.
func afSplitPlain(t *testing.T, data []byte, stripes int, hashAlgo string) ([]byte, error) {
	t.Helper()

	secret := enclaveFrom(t, data)
	split, err := afSplitEnclave(secret, stripes, hashAlgo)
	if err != nil {
		return nil, err
	}
	defer split.Destroy()

	return openSecret(t, split), nil
}

// afMergePlain is afSplitPlain's counterpart for afMergeEnclave.
func afMergePlain(t *testing.T, splitData []byte, stripes, blockSize int, hashAlgo string) ([]byte, error) {
	t.Helper()

	held := enclaveFrom(t, splitData)
	merged, err := afMergeEnclave(held, len(splitData), stripes, blockSize, hashAlgo)
	if err != nil {
		return nil, err
	}
	defer merged.Destroy()

	return openSecret(t, merged), nil
}

// TestAFSplitEnclaveValidSizes tests afSplitEnclave with valid inputs.
func TestAFSplitEnclaveValidSizes(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int
		stripes  int
		hashAlgo string
	}{
		{"32byte_2stripes_sha256", 32, 2, "sha256"},
		{"32byte_4stripes_sha256", 32, 4, "sha256"},
		{"32byte_10stripes_sha256", 32, 10, "sha256"},
		{"32byte_4000stripes_sha256", 32, 4000, "sha256"},
		{"64byte_2stripes_sha512", 64, 2, "sha512"},
		{"64byte_4stripes_sha512", 64, 4, "sha512"},
		{"64byte_10stripes_sha512", 64, 10, "sha512"},
		{"16byte_2stripes_sha256", 16, 2, "sha256"},
		{"128byte_8stripes_sha512", 128, 8, "sha512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			result, err := afSplitPlain(t, data, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afSplitEnclave failed: %v", err)
			}

			expectedSize := tt.dataSize * tt.stripes
			if len(result) != expectedSize {
				t.Fatalf("Expected result size %d, got %d", expectedSize, len(result))
			}
		})
	}
}

// TestAFSplitEnclaveInvalidStripes tests afSplitEnclave with invalid stripe counts.
func TestAFSplitEnclaveInvalidStripes(t *testing.T) {
	tests := []struct {
		name    string
		stripes int
	}{
		{"zero_stripes", 0},
		{"negative_stripes", -1},
		{"negative_large", -100},
	}

	data := make([]byte, 32)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := afSplitPlain(t, data, tt.stripes, "sha256")
			if err == nil {
				t.Fatal("Expected error for invalid stripes, got nil")
			}
		})
	}
}

// TestAFSplitEnclaveInvalidHash tests afSplitEnclave with invalid hash algorithms.
func TestAFSplitEnclaveInvalidHash(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo string
	}{
		{"sha1", "sha1"},
		{"md5", "md5"},
		{"invalid", "invalid"},
		{"empty", ""},
		{"sha384", "sha384"},
	}

	data := make([]byte, 32)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := afSplitPlain(t, data, 4, tt.hashAlgo)
			if err == nil {
				t.Fatalf("Expected error for invalid hash algorithm %s, got nil", tt.hashAlgo)
			}
		})
	}
}

// TestAFMergeEnclaveValidSizes tests afMergeEnclave with valid inputs.
func TestAFMergeEnclaveValidSizes(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int
		stripes  int
		hashAlgo string
	}{
		{"32byte_2stripes_sha256", 32, 2, "sha256"},
		{"32byte_4stripes_sha256", 32, 4, "sha256"},
		{"64byte_2stripes_sha512", 64, 2, "sha512"},
		{"64byte_4stripes_sha512", 64, 4, "sha512"},
		{"16byte_8stripes_sha256", 16, 8, "sha256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create split data
			data := make([]byte, tt.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			splitData, err := afSplitPlain(t, data, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afSplitEnclave failed: %v", err)
			}

			// Merge it back
			merged, err := afMergePlain(t, splitData, tt.stripes, tt.dataSize, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afMergeEnclave failed: %v", err)
			}

			if len(merged) != tt.dataSize {
				t.Fatalf("Expected merged size %d, got %d", tt.dataSize, len(merged))
			}
		})
	}
}

// TestAFMergeEnclaveInvalidSize tests afMergeEnclave with invalid size parameters.
func TestAFMergeEnclaveInvalidSize(t *testing.T) {
	tests := []struct {
		name      string
		splitSize int
		blockSize int
		stripes   int
	}{
		{"mismatch_smaller", 128, 32, 5}, // 128 != 32*5=160
		{"mismatch_larger", 128, 32, 3},  // 128 != 32*3=96
		{"zero_blocksize", 128, 0, 4},    // 128 != 0*4=0
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			splitData := make([]byte, tt.splitSize)
			_, err := afMergePlain(t, splitData, tt.stripes, tt.blockSize, "sha256")
			if err == nil {
				t.Fatal("Expected error for invalid size, got nil")
			}
		})
	}
}

// TestAFMergeEnclaveInvalidHash tests afMergeEnclave with invalid hash algorithms.
func TestAFMergeEnclaveInvalidHash(t *testing.T) {
	tests := []struct {
		name     string
		hashAlgo string
	}{
		{"sha1", "sha1"},
		{"md5", "md5"},
		{"invalid", "invalid"},
		{"empty", ""},
	}

	splitData := make([]byte, 128)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := afMergePlain(t, splitData, 4, 32, tt.hashAlgo)
			if err == nil {
				t.Fatalf("Expected error for invalid hash algorithm %s, got nil", tt.hashAlgo)
			}
		})
	}
}

// TestAFEnclaveRoundTrip tests that afSplitEnclave followed by afMergeEnclave
// recovers original data.
func TestAFEnclaveRoundTrip(t *testing.T) {
	tests := []struct {
		name     string
		dataSize int
		stripes  int
		hashAlgo string
	}{
		{"32byte_2stripes_sha256", 32, 2, "sha256"},
		{"32byte_4stripes_sha256", 32, 4, "sha256"},
		{"32byte_10stripes_sha256", 32, 10, "sha256"},
		{"32byte_4000stripes_sha256", 32, 4000, "sha256"},
		{"64byte_2stripes_sha512", 64, 2, "sha512"},
		{"64byte_4stripes_sha512", 64, 4, "sha512"},
		{"64byte_10stripes_sha512", 64, 10, "sha512"},
		{"16byte_2stripes_sha256", 16, 2, "sha256"},
		{"16byte_8stripes_sha256", 16, 8, "sha256"},
		{"128byte_4stripes_sha512", 128, 4, "sha512"},
		{"256byte_8stripes_sha256", 256, 8, "sha256"},
		{"1byte_2stripes_sha256", 1, 2, "sha256"},
		{"7byte_3stripes_sha512", 7, 3, "sha512"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate original data
			original := make([]byte, tt.dataSize)
			if _, err := rand.Read(original); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			// Split the data
			splitData, err := afSplitPlain(t, original, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afSplitEnclave failed: %v", err)
			}

			// Merge it back
			recovered, err := afMergePlain(t, splitData, tt.stripes, tt.dataSize, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afMergeEnclave failed: %v", err)
			}

			// Verify recovered data matches original
			if !bytes.Equal(original, recovered) {
				t.Fatal("Recovered data doesn't match original")
			}
		})
	}
}

// TestAFEnclaveRoundTripKnownData tests round-trip with known data patterns.
func TestAFEnclaveRoundTripKnownData(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		stripes  int
		hashAlgo string
	}{
		{"all_zeros", make([]byte, 32), 4, "sha256"},
		{"all_ones", bytes.Repeat([]byte{0xFF}, 32), 4, "sha256"},
		{"pattern_aa", bytes.Repeat([]byte{0xAA}, 32), 4, "sha512"},
		{"pattern_55", bytes.Repeat([]byte{0x55}, 64), 8, "sha512"},
		{"sequential", []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, 2, "sha256"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Split the data
			splitData, err := afSplitPlain(t, tt.data, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afSplitEnclave failed: %v", err)
			}

			// Merge it back
			recovered, err := afMergePlain(t, splitData, tt.stripes, len(tt.data), tt.hashAlgo)
			if err != nil {
				t.Fatalf("afMergeEnclave failed: %v", err)
			}

			// Verify recovered data matches original
			if !bytes.Equal(tt.data, recovered) {
				t.Fatal("Recovered data doesn't match original")
			}
		})
	}
}

// TestHashBlock tests the hashBlockInto function
func TestHashBlock(t *testing.T) {
	tests := []struct {
		name  string
		block []byte
		iv    int
	}{
		{"empty_block", []byte{}, 0},
		{"single_byte", []byte{0x42}, 0},
		{"iv_zero", []byte{1, 2, 3, 4}, 0},
		{"iv_one", []byte{1, 2, 3, 4}, 1},
		{"iv_large", []byte{1, 2, 3, 4}, 12345},
		{"16byte_block", make([]byte, 16), 0},
		{"32byte_block", make([]byte, 32), 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := sha256.New()
			result := hashBlockInto(nil, tt.block, h, tt.iv)

			if len(result) != sha256.Size {
				t.Fatalf("Expected hash size %d, got %d", sha256.Size, len(result))
			}

			// Verify different IVs produce different hashes for same block
			if tt.iv == 0 {
				result2 := hashBlockInto(nil, tt.block, sha256.New(), 1)
				if bytes.Equal(result, result2) && len(tt.block) > 0 {
					t.Fatal("Same hash for different IVs")
				}
			}
		})
	}
}

// TestHashBlockDeterministic tests that hashBlockInto is deterministic
func TestHashBlockDeterministic(t *testing.T) {
	block := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	iv := 42

	h1 := sha256.New()
	result1 := hashBlockInto(nil, block, h1, iv)

	h2 := sha256.New()
	result2 := hashBlockInto(nil, block, h2, iv)

	if !bytes.Equal(result1, result2) {
		t.Fatal("hashBlockInto is not deterministic")
	}
}

// TestXorBytes tests the xorBytes function
func TestXorBytes(t *testing.T) {
	tests := []struct {
		name     string
		a        []byte
		b        []byte
		expected []byte
	}{
		{
			"all_zeros",
			[]byte{0x00, 0x00, 0x00, 0x00},
			[]byte{0x00, 0x00, 0x00, 0x00},
			[]byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			"identity",
			[]byte{0xFF, 0xAA, 0x55, 0x00},
			[]byte{0x00, 0x00, 0x00, 0x00},
			[]byte{0xFF, 0xAA, 0x55, 0x00},
		},
		{
			"same_values",
			[]byte{0xFF, 0xAA, 0x55, 0xCC},
			[]byte{0xFF, 0xAA, 0x55, 0xCC},
			[]byte{0x00, 0x00, 0x00, 0x00},
		},
		{
			"all_ones",
			[]byte{0xFF, 0xFF, 0xFF, 0xFF},
			[]byte{0xAA, 0x55, 0xCC, 0x33},
			[]byte{0x55, 0xAA, 0x33, 0xCC},
		},
		{
			"pattern",
			[]byte{0xAA, 0xAA, 0xAA, 0xAA},
			[]byte{0x55, 0x55, 0x55, 0x55},
			[]byte{0xFF, 0xFF, 0xFF, 0xFF},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dest := make([]byte, len(tt.expected))
			xorBytes(tt.a, tt.b, dest)

			if !bytes.Equal(dest, tt.expected) {
				t.Fatalf("Expected %v, got %v", tt.expected, dest)
			}
		})
	}
}

// TestXorBytesInPlace tests XOR operations with in-place updates
func TestXorBytesInPlace(t *testing.T) {
	a := []byte{0xFF, 0xAA, 0x55, 0x00}
	b := []byte{0x0F, 0xF0, 0x55, 0xFF}
	expected := []byte{0xF0, 0x5A, 0x00, 0xFF}

	// XOR into a (in-place)
	xorBytes(a, b, a)

	if !bytes.Equal(a, expected) {
		t.Fatalf("Expected %v, got %v", expected, a)
	}
}

// TestXorBytesCommutative tests that XOR is commutative
func TestXorBytesCommutative(t *testing.T) {
	a := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	b := []byte{0x12, 0x34, 0x56, 0x78}

	dest1 := make([]byte, len(a))
	dest2 := make([]byte, len(a))

	xorBytes(a, b, dest1)
	xorBytes(b, a, dest2)

	if !bytes.Equal(dest1, dest2) {
		t.Fatal("XOR is not commutative")
	}
}

// TestXorBytesInverse tests that XOR is its own inverse
func TestXorBytesInverse(t *testing.T) {
	original := []byte{0xAA, 0xBB, 0xCC, 0xDD}
	key := []byte{0x12, 0x34, 0x56, 0x78}

	encrypted := make([]byte, len(original))
	xorBytes(original, key, encrypted)

	decrypted := make([]byte, len(original))
	xorBytes(encrypted, key, decrypted)

	if !bytes.Equal(original, decrypted) {
		t.Fatal("XOR is not its own inverse")
	}
}

// TestDiffuseViaAFEnclave tests the diffuse function via afSplitEnclave/afMergeEnclave
func TestDiffuseViaAFEnclave(t *testing.T) {
	tests := []struct {
		name      string
		blockSize int
		hashAlgo  string
	}{
		{"32byte_sha256", 32, "sha256"},
		{"64byte_sha512", 64, "sha512"},
		{"16byte_sha256", 16, "sha256"},
		{"33byte_sha256", 33, "sha256"}, // Not multiple of hash size
		{"65byte_sha512", 65, "sha512"}, // Not multiple of hash size
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.blockSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			// Split and merge - this exercises diffuse internally
			splitData, err := afSplitPlain(t, data, 4, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afSplitEnclave failed: %v", err)
			}

			recovered, err := afMergePlain(t, splitData, 4, tt.blockSize, tt.hashAlgo)
			if err != nil {
				t.Fatalf("afMergeEnclave failed: %v", err)
			}

			if !bytes.Equal(data, recovered) {
				t.Fatal("Diffuse function affected round-trip recovery")
			}
		})
	}
}

// TestDiffuseModifiesData tests that diffuse actually modifies the data
func TestDiffuseModifiesData(t *testing.T) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	original := make([]byte, len(data))
	copy(original, data)

	hashFunc, err := getHashFunc("sha256")
	if err != nil {
		t.Fatalf("Failed to get hash function: %v", err)
	}

	diffuse(data, hashFunc, len(data))

	// Diffuse should modify the data
	if bytes.Equal(data, original) {
		t.Fatal("Diffuse did not modify the data")
	}
}

// TestAFSplitEnclaveDifferentOutput tests that afSplitEnclave produces
// different output each time.
func TestAFSplitEnclaveDifferentOutput(t *testing.T) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	split1, err := afSplitPlain(t, data, 4, "sha256")
	if err != nil {
		t.Fatalf("afSplitEnclave failed: %v", err)
	}

	split2, err := afSplitPlain(t, data, 4, "sha256")
	if err != nil {
		t.Fatalf("afSplitEnclave failed: %v", err)
	}

	// Due to randomness, splits should be different
	if bytes.Equal(split1, split2) {
		t.Fatal("afSplitEnclave produced identical output for same input (extremely unlikely)")
	}

	// But both should recover to the same original data
	recovered1, err := afMergePlain(t, split1, 4, 32, "sha256")
	if err != nil {
		t.Fatalf("afMergeEnclave failed: %v", err)
	}

	recovered2, err := afMergePlain(t, split2, 4, 32, "sha256")
	if err != nil {
		t.Fatalf("afMergeEnclave failed: %v", err)
	}

	if !bytes.Equal(recovered1, recovered2) || !bytes.Equal(recovered1, data) {
		t.Fatal("Different splits did not recover to same original data")
	}
}

// TestAFSplitEnclaveHashAlgorithms tests different hash algorithms produce
// different splits.
func TestAFSplitEnclaveHashAlgorithms(t *testing.T) {
	data := make([]byte, 64) // Use 64 bytes to work well with both sha256 and sha512
	for i := range data {
		data[i] = byte(i)
	}

	split256, err := afSplitPlain(t, data, 4, "sha256")
	if err != nil {
		t.Fatalf("afSplitEnclave with sha256 failed: %v", err)
	}

	split512, err := afSplitPlain(t, data, 4, "sha512")
	if err != nil {
		t.Fatalf("afSplitEnclave with sha512 failed: %v", err)
	}

	// The splits should be different due to different hash algorithms
	// (though this is not guaranteed due to randomness, it's very likely)
	if bytes.Equal(split256, split512) {
		t.Log("Warning: Different hash algorithms produced identical splits (very unlikely but possible)")
	}

	// But both should recover correctly
	recovered256, err := afMergePlain(t, split256, 4, 64, "sha256")
	if err != nil {
		t.Fatalf("afMergeEnclave with sha256 failed: %v", err)
	}

	recovered512, err := afMergePlain(t, split512, 4, 64, "sha512")
	if err != nil {
		t.Fatalf("afMergeEnclave with sha512 failed: %v", err)
	}

	if !bytes.Equal(recovered256, data) {
		t.Fatal("sha256 did not recover original data")
	}

	if !bytes.Equal(recovered512, data) {
		t.Fatal("sha512 did not recover original data")
	}
}

// TestAFMergeEnclaveWrongHashAlgo tests that using the wrong hash algo in a
// merge fails to recover.
func TestAFMergeEnclaveWrongHashAlgo(t *testing.T) {
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Split with sha256
	splitData, err := afSplitPlain(t, data, 4, "sha256")
	if err != nil {
		t.Fatalf("afSplitEnclave failed: %v", err)
	}

	// Try to merge with sha512 (wrong hash)
	recovered, err := afMergePlain(t, splitData, 4, 64, "sha512")
	if err != nil {
		t.Fatalf("afMergeEnclave failed: %v", err)
	}

	// Should not recover the original data
	if bytes.Equal(recovered, data) {
		t.Fatal("Wrong hash algorithm unexpectedly recovered correct data")
	}
}

// TestAFSplitEnclaveSingleStripe tests edge case with single stripe
func TestAFSplitEnclaveSingleStripe(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := afSplitPlain(t, data, 1, "sha256")
	// Single stripe should work - the last block would just be XOR'd with zeros
	if err != nil {
		t.Fatalf("afSplitEnclave with single stripe failed: %v", err)
	}
}

// TestHashBlockWithSHA512 tests hashBlockInto with SHA512
func TestHashBlockWithSHA512(t *testing.T) {
	block := []byte("test data for sha512")
	iv := 100

	h := sha512.New()
	result := hashBlockInto(nil, block, h, iv)

	if len(result) != sha512.Size {
		t.Fatalf("Expected hash size %d, got %d", sha512.Size, len(result))
	}

	// Verify deterministic
	result2 := hashBlockInto(nil, block, sha512.New(), iv)
	if !bytes.Equal(result, result2) {
		t.Fatal("hashBlockInto with SHA512 is not deterministic")
	}
}

// TestAFSplitAndMergeEnclaveReportAnUnsupportedHash pins ErrUnsupportedHash on
// the anti-forensic path, which has its own hash dispatch (#70). Both
// directions are checked: a split and a merge reach getHashFunc separately,
// and a fix applied to one of them would otherwise look complete.
func TestAFSplitAndMergeEnclaveReportAnUnsupportedHash(t *testing.T) {
	if _, err := afSplitPlain(t, make([]byte, 32), 4, "md5"); !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("afSplitEnclave = %v, want an error wrapping ErrUnsupportedHash", err)
	}
	if _, err := afMergePlain(t, make([]byte, 128), 4, 32, "md5"); !errors.Is(err, ErrUnsupportedHash) {
		t.Fatalf("afMergeEnclave = %v, want an error wrapping ErrUnsupportedHash", err)
	}
}

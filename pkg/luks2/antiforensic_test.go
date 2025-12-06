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
	"testing"
)

// TestAFSplitValid tests AFSplit with valid inputs
func TestAFSplitValid(t *testing.T) {
	tests := []struct {
		name      string
		dataSize  int
		stripes   int
		hashAlgo  string
		expectErr bool
	}{
		{"32byte_2stripes_sha256", 32, 2, "sha256", false},
		{"32byte_4stripes_sha256", 32, 4, "sha256", false},
		{"32byte_10stripes_sha256", 32, 10, "sha256", false},
		{"32byte_4000stripes_sha256", 32, 4000, "sha256", false},
		{"64byte_2stripes_sha512", 64, 2, "sha512", false},
		{"64byte_4stripes_sha512", 64, 4, "sha512", false},
		{"64byte_10stripes_sha512", 64, 10, "sha512", false},
		{"16byte_2stripes_sha256", 16, 2, "sha256", false},
		{"128byte_8stripes_sha512", 128, 8, "sha512", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.dataSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatalf("Failed to generate test data: %v", err)
			}

			result, err := AFSplit(data, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFSplit failed: %v", err)
			}

			expectedSize := tt.dataSize * tt.stripes
			if len(result) != expectedSize {
				t.Fatalf("Expected result size %d, got %d", expectedSize, len(result))
			}
		})
	}
}

// TestAFSplitInvalidStripes tests AFSplit with invalid stripe counts
func TestAFSplitInvalidStripes(t *testing.T) {
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
			_, err := AFSplit(data, tt.stripes, "sha256")
			if err == nil {
				t.Fatal("Expected error for invalid stripes, got nil")
			}
		})
	}
}

// TestAFSplitInvalidHash tests AFSplit with invalid hash algorithm
func TestAFSplitInvalidHash(t *testing.T) {
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
			_, err := AFSplit(data, 4, tt.hashAlgo)
			if err == nil {
				t.Fatalf("Expected error for invalid hash algorithm %s, got nil", tt.hashAlgo)
			}
		})
	}
}

// TestAFSplitEmptyData tests AFSplit with empty data
func TestAFSplitEmptyData(t *testing.T) {
	data := make([]byte, 0)
	result, err := AFSplit(data, 4, "sha256")
	if err != nil {
		t.Fatalf("AFSplit failed on empty data: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("Expected empty result for empty data, got %d bytes", len(result))
	}
}

// TestAFMergeValid tests AFMerge with valid inputs
func TestAFMergeValid(t *testing.T) {
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

			splitData, err := AFSplit(data, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFSplit failed: %v", err)
			}

			// Merge it back
			merged, err := AFMerge(splitData, tt.stripes, tt.dataSize, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFMerge failed: %v", err)
			}

			if len(merged) != tt.dataSize {
				t.Fatalf("Expected merged size %d, got %d", tt.dataSize, len(merged))
			}
		})
	}
}

// TestAFMergeInvalidSize tests AFMerge with invalid size parameters
func TestAFMergeInvalidSize(t *testing.T) {
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
			_, err := AFMerge(splitData, tt.stripes, tt.blockSize, "sha256")
			if err == nil {
				t.Fatal("Expected error for invalid size, got nil")
			}
		})
	}
}

// TestAFMergeInvalidHash tests AFMerge with invalid hash algorithm
func TestAFMergeInvalidHash(t *testing.T) {
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
			_, err := AFMerge(splitData, 4, 32, tt.hashAlgo)
			if err == nil {
				t.Fatalf("Expected error for invalid hash algorithm %s, got nil", tt.hashAlgo)
			}
		})
	}
}

// TestAFRoundTrip tests that AFSplit followed by AFMerge recovers original data
func TestAFRoundTrip(t *testing.T) {
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
			splitData, err := AFSplit(original, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFSplit failed: %v", err)
			}

			// Merge it back
			recovered, err := AFMerge(splitData, tt.stripes, tt.dataSize, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFMerge failed: %v", err)
			}

			// Verify recovered data matches original
			if !bytes.Equal(original, recovered) {
				t.Fatal("Recovered data doesn't match original")
			}
		})
	}
}

// TestAFRoundTripKnownData tests round-trip with known data patterns
func TestAFRoundTripKnownData(t *testing.T) {
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
			splitData, err := AFSplit(tt.data, tt.stripes, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFSplit failed: %v", err)
			}

			// Merge it back
			recovered, err := AFMerge(splitData, tt.stripes, len(tt.data), tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFMerge failed: %v", err)
			}

			// Verify recovered data matches original
			if !bytes.Equal(tt.data, recovered) {
				t.Fatal("Recovered data doesn't match original")
			}
		})
	}
}

// TestHashBlock tests the hashBlock function
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
			result := hashBlock(tt.block, h, tt.iv)

			if len(result) != sha256.Size {
				t.Fatalf("Expected hash size %d, got %d", sha256.Size, len(result))
			}

			// Verify different IVs produce different hashes for same block
			if tt.iv == 0 {
				result2 := hashBlock(tt.block, sha256.New(), 1)
				if bytes.Equal(result, result2) && len(tt.block) > 0 {
					t.Fatal("Same hash for different IVs")
				}
			}
		})
	}
}

// TestHashBlockDeterministic tests that hashBlock is deterministic
func TestHashBlockDeterministic(t *testing.T) {
	block := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	iv := 42

	h1 := sha256.New()
	result1 := hashBlock(block, h1, iv)

	h2 := sha256.New()
	result2 := hashBlock(block, h2, iv)

	if !bytes.Equal(result1, result2) {
		t.Fatal("hashBlock is not deterministic")
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

// TestDiffuse tests the diffuse function via AFSplit/AFMerge
func TestDiffuse(t *testing.T) {
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
			splitData, err := AFSplit(data, 4, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFSplit failed: %v", err)
			}

			recovered, err := AFMerge(splitData, 4, tt.blockSize, tt.hashAlgo)
			if err != nil {
				t.Fatalf("AFMerge failed: %v", err)
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

// TestAFSplitDifferentOutput tests that AFSplit produces different output each time
func TestAFSplitDifferentOutput(t *testing.T) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	split1, err := AFSplit(data, 4, "sha256")
	if err != nil {
		t.Fatalf("AFSplit failed: %v", err)
	}

	split2, err := AFSplit(data, 4, "sha256")
	if err != nil {
		t.Fatalf("AFSplit failed: %v", err)
	}

	// Due to randomness, splits should be different
	if bytes.Equal(split1, split2) {
		t.Fatal("AFSplit produced identical output for same input (extremely unlikely)")
	}

	// But both should recover to the same original data
	recovered1, err := AFMerge(split1, 4, 32, "sha256")
	if err != nil {
		t.Fatalf("AFMerge failed: %v", err)
	}

	recovered2, err := AFMerge(split2, 4, 32, "sha256")
	if err != nil {
		t.Fatalf("AFMerge failed: %v", err)
	}

	if !bytes.Equal(recovered1, recovered2) || !bytes.Equal(recovered1, data) {
		t.Fatal("Different splits did not recover to same original data")
	}
}

// TestAFSplitHashAlgorithms tests different hash algorithms produce different splits
func TestAFSplitHashAlgorithms(t *testing.T) {
	data := make([]byte, 64) // Use 64 bytes to work well with both sha256 and sha512
	for i := range data {
		data[i] = byte(i)
	}

	split256, err := AFSplit(data, 4, "sha256")
	if err != nil {
		t.Fatalf("AFSplit with sha256 failed: %v", err)
	}

	split512, err := AFSplit(data, 4, "sha512")
	if err != nil {
		t.Fatalf("AFSplit with sha512 failed: %v", err)
	}

	// The splits should be different due to different hash algorithms
	// (though this is not guaranteed due to randomness, it's very likely)
	if bytes.Equal(split256, split512) {
		t.Log("Warning: Different hash algorithms produced identical splits (very unlikely but possible)")
	}

	// But both should recover correctly
	recovered256, err := AFMerge(split256, 4, 64, "sha256")
	if err != nil {
		t.Fatalf("AFMerge with sha256 failed: %v", err)
	}

	recovered512, err := AFMerge(split512, 4, 64, "sha512")
	if err != nil {
		t.Fatalf("AFMerge with sha512 failed: %v", err)
	}

	if !bytes.Equal(recovered256, data) {
		t.Fatal("sha256 did not recover original data")
	}

	if !bytes.Equal(recovered512, data) {
		t.Fatal("sha512 did not recover original data")
	}
}

// TestAFMergeWrongHashAlgo tests that using wrong hash algo in merge fails to recover
func TestAFMergeWrongHashAlgo(t *testing.T) {
	data := make([]byte, 64)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("Failed to generate test data: %v", err)
	}

	// Split with sha256
	splitData, err := AFSplit(data, 4, "sha256")
	if err != nil {
		t.Fatalf("AFSplit failed: %v", err)
	}

	// Try to merge with sha512 (wrong hash)
	recovered, err := AFMerge(splitData, 4, 64, "sha512")
	if err != nil {
		t.Fatalf("AFMerge failed: %v", err)
	}

	// Should not recover the original data
	if bytes.Equal(recovered, data) {
		t.Fatal("Wrong hash algorithm unexpectedly recovered correct data")
	}
}

// TestAFSplitSingleStripe tests edge case with single stripe
func TestAFSplitSingleStripe(t *testing.T) {
	data := []byte{0x01, 0x02, 0x03, 0x04}

	_, err := AFSplit(data, 1, "sha256")
	// Single stripe should work - the last block would just be XOR'd with zeros
	if err != nil {
		t.Fatalf("AFSplit with single stripe failed: %v", err)
	}
}

// TestHashBlockWithSHA512 tests hashBlock with SHA512
func TestHashBlockWithSHA512(t *testing.T) {
	block := []byte("test data for sha512")
	iv := 100

	h := sha512.New()
	result := hashBlock(block, h, iv)

	if len(result) != sha512.Size {
		t.Fatalf("Expected hash size %d, got %d", sha512.Size, len(result))
	}

	// Verify deterministic
	result2 := hashBlock(block, sha512.New(), iv)
	if !bytes.Equal(result, result2) {
		t.Fatal("hashBlock with SHA512 is not deterministic")
	}
}

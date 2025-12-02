// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"bytes"
	"testing"
)

// TestRandomBytes tests random byte generation
func TestRandomBytes(t *testing.T) {
	sizes := []int{16, 32, 64, 128}
	for _, size := range sizes {
		data1, err := randomBytes(size)
		if err != nil {
			t.Fatalf("randomBytes(%d) failed: %v", size, err)
		}
		if len(data1) != size {
			t.Fatalf("Expected %d bytes, got %d", size, len(data1))
		}

		// Verify randomness
		data2, err := randomBytes(size)
		if err != nil {
			t.Fatalf("randomBytes(%d) failed: %v", size, err)
		}
		if bytes.Equal(data1, data2) {
			t.Fatal("randomBytes returned identical values (not random)")
		}
	}
}

// TestRandomBase64 tests random base64 string generation
func TestRandomBase64(t *testing.T) {
	str1, err := randomBase64(32)
	if err != nil {
		t.Fatalf("randomBase64 failed: %v", err)
	}
	str2, err := randomBase64(32)
	if err != nil {
		t.Fatalf("randomBase64 failed: %v", err)
	}
	if str1 == str2 {
		t.Fatal("randomBase64 returned identical strings (should be random)")
	}
	if len(str1) == 0 {
		t.Fatal("randomBase64 returned empty string")
	}
}

// TestCreateKDF tests KDF object creation
func TestCreateKDF(t *testing.T) {
	tests := []struct {
		name    string
		kdfType string
		wantErr bool
	}{
		{"argon2id-default", "argon2id", false},
		{"pbkdf2", "pbkdf2", false},
		{"argon2i", "argon2i", false},
		{"unsupported", "scrypt", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := FormatOptions{
				KDFType:        tt.kdfType,
				PBKDFIterTime:  2000,
				Argon2Time:     4,
				Argon2Memory:   1048576,
				Argon2Parallel: 4,
				HashAlgo:       "sha256",
			}

			_, err := CreateKDF(opts, 32)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func intPtr(i int) *int {
	return &i
}

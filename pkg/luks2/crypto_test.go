// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"testing"
)

// TestRandomBytes tests random byte generation
func TestRandomBytes(t *testing.T) {
	sizes := []int{16, 32, 64, 128}
	for _, size := range sizes {
		data1, err := randomBytes(size, testVolumeSys().cryptoRand)
		if err != nil {
			t.Fatalf("randomBytes(%d) failed: %v", size, err)
		}
		if len(data1) != size {
			t.Fatalf("Expected %d bytes, got %d", size, len(data1))
		}

		// Verify randomness
		data2, err := randomBytes(size, testVolumeSys().cryptoRand)
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
	str1, err := randomBase64(32, testVolumeSys().cryptoRand)
	if err != nil {
		t.Fatalf("randomBase64 failed: %v", err)
	}
	str2, err := randomBase64(32, testVolumeSys().cryptoRand)
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
func intPtr(i int) *int {
	return &i
}

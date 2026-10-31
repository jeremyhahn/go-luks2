// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"testing"
)

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

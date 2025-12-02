// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"bytes"
	"testing"
)

// TestParseSize tests parsing size strings
func TestParseSize(t *testing.T) {
	tests := []struct {
		input    string
		expected int64
		wantErr  bool
	}{
		{"512", 512, false},
		{"4096", 4096, false},
		{"1048576", 1048576, false},
		{"invalid", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result, err := parseSize(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Fatalf("Expected %d, got %d", tt.expected, result)
				}
			}
		})
	}
}

// TestFormatSize tests formatting sizes to strings
func TestFormatSize(t *testing.T) {
	tests := []struct {
		input    int64
		expected string
	}{
		{512, "512"},
		{1024, "1024"},
		{1048576, "1048576"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := formatSize(tt.input)
			if result != tt.expected {
				t.Fatalf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

// TestAlignTo tests alignment calculations
func TestAlignTo(t *testing.T) {
	tests := []struct {
		value     int64
		alignment int64
		expected  int64
	}{
		{100, 512, 512},
		{512, 512, 512},
		{513, 512, 1024},
		{1000, 4096, 4096},
		{4097, 4096, 8192},
	}

	for _, tt := range tests {
		result := alignTo(tt.value, tt.alignment)
		if result != tt.expected {
			t.Fatalf("alignTo(%d, %d) = %d, want %d",
				tt.value, tt.alignment, result, tt.expected)
		}
	}
}

// TestNextPowerOf2 tests power of 2 calculations
func TestNextPowerOf2(t *testing.T) {
	tests := []struct {
		input    int
		expected int
	}{
		{1, 1},
		{2, 2},
		{3, 4},
		{5, 8},
		{100, 128},
		{512, 512},
		{513, 1024},
	}

	for _, tt := range tests {
		result := nextPowerOf2(tt.input)
		if result != tt.expected {
			t.Fatalf("nextPowerOf2(%d) = %d, want %d",
				tt.input, result, tt.expected)
		}
	}
}

// TestIsPowerOf2 tests power of 2 detection
func TestIsPowerOf2(t *testing.T) {
	tests := []struct {
		input    int
		expected bool
	}{
		{1, true},
		{2, true},
		{4, true},
		{512, true},
		{1024, true},
		{3, false},
		{100, false},
		{513, false},
	}

	for _, tt := range tests {
		result := isPowerOf2(tt.input)
		if result != tt.expected {
			t.Fatalf("isPowerOf2(%d) = %v, want %v",
				tt.input, result, tt.expected)
		}
	}
}

// TestClearBytes tests secure byte clearing
func TestClearBytes(t *testing.T) {
	data := []byte{0xFF, 0xAA, 0x55, 0x00}
	clearBytes(data)

	for i, b := range data {
		if b != 0 {
			t.Fatalf("Byte %d not cleared: %02x", i, b)
		}
	}
}

// TestBase64Operations tests base64 encoding/decoding
func TestBase64Operations(t *testing.T) {
	data := []byte("test data for base64")

	encoded := encodeBase64(data)
	if len(encoded) == 0 {
		t.Fatal("encodeBase64 returned empty string")
	}

	decoded, err := decodeBase64(encoded)
	if err != nil {
		t.Fatalf("decodeBase64 failed: %v", err)
	}

	if !bytes.Equal(data, decoded) {
		t.Fatal("Decoded data doesn't match original")
	}
}

// TestDecodeBase64Error tests base64 decoding errors
func TestDecodeBase64Error(t *testing.T) {
	invalid := []string{
		"!!!invalid!!!",
		"not-base64-@#$%",
	}

	for _, str := range invalid {
		t.Run(str, func(t *testing.T) {
			_, err := decodeBase64(str)
			if err == nil {
				t.Fatal("Expected error for invalid base64")
			}
		})
	}
}

// TestGetHashFunc tests hash function retrieval
func TestGetHashFunc(t *testing.T) {
	tests := []struct {
		algo    string
		wantErr bool
	}{
		{"sha256", false},
		{"sha512", false},
		{"sha1", true},
		{"invalid", true},
		{"md5", true},
	}

	for _, tt := range tests {
		t.Run(tt.algo, func(t *testing.T) {
			fn, err := getHashFunc(tt.algo)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Fatalf("Unexpected error: %v", err)
				}
				if fn == nil {
					t.Fatal("Hash function is nil")
				}
			}
		})
	}
}

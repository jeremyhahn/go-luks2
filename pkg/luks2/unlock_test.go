// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"testing"
)

func TestTrimRight(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		cutset   string
		expected []byte
	}{
		{"empty input", []byte{}, "\x00", []byte{}},
		{"no trim needed", []byte("hello"), "\x00", []byte("hello")},
		{"single null byte", []byte("hello\x00"), "\x00", []byte("hello")},
		{"multiple null bytes", []byte("hello\x00\x00\x00"), "\x00", []byte("hello")},
		{"all null bytes", []byte("\x00\x00\x00"), "\x00", []byte{}},
		{"mixed cutset", []byte("hello   "), " ", []byte("hello")},
		{"multiple chars in cutset", []byte("hello \x00 \x00"), " \x00", []byte("hello")},
		{"no matching chars", []byte("hello"), "xyz", []byte("hello")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := TrimRight(tt.input, tt.cutset)
			if string(result) != string(tt.expected) {
				t.Errorf("TrimRight() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestIsUnlocked_NonexistentVolume(t *testing.T) {
	// IsUnlocked should return false for non-existent volumes
	result := IsUnlocked("definitely-nonexistent-volume-12345")
	if result {
		t.Error("IsUnlocked() should return false for non-existent volume")
	}
}

func TestSafeUint64ToInt64(t *testing.T) {
	tests := []struct {
		name    string
		input   uint64
		want    int64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small positive", 100, 100, false},
		{"max int64", uint64(1<<63 - 1), 1<<63 - 1, false},
		{"overflow", 1 << 63, 0, true},
		{"max uint64", ^uint64(0), 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeUint64ToInt64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeUint64ToInt64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeUint64ToInt64() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeUint64ToInt(t *testing.T) {
	tests := []struct {
		name    string
		input   uint64
		want    int
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"small positive", 100, 100, false},
		{"medium value", 1000000, 1000000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeUint64ToInt(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeUint64ToInt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeUint64ToInt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSafeInt64ToUint64(t *testing.T) {
	tests := []struct {
		name    string
		input   int64
		want    uint64
		wantErr bool
	}{
		{"zero", 0, 0, false},
		{"positive", 100, 100, false},
		{"max int64", 1<<63 - 1, 1<<63 - 1, false},
		{"negative one", -1, 0, true},
		{"very negative", -1000000, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SafeInt64ToUint64(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("SafeInt64ToUint64() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("SafeInt64ToUint64() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"testing"
)

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
			got, err := safeUint64ToInt64(tt.input)
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
			got, err := safeUint64ToInt(tt.input)
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
			got, err := safeInt64ToUint64(tt.input)
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

// ErrVolumeAlreadyUnlocked (Unlock adopting an in-use mapping name) and the
// Lock-side refusals moved to pkg/dmcrypt as ErrActive/ErrNotActive with
// the activation code they guarded (#268); see pkg/dmcrypt's own tests.

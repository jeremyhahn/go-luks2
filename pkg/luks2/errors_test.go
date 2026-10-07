// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"errors"
	"fmt"
	"testing"
)

// TestSentinelErrors tests that all sentinel errors are defined
func TestSentinelErrors(t *testing.T) {
	sentinelErrors := []error{
		ErrInvalidHeader,
		ErrDeviceNotFound,
		ErrUnsupported,
		ErrUnsupported,
		ErrKeyslotNotFound,
		ErrNoKeyslots,
		ErrInvalidArgument,
		ErrPermissionDenied,
	}

	for _, err := range sentinelErrors {
		if err == nil {
			t.Fatal("Sentinel error is nil")
		}
		if err.Error() == "" {
			t.Fatal("Sentinel error has empty message")
		}
	}
}

// TestSentinelErrorsIs tests errors.Is() compatibility with sentinel errors
func TestSentinelErrorsIs(t *testing.T) {
	tests := []struct {
		name   string
		err    error
		target error
		want   bool
	}{
		{
			name:   "ErrInvalidHeader matches",
			err:    ErrInvalidHeader,
			target: ErrInvalidHeader,
			want:   true,
		},
		{
			name:   "ErrWrongKey matches",
			err:    ErrWrongKey,
			target: ErrWrongKey,
			want:   true,
		},
		{
			name:   "different sentinel errors don't match",
			err:    ErrInvalidHeader,
			target: ErrWrongKey,
			want:   false,
		},
		{
			name:   "wrapped sentinel error matches",
			err:    fmt.Errorf("wrapped: %w", ErrDeviceNotFound),
			target: ErrDeviceNotFound,
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := errors.Is(tt.err, tt.target); got != tt.want {
				t.Fatalf("errors.Is() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestDeviceError tests DeviceError functionality
// TestDeviceErrorAs tests errors.As() compatibility
// TestDeviceErrorNilHandling tests nil error handling
// TestVolumeError tests VolumeError functionality
// TestVolumeErrorAs tests errors.As() compatibility
// TestVolumeErrorNilHandling tests nil error handling
// TestKeyslotError tests KeyslotError functionality
// TestKeyslotErrorAs tests errors.As() compatibility
// TestKeyslotErrorNilHandling tests nil error handling
// TestCryptoError tests CryptoError functionality
// TestCryptoErrorAs tests errors.As() compatibility
// TestCryptoErrorNilHandling tests nil error handling
// TestErrorChaining tests error wrapping and chaining
// TestErrorTypeSafety tests that different error types don't interfere

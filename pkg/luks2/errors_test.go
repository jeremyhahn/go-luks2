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
		ErrInvalidPassphrase,
		ErrDeviceNotFound,
		ErrVolumeNotUnlocked,
		ErrVolumeAlreadyUnlocked,
		ErrNotMounted,
		ErrAlreadyMounted,
		ErrUnsupportedKDF,
		ErrUnsupportedHash,
		ErrInvalidKeyslot,
		ErrNoKeyslots,
		ErrInvalidSize,
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
			name:   "ErrInvalidPassphrase matches",
			err:    ErrInvalidPassphrase,
			target: ErrInvalidPassphrase,
			want:   true,
		},
		{
			name:   "different sentinel errors don't match",
			err:    ErrInvalidHeader,
			target: ErrInvalidPassphrase,
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
func TestDeviceError(t *testing.T) {
	tests := []struct {
		name         string
		device       string
		op           string
		err          error
		expectedMsg  string
		expectUnwrap error
	}{
		{
			name:         "basic device error",
			device:       "/dev/sda1",
			op:           "open",
			err:          ErrPermissionDenied,
			expectedMsg:  "open /dev/sda1: permission denied",
			expectUnwrap: ErrPermissionDenied,
		},
		{
			name:         "device not found error",
			device:       "/dev/nvme0n1",
			op:           "read",
			err:          ErrDeviceNotFound,
			expectedMsg:  "read /dev/nvme0n1: device not found",
			expectUnwrap: ErrDeviceNotFound,
		},
		{
			name:         "wrapped error",
			device:       "/dev/loop0",
			op:           "format",
			err:          fmt.Errorf("underlying error"),
			expectedMsg:  "format /dev/loop0: underlying error",
			expectUnwrap: nil, // Will check error message instead
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			devErr := &DeviceError{
				Device: tt.device,
				Op:     tt.op,
				Err:    tt.err,
			}

			// Test Error() method
			if got := devErr.Error(); got != tt.expectedMsg {
				t.Fatalf("Error() = %q, want %q", got, tt.expectedMsg)
			}

			// Test Unwrap() method
			unwrapped := devErr.Unwrap()
			if unwrapped != tt.err {
				t.Fatalf("Unwrap() = %v, want %v", unwrapped, tt.err)
			}

			// Test errors.Is() compatibility
			if tt.expectUnwrap != nil && !errors.Is(devErr, tt.expectUnwrap) {
				t.Fatalf("errors.Is() failed for %v", tt.expectUnwrap)
			}
		})
	}
}

// TestDeviceErrorAs tests errors.As() compatibility
func TestDeviceErrorAs(t *testing.T) {
	originalErr := &DeviceError{
		Device: "/dev/test",
		Op:     "test",
		Err:    ErrInvalidHeader,
	}

	wrappedErr := fmt.Errorf("wrapped: %w", originalErr)

	var devErr *DeviceError
	if !errors.As(wrappedErr, &devErr) {
		t.Fatal("errors.As() failed to extract DeviceError")
	}

	if devErr.Device != originalErr.Device {
		t.Fatalf("Device = %q, want %q", devErr.Device, originalErr.Device)
	}

	if devErr.Op != originalErr.Op {
		t.Fatalf("Op = %q, want %q", devErr.Op, originalErr.Op)
	}

	if !errors.Is(devErr.Err, ErrInvalidHeader) {
		t.Fatal("Wrapped error doesn't match ErrInvalidHeader")
	}
}

// TestDeviceErrorNilHandling tests nil error handling
func TestDeviceErrorNilHandling(t *testing.T) {
	devErr := &DeviceError{
		Device: "/dev/test",
		Op:     "test",
		Err:    nil,
	}

	msg := devErr.Error()
	if msg != "test /dev/test: <nil>" {
		t.Fatalf("Error() with nil err = %q, want \"test /dev/test: <nil>\"", msg)
	}

	unwrapped := devErr.Unwrap()
	if unwrapped != nil {
		t.Fatalf("Unwrap() = %v, want nil", unwrapped)
	}
}

// TestVolumeError tests VolumeError functionality
func TestVolumeError(t *testing.T) {
	tests := []struct {
		name         string
		volume       string
		op           string
		err          error
		expectedMsg  string
		expectUnwrap error
	}{
		{
			name:         "unlock volume error",
			volume:       "encrypted-vol",
			op:           "unlock",
			err:          ErrInvalidPassphrase,
			expectedMsg:  "unlock volume encrypted-vol: invalid passphrase",
			expectUnwrap: ErrInvalidPassphrase,
		},
		{
			name:         "volume already unlocked",
			volume:       "data-vol",
			op:           "unlock",
			err:          ErrVolumeAlreadyUnlocked,
			expectedMsg:  "unlock volume data-vol: volume already unlocked",
			expectUnwrap: ErrVolumeAlreadyUnlocked,
		},
		{
			name:         "mount error",
			volume:       "backup-vol",
			op:           "mount",
			err:          ErrAlreadyMounted,
			expectedMsg:  "mount volume backup-vol: already mounted",
			expectUnwrap: ErrAlreadyMounted,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			volErr := &VolumeError{
				Volume: tt.volume,
				Op:     tt.op,
				Err:    tt.err,
			}

			// Test Error() method
			if got := volErr.Error(); got != tt.expectedMsg {
				t.Fatalf("Error() = %q, want %q", got, tt.expectedMsg)
			}

			// Test Unwrap() method
			unwrapped := volErr.Unwrap()
			if unwrapped != tt.err {
				t.Fatalf("Unwrap() = %v, want %v", unwrapped, tt.err)
			}

			// Test errors.Is() compatibility
			if !errors.Is(volErr, tt.expectUnwrap) {
				t.Fatalf("errors.Is() failed for %v", tt.expectUnwrap)
			}
		})
	}
}

// TestVolumeErrorAs tests errors.As() compatibility
func TestVolumeErrorAs(t *testing.T) {
	originalErr := &VolumeError{
		Volume: "test-volume",
		Op:     "lock",
		Err:    ErrVolumeNotUnlocked,
	}

	wrappedErr := fmt.Errorf("operation failed: %w", originalErr)

	var volErr *VolumeError
	if !errors.As(wrappedErr, &volErr) {
		t.Fatal("errors.As() failed to extract VolumeError")
	}

	if volErr.Volume != originalErr.Volume {
		t.Fatalf("Volume = %q, want %q", volErr.Volume, originalErr.Volume)
	}

	if volErr.Op != originalErr.Op {
		t.Fatalf("Op = %q, want %q", volErr.Op, originalErr.Op)
	}

	if !errors.Is(volErr.Err, ErrVolumeNotUnlocked) {
		t.Fatal("Wrapped error doesn't match ErrVolumeNotUnlocked")
	}
}

// TestVolumeErrorNilHandling tests nil error handling
func TestVolumeErrorNilHandling(t *testing.T) {
	volErr := &VolumeError{
		Volume: "test-vol",
		Op:     "test",
		Err:    nil,
	}

	msg := volErr.Error()
	if msg != "test volume test-vol: <nil>" {
		t.Fatalf("Error() with nil err = %q, want \"test volume test-vol: <nil>\"", msg)
	}

	unwrapped := volErr.Unwrap()
	if unwrapped != nil {
		t.Fatalf("Unwrap() = %v, want nil", unwrapped)
	}
}

// TestKeyslotError tests KeyslotError functionality
func TestKeyslotError(t *testing.T) {
	tests := []struct {
		name         string
		keyslot      int
		op           string
		err          error
		expectedMsg  string
		expectUnwrap error
	}{
		{
			name:         "invalid keyslot",
			keyslot:      0,
			op:           "open",
			err:          ErrInvalidKeyslot,
			expectedMsg:  "open keyslot 0: invalid keyslot",
			expectUnwrap: ErrInvalidKeyslot,
		},
		{
			name:         "keyslot 7 error",
			keyslot:      7,
			op:           "activate",
			err:          ErrInvalidPassphrase,
			expectedMsg:  "activate keyslot 7: invalid passphrase",
			expectUnwrap: ErrInvalidPassphrase,
		},
		{
			name:         "no keyslots available",
			keyslot:      -1,
			op:           "find",
			err:          ErrNoKeyslots,
			expectedMsg:  "find keyslot -1: no valid keyslots",
			expectUnwrap: ErrNoKeyslots,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ksErr := &KeyslotError{
				Keyslot: tt.keyslot,
				Op:      tt.op,
				Err:     tt.err,
			}

			// Test Error() method
			if got := ksErr.Error(); got != tt.expectedMsg {
				t.Fatalf("Error() = %q, want %q", got, tt.expectedMsg)
			}

			// Test Unwrap() method
			unwrapped := ksErr.Unwrap()
			if unwrapped != tt.err {
				t.Fatalf("Unwrap() = %v, want %v", unwrapped, tt.err)
			}

			// Test errors.Is() compatibility
			if !errors.Is(ksErr, tt.expectUnwrap) {
				t.Fatalf("errors.Is() failed for %v", tt.expectUnwrap)
			}
		})
	}
}

// TestKeyslotErrorAs tests errors.As() compatibility
func TestKeyslotErrorAs(t *testing.T) {
	originalErr := &KeyslotError{
		Keyslot: 3,
		Op:      "delete",
		Err:     ErrPermissionDenied,
	}

	wrappedErr := fmt.Errorf("keyslot operation failed: %w", originalErr)

	var ksErr *KeyslotError
	if !errors.As(wrappedErr, &ksErr) {
		t.Fatal("errors.As() failed to extract KeyslotError")
	}

	if ksErr.Keyslot != originalErr.Keyslot {
		t.Fatalf("Keyslot = %d, want %d", ksErr.Keyslot, originalErr.Keyslot)
	}

	if ksErr.Op != originalErr.Op {
		t.Fatalf("Op = %q, want %q", ksErr.Op, originalErr.Op)
	}

	if !errors.Is(ksErr.Err, ErrPermissionDenied) {
		t.Fatal("Wrapped error doesn't match ErrPermissionDenied")
	}
}

// TestKeyslotErrorNilHandling tests nil error handling
func TestKeyslotErrorNilHandling(t *testing.T) {
	ksErr := &KeyslotError{
		Keyslot: 5,
		Op:      "test",
		Err:     nil,
	}

	msg := ksErr.Error()
	if msg != "test keyslot 5: <nil>" {
		t.Fatalf("Error() with nil err = %q, want \"test keyslot 5: <nil>\"", msg)
	}

	unwrapped := ksErr.Unwrap()
	if unwrapped != nil {
		t.Fatalf("Unwrap() = %v, want nil", unwrapped)
	}
}

// TestCryptoError tests CryptoError functionality
func TestCryptoError(t *testing.T) {
	tests := []struct {
		name         string
		op           string
		err          error
		expectedMsg  string
		expectUnwrap error
	}{
		{
			name:         "unsupported hash",
			op:           "hash",
			err:          ErrUnsupportedHash,
			expectedMsg:  "crypto hash: unsupported hash algorithm",
			expectUnwrap: ErrUnsupportedHash,
		},
		{
			name:         "unsupported KDF",
			op:           "derive",
			err:          ErrUnsupportedKDF,
			expectedMsg:  "crypto derive: unsupported KDF type",
			expectUnwrap: ErrUnsupportedKDF,
		},
		{
			name:         "encryption error",
			op:           "encrypt",
			err:          fmt.Errorf("AES initialization failed"),
			expectedMsg:  "crypto encrypt: AES initialization failed",
			expectUnwrap: nil,
		},
		{
			name:         "decryption error",
			op:           "decrypt",
			err:          fmt.Errorf("invalid ciphertext"),
			expectedMsg:  "crypto decrypt: invalid ciphertext",
			expectUnwrap: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cryptoErr := &CryptoError{
				Op:  tt.op,
				Err: tt.err,
			}

			// Test Error() method
			if got := cryptoErr.Error(); got != tt.expectedMsg {
				t.Fatalf("Error() = %q, want %q", got, tt.expectedMsg)
			}

			// Test Unwrap() method
			unwrapped := cryptoErr.Unwrap()
			if unwrapped != tt.err {
				t.Fatalf("Unwrap() = %v, want %v", unwrapped, tt.err)
			}

			// Test errors.Is() compatibility when applicable
			if tt.expectUnwrap != nil && !errors.Is(cryptoErr, tt.expectUnwrap) {
				t.Fatalf("errors.Is() failed for %v", tt.expectUnwrap)
			}
		})
	}
}

// TestCryptoErrorAs tests errors.As() compatibility
func TestCryptoErrorAs(t *testing.T) {
	originalErr := &CryptoError{
		Op:  "pbkdf2",
		Err: ErrInvalidSize,
	}

	wrappedErr := fmt.Errorf("crypto operation failed: %w", originalErr)

	var cryptoErr *CryptoError
	if !errors.As(wrappedErr, &cryptoErr) {
		t.Fatal("errors.As() failed to extract CryptoError")
	}

	if cryptoErr.Op != originalErr.Op {
		t.Fatalf("Op = %q, want %q", cryptoErr.Op, originalErr.Op)
	}

	if !errors.Is(cryptoErr.Err, ErrInvalidSize) {
		t.Fatal("Wrapped error doesn't match ErrInvalidSize")
	}
}

// TestCryptoErrorNilHandling tests nil error handling
func TestCryptoErrorNilHandling(t *testing.T) {
	cryptoErr := &CryptoError{
		Op:  "test",
		Err: nil,
	}

	msg := cryptoErr.Error()
	if msg != "crypto test: <nil>" {
		t.Fatalf("Error() with nil err = %q, want \"crypto test: <nil>\"", msg)
	}

	unwrapped := cryptoErr.Unwrap()
	if unwrapped != nil {
		t.Fatalf("Unwrap() = %v, want nil", unwrapped)
	}
}

// TestErrorChaining tests error wrapping and chaining
func TestErrorChaining(t *testing.T) {
	// Create a chain of errors
	baseErr := ErrInvalidPassphrase
	cryptoErr := &CryptoError{Op: "derive", Err: baseErr}
	keyslotErr := &KeyslotError{Keyslot: 0, Op: "unlock", Err: cryptoErr}
	deviceErr := &DeviceError{Device: "/dev/sda1", Op: "open", Err: keyslotErr}

	// Test that we can unwrap through the chain
	if !errors.Is(deviceErr, ErrInvalidPassphrase) {
		t.Fatal("errors.Is() failed to find base error in chain")
	}

	// Test that we can extract each error type
	var de *DeviceError
	if !errors.As(deviceErr, &de) {
		t.Fatal("errors.As() failed to extract DeviceError")
	}

	var ke *KeyslotError
	if !errors.As(deviceErr, &ke) {
		t.Fatal("errors.As() failed to extract KeyslotError")
	}

	var ce *CryptoError
	if !errors.As(deviceErr, &ce) {
		t.Fatal("errors.As() failed to extract CryptoError")
	}

	// Verify the error message contains all context
	msg := deviceErr.Error()
	if msg != "open /dev/sda1: unlock keyslot 0: crypto derive: invalid passphrase" {
		t.Fatalf("Error chain message = %q, want full context", msg)
	}
}

// TestErrorTypeSafety tests that different error types don't interfere
func TestErrorTypeSafety(t *testing.T) {
	devErr := &DeviceError{Device: "/dev/test", Op: "test", Err: ErrInvalidHeader}
	volErr := &VolumeError{Volume: "test", Op: "test", Err: ErrInvalidHeader}
	ksErr := &KeyslotError{Keyslot: 0, Op: "test", Err: ErrInvalidHeader}
	cryptoErr := &CryptoError{Op: "test", Err: ErrInvalidHeader}

	// Verify each error type can be distinguished
	var de *DeviceError
	if !errors.As(devErr, &de) || errors.As(volErr, &de) {
		t.Fatal("DeviceError type safety failed")
	}

	var ve *VolumeError
	if !errors.As(volErr, &ve) || errors.As(devErr, &ve) {
		t.Fatal("VolumeError type safety failed")
	}

	var ke *KeyslotError
	if !errors.As(ksErr, &ke) || errors.As(devErr, &ke) {
		t.Fatal("KeyslotError type safety failed")
	}

	var ce *CryptoError
	if !errors.As(cryptoErr, &ce) || errors.As(devErr, &ce) {
		t.Fatal("CryptoError type safety failed")
	}

	// All should still match the underlying sentinel error
	allErrs := []error{devErr, volErr, ksErr, cryptoErr}
	for _, err := range allErrs {
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("Error %v doesn't match ErrInvalidHeader", err)
		}
	}
}

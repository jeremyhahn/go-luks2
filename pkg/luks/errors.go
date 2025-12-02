// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"errors"
	"fmt"
)

// Common errors that can be checked using errors.Is()
var (
	// ErrInvalidHeader indicates a LUKS header is invalid or corrupted
	ErrInvalidHeader = errors.New("invalid LUKS header")

	// ErrInvalidPassphrase indicates the passphrase is incorrect
	ErrInvalidPassphrase = errors.New("invalid passphrase")

	// ErrDeviceNotFound indicates the device path doesn't exist
	ErrDeviceNotFound = errors.New("device not found")

	// ErrVolumeNotUnlocked indicates the volume is not unlocked
	ErrVolumeNotUnlocked = errors.New("volume not unlocked")

	// ErrVolumeAlreadyUnlocked indicates the volume is already unlocked
	ErrVolumeAlreadyUnlocked = errors.New("volume already unlocked")

	// ErrNotMounted indicates the path is not mounted
	ErrNotMounted = errors.New("not mounted")

	// ErrAlreadyMounted indicates the path is already mounted
	ErrAlreadyMounted = errors.New("already mounted")

	// ErrUnsupportedKDF indicates the KDF type is not supported
	ErrUnsupportedKDF = errors.New("unsupported KDF type")

	// ErrUnsupportedHash indicates the hash algorithm is not supported
	ErrUnsupportedHash = errors.New("unsupported hash algorithm")

	// ErrInvalidKeyslot indicates the keyslot is invalid or unavailable
	ErrInvalidKeyslot = errors.New("invalid keyslot")

	// ErrNoKeyslots indicates no valid keyslots are available
	ErrNoKeyslots = errors.New("no valid keyslots")

	// ErrInvalidSize indicates a size parameter is invalid
	ErrInvalidSize = errors.New("invalid size")

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied")
)

// DeviceError represents an error related to a specific device
type DeviceError struct {
	Device string
	Op     string
	Err    error
}

func (e *DeviceError) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Op, e.Device, e.Err)
}

func (e *DeviceError) Unwrap() error {
	return e.Err
}

// VolumeError represents an error related to a volume operation
type VolumeError struct {
	Volume string
	Op     string
	Err    error
}

func (e *VolumeError) Error() string {
	return fmt.Sprintf("%s volume %s: %v", e.Op, e.Volume, e.Err)
}

func (e *VolumeError) Unwrap() error {
	return e.Err
}

// KeyslotError represents an error related to a keyslot operation
type KeyslotError struct {
	Keyslot int
	Op      string
	Err     error
}

func (e *KeyslotError) Error() string {
	return fmt.Sprintf("%s keyslot %d: %v", e.Op, e.Keyslot, e.Err)
}

func (e *KeyslotError) Unwrap() error {
	return e.Err
}

// CryptoError represents an error in cryptographic operations
type CryptoError struct {
	Op  string
	Err error
}

func (e *CryptoError) Error() string {
	return fmt.Sprintf("crypto %s: %v", e.Op, e.Err)
}

func (e *CryptoError) Unwrap() error {
	return e.Err
}

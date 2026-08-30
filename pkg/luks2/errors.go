// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

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

	// ErrDetachIncomplete indicates a loop device was told to detach and the
	// kernel had not released it before the wait expired. It is deliberately
	// distinct from a failed detach: the request succeeded, and something else
	// still holds the device open. An operator who reads "detach failed" goes
	// looking at the detach; this one has to go looking at what else has the
	// device.
	ErrDetachIncomplete = errors.New("loop device detach did not become observable")

	// ErrPermissionDenied indicates insufficient permissions
	ErrPermissionDenied = errors.New("permission denied")

	// ErrMasterKeyVerification indicates that a candidate master key did not
	// match any digest in the header. It is deliberately one value for every
	// cause -- mismatch, an unsupported or FIPS-refused digest KDF, a corrupt
	// salt, a digest of implausible length -- so that neither the message nor
	// the number of digests tried tells a caller which digest rejected the key.
	ErrMasterKeyVerification = errors.New("master key verification failed")

	// ErrMetadataTooLarge indicates the JSON metadata does not fit the header
	// area the container was formatted with. The area cannot be enlarged after
	// the fact -- the keyslots and data offsets on disk are already sized
	// against it -- so this is a refusal, not a retryable condition.
	ErrMetadataTooLarge = errors.New("metadata does not fit the header area")

	// ErrKeyslotsAreaFull indicates the container has no room for another
	// keyslot: the new one would fall outside the keyslots area the header
	// declares, or past the start of the encrypted data. Both are refusals
	// rather than retryable conditions -- the area is fixed at format time.
	ErrKeyslotsAreaFull = errors.New("no room in the keyslots area for another keyslot")

	// ErrFIPSNotApproved indicates the requested algorithm is not approved by
	// the Go Cryptographic Module and is refused while the process runs in
	// FIPS 140-3 mode. See docs/FIPS.md.
	ErrFIPSNotApproved = errors.New("algorithm not approved in FIPS 140-3 mode")
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

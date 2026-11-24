// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"math"
	"os"
	"path/filepath"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/kdf"
)

// Security constants
const (
	MinPassphraseLength = 8
	MaxPassphraseLength = 512
	minKeySize          = 256
	maxKeySize          = 512
	minSectorSize       = 512
	maxSectorSize       = 4096
	// digestIterationTargetMs is the digest PBKDF2 calibration target, matching cryptsetup's ~100 ms at a 64-byte derivation; it guards no guessable secret.
	digestIterationTargetMs = kdf.DigestIterationTargetMs

	// digestCalibrationKeyLen is the derived length the digest calibration benchmarks: 64 bytes for every hash, as cryptsetup does.
	digestCalibrationKeyLen = kdf.DigestCalibrationKeyLen
)

// validateDevicePath validates a device path for security
func validateDevicePath(device string) error {
	if device == "" {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: "device path is empty"}
	}

	// Clean resolves every ".." in an absolute path lexically.
	cleaned := filepath.Clean(device)

	// Must be absolute path
	if !filepath.IsAbs(cleaned) {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: "device path is not absolute"}
	}

	// Check that device exists
	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			return &errs.Error{Kind: ErrDeviceNotFound, Err: err}
		}
		return &errs.Error{Kind: ErrInvalidArgument, Detail: err.Error()}
	}

	// Must be a regular file or block device
	mode := info.Mode()
	if !mode.IsRegular() && (mode&os.ModeDevice == 0) {
		return &errs.Error{Kind: ErrInvalidArgument, Detail: "device path is neither a regular file nor a block device"}
	}

	return nil
}

// maxCredentialLength is the longest existing credential presented to a keyslot: cryptsetup's 8 MiB key file limit.
const maxCredentialLength = 8 << 20

// validateExistingCredential bounds a credential presented to open a keyslot: not empty and at most maxCredentialLength; the new-credential policy does not apply.
func validateExistingCredential(credential []byte) error {
	if len(credential) == 0 {
		return ErrInvalidCredential
	}
	if len(credential) > maxCredentialLength {
		return ErrInvalidCredential
	}
	return nil
}

// validatePassphraseBytes validates the length of a new passphrase this package enrolls.
func validatePassphraseBytes(passphrase []byte) error {
	if len(passphrase) < MinPassphraseLength {
		return ErrInvalidCredential
	}
	if len(passphrase) > MaxPassphraseLength {
		return ErrInvalidCredential
	}
	return nil
}

// minArgon2MemoryKB is the smallest caller-chosen Argon2 memory cost written (Format, AddKey); reading accepts header.MinArgon2Memory.
const minArgon2MemoryKB = kdf.MinArgon2MemoryKB

// validateArgon2CreateCost bounds the Argon2 costs a caller supplies, on the KDF as it resolves.
func validateArgon2CreateCost(opts formatOptionsForTest) error {
	if !isArgon2Type(resolveKDFType(normalizeKDFType(opts.KDFType), formatArgon2CostGiven(opts))) {
		return nil
	}
	// Each cost has a floor and the read side's ceiling (header.ValidateKDFCost).
	if opts.Argon2Memory != 0 && (opts.Argon2Memory < minArgon2MemoryKB || opts.Argon2Memory > header.MaxArgon2Memory) {
		return &KDFCostError{
			Param: "memory",
			Value: opts.Argon2Memory,
			Min:   minArgon2MemoryKB,
			Max:   header.MaxArgon2Memory,
		}
	}
	if opts.Argon2Time != 0 && (opts.Argon2Time < header.MinArgon2Time || opts.Argon2Time > header.MaxArgon2Time) {
		return &KDFCostError{
			Param: "time",
			Value: opts.Argon2Time,
			Min:   header.MinArgon2Time,
			Max:   header.MaxArgon2Time,
		}
	}
	// Parallelism is checked here with its siblings.
	if opts.Argon2Parallel != 0 && (opts.Argon2Parallel < header.MinArgon2Parallel || opts.Argon2Parallel > header.MaxArgon2Parallel) {
		return &KDFCostError{
			Param: "parallelism",
			Value: opts.Argon2Parallel,
			Min:   header.MinArgon2Parallel,
			Max:   header.MaxArgon2Parallel,
		}
	}
	return nil
}

// validateFormatOptionsForTest validates all format options
func validateFormatOptionsForTest(opts formatOptionsForTest) error {
	// Validate device path
	if err := validateDevicePath(opts.Device); err != nil {
		return err
	}

	// Validate passphrase
	if err := validatePassphraseBytes(opts.Passphrase); err != nil {
		return err
	}

	// Validate key size
	if opts.KeySize != 0 && opts.KeySize != 256 && opts.KeySize != 512 {
		return ErrInvalidArgument
	}

	// Validate sector size
	if opts.SectorSize != 0 && opts.SectorSize != 512 && opts.SectorSize != 4096 {
		return ErrInvalidArgument
	}

	if err := validateMetadataSize(opts.MetadataSize); err != nil {
		return err
	}

	// Cipher, mode and key size as a combination, and the two labels.
	if err := validateFormatChoices(opts); err != nil {
		return err
	}

	// Validate Argon2 parameters if specified
	if err := validateArgon2CreateCost(opts); err != nil {
		return err
	}

	// Check for integer overflow in size calculations
	if opts.KeySize > 0 {
		keyBytes := opts.KeySize / 8
		afSize := keyBytes * header.AFStripes
		if afSize/header.AFStripes != keyBytes {
			return ErrInvalidArgument
		}
	}

	return nil
}

// validateMetadataSize accepts what cryptsetup's --luks2-metadata-size does: zero, or a power of two from header.HeaderMinSize to header.HeaderMaxSize.
func validateMetadataSize(size int) error {
	if size == 0 {
		return nil
	}
	if size < header.HeaderMinSize || size > header.HeaderMaxSize || !isPowerOf2(size) {
		return ErrInvalidArgument
	}
	return nil
}

// ConstantTimeEqual compares two byte slices in constant time
// checkOverflow checks if a*b would overflow
func checkOverflow(a, b int) error {
	if a > 0 && b > 0 && a > math.MaxInt/b {
		return ErrInvalidArgument
	}
	return nil
}

// openDevice opens a device through sys.openFile (internal/device.Open), classifying failures such as ErrPermissionDenied.
func openDevice(op, path string, flag int, sys volumeSys) (*os.File, error) {
	return device.Open(context.Background(), op, path, flag, sys.openFile)
}

// classifyDeviceOpen types an open failure (internal/device.ClassifyOpen) and returns anything else unchanged.
func classifyDeviceOpen(op string, err error) error {
	return device.ClassifyOpen(op, err)
}

// deviceLock wraps internal/device's Pinned/Locked pair: the node flock, then cryptsetup's lock for a block device.
type deviceLock struct {
	locked *device.Locked
}

// DefaultLockWait is the most acquireDeviceLock waits for a competing holder.
const DefaultLockWait = device.DefaultLockWait

// The backoff a device lock wait uses, as internal/device.Lock does it.
// Tests assert the acquisition's timing against these.
const (
	lockBackoffMin = device.LockBackoffMin
	lockBackoffMax = device.LockBackoffMax
)

// acquireDeviceLock acquires an exclusive lock on a device, waiting up to DefaultLockWait.
func acquireDeviceLock(path string) (*deviceLock, error) {
	return acquireDeviceLockTimeout(path, DefaultLockWait)
}

// acquireDeviceLockTimeout is acquireDeviceLock with an explicit budget, polling with backoff; zero or less tries once.
func acquireDeviceLockTimeout(path string, wait time.Duration) (*deviceLock, error) {
	ctx := context.Background()
	return acquireFileLock(ctx, path, wait, clock.System{}, defaultVolumeSys())
}

// acquireFileLock is acquireDeviceLockTimeout on the given clock and sys.
func acquireFileLock(ctx context.Context, path string, wait time.Duration, clk clock.Clock, sys volumeSys) (*deviceLock, error) {
	pinned, err := device.OpenPinned(ctx, "lock the device", path, os.O_RDWR, sys.openFile)
	if err != nil {
		return nil, err
	}
	locked, err := pinned.Lock(ctx, device.LockExclusive, wait, clk, cryptsetupLockDir, device.DefaultOpenLockFile, sys.lockHeld)
	if err != nil {
		_ = pinned.Close()
		return nil, err
	}
	return &deviceLock{locked: locked}, nil
}

// Release releases the file lock
func (l *deviceLock) Release() error {
	if l.locked == nil {
		return nil
	}
	_ = l.locked.Unlock()
	return l.locked.File().Close()
}

// OpenFileSecure opens a file with proper permissions
// safeUint64ToInt64 converts uint64 to int64 safely, returning error on overflow
func safeUint64ToInt64(v uint64) (int64, error) {
	if v > math.MaxInt64 {
		return 0, ErrInvalidArgument
	}
	return int64(v), nil
}

// safeUint64ToInt converts uint64 to int safely, returning error on overflow
func safeUint64ToInt(v uint64) (int, error) {
	if v > uint64(math.MaxInt) {
		return 0, ErrInvalidArgument
	}
	return int(v), nil
}

// safeInt64ToUint64 converts int64 to uint64 safely, returning error on negative
func safeInt64ToUint64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrInvalidArgument
	}
	return uint64(v), nil
}

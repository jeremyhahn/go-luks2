// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/rand"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BLKDISCARD ioctl number for TRIM/discard on block devices
const BLKDISCARD = 0x1277

// WipeOptions contains options for wiping a LUKS volume
type WipeOptions struct {
	Device     string
	Passes     int  // Number of wipe passes (default: 1)
	Random     bool // Use random data (default: zeros)
	HeaderOnly bool // Only wipe headers (default: false, wipes all data)
	Trim       bool // Issue TRIM/DISCARD after wipe (for SSDs)
}

// Wipe securely wipes a LUKS volume
func Wipe(opts WipeOptions) error {
	// Validate device path
	if err := ValidateDevicePath(opts.Device); err != nil {
		return err
	}

	// Validate passes
	if opts.Passes <= 0 {
		return fmt.Errorf("invalid number of passes: %d (must be >= 1)", opts.Passes)
	}

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(opts.Device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	f, err := os.OpenFile(opts.Device, os.O_RDWR, 0600)
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	if opts.HeaderOnly {
		return wipeHeaders(f)
	}

	// Get device size (handles both block devices and regular files)
	size, err := getBlockDeviceSize(opts.Device)
	if err != nil {
		return fmt.Errorf("failed to get device size: %w", err)
	}

	if size <= 0 {
		return fmt.Errorf("invalid device size: %d", size)
	}

	// Wipe in passes
	for pass := 0; pass < opts.Passes; pass++ {
		if err := wipePass(f, size, opts.Random); err != nil {
			return fmt.Errorf("wipe pass %d failed: %w", pass+1, err)
		}
	}

	// Sync to ensure writes are flushed
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// Issue TRIM/DISCARD if requested (for SSDs)
	if opts.Trim {
		if err := issueDiscard(f, size); err != nil {
			// TRIM failure is not fatal - device may not support it
			// Log but continue
			_ = err
		}
	}

	return nil
}

// wipeHeaders wipes only the LUKS headers (primary and backup)
func wipeHeaders(f *os.File) error {
	headerSize := int64(0x8000) // 32KB (covers both headers)

	zeros := make([]byte, headerSize)

	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	if _, err := f.Write(zeros); err != nil {
		return fmt.Errorf("failed to wipe headers: %w", err)
	}

	return f.Sync()
}

// wipePass performs one wipe pass over the device
func wipePass(f *os.File, size int64, random bool) error {
	const bufferSize = 1024 * 1024 // 1MB buffer

	// Validate size to prevent issues with negative values
	if size < 0 {
		return fmt.Errorf("invalid size: %d (must be >= 0)", size)
	}

	buffer := make([]byte, bufferSize)
	// Ensure buffer is cleared when function exits (defense in depth)
	defer clearBytes(buffer)

	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	remaining := size
	for remaining > 0 {
		writeSize := bufferSize
		if remaining < int64(bufferSize) {
			writeSize = int(remaining)
		}

		// Fill buffer
		if random {
			if _, err := rand.Read(buffer[:writeSize]); err != nil {
				return fmt.Errorf("failed to generate random data: %w", err)
			}
		} else {
			// Zeros - clear the portion we're using
			for i := 0; i < writeSize; i++ {
				buffer[i] = 0
			}
		}

		// Write buffer
		n, err := f.Write(buffer[:writeSize])
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}

		remaining -= int64(n)
	}

	return nil
}

// WipeKeyslot wipes a specific keyslot
func WipeKeyslot(device string, keyslot int) error {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Acquire file lock for exclusive access
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read metadata
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return err
	}

	// Find keyslot
	keyslotID := fmt.Sprintf("%d", keyslot)
	ks, ok := metadata.Keyslots[keyslotID]
	if !ok {
		return fmt.Errorf("keyslot %d not found", keyslot)
	}

	// Parse keyslot area offset and size
	offset, err := parseSize(ks.Area.Offset)
	if err != nil {
		return fmt.Errorf("invalid keyslot offset: %w", err)
	}

	size, err := parseSize(ks.Area.Size)
	if err != nil {
		return fmt.Errorf("invalid keyslot size: %w", err)
	}

	// Open device
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	// Seek to keyslot area
	if _, err := f.Seek(offset, 0); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	// Wipe keyslot area
	zeros := make([]byte, size)
	if _, err := f.Write(zeros); err != nil {
		return fmt.Errorf("failed to wipe keyslot: %w", err)
	}

	// Update metadata to remove keyslot
	delete(metadata.Keyslots, keyslotID)

	// Re-read header for writing
	hdr, _, err := ReadHeader(device)
	if err != nil {
		return err
	}

	// Write updated metadata (use internal version since we hold the lock)
	return writeHeaderInternal(device, hdr, metadata)
}

// issueDiscard issues a BLKDISCARD ioctl to inform the SSD to release blocks.
// This is a best-effort operation - failure is not fatal as the device may not support TRIM.
//
// Security note: TRIM on encrypted volumes can leak information about which blocks
// are in use vs. free space. However, when used as part of a secure wipe operation
// (after overwriting data), TRIM provides an additional layer of erasure for SSDs.
func issueDiscard(f *os.File, size int64) error {
	// Validate size to prevent integer overflow when converting to uint64
	// A negative size would wrap to a very large value, potentially causing issues
	if size <= 0 {
		return fmt.Errorf("invalid discard size: %d (must be > 0)", size)
	}

	// BLKDISCARD takes a uint64[2] array: [offset, length]
	discardRange := [2]uint64{0, uint64(size)}

	// #nosec G103 -- unsafe.Pointer required for IOCTL syscall to pass array to kernel
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(BLKDISCARD),
		uintptr(unsafe.Pointer(&discardRange[0])),
	)

	if errno != 0 {
		return fmt.Errorf("BLKDISCARD ioctl failed: %w", errno)
	}

	return nil
}

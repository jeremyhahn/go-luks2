// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// BLKDISCARD ioctl number for TRIM/discard on block devices
const BLKDISCARD = 0x1277

// WipePattern defines the data pattern for a wipe pass
type WipePattern uint8

const (
	PatternZeros  WipePattern = iota // 0x00
	PatternOnes                      // 0xFF
	PatternRandom                    // crypto/rand
)

// String returns the string representation of a WipePattern
func (p WipePattern) String() string {
	switch p {
	case PatternZeros:
		return "zeros"
	case PatternOnes:
		return "ones"
	case PatternRandom:
		return "random"
	default:
		return "unknown"
	}
}

// WipeStandard defines a named wipe methodology
type WipeStandard uint8

const (
	StandardCustom   WipeStandard = iota // Legacy/custom configuration
	StandardNIST                         // NIST SP 800-88 Rev 1
	StandardDoD3Pass                     // DoD 5220.22-M 3-pass
	StandardDoD7Pass                     // DoD 5220.22-M ECE 7-pass
)

// String returns the string representation of a WipeStandard
func (s WipeStandard) String() string {
	switch s {
	case StandardCustom:
		return "custom"
	case StandardNIST:
		return "nist"
	case StandardDoD3Pass:
		return "dod3"
	case StandardDoD7Pass:
		return "dod7"
	default:
		return "unknown"
	}
}

// GetPatternSequence returns the pattern sequence for a standard
func (s WipeStandard) GetPatternSequence() []WipePattern {
	switch s {
	case StandardNIST:
		// NIST SP 800-88: Single pass of random data
		return []WipePattern{PatternRandom}
	case StandardDoD3Pass:
		// DoD 5220.22-M 3-pass: Zeros -> Ones -> Random
		return []WipePattern{PatternZeros, PatternOnes, PatternRandom}
	case StandardDoD7Pass:
		// DoD 5220.22-M ECE 7-pass: (Z->O->R) + R + (Z->O->R)
		return []WipePattern{
			PatternZeros, PatternOnes, PatternRandom,
			PatternRandom,
			PatternZeros, PatternOnes, PatternRandom,
		}
	default:
		return nil
	}
}

// RequiresVerification returns whether the standard requires verification
func (s WipeStandard) RequiresVerification() bool {
	switch s {
	case StandardDoD3Pass, StandardDoD7Pass:
		return true
	default:
		return false
	}
}

// WipeProgress reports wipe operation progress
type WipeProgress struct {
	CurrentPass     int
	TotalPasses     int
	BytesWritten    int64
	TotalBytes      int64
	Pattern         WipePattern
	IsVerification  bool
	PercentComplete float64
}

// WipeProgressFunc is a callback for reporting wipe progress
type WipeProgressFunc func(WipeProgress)

// WipeOptions contains options for wiping a LUKS volume
type WipeOptions struct {
	// Existing fields (backward compatible)
	Device     string
	Passes     int  // Number of wipe passes (default: 1)
	Random     bool // Use random data (default: zeros)
	HeaderOnly bool // Only wipe headers (default: false, wipes all data)
	Trim       bool // Issue TRIM/DISCARD after wipe (for SSDs)

	// New fields for standards support
	Standard     WipeStandard     // Named standard (overrides Passes/Random if set)
	Patterns     []WipePattern    // Custom pattern sequence (overrides Passes/Random if set)
	Verify       bool             // Enable verification pass
	ProgressFunc WipeProgressFunc // Progress callback (optional)
}

// fillBufferWithPattern fills a buffer with the specified pattern
func fillBufferWithPattern(buf []byte, pattern WipePattern) error {
	switch pattern {
	case PatternZeros:
		for i := range buf {
			buf[i] = 0x00
		}
	case PatternOnes:
		for i := range buf {
			buf[i] = 0xFF
		}
	case PatternRandom:
		if _, err := rand.Read(buf); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}
	default:
		return fmt.Errorf("unknown pattern: %d", pattern)
	}
	return nil
}

// wipePassWithPattern performs one wipe pass with a specific pattern
func wipePassWithPattern(f *os.File, size int64, pattern WipePattern,
	progress WipeProgressFunc, passNum, totalPasses int) error {
	const bufferSize = 1024 * 1024 // 1MB buffer

	if size < 0 {
		return fmt.Errorf("invalid size: %d (must be >= 0)", size)
	}

	buffer := make([]byte, bufferSize)
	defer clearBytes(buffer)

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	var bytesWritten int64
	remaining := size
	for remaining > 0 {
		writeSize := bufferSize
		if remaining < int64(bufferSize) {
			writeSize = int(remaining)
		}

		if err := fillBufferWithPattern(buffer[:writeSize], pattern); err != nil {
			return err
		}

		n, err := f.Write(buffer[:writeSize])
		if err != nil {
			return fmt.Errorf("write error: %w", err)
		}

		bytesWritten += int64(n)
		remaining -= int64(n)

		if progress != nil {
			progress(WipeProgress{
				CurrentPass:     passNum,
				TotalPasses:     totalPasses,
				BytesWritten:    bytesWritten,
				TotalBytes:      size,
				Pattern:         pattern,
				IsVerification:  false,
				PercentComplete: float64(bytesWritten) / float64(size) * 100,
			})
		}
	}

	return nil
}

// wipeVerify reads back the device and verifies the final pattern was written correctly
func wipeVerify(f *os.File, size int64, expectedPattern WipePattern,
	progress WipeProgressFunc, totalPasses int) error {
	const bufferSize = 1024 * 1024 // 1MB buffer

	if size <= 0 {
		return nil // Nothing to verify
	}

	// Random pattern cannot be verified (by definition)
	if expectedPattern == PatternRandom {
		return nil
	}

	buffer := make([]byte, bufferSize)
	expected := make([]byte, bufferSize)
	defer clearBytes(buffer)
	defer clearBytes(expected)

	// Fill expected buffer with the pattern
	if err := fillBufferWithPattern(expected, expectedPattern); err != nil {
		return err
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("verification seek failed: %w", err)
	}

	var bytesVerified int64
	remaining := size
	for remaining > 0 {
		readSize := bufferSize
		if remaining < int64(bufferSize) {
			readSize = int(remaining)
		}

		n, err := io.ReadFull(f, buffer[:readSize])
		if err != nil && err != io.ErrUnexpectedEOF {
			return fmt.Errorf("verification read error: %w", err)
		}

		if !bytes.Equal(buffer[:n], expected[:n]) {
			return fmt.Errorf("verification failed: data mismatch at offset %d", bytesVerified)
		}

		bytesVerified += int64(n)
		remaining -= int64(n)

		if progress != nil {
			progress(WipeProgress{
				CurrentPass:     totalPasses + 1,
				TotalPasses:     totalPasses + 1,
				BytesWritten:    bytesVerified,
				TotalBytes:      size,
				Pattern:         expectedPattern,
				IsVerification:  true,
				PercentComplete: float64(bytesVerified) / float64(size) * 100,
			})
		}
	}

	return nil
}

// resolvePatternSequence determines patterns from options
// Returns (patterns, needsVerification)
func resolvePatternSequence(opts WipeOptions) ([]WipePattern, bool) {
	// Priority 1: Named standard
	if opts.Standard != StandardCustom {
		patterns := opts.Standard.GetPatternSequence()
		verify := opts.Standard.RequiresVerification()
		// Allow explicit override of verification
		if opts.Verify {
			verify = true
		}
		return patterns, verify
	}

	// Priority 2: Custom pattern sequence
	if len(opts.Patterns) > 0 {
		return opts.Patterns, opts.Verify
	}

	// Priority 3: Legacy mode (Passes + Random)
	var pattern WipePattern
	if opts.Random {
		pattern = PatternRandom
	} else {
		pattern = PatternZeros
	}

	passes := opts.Passes
	if passes <= 0 {
		passes = 1
	}

	patterns := make([]WipePattern, passes)
	for i := range patterns {
		patterns[i] = pattern
	}

	return patterns, opts.Verify
}

// Wipe securely wipes a LUKS volume
func Wipe(opts WipeOptions) error {
	// Validate device path
	if err := ValidateDevicePath(opts.Device); err != nil {
		return err
	}

	// Resolve pattern sequence (handles standards, custom patterns, and legacy mode)
	patterns, needsVerify := resolvePatternSequence(opts)

	// Validate we have at least one pass (legacy compatibility check)
	if len(patterns) == 0 {
		// Fall back to legacy validation for backward compatibility
		if opts.Passes <= 0 && opts.Standard == StandardCustom && len(opts.Patterns) == 0 {
			return fmt.Errorf("invalid number of passes: %d (must be >= 1)", opts.Passes)
		}
		// If still no patterns, default to single zeros pass
		patterns = []WipePattern{PatternZeros}
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

	totalPasses := len(patterns)

	// Wipe in passes with pattern sequence
	for i, pattern := range patterns {
		if err := wipePassWithPattern(f, size, pattern, opts.ProgressFunc, i+1, totalPasses); err != nil {
			return fmt.Errorf("wipe pass %d (%s) failed: %w", i+1, pattern.String(), err)
		}
	}

	// Sync to ensure writes are flushed
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// Verification pass if required
	if needsVerify && len(patterns) > 0 {
		lastPattern := patterns[len(patterns)-1]
		if err := wipeVerify(f, size, lastPattern, opts.ProgressFunc, totalPasses); err != nil {
			return fmt.Errorf("verification failed: %w", err)
		}
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

	// THE GATE, and it was missing HERE while every sibling path had it.
	//
	// This function is identically destructive to KillKeyslot -- it overwrites
	// the key material and removes the entry -- and it needs no passphrase.
	// Without this it destroyed a single-keyslot volume that KillKeyslot refused
	// to touch, for the same operation.
	//
	// The gap was not an oversight in a list; it was two lists. The last-keyslot
	// guard was applied to the sites enumerated from a review finding, while the
	// metadata cleanup was written per site from the code, and nobody diffed
	// them. A rule and the set it must cover have to come from the same place --
	// see TestEveryKeyslotRemovalPathIsGuarded, which asserts over the paths as a
	// group so a sixth cannot be added without one.
	if err := checkKeyslotRemovable(device, metadata, keyslotID); err != nil {
		return err
	}

	// The keyslot comes straight from the header and nothing has unlocked it, so
	// its geometry is untrusted: validated before it reaches a Seek or sizes an
	// allocation. Same call the unlock path and wipeKeyslotArea make.
	if err := validateKeyslot(keyslotID, ks); err != nil {
		return err
	}

	offset, err := parseSize(ks.Area.Offset)
	if err != nil {
		return fmt.Errorf("invalid keyslot offset: %w", err)
	}

	size, err := parseSize(ks.Area.Size)
	if err != nil {
		return fmt.Errorf("invalid keyslot size: %w", err)
	}

	// Re-read the header for writing BEFORE anything is destroyed, so that the
	// resulting metadata can be proved writable while the key material is still
	// intact (#50). It used to be read after the wipe, which put the one check
	// that can still refuse on the far side of the destruction.
	hdr, _, err := ReadHeader(device)
	if err != nil {
		return err
	}
	removeKeyslotFromMetadata(metadata, keyslotID)

	// THE SEQUENCE ID ADVANCES, and this path was the one that did not.
	//
	// LUKS2 keeps two header copies and uses the sequence id to decide which is
	// current. writeHeaderInternal writes both, so a failure between them leaves
	// two copies with DIFFERENT metadata at the SAME sequence id -- and a reader
	// then has no way to tell which one is newer. That defeats the format's own
	// recovery mechanism, on a path whose whole purpose is destroying key
	// material.
	//
	// Every other mutating path already did this; WipeKeyslot was the eighth of
	// eight and the only omission. Audited rather than assumed after review of
	// e975ed5 named this site: Format, WriteHeader and RestorePrimaryHeader also
	// do not advance it, and all three are correct not to -- Format creates a
	// container with no older copy to disambiguate, WriteHeader is the primitive
	// whose caller owns the header, and RestorePrimaryHeader clones the
	// secondary onto the primary, where advancing would make the repaired copy
	// falsely claim to be newer than the copy it was made from.
	//
	// It is incremented before the pre-flight, matching the other paths exactly.
	// The field lives in the binary header rather than the JSON, so it does not
	// change what checkHeaderWritable measures.
	hdr.SequenceID++

	if err := checkHeaderWritable(hdr, metadata); err != nil {
		return err
	}

	// Open device
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	if err := checkAreaWithinDevice(f, offset, size); err != nil {
		return fmt.Errorf("keyslot %d: %w", keyslot, err)
	}

	// Seek to keyslot area
	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("failed to seek: %w", err)
	}

	// Wipe the keyslot area in fixed-size chunks, so a header-supplied size
	// cannot choose an allocation.
	if err := writeZeros(f, size); err != nil {
		return fmt.Errorf("failed to wipe keyslot: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// Write updated metadata (use internal version since we hold the lock)
	return writeHeaderInternal(device, hdr, metadata)
}

// keyslotWipeChunk is how much of a keyslot area is zeroed per write.
const keyslotWipeChunk = 64 * 1024

// writeZeros zeroes size bytes at the file's current position, in fixed-size
// chunks.
//
// The chunking is not an optimisation. size comes out of a header this process
// did not write, and even after it is bounded there is no reason to let it pick
// an allocation: one make([]byte, size) per wipe hands an attacker-controlled
// number straight to the allocator, on a path that is by definition already
// committed to destroying something.
func writeZeros(f *os.File, size int64) error {
	zeros := make([]byte, keyslotWipeChunk)
	for remaining := size; remaining > 0; {
		n := int64(len(zeros))
		if remaining < n {
			n = remaining
		}
		if _, err := f.Write(zeros[:n]); err != nil {
			return err
		}
		remaining -= n
	}
	return nil
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

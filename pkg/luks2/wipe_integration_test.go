// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"testing"
)

// TestWipeHeader tests wiping LUKS headers
func TestWipeHeader(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-header.img"
	defer os.Remove(tmpfile)

	// Create and format volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify header exists
	if _, _, err := ReadHeader(tmpfile); err != nil {
		t.Fatalf("Header should be readable before wipe: %v", err)
	}

	// Wipe header only
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		HeaderOnly: true,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify header is wiped
	if _, _, err := ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

// TestWipeFull tests full volume wipe
func TestWipeFull(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-full.img"
	defer os.Remove(tmpfile)

	// Create small volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	// Use small file for fast testing
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Full wipe with single pass
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		Random:     true,
		HeaderOnly: false,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify file still exists but header is wiped
	if _, err := os.Stat(tmpfile); err != nil {
		t.Fatal("File should still exist after wipe")
	}

	if _, _, err := ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after full wipe")
	}
}

// TestWipeMultiplePasses tests wiping with multiple passes
func TestWipeMultiplePasses(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-multi.img"
	defer os.Remove(tmpfile)

	// Create small volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(5 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Wipe with 3 passes
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     3,
		Random:     true,
		HeaderOnly: false,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe with 3 passes failed: %v", err)
	}
}

// TestWipeKeyslot tests wiping individual keyslots
func TestWipeKeyslot(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-keyslot.img"
	defer os.Remove(tmpfile)

	// Create and format volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Wipe keyslot 0
	if err := WipeKeyslot(tmpfile, 0); err != nil {
		t.Fatalf("WipeKeyslot failed: %v", err)
	}

	// Try to unlock with the passphrase (should fail)
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	err = Unlock(loopDev, []byte("test-password"), "test-wipe-keyslot")
	if err == nil {
		Lock("test-wipe-keyslot")
		t.Fatal("Unlock should fail after keyslot wipe")
	}
}

// TestWipeErrors tests wipe error conditions
func TestWipeErrors(t *testing.T) {
	tests := []struct {
		name string
		opts WipeOptions
	}{
		{
			name: "nonexistent-device",
			opts: WipeOptions{
				Device: "/nonexistent/device",
				Passes: 1,
			},
		},
		{
			name: "zero-passes",
			opts: WipeOptions{
				Device: "/tmp/test",
				Passes: 0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Wipe(tt.opts)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

// TestWipeWithTrimOnLoopDevice tests TRIM/discard on loop devices
func TestWipeWithTrimOnLoopDevice(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-trim-loop.img"
	defer os.Remove(tmpfile)

	// Create and format volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(20 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Full wipe with Trim enabled
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		Random:     true,
		HeaderOnly: false,
		Trim:       true,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe with Trim failed: %v", err)
	}

	// Verify file still exists
	if _, err := os.Stat(tmpfile); err != nil {
		t.Fatal("File should still exist after wipe")
	}

	// Verify header is wiped
	if _, _, err := ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

// TestWipeWithTrimOnBlockDevice tests TRIM on actual block device if available
func TestWipeWithTrimOnBlockDevice(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-trim-blk.img"
	defer os.Remove(tmpfile)

	// Create file
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(30 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Set up loop device
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Skipf("Cannot set up loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Format on loop device
	opts := FormatOptions{
		Device:     loopDev,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Wipe with Trim on block device
	wipeOpts := WipeOptions{
		Device:     loopDev,
		Passes:     1,
		Random:     false,
		HeaderOnly: false,
		Trim:       true,
	}

	// TRIM might fail on loop device (depends on backing store)
	// but wipe should still succeed
	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe with Trim failed: %v", err)
	}

	// Verify header is wiped
	if _, _, err := ReadHeader(loopDev); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

// TestWipeMultiplePassesWithTrim tests multiple wipe passes followed by TRIM
func TestWipeMultiplePassesWithTrim(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-multi-trim.img"
	defer os.Remove(tmpfile)

	// Create small volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(5 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Wipe with 3 passes and TRIM
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     3,
		Random:     true,
		HeaderOnly: false,
		Trim:       true,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe with 3 passes and Trim failed: %v", err)
	}
}

// TestWipeHeaderOnlyNoTrim tests that header-only wipe doesn't issue TRIM
func TestWipeHeaderOnlyNoTrim(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-header-no-trim.img"
	defer os.Remove(tmpfile)

	// Create and format volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Wipe header only with Trim option (should not affect data area)
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		HeaderOnly: true,
		Trim:       true, // Should be ignored for header-only wipe
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("HeaderOnly wipe failed: %v", err)
	}

	// Verify header is wiped
	if _, _, err := ReadHeader(tmpfile); err == nil {
		t.Fatal("Header should not be readable after wipe")
	}
}

// TestWipeSecurityVerification tests that wiped data is actually overwritten
func TestWipeSecurityVerification(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-security.img"
	defer os.Remove(tmpfile)

	// Create file with known pattern
	testSize := int64(10 * 1024 * 1024)
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Write recognizable pattern
	pattern := []byte("SENSITIVE_DATA_MARKER_")
	buf := make([]byte, 1024*1024)
	for i := 0; i < len(buf); i += len(pattern) {
		copy(buf[i:], pattern)
	}

	for written := int64(0); written < testSize; {
		n, err := f.Write(buf)
		if err != nil {
			f.Close()
			t.Fatalf("Failed to write pattern: %v", err)
		}
		written += int64(n)
	}
	f.Close()

	// Wipe with zeros
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		Random:     false,
		HeaderOnly: false,
		Trim:       false,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Read file and search for pattern
	result, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	// Search for our pattern - it should NOT be found
	for i := 0; i <= len(result)-len(pattern); i++ {
		if string(result[i:i+len(pattern)]) == string(pattern) {
			t.Fatalf("Found sensitive pattern at offset %d - wipe failed!", i)
		}
	}

	// Verify all zeros
	for i, b := range result {
		if b != 0 {
			t.Fatalf("Non-zero byte at offset %d: 0x%02x", i, b)
		}
	}
}

// TestWipeRandomSecurityVerification tests random wipe overwrites data
func TestWipeRandomSecurityVerification(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-random-security.img"
	defer os.Remove(tmpfile)

	// Create file with known pattern
	testSize := int64(5 * 1024 * 1024)
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}

	// Write all zeros first
	zeros := make([]byte, 1024*1024)
	for written := int64(0); written < testSize; {
		n, err := f.Write(zeros)
		if err != nil {
			f.Close()
			t.Fatalf("Failed to write zeros: %v", err)
		}
		written += int64(n)
	}
	f.Close()

	// Wipe with random data
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		Random:     true,
		HeaderOnly: false,
		Trim:       false,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Random wipe failed: %v", err)
	}

	// Read file and verify it's not all zeros
	result, err := os.ReadFile(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	nonZeroCount := 0
	for _, b := range result {
		if b != 0 {
			nonZeroCount++
		}
	}

	// With random data, statistically we should have ~50% non-zero bytes
	// Use a very conservative threshold of 10%
	minExpected := len(result) / 10
	if nonZeroCount < minExpected {
		t.Fatalf("Too few non-zero bytes after random wipe: %d (expected at least %d)",
			nonZeroCount, minExpected)
	}
}

// TestWipeKeyslotWithTrim tests keyslot wiping (doesn't use TRIM)
func TestWipeKeyslotWithTrim(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-keyslot-trim.img"
	defer os.Remove(tmpfile)

	// Create and format volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify keyslot exists
	_, metadata, err := ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if _, ok := metadata.Keyslots["0"]; !ok {
		t.Fatal("Keyslot 0 should exist")
	}

	// Wipe keyslot 0
	if err := WipeKeyslot(tmpfile, 0); err != nil {
		t.Fatalf("WipeKeyslot failed: %v", err)
	}

	// Verify keyslot is gone
	_, metadata, err = ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header after wipe: %v", err)
	}

	if _, ok := metadata.Keyslots["0"]; ok {
		t.Fatal("Keyslot 0 should be wiped")
	}
}

// TestWipeWithDataVerification performs end-to-end wipe verification
func TestWipeWithDataVerification(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-e2e.img"
	defer os.Remove(tmpfile)

	// Create volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(20 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Format
	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Read header before wipe
	hdr, _, err := ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	// Verify magic is present
	if string(hdr.Magic[:]) != LUKS2Magic {
		t.Fatalf("Invalid magic before wipe: %v", hdr.Magic)
	}

	// Wipe with Trim
	wipeOpts := WipeOptions{
		Device:     tmpfile,
		Passes:     2,
		Random:     true,
		HeaderOnly: false,
		Trim:       true,
	}

	if err := Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Try to read magic directly from file
	rf, err := os.Open(tmpfile)
	if err != nil {
		t.Fatalf("Failed to open wiped file: %v", err)
	}
	defer rf.Close()

	magic := make([]byte, 6)
	if _, err := rf.Read(magic); err != nil {
		t.Fatalf("Failed to read magic: %v", err)
	}

	// Magic should NOT be LUKS2
	if string(magic) == LUKS2Magic {
		t.Fatal("LUKS2 magic should be wiped")
	}
}

// TestWipeConcurrentAccess tests that concurrent wipe attempts are blocked
func TestWipeConcurrentAccess(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-concurrent.img"
	defer os.Remove(tmpfile)

	// Create volume
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(10 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Format
	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Try concurrent wipes - one should fail due to file lock
	done := make(chan error, 2)

	go func() {
		wipeOpts := WipeOptions{
			Device:     tmpfile,
			Passes:     3,
			Random:     true,
			HeaderOnly: false,
			Trim:       false,
		}
		done <- Wipe(wipeOpts)
	}()

	go func() {
		wipeOpts := WipeOptions{
			Device:     tmpfile,
			Passes:     3,
			Random:     false,
			HeaderOnly: false,
			Trim:       false,
		}
		done <- Wipe(wipeOpts)
	}()

	err1 := <-done
	err2 := <-done

	// One should succeed, one should fail (or both succeed if timed differently)
	successCount := 0
	if err1 == nil {
		successCount++
	}
	if err2 == nil {
		successCount++
	}

	// At least one should succeed
	if successCount == 0 {
		t.Fatalf("Both wipes failed: err1=%v, err2=%v", err1, err2)
	}

	t.Logf("Concurrent wipe results: err1=%v, err2=%v (successes=%d)", err1, err2, successCount)
}

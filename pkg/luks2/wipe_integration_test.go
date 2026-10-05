// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
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
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// THIS TEST USED TO ASSERT THE DEFECT.
	//
	// It wiped keyslot 0 on a ONE-KEYSLOT volume, required that to succeed, and
	// then confirmed the volume no longer unlocked -- which is exactly the data
	// loss #37 and #71 describe, written down as the expected outcome. The tell
	// is in the assertion: "Unlock should fail after keyslot wipe", on a volume
	// with nothing else to unlock it with. Inverting it is part of the fix.
	//
	// WipeKeyslot is identically destructive to KillKeyslot and needs no
	// passphrase, and it was the one removal path with no last-keyslot guard at
	// all -- so it destroyed a single-keyslot volume that KillKeyslot refused to
	// touch, for the same operation.
	if err := WipeKeyslot(tmpfile, 0); err == nil {
		t.Fatal("WipeKeyslot destroyed the only keyslot that can open this volume, and reported success")
	} else if !errors.Is(err, ErrLastKeyslot) {
		t.Fatalf("WipeKeyslot was refused for some other reason than the guard: %v", err)
	}

	// The refusal is worth nothing if the volume did not survive it, and this is
	// the real-device half of that claim: the dm-crypt mapping still comes up.
	//
	// Scoped, and the loop device is detached before anything writes to the
	// backing file again, so no later step reads the volume through two paths at
	// once. The deferred detach stays as a backstop for a failure inside.
	func() {
		loopDev, err := SetupLoopDevice(tmpfile)
		if err != nil {
			t.Fatalf("Failed to setup loop device: %v", err)
		}
		defer func() { _ = DetachLoopDevice(loopDev) }()

		// #113's idempotent teardown, registered BEFORE the mapping can
		// exist so a partial or rolled-back unlock cannot leave one behind
		// (#100). It supersedes the explicit Lock this test used to do: it
		// unmounts anything mounted from THIS volume, retries to a deadline,
		// and reports a mapping it cannot release rather than leaving it.
		vol := runVolume(t, "test-wipe-keyslot")
		defer releaseVolume(t, vol)

		// The assertion is INVERTED from what #113 hardened, and the inversion
		// is the point: on a volume whose only keyslot survives a refused wipe,
		// the unlock must SUCCEED. #113 was hardening the teardown around the
		// old expectation that it fail.
		if err := Unlock(loopDev, []byte("test-password"), vol); err != nil {
			t.Fatalf("the volume no longer unlocks after a REFUSED WipeKeyslot: %v", err)
		}
	}()

	// What the original test meant to establish -- that WipeKeyslot really does
	// destroy the credential it targets -- still holds, on a volume where doing
	// so leaves a way in.
	if _, err := AddKey(tmpfile, []byte("test-password"), []byte("second-password"), &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if err := WipeKeyslot(tmpfile, 1); err != nil {
		t.Fatalf("WipeKeyslot refused a removal that leaves a working keyslot: %v", err)
	}
	if err := TestKey(tmpfile, []byte("second-password")); err == nil {
		t.Fatal("the wiped credential still opens the volume")
	}
	if err := TestKey(tmpfile, []byte("test-password")); err != nil {
		t.Fatalf("the surviving credential no longer opens the volume: %v", err)
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
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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

// TestWipeWithTrimOnBlockDevice tests TRIM on an actual block device
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

	// Set up loop device. Fails, does not skip: test/integration/Dockerfile's
	// entrypoint pre-creates /dev/loop0-255 and test/integration/cmd/docker-run
	// grants CAP_MKNOD, CAP_SYS_ADMIN and the loop major's device-cgroup rule
	// specifically so this always succeeds in the tier this test belongs to
	// (every other SetupLoopDevice call site in this package already
	// t.Fatalf's here, e.g. line 206 above); a failure means the environment
	// is wrong, not that a block device is optional for a test whose entire
	// point is testing one.
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Format on loop device
	opts := FormatOptions{
		Device:        loopDev,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	opts := FormatOptions{
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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

	// The same bug-defender as TestWipeKeyslot, one assertion shorter: it
	// required wiping the only keyslot on the volume to succeed, and then
	// checked the entry was gone. See the note there.
	if err := WipeKeyslot(tmpfile, 0); err == nil {
		t.Fatal("WipeKeyslot destroyed the only keyslot that can open this volume, and reported success")
	} else if !errors.Is(err, ErrLastKeyslot) {
		t.Fatalf("WipeKeyslot was refused for some other reason than the guard: %v", err)
	}

	// The entry survives the refusal. Asserting on the metadata rather than on
	// the error is what distinguishes "refused" from "wiped, then reported an
	// error" -- the error is the diagnosis, the header is the damage.
	_, metadata, err = ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header after the refusal: %v", err)
	}
	if _, ok := metadata.Keyslots["0"]; !ok {
		t.Fatal("WipeKeyslot was refused AND the keyslot was removed anyway")
	}

	// And the entry really does go when the removal is legitimate.
	if _, err := AddKey(tmpfile, []byte("test-password"), []byte("second-password"), &AddKeyOptions{
		KDFType:       KDFTypePBKDF2,
		PBKDFIterTime: 1,
	}); err != nil {
		t.Fatalf("AddKey failed: %v", err)
	}
	if err := WipeKeyslot(tmpfile, 1); err != nil {
		t.Fatalf("WipeKeyslot refused a removal that leaves a working keyslot: %v", err)
	}
	_, metadata, err = ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header after wipe: %v", err)
	}
	if _, ok := metadata.Keyslots["1"]; ok {
		t.Fatal("Keyslot 1 should be wiped")
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
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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
	if err := f.Truncate(32 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	// Format
	opts := FormatOptions{
		Device:        tmpfile,
		Passphrase:    []byte("test-password"),
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1, // keyslot cost is not what this test exercises (#52)
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

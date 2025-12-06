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

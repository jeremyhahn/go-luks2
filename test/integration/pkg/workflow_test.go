// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestFullWorkflow(t *testing.T) {
	tmpfile := "/tmp/test-luks-workflow.img"
	volumeName := "test-workflow"
	mountpoint := "/tmp/test-luks-mount"
	var loopDev string

	defer func() {
		// Cleanup
		_ = luks2.Unmount(mountpoint, 0)
		testCleanup(volumeName, loopDev, tmpfile)
		_ = os.RemoveAll(mountpoint)
	}()

	// Step 1: Create test file
	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Step 2: Format as LUKS2
	passphrase := []byte("test-password-123")
	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: passphrase,
		Label:      "TestWorkflow",
		KDFType:    "pbkdf2",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}
	t.Log("Step 2: Format completed")

	// Step 3: Setup loop device
	var err error
	loopDev, err = luks2.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	t.Logf("Step 3: Loop device setup: %s", loopDev)

	// Step 4: Unlock the volume
	_ = luks2.Lock(volumeName) // Cleanup from previous runs
	if err := luks2.Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	t.Log("Step 4: Volume unlocked")

	// Wait for unlock
	if !waitForUnlock(volumeName, 5000) {
		t.Fatal("Volume not unlocked in time")
	}

	// Step 5: Create filesystem
	if err := luks2.MakeFilesystem(volumeName, "ext4", "TestFS"); err != nil {
		t.Fatalf("Filesystem creation failed: %v", err)
	}
	t.Log("Step 5: Filesystem created")

	// Step 6: Mount the volume
	if err := os.MkdirAll(mountpoint, 0755); err != nil {
		t.Fatalf("Failed to create mountpoint: %v", err)
	}

	mountOpts := luks2.MountOptions{
		Device:     volumeName,
		MountPoint: mountpoint,
		FSType:     "ext4",
	}

	if err := luks2.Mount(mountOpts); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	t.Log("Step 6: Volume mounted")

	// Step 7: Verify mount
	mounted, err := luks2.IsMounted(mountpoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if !mounted {
		t.Fatal("Volume should be mounted")
	}

	// Step 8: Write and read data
	testFile := filepath.Join(mountpoint, "test.txt")
	testData := []byte("Hello, encrypted world!")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data mismatch: got %q, want %q", readData, testData)
	}
	t.Log("Step 8: Data verified")

	// Step 9: Unmount
	if err := luks2.Unmount(mountpoint, 0); err != nil {
		t.Fatalf("Unmount failed: %v", err)
	}
	t.Log("Step 9: Volume unmounted")

	// Step 10: Lock
	if err := luks2.Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}
	t.Log("Step 10: Volume locked")

	// Verify locked
	if !waitForLock(volumeName, 5000) {
		t.Fatal("Volume should be locked")
	}

	t.Log("Full workflow completed successfully!")
}

func TestVolumeInfo(t *testing.T) {
	tmpfile := "/tmp/test-luks-info.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Format the volume
	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		Label:      "InfoTestVolume",
		KDFType:    "argon2id",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Get volume info
	info, err := luks2.GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed: %v", err)
	}

	// Verify info
	if info.Version != 2 {
		t.Errorf("Expected version 2, got %d", info.Version)
	}

	if info.Label != "InfoTestVolume" {
		t.Errorf("Expected label 'InfoTestVolume', got %q", info.Label)
	}

	if len(info.UUID) == 0 {
		t.Error("Expected non-empty UUID")
	}

	if len(info.ActiveKeyslots) == 0 {
		t.Error("Expected at least one active keyslot")
	}

	if info.Cipher == "" {
		t.Error("Expected non-empty cipher")
	}

	if info.SectorSize != 512 && info.SectorSize != 4096 {
		t.Errorf("Unexpected sector size: %d", info.SectorSize)
	}
}

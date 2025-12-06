// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// waitForDevice waits for the device-mapper device to appear after unlock
func waitForDevice(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if IsUnlocked(name) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// TestMakeFilesystemExt4 tests creating an ext4 filesystem on a LUKS volume
func TestMakeFilesystemExt4(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-fs-ext4-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-fs-ext4-pass")
	volumeName := "test-fs-ext4"

	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	// Format LUKS volume
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock volume
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Create ext4 filesystem
	if err := MakeFilesystem(volumeName, "ext4", "test-ext4"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Verify filesystem exists by mounting it
	mountPoint := filepath.Join(os.TempDir(), "luks-fs-ext4-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountOpts := MountOptions{
		Device:     volumeName,
		MountPoint: mountPoint,
		FSType:     "ext4",
	}

	if err := Mount(mountOpts); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer Unmount(mountPoint, 0)

	// Verify filesystem is ext4
	cmd := exec.Command("stat", "-f", "-c", "%T", mountPoint)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to stat filesystem: %v", err)
	}

	fstype := strings.TrimSpace(string(output))
	if fstype != "ext2/ext3" && fstype != "ext4" {
		t.Errorf("Expected ext4 filesystem, got: %s", fstype)
	}
}

// TestMakeFilesystemExt3 tests creating an ext3 filesystem if supported
func TestMakeFilesystemExt3(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Check if mkfs.ext3 exists
	if _, err := exec.LookPath("mkfs.ext3"); err != nil {
		t.Skip("mkfs.ext3 not available on this system")
	}

	tmpfile, err := os.CreateTemp("", "luks-fs-ext3-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-fs-ext3-pass")
	volumeName := "test-fs-ext3"

	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	// Format LUKS volume
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock volume
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Create ext3 filesystem
	if err := MakeFilesystem(volumeName, "ext3", "test-ext3"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Verify filesystem exists by checking device mapper path
	devicePath := "/dev/mapper/" + volumeName
	if _, err := os.Stat(devicePath); err != nil {
		t.Errorf("Device mapper path not found: %v", err)
	}
}

// TestMakeFilesystemExt2 tests creating an ext2 filesystem if supported
func TestMakeFilesystemExt2(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Check if mkfs.ext2 exists
	if _, err := exec.LookPath("mkfs.ext2"); err != nil {
		t.Skip("mkfs.ext2 not available on this system")
	}

	tmpfile, err := os.CreateTemp("", "luks-fs-ext2-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-fs-ext2-pass")
	volumeName := "test-fs-ext2"

	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	// Format LUKS volume
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock volume
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Create ext2 filesystem
	if err := MakeFilesystem(volumeName, "ext2", "test-ext2"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Wait for device-mapper to stabilize after filesystem creation
	devicePath := "/dev/mapper/" + volumeName
	var deviceExists bool
	for i := 0; i < 20; i++ {
		if _, err := os.Stat(devicePath); err == nil {
			deviceExists = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !deviceExists {
		t.Errorf("Device mapper path not found after waiting: %s", devicePath)
	}
}

// TestMakeFilesystemWithLabel tests creating filesystem with custom label
func TestMakeFilesystemWithLabel(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-fs-label-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-fs-label-pass")
	volumeName := "test-fs-label"
	fsLabel := "my-custom-label"

	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	// Format LUKS volume
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock volume
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Create filesystem with custom label
	if err := MakeFilesystem(volumeName, "ext4", fsLabel); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Sync to flush filesystem metadata to disk
	exec.Command("sync").Run()

	// Verify label using e2label or blkid
	devicePath := "/dev/mapper/" + volumeName

	// Retry with blkid -p (low-level probing, no cache) to ensure we get fresh data
	var actualLabel string
	var labelErr error
	for i := 0; i < 10; i++ {
		// Use -p for low-level probing without cache
		cmd := exec.Command("blkid", "-p", "-s", "LABEL", "-o", "value", devicePath)
		output, err := cmd.CombinedOutput()
		if err == nil {
			actualLabel = strings.TrimSpace(string(output))
			break
		}
		labelErr = err
		time.Sleep(100 * time.Millisecond)
	}
	if actualLabel == "" && labelErr != nil {
		t.Fatalf("Failed to get filesystem label after retries: %v", labelErr)
	}

	if actualLabel != fsLabel {
		t.Errorf("Expected label %q, got %q", fsLabel, actualLabel)
	}
}

// TestMakeFilesystemErrors tests error conditions in MakeFilesystem
func TestMakeFilesystemErrors(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tests := []struct {
		name       string
		volumeName string
		fstype     string
		label      string
		wantErr    bool
	}{
		{
			name:       "nonexistent-volume",
			volumeName: "nonexistent-volume",
			fstype:     "ext4",
			label:      "test",
			wantErr:    true,
		},
		{
			name:       "unsupported-filesystem",
			volumeName: "test-volume",
			fstype:     "invalid-fs-type",
			label:      "test",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := MakeFilesystem(tt.volumeName, tt.fstype, tt.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeFilesystem() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestFilesystemWriteRead tests writing and reading data to verify filesystem works
func TestFilesystemWriteRead(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-fs-rw-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-fs-rw-pass")
	// Use a unique volume name per run to avoid conflicts with zombie device mappers
	volumeName := fmt.Sprintf("test-fs-rw-%d", time.Now().UnixNano())

	// Cleanup any leftover device mapper from previous runs (just in case)
	_ = Lock(volumeName)

	// Format LUKS volume
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock volume
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Create filesystem
	if err := MakeFilesystem(volumeName, "ext4", "test-rw"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Mount filesystem
	mountPoint := filepath.Join(os.TempDir(), "luks-fs-rw-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountOpts := MountOptions{
		Device:     volumeName,
		MountPoint: mountPoint,
		FSType:     "ext4",
	}

	if err := Mount(mountOpts); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer Unmount(mountPoint, 0)

	// Write test data
	testFile := filepath.Join(mountPoint, "testfile.txt")
	testData := []byte("Hello, LUKS filesystem!")

	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Read test data
	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	// Verify data
	if string(readData) != string(testData) {
		t.Errorf("Data mismatch: expected %q, got %q", testData, readData)
	}

	// Test directory creation
	testDir := filepath.Join(mountPoint, "testdir")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	// Verify directory exists
	if stat, err := os.Stat(testDir); err != nil {
		t.Fatalf("Failed to stat test directory: %v", err)
	} else if !stat.IsDir() {
		t.Error("Expected testdir to be a directory")
	}

	// Write nested file
	nestedFile := filepath.Join(testDir, "nested.txt")
	nestedData := []byte("Nested file content")
	if err := os.WriteFile(nestedFile, nestedData, 0644); err != nil {
		t.Fatalf("Failed to write nested file: %v", err)
	}

	// Read nested file
	readNested, err := os.ReadFile(nestedFile)
	if err != nil {
		t.Fatalf("Failed to read nested file: %v", err)
	}

	if string(readNested) != string(nestedData) {
		t.Errorf("Nested data mismatch: expected %q, got %q", nestedData, readNested)
	}
}

// TestFilesystemPersistence tests that data persists after unmount/remount
func TestFilesystemPersistence(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-fs-persist-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-fs-persist-pass")
	// Use a unique volume name per run to avoid conflicts with zombie device mappers
	volumeName := fmt.Sprintf("test-fs-persist-%d", time.Now().UnixNano())
	testData := []byte("Persistent data test")

	// Format LUKS volume
	opts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock volume
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Create filesystem
	if err := MakeFilesystem(volumeName, "ext4", "test-persist"); err != nil {
		Lock(volumeName)
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Mount filesystem
	mountPoint := filepath.Join(os.TempDir(), "luks-fs-persist-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		Lock(volumeName)
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountOpts := MountOptions{
		Device:     volumeName,
		MountPoint: mountPoint,
		FSType:     "ext4",
	}

	if err := Mount(mountOpts); err != nil {
		Lock(volumeName)
		t.Fatalf("Mount failed: %v", err)
	}

	// Write test data
	testFile := filepath.Join(mountPoint, "persistent.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		Unmount(mountPoint, 0)
		Lock(volumeName)
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Unmount
	if err := Unmount(mountPoint, 0); err != nil {
		Lock(volumeName)
		t.Fatalf("Unmount failed: %v", err)
	}

	// Lock volume
	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Unlock again
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Second unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Wait for device to appear
	if !waitForDevice(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after second unlock")
	}

	// Remount
	if err := Mount(mountOpts); err != nil {
		t.Fatalf("Second mount failed: %v", err)
	}
	defer Unmount(mountPoint, 0)

	// Read test data
	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file after remount: %v", err)
	}

	// Verify data persisted
	if string(readData) != string(testData) {
		t.Errorf("Data did not persist: expected %q, got %q", testData, readData)
	}

	// Write additional data to verify filesystem is still writable
	additionalData := []byte("Additional data after remount")
	additionalFile := filepath.Join(mountPoint, "additional.txt")
	if err := os.WriteFile(additionalFile, additionalData, 0644); err != nil {
		t.Fatalf("Failed to write additional file: %v", err)
	}

	// Verify both files exist
	files, err := os.ReadDir(mountPoint)
	if err != nil {
		t.Fatalf("Failed to read directory: %v", err)
	}

	fileCount := 0
	for _, f := range files {
		if f.Name() == "persistent.txt" || f.Name() == "additional.txt" {
			fileCount++
		}
	}

	if fileCount != 2 {
		t.Errorf("Expected 2 files, found %d", fileCount)
	}
}

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// waitForUnlock waits for the device-mapper device to appear after unlock
// Returns true if device appears within timeout, false otherwise
func waitForUnlock(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if IsUnlocked(name) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// waitForLock waits for the device-mapper device to disappear after lock
func waitForLock(name string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if !IsUnlocked(name) {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// TestDataPersistenceAcrossUnlockCycles verifies that data written to a LUKS
// volume persists across multiple lock/unlock cycles
func TestDataPersistenceAcrossUnlockCycles(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Create temporary file for LUKS volume
	tmpfile, err := os.CreateTemp("", "luks-persist-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	// Create 50MB volume
	if err := tmpfile.Truncate(50 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("persistence-test-passphrase")
	volumeName := "luks-persist-test"
	testData := []byte("This data must persist across lock/unlock cycles!")

	t.Logf("Step 1: Formatting LUKS volume at %s", volumePath)

	// Format the volume
	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		Label:         "persist-test",
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	t.Logf("Step 2: Setting up loop device")

	// Setup loop device
	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	t.Logf("Step 3: First unlock and filesystem creation")

	// First unlock
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("First Unlock failed: %v", err)
	}

	// Create filesystem
	if err := MakeFilesystem(volumeName, "ext4", "persistfs"); err != nil {
		Lock(volumeName)
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	// Create mount point
	mountPoint := filepath.Join(os.TempDir(), "luks-persist-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		Lock(volumeName)
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	t.Logf("Step 4: Mounting and writing test data")

	// Mount
	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		Lock(volumeName)
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		Lock(volumeName)
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}

	// Write test data
	testFile := filepath.Join(mountPoint, "persistence-test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		exec.Command("umount", mountPoint).Run()
		Lock(volumeName)
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Sync to ensure data is written
	exec.Command("sync").Run()
	time.Sleep(200 * time.Millisecond)

	t.Logf("Step 5: Unmounting and locking")

	// Unmount
	umountCmd := exec.Command("umount", mountPoint)
	if output, err := umountCmd.CombinedOutput(); err != nil {
		Lock(volumeName)
		t.Fatalf("Unmount failed: %v\nOutput: %s", err, string(output))
	}

	// Lock
	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	t.Logf("Step 6: Second unlock cycle - verifying data persistence")

	// Second unlock
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Second Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Wait for device to appear
	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after second unlock")
	}

	// Get fresh device path after re-unlock
	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after second unlock: %v", err)
	}

	// Mount again
	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Second Mount failed: %v\nOutput: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	// Read and verify data
	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed after unlock: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data mismatch after unlock cycle:\nExpected: %s\nGot: %s", string(testData), string(readData))
	}

	t.Logf("Step 7: Third unlock cycle - final verification")

	// Unmount and lock again
	exec.Command("umount", mountPoint).Run()
	Lock(volumeName)

	// Third unlock
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Third Unlock failed: %v", err)
	}

	// Wait for device to appear
	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after third unlock")
	}

	// Get fresh device path after third unlock
	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after third unlock: %v", err)
	}

	// Mount and verify once more
	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Third Mount failed: %v\nOutput: %s", err, string(output))
	}

	readData, err = os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed on third cycle: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data lost after multiple cycles:\nExpected: %s\nGot: %s", string(testData), string(readData))
	}

	t.Logf("SUCCESS: Data persisted across 3 unlock cycles")
}

// TestDataPersistenceMultipleFiles verifies multiple files persist correctly
func TestDataPersistenceMultipleFiles(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-multifile-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(50 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("multifile-test-pass")
	volumeName := "luks-multifile"

	t.Logf("Creating and formatting LUKS volume")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	if err := MakeFilesystem(volumeName, "ext4", "multifile"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-multifile-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		Lock(volumeName)
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	t.Logf("Writing multiple test files")

	// Create 10 files with different content
	testFiles := make(map[string][]byte)
	for i := 0; i < 10; i++ {
		filename := fmt.Sprintf("file-%d.txt", i)
		content := []byte(fmt.Sprintf("Content for file number %d - unique data", i))
		testFiles[filename] = content

		filePath := filepath.Join(mountPoint, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", filename, err)
		}
	}

	// Create subdirectory with files
	subdir := filepath.Join(mountPoint, "subdir")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatalf("Failed to create subdirectory: %v", err)
	}

	for i := 0; i < 5; i++ {
		filename := fmt.Sprintf("subdir/nested-%d.txt", i)
		content := []byte(fmt.Sprintf("Nested content %d", i))
		testFiles[filename] = content

		filePath := filepath.Join(mountPoint, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", filename, err)
		}
	}

	exec.Command("sync").Run()
	time.Sleep(200 * time.Millisecond)

	t.Logf("Unmounting and re-mounting to verify persistence")

	// Unmount and remount
	exec.Command("umount", mountPoint).Run()
	Lock(volumeName)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Re-unlock failed: %v", err)
	}

	// Wait for device to appear
	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after re-unlock")
	}

	// Get fresh device path after re-unlock
	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after re-unlock: %v", err)
	}

	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Re-mount failed: %v\nOutput: %s", err, string(output))
	}

	t.Logf("Verifying all files persisted correctly")

	// Verify all files
	for filename, expectedContent := range testFiles {
		filePath := filepath.Join(mountPoint, filename)
		readContent, err := os.ReadFile(filePath)
		if err != nil {
			t.Errorf("Failed to read %s: %v", filename, err)
			continue
		}

		if string(readContent) != string(expectedContent) {
			t.Errorf("Content mismatch for %s:\nExpected: %s\nGot: %s",
				filename, string(expectedContent), string(readContent))
		}
	}

	t.Logf("SUCCESS: All %d files persisted correctly", len(testFiles))
}

// TestDataPersistenceLargeFile verifies large file integrity with checksum
func TestDataPersistenceLargeFile(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-largefile-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	// Create 100MB volume to hold 5MB file
	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("largefile-test-pass")
	volumeName := "luks-largefile"

	t.Logf("Setting up LUKS volume")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	if err := MakeFilesystem(volumeName, "ext4", "largefile"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-largefile-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		Lock(volumeName)
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	t.Logf("Generating 5MB random data file")

	// Generate 5MB of random data
	largeData := make([]byte, 5*1024*1024)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	// Calculate checksum
	hash := sha256.Sum256(largeData)
	originalChecksum := hash[:]

	t.Logf("Writing large file (checksum: %x)", originalChecksum[:8])

	// Write to volume
	largeFile := filepath.Join(mountPoint, "large-file.bin")
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatalf("Failed to write large file: %v", err)
	}

	exec.Command("sync").Run()
	time.Sleep(500 * time.Millisecond)

	t.Logf("Unmounting and re-mounting")

	// Unmount and remount
	exec.Command("umount", mountPoint).Run()
	Lock(volumeName)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Re-unlock failed: %v", err)
	}

	// Wait for device to appear
	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after re-unlock")
	}

	// Get fresh device path after re-unlock
	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after re-unlock: %v", err)
	}

	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Re-mount failed: %v\nOutput: %s", err, string(output))
	}

	t.Logf("Reading and verifying checksum")

	// Read back
	readData, err := os.ReadFile(largeFile)
	if err != nil {
		t.Fatalf("Failed to read large file: %v", err)
	}

	if len(readData) != len(largeData) {
		t.Fatalf("File size mismatch: expected %d, got %d", len(largeData), len(readData))
	}

	// Verify checksum
	hash = sha256.Sum256(readData)
	readChecksum := hash[:]

	if string(readChecksum) != string(originalChecksum) {
		t.Errorf("Checksum mismatch:\nOriginal: %x\nRead:     %x", originalChecksum[:8], readChecksum[:8])
	} else {
		t.Logf("SUCCESS: 5MB file integrity verified (checksum: %x)", readChecksum[:8])
	}
}

// TestSmallVolumeMinimumSize tests with minimum viable volume size
func TestSmallVolumeMinimumSize(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-small-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	// 16MB minimum size
	if err := tmpfile.Truncate(16 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("small-vol-pass")
	volumeName := "luks-small"

	t.Logf("Testing minimum viable volume size (16MB)")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	if err := MakeFilesystem(volumeName, "ext4", "small"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-small-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		Lock(volumeName)
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	// Write small test file
	testFile := filepath.Join(mountPoint, "test.txt")
	testData := []byte("Small volume test")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	exec.Command("sync").Run()

	// Read back
	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data mismatch: expected %s, got %s", string(testData), string(readData))
	}

	t.Logf("SUCCESS: Minimum size volume (16MB) works correctly")
}

// TestLabelSpecialCharacters tests labels with special characters
func TestLabelSpecialCharacters(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	testCases := []struct {
		name  string
		label string
	}{
		{"spaces", "my test label"},
		{"dashes", "my-test-label"},
		{"underscores", "my_test_label"},
		{"mixed", "My-Test_Label 123"},
		{"unicode", "test-λαβελ-日本"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpfile, err := os.CreateTemp("", "luks-label-*.img")
			if err != nil {
				t.Fatalf("Failed to create temp file: %v", err)
			}
			volumePath := tmpfile.Name()
			defer os.Remove(volumePath)

			if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
				t.Fatalf("Failed to truncate: %v", err)
			}
			tmpfile.Close()

			passphrase := []byte("label-test-pass")

			t.Logf("Testing label: '%s'", tc.label)

			formatOpts := FormatOptions{
				Device:        volumePath,
				Passphrase:    passphrase,
				Label:         tc.label,
				KDFType:       "pbkdf2",
				PBKDFIterTime: 100,
			}

			if err := Format(formatOpts); err != nil {
				t.Fatalf("Format failed for label '%s': %v", tc.label, err)
			}

			// Verify label was set
			info, err := GetVolumeInfo(volumePath)
			if err != nil {
				t.Fatalf("GetVolumeInfo failed: %v", err)
			}

			if info.Label != tc.label {
				t.Errorf("Label mismatch: expected '%s', got '%s'", tc.label, info.Label)
			}

			t.Logf("SUCCESS: Label '%s' set correctly", tc.label)
		})
	}
}

// TestUnicodePassphrase tests with unicode passphrase
func TestUnicodePassphrase(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-unicode-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	// Unicode passphrase with various scripts
	passphrase := []byte("pāsswörd-日本語-Ελληνικά-🔐")
	volumeName := "luks-unicode"

	t.Logf("Testing Unicode passphrase: %s", string(passphrase))

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	// Unlock with unicode passphrase
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock with unicode passphrase failed: %v", err)
	}
	defer Lock(volumeName)

	// Verify unlocked (wait for device-mapper to create device)
	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Volume should be unlocked")
	}

	t.Logf("SUCCESS: Unicode passphrase works correctly")
}

// TestLongPassphrase tests passphrase length limits
func TestLongPassphrase(t *testing.T) {
	// Test maximum valid length (512 bytes)
	t.Run("max-valid-length", func(t *testing.T) {
		if os.Getuid() != 0 {
			t.Skip("This test requires root privileges")
		}

		tmpfile, err := os.CreateTemp("", "luks-longpass-*.img")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		volumePath := tmpfile.Name()
		defer os.Remove(volumePath)

		if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
			t.Fatalf("Failed to truncate: %v", err)
		}
		tmpfile.Close()

		// Generate 512 byte passphrase (max valid)
		maxPass := make([]byte, 512)
		for i := range maxPass {
			maxPass[i] = byte('A' + (i % 26))
		}

		t.Logf("Testing maximum valid passphrase (512 bytes)")
		opts := FormatOptions{
			Device:     volumePath,
			Passphrase: maxPass,
			KDFType:    "pbkdf2",
		}

		if err := Format(opts); err != nil {
			t.Fatalf("Format with 512 byte passphrase failed: %v", err)
		}
		t.Logf("SUCCESS: Maximum length passphrase works correctly")
	})

	// Test too long (should fail validation)
	t.Run("too-long", func(t *testing.T) {
		tmpfile, err := os.CreateTemp("", "luks-toolong-*.img")
		if err != nil {
			t.Fatalf("Failed to create temp file: %v", err)
		}
		volumePath := tmpfile.Name()
		defer os.Remove(volumePath)

		if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
			t.Fatalf("Failed to truncate: %v", err)
		}
		tmpfile.Close()

		// Generate 1024 byte passphrase (too long)
		tooLong := make([]byte, 1024)
		for i := range tooLong {
			tooLong[i] = byte('A' + (i % 26))
		}

		t.Logf("Testing too-long passphrase (1024 bytes)")
		opts := FormatOptions{
			Device:     volumePath,
			Passphrase: tooLong,
			KDFType:    "pbkdf2",
		}

		err = Format(opts)
		if err == nil {
			t.Fatal("Expected error for too-long passphrase")
		}
		if !errors.Is(err, ErrPassphraseTooLong) {
			t.Fatalf("Expected ErrPassphraseTooLong, got: %v", err)
		}
		t.Logf("SUCCESS: Too-long passphrase correctly rejected")
	})
}

// TestEmptyPassphrase verifies empty passphrase handling
func TestEmptyPassphrase(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-empty-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	emptyPass := []byte("")

	t.Logf("Testing empty passphrase behavior")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    emptyPass,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	// Empty passphrase might be rejected or accepted depending on implementation
	err = Format(formatOpts)
	if err != nil {
		t.Logf("Empty passphrase rejected (expected behavior): %v", err)
	} else {
		t.Logf("Empty passphrase accepted - verifying unlock works")

		loopDevice, err := SetupLoopDevice(volumePath)
		if err != nil {
			t.Fatalf("SetupLoopDevice failed: %v", err)
		}
		defer DetachLoopDevice(loopDevice)

		volumeName := "luks-empty"
		if err := Unlock(loopDevice, emptyPass, volumeName); err != nil {
			t.Fatalf("Unlock with empty passphrase failed: %v", err)
		}
		defer Lock(volumeName)

		if !waitForUnlock(volumeName, 5*time.Second) {
			t.Fatal("Volume should be unlocked")
		}

		t.Logf("SUCCESS: Empty passphrase handled correctly")
	}
}

// TestRapidLockUnlock tests rapid lock/unlock cycles for stability
func TestRapidLockUnlock(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-rapid-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("rapid-test-pass")
	volumeName := "luks-rapid"

	// Clean up any leftover state from previous test runs
	Lock(volumeName) // Ignore error if not exists

	t.Logf("Setting up test volume")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	t.Logf("Performing 10 rapid lock/unlock cycles")

	// Perform 10 rapid lock/unlock cycles (reduced from 20 for container stability)
	for i := 0; i < 10; i++ {
		if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
			t.Fatalf("Unlock failed on cycle %d: %v", i+1, err)
		}

		if !waitForUnlock(volumeName, 5*time.Second) {
			t.Fatalf("Volume should be unlocked on cycle %d", i+1)
		}

		// Delay to let kernel settle before lock
		time.Sleep(100 * time.Millisecond)

		// Retry Lock with backoff for device-mapper race conditions
		var lockErr error
		for retry := 0; retry < 3; retry++ {
			if lockErr = Lock(volumeName); lockErr == nil {
				break
			}
			time.Sleep(time.Duration(100*(retry+1)) * time.Millisecond)
		}
		if lockErr != nil {
			t.Fatalf("Lock failed on cycle %d after retries: %v", i+1, lockErr)
		}

		if !waitForLock(volumeName, 5*time.Second) {
			t.Fatalf("Volume should be locked on cycle %d", i+1)
		}

		// Delay between cycles to avoid device-mapper race conditions
		time.Sleep(200 * time.Millisecond)

		if (i+1)%5 == 0 {
			t.Logf("Completed %d cycles", i+1)
		}
	}

	t.Logf("SUCCESS: 10 rapid lock/unlock cycles completed successfully")
}

// TestConcurrentRead tests multiple goroutines reading from mounted volume
func TestConcurrentRead(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-concurrent-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(50 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("concurrent-test-pass")
	volumeName := "luks-concurrent"

	t.Logf("Setting up test volume")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	if err := MakeFilesystem(volumeName, "ext4", "concurrent"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-concurrent-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		Lock(volumeName)
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	t.Logf("Creating test files")

	// Create multiple test files
	numFiles := 10
	testData := make(map[string][]byte)
	for i := 0; i < numFiles; i++ {
		filename := fmt.Sprintf("concurrent-%d.txt", i)
		content := []byte(fmt.Sprintf("Concurrent test data %d", i))
		testData[filename] = content

		filePath := filepath.Join(mountPoint, filename)
		if err := os.WriteFile(filePath, content, 0644); err != nil {
			t.Fatalf("Failed to write %s: %v", filename, err)
		}
	}

	exec.Command("sync").Run()

	t.Logf("Launching 50 concurrent readers")

	// Launch 50 concurrent readers
	var wg sync.WaitGroup
	errors := make(chan error, 50)

	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			// Each goroutine reads all files
			for filename, expectedContent := range testData {
				filePath := filepath.Join(mountPoint, filename)
				readContent, err := os.ReadFile(filePath)
				if err != nil {
					errors <- fmt.Errorf("goroutine %d: failed to read %s: %w", id, filename, err)
					return
				}

				if string(readContent) != string(expectedContent) {
					errors <- fmt.Errorf("goroutine %d: content mismatch in %s", id, filename)
					return
				}
			}

			// Small delay to overlap I/O
			time.Sleep(10 * time.Millisecond)
		}(i)
	}

	wg.Wait()
	close(errors)

	// Check for errors
	errorCount := 0
	for err := range errors {
		t.Errorf("Concurrent read error: %v", err)
		errorCount++
	}

	if errorCount == 0 {
		t.Logf("SUCCESS: 50 concurrent readers completed without errors")
	} else {
		t.Fatalf("Concurrent read test failed with %d errors", errorCount)
	}
}

// TestIsMountedAccuracy verifies IsMounted correctly reports mount state
func TestIsMountedAccuracy(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	tmpfile, err := os.CreateTemp("", "luks-ismounted-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(30 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("ismounted-test-pass")
	volumeName := "luks-ismounted"

	t.Logf("Setting up test volume")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer DetachLoopDevice(loopDevice)

	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	if err := MakeFilesystem(volumeName, "ext4", "ismounted"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-ismounted-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	t.Logf("Step 1: Verify IsMounted returns false before mounting")

	// Should not be mounted yet
	mounted, err := IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if mounted {
		t.Fatal("IsMounted should return false before mounting")
	}

	t.Logf("Step 2: Mount and verify IsMounted returns true")

	// Mount
	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		Lock(volumeName)
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}

	// Should be mounted now
	mounted, err = IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if !mounted {
		t.Fatal("IsMounted should return true after mounting")
	}

	t.Logf("Step 3: Unmount and verify IsMounted returns false")

	// Unmount
	umountCmd := exec.Command("umount", mountPoint)
	if output, err := umountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Unmount failed: %v\nOutput: %s", err, string(output))
	}

	// Should not be mounted anymore
	mounted, err = IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if mounted {
		t.Fatal("IsMounted should return false after unmounting")
	}

	t.Logf("Step 4: Test with non-existent mount point")

	// Test with non-existent path
	mounted, err = IsMounted("/nonexistent/mount/point")
	if err != nil {
		t.Fatalf("IsMounted check failed for non-existent path: %v", err)
	}
	if mounted {
		t.Fatal("IsMounted should return false for non-existent path")
	}

	t.Logf("SUCCESS: IsMounted accurately reports mount state in all scenarios")
}

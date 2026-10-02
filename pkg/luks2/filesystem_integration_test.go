// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"errors"
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
	requireRoot(t)

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
	volumeName := runVolume(t, "test-fs-ext4")

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
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

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

// TestMakeFilesystemWithLabel tests creating filesystem with custom label
func TestMakeFilesystemWithLabel(t *testing.T) {
	requireRoot(t)

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
	volumeName := runVolume(t, "test-fs-label")
	fsLabel := "my-custom-label"

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
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

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
	requireRoot(t)

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

// TestCheckFilesystemFailureIsTypedOnHost runs the real e2fsck against a
// device that does not exist and checks the failure comes back as a
// *FilesystemCommandError naming the command and device, not as a refusal.
// The in-process unit test covers the same path through an injected runner.
func TestCheckFilesystemFailureIsTypedOnHost(t *testing.T) {
	const dev = "/dev/luks2-test-no-such-device"
	err := CheckFilesystem(dev, FilesystemExt4, false)

	var fce *FilesystemCommandError
	if !errors.As(err, &fce) {
		t.Fatalf("CheckFilesystem = %v (%T), want *FilesystemCommandError", err, err)
	}
	if fce.Command != "e2fsck" || fce.Device != dev {
		t.Errorf("FilesystemCommandError{Command: %q, Device: %q}, want e2fsck on %q", fce.Command, fce.Device, dev)
	}
	if fce.Err == nil || errors.Unwrap(err) != fce.Err {
		t.Errorf("Unwrap() = %v, want the exec error %v", errors.Unwrap(err), fce.Err)
	}
	if errors.Is(err, ErrUnsupportedFilesystem) {
		t.Errorf("a failed check of a supported type matched ErrUnsupportedFilesystem: %v", err)
	}
}

// TestFilesystemWriteRead tests writing and reading data to verify filesystem works
func TestFilesystemWriteRead(t *testing.T) {
	requireRoot(t)

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
	volumeName := runVolume(t, "test-fs-rw")

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
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

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
	requireRoot(t)

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
	volumeName := runVolume(t, "test-fs-persist")
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
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
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
	// Registered BEFORE the mapping can exist, so a partial or rolled-back
	// unlock cannot leave one behind either (#100). Idempotent.
	defer releaseVolume(t, volumeName)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Second unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

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

// runTool runs one e2fsprogs tool the repair test needs to build its fixture
// and fails the test, loudly, if it is missing or fails: test/integration's
// Dockerfile installs e2fsprogs, which carries mkfs.ext4 and debugfs, so a
// missing tool is a broken image, not an optional filesystem.
func runTool(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- fixed e2fsprogs tool; arguments are test constants and a TempDir path
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

// TestCheckFilesystemRepairsCorruptExt4 is #228 against the real e2fsck: an
// ext4 filesystem with a wrong inode link count is reported broken by a
// read-only check (e2fsck -n exits 4), repaired by CheckFilesystemDetailed
// with repair -- e2fsck -p corrects it and exits 1, which must be success
// with Repaired set, not a failure -- and is clean afterwards. It runs on an
// image file, which e2fsck checks as it does a block device, so it needs
// neither root nor a loop device.
func TestCheckFilesystemRepairsCorruptExt4(t *testing.T) {
	dir := t.TempDir()
	img := filepath.Join(dir, "ext4.img")
	if err := os.WriteFile(img, nil, 0o600); err != nil {
		t.Fatalf("creating the image: %v", err)
	}
	if err := os.Truncate(img, 16*1024*1024); err != nil {
		t.Fatalf("sizing the image: %v", err)
	}
	payload := filepath.Join(dir, "payload.txt")
	if err := os.WriteFile(payload, []byte("payload\n"), 0o600); err != nil {
		t.Fatalf("writing the payload: %v", err)
	}

	runTool(t, "mkfs.ext4", "-q", "-F", img)
	runTool(t, "debugfs", "-w", "-R", "write "+payload+" payload.txt", img)
	// Corrupt it: the file has one directory entry but claims five links.
	runTool(t, "debugfs", "-w", "-R", "sif /payload.txt links_count 5", img)
	// Mark it not cleanly unmounted, as a crash would, so e2fsck -p checks it
	// instead of trusting the clean flag.
	runTool(t, "debugfs", "-w", "-R", "ssv state 0", img)

	// The corruption is real: a read-only check fails with e2fsck's
	// "errors left uncorrected" status.
	err := CheckFilesystem(img, FilesystemExt4, false)
	var fce *FilesystemCommandError
	if !errors.As(err, &fce) || exitStatus(err) != e2fsckUncorrected {
		t.Fatalf("read-only check of the corrupted image = %v (exit %d), want a *FilesystemCommandError with exit %d",
			err, exitStatus(err), e2fsckUncorrected)
	}

	res, err := CheckFilesystemDetailed(img, FilesystemExt4, true)
	if err != nil {
		t.Fatalf("repairing check = %v, want success: e2fsck -p corrected the errors", err)
	}
	if !res.Repaired || res.RebootRequired {
		t.Errorf("repairing check result = %+v, want Repaired and no reboot request", res)
	}

	if err := CheckFilesystem(img, FilesystemExt4, false); err != nil {
		t.Errorf("read-only check after the repair = %v, want a clean filesystem", err)
	}
}

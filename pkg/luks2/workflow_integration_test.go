// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// TestFullEndToEndWorkflow tests the entire LUKS workflow from creation to cleanup
// This test creates a file-based LUKS volume, unlocks it, mounts it, writes data,
// reads data, and then cleans up. This verifies all operations work end-to-end.
func TestFullEndToEndWorkflow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Step 1: Create a temporary file for the LUKS volume
	tmpfile, err := os.CreateTemp("", "luks-workflow-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	// Create 100MB sparse file
	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-integration-passphrase-123")
	volumeName := "luks-integration-test"

	t.Logf("Step 1: Created volume file at %s", volumePath)

	// Step 2: Format the LUKS volume
	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		Label:         "integration-test",
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100, // Fast for testing
	}

	if err := Format(formatOpts); err != nil {
		t.Fatalf("Step 2 FAILED - Format: %v", err)
	}
	t.Logf("Step 2: Formatted LUKS volume successfully")

	// Step 3: Verify we can read the volume info
	info, err := GetVolumeInfo(volumePath)
	if err != nil {
		t.Fatalf("Step 3 FAILED - GetVolumeInfo: %v", err)
	}
	if info.Label != "integration-test" {
		t.Errorf("Step 3 - Label mismatch: got %s, expected integration-test", info.Label)
	}
	t.Logf("Step 3: Read volume info successfully (Label: %s)", info.Label)

	// Step 4: Setup loop device (required for file-based volumes)
	loopDevice, err := SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Step 4 FAILED - SetupLoopDevice: %v", err)
	}
	defer DetachLoopDevice(loopDevice)
	t.Logf("Step 4: Setup loop device %s", loopDevice)

	// Step 5: Unlock the LUKS volume
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Step 5 FAILED - Unlock: %v", err)
	}
	defer Lock(volumeName)
	t.Logf("Step 5: Unlocked LUKS volume as %s", volumeName)

	// Verify the device-mapper device exists (wait for it to appear)
	var dmExists bool
	for i := 0; i < 50; i++ {
		if IsUnlocked(volumeName) {
			dmExists = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !dmExists {
		t.Fatalf("Step 5 verification FAILED - Device-mapper device not found after 5 seconds")
	}

	// Get the actual device path (handles both udev and non-udev environments)
	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("Step 5 verification FAILED - Could not get device path: %v", err)
	}
	t.Logf("Step 5 verified: Device-mapper device exists at %s", dmDevicePath)

	// Step 6: Create filesystem on the unlocked volume
	if err := MakeFilesystem(volumeName, "ext4", "testfs"); err != nil {
		t.Fatalf("Step 6 FAILED - MakeFilesystem: %v", err)
	}
	t.Logf("Step 6: Created ext4 filesystem")

	// Step 7: Create mount point
	mountPoint := filepath.Join(os.TempDir(), "luks-test-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Step 7 FAILED - Create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)
	t.Logf("Step 7: Created mount point at %s", mountPoint)

	// Step 8: Mount the filesystem
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Step 8 FAILED - Mount: %v\nOutput: %s", err, string(output))
	}
	defer func() {
		// Ensure we unmount even if test fails
		exec.Command("umount", mountPoint).Run()
	}()
	t.Logf("Step 8: Mounted filesystem at %s", mountPoint)

	// Wait a moment for mount to stabilize
	time.Sleep(500 * time.Millisecond)

	// Step 9: Write test data to the mounted volume
	testFile := filepath.Join(mountPoint, "test-data.txt")
	testData := []byte("This is integration test data written to the LUKS encrypted volume!")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Step 9 FAILED - Write test file: %v", err)
	}
	t.Logf("Step 9: Wrote test data to %s", testFile)

	// Step 10: Read test data back and verify
	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Step 10 FAILED - Read test file: %v", err)
	}
	if string(readData) != string(testData) {
		t.Errorf("Step 10 FAILED - Data mismatch:\nExpected: %s\nGot: %s", string(testData), string(readData))
	}
	t.Logf("Step 10: Read and verified test data successfully")

	// Step 11: Unmount the filesystem
	umountCmd := exec.Command("umount", mountPoint)
	if output, err := umountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Step 11 FAILED - Unmount: %v\nOutput: %s", err, string(output))
	}
	t.Logf("Step 11: Unmounted filesystem")

	// Step 12: Close/lock the LUKS volume
	if err := Lock(volumeName); err != nil {
		t.Fatalf("Step 12 FAILED - Lock: %v", err)
	}
	t.Logf("Step 12: Locked LUKS volume")

	// Step 13: Verify device-mapper device is removed
	if _, err := os.Stat(dmDevicePath); err == nil {
		t.Errorf("Step 13 FAILED - Device-mapper device still exists after lock")
	}
	t.Logf("Step 13: Verified device-mapper device removed")

	// Step 14: Detach loop device (deferred cleanup)
	// This will happen in defer DetachLoopDevice(loopDevice) above

	t.Logf("SUCCESS: Complete workflow test passed!")
	t.Logf("  ✓ Created LUKS volume")
	t.Logf("  ✓ Formatted with LUKS2")
	t.Logf("  ✓ Setup loop device")
	t.Logf("  ✓ Unlocked with passphrase")
	t.Logf("  ✓ Created ext4 filesystem")
	t.Logf("  ✓ Mounted volume")
	t.Logf("  ✓ Wrote data to encrypted volume")
	t.Logf("  ✓ Read and verified data")
	t.Logf("  ✓ Unmounted volume")
	t.Logf("  ✓ Locked volume")
	t.Logf("  ✓ Cleaned up resources")
}

// TestFileVolumeOnly verifies we're testing file-based volumes, not block devices
func TestFileVolumeOnly(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("This test requires root privileges")
	}

	// Create a temporary file
	tmpfile, err := os.CreateTemp("", "luks-file-test-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(50 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	// Verify it's a regular file, not a block device
	stat, err := os.Stat(volumePath)
	if err != nil {
		t.Fatalf("Failed to stat: %v", err)
	}

	if stat.Mode()&os.ModeDevice != 0 {
		t.Fatalf("Expected regular file, got block device")
	}

	t.Logf("Confirmed: Testing file-based volume (not block device)")
	t.Logf("  File: %s", volumePath)
	t.Logf("  Size: %d bytes", stat.Size())
	t.Logf("  Mode: %s", stat.Mode())
}

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// TestFullEndToEndWorkflow tests the entire LUKS workflow from creation to
// cleanup: format, unlock, mount, write, read, unmount, lock.
func TestFullEndToEndWorkflow(t *testing.T) {
	requireRoot(t)

	tmpfile, err := os.CreateTemp("", "luks-workflow-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("test-integration-passphrase-123")
	volumeName := runVolume(t, "luks-integration-test")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		Label:         "integration-test",
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format: %v", err)
	}

	info, err := harness.GetVolumeInfo(volumePath)
	if err != nil {
		t.Fatalf("GetVolumeInfo: %v", err)
	}
	if info.Label != "integration-test" {
		t.Errorf("Label mismatch: got %s, expected integration-test", info.Label)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	var dmExists bool
	for i := 0; i < 50; i++ {
		if IsUnlocked(volumeName) {
			dmExists = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !dmExists {
		t.Fatalf("Device-mapper device not found after 5 seconds")
	}

	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("Could not get device path: %v", err)
	}

	if err := harness.MakeFilesystem(volumeName, "ext4", "testfs"); err != nil {
		t.Fatalf("MakeFilesystem: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-test-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount: %v\nOutput: %s", err, string(output))
	}
	defer func() { exec.Command("umount", mountPoint).Run() }()

	testFile := filepath.Join(mountPoint, "test-data.txt")
	testData := []byte("This is integration test data written to the LUKS encrypted volume!")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Write test file: %v", err)
	}

	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Read test file: %v", err)
	}
	if string(readData) != string(testData) {
		t.Errorf("Data mismatch:\nExpected: %s\nGot: %s", string(testData), string(readData))
	}

	umountCmd := exec.Command("umount", mountPoint)
	if output, err := umountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Unmount: %v\nOutput: %s", err, string(output))
	}

	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock: %v", err)
	}

	if _, err := os.Stat(dmDevicePath); err == nil {
		t.Errorf("Device-mapper device still exists after lock")
	}
}

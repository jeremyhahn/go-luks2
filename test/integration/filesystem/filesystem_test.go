// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package filesystem_test

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/pkg/filesystem"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// formatForTest formats path as a minimal PBKDF2 LUKS2 container, the way
// the pre-redesign library's free function Format did
// before B.6 moved Format behind (*luks2.Volume).Format.
func formatForTest(path string, passphrase []byte) error {
	ctx := context.Background()
	v, err := luks2.Open(ctx, path)
	if err != nil {
		return err
	}
	defer func() { _ = v.Close() }()

	pass, err := enclave.NewMemoryCopy(passphrase)
	if err != nil {
		return err
	}
	defer func() { _ = pass.Destroy() }()

	return v.Format(ctx, pass, luks2.FormatParams{
		KDF: luks2.KDFParams{Type: luks2.KDFPBKDF2, IterTime: 100 * time.Millisecond},
	})
}

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

	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	if err := harness.MakeFilesystem(volumeName, "ext4", "test-ext4"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-fs-ext4-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer harness.Unmount(mountPoint, 0)

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

	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	if err := harness.MakeFilesystem(volumeName, "ext4", fsLabel); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	exec.Command("sync").Run()

	devicePath := "/dev/mapper/" + volumeName

	var actualLabel string
	var labelErr error
	for i := 0; i < 10; i++ {
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

func TestMakeFilesystemErrors(t *testing.T) {
	requireRoot(t)

	tests := []struct {
		name       string
		volumeName string
		fstype     string
		label      string
		wantErr    bool
	}{
		{"nonexistent-volume", "nonexistent-volume", "ext4", "test", true},
		{"unsupported-filesystem", "test-volume", "invalid-fs-type", "test", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := harness.MakeFilesystem(tt.volumeName, tt.fstype, tt.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeFilesystem() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCheckFilesystemFailureIsTypedOnHost(t *testing.T) {
	const dev = "/dev/luks2-test-no-such-device"
	err := harness.CheckFilesystem(dev, harness.FilesystemExt4, false)

	var fce *harness.FilesystemCommandError
	if !errors.As(err, &fce) {
		t.Fatalf("CheckFilesystem = %v (%T), want *FilesystemCommandError", err, err)
	}
	if fce.Command != "e2fsck" || fce.Device != dev {
		t.Errorf("FilesystemCommandError{Command: %q, Device: %q}, want e2fsck on %q", fce.Command, fce.Device, dev)
	}
	if fce.Err == nil || errors.Unwrap(err) != fce.Err {
		t.Errorf("Unwrap() = %v, want the exec error %v", errors.Unwrap(err), fce.Err)
	}
	if errors.Is(err, filesystem.ErrUnsupported) {
		t.Errorf("a failed check of a supported type matched ErrUnsupportedFilesystem: %v", err)
	}
}

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
	volumeName := runVolume(t, "test-fs-rw")

	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	if err := harness.MakeFilesystem(volumeName, "ext4", "test-rw"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-fs-rw-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}
	defer harness.Unmount(mountPoint, 0)

	testFile := filepath.Join(mountPoint, "testfile.txt")
	testData := []byte("Hello, LUKS filesystem!")

	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data mismatch: expected %q, got %q", testData, readData)
	}

	testDir := filepath.Join(mountPoint, "testdir")
	if err := os.MkdirAll(testDir, 0755); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}

	if stat, err := os.Stat(testDir); err != nil {
		t.Fatalf("Failed to stat test directory: %v", err)
	} else if !stat.IsDir() {
		t.Error("Expected testdir to be a directory")
	}

	nestedFile := filepath.Join(testDir, "nested.txt")
	nestedData := []byte("Nested file content")
	if err := os.WriteFile(nestedFile, nestedData, 0644); err != nil {
		t.Fatalf("Failed to write nested file: %v", err)
	}

	readNested, err := os.ReadFile(nestedFile)
	if err != nil {
		t.Fatalf("Failed to read nested file: %v", err)
	}

	if string(readNested) != string(nestedData) {
		t.Errorf("Nested data mismatch: expected %q, got %q", nestedData, readNested)
	}
}

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
	volumeName := runVolume(t, "test-fs-persist")
	testData := []byte("Persistent data test")

	if err := formatForTest(volumePath, passphrase); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	if err := harness.MakeFilesystem(volumeName, "ext4", "test-persist"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-fs-persist-test")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Mount failed: %v", err)
	}

	testFile := filepath.Join(mountPoint, "persistent.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		harness.Unmount(mountPoint, 0)
		t.Fatalf("Failed to write test file: %v", err)
	}

	if err := harness.Unmount(mountPoint, 0); err != nil {
		t.Fatalf("Unmount failed: %v", err)
	}

	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Second unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName)

	if !waitForDevice(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after second unlock")
	}

	if err := harness.Mount(harness.MountOptions{Device: volumeName, MountPoint: mountPoint, FSType: "ext4"}); err != nil {
		t.Fatalf("Second mount failed: %v", err)
	}
	defer harness.Unmount(mountPoint, 0)

	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("Failed to read test file after remount: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data did not persist: expected %q, got %q", testData, readData)
	}

	additionalData := []byte("Additional data after remount")
	additionalFile := filepath.Join(mountPoint, "additional.txt")
	if err := os.WriteFile(additionalFile, additionalData, 0644); err != nil {
		t.Fatalf("Failed to write additional file: %v", err)
	}

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

func runTool(t *testing.T, name string, args ...string) {
	t.Helper()
	out, err := exec.Command(name, args...).CombinedOutput() // #nosec G204 -- fixed e2fsprogs tool; arguments are test constants and a TempDir path
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
}

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
	runTool(t, "debugfs", "-w", "-R", "sif /payload.txt links_count 5", img)
	runTool(t, "debugfs", "-w", "-R", "ssv state 0", img)

	err := harness.CheckFilesystem(img, harness.FilesystemExt4, false)
	var fce *harness.FilesystemCommandError
	var ec interface{ ExitCode() int }
	const e2fsckUncorrected = 4
	if !errors.As(err, &fce) || !errors.As(err, &ec) || ec.ExitCode() != e2fsckUncorrected {
		t.Fatalf("read-only check of the corrupted image = %v, want a *FilesystemCommandError with exit %d",
			err, e2fsckUncorrected)
	}

	res, err := harness.CheckFilesystemDetailed(img, harness.FilesystemExt4, true)
	if err != nil {
		t.Fatalf("repairing check = %v, want success: e2fsck -p corrected the errors", err)
	}
	if !res.Repaired || res.RebootRequired {
		t.Errorf("repairing check result = %+v, want Repaired and no reboot request", res)
	}

	if err := harness.CheckFilesystem(img, harness.FilesystemExt4, false); err != nil {
		t.Errorf("read-only check after the repair = %v, want a clean filesystem", err)
	}
}

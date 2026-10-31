// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

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

func TestDataPersistenceAcrossUnlockCycles(t *testing.T) {
	requireRoot(t)

	tmpfile, err := os.CreateTemp("", "luks-persist-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(50 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("persistence-test-passphrase")
	volumeName := runVolume(t, "luks-persist-test")
	testData := []byte("This data must persist across lock/unlock cycles!")

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

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("First Unlock failed: %v", err)
	}

	if err := harness.MakeFilesystem(volumeName, "ext4", "persistfs"); err != nil {
		Lock(volumeName)
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-persist-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		Lock(volumeName)
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
		Lock(volumeName)
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}

	testFile := filepath.Join(mountPoint, "persistence-test.txt")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		exec.Command("umount", mountPoint).Run()
		Lock(volumeName)
		t.Fatalf("WriteFile failed: %v", err)
	}

	exec.Command("sync").Run()

	umountCmd := exec.Command("umount", mountPoint)
	if output, err := umountCmd.CombinedOutput(); err != nil {
		Lock(volumeName)
		t.Fatalf("Unmount failed: %v\nOutput: %s", err, string(output))
	}

	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Second Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after second unlock")
	}

	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after second unlock: %v", err)
	}

	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Second Mount failed: %v\nOutput: %s", err, string(output))
	}
	defer exec.Command("umount", mountPoint).Run()

	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed after unlock: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data mismatch after unlock cycle:\nExpected: %s\nGot: %s", string(testData), string(readData))
	}

	exec.Command("umount", mountPoint).Run()
	Lock(volumeName)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Third Unlock failed: %v", err)
	}

	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after third unlock")
	}

	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after third unlock: %v", err)
	}

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

	// Unmount before the deferred releaseVolume calls try to close the
	// mapping: a filesystem still mounted from it holds it open, and no
	// amount of retrying in releaseVolume frees what only umount can.
	_ = exec.Command("umount", mountPoint).Run()
}

func TestDataPersistenceMultipleFiles(t *testing.T) {
	requireRoot(t)

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
	volumeName := runVolume(t, "luks-multifile")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if err := harness.MakeFilesystem(volumeName, "ext4", "multifile"); err != nil {
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

	exec.Command("umount", mountPoint).Run()
	Lock(volumeName)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Re-unlock failed: %v", err)
	}

	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after re-unlock")
	}

	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after re-unlock: %v", err)
	}

	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Re-mount failed: %v\nOutput: %s", err, string(output))
	}

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

	// Unmount before the deferred releaseVolume calls try to close the
	// mapping: a filesystem still mounted from it holds it open, and no
	// amount of retrying in releaseVolume frees what only umount can.
	_ = exec.Command("umount", mountPoint).Run()
}

func TestDataPersistenceLargeFile(t *testing.T) {
	requireRoot(t)

	tmpfile, err := os.CreateTemp("", "luks-largefile-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(100 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("largefile-test-pass")
	volumeName := runVolume(t, "luks-largefile")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if err := harness.MakeFilesystem(volumeName, "ext4", "largefile"); err != nil {
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

	largeData := make([]byte, 5*1024*1024)
	if _, err := rand.Read(largeData); err != nil {
		t.Fatalf("Failed to generate random data: %v", err)
	}

	hash := sha256.Sum256(largeData)
	originalChecksum := hash[:]

	largeFile := filepath.Join(mountPoint, "large-file.bin")
	if err := os.WriteFile(largeFile, largeData, 0644); err != nil {
		t.Fatalf("Failed to write large file: %v", err)
	}

	exec.Command("sync").Run()

	exec.Command("umount", mountPoint).Run()
	Lock(volumeName)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Re-unlock failed: %v", err)
	}

	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Device did not appear after re-unlock")
	}

	dmDevicePath, err = GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed after re-unlock: %v", err)
	}

	mountCmd = exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Re-mount failed: %v\nOutput: %s", err, string(output))
	}

	readData, err := os.ReadFile(largeFile)
	if err != nil {
		t.Fatalf("Failed to read large file: %v", err)
	}

	if len(readData) != len(largeData) {
		t.Fatalf("File size mismatch: expected %d, got %d", len(largeData), len(readData))
	}

	hash = sha256.Sum256(readData)
	readChecksum := hash[:]

	if string(readChecksum) != string(originalChecksum) {
		t.Errorf("Checksum mismatch:\nOriginal: %x\nRead:     %x", originalChecksum[:8], readChecksum[:8])
	}

	// Unmount before the deferred releaseVolume calls try to close the
	// mapping: a filesystem still mounted from it holds it open, and no
	// amount of retrying in releaseVolume frees what only umount can.
	_ = exec.Command("umount", mountPoint).Run()
}

func TestSmallVolumeMinimumSize(t *testing.T) {
	requireRoot(t)

	tmpfile, err := os.CreateTemp("", "luks-small-*.img")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	volumePath := tmpfile.Name()
	defer os.Remove(volumePath)

	if err := tmpfile.Truncate(32 * 1024 * 1024); err != nil {
		t.Fatalf("Failed to truncate: %v", err)
	}
	tmpfile.Close()

	passphrase := []byte("small-vol-pass")
	volumeName := runVolume(t, "luks-small")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if err := harness.MakeFilesystem(volumeName, "ext4", "small"); err != nil {
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

	testFile := filepath.Join(mountPoint, "test.txt")
	testData := []byte("Small volume test")
	if err := os.WriteFile(testFile, testData, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	exec.Command("sync").Run()

	readData, err := os.ReadFile(testFile)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("Data mismatch: expected %s, got %s", string(testData), string(readData))
	}
}

func TestLabelSpecialCharacters(t *testing.T) {
	requireRoot(t)

	testCases := []struct{ name, label string }{
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

			info, err := harness.GetVolumeInfo(volumePath)
			if err != nil {
				t.Fatalf("GetVolumeInfo failed: %v", err)
			}

			if info.Label != tc.label {
				t.Errorf("Label mismatch: expected '%s', got '%s'", tc.label, info.Label)
			}
		})
	}
}

func TestUnicodePassphrase(t *testing.T) {
	requireRoot(t)

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

	passphrase := []byte("pāsswörd-日本語-Ελληνικά-🔐")
	volumeName := runVolume(t, "luks-unicode")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock with unicode passphrase failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Volume should be unlocked")
	}
}

func TestLongPassphrase(t *testing.T) {
	t.Run("max-valid-length", func(t *testing.T) {
		requireRoot(t)

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

		maxPass := make([]byte, 512)
		for i := range maxPass {
			maxPass[i] = byte('A' + (i % 26))
		}

		opts := FormatOptions{
			Device:        volumePath,
			Passphrase:    maxPass,
			KDFType:       "pbkdf2",
			PBKDFIterTime: 1,
		}
		if err := Format(opts); err != nil {
			t.Fatalf("Format with 512 byte passphrase failed: %v", err)
		}
	})

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

		tooLong := make([]byte, 1024)
		for i := range tooLong {
			tooLong[i] = byte('A' + (i % 26))
		}

		opts := FormatOptions{
			Device:        volumePath,
			Passphrase:    tooLong,
			KDFType:       "pbkdf2",
			PBKDFIterTime: 1,
		}

		err = Format(opts)
		if err == nil {
			t.Fatal("Expected error for too-long passphrase")
		}
		if !errors.Is(err, luks2.ErrInvalidCredential) {
			t.Fatalf("Expected ErrPassphraseTooLong, got: %v", err)
		}
	})
}

func TestEmptyPassphrase(t *testing.T) {
	requireRoot(t)

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

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    emptyPass,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}

	err = Format(formatOpts)
	if err != nil {
		t.Logf("Empty passphrase rejected (expected behavior): %v", err)
		return
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	volumeName := runVolume(t, "luks-empty")
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, emptyPass, volumeName); err != nil {
		t.Fatalf("Unlock with empty passphrase failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if !waitForUnlock(volumeName, 5*time.Second) {
		t.Fatal("Volume should be unlocked")
	}
}

func TestRapidLockUnlock(t *testing.T) {
	requireRoot(t)

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
	volumeName := runVolume(t, "luks-rapid")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	for i := 0; i < 10; i++ {
		if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
			t.Fatalf("Unlock failed on cycle %d: %v", i+1, err)
		}

		if !waitForUnlock(volumeName, 5*time.Second) {
			t.Fatalf("Volume should be unlocked on cycle %d", i+1)
		}

		// Lock can briefly find the mapping busy (udev probes a new node),
		// so it is polled until it succeeds or the deadline passes.
		var lockErr error
		lockDeadline := time.Now().Add(5 * time.Second)
		for {
			if lockErr = Lock(volumeName); lockErr == nil || !time.Now().Before(lockDeadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if lockErr != nil {
			t.Fatalf("Lock failed on cycle %d after retries: %v", i+1, lockErr)
		}

		if !waitForLock(volumeName, 5*time.Second) {
			t.Fatalf("Volume should be locked on cycle %d", i+1)
		}
	}
}

func TestIsMountedAccuracy(t *testing.T) {
	requireRoot(t)

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
	volumeName := runVolume(t, "luks-ismounted")

	formatOpts := FormatOptions{
		Device:        volumePath,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 100,
	}
	if err := Format(formatOpts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDevice, err := harness.SetupLoopDevice(volumePath)
	if err != nil {
		t.Fatalf("SetupLoopDevice failed: %v", err)
	}
	defer harness.DetachLoopDevice(loopDevice)

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDevice, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })

	if err := harness.MakeFilesystem(volumeName, "ext4", "ismounted"); err != nil {
		t.Fatalf("MakeFilesystem failed: %v", err)
	}

	mountPoint := filepath.Join(os.TempDir(), "luks-ismounted-mount")
	if err := os.MkdirAll(mountPoint, 0755); err != nil {
		t.Fatalf("Failed to create mount point: %v", err)
	}
	defer os.RemoveAll(mountPoint)

	mounted, err := harness.IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if mounted {
		t.Fatal("IsMounted should return false before mounting")
	}

	dmDevicePath, err := GetMappedDevicePath(volumeName)
	if err != nil {
		t.Fatalf("GetMappedDevicePath failed: %v", err)
	}
	mountCmd := exec.Command("mount", dmDevicePath, mountPoint)
	if output, err := mountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Mount failed: %v\nOutput: %s", err, string(output))
	}

	mounted, err = harness.IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if !mounted {
		t.Fatal("IsMounted should return true after mounting")
	}

	umountCmd := exec.Command("umount", mountPoint)
	if output, err := umountCmd.CombinedOutput(); err != nil {
		t.Fatalf("Unmount failed: %v\nOutput: %s", err, string(output))
	}

	mounted, err = harness.IsMounted(mountPoint)
	if err != nil {
		t.Fatalf("IsMounted check failed: %v", err)
	}
	if mounted {
		t.Fatal("IsMounted should return false after unmounting")
	}

	mounted, err = harness.IsMounted("/nonexistent/mount/point")
	if err != nil {
		t.Fatalf("IsMounted check failed for non-existent path: %v", err)
	}
	if mounted {
		t.Fatal("IsMounted should return false for non-existent path")
	}
}

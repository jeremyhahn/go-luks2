// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestUnlockBasic(t *testing.T) {
	tmpfile := "/tmp/test-luks-unlock.img"
	volumeName := "test-unlock"
	var loopDev string
	defer func() { testCleanup(volumeName, loopDev, tmpfile) }()

	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	passphrase := []byte("test-password")
	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: passphrase,
		KDFType:    "pbkdf2",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var err error
	loopDev, err = luks2.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}

	// Cleanup any leftover device mapper from previous runs
	_ = luks2.Lock(volumeName)

	if err := luks2.Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Verify it's unlocked
	if !waitForUnlock(volumeName, 5000) {
		t.Fatal("Volume should be unlocked")
	}

	// Verify IsUnlocked returns true
	if !luks2.IsUnlocked(volumeName) {
		t.Error("IsUnlocked should return true for unlocked volume")
	}

	// Lock it
	if err := luks2.Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Verify it's locked
	if !waitForLock(volumeName, 5000) {
		t.Fatal("Volume should be locked")
	}
}

func TestUnlockWithWrongPassphrase(t *testing.T) {
	tmpfile := "/tmp/test-luks-wrong-pass.img"
	volumeName := "test-wrong-pass"
	var loopDev string
	defer func() { testCleanup(volumeName, loopDev, tmpfile) }()

	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("correct-password"),
		KDFType:    "pbkdf2",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	var err error
	loopDev, err = luks2.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}

	// Try with wrong passphrase
	err = luks2.Unlock(loopDev, []byte("wrong-password"), volumeName)
	if err == nil {
		luks2.Lock(volumeName)
		t.Fatal("Unlock should have failed with wrong passphrase")
	}
}

func TestUnlockErrors(t *testing.T) {
	tests := []struct {
		name       string
		device     string
		passphrase []byte
		volumeName string
	}{
		{
			name:       "nonexistent-device",
			device:     "/dev/nonexistent",
			passphrase: []byte("test"),
			volumeName: "test",
		},
		{
			name:       "empty-volume-name",
			device:     "/dev/loop0",
			passphrase: []byte("test"),
			volumeName: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := luks2.Unlock(tt.device, tt.passphrase, tt.volumeName)
			if err == nil {
				luks2.Lock(tt.volumeName)
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestLockErrors(t *testing.T) {
	err := luks2.Lock("nonexistent-volume")
	if err == nil {
		t.Fatal("Expected error when locking nonexistent volume")
	}
}

func TestIsUnlockedNonexistent(t *testing.T) {
	if luks2.IsUnlocked("definitely-not-a-real-volume") {
		t.Error("IsUnlocked should return false for nonexistent volume")
	}
}

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"testing"
	"time"
)

// TestUnlockBasic tests basic LUKS volume unlocking
func TestUnlockBasic(t *testing.T) {
	tmpfile := "/tmp/test-luks-unlock.img"
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

	passphrase := []byte("test-password")
	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: passphrase,
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Setup loop device
	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Unlock
	volumeName := "test-unlock"
	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Verify it's unlocked (wait for device-mapper to create device)
	unlocked := false
	for i := 0; i < 50; i++ {
		if IsUnlocked(volumeName) {
			unlocked = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !unlocked {
		t.Fatal("Volume should be unlocked")
	}

	// Lock it
	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Verify it's locked (wait for device-mapper to remove device)
	locked := false
	for i := 0; i < 50; i++ {
		if !IsUnlocked(volumeName) {
			locked = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !locked {
		t.Fatal("Volume should be locked")
	}
}

// TestUnlockWithWrongPassphrase tests unlock failures with incorrect passphrase
func TestUnlockWithWrongPassphrase(t *testing.T) {
	tmpfile := "/tmp/test-luks-wrong-pass.img"
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
		Passphrase: []byte("correct-password"),
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer DetachLoopDevice(loopDev)

	// Try with wrong passphrase
	err = Unlock(loopDev, []byte("wrong-password"), "test-wrong-pass")
	if err == nil {
		Lock("test-wrong-pass")
		t.Fatal("Unlock should have failed with wrong passphrase")
	}
}

// TestUnlockErrors tests error conditions during unlock
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
			err := Unlock(tt.device, tt.passphrase, tt.volumeName)
			if err == nil {
				Lock(tt.volumeName)
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

// TestLockErrors tests lock error conditions
func TestLockErrors(t *testing.T) {
	err := Lock("nonexistent-volume")
	if err == nil {
		t.Fatal("Expected error when locking nonexistent volume")
	}
}

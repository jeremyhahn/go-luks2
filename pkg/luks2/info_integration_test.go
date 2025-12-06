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

// waitForDeviceState waits for the device-mapper device to reach expected state
func waitForDeviceState(name string, shouldExist bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		exists := IsUnlocked(name)
		if exists == shouldExist {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

// TestGetVolumeInfo tests retrieving volume info from a formatted LUKS volume
func TestGetVolumeInfo(t *testing.T) {
	tmpfile := "/tmp/test-luks-info.img"
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
		Cipher:     "aes",
		CipherMode: "xts-plain64",
		KeySize:    512,
		SectorSize: 512,
		HashAlgo:   "sha256",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Get volume info
	info, err := GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed: %v", err)
	}

	// Verify fields
	if info.UUID == "" {
		t.Error("UUID should not be empty")
	}

	if info.Version != LUKS2Version {
		t.Errorf("Expected version %d, got %d", LUKS2Version, info.Version)
	}

	expectedCipher := "aes-xts-plain64"
	if info.Cipher != expectedCipher {
		t.Errorf("Expected cipher %s, got %s", expectedCipher, info.Cipher)
	}

	if info.SectorSize != 512 {
		t.Errorf("Expected sector size 512, got %d", info.SectorSize)
	}

	if len(info.ActiveKeyslots) == 0 {
		t.Error("Expected at least one active keyslot")
	}

	// Verify keyslot 0 is active
	hasKeyslot0 := false
	for _, slot := range info.ActiveKeyslots {
		if slot == 0 {
			hasKeyslot0 = true
			break
		}
	}
	if !hasKeyslot0 {
		t.Error("Expected keyslot 0 to be active")
	}

	// Verify metadata is present
	if info.Metadata == nil {
		t.Fatal("Metadata should not be nil")
	}

	if len(info.Metadata.Keyslots) == 0 {
		t.Error("Expected metadata to contain keyslots")
	}

	if len(info.Metadata.Segments) == 0 {
		t.Error("Expected metadata to contain segments")
	}

	if len(info.Metadata.Digests) == 0 {
		t.Error("Expected metadata to contain digests")
	}

	if info.Metadata.Config == nil {
		t.Error("Expected metadata config to be present")
	}
}

// TestGetVolumeInfoWithLabel tests that volume labels are correctly returned
func TestGetVolumeInfoWithLabel(t *testing.T) {
	tmpfile := "/tmp/test-luks-label.img"
	defer os.Remove(tmpfile)

	// Create and format volume with label
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	expectedLabel := "test-volume"
	passphrase := []byte("test-password")
	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: passphrase,
		Label:      expectedLabel,
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Get volume info
	info, err := GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed: %v", err)
	}

	// Verify label
	if info.Label != expectedLabel {
		t.Errorf("Expected label %s, got %s", expectedLabel, info.Label)
	}
}

// TestGetVolumeInfoWithSubsystem tests that subsystem labels are correctly returned
func TestGetVolumeInfoWithSubsystem(t *testing.T) {
	tmpfile := "/tmp/test-luks-subsystem.img"
	defer os.Remove(tmpfile)

	// Create and format volume with subsystem
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create file: %v", err)
	}
	if err := f.Truncate(50 * 1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate: %v", err)
	}
	f.Close()

	expectedSubsystem := "test-subsystem"
	passphrase := []byte("test-password")
	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: passphrase,
		Subsystem:  expectedSubsystem,
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Read header directly to verify subsystem
	hdr, _, err := ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	// Verify subsystem is stored in header
	subsystem := string(hdr.SubsystemLabel[:])
	// Trim null bytes
	for i, b := range subsystem {
		if b == 0 {
			subsystem = subsystem[:i]
			break
		}
	}

	if subsystem != expectedSubsystem {
		t.Errorf("Expected subsystem %s, got %s", expectedSubsystem, subsystem)
	}
}

// TestGetVolumeInfoKDFType tests that KDF type is correctly reported in metadata
func TestGetVolumeInfoKDFType(t *testing.T) {
	tests := []struct {
		name    string
		kdfType string
	}{
		{
			name:    "pbkdf2",
			kdfType: "pbkdf2",
		},
		{
			name:    "argon2id",
			kdfType: "argon2id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile := "/tmp/test-luks-kdf-" + tt.name + ".img"
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
				KDFType:    tt.kdfType,
			}

			if err := Format(opts); err != nil {
				t.Fatalf("Format failed: %v", err)
			}

			// Get volume info
			info, err := GetVolumeInfo(tmpfile)
			if err != nil {
				t.Fatalf("GetVolumeInfo failed: %v", err)
			}

			// Verify KDF type in first keyslot
			if info.Metadata == nil {
				t.Fatal("Metadata should not be nil")
			}

			keyslot, exists := info.Metadata.Keyslots["0"]
			if !exists {
				t.Fatal("Expected keyslot 0 to exist")
			}

			if keyslot.KDF == nil {
				t.Fatal("KDF should not be nil")
			}

			if keyslot.KDF.Type != tt.kdfType {
				t.Errorf("Expected KDF type %s, got %s", tt.kdfType, keyslot.KDF.Type)
			}

			// Verify KDF-specific fields
			switch tt.kdfType {
			case "pbkdf2":
				if keyslot.KDF.Hash == "" {
					t.Error("PBKDF2 should have hash field")
				}
				if keyslot.KDF.Iterations == nil || *keyslot.KDF.Iterations <= 0 {
					t.Error("PBKDF2 should have positive iterations")
				}
			case "argon2id":
				if keyslot.KDF.Time == nil || *keyslot.KDF.Time <= 0 {
					t.Error("Argon2id should have positive time cost")
				}
				if keyslot.KDF.Memory == nil || *keyslot.KDF.Memory <= 0 {
					t.Error("Argon2id should have positive memory cost")
				}
				if keyslot.KDF.CPUs == nil || *keyslot.KDF.CPUs <= 0 {
					t.Error("Argon2id should have positive CPU count")
				}
			}
		})
	}
}

// TestGetVolumeInfoErrors tests error conditions for GetVolumeInfo
func TestGetVolumeInfoErrors(t *testing.T) {
	tests := []struct {
		name        string
		device      string
		setupFunc   func() (string, error)
		cleanupFunc func(string)
	}{
		{
			name:   "nonexistent-file",
			device: "/tmp/nonexistent-luks-device.img",
			setupFunc: func() (string, error) {
				return "/tmp/nonexistent-luks-device.img", nil
			},
			cleanupFunc: func(string) {},
		},
		{
			name:   "non-luks-file",
			device: "/tmp/test-non-luks.img",
			setupFunc: func() (string, error) {
				tmpfile := "/tmp/test-non-luks.img"
				f, err := os.Create(tmpfile)
				if err != nil {
					return "", err
				}
				// Write non-LUKS data
				data := make([]byte, 8192)
				for i := range data {
					data[i] = byte(i % 256)
				}
				if _, err := f.Write(data); err != nil {
					f.Close()
					return "", err
				}
				f.Close()
				return tmpfile, nil
			},
			cleanupFunc: func(path string) {
				os.Remove(path)
			},
		},
		{
			name:   "corrupted-header",
			device: "/tmp/test-corrupted-luks.img",
			setupFunc: func() (string, error) {
				tmpfile := "/tmp/test-corrupted-luks.img"
				// Create and format a valid volume first
				f, err := os.Create(tmpfile)
				if err != nil {
					return "", err
				}
				if err := f.Truncate(50 * 1024 * 1024); err != nil {
					f.Close()
					return "", err
				}
				f.Close()

				opts := FormatOptions{
					Device:     tmpfile,
					Passphrase: []byte("test-passphrase"),
					KDFType:    "pbkdf2",
				}
				if err := Format(opts); err != nil {
					return "", err
				}

				// Corrupt the checksum by writing garbage
				f, err = os.OpenFile(tmpfile, os.O_RDWR, 0600)
				if err != nil {
					return "", err
				}
				// Write garbage at checksum offset
				garbage := make([]byte, 64)
				for i := range garbage {
					garbage[i] = 0xFF
				}
				if _, err := f.WriteAt(garbage, 0x1C0); err != nil {
					f.Close()
					return "", err
				}
				f.Close()
				return tmpfile, nil
			},
			cleanupFunc: func(path string) {
				os.Remove(path)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, err := tt.setupFunc()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}
			defer tt.cleanupFunc(device)

			_, err = GetVolumeInfo(device)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

// TestIsUnlockedTrue tests that IsUnlocked returns true for unlocked volumes
func TestIsUnlockedTrue(t *testing.T) {
	tmpfile := "/tmp/test-luks-unlocked.img"
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

	// Unlock volume
	volumeName := "test-is-unlocked"
	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}
	defer Lock(volumeName)

	// Verify IsUnlocked returns true (wait for device-mapper)
	if !waitForDeviceState(volumeName, true, 5*time.Second) {
		t.Error("IsUnlocked should return true for unlocked volume")
	}
}

// TestIsUnlockedFalse tests that IsUnlocked returns false for locked volumes
func TestIsUnlockedFalse(t *testing.T) {
	tmpfile := "/tmp/test-luks-locked.img"
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

	// DO NOT unlock - verify IsUnlocked returns false
	volumeName := "test-is-locked"
	if IsUnlocked(volumeName) {
		t.Error("IsUnlocked should return false for locked volume")
	}
}

// TestIsUnlockedNonexistent tests that IsUnlocked returns false for nonexistent volumes
func TestIsUnlockedNonexistent(t *testing.T) {
	volumeName := "nonexistent-volume-12345"

	if IsUnlocked(volumeName) {
		t.Error("IsUnlocked should return false for nonexistent volume")
	}
}

// TestVolumeStateTransitions tests state transitions: locked -> unlocked -> locked
func TestVolumeStateTransitions(t *testing.T) {
	tmpfile := "/tmp/test-luks-state-transitions.img"
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

	volumeName := "test-state-transitions"
	// Cleanup any leftover device mapper from previous runs
	_ = Lock(volumeName)

	// Initial state: locked
	if IsUnlocked(volumeName) {
		t.Error("Volume should be locked initially")
	}

	// Transition 1: locked -> unlocked
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	// Verify unlocked state (wait for device-mapper)
	if !waitForDeviceState(volumeName, true, 5*time.Second) {
		t.Error("Volume should be unlocked after Unlock")
	}

	// Get volume info while unlocked
	info, err := GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed while unlocked: %v", err)
	}
	if info.UUID == "" {
		t.Error("Should be able to get volume info while unlocked")
	}

	// Transition 2: unlocked -> locked
	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	// Verify locked state (wait for device-mapper)
	if !waitForDeviceState(volumeName, false, 5*time.Second) {
		t.Error("Volume should be locked after Lock")
	}

	// Verify we can still get volume info while locked
	info, err = GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed while locked: %v", err)
	}
	if info.UUID == "" {
		t.Error("Should be able to get volume info while locked")
	}

	// Transition 3: locked -> unlocked (again)
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Second unlock failed: %v", err)
	}

	// Verify unlocked state (wait for device-mapper)
	if !waitForDeviceState(volumeName, true, 5*time.Second) {
		t.Error("Volume should be unlocked after second Unlock")
	}

	// Final cleanup
	if err := Lock(volumeName); err != nil {
		t.Fatalf("Final lock failed: %v", err)
	}
}

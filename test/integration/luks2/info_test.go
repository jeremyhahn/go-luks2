// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/test/internal/harness"
)

// waitForDeviceState waits for the device-mapper device to reach expected state
func waitForDeviceState(name string, shouldExist bool, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if IsUnlocked(name) == shouldExist {
			return true
		}
		time.Sleep(100 * time.Millisecond)
	}
	return false
}

func TestGetVolumeInfo(t *testing.T) {
	tmpfile := "/tmp/test-luks-info.img"
	defer os.Remove(tmpfile)

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
		Device:        tmpfile,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
		Cipher:        "aes",
		CipherMode:    "xts-plain64",
		KeySize:       512,
		SectorSize:    512,
		HashAlgo:      "sha256",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	info, err := harness.GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed: %v", err)
	}

	if info.UUID == "" {
		t.Error("UUID should not be empty")
	}
	if info.Version != header.Version {
		t.Errorf("Expected version %d, got %d", header.Version, info.Version)
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

func TestGetVolumeInfoWithLabel(t *testing.T) {
	tmpfile := "/tmp/test-luks-label.img"
	defer os.Remove(tmpfile)

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
		Device:        tmpfile,
		Passphrase:    passphrase,
		Label:         expectedLabel,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	info, err := harness.GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed: %v", err)
	}

	if info.Label != expectedLabel {
		t.Errorf("Expected label %s, got %s", expectedLabel, info.Label)
	}
}

func TestGetVolumeInfoWithSubsystem(t *testing.T) {
	tmpfile := "/tmp/test-luks-subsystem.img"
	defer os.Remove(tmpfile)

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
		Device:        tmpfile,
		Passphrase:    passphrase,
		Subsystem:     expectedSubsystem,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	hdr, _, err := harness.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("ReadHeader failed: %v", err)
	}

	subsystem := string(hdr.SubsystemLabel[:])
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

func TestGetVolumeInfoKDFType(t *testing.T) {
	tests := []struct {
		name    string
		kdfType string
	}{
		{name: "pbkdf2", kdfType: "pbkdf2"},
		{name: "argon2id", kdfType: "argon2id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile := "/tmp/test-luks-kdf-" + tt.name + ".img"
			defer os.Remove(tmpfile)

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

			info, err := harness.GetVolumeInfo(tmpfile)
			if err != nil {
				t.Fatalf("GetVolumeInfo failed: %v", err)
			}

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

func TestGetVolumeInfoErrors(t *testing.T) {
	tests := []struct {
		name        string
		setupFunc   func() (string, error)
		cleanupFunc func(string)
	}{
		{
			name: "nonexistent-file",
			setupFunc: func() (string, error) {
				return "/tmp/nonexistent-luks-device.img", nil
			},
			cleanupFunc: func(string) {},
		},
		{
			name: "non-luks-file",
			setupFunc: func() (string, error) {
				tmpfile := "/tmp/test-non-luks.img"
				f, err := os.Create(tmpfile)
				if err != nil {
					return "", err
				}
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
			cleanupFunc: func(path string) { os.Remove(path) },
		},
		{
			name: "corrupted-header",
			setupFunc: func() (string, error) {
				tmpfile := "/tmp/test-corrupted-luks.img"
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
					Device:        tmpfile,
					Passphrase:    []byte("test-passphrase"),
					KDFType:       "pbkdf2",
					PBKDFIterTime: 1,
				}
				if err := Format(opts); err != nil {
					return "", err
				}

				f, err = os.OpenFile(tmpfile, os.O_RDWR, 0600)
				if err != nil {
					return "", err
				}
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
			cleanupFunc: func(path string) { os.Remove(path) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			device, err := tt.setupFunc()
			if err != nil {
				t.Fatalf("Setup failed: %v", err)
			}
			defer tt.cleanupFunc(device)

			_, err = harness.GetVolumeInfo(device)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

func TestVolumeStateTransitions(t *testing.T) {
	tmpfile := filepath.Join(t.TempDir(), "test-luks-state-transitions.img")
	defer os.Remove(tmpfile)

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
		Device:        tmpfile,
		Passphrase:    passphrase,
		KDFType:       "pbkdf2",
		PBKDFIterTime: 1,
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	loopDev, err := harness.SetupLoopDevice(tmpfile)
	if err != nil {
		t.Fatalf("Failed to setup loop device: %v", err)
	}
	defer harness.DetachLoopDevice(loopDev)

	volumeName := runVolume(t, "test-state-transitions")

	if IsUnlocked(volumeName) {
		t.Error("Volume should be locked initially")
	}

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Unlock failed: %v", err)
	}

	if !waitForDeviceState(volumeName, true, 5*time.Second) {
		t.Error("Volume should be unlocked after Unlock")
	}

	info, err := harness.GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed while unlocked: %v", err)
	}
	if info.UUID == "" {
		t.Error("Should be able to get volume info while unlocked")
	}

	if err := Lock(volumeName); err != nil {
		t.Fatalf("Lock failed: %v", err)
	}

	if !waitForDeviceState(volumeName, false, 5*time.Second) {
		t.Error("Volume should be locked after Lock")
	}

	info, err = harness.GetVolumeInfo(tmpfile)
	if err != nil {
		t.Fatalf("GetVolumeInfo failed while locked: %v", err)
	}
	if info.UUID == "" {
		t.Error("Should be able to get volume info while locked")
	}

	defer releaseVolume(t, volumeName, func() error { return Lock(volumeName) })
	if err := Unlock(loopDev, passphrase, volumeName); err != nil {
		t.Fatalf("Second unlock failed: %v", err)
	}

	if !waitForDeviceState(volumeName, true, 5*time.Second) {
		t.Error("Volume should be unlocked after second Unlock")
	}

	if err := Lock(volumeName); err != nil {
		t.Fatalf("Final lock failed: %v", err)
	}
}

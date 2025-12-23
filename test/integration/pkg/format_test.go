// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package pkg_test

import (
	"os"
	"testing"

	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

func TestFormatBasic(t *testing.T) {
	tmpfile := "/tmp/test-luks-format.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		Label:      "TestVolume",
		KDFType:    "argon2id",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify header can be read
	hdr, metadata, err := luks2.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header after format: %v", err)
	}

	// Verify header fields
	if hdr.Version != 2 {
		t.Errorf("Expected LUKS version 2, got %d", hdr.Version)
	}

	// Verify metadata contains keyslot
	if len(metadata.Keyslots) == 0 {
		t.Error("Expected at least one keyslot")
	}
}

func TestFormatWithKDFTypes(t *testing.T) {
	tests := []struct {
		name    string
		kdfType string
	}{
		{"pbkdf2", "pbkdf2"},
		{"argon2i", "argon2i"},
		{"argon2id", "argon2id"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpfile := "/tmp/test-luks-kdf-" + tt.name + ".img"
			volumeName := "test-kdf-" + tt.name
			defer testCleanup(volumeName, "", tmpfile)

			if err := createTestFile(tmpfile, 50); err != nil {
				t.Fatalf("Failed to create test file: %v", err)
			}

			opts := luks2.FormatOptions{
				Device:        tmpfile,
				Passphrase:    []byte("test-password"),
				Label:         "TestKDF",
				KDFType:       tt.kdfType,
				PBKDFIterTime: 100,
				Argon2Time:    1,
				Argon2Memory:  65536,
			}

			if err := luks2.Format(opts); err != nil {
				t.Fatalf("Format with %s failed: %v", tt.kdfType, err)
			}

			// Verify we can unlock it
			loopDev, err := luks2.SetupLoopDevice(tmpfile)
			if err != nil {
				t.Fatalf("Failed to setup loop device: %v", err)
			}
			defer luks2.DetachLoopDevice(loopDev)

			// Clean up any previous device mapper
			_ = luks2.Lock(volumeName)

			if err := luks2.Unlock(loopDev, []byte("test-password"), volumeName); err != nil {
				t.Fatalf("Failed to unlock %s volume: %v", tt.kdfType, err)
			}
			luks2.Lock(volumeName)
		})
	}
}

func TestFormatWithMetadata(t *testing.T) {
	tmpfile := "/tmp/test-luks-metadata.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		Label:      "MyEncryptedDisk",
		Subsystem:  "my-subsystem",
		KDFType:    "pbkdf2",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Read and verify metadata
	header, _, err := luks2.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	labelStr := string(header.Label[:len("MyEncryptedDisk")])
	if labelStr != "MyEncryptedDisk" {
		t.Errorf("Label not set correctly: got %q", labelStr)
	}

	subsysStr := string(header.SubsystemLabel[:len("my-subsystem")])
	if subsysStr != "my-subsystem" {
		t.Errorf("Subsystem not set correctly: got %q", subsysStr)
	}
}

func TestFormatErrors(t *testing.T) {
	tests := []struct {
		name string
		opts luks2.FormatOptions
	}{
		{
			name: "empty-device",
			opts: luks2.FormatOptions{
				Device:     "",
				Passphrase: []byte("test"),
			},
		},
		{
			name: "nonexistent-device",
			opts: luks2.FormatOptions{
				Device:     "/nonexistent/device",
				Passphrase: []byte("test"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := luks2.Format(tt.opts)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

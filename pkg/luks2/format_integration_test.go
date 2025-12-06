// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration

package luks2

import (
	"os"
	"testing"
)

// TestFormatBasic tests basic LUKS volume formatting
func TestFormatBasic(t *testing.T) {
	tmpfile := "/tmp/test-luks-format.img"
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

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		Label:      "TestVolume",
		KDFType:    "argon2id",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify header can be read
	if _, _, err := ReadHeader(tmpfile); err != nil {
		t.Fatalf("Failed to read header after format: %v", err)
	}
}

// TestFormatWithKDFTypes tests formatting with different KDF algorithms
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

			opts := FormatOptions{
				Device:        tmpfile,
				Passphrase:    []byte("test-password"),
				Label:         "TestKDF",
				KDFType:       tt.kdfType,
				PBKDFIterTime: 100, // Fast for testing
				Argon2Time:    1,   // Fast for testing
				Argon2Memory:  65536,
			}

			if err := Format(opts); err != nil {
				t.Fatalf("Format with %s failed: %v", tt.kdfType, err)
			}

			// Verify we can unlock it
			loopDev, err := SetupLoopDevice(tmpfile)
			if err != nil {
				t.Fatalf("Failed to setup loop device: %v", err)
			}
			defer DetachLoopDevice(loopDev)

			if err := Unlock(loopDev, []byte("test-password"), "test-kdf-"+tt.name); err != nil {
				t.Fatalf("Failed to unlock %s volume: %v", tt.kdfType, err)
			}
			Lock("test-kdf-" + tt.name)
		})
	}
}

// TestFormatWithMetadata tests formatting with labels and subsystem
func TestFormatWithMetadata(t *testing.T) {
	tmpfile := "/tmp/test-luks-metadata.img"
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

	opts := FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		Label:      "MyEncryptedDisk",
		Subsystem:  "my-subsystem",
		KDFType:    "pbkdf2",
	}

	if err := Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Read and verify metadata
	header, _, err := ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	if string(header.Label[:len("MyEncryptedDisk")]) != "MyEncryptedDisk" {
		t.Fatal("Label not set correctly")
	}
	if string(header.SubsystemLabel[:len("my-subsystem")]) != "my-subsystem" {
		t.Fatal("Subsystem not set correctly")
	}
}

// TestFormatErrors tests error conditions during formatting
func TestFormatErrors(t *testing.T) {
	tests := []struct {
		name string
		opts FormatOptions
	}{
		{
			name: "empty-device",
			opts: FormatOptions{
				Device:     "",
				Passphrase: []byte("test"),
			},
		},
		{
			name: "nonexistent-device",
			opts: FormatOptions{
				Device:     "/nonexistent/device",
				Passphrase: []byte("test"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Format(tt.opts)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

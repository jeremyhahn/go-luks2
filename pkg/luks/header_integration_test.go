// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build integration
// +build integration

package luks

import (
	"os"
	"testing"
)

func TestHeaderWriteRead(t *testing.T) {
	tmpfile := "/tmp/test-luks-header.bin"
	defer os.Remove(tmpfile)

	// Create the file first
	f, err := os.Create(tmpfile)
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	// Make it large enough
	if err := f.Truncate(1024 * 1024); err != nil {
		f.Close()
		t.Fatalf("Failed to truncate file: %v", err)
	}
	f.Close()

	// Create a test header
	opts := FormatOptions{
		Label:      "TestVolume",
		Passphrase: []byte("test-passphrase"),
		KDFType:    "pbkdf2",
	}

	hdr, err := CreateBinaryHeader(opts)
	if err != nil {
		t.Fatalf("Failed to create header: %v", err)
	}

	// Create test metadata - use same structure as Format creates
	kdf := &KDF{
		Type:       "pbkdf2",
		Salt:       "dGVzdHNhbHQxMjM0NTY3OA==", // base64 encoded
		Hash:       "sha256",
		Iterations: intPtr(100000),
	}

	metadata := &LUKS2Metadata{
		Keyslots: map[string]*Keyslot{
			"0": {
				Type:     "luks2",
				KeySize:  64,
				Priority: intPtr(1),
				AF: &AntiForensic{
					Type:    "luks1",
					Hash:    "sha256",
					Stripes: 4000,
				},
				Area: &KeyslotArea{
					Type:       "raw",
					Encryption: "aes-xts-plain64",
					KeySize:    64,
					Offset:     "32768",
					Size:       "258048",
				},
				KDF: kdf,
			},
		},
		Segments: map[string]*Segment{
			"0": {
				Type:       "crypt",
				Offset:     "1048576",
				Size:       "dynamic",
				IVTweak:    "0",
				Encryption: "aes-xts-plain64",
				SectorSize: 512,
			},
		},
		Digests: map[string]*Digest{
			"0": {
				Type:       "pbkdf2",
				Keyslots:   []string{"0"},
				Segments:   []string{"0"},
				Hash:       "sha256",
				Salt:       "ZGlnZXN0c2FsdDEyMzQ1Njc4", // base64
				Digest:     "dGVzdGRpZ2VzdDE",
				Iterations: 100000,
			},
		},
		Config: &Config{
			JSONSize:     "16384",
			KeyslotsSize: "3145728",
			Flags:        []string{},
			Requirements: []string{},
		},
	}

	// Write header
	if err := WriteHeader(tmpfile, hdr, metadata); err != nil {
		t.Fatalf("Failed to write header: %v", err)
	}

	t.Logf("Header written successfully")
	t.Logf("HeaderSize: %d", hdr.HeaderSize)
	t.Logf("HeaderOffset: %d", hdr.HeaderOffset)
	t.Logf("Checksum (first 16 bytes): %x", hdr.Checksum[:16])

	// Read header back
	readHdr, readMeta, err := ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	t.Logf("Header read successfully")
	t.Logf("Read HeaderSize: %d", readHdr.HeaderSize)
	t.Logf("Read HeaderOffset: %d", readHdr.HeaderOffset)
	t.Logf("Read Checksum (first 16 bytes): %x", readHdr.Checksum[:16])

	// Verify metadata was read
	if readMeta == nil {
		t.Fatal("Metadata is nil")
	}
}

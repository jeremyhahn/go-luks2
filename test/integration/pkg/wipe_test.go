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

func TestWipeHeaderOnly(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-header.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 50); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Format the volume first
	opts := luks2.FormatOptions{
		Device:     tmpfile,
		Passphrase: []byte("test-password"),
		KDFType:    "pbkdf2",
	}

	if err := luks2.Format(opts); err != nil {
		t.Fatalf("Format failed: %v", err)
	}

	// Verify it's a valid LUKS device
	_, _, err := luks2.ReadHeader(tmpfile)
	if err != nil {
		t.Fatalf("Failed to read header: %v", err)
	}

	// Wipe headers only
	wipeOpts := luks2.WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		HeaderOnly: true,
	}

	if err := luks2.Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify headers are wiped (should fail to read)
	_, _, err = luks2.ReadHeader(tmpfile)
	if err == nil {
		t.Fatal("Should fail to read header after wipe")
	}
}

func TestWipeFull(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-full.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 10); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Write some data
	f, err := os.OpenFile(tmpfile, os.O_WRONLY, 0644)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}

	data := make([]byte, 1024*1024) // 1MB of non-zero data
	for i := range data {
		data[i] = 0xAB
	}
	_, err = f.Write(data)
	f.Close()
	if err != nil {
		t.Fatalf("Failed to write data: %v", err)
	}

	// Wipe the file
	wipeOpts := luks2.WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		HeaderOnly: false,
	}

	if err := luks2.Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify data is wiped
	f, err = os.Open(tmpfile)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 1024)
	_, err = f.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	// Check that data is zeros
	for i, b := range buf {
		if b != 0 {
			t.Fatalf("Data not wiped at offset %d: got %x", i, b)
		}
	}
}

func TestWipeWithRandom(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-random.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 10); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wipe with random data
	wipeOpts := luks2.WipeOptions{
		Device:     tmpfile,
		Passes:     1,
		Random:     true,
		HeaderOnly: false,
	}

	if err := luks2.Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify file is not all zeros (random data was written)
	f, err := os.Open(tmpfile)
	if err != nil {
		t.Fatalf("Failed to open file: %v", err)
	}
	defer f.Close()

	buf := make([]byte, 4096)
	_, err = f.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	// Check that at least some data is non-zero
	hasNonZero := false
	for _, b := range buf {
		if b != 0 {
			hasNonZero = true
			break
		}
	}

	if !hasNonZero {
		t.Error("Random wipe should produce non-zero data")
	}
}

func TestWipeMultiplePasses(t *testing.T) {
	tmpfile := "/tmp/test-luks-wipe-passes.img"
	defer os.Remove(tmpfile)

	if err := createTestFile(tmpfile, 5); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wipe with multiple passes
	wipeOpts := luks2.WipeOptions{
		Device:     tmpfile,
		Passes:     3,
		HeaderOnly: false,
	}

	if err := luks2.Wipe(wipeOpts); err != nil {
		t.Fatalf("Wipe with 3 passes failed: %v", err)
	}
}

func TestWipeErrors(t *testing.T) {
	tests := []struct {
		name string
		opts luks2.WipeOptions
	}{
		{
			name: "empty-device",
			opts: luks2.WipeOptions{
				Device: "",
				Passes: 1,
			},
		},
		{
			name: "nonexistent-device",
			opts: luks2.WipeOptions{
				Device: "/nonexistent/device",
				Passes: 1,
			},
		},
		{
			name: "zero-passes",
			opts: luks2.WipeOptions{
				Device: "/tmp/test.img",
				Passes: 0,
			},
		},
		{
			name: "negative-passes",
			opts: luks2.WipeOptions{
				Device: "/tmp/test.img",
				Passes: -1,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := luks2.Wipe(tt.opts)
			if err == nil {
				t.Fatal("Expected error, got nil")
			}
		})
	}
}

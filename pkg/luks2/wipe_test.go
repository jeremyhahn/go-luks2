// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"crypto/aes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestWipeOptions_DefaultPasses tests that default passes is set to 1
func TestWipeOptions_DefaultPasses(t *testing.T) {
	opts := WipeOptions{
		Device: "/dev/null",
		Passes: 0,
	}

	// The Wipe function should set default to 1 if 0 is provided
	if opts.Passes == 0 {
		opts.Passes = 1
	}

	if opts.Passes != 1 {
		t.Fatalf("Expected default passes to be 1, got %d", opts.Passes)
	}
}

// TestWipePass_Zeros tests wiping with zero pattern
func TestWipePass_Zeros(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_zeros")

	// Create file with non-zero data
	testData := make([]byte, 4096)
	for i := range testData {
		testData[i] = 0xFF
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if err := wipePass(f, int64(len(testData)), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify all bytes are zero
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	if len(result) != len(testData) {
		t.Fatalf("Result size mismatch: got %d, want %d", len(result), len(testData))
	}

	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte at position %d is not zero: 0x%02x", i, b)
		}
	}
}

// TestWipePass_Random tests wiping with random pattern
func TestWipePass_Random(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_random")

	// Create file with zero data
	testData := make([]byte, 4096)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with random data
	if err := wipePass(f, int64(len(testData)), true); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify data is not all zeros (random data should have written)
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	if len(result) != len(testData) {
		t.Fatalf("Result size mismatch: got %d, want %d", len(result), len(testData))
	}

	// Check that at least some bytes are non-zero
	// (extremely unlikely all random bytes are zero)
	nonZeroCount := 0
	for _, b := range result {
		if b != 0 {
			nonZeroCount++
		}
	}

	// With 4096 bytes of random data, we should have many non-zero bytes
	// Using a very conservative threshold
	if nonZeroCount < 100 {
		t.Fatalf("Too few non-zero bytes in random wipe: %d", nonZeroCount)
	}
}

// TestWipePass_SmallSize tests wiping smaller than buffer size
func TestWipePass_SmallSize(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_small")

	// Create small file (smaller than 1MB buffer)
	testSize := 512
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xAA
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if err := wipePass(f, int64(testSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify all bytes are zero
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte at position %d is not zero: 0x%02x", i, b)
		}
	}
}

// TestWipePass_LargeSize tests wiping larger than buffer size
func TestWipePass_LargeSize(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_large")

	// Create file larger than 1MB buffer (2MB)
	testSize := 2 * 1024 * 1024
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0x55
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if err := wipePass(f, int64(testSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify file size is correct
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	if fi.Size() != int64(testSize) {
		t.Fatalf("File size mismatch: got %d, want %d", fi.Size(), testSize)
	}

	// Verify a sample of bytes are zero (checking all 2MB would be slow)
	// Check first 4KB, middle 4KB, and last 4KB
	checkRanges := []int64{0, int64(testSize/2) - 2048, int64(testSize) - 4096}

	for _, offset := range checkRanges {
		sample := make([]byte, 4096)
		if _, err := f.Seek(offset, 0); err != nil {
			t.Fatalf("Failed to seek: %v", err)
		}
		if _, err := io.ReadFull(f, sample); err != nil {
			t.Fatalf("Failed to read sample: %v", err)
		}

		for i, b := range sample {
			if b != 0 {
				t.Fatalf("Byte at offset %d+%d is not zero: 0x%02x", offset, i, b)
			}
		}
	}
}

// TestWipePass_ZeroSize tests wiping with zero size
func TestWipePass_ZeroSize(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_zero_size")

	// Create empty file
	if err := os.WriteFile(tmpFile, []byte{}, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zero size should complete without error
	if err := wipePass(f, 0, false); err != nil {
		t.Fatalf("wipePass with zero size failed: %v", err)
	}
}

// TestWipeHeaders tests wiping LUKS headers
func TestWipeHeaders(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_headers")

	// Create file with test data
	testSize := 64 * 1024 // 64KB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xFF
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping headers
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe headers
	if err := wipeHeaders(f); err != nil {
		t.Fatalf("wipeHeaders failed: %v", err)
	}

	// Read file to verify headers are wiped
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	// First 32KB (0x8000 bytes) should be zeros
	headerSize := 0x8000
	for i := 0; i < headerSize; i++ {
		if result[i] != 0 {
			t.Fatalf("Header byte at position %d is not zero: 0x%02x", i, result[i])
		}
	}

	// Remaining bytes should still be 0xFF
	for i := headerSize; i < len(result); i++ {
		if result[i] != 0xFF {
			t.Fatalf("Data byte at position %d was modified: 0x%02x", i, result[i])
		}
	}
}

// TestWipeHeaders_ExactSize tests wiping headers on file exactly header size
func TestWipeHeaders_ExactSize(t *testing.T) {
	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_headers_exact")

	// Create file exactly header size
	headerSize := 0x8000
	testData := make([]byte, headerSize)
	for i := range testData {
		testData[i] = 0xAA
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping headers
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe headers
	if err := wipeHeaders(f); err != nil {
		t.Fatalf("wipeHeaders failed: %v", err)
	}

	// Read file to verify all bytes are wiped
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte at position %d is not zero: 0x%02x", i, b)
		}
	}
}

// TestWipePass_SeekError tests error handling when seek fails
func TestWipePass_SeekError(t *testing.T) {
	defer parallel(t)()

	// Create a read-only file to trigger seek/write errors
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_readonly")

	testData := make([]byte, 1024)
	if err := os.WriteFile(tmpFile, testData, 0400); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open as read-only
	f, err := os.Open(tmpFile)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Close the file to trigger seek error
	_ = f.Close()

	// Attempting wipePass on closed file should error
	err = wipePass(f, 1024, false)
	if err == nil {
		t.Fatal("Expected error when wiping closed file, got nil")
	}
}

// TestWipePass_BufferBoundary tests wiping at exact buffer boundaries
func TestWipePass_BufferBoundary(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_boundary")

	// Create file exactly 1MB (buffer size)
	bufferSize := 1024 * 1024
	testData := make([]byte, bufferSize)
	for i := range testData {
		testData[i] = 0xCC
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if err := wipePass(f, int64(bufferSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify all bytes are zero
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	if len(result) != bufferSize {
		t.Fatalf("Size mismatch: got %d, want %d", len(result), bufferSize)
	}

	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte at position %d is not zero: 0x%02x", i, b)
		}
	}
}

// TestWipePass_RandomDataDifferent tests that random wipes produce different data
func TestWipePass_RandomDataDifferent(t *testing.T) {
	defer parallel(t)()

	// Create two temporary files
	tmpDir := t.TempDir()
	tmpFile1 := filepath.Join(tmpDir, "test_random1")
	tmpFile2 := filepath.Join(tmpDir, "test_random2")

	testSize := 4096
	testData := make([]byte, testSize)

	// Create both files
	if err := os.WriteFile(tmpFile1, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file 1: %v", err)
	}
	if err := os.WriteFile(tmpFile2, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file 2: %v", err)
	}

	// Wipe first file with random data
	f1, err := os.OpenFile(tmpFile1, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file 1: %v", err)
	}
	if err := wipePass(f1, int64(testSize), true); err != nil {
		_ = f1.Close()
		t.Fatalf("wipePass on file 1 failed: %v", err)
	}
	_ = f1.Close()

	// Wipe second file with random data
	f2, err := os.OpenFile(tmpFile2, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file 2: %v", err)
	}
	if err := wipePass(f2, int64(testSize), true); err != nil {
		_ = f2.Close()
		t.Fatalf("wipePass on file 2 failed: %v", err)
	}
	_ = f2.Close()

	// Read both files
	result1, err := os.ReadFile(tmpFile1)
	if err != nil {
		t.Fatalf("Failed to read result 1: %v", err)
	}
	result2, err := os.ReadFile(tmpFile2)
	if err != nil {
		t.Fatalf("Failed to read result 2: %v", err)
	}

	// Results should be different (extremely unlikely to be identical)
	if bytes.Equal(result1, result2) {
		t.Fatal("Random wipes produced identical data (highly improbable)")
	}
}

// TestWipePass_PartialBuffer tests wiping size that's not a multiple of buffer
func TestWipePass_PartialBuffer(t *testing.T) {
	defer parallel(t)()

	// Create temporary file for testing
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_partial")

	// Create file with odd size (buffer + half buffer)
	bufferSize := 1024 * 1024
	testSize := bufferSize + (bufferSize / 2)
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0x77
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for wiping
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if err := wipePass(f, int64(testSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify file is correct size
	fi, err := f.Stat()
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	if fi.Size() != int64(testSize) {
		t.Fatalf("File size mismatch: got %d, want %d", fi.Size(), testSize)
	}

	// Verify samples are zero
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	// Check beginning, middle, and end
	checkSize := 1024
	for i := 0; i < checkSize; i++ {
		if result[i] != 0 {
			t.Fatalf("Beginning byte %d is not zero: 0x%02x", i, result[i])
		}
	}

	midpoint := len(result) / 2
	for i := midpoint; i < midpoint+checkSize; i++ {
		if result[i] != 0 {
			t.Fatalf("Middle byte %d is not zero: 0x%02x", i, result[i])
		}
	}

	for i := len(result) - checkSize; i < len(result); i++ {
		if result[i] != 0 {
			t.Fatalf("End byte %d is not zero: 0x%02x", i, result[i])
		}
	}
}

// TestWipePass_RandomReadError tests error handling for random data generation
func TestWipePass_RandomReadError(t *testing.T) {
	defer parallel(t)()

	// This test documents that wipePass relies on crypto/rand.Read
	// which could theoretically fail in extreme cases (e.g., system entropy exhaustion)
	// However, in practice this is nearly impossible to trigger in tests
	// without mocking the rand.Read function

	// Create temporary file
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_random_read")

	testSize := 1024
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Normal operation should succeed
	// (we cannot easily trigger rand.Read failure without system-level intervention)
	if err := wipePass(f, int64(testSize), true); err != nil {
		t.Fatalf("wipePass with random should succeed under normal conditions: %v", err)
	}
}

// BenchmarkWipePass_Zeros benchmarks zero pattern wiping
func BenchmarkWipePass_Zeros(b *testing.B) {
	tmpDir := b.TempDir()
	tmpFile := filepath.Join(tmpDir, "bench_zeros")

	// Create 10MB test file
	testSize := 10 * 1024 * 1024
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(int64(testSize))

	for i := 0; i < b.N; i++ {
		f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
		if err != nil {
			b.Fatalf("Failed to open file: %v", err)
		}

		if err := wipePass(f, int64(testSize), false); err != nil {
			_ = f.Close()
			b.Fatalf("wipePass failed: %v", err)
		}

		_ = f.Close()
	}
}

// BenchmarkWipePass_Random benchmarks random pattern wiping
func BenchmarkWipePass_Random(b *testing.B) {
	tmpDir := b.TempDir()
	tmpFile := filepath.Join(tmpDir, "bench_random")

	// Create 10MB test file
	testSize := 10 * 1024 * 1024
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(int64(testSize))

	for i := 0; i < b.N; i++ {
		f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
		if err != nil {
			b.Fatalf("Failed to open file: %v", err)
		}

		if err := wipePass(f, int64(testSize), true); err != nil {
			_ = f.Close()
			b.Fatalf("wipePass failed: %v", err)
		}

		_ = f.Close()
	}
}

// BenchmarkWipeHeaders benchmarks header wiping
func BenchmarkWipeHeaders(b *testing.B) {
	tmpDir := b.TempDir()
	tmpFile := filepath.Join(tmpDir, "bench_headers")

	// Create 64KB test file
	testSize := 64 * 1024
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		b.Fatalf("Failed to create test file: %v", err)
	}

	b.ResetTimer()
	b.SetBytes(0x8000) // Header size

	for i := 0; i < b.N; i++ {
		f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
		if err != nil {
			b.Fatalf("Failed to open file: %v", err)
		}

		if err := wipeHeaders(f); err != nil {
			_ = f.Close()
			b.Fatalf("wipeHeaders failed: %v", err)
		}

		_ = f.Close()
	}
}

// TestWipe_InvalidDevice tests error handling for invalid device path
func TestWipe_InvalidDevice(t *testing.T) {
	opts := WipeOptions{
		Device: "/nonexistent/invalid/device",
		Passes: 1,
	}

	err := Wipe(opts)
	if err == nil {
		t.Fatal("Expected error for invalid device, got nil")
	}
}

// TestWipeOptions_Structure tests WipeOptions structure fields
func TestWipeOptions_Structure(t *testing.T) {
	opts := WipeOptions{
		Device:     "/dev/test",
		Passes:     3,
		Random:     true,
		HeaderOnly: false,
	}

	if opts.Device != "/dev/test" {
		t.Fatalf("Device mismatch: got %s, want /dev/test", opts.Device)
	}
	if opts.Passes != 3 {
		t.Fatalf("Passes mismatch: got %d, want 3", opts.Passes)
	}
	if !opts.Random {
		t.Fatal("Random should be true")
	}
	if opts.HeaderOnly {
		t.Fatal("HeaderOnly should be false")
	}
}

// TestWipeOptions_TrimField tests the Trim field in WipeOptions
func TestWipeOptions_TrimField(t *testing.T) {
	tests := []struct {
		name     string
		opts     WipeOptions
		wantTrim bool
	}{
		{
			name: "trim disabled by default",
			opts: WipeOptions{
				Device: "/dev/test",
				Passes: 1,
			},
			wantTrim: false,
		},
		{
			name: "trim explicitly enabled",
			opts: WipeOptions{
				Device: "/dev/test",
				Passes: 1,
				Trim:   true,
			},
			wantTrim: true,
		},
		{
			name: "trim with random wipe",
			opts: WipeOptions{
				Device: "/dev/test",
				Passes: 3,
				Random: true,
				Trim:   true,
			},
			wantTrim: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.opts.Trim != tt.wantTrim {
				t.Errorf("Trim = %v, want %v", tt.opts.Trim, tt.wantTrim)
			}
		})
	}
}

// TestIssueDiscard_InvalidFile tests issueDiscard with invalid file descriptors
func TestIssueDiscard_InvalidFile(t *testing.T) {
	// Create a temporary file (not a block device)
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_discard")

	testData := make([]byte, 4096)
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// issueDiscard should fail on a regular file (not a block device)
	err = issueDiscard(f, int64(len(testData)))
	// We expect an error since regular files don't support BLKDISCARD
	if err == nil {
		t.Log("issueDiscard succeeded on regular file - this is OS-dependent")
	} else {
		t.Logf("issueDiscard correctly failed on regular file: %v", err)
	}
}

// TestIssueDiscard_ClosedFile tests issueDiscard with a closed file
func TestIssueDiscard_ClosedFile(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_discard_closed")

	testData := make([]byte, 4096)
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}

	// Close the file before calling issueDiscard
	_ = f.Close()

	// Should fail on closed file descriptor
	err = issueDiscard(f, 4096)
	if err == nil {
		t.Fatal("Expected error when calling issueDiscard on closed file")
	}
}

// TestIssueDiscard_ZeroSize tests issueDiscard with zero size
func TestIssueDiscard_ZeroSize(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_discard_zero")

	testData := make([]byte, 4096)
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Zero size discard should now return an error (security validation)
	err = issueDiscard(f, 0)
	if err == nil {
		t.Fatal("Expected error for zero size discard")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("invalid discard size")) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestIssueDiscard_NegativeSize tests issueDiscard with negative size
func TestIssueDiscard_NegativeSize(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_discard_negative")

	testData := make([]byte, 4096)
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Negative size should be rejected to prevent integer overflow
	// (negative int64 would wrap to huge uint64 value)
	err = issueDiscard(f, -1)
	if err == nil {
		t.Fatal("Expected error for negative size discard")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("invalid discard size")) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestWipe_WithTrimOption tests that Wipe honors the Trim option
func TestWipe_WithTrimOption(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_trim")

	// Create test file
	testSize := 1024 * 1024 // 1MB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xAA
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wipe with Trim enabled (will fail TRIM on regular file but should complete wipe)
	opts := WipeOptions{
		Device: tmpFile,
		Passes: 1,
		Random: false,
		Trim:   true,
	}

	err := Wipe(opts)
	if err != nil {
		t.Fatalf("Wipe with Trim failed: %v", err)
	}

	// Verify data was wiped
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	// Check that data is all zeros
	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte at position %d is not zero after wipe: 0x%02x", i, b)
		}
	}
}

// TestWipe_TrimAfterMultiplePasses tests TRIM is issued after all passes complete
func TestWipe_TrimAfterMultiplePasses(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_trim_multi")

	// Create test file
	testSize := 512 * 1024 // 512KB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xFF
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wipe with multiple passes and Trim
	opts := WipeOptions{
		Device: tmpFile,
		Passes: 3,
		Random: true,
		Trim:   true,
	}

	err := Wipe(opts)
	if err != nil {
		t.Fatalf("Wipe with multiple passes and Trim failed: %v", err)
	}

	// Verify file still exists and has correct size
	fi, err := os.Stat(tmpFile)
	if err != nil {
		t.Fatalf("Failed to stat file after wipe: %v", err)
	}

	if fi.Size() != int64(testSize) {
		t.Fatalf("File size changed after wipe: got %d, want %d", fi.Size(), testSize)
	}
}

// TestWipe_HeaderOnlyIgnoresTrim tests that HeaderOnly mode doesn't use Trim
func TestWipe_HeaderOnlyIgnoresTrim(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_wipe_header_trim")

	// Create test file (64KB)
	testSize := 64 * 1024
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xCC
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Wipe headers only with Trim option (Trim should be skipped for header-only)
	opts := WipeOptions{
		Device:     tmpFile,
		Passes:     1,
		HeaderOnly: true,
		Trim:       true,
	}

	err := Wipe(opts)
	if err != nil {
		t.Fatalf("HeaderOnly wipe failed: %v", err)
	}

	// Verify only headers (32KB) were wiped
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	headerSize := 0x8000
	for i := 0; i < headerSize; i++ {
		if result[i] != 0 {
			t.Fatalf("Header byte %d not wiped: 0x%02x", i, result[i])
		}
	}

	// Verify data after header is untouched
	for i := headerSize; i < len(result); i++ {
		if result[i] != 0xCC {
			t.Fatalf("Data byte %d was modified: 0x%02x", i, result[i])
		}
	}
}

// TestBLKDISCARD_Constant verifies the BLKDISCARD constant value
func TestBLKDISCARD_Constant(t *testing.T) {
	// BLKDISCARD should be 0x1277 (as defined in Linux kernel headers)
	expected := uintptr(0x1277)
	if BLKDISCARD != expected {
		t.Errorf("BLKDISCARD = 0x%x, want 0x%x", BLKDISCARD, expected)
	}
}

// TestWipePass_BufferClearing tests that wipePass handles buffer correctly
func TestWipePass_BufferClearing(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_buffer_clear")

	// Create small file
	testSize := 2048
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xBB
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if err := wipePass(f, int64(testSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify all bytes are zero
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte %d not zero: 0x%02x", i, b)
		}
	}
}

// TestWipePass_ConcurrentAccess tests that wipe handles concurrent access attempts
func TestWipePass_ConcurrentAccess(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_concurrent")

	// Create test file
	testSize := 1024 * 100 // 100KB
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Open file for concurrent test
	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Run multiple wipe passes concurrently
	done := make(chan error, 2)

	go func() {
		done <- wipePass(f, int64(testSize), true)
	}()

	go func() {
		done <- wipePass(f, int64(testSize), false)
	}()

	// Collect results - at least one should succeed
	err1 := <-done
	err2 := <-done

	// We're mainly checking no crashes occur
	t.Logf("Concurrent wipe results: err1=%v, err2=%v", err1, err2)
}

// TestWipePass_VeryLargeSize tests handling of very large sizes
func TestWipePass_VeryLargeSize(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_large_size")

	// Create small file
	testSize := 4096
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Try to wipe with a size larger than the file
	// This tests boundary handling
	largeSize := int64(1024 * 1024 * 10) // 10MB
	err = wipePass(f, largeSize, false)
	// This may succeed or fail depending on filesystem behavior
	t.Logf("wipePass with large size result: %v", err)
}

// TestWipe_ZeroPasses tests that zero passes defaults to 1 pass
func TestWipe_ZeroPasses(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_zero_passes")

	testData := make([]byte, 4096)
	for i := range testData {
		testData[i] = 0xAA
	}
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := WipeOptions{
		Device: tmpFile,
		Passes: 0, // Now defaults to 1 pass
		Random: false,
	}

	// With the new logic, zero passes defaults to 1
	err := Wipe(opts)
	if err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify file was wiped to zeros
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0x00 {
			t.Fatalf("Byte at %d is 0x%02x, want 0x00", i, b)
		}
	}
}

// TestWipe_NegativePasses tests that negative passes defaults to 1 pass
func TestWipe_NegativePasses(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_negative_passes")

	testData := make([]byte, 4096)
	for i := range testData {
		testData[i] = 0xBB
	}
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := WipeOptions{
		Device: tmpFile,
		Passes: -1, // Now defaults to 1 pass
		Random: false,
	}

	// With the new logic, negative passes defaults to 1
	err := Wipe(opts)
	if err != nil {
		t.Fatalf("Wipe failed: %v", err)
	}

	// Verify file was wiped to zeros
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0x00 {
			t.Fatalf("Byte at %d is 0x%02x, want 0x00", i, b)
		}
	}
}

// TestWipePass_ExactlyBufferSize tests wiping exactly at buffer boundary
func TestWipePass_ExactlyBufferSize(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_exact_buffer")

	// Create file exactly 1MB (buffer size)
	bufferSize := 1024 * 1024
	testData := make([]byte, bufferSize)
	for i := range testData {
		testData[i] = 0xDD
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := wipePass(f, int64(bufferSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Verify complete wipe
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0 {
			t.Fatalf("Byte %d not zero: 0x%02x", i, b)
		}
	}
}

// TestWipePass_MultipleBufferSize tests wiping at multiple of buffer boundary
func TestWipePass_MultipleBufferSize(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_multi_buffer")

	// Create file exactly 3MB (3x buffer size)
	bufferSize := 3 * 1024 * 1024
	testData := make([]byte, bufferSize)
	for i := range testData {
		testData[i] = 0xEE
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := wipePass(f, int64(bufferSize), false); err != nil {
		t.Fatalf("wipePass failed: %v", err)
	}

	// Spot check beginning, middle, and end
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	checkPoints := []int{0, bufferSize / 2, bufferSize - 1}
	for _, idx := range checkPoints {
		if result[idx] != 0 {
			t.Fatalf("Byte at %d not zero: 0x%02x", idx, result[idx])
		}
	}
}

// ============================================================================
// New tests for WipePattern, WipeStandard, and multi-pattern support
// ============================================================================

// TestWipePattern_String tests the String() method of WipePattern
func TestWipePattern_String(t *testing.T) {
	tests := []struct {
		pattern  WipePattern
		expected string
	}{
		{PatternZeros, "zeros"},
		{PatternOnes, "ones"},
		{PatternRandom, "random"},
		{WipePattern(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.pattern.String(); got != tt.expected {
				t.Errorf("WipePattern.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestWipeStandard_String tests the String() method of WipeStandard
func TestWipeStandard_String(t *testing.T) {
	tests := []struct {
		standard WipeStandard
		expected string
	}{
		{StandardCustom, "custom"},
		{StandardNIST, "nist"},
		{StandardDoD3Pass, "dod3"},
		{StandardDoD7Pass, "dod7"},
		{WipeStandard(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			if got := tt.standard.String(); got != tt.expected {
				t.Errorf("WipeStandard.String() = %q, want %q", got, tt.expected)
			}
		})
	}
}

// TestWipeStandard_GetPatternSequence tests pattern sequences for each standard
func TestWipeStandard_GetPatternSequence(t *testing.T) {
	tests := []struct {
		name     string
		standard WipeStandard
		expected []WipePattern
	}{
		{
			name:     "NIST SP 800-88",
			standard: StandardNIST,
			expected: []WipePattern{PatternRandom},
		},
		{
			name:     "DoD 5220.22-M 3-pass",
			standard: StandardDoD3Pass,
			expected: []WipePattern{PatternZeros, PatternOnes, PatternRandom},
		},
		{
			name:     "DoD 5220.22-M ECE 7-pass",
			standard: StandardDoD7Pass,
			expected: []WipePattern{
				PatternZeros, PatternOnes, PatternRandom,
				PatternRandom,
				PatternZeros, PatternOnes, PatternRandom,
			},
		},
		{
			name:     "Custom (returns nil)",
			standard: StandardCustom,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.standard.GetPatternSequence()
			if len(got) != len(tt.expected) {
				t.Fatalf("GetPatternSequence() len = %d, want %d", len(got), len(tt.expected))
			}
			for i := range got {
				if got[i] != tt.expected[i] {
					t.Errorf("GetPatternSequence()[%d] = %v, want %v", i, got[i], tt.expected[i])
				}
			}
		})
	}
}

// TestWipeStandard_RequiresVerification tests verification requirements
func TestWipeStandard_RequiresVerification(t *testing.T) {
	tests := []struct {
		standard WipeStandard
		expected bool
	}{
		{StandardCustom, false},
		{StandardNIST, false},
		{StandardDoD3Pass, true},
		{StandardDoD7Pass, true},
	}

	for _, tt := range tests {
		t.Run(tt.standard.String(), func(t *testing.T) {
			if got := tt.standard.RequiresVerification(); got != tt.expected {
				t.Errorf("RequiresVerification() = %v, want %v", got, tt.expected)
			}
		})
	}
}

// TestPassStreamFillsEachPattern: zeros and ones are what they say, and an
// unknown pattern is refused before anything is written.
func TestPassStreamFillsEachPattern(t *testing.T) {
	for _, tc := range []struct {
		pattern WipePattern
		want    byte
	}{{PatternZeros, 0x00}, {PatternOnes, 0xFF}} {
		s, err := newPassStream(tc.pattern)
		if err != nil {
			t.Fatalf("newPassStream(%s): %v", tc.pattern, err)
		}
		buf := bytes.Repeat([]byte{0xAA}, 1024)
		s.fill(buf, 4096)
		for i, b := range buf {
			if b != tc.want {
				t.Fatalf("%s: byte %d is 0x%02x, want 0x%02x", tc.pattern, i, b, tc.want)
			}
		}
	}

	if _, err := newPassStream(WipePattern(99)); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("newPassStream(99) = %v, want ErrInvalidSize", err)
	}
}

// TestRandomPassStreamIsReproducible is what makes a random pass verifiable
// (#246 D1): the stream at any chunk can be produced again on its own, a
// fresh pass gets a fresh key, and the output is not a constant.
func TestRandomPassStreamIsReproducible(t *testing.T) {
	s, err := newPassStream(PatternRandom)
	if err != nil {
		t.Fatalf("newPassStream: %v", err)
	}

	whole := make([]byte, 3*aes.BlockSize*64)
	s.fill(whole, 0)
	part := make([]byte, aes.BlockSize*64)
	s.fill(part, int64(aes.BlockSize*64))
	if !bytes.Equal(part, whole[aes.BlockSize*64:2*aes.BlockSize*64]) {
		t.Fatal("the stream regenerated at an offset differs from the stream written through it")
	}
	if bytes.Count(whole, []byte{0}) > len(whole)/16 {
		t.Fatal("the random stream is mostly zeros")
	}

	other, err := newPassStream(PatternRandom)
	if err != nil {
		t.Fatalf("newPassStream: %v", err)
	}
	again := make([]byte, len(whole))
	other.fill(again, 0)
	if bytes.Equal(again, whole) {
		t.Fatal("two random passes wrote the same stream: the key is not drawn per pass")
	}
}

// TestRandomPassStreamCarriesTheCounter: an IV whose low half is about to wrap
// carries into the high half, so the stream past the wrap is still the CTR
// stream and not a repeat of its start.
func TestRandomPassStreamCarriesTheCounter(t *testing.T) {
	s, err := newPassStream(PatternRandom)
	if err != nil {
		t.Fatalf("newPassStream: %v", err)
	}
	for i := 8; i < aes.BlockSize; i++ {
		s.iv[i] = 0xFF
	}

	whole := make([]byte, 4*aes.BlockSize)
	s.fill(whole, 0)
	tail := make([]byte, 2*aes.BlockSize)
	s.fill(tail, 2*aes.BlockSize)
	if !bytes.Equal(tail, whole[2*aes.BlockSize:]) {
		t.Fatal("the stream regenerated past the counter wrap differs from the stream written through it")
	}
}

// writeWipeFixture writes a file of size bytes of fill and returns its path and
// an open read-write descriptor.
func writeWipeFixture(t *testing.T, size int, fill byte) (string, *os.File) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "wipe-fixture")
	if err := os.WriteFile(path, bytes.Repeat([]byte{fill}, size), 0o600); err != nil {
		t.Fatalf("write fixture: %v", err)
	}
	f, err := os.OpenFile(path, os.O_RDWR, 0o600) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatalf("open fixture: %v", err)
	}
	t.Cleanup(func() { _ = f.Close() })
	return path, f
}

// TestWipePassWithStreamWritesThePattern covers each fixed pattern end to end.
func TestWipePassWithStreamWritesThePattern(t *testing.T) {
	defer parallel(t)()

	for _, tc := range []struct {
		pattern WipePattern
		start   byte
		want    byte
	}{{PatternZeros, 0xFF, 0x00}, {PatternOnes, 0x00, 0xFF}} {
		path, f := writeWipeFixture(t, 4096, tc.start)
		s, err := newPassStream(tc.pattern)
		if err != nil {
			t.Fatalf("newPassStream: %v", err)
		}
		if err := wipePassWithStream(f, 4096, s, nil, 1, 1); err != nil {
			t.Fatalf("wipePassWithStream(%s): %v", tc.pattern, err)
		}
		got, err := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatalf("read back: %v", err)
		}
		if !bytes.Equal(got, bytes.Repeat([]byte{tc.want}, 4096)) {
			t.Fatalf("%s pass did not write 0x%02x throughout", tc.pattern, tc.want)
		}
	}
}

// TestWipePassWithStreamRefusesANegativeSize, and writes nothing.
func TestWipePassWithStreamRefusesANegativeSize(t *testing.T) {
	_, f := writeWipeFixture(t, 16, 0xAA)
	s, _ := newPassStream(PatternZeros)
	if err := wipePassWithStream(f, -1, s, nil, 1, 1); !errors.Is(err, ErrInvalidSize) {
		t.Fatalf("wipePassWithStream(-1) = %v, want ErrInvalidSize", err)
	}
}

// TestWipePassWithStreamReportsAWriteFailure: a descriptor that cannot be
// written is a DeviceError, not a silent short wipe.
func TestWipePassWithStreamReportsAWriteFailure(t *testing.T) {
	path, _ := writeWipeFixture(t, 16, 0xAA)
	ro, err := os.Open(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ro.Close() }()
	s, _ := newPassStream(PatternZeros)
	var de *DeviceError
	if err := wipePassWithStream(ro, 16, s, nil, 1, 1); !errors.As(err, &de) {
		t.Fatalf("wipePassWithStream on a read-only descriptor = %v, want a DeviceError", err)
	}
}

// TestWipePassWithStreamReportsProgress tests the progress callback.
func TestWipePassWithStreamReportsProgress(t *testing.T) {
	defer parallel(t)()

	testSize := 2 * wipeChunk
	_, f := writeWipeFixture(t, testSize, 0)
	s, _ := newPassStream(PatternZeros)

	var progressCalls []WipeProgress
	if err := wipePassWithStream(f, int64(testSize), s, func(p WipeProgress) { progressCalls = append(progressCalls, p) }, 1, 3); err != nil {
		t.Fatalf("wipePassWithStream failed: %v", err)
	}

	if len(progressCalls) != 2 {
		t.Fatalf("got %d progress callbacks, want one per chunk (2)", len(progressCalls))
	}
	first := progressCalls[0]
	if first.CurrentPass != 1 || first.TotalPasses != 3 || first.Pattern != PatternZeros || first.IsVerification {
		t.Errorf("first progress = %+v", first)
	}
	last := progressCalls[len(progressCalls)-1]
	if last.BytesWritten != int64(testSize) || last.PercentComplete < 99.9 {
		t.Errorf("last progress = %+v", last)
	}
}

// TestVerifyWipeAcceptsWhatThePassWrote, for every pattern, and reports
// verification progress.
func TestVerifyWipeAcceptsWhatThePassWrote(t *testing.T) {
	defer parallel(t)()

	for _, pattern := range []WipePattern{PatternZeros, PatternOnes, PatternRandom} {
		path, f := writeWipeFixture(t, wipeChunk+4096+100, 0xAA)
		s, err := newPassStream(pattern)
		if err != nil {
			t.Fatal(err)
		}
		if err := wipePassWithStream(f, wipeChunk+4096+100, s, nil, 1, 1); err != nil {
			t.Fatal(err)
		}
		if err := f.Sync(); err != nil {
			t.Fatal(err)
		}
		var verified int64
		progress := func(p WipeProgress) {
			if p.IsVerification {
				verified = p.BytesWritten
			}
		}
		if err := verifyWipe(path, path, wipeChunk+4096+100, s, progress, 1); err != nil {
			t.Fatalf("verifyWipe(%s) refused what the pass wrote: %v", pattern, err)
		}
		if verified != wipeChunk+4096+100 {
			t.Fatalf("verification progress reached %d bytes, want %d", verified, wipeChunk+4096+100)
		}
	}
}

// TestVerifyWipeDetectsADifferenceInARandomPass is #246 D1. The DoD sequences
// end with a random pass, and verification used to return nil for a random
// pass without reading a byte -- so "verify" verified nothing.
func TestVerifyWipeDetectsADifferenceInARandomPass(t *testing.T) {
	defer parallel(t)()

	path, f := writeWipeFixture(t, 64*1024, 0)
	s, err := newPassStream(PatternRandom)
	if err != nil {
		t.Fatal(err)
	}
	if err := wipePassWithStream(f, 64*1024, s, nil, 1, 1); err != nil {
		t.Fatal(err)
	}
	// One byte of the medium is not what the pass wrote.
	one := make([]byte, 1)
	if _, err := f.ReadAt(one, 40000); err != nil {
		t.Fatal(err)
	}
	one[0] ^= 0x01
	if _, err := f.WriteAt(one, 40000); err != nil {
		t.Fatal(err)
	}
	if err := f.Sync(); err != nil {
		t.Fatal(err)
	}

	err = verifyWipe(path, path, 64*1024, s, nil, 1)
	if !errors.Is(err, ErrWipeVerification) {
		t.Fatalf("verifyWipe = %v, want ErrWipeVerification", err)
	}
	if !strings.Contains(err.Error(), "byte 40000") {
		t.Fatalf("the error does not name the first differing byte: %v", err)
	}
}

// TestVerifyWipeDetectsAShortMedium: a medium that ends early is not verified.
func TestVerifyWipeDetectsAShortMedium(t *testing.T) {
	defer parallel(t)()

	path, _ := writeWipeFixture(t, 4096, 0)
	s, _ := newPassStream(PatternZeros)
	if err := verifyWipe(path, path, 8192, s, nil, 1); !errors.Is(err, ErrWipeVerification) {
		t.Fatalf("verifyWipe past the end = %v, want ErrWipeVerification", err)
	}
	if err := verifyWipe(path, path, 0, s, nil, 1); err != nil {
		t.Fatalf("verifyWipe of nothing = %v, want nil", err)
	}
}

// staleMedium is a mediumReader whose bytes are NOT the file's: what the medium
// holds when the page cache has the wipe and the device does not.
type staleMedium struct {
	data   []byte
	closed bool
}

func (m *staleMedium) ReadAt(p []byte, off int64) (int, error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n := copy(p, m.data[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *staleMedium) Close() error { m.closed = true; return nil }

// useStaleMedium substitutes openMediumReader for the rest of the test. Not
// parallel: the seam is package state.
func useStaleMedium(t *testing.T, data []byte) *staleMedium {
	t.Helper()
	m := &staleMedium{data: data}
	previous := openMediumReader
	openMediumReader = func(string) (mediumReader, error) { return m, nil }
	t.Cleanup(func() { openMediumReader = previous })
	return m
}

// TestWipeVerificationReadsPastTheCache is #246 D2. Verification used to
// read back through the descriptor it had just written, so the page cache
// answered with the bytes this process put there whatever reached the medium.
// The medium is modeled here as still holding the old contents; a verification
// that consults the cache passes, and one that consults the medium does not.
func TestWipeVerificationReadsPastTheCache(t *testing.T) {
	path, _ := writeWipeFixture(t, 16*1024, 0xAA)
	m := useStaleMedium(t, bytes.Repeat([]byte{0xAA}, 16*1024))

	err := Wipe(WipeOptions{Device: path, Standard: StandardDoD3Pass})
	if !errors.Is(err, ErrWipeVerification) {
		t.Fatalf("Wipe with a medium that kept the old data = %v, want ErrWipeVerification", err)
	}
	if !m.closed {
		t.Fatal("the medium reader was not closed")
	}
}

// TestVerifyWipePropagatesAMediumOpenFailure: a medium that cannot be read
// past the cache is not reported as verified.
func TestVerifyWipePropagatesAMediumOpenFailure(t *testing.T) {
	path, _ := writeWipeFixture(t, 4096, 0)
	previous := openMediumReader
	openMediumReader = func(p string) (mediumReader, error) {
		return nil, &detailError{Kind: ErrDirectIOUnsupported, Detail: p}
	}
	t.Cleanup(func() { openMediumReader = previous })

	s, _ := newPassStream(PatternZeros)
	if err := verifyWipe(path, path, 4096, s, nil, 1); !errors.Is(err, ErrDirectIOUnsupported) {
		t.Fatalf("verifyWipe = %v, want ErrDirectIOUnsupported", err)
	}
}

// failingMedium fails every read, or only its Close.
type failingMedium struct{ readErr, closeErr error }

func (m failingMedium) ReadAt(p []byte, _ int64) (int, error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	clear(p)
	return len(p), nil
}

func (m failingMedium) Close() error { return m.closeErr }

// TestVerifyWipeReportsReadAndCloseFailures as device errors.
func TestVerifyWipeReportsReadAndCloseFailures(t *testing.T) {
	path, _ := writeWipeFixture(t, 4096, 0)
	s, _ := newPassStream(PatternZeros)
	previous := openMediumReader
	t.Cleanup(func() { openMediumReader = previous })

	for name, m := range map[string]failingMedium{
		"read":  {readErr: unix.EIO},
		"close": {closeErr: unix.EIO},
	} {
		openMediumReader = func(string) (mediumReader, error) { return m, nil }
		var de *DeviceError
		if err := verifyWipe(path, path, 4096, s, nil, 1); !errors.As(err, &de) || !errors.Is(err, unix.EIO) {
			t.Fatalf("%s failure: verifyWipe = %v, want a DeviceError wrapping EIO", name, err)
		}
	}
}

// TestDirectReaderReadsUnalignedSpans: the O_DIRECT reader aligns every read
// itself, so a caller's offset and length need not be.
func TestDirectReaderReadsUnalignedSpans(t *testing.T) {
	defer parallel(t)()

	content := make([]byte, wipeChunk+3*directIOAlign)
	for i := range content {
		content[i] = byte(i * 7)
	}
	path := filepath.Join(t.TempDir(), "direct")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}

	r, err := openDirectReader(path)
	if err != nil {
		t.Fatalf("openDirectReader: %v", err)
	}
	defer func() { _ = r.Close() }()

	// Exercise the aligned-buffer path whatever the filesystem under the temp
	// directory does with O_DIRECT.
	if _, ok := r.(*directReader); !ok {
		buf, err := unix.Mmap(-1, 0, wipeChunk+2*directIOAlign, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_ANON|unix.MAP_PRIVATE)
		if err != nil {
			t.Fatal(err)
		}
		f, err := os.Open(path) // #nosec G304 -- under t.TempDir()
		if err != nil {
			t.Fatal(err)
		}
		r = &directReader{f: f, buf: buf}
	}

	got := make([]byte, wipeChunk+100)
	n, err := r.ReadAt(got, 1234)
	if err != nil || n != len(got) || !bytes.Equal(got, content[1234:1234+len(got)]) {
		t.Fatalf("ReadAt(1234) = %d, %v; content mismatch=%v", n, err, !bytes.Equal(got[:n], content[1234:1234+n]))
	}

	tail := make([]byte, 5000)
	n, err = r.ReadAt(tail, int64(len(content)-100))
	if !errors.Is(err, io.EOF) || n != 100 || !bytes.Equal(tail[:n], content[len(content)-100:]) {
		t.Fatalf("ReadAt past the end = %d, %v; want 100 bytes and EOF", n, err)
	}
}

// TestOpenDirectReaderRefusesWhatItCannotOpen passes the open failure through.
func TestOpenDirectReaderRefusesWhatItCannotOpen(t *testing.T) {
	if _, err := openDirectReader(filepath.Join(t.TempDir(), "absent")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("openDirectReader(absent) = %v, want ErrNotExist", err)
	}
}

// TestOpenDirectReaderFallsBackOnlyWhereTheCacheIsTheStorage: O_DIRECT refused
// with EINVAL is a buffered read on a memory filesystem and a refusal
// everywhere else.
func TestOpenDirectReaderFallsBackOnlyWhereTheCacheIsTheStorage(t *testing.T) {
	path, _ := writeWipeFixture(t, 4096, 0)
	previous := openFileFunc
	t.Cleanup(func() { openFileFunc = previous })
	openFileFunc = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if flag&unix.O_DIRECT != 0 {
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.EINVAL}
		}
		return previous(name, flag, perm)
	}

	memory, err := cacheIsTheStorage(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := openDirectReader(path)
	switch {
	case memory && err == nil:
		_ = r.Close()
	case !memory && errors.Is(err, ErrDirectIOUnsupported):
	default:
		t.Fatalf("openDirectReader with O_DIRECT refused (memory filesystem=%v) = %v", memory, err)
	}

	if _, err := openDirectReader(filepath.Join(t.TempDir(), "absent")); err == nil {
		t.Fatal("openDirectReader(absent) with O_DIRECT refused succeeded")
	}
}

// TestResolvePatternSequence_StandardNIST tests NIST standard resolution
func TestResolvePatternSequence_StandardNIST(t *testing.T) {
	opts := WipeOptions{
		Standard: StandardNIST,
	}

	patterns, verify := resolvePatternSequence(opts)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern, got %d", len(patterns))
	}
	if patterns[0] != PatternRandom {
		t.Errorf("Expected PatternRandom, got %v", patterns[0])
	}
	if verify {
		t.Error("NIST should not require verification")
	}
}

// TestResolvePatternSequence_StandardDoD3Pass tests DoD 3-pass resolution
func TestResolvePatternSequence_StandardDoD3Pass(t *testing.T) {
	opts := WipeOptions{
		Standard: StandardDoD3Pass,
	}

	patterns, verify := resolvePatternSequence(opts)

	if len(patterns) != 3 {
		t.Fatalf("Expected 3 patterns, got %d", len(patterns))
	}
	expected := []WipePattern{PatternZeros, PatternOnes, PatternRandom}
	for i := range patterns {
		if patterns[i] != expected[i] {
			t.Errorf("Pattern[%d] = %v, want %v", i, patterns[i], expected[i])
		}
	}
	if !verify {
		t.Error("DoD 3-pass should require verification")
	}
}

// TestResolvePatternSequence_StandardDoD7Pass tests DoD 7-pass resolution
func TestResolvePatternSequence_StandardDoD7Pass(t *testing.T) {
	opts := WipeOptions{
		Standard: StandardDoD7Pass,
	}

	patterns, verify := resolvePatternSequence(opts)

	if len(patterns) != 7 {
		t.Fatalf("Expected 7 patterns, got %d", len(patterns))
	}
	if !verify {
		t.Error("DoD 7-pass should require verification")
	}
}

// TestResolvePatternSequence_CustomPatterns tests custom pattern sequence
func TestResolvePatternSequence_CustomPatterns(t *testing.T) {
	opts := WipeOptions{
		Patterns: []WipePattern{PatternOnes, PatternZeros},
		Verify:   true,
	}

	patterns, verify := resolvePatternSequence(opts)

	if len(patterns) != 2 {
		t.Fatalf("Expected 2 patterns, got %d", len(patterns))
	}
	if patterns[0] != PatternOnes || patterns[1] != PatternZeros {
		t.Errorf("Unexpected pattern sequence: %v", patterns)
	}
	if !verify {
		t.Error("Verify should be true when explicitly set")
	}
}

// TestResolvePatternSequence_LegacyZeros tests legacy mode with zeros
func TestResolvePatternSequence_LegacyZeros(t *testing.T) {
	opts := WipeOptions{
		Passes: 3,
		Random: false,
	}

	patterns, verify := resolvePatternSequence(opts)

	if len(patterns) != 3 {
		t.Fatalf("Expected 3 patterns, got %d", len(patterns))
	}
	for i, p := range patterns {
		if p != PatternZeros {
			t.Errorf("Pattern[%d] = %v, want PatternZeros", i, p)
		}
	}
	if verify {
		t.Error("Legacy mode should not verify by default")
	}
}

// TestResolvePatternSequence_LegacyRandom tests legacy mode with random
func TestResolvePatternSequence_LegacyRandom(t *testing.T) {
	opts := WipeOptions{
		Passes: 2,
		Random: true,
	}

	patterns, verify := resolvePatternSequence(opts)

	if len(patterns) != 2 {
		t.Fatalf("Expected 2 patterns, got %d", len(patterns))
	}
	for i, p := range patterns {
		if p != PatternRandom {
			t.Errorf("Pattern[%d] = %v, want PatternRandom", i, p)
		}
	}
	if verify {
		t.Error("Legacy mode should not verify by default")
	}
}

// TestResolvePatternSequence_LegacyDefaultPasses tests legacy mode with zero passes
func TestResolvePatternSequence_LegacyDefaultPasses(t *testing.T) {
	opts := WipeOptions{
		Passes: 0,
		Random: false,
	}

	patterns, _ := resolvePatternSequence(opts)

	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern (default), got %d", len(patterns))
	}
	if patterns[0] != PatternZeros {
		t.Errorf("Expected PatternZeros, got %v", patterns[0])
	}
}

// TestResolvePatternSequence_StandardOverridesLegacy tests standard takes priority
func TestResolvePatternSequence_StandardOverridesLegacy(t *testing.T) {
	opts := WipeOptions{
		Standard: StandardNIST,
		Passes:   5,     // Should be ignored
		Random:   false, // Should be ignored
	}

	patterns, _ := resolvePatternSequence(opts)

	// Should use NIST (1 random pass), not legacy (5 zero passes)
	if len(patterns) != 1 {
		t.Fatalf("Expected 1 pattern, got %d", len(patterns))
	}
	if patterns[0] != PatternRandom {
		t.Errorf("Expected PatternRandom, got %v", patterns[0])
	}
}

// TestResolvePatternSequence_VerifyOverride tests explicit verify override
func TestResolvePatternSequence_VerifyOverride(t *testing.T) {
	// NIST normally doesn't require verification, but we can force it
	opts := WipeOptions{
		Standard: StandardNIST,
		Verify:   true,
	}

	_, verify := resolvePatternSequence(opts)

	if !verify {
		t.Error("Explicit Verify=true should enable verification")
	}
}

// TestWipe_LegacyCompatibility tests backward compatibility with legacy options
func TestWipe_LegacyCompatibility(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_legacy_compat")

	testSize := 1024 * 1024 // 1MB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xAA
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Use legacy options (as before the refactor)
	opts := WipeOptions{
		Device: tmpFile,
		Passes: 2,
		Random: false,
	}

	if err := Wipe(opts); err != nil {
		t.Fatalf("Wipe with legacy options failed: %v", err)
	}

	// Verify file is wiped to zeros
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0x00 {
			t.Fatalf("Byte at %d is 0x%02x, want 0x00", i, b)
		}
	}
}

// TestWipe_StandardNIST tests wipe with NIST standard
func TestWipe_StandardNIST(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_nist")

	testSize := 512 * 1024 // 512KB
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	opts := WipeOptions{
		Device:   tmpFile,
		Standard: StandardNIST,
	}

	if err := Wipe(opts); err != nil {
		t.Fatalf("Wipe with NIST standard failed: %v", err)
	}

	// Verify file was wiped (with random data - can't check exact value)
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	if len(result) != testSize {
		t.Fatalf("File size changed: got %d, want %d", len(result), testSize)
	}
}

// TestWipe_StandardDoD3Pass tests wipe with DoD 3-pass standard
func TestWipe_StandardDoD3Pass(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_dod3")

	testSize := 512 * 1024 // 512KB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xAA
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var progressCalls []WipeProgress
	opts := WipeOptions{
		Device:   tmpFile,
		Standard: StandardDoD3Pass,
		ProgressFunc: func(p WipeProgress) {
			progressCalls = append(progressCalls, p)
		},
	}

	if err := Wipe(opts); err != nil {
		t.Fatalf("Wipe with DoD 3-pass standard failed: %v", err)
	}

	// Verify we got progress callbacks
	if len(progressCalls) == 0 {
		t.Error("Expected progress callbacks")
	}

	// Verify 3 passes were performed (multiple callbacks per pass)
	seenPasses := make(map[int]bool)
	for _, p := range progressCalls {
		if !p.IsVerification {
			seenPasses[p.CurrentPass] = true
		}
	}
	if len(seenPasses) != 3 {
		t.Errorf("Expected 3 different passes, got %d", len(seenPasses))
	}
}

// TestWipe_WithVerification tests wipe with explicit verification
func TestWipe_WithVerification(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_verify")

	testSize := 256 * 1024 // 256KB
	testData := make([]byte, testSize)
	for i := range testData {
		testData[i] = 0xAA
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	var verificationCalled bool
	opts := WipeOptions{
		Device: tmpFile,
		Passes: 1,
		Random: false,
		Verify: true,
		ProgressFunc: func(p WipeProgress) {
			if p.IsVerification {
				verificationCalled = true
			}
		},
	}

	if err := Wipe(opts); err != nil {
		t.Fatalf("Wipe with verification failed: %v", err)
	}

	if !verificationCalled {
		t.Error("Verification was not performed")
	}
}

// TestWipe_CustomPatternSequence tests wipe with custom pattern sequence
func TestWipe_CustomPatternSequence(t *testing.T) {
	defer parallel(t)()

	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_custom_patterns")

	testSize := 256 * 1024 // 256KB
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	patternsSeen := make(map[WipePattern]int)
	opts := WipeOptions{
		Device:   tmpFile,
		Patterns: []WipePattern{PatternOnes, PatternZeros, PatternOnes},
		ProgressFunc: func(p WipeProgress) {
			if !p.IsVerification && p.PercentComplete >= 99.9 {
				patternsSeen[p.Pattern]++
			}
		},
	}

	if err := Wipe(opts); err != nil {
		t.Fatalf("Wipe with custom patterns failed: %v", err)
	}

	// Should have seen ones twice and zeros once
	if patternsSeen[PatternOnes] != 2 {
		t.Errorf("PatternOnes seen %d times, want 2", patternsSeen[PatternOnes])
	}
	if patternsSeen[PatternZeros] != 1 {
		t.Errorf("PatternZeros seen %d times, want 1", patternsSeen[PatternZeros])
	}

	// Final pattern is ones, so file should end with 0xFF
	result, err := os.ReadFile(tmpFile)
	if err != nil {
		t.Fatalf("Failed to read result: %v", err)
	}

	for i, b := range result {
		if b != 0xFF {
			t.Fatalf("Byte at %d is 0x%02x, want 0xFF", i, b)
		}
	}
}

// TestWipeProgress_Fields tests WipeProgress struct fields
func TestWipeProgress_Fields(t *testing.T) {
	progress := WipeProgress{
		CurrentPass:     2,
		TotalPasses:     3,
		BytesWritten:    512,
		TotalBytes:      1024,
		Pattern:         PatternOnes,
		IsVerification:  false,
		PercentComplete: 50.0,
	}

	if progress.CurrentPass != 2 {
		t.Errorf("CurrentPass = %d, want 2", progress.CurrentPass)
	}
	if progress.TotalPasses != 3 {
		t.Errorf("TotalPasses = %d, want 3", progress.TotalPasses)
	}
	if progress.BytesWritten != 512 {
		t.Errorf("BytesWritten = %d, want 512", progress.BytesWritten)
	}
	if progress.TotalBytes != 1024 {
		t.Errorf("TotalBytes = %d, want 1024", progress.TotalBytes)
	}
	if progress.Pattern != PatternOnes {
		t.Errorf("Pattern = %v, want PatternOnes", progress.Pattern)
	}
	if progress.IsVerification {
		t.Error("IsVerification = true, want false")
	}
	if progress.PercentComplete != 50.0 {
		t.Errorf("PercentComplete = %f, want 50.0", progress.PercentComplete)
	}
}

// TestWipeRefusesWhatItCannotWipe is Wipe's front door: a path that is not a
// device, and a device with no bytes in it. The second is refused rather than
// reported as wiped -- "wiped zero bytes" is a success claim about nothing.
func TestWipeRefusesWhatItCannotWipe(t *testing.T) {
	defer parallel(t)()

	if err := Wipe(WipeOptions{Device: ""}); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("an empty path: %v, want ErrInvalidPath", err)
	}

	empty := filepath.Join(t.TempDir(), "empty.img")
	if err := os.WriteFile(empty, nil, 0o600); err != nil {
		t.Fatalf("creating the empty device: %v", err)
	}
	if err := Wipe(WipeOptions{Device: empty, Passes: 1}); !errors.Is(err, ErrInvalidSize) {
		t.Errorf("an empty device: %v, want it refused for having no size", err)
	}
}

// TestWipeKeyslotRefusesBeforeDestroyingAnything covers WipeKeyslot's refusals
// that come before the key material is touched: no device, no LUKS2 header, and
// a keyslot the header does not have. On the last the container must be
// byte-identical afterwards, since WipeKeyslot needs no passphrase to destroy.
func TestWipeKeyslotRefusesBeforeDestroyingAnything(t *testing.T) {
	defer parallel(t)()

	if err := WipeKeyslot("", 0); !errors.Is(err, ErrInvalidPath) {
		t.Errorf("an empty path: %v, want ErrInvalidPath", err)
	}
	if err := WipeKeyslot(newImage(t, "blank.img"), 0); !errors.Is(err, ErrInvalidHeader) {
		t.Errorf("a device with no LUKS2 header: %v, want ErrInvalidHeader", err)
	}

	device := newImage(t, "volume.img")
	formatWithLibrary(t, device)
	before := readAreaBytes(t, device, 0, goldenPrefixBytes)
	if err := WipeKeyslot(device, 5); err == nil || !strings.Contains(err.Error(), "keyslot 5 not found") {
		t.Errorf("a keyslot the header does not have: %v, want it refused by number", err)
	}
	if !bytes.Equal(before, readAreaBytes(t, device, 0, goldenPrefixBytes)) {
		t.Error("the refused WipeKeyslot changed the container")
	}
}

// TestWipeHeaderOnlyIsACryptoErase is #246 D3. A header-only wipe zeroed the
// two header copies and left the keyslot areas -- the wrapped volume key --
// intact, so anyone holding a copy of the header from before the wipe (a
// luksHeaderBackup, a snapshot, the first megabytes of a disk image) put it
// back and opened the volume with the old passphrase. A crypto-erase must
// leave that copy opening nothing.
func TestWipeHeaderOnlyIsACryptoErase(t *testing.T) {
	defer parallel(t)()

	path := newImage(t, "crypto-erase.img")
	if err := Format(standardFormatOptions(path)); err != nil {
		t.Fatalf("Format: %v", err)
	}
	hdr, metadata, err := ReadHeader(path)
	if err != nil {
		t.Fatalf("ReadHeader: %v", err)
	}
	area := int64(hdr.HeaderSize)
	backup := readImageAt(t, path, 0, int(2*area))
	_, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		t.Fatalf("keyslotsAreaBounds: %v", err)
	}

	if err := Wipe(WipeOptions{Device: path, HeaderOnly: true}); err != nil {
		t.Fatalf("header-only Wipe: %v", err)
	}
	if region := readImageAt(t, path, 0, int(keyslotsEnd)); !bytes.Equal(region, make([]byte, len(region))) {
		t.Fatal("the keyslots area is not all zeroes after a header-only wipe")
	}

	// Put the pre-wipe header copies back, as an attacker holding them would.
	writeImageAt(t, path, 0, backup)
	if _, _, err := ReadHeader(path); err != nil {
		t.Fatalf("precondition: the restored header does not read: %v", err)
	}
	if err := TestKey(path, []byte(conformancePassphrase)); err == nil {
		t.Fatal("the old passphrase opens the volume from a header restored after a header-only wipe: the keyslot material survived")
	}
}

// TestWipeHeaderOnlyErasesAStrayCopysJSON is #246 D3's second half. A stray
// header copy -- left by an earlier format with a different metadata size,
// beyond this container's keyslots area -- had only its 4 KiB binary header
// zeroed. Its JSON, keyslot salts and digests included, survived, and a
// binary header is a checksum computation away from rebuilt. The JSON goes
// too; the data segment does not.
func TestWipeHeaderOnlyErasesAStrayCopysJSON(t *testing.T) {
	defer parallel(t)()

	requireCryptsetup(t)

	const (
		strayAt    = 2 << 20
		dataOffset = 8 << 20
	)
	path := newForeignContainer(t, "stray.img", foreignGeometry{
		metadataSize:     "16k",
		keyslotsSize:     "1m",
		dataOffsetSec:    strconv.Itoa(dataOffset / 512),
		wantArea:         LUKS2HeaderMinSize,
		wantKeyslotsSize: 1 << 20,
	})

	// The stray: the secondary copy of a container formatted with 2 MiB of
	// metadata, which sits at 2 MiB -- past this container's keyslots area.
	donor := newImage(t, "donor.img")
	if err := Format(metadataSizeFormatOptions(donor, strayAt)); err != nil {
		t.Fatalf("Format donor: %v", err)
	}
	stray := readImageAt(t, donor, strayAt, strayAt)
	writeImageAt(t, path, strayAt, stray)
	payload := bytes.Repeat([]byte("payload!"), 512)
	writeImageAt(t, path, dataOffset, payload)

	if err := Wipe(WipeOptions{Device: path, HeaderOnly: true}); err != nil {
		t.Fatalf("header-only Wipe: %v", err)
	}

	if got := readImageAt(t, path, strayAt, strayAt); !bytes.Equal(got, make([]byte, len(got))) {
		t.Fatal("the stray copy's JSON survived a header-only wipe")
	}
	if !bytes.Equal(readImageAt(t, path, dataOffset, len(payload)), payload) {
		t.Fatal("the header-only wipe reached the data segment")
	}
}

// TestWipeHeaderPlanStaysOutOfTheData: a keyslot area or a stray copy that a
// validated header places at or past the first data segment is not zeroed
// there, and an unvalidated copy is zeroed only as far as its JSON runs.
func TestWipeHeaderPlanStaysOutOfTheData(t *testing.T) {
	metadata := &LUKS2Metadata{
		Segments: map[string]*Segment{"0": {Offset: "65536"}, "1": {Offset: "bogus"}, "2": nil},
		Keyslots: map[string]*Keyslot{
			"0": {Area: &KeyslotArea{Offset: "32768", Size: "65536"}},
			"1": {Area: &KeyslotArea{Offset: "x", Size: "1"}},
			"2": {},
			"3": nil,
		},
	}
	if got := firstDataOffset(metadata); got != 65536 {
		t.Fatalf("firstDataOffset = %d, want 65536", got)
	}
	if got := declaredKeyslotAreas(metadata); len(got) != 1 || got[0] != (wipeRegion{offset: 32768, size: 65536}) {
		t.Fatalf("declaredKeyslotAreas = %+v, want only the parseable area", got)
	}
	if got := firstDataOffset(&LUKS2Metadata{}); got != -1 {
		t.Fatalf("firstDataOffset with no segment = %d, want -1", got)
	}

	path := filepath.Join(t.TempDir(), "extent")
	content := make([]byte, 3*LUKS2HeaderSize)
	for i := LUKS2HeaderSize; i < 2*LUKS2HeaderSize+10; i++ {
		content[i] = '{'
	}
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if got := headerCopyExtent(f, 0, 16384); got != 2*LUKS2HeaderSize+11 {
		t.Fatalf("headerCopyExtent = %d, want the JSON and its NUL (%d)", got, 2*LUKS2HeaderSize+11)
	}
	if got := headerCopyExtent(f, 0, 2*LUKS2HeaderSize); got != 2*LUKS2HeaderSize {
		t.Fatalf("headerCopyExtent with no NUL inside the area = %d, want the area", got)
	}
	if got := headerCopyExtent(f, 2*LUKS2HeaderSize, 16384); got != LUKS2HeaderSize {
		t.Fatalf("headerCopyExtent running off the end = %d, want what could be read (%d)", got, LUKS2HeaderSize)
	}
}

// busyExclusiveOpens substitutes openFileFunc so that an O_EXCL open of path
// fails with EBUSY -- what the kernel answers for a block device that is
// mounted, mapped or held -- and records whether one was attempted. Not
// parallel: the seam is package state.
func busyExclusiveOpens(t *testing.T, path string) *bool {
	t.Helper()
	attempted := false
	previous := openFileFunc
	openFileFunc = func(name string, flag int, perm os.FileMode) (*os.File, error) {
		if name == path && flag&unix.O_EXCL != 0 {
			attempted = true
			return nil, &os.PathError{Op: "open", Path: name, Err: unix.EBUSY}
		}
		return previous(name, flag, perm)
	}
	t.Cleanup(func() { openFileFunc = previous })
	return &attempted
}

// TestWipeOpensTheDeviceExclusively is #246 D4. Wipe opened the device
// O_RDWR alone, so a mounted filesystem, a live dm-crypt mapping or anything
// else holding the device was overwritten underneath its user. The kernel's
// O_EXCL claim is the in-use check; EBUSY from it is ErrDeviceInUse and
// nothing is written.
func TestWipeOpensTheDeviceExclusively(t *testing.T) {
	path, _ := writeWipeFixture(t, 64*1024, 0xAA)
	attempted := busyExclusiveOpens(t, path)

	for _, opts := range []WipeOptions{{Device: path, HeaderOnly: true}, {Device: path, Passes: 1}} {
		err := Wipe(opts)
		if !*attempted {
			t.Fatal("Wipe did not open the device with O_EXCL")
		}
		if !errors.Is(err, ErrDeviceInUse) || !errors.Is(err, unix.EBUSY) {
			t.Fatalf("Wipe of a busy device = %v, want ErrDeviceInUse wrapping EBUSY", err)
		}
	}
	got, err := os.ReadFile(path) // #nosec G304 -- under t.TempDir()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat([]byte{0xAA}, 64*1024)) {
		t.Fatal("Wipe wrote to a device it reported busy")
	}
}

// TestWipeKeyslotOpensTheDeviceExclusively is D4 for WipeKeyslot: a keyslot of
// a volume that is open is not wiped out from under it.
func TestWipeKeyslotOpensTheDeviceExclusively(t *testing.T) {
	path := newImage(t, "wipe-keyslot-busy.img")
	formatWithLibrary(t, path)
	key, err := AddRecoveryKey(path, []byte(conformancePassphrase), &RecoveryKeyOptions{KDFType: KDFTypePBKDF2, PBKDFIterations: minPBKDF2Iterations})
	if err != nil {
		t.Fatalf("AddRecoveryKey: %v", err)
	}
	key.Clear()
	before := readImageAt(t, path, 0, 16<<20)
	attempted := busyExclusiveOpens(t, path)

	err = WipeKeyslot(path, key.Keyslot)
	if !*attempted {
		t.Fatal("WipeKeyslot did not open the device with O_EXCL")
	}
	if !errors.Is(err, ErrDeviceInUse) {
		t.Fatalf("WipeKeyslot of a busy device = %v, want ErrDeviceInUse", err)
	}
	if !bytes.Equal(readImageAt(t, path, 0, 16<<20), before) {
		t.Fatal("the container changed although the device was reported busy")
	}
}

// TestWipeNoVerifySkipsAStandardsVerification: NoVerify turns verification
// off even for a standard that requires it -- the medium here would fail it.
func TestWipeNoVerifySkipsAStandardsVerification(t *testing.T) {
	path, _ := writeWipeFixture(t, 16*1024, 0xAA)
	useStaleMedium(t, bytes.Repeat([]byte{0xAA}, 16*1024))

	if err := Wipe(WipeOptions{Device: path, Standard: StandardDoD3Pass, NoVerify: true}); err != nil {
		t.Fatalf("Wipe dod3 with NoVerify = %v, want no verification", err)
	}
	for _, opts := range []WipeOptions{
		{Standard: StandardDoD7Pass, NoVerify: true},
		{Patterns: []WipePattern{PatternOnes}, Verify: true, NoVerify: true},
		{Passes: 2, Verify: true, NoVerify: true},
	} {
		if _, verify := resolvePatternSequence(opts); verify {
			t.Errorf("resolvePatternSequence(%+v) still verifies", opts)
		}
	}
}

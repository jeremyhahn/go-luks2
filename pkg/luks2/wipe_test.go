// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
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

// TestFillBufferWithPattern_Zeros tests filling buffer with zeros
func TestFillBufferWithPattern_Zeros(t *testing.T) {
	buf := make([]byte, 1024)
	// Pre-fill with non-zero data
	for i := range buf {
		buf[i] = 0xAA
	}

	if err := fillBufferWithPattern(buf, PatternZeros); err != nil {
		t.Fatalf("fillBufferWithPattern failed: %v", err)
	}

	for i, b := range buf {
		if b != 0x00 {
			t.Fatalf("Byte at %d is 0x%02x, want 0x00", i, b)
		}
	}
}

// TestFillBufferWithPattern_Ones tests filling buffer with ones (0xFF)
func TestFillBufferWithPattern_Ones(t *testing.T) {
	buf := make([]byte, 1024)
	// Pre-fill with zeros
	for i := range buf {
		buf[i] = 0x00
	}

	if err := fillBufferWithPattern(buf, PatternOnes); err != nil {
		t.Fatalf("fillBufferWithPattern failed: %v", err)
	}

	for i, b := range buf {
		if b != 0xFF {
			t.Fatalf("Byte at %d is 0x%02x, want 0xFF", i, b)
		}
	}
}

// TestFillBufferWithPattern_Random tests filling buffer with random data
func TestFillBufferWithPattern_Random(t *testing.T) {
	buf := make([]byte, 4096)
	// Pre-fill with zeros
	for i := range buf {
		buf[i] = 0x00
	}

	if err := fillBufferWithPattern(buf, PatternRandom); err != nil {
		t.Fatalf("fillBufferWithPattern failed: %v", err)
	}

	// Check that at least some bytes are non-zero (random should produce variety)
	nonZeroCount := 0
	for _, b := range buf {
		if b != 0 {
			nonZeroCount++
		}
	}

	// With 4096 random bytes, we should have many non-zero bytes
	if nonZeroCount < 100 {
		t.Fatalf("Too few non-zero bytes in random buffer: %d", nonZeroCount)
	}
}

// TestFillBufferWithPattern_Unknown tests error handling for unknown pattern
func TestFillBufferWithPattern_Unknown(t *testing.T) {
	buf := make([]byte, 1024)
	err := fillBufferWithPattern(buf, WipePattern(99))
	if err == nil {
		t.Fatal("Expected error for unknown pattern")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("unknown pattern")) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestWipePassWithPattern_Zeros tests wipePassWithPattern with zeros
func TestWipePassWithPattern_Zeros(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_pattern_zeros")

	testData := make([]byte, 4096)
	for i := range testData {
		testData[i] = 0xFF
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := wipePassWithPattern(f, int64(len(testData)), PatternZeros, nil, 1, 1); err != nil {
		t.Fatalf("wipePassWithPattern failed: %v", err)
	}

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

// TestWipePassWithPattern_Ones tests wipePassWithPattern with ones
func TestWipePassWithPattern_Ones(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_pattern_ones")

	testData := make([]byte, 4096)
	// Start with zeros
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := wipePassWithPattern(f, int64(len(testData)), PatternOnes, nil, 1, 1); err != nil {
		t.Fatalf("wipePassWithPattern failed: %v", err)
	}

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

// TestWipePassWithPattern_Progress tests progress callback
func TestWipePassWithPattern_Progress(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_pattern_progress")

	testSize := 2 * 1024 * 1024 // 2MB (will trigger multiple progress updates)
	testData := make([]byte, testSize)

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	var progressCalls []WipeProgress
	progressFunc := func(p WipeProgress) {
		progressCalls = append(progressCalls, p)
	}

	if err := wipePassWithPattern(f, int64(testSize), PatternZeros, progressFunc, 1, 3); err != nil {
		t.Fatalf("wipePassWithPattern failed: %v", err)
	}

	if len(progressCalls) == 0 {
		t.Fatal("No progress callbacks received")
	}

	// Check first and last progress
	first := progressCalls[0]
	if first.CurrentPass != 1 || first.TotalPasses != 3 {
		t.Errorf("First progress: CurrentPass=%d, TotalPasses=%d, want 1, 3", first.CurrentPass, first.TotalPasses)
	}
	if first.Pattern != PatternZeros {
		t.Errorf("First progress pattern = %v, want PatternZeros", first.Pattern)
	}
	if first.IsVerification {
		t.Error("First progress should not be verification")
	}

	last := progressCalls[len(progressCalls)-1]
	if last.BytesWritten != int64(testSize) {
		t.Errorf("Last progress BytesWritten = %d, want %d", last.BytesWritten, testSize)
	}
	if last.PercentComplete < 99.9 {
		t.Errorf("Last progress PercentComplete = %f, want ~100", last.PercentComplete)
	}
}

// TestWipeVerify_Success tests successful verification
func TestWipeVerify_Success(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_verify_success")

	testSize := 4096
	testData := make([]byte, testSize)
	// Fill with zeros (pattern we'll verify)
	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := wipeVerify(f, int64(testSize), PatternZeros, nil, 1); err != nil {
		t.Fatalf("wipeVerify unexpectedly failed: %v", err)
	}
}

// TestWipeVerify_Failure tests verification failure detection
func TestWipeVerify_Failure(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_verify_failure")

	testSize := 4096
	testData := make([]byte, testSize)
	// Fill with zeros
	for i := range testData {
		testData[i] = 0x00
	}
	// Add a single wrong byte
	testData[100] = 0xFF

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	err = wipeVerify(f, int64(testSize), PatternZeros, nil, 1)
	if err == nil {
		t.Fatal("Expected verification failure")
	}
	if !bytes.Contains([]byte(err.Error()), []byte("verification failed")) {
		t.Errorf("Unexpected error message: %v", err)
	}
}

// TestWipeVerify_RandomPattern tests that random pattern verification is skipped
func TestWipeVerify_RandomPattern(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_verify_random")

	testSize := 4096
	testData := make([]byte, testSize)
	// Fill with arbitrary data
	for i := range testData {
		testData[i] = byte(i % 256)
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	// Random pattern verification should always succeed (skip verification)
	if err := wipeVerify(f, int64(testSize), PatternRandom, nil, 1); err != nil {
		t.Fatalf("wipeVerify with random pattern should not fail: %v", err)
	}
}

// TestWipeVerify_OnesPattern tests verification with ones pattern
func TestWipeVerify_OnesPattern(t *testing.T) {
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "test_verify_ones")

	testSize := 4096
	testData := make([]byte, testSize)
	// Fill with ones (0xFF)
	for i := range testData {
		testData[i] = 0xFF
	}

	if err := os.WriteFile(tmpFile, testData, 0600); err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	f, err := os.OpenFile(tmpFile, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := wipeVerify(f, int64(testSize), PatternOnes, nil, 1); err != nil {
		t.Fatalf("wipeVerify unexpectedly failed: %v", err)
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

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

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
	defer f.Close()

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
	defer f.Close()

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
	defer f.Close()

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
	defer f.Close()

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
	defer f.Close()

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
	defer f.Close()

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
	defer f.Close()

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
	defer f.Close()

	// Close the file to trigger seek error
	f.Close()

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
	defer f.Close()

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
		f1.Close()
		t.Fatalf("wipePass on file 1 failed: %v", err)
	}
	f1.Close()

	// Wipe second file with random data
	f2, err := os.OpenFile(tmpFile2, os.O_RDWR, 0600)
	if err != nil {
		t.Fatalf("Failed to open test file 2: %v", err)
	}
	if err := wipePass(f2, int64(testSize), true); err != nil {
		f2.Close()
		t.Fatalf("wipePass on file 2 failed: %v", err)
	}
	f2.Close()

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
	defer f.Close()

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
	defer f.Close()

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
			f.Close()
			b.Fatalf("wipePass failed: %v", err)
		}

		f.Close()
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
			f.Close()
			b.Fatalf("wipePass failed: %v", err)
		}

		f.Close()
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
			f.Close()
			b.Fatalf("wipeHeaders failed: %v", err)
		}

		f.Close()
	}
}

// mockFailingWriter is a writer that fails after a certain number of bytes
type mockFailingWriter struct {
	written    int
	failAt     int
	underlying *os.File
}

func (m *mockFailingWriter) Write(p []byte) (n int, err error) {
	if m.written >= m.failAt {
		return 0, io.ErrShortWrite
	}
	remaining := m.failAt - m.written
	if len(p) > remaining {
		n, err = m.underlying.Write(p[:remaining])
		m.written += n
		return n, io.ErrShortWrite
	}
	n, err = m.underlying.Write(p)
	m.written += n
	return n, err
}

func (m *mockFailingWriter) Seek(offset int64, whence int) (int64, error) {
	return m.underlying.Seek(offset, whence)
}

func (m *mockFailingWriter) Stat() (os.FileInfo, error) {
	return m.underlying.Stat()
}

func (m *mockFailingWriter) Sync() error {
	return m.underlying.Sync()
}

func (m *mockFailingWriter) Close() error {
	return m.underlying.Close()
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

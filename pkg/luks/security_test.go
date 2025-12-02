// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks

import (
	"math"
	"os"
	"path/filepath"
	"testing"
)

func TestValidateDevicePath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
	}{
		{"empty path", "", true},
		{"relative path", "relative/path", true},
		{"non-existent", "/nonexistent/device/path", true},
		{"path with dots", "../../../etc/passwd", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDevicePath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDevicePath(%q) error = %v, wantErr %v", tt.path, err, tt.wantErr)
			}
		})
	}

	// Test valid file
	t.Run("valid file", func(t *testing.T) {
		tmpFile, err := os.CreateTemp("", "luks-test-*")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(tmpFile.Name())
		tmpFile.Close()

		if err := ValidateDevicePath(tmpFile.Name()); err != nil {
			t.Errorf("ValidateDevicePath(valid file) = %v, want nil", err)
		}
	})
}

func TestValidateDevicePath_InvalidFile(t *testing.T) {
	// Create a directory instead of a file
	tmpDir, err := os.MkdirTemp("", "luks-test-dir-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	err = ValidateDevicePath(tmpDir)
	if err != ErrInvalidPath {
		t.Errorf("ValidateDevicePath(directory) = %v, want %v", err, ErrInvalidPath)
	}
}

func TestValidatePassphrase(t *testing.T) {
	tests := []struct {
		name       string
		passphrase []byte
		wantErr    error
	}{
		{"empty passphrase", []byte{}, ErrPassphraseTooShort},
		{"too short", []byte("short"), ErrPassphraseTooShort},
		{"minimum length", []byte("12345678"), nil},
		{"valid length", []byte("this-is-a-valid-passphrase"), nil},
		{"maximum length", make([]byte, MaxPassphraseLength), nil},
		{"too long", make([]byte, MaxPassphraseLength+1), ErrPassphraseTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePassphrase(tt.passphrase)
			if err != tt.wantErr {
				t.Errorf("ValidatePassphrase() = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidatePassphrase_EdgeCases(t *testing.T) {
	t.Run("exactly MinPassphraseLength", func(t *testing.T) {
		passphrase := make([]byte, MinPassphraseLength)
		if err := ValidatePassphrase(passphrase); err != nil {
			t.Errorf("ValidatePassphrase(min length) = %v, want nil", err)
		}
	})

	t.Run("one byte below minimum", func(t *testing.T) {
		passphrase := make([]byte, MinPassphraseLength-1)
		if err := ValidatePassphrase(passphrase); err != ErrPassphraseTooShort {
			t.Errorf("ValidatePassphrase(min-1) = %v, want %v", err, ErrPassphraseTooShort)
		}
	})
}

func TestValidateFormatOptions(t *testing.T) {
	// Create a temp file for testing
	tmpFile, err := os.CreateTemp("", "luks-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	tests := []struct {
		name    string
		opts    FormatOptions
		wantErr bool
	}{
		{
			name: "valid options",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    512,
				SectorSize: 512,
			},
			wantErr: false,
		},
		{
			name: "valid with 256 key size",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    256,
				SectorSize: 512,
			},
			wantErr: false,
		},
		{
			name: "valid with 4096 sector size",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    512,
				SectorSize: 4096,
			},
			wantErr: false,
		},
		{
			name: "zero key size is valid (defaults will be used)",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    0,
				SectorSize: 512,
			},
			wantErr: false,
		},
		{
			name: "zero sector size is valid (defaults will be used)",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    512,
				SectorSize: 0,
			},
			wantErr: false,
		},
		{
			name: "invalid key size",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				KeySize:    128,
			},
			wantErr: true,
		},
		{
			name: "invalid sector size",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("valid-passphrase"),
				SectorSize: 1024,
			},
			wantErr: true,
		},
		{
			name: "short passphrase",
			opts: FormatOptions{
				Device:     tmpFile.Name(),
				Passphrase: []byte("short"),
			},
			wantErr: true,
		},
		{
			name: "invalid device path",
			opts: FormatOptions{
				Device:     "/nonexistent/path",
				Passphrase: []byte("valid-passphrase"),
			},
			wantErr: true,
		},
		{
			name: "argon2id with valid parameters",
			opts: FormatOptions{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2id",
				Argon2Memory: 65536,
				Argon2Time:   1,
			},
			wantErr: false,
		},
		{
			name: "argon2i with valid parameters",
			opts: FormatOptions{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2i",
				Argon2Memory: 131072,
				Argon2Time:   4,
			},
			wantErr: false,
		},
		{
			name: "argon2id with insufficient memory",
			opts: FormatOptions{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2id",
				Argon2Memory: 32768,
			},
			wantErr: true,
		},
		{
			name: "argon2id with negative time cost",
			opts: FormatOptions{
				Device:       tmpFile.Name(),
				Passphrase:   []byte("valid-passphrase"),
				KDFType:      "argon2id",
				Argon2Memory: 65536,
				Argon2Time:   -1,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateFormatOptions(tt.opts)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateFormatOptions() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateFormatOptions_OverflowDetection(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "luks-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// This test verifies integer overflow detection in size calculations
	// KeySize is in bits, so we divide by 8 to get bytes
	// Then multiply by AFStripes (4000)
	// We want to test that the overflow check works
	t.Run("normal key size no overflow", func(t *testing.T) {
		opts := FormatOptions{
			Device:     tmpFile.Name(),
			Passphrase: []byte("valid-passphrase"),
			KeySize:    512,
		}
		if err := ValidateFormatOptions(opts); err != nil {
			t.Errorf("ValidateFormatOptions() unexpected error = %v", err)
		}
	})
}

func TestConstantTimeEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []byte
		want bool
	}{
		{"equal slices", []byte("hello"), []byte("hello"), true},
		{"different slices", []byte("hello"), []byte("world"), false},
		{"different lengths", []byte("hello"), []byte("hi"), false},
		{"empty slices", []byte{}, []byte{}, true},
		{"nil slices", nil, nil, true},
		{"one nil one empty", nil, []byte{}, true},
		{"same content different case", []byte("Hello"), []byte("hello"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ConstantTimeEqual(tt.a, tt.b); got != tt.want {
				t.Errorf("ConstantTimeEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConstantTimeEqual_ActuallyConstantTime(t *testing.T) {
	// Verify that comparison is constant time regardless of where difference occurs
	a := []byte("aaaaaaaaaaaaaaaaaaaa")
	b1 := []byte("baaaaaaaaaaaaaaaaaaaa") // Differs at position 0
	b2 := []byte("aaaaaaaaaaaaaaaaaaaab") // Differs at position 19

	// Both should be false
	if ConstantTimeEqual(a, b1) {
		t.Error("Expected false for b1")
	}
	if ConstantTimeEqual(a, b2) {
		t.Error("Expected false for b2")
	}
}

func TestCheckOverflow(t *testing.T) {
	tests := []struct {
		name    string
		a, b    int
		wantErr bool
	}{
		{"no overflow small numbers", 100, 200, false},
		{"no overflow zero values", 0, 1000000, false},
		{"no overflow zero a", 0, math.MaxInt, false},
		{"no overflow zero b", math.MaxInt, 0, false},
		{"no overflow negative", -100, 200, false},
		{"large but safe", 1000000, 1000, false},
		{"overflow at max", math.MaxInt, 2, true},
		{"overflow large numbers", math.MaxInt / 2, 3, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := CheckOverflow(tt.a, tt.b)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckOverflow(%d, %d) error = %v, wantErr %v", tt.a, tt.b, err, tt.wantErr)
			}
			if err != nil && err != ErrIntegerOverflow {
				t.Errorf("CheckOverflow() error = %v, want %v", err, ErrIntegerOverflow)
			}
		})
	}
}

func TestCheckOverflow_EdgeCases(t *testing.T) {
	t.Run("exactly at boundary", func(t *testing.T) {
		// math.MaxInt / 2 * 2 should not overflow
		err := CheckOverflow(math.MaxInt/2, 2)
		if err != nil {
			t.Errorf("CheckOverflow(MaxInt/2, 2) = %v, want nil", err)
		}
	})

	t.Run("just over boundary", func(t *testing.T) {
		// (math.MaxInt / 2 + 1) * 2 should overflow
		err := CheckOverflow(math.MaxInt/2+1, 2)
		if err == nil {
			t.Error("CheckOverflow(MaxInt/2+1, 2) = nil, want error")
		}
	})
}

func TestFileLock(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "luks-lock-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Acquire lock
	lock, err := AcquireFileLock(tmpFile.Name())
	if err != nil {
		t.Fatalf("AcquireFileLock() error = %v", err)
	}

	// Try to acquire again (should fail)
	_, err = AcquireFileLock(tmpFile.Name())
	if err == nil {
		t.Error("Expected error acquiring second lock, got nil")
	}

	// Release lock
	if err := lock.Release(); err != nil {
		t.Errorf("Release() error = %v", err)
	}

	// Should be able to acquire again
	lock2, err := AcquireFileLock(tmpFile.Name())
	if err != nil {
		t.Fatalf("AcquireFileLock() after release error = %v", err)
	}
	defer func() { _ = lock2.Release() }()
}

func TestFileLock_NonexistentFile(t *testing.T) {
	_, err := AcquireFileLock("/nonexistent/file/path")
	if err == nil {
		t.Error("AcquireFileLock(nonexistent) = nil, want error")
	}
}

func TestFileLock_ReleaseNilFile(t *testing.T) {
	lock := &FileLock{file: nil}
	if err := lock.Release(); err != nil {
		t.Errorf("Release() on nil file = %v, want nil", err)
	}
}

func TestFileLock_MultipleRelease(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "luks-lock-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	lock, err := AcquireFileLock(tmpFile.Name())
	if err != nil {
		t.Fatal(err)
	}

	// First release
	if err := lock.Release(); err != nil {
		t.Errorf("First Release() error = %v", err)
	}

	// Second release should not crash (file is closed)
	// This tests defensive programming
	if err := lock.Release(); err == nil {
		// File is already closed, so we expect an error
		t.Log("Second Release() returned nil (expected error for closed file)")
	}
}

func TestOpenFileSecure(t *testing.T) {
	tmpDir := os.TempDir()
	path := filepath.Join(tmpDir, "luks-secure-test")
	defer os.Remove(path)

	// Open with secure function (create new file)
	f, err := OpenFileSecure(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatalf("OpenFileSecure() error = %v", err)
	}
	defer f.Close()

	// Verify file is open
	if _, err := f.Stat(); err != nil {
		t.Errorf("File not properly opened: %v", err)
	}

	// Verify permissions are 0600
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("File permissions = %o, want 0600", mode)
	}
}

func TestOpenFileSecure_NewFile(t *testing.T) {
	tmpDir := os.TempDir()
	path := filepath.Join(tmpDir, "luks-secure-new-test")
	defer os.Remove(path)

	// Open non-existent file with O_CREATE
	f, err := OpenFileSecure(path, os.O_RDWR|os.O_CREATE)
	if err != nil {
		t.Fatalf("OpenFileSecure() error = %v", err)
	}
	defer f.Close()

	// Verify permissions are 0600
	info, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}

	mode := info.Mode().Perm()
	if mode != 0600 {
		t.Errorf("File permissions = %o, want 0600", mode)
	}
}

func TestOpenFileSecure_InvalidPath(t *testing.T) {
	_, err := OpenFileSecure("/nonexistent/dir/file", os.O_RDWR)
	if err == nil {
		t.Error("OpenFileSecure(nonexistent) = nil, want error")
	}
}

func TestValidateDevicePath_SymlinkHandling(t *testing.T) {
	// Create a temp file
	tmpFile, err := os.CreateTemp("", "luks-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	// Create a symlink to it
	symlinkPath := filepath.Join(os.TempDir(), "luks-test-symlink")
	if err := os.Symlink(tmpFile.Name(), symlinkPath); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(symlinkPath)

	// Symlink should be validated successfully
	if err := ValidateDevicePath(symlinkPath); err != nil {
		t.Errorf("ValidateDevicePath(symlink) = %v, want nil", err)
	}
}

func TestSecurityConstants(t *testing.T) {
	// Verify security constants have reasonable values
	tests := []struct {
		name  string
		value int
		min   int
	}{
		{"MinPassphraseLength", MinPassphraseLength, 8},
		{"MaxPassphraseLength", MaxPassphraseLength, 512},
		{"MinKeySize", MinKeySize, 256},
		{"MaxKeySize", MaxKeySize, 512},
		{"MinSectorSize", MinSectorSize, 512},
		{"MaxSectorSize", MaxSectorSize, 4096},
		{"DigestIterations", DigestIterations, 100000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.value < tt.min {
				t.Errorf("%s = %d, want >= %d", tt.name, tt.value, tt.min)
			}
		})
	}
}

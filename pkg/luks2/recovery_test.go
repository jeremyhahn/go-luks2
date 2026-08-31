// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build !integration

package luks2

import (
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-enclave"
)

func TestGenerateRecoveryKey(t *testing.T) {
	tests := []struct {
		name      string
		length    int
		format    RecoveryKeyFormat
		expectLen int
		expectErr bool
	}{
		{
			name:      "default length hex format",
			length:    0, // Will use default
			format:    RecoveryKeyFormatHex,
			expectLen: RecoveryKeyLength,
			expectErr: false,
		},
		{
			name:      "32 bytes hex format",
			length:    32,
			format:    RecoveryKeyFormatHex,
			expectLen: 32,
			expectErr: false,
		},
		{
			name:      "64 bytes base64 format",
			length:    64,
			format:    RecoveryKeyFormatBase64,
			expectLen: 64,
			expectErr: false,
		},
		{
			name:      "32 bytes dashed format",
			length:    32,
			format:    RecoveryKeyFormatDashed,
			expectLen: 32,
			expectErr: false,
		},
		{
			name:      "empty format defaults to dashed",
			length:    32,
			format:    "",
			expectLen: 32,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GenerateRecoveryKey(tt.length, tt.format)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			defer key.Clear()

			if key.Key.Size() != tt.expectLen {
				t.Errorf("expected key length %d, got %d", tt.expectLen, key.Key.Size())
			}

			// The key is held in an ENCLAVE, not a slice: it can be destroyed,
			// and reading it afterwards fails rather than returning stale bytes.
			if !key.Key.IsAlive() {
				t.Error("the generated key is not held in live protected memory")
			}

			if key.Formatted.Size() == 0 {
				t.Error("expected formatted key to be non-empty")
			}

			if key.KeyHash == "" {
				t.Error("expected key hash to be non-empty")
			}

			if key.CreatedAt.IsZero() {
				t.Error("expected created at to be set")
			}

			// Verify format
			expectedFormat := tt.format
			if expectedFormat == "" {
				expectedFormat = RecoveryKeyFormatDashed
			}
			if key.Format != expectedFormat {
				t.Errorf("expected format %s, got %s", expectedFormat, key.Format)
			}
		})
	}
}

// TestFormatDashedKey pins the dashed rendering byte for byte.
//
// It matters more than it looks: the rendering is now built IN PLACE inside
// locked memory, by encoding the hex right-aligned in the destination and
// expanding it leftward around the separators, rather than by joining strings.
// These fixtures are what stands between that rewrite and a recovery key that
// prints differently from the one that was stored.
func TestFormatDashedKey(t *testing.T) {
	tests := []struct {
		name     string
		key      []byte
		expected string
	}{
		{
			name:     "simple 6 bytes",
			key:      []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06},
			expected: "010203-040506",
		},
		{
			name:     "12 bytes",
			key:      []byte{0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66},
			expected: "AABBCC-DDEEFF-112233-445566",
		},
		{
			name:     "uneven bytes",
			key:      []byte{0x01, 0x02, 0x03, 0x04, 0x05},
			expected: "010203-0405",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dst := make([]byte, formattedLen(len(tt.key), RecoveryKeyFormatDashed))
			formatRecoveryKeyInto(dst, tt.key, RecoveryKeyFormatDashed)

			if result := string(dst); result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestParseRecoveryKey(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expectLen int
		expectErr bool
	}{
		{
			name:      "dashed format",
			input:     "AABBCC-DDEEFF-112233-445566",
			expectLen: 12,
			expectErr: false,
		},
		{
			name:      "hex format",
			input:     "aabbccddeeff112233445566",
			expectLen: 12,
			expectErr: false,
		},
		{
			name:      "base64 format",
			input:     "qrvM3e7/ESIzRFVm",
			expectLen: 12,
			expectErr: false,
		},
		{
			name:      "hex with spaces (trimmed)",
			input:     "  aabbccddeeff  ",
			expectLen: 6,
			expectErr: false,
		},
		{
			name:      "invalid hex",
			input:     "gghhii",
			expectLen: 0,
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := ParseRecoveryKey(tt.input)

			if tt.expectErr {
				if err == nil {
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			defer key.Destroy()

			// ParseRecoveryKey hands back an ENCLAVE, so the decoded key is
			// never a slice the caller has to remember to wipe.
			if key.Size() != tt.expectLen {
				t.Errorf("expected length %d, got %d", tt.expectLen, key.Size())
			}
		})
	}
}

func TestRecoveryKeyRoundTrip(t *testing.T) {
	// Generate a key
	original, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	defer original.Clear()

	formatted, err := original.FormattedString()
	if err != nil {
		t.Fatalf("failed to materialize the formatted key: %v", err)
	}

	// Parse it back
	parsed, err := ParseRecoveryKey(formatted)
	if err != nil {
		t.Fatalf("failed to parse key: %v", err)
	}
	defer parsed.Destroy()

	// Compare
	if hex.EncodeToString(openSecret(t, original.Key)) != hex.EncodeToString(openSecret(t, parsed)) {
		t.Error("round-trip failed: keys don't match")
	}
}

func TestSaveAndLoadRecoveryKey(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "luks-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Generate key
	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatDashed)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	key.VolumeUUID = "test-uuid-1234"
	key.Keyslot = 2

	// Save to file
	keyPath := filepath.Join(tmpDir, "recovery-key.txt")
	if err := SaveRecoveryKey(key, keyPath); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	// Verify file permissions
	info, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("failed to stat key file: %v", err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("expected file permissions 0400, got %o", info.Mode().Perm())
	}

	// Load and verify
	loaded, err := LoadRecoveryKey(keyPath)
	if err != nil {
		t.Fatalf("failed to load key: %v", err)
	}

	defer loaded.Destroy()

	if hex.EncodeToString(openSecret(t, key.Key)) != hex.EncodeToString(openSecret(t, loaded)) {
		t.Error("loaded key doesn't match original")
	}
}

func TestSaveRecoveryKeyContent(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "luks-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Generate key with specific values
	key := &RecoveryKey{
		Key:        enclaveFrom(t, []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06}),
		Formatted:  enclaveFrom(t, []byte("010203-040506")),
		Format:     RecoveryKeyFormatDashed,
		KeyHash:    "testhash",
		VolumeUUID: "test-uuid",
		Keyslot:    1,
	}

	keyPath := filepath.Join(tmpDir, "recovery-key.txt")
	if err := SaveRecoveryKey(key, keyPath); err != nil {
		t.Fatalf("failed to save key: %v", err)
	}

	// Read file content
	content, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("failed to read key file: %v", err)
	}

	contentStr := string(content)

	// Verify content contains expected elements
	if !strings.Contains(contentStr, "LUKS Recovery Key") {
		t.Error("expected header in file")
	}
	if !strings.Contains(contentStr, "test-uuid") {
		t.Error("expected UUID in file")
	}
	if !strings.Contains(contentStr, "Keyslot: 1") {
		t.Error("expected keyslot in file")
	}
	if !strings.Contains(contentStr, "010203-040506") {
		t.Error("expected recovery key in file")
	}
}

func TestRecoveryKeyClear(t *testing.T) {
	key, err := GenerateRecoveryKey(32, RecoveryKeyFormatHex)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Verify key is set
	if key.Key.Size() == 0 {
		t.Fatal("key should not be empty")
	}
	if key.Formatted.Size() == 0 {
		t.Fatal("formatted key should not be empty")
	}

	held, rendered := key.Key, key.Formatted

	// Clear the key
	key.Clear()

	// Verify key is cleared. Both halves matter: the handle is dropped AND the
	// locked region behind it is destroyed, so a copy of the handle taken
	// before Clear cannot still read the key.
	if key.Key != nil {
		t.Error("key should be nil after clear")
	}
	if key.Formatted != nil {
		t.Error("formatted should be nil after clear")
	}
	if held.IsAlive() {
		t.Error("the key's locked region survived Clear")
	}
	if rendered.IsAlive() {
		t.Error("the rendering's locked region survived Clear")
	}
	if err := held.WithBytes(func([]byte) error { return nil }); !errors.Is(err, enclave.ErrEnclaveDestroyed) {
		t.Errorf("a cleared key is still readable: %v", err)
	}

	// Clear is idempotent, because error paths call it after a partial setup.
	key.Clear()
}

func TestRecoveryKeyFormats(t *testing.T) {
	// Test each format constant
	if RecoveryKeyFormatHex != "hex" {
		t.Errorf("expected 'hex', got %s", RecoveryKeyFormatHex)
	}
	if RecoveryKeyFormatBase64 != "base64" {
		t.Errorf("expected 'base64', got %s", RecoveryKeyFormatBase64)
	}
	if RecoveryKeyFormatDashed != "dashed" {
		t.Errorf("expected 'dashed', got %s", RecoveryKeyFormatDashed)
	}
}

func TestRecoveryKeyLength(t *testing.T) {
	if RecoveryKeyLength != 32 {
		t.Errorf("expected RecoveryKeyLength to be 32, got %d", RecoveryKeyLength)
	}
}

func TestRecoveryKeyOptions(t *testing.T) {
	opts := &RecoveryKeyOptions{
		Length:         64,
		Format:         RecoveryKeyFormatHex,
		Keyslot:        intPtr(5),
		OutputPath:     "/tmp/test-key.txt",
		KDFType:        "argon2id",
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}

	if opts.Length != 64 {
		t.Errorf("expected Length 64, got %d", opts.Length)
	}
	if opts.Format != RecoveryKeyFormatHex {
		t.Errorf("expected Format hex, got %s", opts.Format)
	}
	if *opts.Keyslot != 5 {
		t.Errorf("expected Keyslot 5, got %d", *opts.Keyslot)
	}
	if opts.OutputPath != "/tmp/test-key.txt" {
		t.Errorf("expected OutputPath /tmp/test-key.txt, got %s", opts.OutputPath)
	}
}

func TestDecodeHex(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		expected  []byte
		expectErr bool
	}{
		{
			name:     "lowercase hex",
			input:    "aabbccdd",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:     "uppercase hex",
			input:    "AABBCCDD",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:     "with whitespace",
			input:    "  aabbccdd  ",
			expected: []byte{0xAA, 0xBB, 0xCC, 0xDD},
		},
		{
			name:      "invalid hex chars",
			input:     "gghhii",
			expectErr: true,
		},
		{
			name:      "odd length",
			input:     "aabbc",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// decodeHexSecret takes bytes and expects them already trimmed and
			// lower-cased -- the caller normalises in place inside locked
			// memory rather than through strings.TrimSpace/ToLower, which each
			// yield an unwipeable copy of the credential. The test does the
			// same normalisation the parser does.
			normalized := []byte(tt.input)
			normalized = trimASCIISpace(normalized)
			lowerASCII(normalized)

			result, err := decodeHexSecret(normalized)

			if tt.expectErr {
				if err == nil {
					result.Destroy()
					t.Error("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			defer result.Destroy()

			// The decode writes straight into locked memory, so what is
			// asserted on here is a test-only copy taken back out of it.
			if got := openSecret(t, result); hex.EncodeToString(got) != hex.EncodeToString(tt.expected) {
				t.Errorf("expected %x, got %x", tt.expected, got)
			}
		})
	}
}

func TestLoadRecoveryKeyNonExistent(t *testing.T) {
	_, err := LoadRecoveryKey("/nonexistent/path/key.txt")
	if err == nil {
		t.Error("expected error for non-existent file")
	}
}

func TestLoadRecoveryKeyEmptyFile(t *testing.T) {
	// Create temp directory
	tmpDir, err := os.MkdirTemp("", "luks-recovery-test-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	// Create empty file
	keyPath := filepath.Join(tmpDir, "empty-key.txt")
	if err := os.WriteFile(keyPath, []byte("# Comment only\n"), 0400); err != nil {
		t.Fatalf("failed to create empty file: %v", err)
	}

	_, err = LoadRecoveryKey(keyPath)
	if err == nil {
		t.Error("expected error for empty/comment-only file")
	}
}

func TestRecoveryKeySaveError(t *testing.T) {
	// Test that SaveError field can be set and checked
	key := &RecoveryKey{
		Key:        enclaveFrom(t, []byte{0x01, 0x02, 0x03}),
		Formatted:  enclaveFrom(t, []byte("010203")),
		Format:     RecoveryKeyFormatHex,
		VolumeUUID: "test-uuid",
		Keyslot:    0,
	}

	// Initially SaveError should be nil
	if key.SaveError != nil {
		t.Error("expected SaveError to be nil initially")
	}

	// Set SaveError
	key.SaveError = os.ErrPermission

	// Verify SaveError is set
	if key.SaveError == nil {
		t.Error("expected SaveError to be set")
	}
	if key.SaveError != os.ErrPermission {
		t.Errorf("expected SaveError to be ErrPermission, got %v", key.SaveError)
	}
}

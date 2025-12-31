// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// RecoveryKeyLength is the default length for recovery keys (32 bytes = 256 bits)
const RecoveryKeyLength = 32

// RecoveryKeyFormat specifies the output format for recovery keys
type RecoveryKeyFormat string

const (
	// RecoveryKeyFormatHex outputs the key as hexadecimal
	RecoveryKeyFormatHex RecoveryKeyFormat = "hex"

	// RecoveryKeyFormatBase64 outputs the key as base64
	RecoveryKeyFormatBase64 RecoveryKeyFormat = "base64"

	// RecoveryKeyFormatDashed outputs as dash-separated hex groups (like Windows BitLocker)
	RecoveryKeyFormatDashed RecoveryKeyFormat = "dashed"
)

// RecoveryKey represents a generated recovery key
type RecoveryKey struct {
	// Key is the raw key bytes (sensitive - clear after use)
	Key []byte

	// Formatted is the human-readable representation
	Formatted string

	// Format is the format used
	Format RecoveryKeyFormat

	// KeyHash is a SHA-256 hash of the key for verification
	KeyHash string

	// CreatedAt is when the key was generated
	CreatedAt time.Time

	// VolumeUUID is the UUID of the volume this key is for
	VolumeUUID string

	// Keyslot is the keyslot number this key was added to
	Keyslot int

	// SaveError contains any error that occurred while saving the key to file.
	// The key was still successfully added to the volume even if this is set.
	SaveError error
}

// RecoveryKeyOptions contains options for recovery key generation
type RecoveryKeyOptions struct {
	// Length is the key length in bytes (default: 32)
	Length int

	// Format is the output format (default: dashed)
	Format RecoveryKeyFormat

	// Keyslot specifies which keyslot to use (nil = auto-select)
	Keyslot *int

	// OutputPath is where to save the recovery key (optional)
	OutputPath string

	// KDFType specifies the KDF type (default: argon2id)
	KDFType string

	// Argon2 parameters
	Argon2Time     int
	Argon2Memory   int
	Argon2Parallel int
}

// GenerateRecoveryKey generates a cryptographically secure recovery key
func GenerateRecoveryKey(length int, format RecoveryKeyFormat) (*RecoveryKey, error) {
	if length <= 0 {
		length = RecoveryKeyLength
	}

	if format == "" {
		format = RecoveryKeyFormatDashed
	}

	// Generate random bytes
	key := make([]byte, length)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("failed to generate random key: %w", err)
	}

	// Format the key
	var formatted string
	switch format {
	case RecoveryKeyFormatHex:
		formatted = hex.EncodeToString(key)
	case RecoveryKeyFormatBase64:
		formatted = base64.StdEncoding.EncodeToString(key)
	case RecoveryKeyFormatDashed:
		formatted = formatDashedKey(key)
	default:
		formatted = formatDashedKey(key)
	}

	// Calculate hash for verification
	hash := sha256.Sum256(key)

	return &RecoveryKey{
		Key:       key,
		Formatted: formatted,
		Format:    format,
		KeyHash:   hex.EncodeToString(hash[:]),
		CreatedAt: time.Now(),
	}, nil
}

// AddRecoveryKey generates a recovery key and adds it to a LUKS volume
// existingPassphrase is used to unlock the volume
func AddRecoveryKey(device string, existingPassphrase []byte, opts *RecoveryKeyOptions) (*RecoveryKey, error) {
	if opts == nil {
		opts = &RecoveryKeyOptions{}
	}

	// Set defaults
	if opts.Length <= 0 {
		opts.Length = RecoveryKeyLength
	}
	if opts.Format == "" {
		opts.Format = RecoveryKeyFormatDashed
	}

	// Generate recovery key
	recoveryKey, err := GenerateRecoveryKey(opts.Length, opts.Format)
	if err != nil {
		return nil, err
	}

	// Add the recovery key to the volume
	addOpts := &AddKeyOptions{
		Keyslot:        opts.Keyslot,
		KDFType:        opts.KDFType,
		Argon2Time:     opts.Argon2Time,
		Argon2Memory:   opts.Argon2Memory,
		Argon2Parallel: opts.Argon2Parallel,
	}

	if err := AddKey(device, existingPassphrase, recoveryKey.Key, addOpts); err != nil {
		clearBytes(recoveryKey.Key)
		return nil, fmt.Errorf("failed to add recovery key: %w", err)
	}

	// Get volume info for UUID
	info, err := GetVolumeInfo(device)
	if err == nil {
		recoveryKey.VolumeUUID = info.UUID
	}

	// Determine which keyslot was used
	if opts.Keyslot != nil {
		recoveryKey.Keyslot = *opts.Keyslot
	} else {
		// Find the newly added keyslot
		slots, err := ListKeyslots(device)
		if err == nil {
			maxSlot := 0
			for _, s := range slots {
				if s.ID > maxSlot {
					maxSlot = s.ID
				}
			}
			recoveryKey.Keyslot = maxSlot
		}
	}

	// Save to file if path specified
	if opts.OutputPath != "" {
		if err := SaveRecoveryKey(recoveryKey, opts.OutputPath); err != nil {
			// Non-fatal - key was still added, but caller should be aware
			recoveryKey.SaveError = fmt.Errorf("failed to save recovery key to %s: %w", opts.OutputPath, err)
		}
	}

	return recoveryKey, nil
}

// SaveRecoveryKey saves a recovery key to a file
func SaveRecoveryKey(key *RecoveryKey, path string) error {
	// Ensure directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Build content
	var content strings.Builder
	content.WriteString("# LUKS Recovery Key\n")
	content.WriteString("# IMPORTANT: Store this key in a safe location!\n")
	content.WriteString("# This key can be used to unlock the encrypted volume if the primary\n")
	content.WriteString("# passphrase is lost or the TPM becomes unavailable.\n")
	content.WriteString("#\n")
	content.WriteString(fmt.Sprintf("# Volume UUID: %s\n", key.VolumeUUID))
	content.WriteString(fmt.Sprintf("# Keyslot: %d\n", key.Keyslot))
	content.WriteString(fmt.Sprintf("# Created: %s\n", key.CreatedAt.Format(time.RFC3339)))
	content.WriteString(fmt.Sprintf("# Key Hash (SHA-256): %s\n", key.KeyHash))
	content.WriteString("#\n")
	content.WriteString("# Recovery Key:\n")
	content.WriteString(key.Formatted)
	content.WriteString("\n")

	// Write with restricted permissions (owner read only)
	if err := os.WriteFile(path, []byte(content.String()), 0400); err != nil {
		return fmt.Errorf("failed to write recovery key: %w", err)
	}

	return nil
}

// LoadRecoveryKey loads a recovery key from a file
func LoadRecoveryKey(path string) ([]byte, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- user-provided path for recovery key file
	if err != nil {
		return nil, fmt.Errorf("failed to read recovery key file: %w", err)
	}

	// Parse the file - look for the actual key (skip comments)
	lines := strings.Split(string(data), "\n")
	var keyLine string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		keyLine = line
		break
	}

	if keyLine == "" {
		return nil, fmt.Errorf("no recovery key found in file")
	}

	// Try to parse the key based on format
	return ParseRecoveryKey(keyLine)
}

// ParseRecoveryKey parses a recovery key from its formatted string representation
func ParseRecoveryKey(formatted string) ([]byte, error) {
	formatted = strings.TrimSpace(formatted)

	// Try dashed format first (most common for recovery keys)
	if strings.Contains(formatted, "-") {
		// Remove dashes
		hexStr := strings.ReplaceAll(formatted, "-", "")
		return decodeHex(hexStr)
	}

	// Check if it looks like pure hex (only hex characters)
	isHex := true
	for _, c := range strings.ToLower(formatted) {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			isHex = false
			break
		}
	}

	// If it looks like hex and has even length, try hex first
	if isHex && len(formatted)%2 == 0 {
		if key, err := decodeHex(formatted); err == nil {
			return key, nil
		}
	}

	// Try base64 (must have padding or non-hex chars to be considered base64)
	if strings.HasSuffix(formatted, "=") || !isHex {
		if key, err := base64.StdEncoding.DecodeString(formatted); err == nil {
			return key, nil
		}
	}

	// Final fallback to hex
	return decodeHex(formatted)
}

// VerifyRecoveryKey verifies a recovery key can unlock the volume
func VerifyRecoveryKey(device string, key []byte) (bool, error) {
	if err := ValidateDevicePath(device); err != nil {
		return false, err
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		return false, err
	}

	// Try to unlock with the key
	_, err = getMasterKey(device, key, metadata)
	return err == nil, nil
}

// formatDashedKey formats a key as dash-separated hex groups
// Format: XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX-XXXXXX
func formatDashedKey(key []byte) string {
	hexStr := hex.EncodeToString(key)
	var groups []string
	groupSize := 6

	for i := 0; i < len(hexStr); i += groupSize {
		end := i + groupSize
		if end > len(hexStr) {
			end = len(hexStr)
		}
		groups = append(groups, strings.ToUpper(hexStr[i:end]))
	}

	return strings.Join(groups, "-")
}

// decodeHex decodes a hex string to bytes
func decodeHex(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.ToLower(s)
	return hex.DecodeString(s)
}

// Clear clears the sensitive key material from memory
func (r *RecoveryKey) Clear() {
	if r.Key != nil {
		clearBytes(r.Key)
		r.Key = nil
	}
	r.Formatted = ""
}

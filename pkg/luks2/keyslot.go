// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"fmt"
	"os"
	"strconv"
)

// LUKS2 keyslot constants
const (
	// MaxKeyslots is the maximum number of keyslots in LUKS2
	MaxKeyslots = 32

	// KeyslotAreaAlignment is the alignment for keyslot areas
	KeyslotAreaAlignment = 4096
)

// AddKeyOptions contains options for adding a new key
type AddKeyOptions struct {
	// Keyslot specifies which keyslot to use (nil = auto-select)
	Keyslot *int

	// KDFType specifies the KDF type (default: argon2id)
	KDFType string

	// Argon2 parameters (optional, uses defaults if not specified)
	Argon2Time     int
	Argon2Memory   int
	Argon2Parallel int

	// PBKDF2 parameters (for pbkdf2 KDF type)
	PBKDFIterTime int
}

// AddKey adds a new passphrase to an available keyslot
// existingPassphrase is used to unlock the volume and retrieve the master key
// newPassphrase is the new passphrase to add
func AddKey(device string, existingPassphrase, newPassphrase []byte, opts *AddKeyOptions) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(existingPassphrase); err != nil {
		return fmt.Errorf("invalid existing passphrase: %w", err)
	}
	if err := ValidatePassphrase(newPassphrase); err != nil {
		return fmt.Errorf("invalid new passphrase: %w", err)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Unlock with existing passphrase to get master key
	masterKey, err := getMasterKey(device, existingPassphrase, metadata)
	if err != nil {
		return fmt.Errorf("failed to unlock with existing passphrase: %w", err)
	}
	defer clearBytes(masterKey)

	// Find available keyslot
	targetSlot, err := findAvailableKeyslot(metadata, opts)
	if err != nil {
		return err
	}

	// Get existing keyslot for reference (cipher, key size, etc.)
	var referenceKeyslot *Keyslot
	for _, ks := range metadata.Keyslots {
		referenceKeyslot = ks
		break
	}
	if referenceKeyslot == nil {
		return fmt.Errorf("no existing keyslot found for reference")
	}

	// Calculate new keyslot area offset
	newOffset, err := calculateNextKeyslotOffset(metadata)
	if err != nil {
		return err
	}

	// Create KDF for new keyslot
	kdfType := "argon2id"
	if opts != nil && opts.KDFType != "" {
		kdfType = opts.KDFType
	}

	formatOpts := FormatOptions{
		KDFType:        kdfType,
		HashAlgo:       DefaultHashAlgo,
		Argon2Time:     4,
		Argon2Memory:   1048576,
		Argon2Parallel: 4,
	}
	if opts != nil {
		if opts.Argon2Time > 0 {
			formatOpts.Argon2Time = opts.Argon2Time
		}
		if opts.Argon2Memory > 0 {
			formatOpts.Argon2Memory = opts.Argon2Memory
		}
		if opts.Argon2Parallel > 0 {
			formatOpts.Argon2Parallel = opts.Argon2Parallel
		}
		if opts.PBKDFIterTime > 0 {
			formatOpts.PBKDFIterTime = opts.PBKDFIterTime
		}
	}

	kdf, err := CreateKDF(formatOpts, referenceKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to create KDF: %w", err)
	}

	// Derive key from new passphrase
	passphraseKey, err := DeriveKey(newPassphrase, kdf, referenceKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer clearBytes(passphraseKey)

	// Apply anti-forensic split to master key
	afData, err := AFSplit(masterKey, AFStripes, DefaultHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to apply AF split: %w", err)
	}
	defer clearBytes(afData)

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterial(afData, passphraseKey, DefaultCipher)
	if err != nil {
		return fmt.Errorf("failed to encrypt key material: %w", err)
	}
	defer clearBytes(encryptedKeyMaterial)

	// Calculate aligned size
	alignedSize := alignTo(int64(len(encryptedKeyMaterial)), KeyslotAreaAlignment)

	// Create new keyslot metadata
	priority := 2 // Lower priority than original keyslot
	newKeyslot := &Keyslot{
		Type:     "luks2",
		KeySize:  referenceKeyslot.KeySize,
		Priority: &priority,
		Area: &KeyslotArea{
			Type:       "raw",
			KeySize:    referenceKeyslot.KeySize,
			Offset:     formatSize(newOffset),
			Size:       formatSize(alignedSize),
			Encryption: referenceKeyslot.Area.Encryption,
		},
		KDF: kdf,
		AF: &AntiForensic{
			Type:    "luks1",
			Stripes: AFStripes,
			Hash:    DefaultHashAlgo,
		},
	}

	// Add keyslot to metadata
	slotIDStr := strconv.Itoa(targetSlot)
	metadata.Keyslots[slotIDStr] = newKeyslot

	// Update digest to include new keyslot
	for _, digest := range metadata.Digests {
		found := false
		for _, ks := range digest.Keyslots {
			if ks == slotIDStr {
				found = true
				break
			}
		}
		if !found {
			digest.Keyslots = append(digest.Keyslots, slotIDStr)
		}
	}

	// Update keyslots size in config
	newKeyslotsEnd := newOffset + alignedSize
	metadata.Config.KeyslotsSize = formatSize(newKeyslotsEnd)

	// Increment sequence ID
	hdr.SequenceID++

	// Write encrypted key material to device
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Seek(newOffset, 0); err != nil {
		return fmt.Errorf("failed to seek to keyslot area: %w", err)
	}

	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return fmt.Errorf("failed to write key material: %w", err)
	}

	// Pad to aligned size
	padding := make([]byte, alignedSize-int64(len(encryptedKeyMaterial)))
	if _, err := f.Write(padding); err != nil {
		return fmt.Errorf("failed to write padding: %w", err)
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// RemoveKey removes a passphrase from a keyslot
// The passphrase must match the key in the specified slot
func RemoveKey(device string, passphrase []byte, keyslot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", keyslot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", keyslot)
	}

	// Verify passphrase unlocks this specific keyslot
	_, err = unlockKeyslot(device, passphrase, targetKeyslot, metadata.Digests)
	if err != nil {
		return fmt.Errorf("passphrase does not match keyslot %d: %w", keyslot, err)
	}

	// Ensure at least one keyslot remains
	if len(metadata.Keyslots) <= 1 {
		return fmt.Errorf("cannot remove last keyslot")
	}

	// Wipe the keyslot area
	if err := wipeKeyslotArea(device, targetKeyslot); err != nil {
		return fmt.Errorf("failed to wipe keyslot area: %w", err)
	}

	// Remove keyslot from metadata
	delete(metadata.Keyslots, slotIDStr)

	// Remove from digests
	for _, digest := range metadata.Digests {
		newKeyslots := make([]string, 0, len(digest.Keyslots))
		for _, ks := range digest.Keyslots {
			if ks != slotIDStr {
				newKeyslots = append(newKeyslots, ks)
			}
		}
		digest.Keyslots = newKeyslots
	}

	// Increment sequence ID
	hdr.SequenceID++

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// ChangeKey changes the passphrase for a specific keyslot
func ChangeKey(device string, oldPassphrase, newPassphrase []byte, keyslot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(oldPassphrase); err != nil {
		return fmt.Errorf("invalid old passphrase: %w", err)
	}
	if err := ValidatePassphrase(newPassphrase); err != nil {
		return fmt.Errorf("invalid new passphrase: %w", err)
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", keyslot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", keyslot)
	}

	// Unlock with old passphrase to get master key
	masterKey, err := unlockKeyslot(device, oldPassphrase, targetKeyslot, metadata.Digests)
	if err != nil {
		return fmt.Errorf("old passphrase does not match keyslot %d: %w", keyslot, err)
	}
	defer clearBytes(masterKey)

	// Create new KDF (keep same type as existing)
	kdfType := targetKeyslot.KDF.Type
	formatOpts := FormatOptions{
		KDFType:  kdfType,
		HashAlgo: DefaultHashAlgo,
	}

	// Copy existing Argon2 parameters or set defaults
	if kdfType == "argon2id" || kdfType == "argon2i" {
		formatOpts.Argon2Time = 4
		formatOpts.Argon2Memory = 1048576
		formatOpts.Argon2Parallel = 4
		if targetKeyslot.KDF.Time != nil {
			formatOpts.Argon2Time = *targetKeyslot.KDF.Time
		}
		if targetKeyslot.KDF.Memory != nil {
			formatOpts.Argon2Memory = *targetKeyslot.KDF.Memory
		}
		if targetKeyslot.KDF.CPUs != nil {
			formatOpts.Argon2Parallel = *targetKeyslot.KDF.CPUs
		}
	}

	kdf, err := CreateKDF(formatOpts, targetKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to create KDF: %w", err)
	}

	// Derive key from new passphrase
	passphraseKey, err := DeriveKey(newPassphrase, kdf, targetKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer clearBytes(passphraseKey)

	// Apply anti-forensic split to master key
	afData, err := AFSplit(masterKey, AFStripes, targetKeyslot.AF.Hash)
	if err != nil {
		return fmt.Errorf("failed to apply AF split: %w", err)
	}
	defer clearBytes(afData)

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterial(afData, passphraseKey, DefaultCipher)
	if err != nil {
		return fmt.Errorf("failed to encrypt key material: %w", err)
	}
	defer clearBytes(encryptedKeyMaterial)

	// Get existing keyslot offset
	existingOffset, err := parseSize(targetKeyslot.Area.Offset)
	if err != nil {
		return fmt.Errorf("failed to parse keyslot offset: %w", err)
	}

	existingSize, err := parseSize(targetKeyslot.Area.Size)
	if err != nil {
		return fmt.Errorf("failed to parse keyslot size: %w", err)
	}

	// Verify new key material fits in existing area
	if int64(len(encryptedKeyMaterial)) > existingSize {
		return fmt.Errorf("new key material too large for existing keyslot area")
	}

	// Wipe existing keyslot area first
	if err := wipeKeyslotArea(device, targetKeyslot); err != nil {
		return fmt.Errorf("failed to wipe existing keyslot: %w", err)
	}

	// Write new encrypted key material
	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return fmt.Errorf("failed to open device: %w", err)
	}
	defer func() { _ = f.Close() }()

	if _, err := f.Seek(existingOffset, 0); err != nil {
		return fmt.Errorf("failed to seek to keyslot area: %w", err)
	}

	if _, err := f.Write(encryptedKeyMaterial); err != nil {
		return fmt.Errorf("failed to write key material: %w", err)
	}

	// Pad remaining area
	remaining := existingSize - int64(len(encryptedKeyMaterial))
	if remaining > 0 {
		padding := make([]byte, remaining)
		if _, err := f.Write(padding); err != nil {
			return fmt.Errorf("failed to write padding: %w", err)
		}
	}

	if err := f.Sync(); err != nil {
		return fmt.Errorf("failed to sync: %w", err)
	}

	// Update keyslot KDF in metadata
	targetKeyslot.KDF = kdf

	// Increment sequence ID
	hdr.SequenceID++

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// KillKeyslot removes a keyslot without requiring the passphrase
// WARNING: This is a destructive operation - the keyslot cannot be recovered
func KillKeyslot(device string, keyslot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if keyslot < 0 || keyslot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", keyslot, MaxKeyslots-1)
	}

	// Acquire exclusive lock
	lock, err := AcquireFileLock(device)
	if err != nil {
		return fmt.Errorf("failed to acquire lock: %w", err)
	}
	defer func() { _ = lock.Release() }()

	// Read existing header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Check that keyslot exists
	slotIDStr := strconv.Itoa(keyslot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", keyslot)
	}

	// Ensure at least one keyslot remains
	if len(metadata.Keyslots) <= 1 {
		return fmt.Errorf("cannot remove last keyslot")
	}

	// Wipe the keyslot area
	if err := wipeKeyslotArea(device, targetKeyslot); err != nil {
		return fmt.Errorf("failed to wipe keyslot area: %w", err)
	}

	// Remove keyslot from metadata
	delete(metadata.Keyslots, slotIDStr)

	// Remove from digests
	for _, digest := range metadata.Digests {
		newKeyslots := make([]string, 0, len(digest.Keyslots))
		for _, ks := range digest.Keyslots {
			if ks != slotIDStr {
				newKeyslots = append(newKeyslots, ks)
			}
		}
		digest.Keyslots = newKeyslots
	}

	// Increment sequence ID
	hdr.SequenceID++

	// Write updated headers
	if err := writeHeaderInternal(device, hdr, metadata); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	return nil
}

// ListKeyslots returns information about all active keyslots
func ListKeyslots(device string) ([]KeyslotInfo, error) {
	if err := ValidateDevicePath(device); err != nil {
		return nil, err
	}

	_, metadata, err := ReadHeader(device)
	if err != nil {
		return nil, fmt.Errorf("failed to read header: %w", err)
	}

	var slots []KeyslotInfo
	for idStr, ks := range metadata.Keyslots {
		id, err := strconv.Atoi(idStr)
		if err != nil {
			continue
		}

		priority := 0
		if ks.Priority != nil {
			priority = *ks.Priority
		}

		slots = append(slots, KeyslotInfo{
			ID:         id,
			Type:       ks.Type,
			KeySize:    ks.KeySize,
			Priority:   priority,
			KDFType:    ks.KDF.Type,
			Encryption: ks.Area.Encryption,
		})
	}

	return slots, nil
}

// KeyslotInfo contains information about a keyslot
type KeyslotInfo struct {
	ID         int
	Type       string
	KeySize    int
	Priority   int
	KDFType    string
	Encryption string
}

// getMasterKey unlocks the volume and returns the master key
func getMasterKey(device string, passphrase []byte, metadata *LUKS2Metadata) ([]byte, error) {
	for _, keyslot := range metadata.Keyslots {
		if keyslot.Type != "luks2" {
			continue
		}

		masterKey, err := unlockKeyslot(device, passphrase, keyslot, metadata.Digests)
		if err != nil {
			continue
		}

		return masterKey, nil
	}

	return nil, fmt.Errorf("incorrect passphrase")
}

// findAvailableKeyslot finds the next available keyslot number
func findAvailableKeyslot(metadata *LUKS2Metadata, opts *AddKeyOptions) (int, error) {
	// If specific keyslot requested, verify it's available
	if opts != nil && opts.Keyslot != nil {
		slot := *opts.Keyslot
		if slot < 0 || slot >= MaxKeyslots {
			return 0, fmt.Errorf("invalid keyslot: %d (must be 0-%d)", slot, MaxKeyslots-1)
		}
		slotIDStr := strconv.Itoa(slot)
		if _, exists := metadata.Keyslots[slotIDStr]; exists {
			return 0, fmt.Errorf("keyslot %d already in use", slot)
		}
		return slot, nil
	}

	// Find first available keyslot
	for i := 0; i < MaxKeyslots; i++ {
		slotIDStr := strconv.Itoa(i)
		if _, exists := metadata.Keyslots[slotIDStr]; !exists {
			return i, nil
		}
	}

	return 0, fmt.Errorf("no available keyslots")
}

// calculateNextKeyslotOffset calculates the offset for the next keyslot area
func calculateNextKeyslotOffset(metadata *LUKS2Metadata) (int64, error) {
	var maxEnd int64 = 0x8000 // Start after headers (32KB)

	for _, ks := range metadata.Keyslots {
		offset, err := parseSize(ks.Area.Offset)
		if err != nil {
			continue
		}
		size, err := parseSize(ks.Area.Size)
		if err != nil {
			continue
		}
		end := offset + size
		if end > maxEnd {
			maxEnd = end
		}
	}

	// Align to 4KB boundary
	return alignTo(maxEnd, KeyslotAreaAlignment), nil
}

// wipeKeyslotArea securely wipes a keyslot area
func wipeKeyslotArea(device string, keyslot *Keyslot) error {
	offset, err := parseSize(keyslot.Area.Offset)
	if err != nil {
		return err
	}

	size, err := parseSize(keyslot.Area.Size)
	if err != nil {
		return err
	}

	f, err := os.OpenFile(device, os.O_RDWR, 0600) // #nosec G304 -- device path validated by caller
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	// Wipe with zeros
	if _, err := f.Seek(offset, 0); err != nil {
		return err
	}

	zeros := make([]byte, size)
	if _, err := f.Write(zeros); err != nil {
		return err
	}

	return f.Sync()
}

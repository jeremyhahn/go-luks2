// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"cmp"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"

	"github.com/jeremyhahn/go-enclave"
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
	// Valid values: "pbkdf2", "argon2i", "argon2id"
	KDFType string

	// Hash specifies the hash algorithm for PBKDF2 (default: sha256)
	// Valid values: "sha256", "sha512"
	// Note: This is only used when KDFType is "pbkdf2"
	Hash string

	// Argon2 parameters (optional, uses defaults if not specified)
	Argon2Time     int
	Argon2Memory   int
	Argon2Parallel int

	// PBKDF2 parameters (for pbkdf2 KDF type)
	PBKDFIterTime int
}

// TestKey verifies that a passphrase can unlock the LUKS volume
// Returns nil if the passphrase is valid, error otherwise
func TestKey(device string, passphrase []byte) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}

	// Read header and metadata
	_, metadata, err := ReadHeader(device)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Try to get master key with the passphrase
	masterKey, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		return fmt.Errorf("passphrase does not unlock any keyslot: %w", err)
	}
	// The key is recovered only to prove the passphrase opens a slot; it is
	// released immediately rather than at the end of a scope that does nothing
	// else with it.
	masterKey.Destroy()

	return nil
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
	defer masterKey.Destroy()

	// Find available keyslot
	targetSlot, err := findAvailableKeyslot(metadata, opts)
	if err != nil {
		return err
	}

	// Get existing keyslot for reference (cipher, key size, etc.).
	//
	// Its KeySize sizes the derivation and the AF split for the NEW keyslot, so
	// a damaged slot picked as the template would push its damage into a slot
	// that is about to be written. Slots are considered in scan order and the
	// first usable one wins, rather than whichever the map yielded first: with
	// a random pick, whether AddKey succeeded depended on which keyslot Go
	// happened to iterate to.
	var referenceKeyslot *Keyslot
	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		ks := metadata.Keyslots[id]
		if ks.Type != "luks2" || validateKeyslot(id, ks) != nil {
			continue
		}
		referenceKeyslot = ks
		break
	}
	if referenceKeyslot == nil {
		return fmt.Errorf("%w: no existing keyslot is usable as a template for a new one", ErrInvalidKeyslot)
	}

	// Read the container's reserved keyslots area out of its own header rather
	// than assuming this library's default geometry.
	keyslotsStart, keyslotsEnd, err := keyslotsAreaBounds(hdr, metadata)
	if err != nil {
		return err
	}

	// Calculate new keyslot area offset
	newOffset, err := calculateNextKeyslotOffset(metadata, keyslotsStart)
	if err != nil {
		return err
	}

	// Create KDF for new keyslot
	kdfType := "argon2id"
	if opts != nil && opts.KDFType != "" {
		kdfType = opts.KDFType
	}

	// Determine hash algorithm - use provided value or default to sha256
	hashAlgo := DefaultHashAlgo
	if opts != nil && opts.Hash != "" {
		hashAlgo = opts.Hash
	}

	formatOpts := FormatOptions{
		KDFType:        kdfType,
		HashAlgo:       hashAlgo,
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
	passphraseKey, err := DeriveKeyEnclave(newPassphrase, kdf, referenceKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer passphraseKey.Destroy()

	// Apply anti-forensic split to master key
	afData, err := afSplitEnclave(masterKey, AFStripes, DefaultHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to apply AF split: %w", err)
	}
	defer afData.Destroy()

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterialEnclave(afData, passphraseKey, DefaultCipher)
	if err != nil {
		return fmt.Errorf("failed to encrypt key material: %w", err)
	}
	defer clearBytes(encryptedKeyMaterial)

	// Calculate aligned size
	alignedSize := alignTo(int64(len(encryptedKeyMaterial)), KeyslotAreaAlignment)

	newKeyslotsEnd := newOffset + alignedSize

	// CRITICAL, and two separate boundaries.
	//
	// The first is the container's DECLARED geometry: config.keyslots_size. A
	// keyslot beyond it is outside the area the container says it reserved for
	// keyslots, even when nothing is physically overwritten, and another LUKS2
	// implementation is entitled to refuse the result. Only the data-segment
	// check existed before, which on a conformant container whose data offset
	// sits past the keyslots area let a new keyslot be placed in the gap
	// between the two.
	if newKeyslotsEnd > keyslotsEnd {
		return fmt.Errorf("%w: a new keyslot would end at offset %d but the container's keyslots area is %d..%d (config.keyslots_size %s); reformat with a larger keyslots area",
			ErrKeyslotsAreaFull, newKeyslotsEnd, keyslotsStart, keyslotsEnd, metadata.Config.KeyslotsSize)
	}

	// The second is PHYSICAL: the encrypted data itself. It is kept even though
	// the declared bound is normally tighter, because a container whose
	// config.keyslots_size overstates the space available would otherwise let a
	// keyslot be written over user data.
	for _, segment := range metadata.Segments {
		segmentOffset, err := parseSize(segment.Offset)
		if err != nil {
			continue
		}
		if newKeyslotsEnd > segmentOffset {
			return fmt.Errorf("%w: a new keyslot would end at offset %d but the data segment starts at %d; reformat with a larger header",
				ErrKeyslotsAreaFull, newKeyslotsEnd, segmentOffset)
		}
	}

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

	// config.keyslots_size is deliberately NOT touched here.
	//
	// It is the size of the RESERVED keyslots area, fixed when the container was
	// formatted, and not a high-water mark of the slots in use. Writing
	// newKeyslotsEnd -- an absolute end offset -- into it was the same defect as
	// the one Format carried (#28): it stored an offset where the spec wants a
	// size, and on top of that it SHRANK the reserved area down to the end of the
	// newly added slot, so a conformant container stopped being one as soon as a
	// second passphrase was added.
	//
	// Nothing needs to grow either: the overlap check above already refuses a slot
	// that would run past the data segment, which is the boundary the reserved
	// area was sized against.

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

	// Verify passphrase unlocks this specific keyslot. The recovered key is
	// wanted only as proof, so it is released at once instead of being held for
	// the rest of the removal.
	verified, err := unlockKeyslot(device, passphrase, targetKeyslot, metadata.Digests)
	if err != nil {
		return fmt.Errorf("passphrase does not match keyslot %d: %w", keyslot, err)
	}
	verified.Destroy()

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

// KillSlot removes a keyslot from a LUKS device after authenticating with any valid passphrase.
// This is equivalent to "cryptsetup luksKillSlot --key-file keyfile device slot".
// Unlike RemoveKey, the authentication passphrase does NOT need to be from the slot being removed.
//
// Parameters:
//   - device: Path to the LUKS device
//   - authPassphrase: A valid passphrase from ANY keyslot (for authentication)
//   - targetSlot: The keyslot number to remove (0-31)
func KillSlot(device string, authPassphrase []byte, targetSlot int) error {
	// Validate inputs
	if err := ValidateDevicePath(device); err != nil {
		return err
	}
	if err := ValidatePassphrase(authPassphrase); err != nil {
		return err
	}
	if targetSlot < 0 || targetSlot >= MaxKeyslots {
		return fmt.Errorf("invalid keyslot: %d (must be 0-%d)", targetSlot, MaxKeyslots-1)
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

	// Verify the auth passphrase works with any keyslot (authentication check)
	authValid := false
	for _, slotID := range keyslotIDsInScanOrder(metadata.Keyslots) {
		keyslot := metadata.Keyslots[slotID]
		candidate, err := unlockKeyslot(device, authPassphrase, keyslot, metadata.Digests)
		if err == nil {
			// Authentication only: the key is not needed past this point.
			candidate.Destroy()
			authValid = true
			// Make sure we're not removing the only keyslot we can authenticate with
			if slotID == strconv.Itoa(targetSlot) && len(metadata.Keyslots) == 1 {
				return fmt.Errorf("cannot remove last keyslot")
			}
			break
		}
	}
	if !authValid {
		return fmt.Errorf("authentication failed: passphrase does not match any keyslot")
	}

	// Check that target keyslot exists
	slotIDStr := strconv.Itoa(targetSlot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return fmt.Errorf("keyslot %d does not exist", targetSlot)
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
	defer masterKey.Destroy()

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
	passphraseKey, err := DeriveKeyEnclave(newPassphrase, kdf, targetKeyslot.KeySize)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer passphraseKey.Destroy()

	// Apply anti-forensic split to master key
	afData, err := afSplitEnclave(masterKey, AFStripes, targetKeyslot.AF.Hash)
	if err != nil {
		return fmt.Errorf("failed to apply AF split: %w", err)
	}
	defer afData.Destroy()

	// Encrypt AF-split key material with new passphrase-derived key
	encryptedKeyMaterial, err := encryptKeyMaterialEnclave(afData, passphraseKey, DefaultCipher)
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

	return listKeyslotsFrom(metadata)
}

func listKeyslotsFrom(metadata *LUKS2Metadata) ([]KeyslotInfo, error) {
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

		// kdf and area are OPTIONAL as far as this function is concerned. A
		// luks2 keyslot always has both and the header reader enforces that,
		// but a "reencrypt" keyslot has no kdf at all, and listing keyslots is
		// an inspection operation -- the one thing an operator does when a
		// container is in a state nothing else can handle. It must report what
		// is there rather than crash on what is not.
		info := KeyslotInfo{
			ID:       id,
			Type:     ks.Type,
			KeySize:  ks.KeySize,
			Priority: priority,
		}
		if ks.KDF != nil {
			info.KDFType = ks.KDF.Type
		}
		if ks.Area != nil {
			info.Encryption = ks.Area.Encryption
		}

		slots = append(slots, info)
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

// keyslotIDsInScanOrder returns every keyslot ID in the order unlock attempts
// are made: ascending numeric ID, with any ID that does not parse with
// strconv.Atoi after those, in lexical order. That tail is not only
// non-numeric spellings -- a decimal string too large for an int lands there
// too, because Atoi reports it as an error.
//
// Ranging over the keyslot map directly leaves the order to Go's randomized map
// iteration, which costs twice. Every attempt is a full derivation -- a failed
// one costs exactly as much as a successful one, because the digest comparison
// is the only rejection point -- and the credential in use is almost always in
// the lowest-numbered slot, so a random start pays O(n/2) derivations where
// ascending order pays one. It also makes the time to open a volume differ on
// every call for reasons the caller cannot see or control.
//
// The ordering is TOTAL: every key in the map is returned exactly once. An ID
// that does not parse as a number is still returned rather than skipped,
// because dropping it would make its keyslot unreachable, and an unreachable
// keyslot is a credential that can no longer open the volume.
//
// Keyslot priority is deliberately not consulted here. No unlock path reads
// that field -- ListKeyslots reads it, but only to report it -- and honoring it
// would change WHICH keyslots are tried rather than merely the order, which is
// a different decision from this one. See #56: the values written for it are
// inverted with respect to LUKS2, so it must not be wired up as it stands.
func keyslotIDsInScanOrder(keyslots map[string]*Keyslot) []string {
	ids := make([]string, 0, len(keyslots))
	for id := range keyslots {
		ids = append(ids, id)
	}

	slices.SortFunc(ids, func(a, b string) int {
		na, errA := strconv.Atoi(a)
		nb, errB := strconv.Atoi(b)
		switch {
		case errA == nil && errB == nil:
			// Two spellings of one number ("7" and "007") parse equal. Ties
			// must break on the raw string: slices.SortFunc is not stable and
			// the input order comes from the map, so leaving them equal would
			// hand exactly this header back to the randomness the ordering
			// exists to remove.
			if c := cmp.Compare(na, nb); c != 0 {
				return c
			}
			return cmp.Compare(a, b)
		case errA == nil:
			return -1
		case errB == nil:
			return 1
		default:
			return cmp.Compare(a, b)
		}
	})

	return ids
}

// getMasterKey unlocks the volume and returns the master key HELD IN PROTECTED
// MEMORY. The caller owns the returned enclave and must Destroy it.
//
// Keyslots are tried in the order given by keyslotIDsInScanOrder; every slot is
// tried before the attempt is reported as having failed.
//
// # Failing to VERIFY and failing to TRY are different facts
//
// This used to collapse every failure into a bare "incorrect passphrase", which
// made a damaged volume indistinguishable from a wrong credential all the way
// up to VerifyRecoveryKey -- where an operator is told to discard a recovery key
// that in fact works (#72).
//
// So a keyslot that was tried and whose digest did not match is separated from
// one that could not be tried at all. If NO keyslot verified and at least one
// could not be tried, the reason it could not be tried is what comes back: the
// volume's state is the thing the caller can act on, and claiming a credential
// verdict that was never actually reached is the failure being fixed.
//
// # What this deliberately does NOT claim
//
// It does not report ErrInvalidPassphrase for a digest mismatch. Three causes
// arrive at that comparison indistinguishably -- a wrong credential, the RIGHT
// credential over damaged key material, and a semantically wrong digest -- so
// naming it after one of them would be a false statement of exactly the kind
// this change exists to remove. What a non-verifying keyslot set should be
// called is an open design question (#68), left untyped here rather than
// guessed at; ErrMasterKeyVerification says what happened without saying why.
//
// It also does not raise ErrNoKeyslots when nothing was tried at all. That is a
// separate defect with its own issue (#30) and its own semantics, and inventing
// a second answer to it here is how two answers come to disagree.
func getMasterKey(device string, passphrase []byte, metadata *LUKS2Metadata) (*enclave.MemoryEnclave, error) {
	// The first reason a keyslot could not be TRIED, kept in case nothing
	// verifies. The first rather than the last, because scan order is
	// deterministic and the lowest-numbered damaged slot is the one an operator
	// will look at first.
	var untried error

	for _, id := range keyslotIDsInScanOrder(metadata.Keyslots) {
		keyslot := metadata.Keyslots[id]
		if keyslot.Type != "luks2" {
			continue
		}

		masterKey, err := unlockKeyslot(device, passphrase, keyslot, metadata.Digests)
		if err == nil {
			return masterKey, nil
		}

		// Protected memory is FAIL-CLOSED, so this aborts rather than moving on:
		// every remaining keyslot needs the same locked pages and would fail the
		// same way, and continuing would bury an operator-fixable RLIMIT_MEMLOCK
		// condition under a credential verdict.
		if errors.Is(err, ErrProtectedMemory) {
			return nil, err
		}

		if errors.Is(err, ErrMasterKeyVerification) {
			// Tried, and did not verify. Try the next keyslot.
			continue
		}

		if untried == nil {
			untried = fmt.Errorf("keyslot %s could not be tried: %w", id, err)
		}
	}

	if untried != nil {
		return nil, untried
	}

	return nil, ErrMasterKeyVerification
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

// keyslotsAreaBounds returns the half-open [start, end) byte range of the
// container's reserved keyslots area.
//
// Both ends are READ FROM THE CONTAINER; neither is assumed. The area starts at
// twice the header area size, because the two header copies tile the front of
// the device, and it runs for config.keyslots_size bytes. Hardcoding the start
// at 0x8000 is correct only for the 16 KiB metadata area this library formats
// with -- a container with a 32 KiB area starts its keyslots at 0x10000 -- and
// it is the same "geometry as a constant" mistake that put the secondary header
// at a fixed offset.
//
// The data segment is NOT the end of this area. On a conformant container the
// data offset may sit well past it, and the gap between the two is space that
// belongs to neither: a keyslot placed there passes a segment-overlap check
// while falling outside the geometry the container declares about itself.
func keyslotsAreaBounds(hdr *LUKS2BinaryHeader, metadata *LUKS2Metadata) (int64, int64, error) {
	area, err := headerAreaSize(hdr)
	if err != nil {
		return 0, 0, err
	}
	start := 2 * int64(area)

	if metadata.Config == nil {
		return 0, 0, fmt.Errorf("%w: header has no config object, so the keyslots area is undefined",
			ErrInvalidHeader)
	}
	size, err := parseSize(metadata.Config.KeyslotsSize)
	if err != nil {
		return 0, 0, fmt.Errorf("%w: config.keyslots_size %q is not a size: %v",
			ErrInvalidHeader, metadata.Config.KeyslotsSize, err)
	}
	if size <= 0 {
		return 0, 0, fmt.Errorf("%w: config.keyslots_size %d leaves no room for any keyslot",
			ErrInvalidHeader, size)
	}

	return start, start + size, nil
}

// calculateNextKeyslotOffset calculates the offset for the next keyslot area.
//
// keyslotsStart is where the container's keyslots area begins -- see
// keyslotsAreaBounds. It is a parameter rather than a constant because it is a
// property of the container, not of this library.
func calculateNextKeyslotOffset(metadata *LUKS2Metadata, keyslotsStart int64) (int64, error) {
	maxEnd := keyslotsStart

	for _, ks := range metadata.Keyslots {
		// A keyslot with no area object is skipped rather than dereferenced.
		// Its extent is unknown, which is exactly why the new slot must not be
		// placed as though the damaged one were not there -- but the overlap
		// checks in AddKey are what refuse that, and they work off the
		// container's declared bounds rather than off this maximum.
		if ks == nil || ks.Area == nil {
			continue
		}
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

// wipeKeyslotArea securely wipes a keyslot area.
//
// It screens the keyslot itself because KillKeyslot reaches it with NO
// passphrase and therefore never passes through unlockKeyslot's check. That
// makes this the one path where a crafted keyslot's declared offset and size
// decide where zeros get written, and where a missing area object dereferences
// nil.
func wipeKeyslotArea(device string, keyslot *Keyslot) error {
	if err := validateKeyslot("", keyslot); err != nil {
		return err
	}

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

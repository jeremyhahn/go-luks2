// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"crypto/subtle"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"
)

// Unlock opens a LUKS2 volume and creates a device-mapper mapping
func Unlock(device string, passphrase []byte, name string) error {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Validate passphrase
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}

	// Check if already unlocked
	if IsUnlocked(name) {
		return fmt.Errorf("device mapper '%s' already exists - close it first with: luks close %s", name, name)
	}

	// Read header and metadata
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return err
	}

	// Try each keyslot by priority
	var masterKey []byte
	var unlocked bool

	for keyslotID, keyslot := range metadata.Keyslots {
		if keyslot.Type != "luks2" {
			continue
		}

		// Try to unlock with this keyslot
		mk, err := unlockKeyslot(device, passphrase, keyslot, metadata.Digests)
		if err != nil {
			continue // Try next keyslot
		}

		masterKey = mk
		unlocked = true
		_ = keyslotID
		break
	}

	if !unlocked {
		return fmt.Errorf("failed to unlock any keyslot: incorrect passphrase")
	}
	defer clearBytes(masterKey)

	// Get segment information
	var segment *Segment
	for _, seg := range metadata.Segments {
		if seg.Type == "crypt" {
			segment = seg
			break
		}
	}

	if segment == nil {
		return fmt.Errorf("no crypt segment found")
	}

	// Parse segment offset
	offsetBytes, err := parseSize(segment.Offset)
	if err != nil {
		return fmt.Errorf("invalid segment offset: %w", err)
	}

	// Get device size for dynamic segments
	var sizeBytes int64
	if segment.Size == "dynamic" {
		// For block devices, we need to use ioctl to get the size
		devSize, err := getBlockDeviceSize(device)
		if err != nil {
			return fmt.Errorf("failed to get device size: %w", err)
		}
		sizeBytes = devSize - offsetBytes
	} else {
		sizeBytes, err = parseSize(segment.Size)
		if err != nil {
			return fmt.Errorf("invalid segment size: %w", err)
		}
	}

	// Safe conversion of sizes to uint64
	length, err := SafeInt64ToUint64(sizeBytes)
	if err != nil {
		return fmt.Errorf("invalid segment size: %w", err)
	}
	backendOffset, err := SafeInt64ToUint64(offsetBytes)
	if err != nil {
		return fmt.Errorf("invalid segment offset: %w", err)
	}

	// Create device-mapper table
	// Note: The devmapper library expects Length and BackendOffset in BYTES
	// (it converts them to sectors internally)
	table := devmapper.CryptTable{
		Start:         0,
		Length:        length,
		BackendDevice: device,
		BackendOffset: backendOffset,
		Encryption:    segment.Encryption,
		Key:           masterKey,
		IVTweak:       parseIVTweak(segment.IVTweak),
		SectorSize:    uint64(segment.SectorSize), // #nosec G115 - sector size is validated (512 or 4096)
	}

	// Generate UUID for device-mapper
	uuid := fmt.Sprintf("CRYPT-LUKS2-%s-%s",
		strings.ReplaceAll(string(TrimRight(hdr.UUID[:], "\x00")), "-", ""),
		name)

	// Create and load the device-mapper target
	if err := devmapper.CreateAndLoad(name, uuid, 0, table); err != nil {
		return fmt.Errorf("failed to create device-mapper: %w", err)
	}

	// Ensure device node exists (may need to create it in containerized environments)
	// Non-fatal - device may still be accessible via /dev/mapper/
	_ = ensureDeviceNode(name)

	return nil
}

// TrimRight is a helper function to replace bytes.TrimRight
func TrimRight(b []byte, cutset string) []byte {
	i := len(b)
	for i > 0 {
		found := false
		for _, c := range cutset {
			if b[i-1] == byte(c) {
				found = true
				break
			}
		}
		if !found {
			break
		}
		i--
	}
	return b[:i]
}

// ensureDeviceNode creates the /dev/dm-X device node if it doesn't exist.
// This is needed in containerized environments where udev may not be running.
func ensureDeviceNode(name string) error {
	// Get device info
	info, err := devmapper.InfoByName(name)
	if err != nil {
		return err
	}

	// Extract major/minor from DevNo
	// DevNo format: (major << 8) | minor for traditional 16-bit dev_t
	// or (major << 20) | minor for 32-bit dev_t
	// Masks ensure values fit in uint32 (0xFFF = 4095, 0xFFF00 = 1048320)
	var major, minor uint32
	if info.DevNo > 0xFFFF {
		// For larger device numbers - masks guarantee values fit in uint32
		major = uint32((info.DevNo >> 8) & 0xFFF)                            // #nosec G115 - max 4095
		minor = uint32((info.DevNo & 0xFF) | ((info.DevNo >> 12) & 0xFFF00)) // #nosec G115 - max 1048575
	} else {
		// Masks guarantee values fit in uint32
		major = uint32((info.DevNo >> 8) & 0xFFF) // #nosec G115 - max 4095
		minor = uint32(info.DevNo & 0xFF)         // #nosec G115 - max 255
	}

	dmPath := fmt.Sprintf("/dev/dm-%d", minor)
	mapperPath := fmt.Sprintf("/dev/mapper/%s", name)

	// Check if device already exists
	if _, err := os.Stat(dmPath); err == nil {
		return nil
	}
	if _, err := os.Stat(mapperPath); err == nil {
		return nil
	}

	// Create the device node using mknod
	dev := unix.Mkdev(major, minor)
	// Safe conversion of dev to int (device numbers are always small enough)
	devInt, err := SafeUint64ToInt(dev)
	if err != nil {
		return fmt.Errorf("invalid device number: %w", err)
	}
	if err := unix.Mknod(dmPath, unix.S_IFBLK|0660, devInt); err != nil {
		// Try creating in /dev/mapper instead
		if err2 := unix.Mknod(mapperPath, unix.S_IFBLK|0660, devInt); err2 != nil {
			return fmt.Errorf("failed to create device node: %v, %v", err, err2)
		}
	}

	return nil
}

// Lock closes a device-mapper mapping
func Lock(name string) error {
	// Get device info before removing (to find the device node path)
	info, _ := devmapper.InfoByName(name)

	if err := devmapper.Remove(name); err != nil {
		return fmt.Errorf("failed to remove device-mapper: %w", err)
	}

	// Clean up device nodes that we may have created
	if info != nil {
		minor := info.DevNo & 0xFF
		dmPath := fmt.Sprintf("/dev/dm-%d", minor)
		_ = os.Remove(dmPath) // Ignore error - may already be gone
	}
	mapperPath := fmt.Sprintf("/dev/mapper/%s", name)
	_ = os.Remove(mapperPath) // Ignore error - may already be gone

	return nil
}

// IsUnlocked checks if a device-mapper mapping exists
func IsUnlocked(name string) bool {
	// Check dmsetup directly first - this is authoritative
	// InfoByName returns error if device doesn't exist
	_, err := devmapper.InfoByName(name)
	if err == nil {
		return true
	}

	// Also check the symlink and verify it points to a valid device
	// (symlink might be stale if udev didn't clean up properly)
	path := fmt.Sprintf("/dev/mapper/%s", name)
	if fi, err := os.Stat(path); err == nil {
		// Stat follows the symlink - if the target doesn't exist, this would fail
		// But also check if it's a valid device
		if fi.Mode()&os.ModeDevice != 0 {
			return true
		}
	}

	return false
}

// GetMappedDevicePath returns the device path to use for an unlocked volume.
// It prefers /dev/mapper/{name} (created by udev) but falls back to /dev/dm-{minor}
// for environments without udev (e.g., Docker containers).
func GetMappedDevicePath(name string) (string, error) {
	// First check the symlink (preferred, created by udev)
	symlinkPath := fmt.Sprintf("/dev/mapper/%s", name)
	if _, err := os.Stat(symlinkPath); err == nil {
		return symlinkPath, nil
	}

	// Fall back to getting dm-X device directly
	info, err := devmapper.InfoByName(name)
	if err != nil {
		return "", fmt.Errorf("device %s not found: %w", name, err)
	}

	// Extract minor number from DevNo (DevNo = major << 8 | minor for older API,
	// or use unix.Minor for proper extraction)
	minor := info.DevNo & 0xFF
	if info.DevNo > 0xFFFF {
		// Handle 64-bit devno: major is in upper 32 bits, minor in lower 32
		minor = info.DevNo & 0xFFFFFFFF
	}

	// Build the /dev/dm-{minor} path
	dmPath := fmt.Sprintf("/dev/dm-%d", minor)

	// Wait for the device file to appear (kernel creates it asynchronously)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(dmPath); err == nil {
			return dmPath, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return dmPath, nil
}

// unlockKeyslot attempts to unlock a keyslot with the given passphrase
func unlockKeyslot(device string, passphrase []byte, keyslot *Keyslot, digests map[string]*Digest) ([]byte, error) {
	// Derive key from passphrase
	passphraseKey, err := DeriveKey(passphrase, keyslot.KDF, keyslot.KeySize)
	if err != nil {
		return nil, err
	}
	defer clearBytes(passphraseKey)

	// Read encrypted key material from keyslot area
	offset, err := parseSize(keyslot.Area.Offset)
	if err != nil {
		return nil, err
	}

	size, err := parseSize(keyslot.Area.Size)
	if err != nil {
		return nil, err
	}

	f, err := os.Open(device) // #nosec G304 -- device path validated by caller
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	encryptedKeyMaterial := make([]byte, size)
	defer clearBytes(encryptedKeyMaterial)
	if _, err := f.ReadAt(encryptedKeyMaterial, offset); err != nil {
		return nil, err
	}

	// Extract cipher from area encryption (e.g., "aes-xts-plain64" -> "aes")
	cipherAlgo := strings.Split(keyslot.Area.Encryption, "-")[0]

	// Decrypt key material
	sectorSize := 512 // Default for key material
	decryptedKeyMaterial, err := decryptKeyMaterial(encryptedKeyMaterial, passphraseKey, cipherAlgo, sectorSize)
	if err != nil {
		return nil, err
	}
	defer clearBytes(decryptedKeyMaterial)

	// Merge anti-forensic split
	// Note: The keyslot area may be larger than the actual AF-split data due to alignment
	// We only need keySize * stripes bytes for AF-merge
	afSplitSize := keyslot.KeySize * keyslot.AF.Stripes
	if len(decryptedKeyMaterial) < afSplitSize {
		return nil, fmt.Errorf("decrypted data too small: got %d, need %d", len(decryptedKeyMaterial), afSplitSize)
	}
	masterKey, err := AFMerge(decryptedKeyMaterial[:afSplitSize], keyslot.AF.Stripes, keyslot.KeySize, keyslot.AF.Hash)
	if err != nil {
		return nil, err
	}

	// Verify master key using digest
	if err := verifyMasterKey(masterKey, digests); err != nil {
		clearBytes(masterKey)
		return nil, err
	}

	return masterKey, nil
}

// verifyMasterKey verifies the master key against stored digests
func verifyMasterKey(masterKey []byte, digests map[string]*Digest) error {
	// Use the first digest for verification
	for _, digest := range digests {
		kdf := &KDF{
			Type:       digest.Type,
			Hash:       digest.Hash,
			Salt:       digest.Salt,
			Iterations: &digest.Iterations,
		}

		// Derive digest from master key
		derived, err := DeriveKey(masterKey, kdf, 32) // 32 bytes digest
		if err != nil {
			return err
		}
		defer clearBytes(derived)

		// Decode expected digest
		expected, err := decodeBase64(digest.Digest)
		if err != nil {
			return err
		}
		defer clearBytes(expected)

		// Compare using constant-time comparison to prevent timing attacks
		if subtle.ConstantTimeCompare(derived, expected) == 1 {
			clearBytes(derived)
			clearBytes(expected)
			return nil // Verification successful
		}
	}

	return fmt.Errorf("master key verification failed")
}

// getBlockDeviceSize gets the size of a block device or file
func getBlockDeviceSize(device string) (int64, error) {
	f, err := os.Open(device) // #nosec G304 -- device path validated by caller
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	// Try BLKGETSIZE64 ioctl first (works for block devices)
	var size int64
	// #nosec G103 -- unsafe.Pointer required for ioctl syscall
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno == 0 {
		return size, nil
	}

	// If ioctl fails, try stat (works for regular files)
	stat, err := f.Stat()
	if err != nil {
		return 0, fmt.Errorf("failed to get device/file size: %w", err)
	}

	return stat.Size(), nil
}

// parseIVTweak parses IV tweak value
func parseIVTweak(s string) uint64 {
	val, _ := strconv.ParseUint(s, 10, 64)
	return val
}

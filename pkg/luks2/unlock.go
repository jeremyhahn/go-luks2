// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-enclave"
	"golang.org/x/sys/unix"
)

// Unlock opens a LUKS2 volume and creates a device-mapper mapping.
//
// The volume key is given to dm-crypt through the KERNEL KEYRING, never inside
// the device-mapper table, and there is no option that changes that. If the
// keyring cannot hold the key the unlock is REFUSED with an error matching
// ErrKeyringUnavailable, whose message names the cause and the fix; see
// keyring.go and KeyringUnavailableError.
//
// The condition that refusal detects -- a container started without the keyring
// syscalls -- is fixed at boot, so a long-lived consumer should call
// CheckKeyringAvailable during initialization rather than discovering it here,
// at the first unlock of a real volume.
func Unlock(device string, passphrase []byte, name string) error {
	// Validate device path
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Resolve symlink to get real device path for devmapper
	// The kernel's dm-crypt requires the actual block device path
	realDevice, err := filepath.EvalSymlinks(device)
	if err != nil {
		// If symlink resolution fails, use the original path
		realDevice = device
	}

	// Validate passphrase
	if err := ValidatePassphrase(passphrase); err != nil {
		return err
	}

	// Validate the mapping name.
	//
	// This used to be unchecked, which was survivable while the name only
	// reached fixed-width ioctl fields and a /dev path. Since #78 it also
	// contributes to the identity behind the dm-crypt keyring reference, and a
	// target specification is a space-delimited positional grammar. The
	// description is hashed before it reaches that grammar so the charset is
	// closed by construction, but the name still reaches /dev/mapper/<name>
	// and the dm UUID, and neither wants a caller's arbitrary bytes.
	if err := ValidateMappingName(name); err != nil {
		return err
	}

	// Check if already unlocked
	if IsUnlocked(name) {
		return fmt.Errorf("device mapper '%s' already exists - close it first with: luks close %s", name, name)
	}

	// Read header and metadata (use original device for reading, symlink is fine for open())
	hdr, metadata, err := ReadHeader(device)
	if err != nil {
		return err
	}

	// Keyslots are tried by getMasterKey, which is the ONE implementation of
	// that scan. This function used to carry a second copy of it -- same order,
	// same type filter, same first-success-wins -- which is how the two came to
	// report failures differently: getMasterKey now distinguishes a keyslot that
	// did not verify from one that could not be tried, and the copy here still
	// said "incorrect passphrase" for both.
	//
	// Priority is NOT consulted, by either -- see keyslotIDsInScanOrder -- so
	// nothing here should be read as a claim that LUKS2 keyslot priority is
	// honored. It is not.
	masterKey, err := getMasterKey(device, passphrase, metadata)
	if err != nil {
		return fmt.Errorf("failed to unlock any keyslot: %w", err)
	}
	defer masterKey.Destroy()

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

	// Generate UUID for device-mapper
	uuid := fmt.Sprintf("CRYPT-LUKS2-%s-%s",
		strings.ReplaceAll(string(TrimRight(hdr.UUID[:], "\x00")), "-", ""),
		name)

	// THE KEY DOES NOT GO IN THE TABLE.
	//
	// dm-crypt accepts its volume key two ways: inline in the table it is
	// handed, or as a REFERENCE into the calling task's kernel keyrings. This
	// library only ever uses the reference, and the difference is the whole of
	// residual exposure 5.
	//
	// Inline, the key is hex-encoded by devmapper.go into two immutable Go
	// strings and copied into an ioctl buffer it never clears -- three pieces
	// of unprotected, unwipeable memory inside a third-party package, holding
	// the volume key for an unbounded time after the mapping is created. By
	// reference, the bytes go from this library's enclave into the kernel
	// through add_key and are gone from userspace entirely; no string ever
	// holds them. That is what cryptsetup does, and keyring.go has the detail:
	// why the "logon" type, why the session keyring, why the goroutine is
	// pinned, why a pre-existing entry is refused rather than overwritten, and
	// why the entry is released the instant activation returns.
	//
	// There is NO FALLBACK, by owner ruling (2026-08-31): a keyring that cannot
	// hold the key fails the unlock with an error matching
	// ErrKeyringUnavailable, naming the cause and the remedy. Nothing in this
	// package assigns CryptTable.Key, so the hex encoding above is structurally
	// unreachable rather than merely unused -- which is why exposure 5 is now
	// about the kernel keyring instead.
	//
	// What is left of the borrow is the narrowest window the API permits:
	// everything derivable from the header -- the segment, the device size
	// ioctl, the UUID -- has already been computed, the key is raw for one
	// add_key syscall, and the device-node and udev-settle work that follows
	// runs after it is destroyed.
	// FROM HERE THE MAPPING IS A TRANSACTION.
	//
	// Once the target may exist, every failure below has to take it down again,
	// because the target is DECRYPTED DATA. A caller told "unlock failed" is
	// entitled to assume no plaintext device exists and will do nothing to
	// remove one; leaving it live turns a reported failure into an unowned
	// decrypted device, and in a volume manager it also wedges the rollback --
	// the backing device cannot be released while the mapping holds it open, so
	// the operator ends up with a failed attach, a live plaintext mapping and an
	// activated backing device, which is the opposite of what the error said.
	//
	// The rollback runs on the load failure too, not only after a successful
	// one. devmapper's CreateAndLoad is create-then-load-then-resume and unwinds
	// only the middle step: a failed table load is cleaned up, a failed resume
	// is not, so a CreateAndLoad error can also leave a target behind.
	//
	// Nothing keyring-shaped needs unwinding here, and that is by construction
	// rather than by omission: unlockLoadTable releases its keyring entry
	// before it returns, on every path, so no entry can outlive the call that
	// made it and neither this rollback nor Lock can forget one.
	if err := unlockLoadTable(name, uuid, realDevice, segment, masterKey, length, backendOffset); err != nil {
		return errors.Join(err, removeCreatedMapping(name, uuid))
	}

	// The kernel has the key now, so give up ours immediately rather than at
	// function exit: nothing below needs it. Destroy is idempotent, so the
	// deferred Destroy above stays correct.
	masterKey.Destroy()

	// Ensure device node exists (may need to create it in containerized
	// environments).
	//
	// Still NON-FATAL, and deliberately so: the device may be perfectly
	// reachable through /dev/mapper/<name> without this having done anything,
	// and failing an otherwise good unlock because a redundant node could not be
	// made would be worse than the problem. What it is no longer is SILENT. It
	// used to be discarded outright, which left waitForDeviceReady as the only
	// thing between a half-created mapping and the caller, and made the two
	// halves of one story unreadable: when mknod fails because the process lacks
	// CAP_MKNOD and udev is also absent, the operator saw "device not ready" and
	// no reason to suspect node creation at all. It is now carried and reported
	// alongside the readiness failure it usually explains.
	nodeErr := dm.ensureNode(name)

	// Wait for device to be ready - udev needs time to create /dev/mapper/name symlink
	if err := dm.waitReady(name); err != nil {
		readiness := fmt.Errorf("device not ready after unlock: %w", err)
		if nodeErr != nil {
			readiness = fmt.Errorf("%w (creating the device node also failed: %v)", readiness, nodeErr)
		}
		return errors.Join(readiness, removeCreatedMapping(name, uuid))
	}

	return nil
}

// TrimRight is a helper function to replace bytes.TrimRight. The cutset is
// matched byte-wise, not rune-wise: every caller trims NUL or ASCII padding
// out of a fixed-width on-disk header field, which is a byte sequence rather
// than UTF-8 text. Ranging over the cutset as runes and narrowing each to a
// byte would silently mis-match any multi-byte cutset character.
func TrimRight(b []byte, cutset string) []byte {
	i := len(b)
	for i > 0 && strings.IndexByte(cutset, b[i-1]) >= 0 {
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

	// One decoder, shared with the removal path. See decodeDevNo for what the
	// three hand-rolled variants that used to live here disagreed about.
	major, minor := decodeDevNo(info.DevNo)

	dmPath := dmNodePath(minor)
	mapperPath := mapperNodePath(name)

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

// waitForDeviceReady waits for the device-mapper device to be ready at /dev/mapper/{name}.
// If udev doesn't create the device nodes in time, it creates them manually.
func waitForDeviceReady(name string) error {
	mapperPath := mapperNodePath(name)

	// Wait up to 3 seconds for udev to create /dev/mapper/{name}
	for i := 0; i < 30; i++ {
		// Check if /dev/mapper/name exists and is a block device
		if fi, err := os.Stat(mapperPath); err == nil {
			if fi.Mode()&os.ModeDevice != 0 {
				return nil
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	// udev hasn't created the device yet - create it manually
	// Get device info to find the dm-X path
	info, err := devmapper.InfoByName(name)
	if err != nil {
		return fmt.Errorf("device %s not found in device-mapper: %w", name, err)
	}

	major, minor := decodeDevNo(info.DevNo)
	dmPath := dmNodePath(minor)

	// Wait briefly for dm-X device node to exist
	dmExists := false
	for i := 0; i < 20; i++ {
		if fi, err := os.Stat(dmPath); err == nil {
			if fi.Mode()&os.ModeDevice != 0 {
				dmExists = true
				break
			}
		}
		time.Sleep(100 * time.Millisecond)
	}

	// If dm-X doesn't exist, create it with mknod
	if !dmExists {
		dev := unix.Mkdev(major, minor)
		devInt, err := SafeUint64ToInt(dev)
		if err != nil {
			return fmt.Errorf("invalid device number: %w", err)
		}
		if err := unix.Mknod(dmPath, unix.S_IFBLK|0660, devInt); err != nil && !os.IsExist(err) {
			return fmt.Errorf("failed to create device node %s: %w", dmPath, err)
		}
	}

	// Verify dm-X exists now
	if _, err := os.Stat(dmPath); err != nil {
		return fmt.Errorf("device node %s still doesn't exist: %w", dmPath, err)
	}

	// Create /dev/mapper directory if it doesn't exist
	if err := os.MkdirAll(mapperDir(), 0750); err != nil {
		return fmt.Errorf("failed to create /dev/mapper: %w", err)
	}

	// Create symlink from /dev/mapper/{name} -> /dev/dm-{minor}
	if err := os.Symlink(dmPath, mapperPath); err != nil {
		// Check if symlink was created by udev in the meantime
		if fi, err := os.Stat(mapperPath); err == nil {
			if fi.Mode()&os.ModeDevice != 0 {
				return nil
			}
		}
		// If the symlink exists but points elsewhere, that's also OK
		if os.IsExist(err) {
			if fi, err := os.Stat(mapperPath); err == nil {
				if fi.Mode()&os.ModeDevice != 0 {
					return nil
				}
			}
		}
		return fmt.Errorf("failed to create symlink %s -> %s: %w", mapperPath, dmPath, err)
	}

	// Verify the symlink works
	if fi, err := os.Stat(mapperPath); err == nil {
		if fi.Mode()&os.ModeDevice != 0 {
			return nil
		}
	}

	return fmt.Errorf("device %s not ready after creating symlink", mapperPath)
}

// Lock closes a device-mapper mapping.
//
// There is deliberately nothing keyring-related here. The entry holding the
// volume key is released as soon as the activation ioctl returns, not kept for
// the mapping's lifetime, so by the time anything can be closed there is
// nothing left to release. See keyring.go.
func Lock(name string) error {
	// Get device info before removing (to find the device node path)
	info, _ := dm.infoByName(name)

	if err := dm.remove(name); err != nil {
		return fmt.Errorf("failed to remove device-mapper: %w", err)
	}

	// Clean up device nodes that we may have created. This is the same cleanup
	// a rolled-back unlock performs, so the two leave the same state behind.
	removeMappingNodes(name, info)

	return nil
}

// IsUnlocked checks if a device-mapper mapping exists
func IsUnlocked(name string) bool {
	// Check dmsetup directly first - this is authoritative
	// InfoByName returns error if device doesn't exist
	_, err := dm.infoByName(name)
	if err == nil {
		return true
	}

	// Also check the symlink and verify it points to a valid device
	// (symlink might be stale if udev didn't clean up properly)
	path := mapperNodePath(name)
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
	symlinkPath := mapperNodePath(name)
	if _, err := os.Stat(symlinkPath); err == nil {
		return symlinkPath, nil
	}

	// Fall back to getting dm-X device directly
	info, err := devmapper.InfoByName(name)
	if err != nil {
		return "", fmt.Errorf("device %s not found: %w", name, err)
	}

	// The same decoder as everything else. This site carried a THIRD spelling
	// -- masking the low 32 bits, which is not a minor at all -- so a large
	// device number produced a path no node has ever had.
	_, minor := decodeDevNo(info.DevNo)
	dmPath := dmNodePath(minor)

	// Wait for the device file to appear (kernel creates it asynchronously)
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(dmPath); err == nil {
			return dmPath, nil
		}
		time.Sleep(100 * time.Millisecond)
	}

	return dmPath, nil
}

// unlockLoadTable builds the dm-crypt table and loads it, with the master key
// borrowed from its enclave for exactly that call.
//
// It is a separate function so the borrow closure has nothing else in it: the
// window in which the key is raw bytes is this function body and no more. The
// key does not reach the table -- it reaches the KERNEL KEYRING, and the table
// carries only a reference to it. See keyring.go.
func unlockLoadTable(name, uuid, realDevice string, segment *Segment, masterKey *enclave.MemoryEnclave, length, backendOffset uint64) error {
	// The goroutine is pinned to its OS thread for the whole add-activate-
	// release sequence.
	//
	// This is not defensive tidiness. Linux keyrings are resolved from the
	// credentials of the TASK issuing the syscall, and joining or installing a
	// keyring diverges the calling thread's credentials from its siblings' --
	// so a key added on one OS thread is not necessarily visible to the
	// DM_TABLE_LOAD ioctl if the Go scheduler has moved the goroutine to
	// another thread in between. Without the pin this works almost always and
	// fails occasionally with ENOKEY, which is the worst possible shape for a
	// bug in an unlock path. keyring.go has the detail.
	unpin := pinToOSThread()
	defer unpin()

	// loadErr is kept separate from the borrow's own error so that a failure to
	// reach protected memory is not reported as a device-mapper failure. The two
	// send an operator to completely different places. releaseErr is separate
	// for the same reason again: a keyring entry that could not be removed is
	// neither of those things and must not be reported as either.
	var loadErr, releaseErr error

	err := borrowSecret("master key", masterKey, func(key []byte) error {
		// Note: The devmapper library expects Length and BackendOffset in BYTES
		// (it converts them to sectors internally)
		// IMPORTANT: Use realDevice (resolved symlink) for devmapper, not the original device path
		table := devmapper.CryptTable{
			Start:         0,
			Length:        length,
			BackendDevice: realDevice,
			BackendOffset: backendOffset,
			Encryption:    segment.Encryption,
			IVTweak:       parseIVTweak(segment.IVTweak),
			SectorSize:    uint64(segment.SectorSize), // #nosec G115 - sector size is validated (512 or 4096)
		}

		// Key is deliberately NOT set, here or anywhere else in this package.
		// devmapper's buildSpec takes KeyID when it is non-empty and only falls
		// back to hex.EncodeToString(Key) when it is empty, so an unassigned
		// Key is what makes the hex encoding structurally unreachable rather
		// than merely unused. If the keyring cannot hold the key, this function
		// returns and no table is loaded at all.
		keyEntry, keyringErr := addVolumeKeyToKeyring(uuid, key)
		if keyringErr != nil {
			return keyringErr
		}

		// Released before this closure returns, on the success path and on
		// every failure path including a panic -- so the entry cannot outlive
		// the activation and there is nothing for the caller's rollback to
		// clean up. release verifies the key is gone rather than trusting the
		// syscalls; see keyring.go.
		defer func() { releaseErr = keyEntry.release() }()
		table.KeyID = keyEntry.tableKeyID()

		loadErr = dm.createAndLoad(name, uuid, 0, table)
		return loadErr
	})

	// The release is checked whatever the activation did. A keyring entry left
	// holding the volume key is a custody failure in its own right, and one
	// that a successful unlock would otherwise hide completely.
	//
	// Returning it makes the caller roll the mapping back, which is the only
	// answer consistent with both contracts this function is under: reporting
	// success would leave the caller believing a custody guarantee that did not
	// hold, and reporting failure while leaving the target live would leave an
	// unowned plaintext device. Losing a working mapping is the lesser cost,
	// and release only fails if the kernel refuses -- or cannot confirm -- an
	// operation on a key this process just created.
	if err == nil {
		return releaseErr
	}
	if loadErr != nil {
		return errors.Join(fmt.Errorf("failed to create device-mapper: %w", loadErr), releaseErr)
	}
	return errors.Join(err, releaseErr)
}

// unlockKeyslot attempts to unlock a keyslot with the given passphrase and
// returns the master key HELD IN PROTECTED MEMORY.
//
// Everything derived along the way that is or reveals the master key -- the
// passphrase-derived key, the decrypted AF stripes, the merged key itself --
// lives in an enclave and is destroyed on every path out, success or failure.
// What is deliberately not enclaved is the ciphertext read off the device,
// which is already on the device; see decryptKeyMaterialEnclave.
func unlockKeyslot(device string, passphrase []byte, keyslot *Keyslot, digests map[string]*Digest) (*enclave.MemoryEnclave, error) {
	// The type is checked HERE and not only in the scan.
	//
	// getMasterKey skips anything that is not "luks2", but RemoveKey, ChangeKey
	// and KillSlot reach this function with a keyslot the caller NAMED, without
	// consulting its type. A LUKS2 "reencrypt" keyslot has no kdf object, so
	// arriving at the derivation with one dereferences nil -- a crash reachable
	// from a container that is merely mid-reencryption, not even a hostile one.
	if keyslot.Type != "luks2" {
		return nil, fmt.Errorf("%w: keyslot type %q cannot be opened; only luks2 keyslots hold a passphrase-wrapped volume key",
			ErrInvalidKeyslot, keyslot.Type)
	}

	// THE GATE. Everything below this line trusts the keyslot's declared
	// geometry: that the objects it needs exist, that its offsets and sizes
	// parse, and that its key size, stripe count and area describe an amount of
	// work worth doing.
	//
	// The header reader already applied this to every keyslot it parsed (see
	// keyslotvalidation.go); it is repeated here because this function is also
	// reachable with a keyslot a caller CONSTRUCTED rather than read. What it
	// replaced was three overlapping bounds scattered down this function --
	// an area-size check here, an overflow check in afSplitBytes there -- which
	// is the shape that let an unbounded key_size reach the KDF in the first
	// place: a bound at one call site says nothing about the call site above it.
	if err := validateKeyslot("", keyslot); err != nil {
		return nil, err
	}

	// What the KDF would COST is checked immediately before it is paid, and
	// here rather than in validateKeyslot: a keyslot with a deliberately
	// expensive KDF is still a fine template for a new one, and AddKey's
	// reference pick screens shape without needing to run anything. See
	// validateKDFCost.
	//
	// Wrapped as an unusable KEYSLOT, which is what makes the scan skip past a
	// crafted slot rather than let it deny the volume.
	if err := validateKDFCost(keyslot.KDF); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidKeyslot, err)
	}

	// Derive key from passphrase
	passphraseKey, err := DeriveKeyEnclave(passphrase, keyslot.KDF, keyslot.KeySize)
	if err != nil {
		return nil, err
	}
	defer passphraseKey.Destroy()

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

	// Merge anti-forensic split.
	//
	// The keyslot area is 4 KiB-aligned and so is usually LARGER than the
	// keySize*stripes the merge consumes. Only that much is decrypted, rounded
	// UP to a whole sector: XTS tweaks on the sector index, so decrypting a
	// whole-sector prefix yields byte-identical plaintext to decrypting the
	// area and truncating, while the locked region needed shrinks to the
	// stripes themselves. Rounding up rather than down matters -- a short final
	// sector would be zero-padded by the transform and decrypt to something
	// else entirely.
	// The gate above has established that this product does not overflow and
	// fits the area, so it is computed rather than re-checked.
	afSplitSize := keyslot.KeySize * keyslot.AF.Stripes

	sectorSize := 512 // Default for key material
	decryptLen := alignTo(int64(afSplitSize), int64(sectorSize))
	if decryptLen > size {
		// Only reachable for an area size that is not a whole number of
		// sectors, which LUKS2's 4096-byte keyslot alignment rules out for any
		// container cryptsetup or this library writes.
		//
		// It is refused rather than clamped. Clamping would send the final
		// sector through the zero-padding partial-sector path, which decrypts
		// to something other than what was written -- so the merge would fail
		// with a message about the AF material rather than about the geometry
		// that caused it, and an operator would go looking in the wrong place.
		return nil, fmt.Errorf("%w: area of %d bytes is not a whole number of %d-byte sectors and cannot hold the %d bytes of AF material this keyslot declares",
			ErrInvalidKeyslot, size, sectorSize, afSplitSize)
	}

	decryptedKeyMaterial, err := decryptKeyMaterialEnclave(
		encryptedKeyMaterial[:decryptLen], passphraseKey, cipherAlgo, sectorSize)
	if err != nil {
		return nil, err
	}
	defer decryptedKeyMaterial.Destroy()

	if decryptedKeyMaterial.Size() < afSplitSize {
		return nil, fmt.Errorf("decrypted data too small: got %d, need %d", decryptedKeyMaterial.Size(), afSplitSize)
	}

	masterKey, err := afMergeEnclave(decryptedKeyMaterial, afSplitSize, keyslot.AF.Stripes, keyslot.KeySize, keyslot.AF.Hash)
	if err != nil {
		return nil, err
	}

	// Verify master key using digest
	if err := verifyMasterKey(masterKey, digests); err != nil {
		masterKey.Destroy()
		return nil, err
	}

	return masterKey, nil
}

// verifyMasterKey verifies the master key against the stored digests.
//
// Every digest in the set is tried, and a digest that ERRORS is skipped exactly
// like a digest that mismatches. That symmetry is the fix for #58: the mismatch
// path already continued, but the derive and decode paths returned, so one
// unusable digest hid every usable one behind it. Under GODEBUG=fips140=only,
// DeriveKey refuses an argon2 digest KDF, which made whether a volume opened
// depend on Go's randomized map iteration order -- the same header opening or
// not opening from run to run.
//
// The failure returned once the set is exhausted is deliberately identical
// whether the cause was a mismatch, an unsupported KDF, a corrupt salt or a
// digest of implausible length: the caller learns that this key did not verify
// and nothing about which digest rejected it or why.
func verifyMasterKey(masterKey *enclave.MemoryEnclave, digests map[string]*Digest) error {
	for _, digest := range digests {
		kdf := &KDF{
			Type:       digest.Type,
			Hash:       digest.Hash,
			Salt:       digest.Salt,
			Iterations: &digest.Iterations,
		}

		// Decode the expected digest FIRST, because its length is what the
		// derivation has to match.
		expected, err := decodeBase64(digest.Digest)
		if err != nil {
			continue // unusable digest -- try the next one (#58)
		}

		// Derive to the length ACTUALLY STORED, not to a hardcoded 32 and not
		// to the natural length of digest.Hash.
		//
		// Deriving to the stored length is what cryptsetup does, and it is the
		// only choice that is correct in both directions. A cryptsetup-written
		// sha512 volume stores 64 bytes and needs 64 derived, which the
		// hardcoded 32 could never produce (#73). A volume written by an
		// earlier version of THIS library stores 32 bytes under a "sha512"
		// label; deriving to the hash's natural 64 would fail to verify it and
		// would render every such volume unopenable.
		//
		// Which lengths are derived to is a whitelist, not a range: the length
		// the declared hash implies, plus legacyDigestLen for those older
		// containers. See legacyDigestLen for why the carve-out is exactly one
		// value.
		wantLen, err := hashOutputLen(digest.Hash)
		if err != nil {
			clearBytes(expected)
			continue // unknown or FIPS-refused hash -- try the next (#58)
		}
		if len(expected) != wantLen && len(expected) != legacyDigestLen {
			clearBytes(expected)
			continue // length agrees with neither the hash nor the carve-out (#58)
		}

		// The digest's KDF is header-supplied too, and it is the one that is
		// easy to miss: it is not the keyslot's. An absurd cost here is skipped
		// exactly as an unusable digest is -- the symmetry #58 established --
		// rather than run, and rather than aborting a volume whose other
		// digests are fine.
		if err := validateKDFCost(kdf); err != nil {
			clearBytes(expected)
			continue
		}

		// The derivation borrows the master key in place; this package makes
		// no copy of it.
		//
		// It does leave protected memory once inside the KDF, though: pbkdf2
		// stringifies its password argument, so every digest tried here puts
		// the master key into an unwipeable Go string. See exposure 2 in
		// enclave.go. Trying N digests materializes it N times.
		derived, err := deriveKeySecret(masterKey, kdf, len(expected))
		if err != nil {
			clearBytes(expected)
			continue // e.g. non-approved KDF in FIPS mode -- try the next (#58)
		}

		// Compare using constant-time comparison to prevent timing attacks.
		// MemoryEnclave.EqualTo does exactly that, under the enclave's own read
		// lock, so the derived digest is never copied out to be compared. The
		// stored digest is a cleartext header field and is cleared anyway; the
		// derived one is destroyed on every path before the next iteration,
		// because deferring would pile up one locked region per digest and free
		// none of them until the function returned.
		matched := derived.EqualTo(expected)
		derived.Destroy()
		clearBytes(expected)
		if matched {
			return nil // Verification successful
		}
	}

	return ErrMasterKeyVerification
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

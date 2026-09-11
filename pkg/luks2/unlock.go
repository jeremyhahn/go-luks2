// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

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

	// Resolve the symlink, because the kernel's dm-crypt target is built from
	// the ACTUAL block device path -- see unlockLoadTable below, whose comment
	// says in as many words to use realDevice and not the original.
	//
	// A FAILED RESOLUTION IS A REFUSAL, NOT A FALLBACK. Owner ruling against
	// #142. This used to assign `realDevice = device` and carry on, which put
	// the exact value the downstream comment forbids into the crypt table --
	// so "I could not find the real device" became "use the symlink and hope",
	// on the unlock path, silently.
	//
	// It is silent in the SUCCESS case too, which is what made it survive:
	// the kernel resolves a symlink at table-load time anyway, so the fallback
	// usually works and tells nobody it happened. What it costs is the case it
	// was written for -- a udev re-enumeration racing the open, an EIO on an
	// intermediate component -- where the two lookups are not atomic with each
	// other and the table can be built against a path that no longer names the
	// device just validated.
	realDevice, err := filepath.EvalSymlinks(device)
	if err != nil {
		return &DeviceError{Device: device, Op: "resolve the real device path for the dm-crypt backend", Err: err}
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

	// Check if already unlocked.
	//
	// Typed since #70: the refusal was correct and untyped, so a caller could
	// not tell "that name is taken" from any other unlock failure without
	// matching on message text. It is a refusal rather than a no-op because the
	// existing target may map a DIFFERENT volume, and returning success would
	// hand the caller a plaintext device this call did not open.
	if IsUnlocked(name) {
		return fmt.Errorf("%w: the device-mapper name %q is already in use - close it first with: luks close %s",
			ErrVolumeAlreadyUnlocked, name, name)
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

	// Get segment information.
	//
	// Visited in sorted id order rather than in map order. A container being
	// reencrypted carries more than one segment, and picking whichever one Go's
	// randomized iteration yielded first made WHICH segment a volume opened
	// through a coin flip -- the same defect class as #54 and #57, on a value
	// that decides where the plaintext device is backed.
	var segment *Segment
	var segmentID string
	for _, id := range slices.Sorted(maps.Keys(metadata.Segments)) {
		if metadata.Segments[id].Type == "crypt" {
			segment = metadata.Segments[id]
			segmentID = id
			break
		}
	}

	if segment == nil {
		return fmt.Errorf("%w: the header declares no crypt segment, so there is nothing to map", ErrInvalidHeader)
	}

	// The three fields that reach the device-mapper ioctl are obtained HERE,
	// through the validator, and not read off the segment at the table. The
	// header this came from has already been through the same check at the read
	// boundary; this is how the values are converted, not a second bound. See
	// segmentvalidation.go (#40).
	params, err := cryptTableParams(segmentID, segment)
	if err != nil {
		return err
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
	if err := unlockLoadTable(name, uuid, realDevice, params, masterKey, length, backendOffset); err != nil {
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
	// Typed since #70. Closing a name nothing has opened used to surface as
	// "failed to remove device-mapper: ..." -- a device-mapper failure, which
	// sends an operator to look at device-mapper, when the actual state is that
	// there was nothing to close. Callers that close idempotently can now say so
	// with errors.Is instead of matching on text.
	if !IsUnlocked(name) {
		return fmt.Errorf("%w: no device-mapper mapping named %q exists", ErrVolumeNotUnlocked, name)
	}

	// The identity MUST be established before anything is removed. Discarding
	// this error left `info` nil, and the retry below then removed BY NAME with
	// no identity check at all -- across the full three-second budget. That is
	// the exact race the identity check exists to prevent, widened rather than
	// closed: IsUnlocked can succeed through its device-node fallback, so a nil
	// `info` is reachable in ordinary operation and not only under a transient
	// fault.
	//
	// No-such-device here is the same state IsUnlocked reports on: the mapping
	// went away between the two calls, which is the typed not-unlocked case, not
	// a device-mapper failure. Any other inspection error means the identity
	// cannot be established, and the only safe answer is to say so rather than
	// to remove something whose identity is unknown.
	// The capture is RETRIED on EBUSY like everything else on this path. Failing
	// fast here would reintroduce the very flakiness this function absorbs: the
	// identity lookup goes through the same device-mapper control path as the
	// close, so it is subject to the same transient hold, and refusing on it
	// would leave the mapping live without ever attempting the close.
	//
	// What must NOT be retried away is a lookup that keeps failing. Identity is
	// required before anything is removed -- discarding this error once left the
	// retry removing BY NAME with no identity check across the whole budget,
	// which is the race the check exists to prevent.
	var info *devmapper.DeviceInfo
	if _, err := retryWhileBusy(func() error {
		var err error
		info, err = dm.infoByName(name)
		return err
	}); err != nil {
		if isNoSuchDevice(err) {
			// The mapping went away between IsUnlocked and here: the typed
			// not-unlocked case, not a device-mapper failure.
			return fmt.Errorf("%w: no device-mapper mapping named %q exists", ErrVolumeNotUnlocked, name)
		}
		return fmt.Errorf("cannot establish the identity of mapping %q, so it will not be removed: %w", name, err)
	}

	// A close rides out a transient hold rather than failing on it. Something
	// holds a target open for a moment after the activity that preceded the
	// close -- a udev-triggered scan, in practice -- and the device frees
	// itself; dmsetup(8) ships --retry for exactly this. See
	// removeMappingWithRetry (#122).
	//
	// When the budget is spent, the answer is SPECIFIC rather than the bare
	// errno: an operator has to be able to tell "busy for an instant" from
	// "something is genuinely holding this", and after a retry exists that
	// distinction is the whole diagnostic value. Silence, or an unchanged
	// message, would make the retry a slower way to say the same thing.
	// The identity is re-confirmed before EVERY attempt, for the same reason the
	// rollback does it (#122): during a backoff another actor can remove this
	// target and create a DIFFERENT mapping under the same name, and removing
	// that one would destroy a plaintext device this caller never opened.
	// Retrying by name alone would widen a one-ioctl window into a three-second
	// one.
	//
	// If the identity changes, or the target disappears, the mapping this call
	// was asked to close is already gone: that is the goal, so it reports
	// success and does NOT remove whatever now holds the name. Node cleanup is
	// skipped in that case too -- the info captured above describes a device
	// that is no longer there, and unlinking by a stale minor is how the wrong
	// node gets removed.
	//
	// info is now guaranteed non-nil: the inspection above returns rather than
	// proceeding without an identity, so there is no name-only path left.
	replaced := false
	attempts, err := retryWhileBusy(func() error {
		current, err := dm.infoByName(name)
		if err != nil {
			if isNoSuchDevice(err) {
				replaced = true
				return nil
			}
			return err
		}
		// The dm UUID is CRYPT-LUKS2-<header uuid>-<name>: a function of
		// the VOLUME and the NAME, not of this activation. So a mapping of
		// the same volume, recreated under the same name during the
		// backoff, carries an identical UUID and the UUID alone cannot
		// tell it from ours. DevNo is the closest thing to an instance
		// handle the dm API offers here, and a recreated target is
		// normally allocated a different minor.
		//
		// This NARROWS the window rather than closing it -- minors are
		// reused eventually -- and the residue is the pre-existing race
		// that inspect-then-remove always had. Stated rather than implied,
		// because a reader who sees two fields compared will otherwise
		// assume the identity is exact.
		if current.UUID != info.UUID || current.DevNo != info.DevNo {
			replaced = true
			return nil
		}

		return dm.remove(name)
	})
	if replaced {
		return nil
	}
	if err != nil {
		if errors.Is(err, unix.EBUSY) {
			return fmt.Errorf("%w: %q was still held after %d attempts over %v (%w); find the holder with `lsof /dev/mapper/%s`, `mount | grep %s` or `dmsetup info -c %s`, or schedule the removal for when it frees with `dmsetup remove --deferred %s`",
				ErrMappingBusy, name, attempts, dmRemoveRetryBudget, err, name, name, name, name)
		}
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
func unlockLoadTable(name, uuid, realDevice string, params cryptSegmentParams, masterKey *enclave.MemoryEnclave, length, backendOffset uint64) error {
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
			// Validated at the header read boundary and converted by
			// cryptTableParams, which is why there is no conversion and no
			// gosec suppression on this line any more. The one it replaced said
			// "sector size is validated (512 or 4096)" and named a check that
			// only ever applied to the FORMAT path (#40).
			Encryption: params.encryption,
			IVTweak:    params.ivTweak,
			SectorSize: params.sectorSize,
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
// keyslotID is the key this keyslot has in the header's keyslots object, and it
// is not decoration: it selects which digests are allowed to authenticate the
// recovered key. See verifyMasterKey.
//
// Everything derived along the way that is or reveals the master key -- the
// passphrase-derived key, the decrypted AF stripes, the merged key itself --
// lives in an enclave and is destroyed on every path out, success or failure.
// What is deliberately not enclaved is the ciphertext read off the device,
// which is already on the device; see decryptKeyMaterialEnclave.
func unlockKeyslot(device string, keyslotID string, passphrase []byte, keyslot *Keyslot, digests map[string]*Digest) (*enclave.MemoryEnclave, error) {
	// THE GATE, and it is one call rather than a prefix of checks written here.
	//
	// screenKeyslot performs every rejection this function can make WITHOUT the
	// passphrase -- the type, the geometry, the KDF's cost and its parameters,
	// the area cipher, the volume key size, the anti-forensic hash, whether the
	// area can hold its own split, and whether any digest attests the slot at
	// all -- and hands back the values the rest of this function needs.
	//
	// That is the whole of #45. The removal guard has to answer the same
	// question off metadata alone, and while these checks lived here it answered
	// it with a hand-maintained copy that was wrong three times and cost the
	// volume each time. The guard now calls screenKeyslot too. Consuming what it
	// returns is what makes the coupling mechanical: this function cannot skip
	// the screen and still work, so a rejection added there is inherited by the
	// guard and cannot be forgotten. See keyslotscreen.go.
	//
	// It is applied here as well as at the header read because this function is
	// also reachable with a keyslot a caller CONSTRUCTED rather than read.
	plan, err := screenKeyslot(keyslotID, keyslot, digests)
	if err != nil {
		return nil, err
	}

	// Derive key from passphrase
	passphraseKey, err := DeriveKeyEnclave(passphrase, keyslot.KDF, keyslot.KeySize)
	if err != nil {
		return nil, err
	}
	defer passphraseKey.Destroy()

	// The area bounds come from the screen, which parsed and bounded them --
	// see screenKeyslot. openDevice is main's typed opener, adopted here so this
	// path reports a device failure the same way every other one does.
	f, err := openDevice("read the keyslot area", device, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	encryptedKeyMaterial := make([]byte, plan.areaSize)
	defer clearBytes(encryptedKeyMaterial)
	if _, err := f.ReadAt(encryptedKeyMaterial, plan.areaOffset); err != nil {
		return nil, err
	}

	// Merge anti-forensic split.
	//
	// The keyslot area is 4 KiB-aligned and so is usually LARGER than the
	// keySize*stripes the merge consumes. Only plan.decryptLen is decrypted:
	// the stripes rounded UP to a whole sector. XTS tweaks on the sector index,
	// so decrypting a whole-sector prefix yields byte-identical plaintext to
	// decrypting the area and truncating, while the locked region needed shrinks
	// to the stripes themselves. Rounding up rather than down matters -- a short
	// final sector would be zero-padded by the transform and decrypt to
	// something else entirely.
	//
	// The screen computed all of it, including that the rounded length fits the
	// area; nothing here recomputes or re-checks any of it.
	decryptedKeyMaterial, err := decryptKeyMaterialEnclave(
		encryptedKeyMaterial[:plan.decryptLen], passphraseKey, plan.cipherAlgo, keyslotSectorSize)
	if err != nil {
		return nil, err
	}
	defer decryptedKeyMaterial.Destroy()

	if decryptedKeyMaterial.Size() < plan.afSplitSize {
		return nil, fmt.Errorf("decrypted data too small: got %d, need %d", decryptedKeyMaterial.Size(), plan.afSplitSize)
	}

	masterKey, err := afMergeEnclave(decryptedKeyMaterial, plan.afSplitSize, keyslot.AF.Stripes, keyslot.KeySize, keyslot.AF.Hash)
	if err != nil {
		return nil, err
	}

	// Verify master key using the digests that authenticate THIS keyslot
	if err := verifyMasterKey(masterKey, keyslotID, digests); err != nil {
		masterKey.Destroy()
		return nil, err
	}

	return masterKey, nil
}

// verifyMasterKey verifies a key recovered from keyslot keyslotID against the
// digests the header says authenticate THAT keyslot.
//
// # Only the digests that name this keyslot are consulted
//
// A LUKS2 digest carries a "keyslots" array naming the keyslots it
// authenticates, and it is not advisory: a container can hold more than one
// volume key -- that is the ordinary state of a container mid-reencryption --
// and each digest attests one of them. Trying EVERY digest against a key
// recovered from ONE keyslot accepts that key on the strength of an attestation
// made about a different keyslot. The unlock then treats it as authenticated
// for this keyslot's segments, and KillSlot authorizes a destructive operation
// through an association the header never made.
//
// So the digest set is filtered to those whose Keyslots contains keyslotID, and
// a keyslot no digest names cannot be authenticated at all -- reported as
// ErrInvalidHeader, because a keyslot with no digest is a broken header rather
// than a failed credential. A header with no digests at all lands in the same
// place for the same reason.
//
// # Among the digests that DO name it, every one is tried
//
// A digest that ERRORS is skipped exactly like a digest that mismatches. That
// symmetry is the fix for #58: the mismatch path already continued, but the
// derive and decode paths returned, so one unusable digest hid every usable one
// behind it. Under GODEBUG=fips140=only a PBKDF2-HMAC-SHA1 digest is refused,
// which made whether a volume opened depend on Go's randomized map iteration
// order -- the same header opening or not opening from run to run.
//
// The failure returned once the set is exhausted is deliberately identical
// whether the cause was a mismatch, an unsupported KDF, a corrupt salt or a
// digest of implausible length: the caller learns that this key did not verify
// and nothing about which digest rejected it or why.
func verifyMasterKey(masterKey *enclave.MemoryEnclave, keyslotID string, digests map[string]*Digest) error {
	// applicable counts the digests that ATTEST this keyslot; evaluated counts
	// the ones that got as far as a comparison. They differ by exactly the
	// digests that were unusable, and the difference is what separates a header
	// fault from a credential verdict at the bottom of this function.
	applicable := 0
	evaluated := 0

	for _, digest := range digests {
		// The association is checked BEFORE any derivation, so a digest that
		// does not attest this keyslot costs nothing and cannot influence the
		// outcome by any route.
		if !digestCovers(digest, keyslotID) {
			continue
		}
		applicable++

		// EVERY pre-derivation check lives in screenDigest, which the removal
		// guard also consumes -- see keyslotHasUsableDigest. This function used
		// to carry them inline, and the guard therefore had no way to ask the
		// question they answer: it settled for "is a digest ASSOCIATED with this
		// keyslot", counted a keyslot whose only digest could never be
		// evaluated, and authorized destroying the one that worked.
		//
		// It is consumed rather than repeated: `expected` and `kdf` are values
		// this loop cannot obtain any other way, so the screen cannot be skipped
		// and a check added to it cannot fail to reach the guard.
		//
		// Deriving to the length ACTUALLY STORED, which screenDigest establishes,
		// is what cryptsetup does and is the only choice correct in both
		// directions. A cryptsetup-written sha512 volume stores 64 bytes and
		// needs 64 derived, which a hardcoded 32 could never produce (#73). A
		// volume written by an earlier version of THIS library stores 32 bytes
		// under a "sha512" label; deriving to the hash's natural 64 would render
		// every such volume unopenable.
		//
		// A digest that fails any of it is SKIPPED, not fatal -- the symmetry
		// #58 established -- so one unusable digest cannot hide a usable one
		// behind it.
		expected, kdf, err := screenDigest(digest)
		if err != nil {
			clearBytes(expected)
			continue // unusable digest -- try the next one (#58)
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
		// A comparison is about to run, which is what makes this digest
		// EVALUATED rather than merely applicable. Counted whether it matches
		// or not.
		evaluated++
		matched := derived.EqualTo(expected)
		derived.Destroy()
		clearBytes(expected)
		if matched {
			return nil // Verification successful
		}
	}

	// No digest in the header attests this keyslot. That is a header defect, not
	// a credential verdict, and it must not be reported as one: an operator told
	// their passphrase failed would go looking at the passphrase, while the
	// actual state is that the container declares a keyslot nothing can verify.
	if applicable == 0 {
		return unverifiableKeyslotError(keyslotID, applicable)
	}

	// Digests attest this keyslot and NOT ONE OF THEM COULD BE EVALUATED, so no
	// comparison ever ran. That is a header fault, and reporting it as a
	// verification verdict says a key was judged when nothing judged it (#41).
	//
	// # Why this case may be distinguished when the ones above it may not
	//
	// Every other exit from this function folds into ErrMasterKeyVerification
	// on purpose, and that must not be "tidied up" into per-cause errors. The
	// reason is a real attacker: someone holding the device can craft a header,
	// and an error distinguishing "digest 2 uses a KDF I refuse" from "digest 2
	// did not match" tells them WHICH keyslot to work on and how this
	// implementation reads the header. Any error derived from the OUTCOME OF A
	// COMPARISON carries that information, so all of them say one thing.
	//
	// This branch is the one place where no comparison happened. evaluated == 0
	// means every applicable digest fell out before EqualTo was reached, so
	// there is no comparison outcome in existence to leak, and the statement
	// being made is about the SHAPE OF THE HEADER -- which the attacker wrote,
	// and which anyone holding the device can read in cleartext. It leaks
	// nothing they do not already have.
	//
	// That is also why it stops here. The message names the keyslot and the
	// count and NOT the cause, even though the causes are header facts too:
	// naming them here would make naming them in the mixed case look like the
	// obvious next step, and in the mixed case a comparison DID run. The
	// boundary is easier to hold at "did a comparison happen" than at a
	// per-field judgement of what each cause reveals.
	//
	// The applicable == 0 branch above is the same distinction already being
	// drawn for the case where the header names no digest at all; this extends
	// it to the case where it names digests that cannot be used.
	if evaluated == 0 {
		return unverifiableKeyslotError(keyslotID, applicable)
	}

	return ErrMasterKeyVerification
}

// getBlockDeviceSize gets the size of a block device or file.
//
// The measurement itself is deviceSizeFromFile, shared with the keyslot-area
// bound in keyslotscreen.go. It used to be written out twice-over -- once here
// for the data segment and, in effect, once there as a bare Stat -- and the two
// did not agree: this one asked the kernel and that one did not, so the guard
// deciding whether a keyslot lies inside the device was blind on exactly the
// devices this package exists for.
func getBlockDeviceSize(device string) (int64, error) {
	f, err := openDevice("read the device size", device, os.O_RDONLY)
	if err != nil {
		return 0, err
	}
	defer func() { _ = f.Close() }()

	return deviceSizeFromFile(f)
}

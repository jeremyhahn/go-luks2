// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/anatol/devmapper.go"
	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-luks2/internal/af"
	"github.com/jeremyhahn/go-luks2/internal/clock"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/secret"
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
	return unlockVolume(device, name,
		func() error { return validateExistingCredential(passphrase) },
		func(f *os.File, _ string, metadata *LUKS2Metadata) (*enclave.MemoryEnclave, func(), error) {
			// Only keyslots bound to the data segment are tried, and only
			// against the digests that bind it: getVolumeKey, the scan every
			// operation that needs the VOLUME key shares. A LUKS2 header can
			// carry UNBOUND keys beside the volume key, and a passphrase that
			// opened only one of those used to have its key handed to dm-crypt:
			// the mapping succeeded and every byte read through it was garbage
			// (#250, C1). The keyslot areas are read through f, the descriptor
			// whose header was read (C6).
			//
			// Priority is NOT consulted -- see keyslotIDsInScanOrder -- so
			// nothing here should be read as a claim that LUKS2 keyslot priority
			// is honored. It is not.
			masterKey, _, err := getVolumeKey(f, device, passphrase, metadata)
			if err != nil {
				return nil, nil, &UnlockError{Op: "unlock any keyslot", Err: err}
			}
			// The derived key is THIS package's, so releasing it destroys it,
			// through the one place this package handles a release report.
			return masterKey, func() { custody.Release(masterKey) }, nil
		})
}

// UnlockWithVolumeKey opens a LUKS2 volume with a volume key the caller already
// holds, and creates a device-mapper mapping exactly as Unlock does.
//
// It is the seam for a key that never was a passphrase -- one unsealed by
// hardware, or returned by a key service, in a layer above this one (#79). Where
// the key came from is not this package's business and nothing here asks: it
// receives a key in protected memory and uses it. There is no hardware code in
// this package, and there is no policy about key sources.
//
// # What it skips, and what it does not
//
// It skips the KEYSLOTS: no keyslot is scanned, no passphrase is derived, and
// the keyslot KDF never runs. That is the whole point -- the derivation exists
// only because a credential started as a human secret, and this one did not.
//
// It does NOT skip the header or the key check. The header is read and
// validated by the same ReadHeader every path uses; the mapping name, the
// in-use check, the segment validation, the keyring transport and the rollback
// are the same code as Unlock's. And the key must be ATTESTED by a digest the
// header assigns to the crypt segment being mapped -- which is what cryptsetup
// checks when it activates by volume key. Without that, a wrong key would map
// garbage as the plaintext device and the first mkfs on it would destroy the
// volume. A key the header does not attest is refused as
// ErrMasterKeyVerification, the same verdict a passphrase recovering the wrong
// key gets.
//
// That check derives from the volume key through the DIGEST's PBKDF2, so
// residual exposure 2 in internal/secret still applies to this path on its digest
// leg, once per digest tried. What this path removes is the keyslot leg: the
// passphrase derivation and everything downstream of it.
//
// # Custody
//
// volumeKey is the CALLER's. It is borrowed for the digest check and for the
// one add_key syscall that hands it to the kernel keyring, and it is never
// copied out, retained or destroyed here; the caller destroys it when it is
// done with it. A nil or destroyed enclave, or one no keyslot of this package
// could hold, is refused with ErrInvalidVolumeKey before the device is read.
//
// Keyslot policy is untouched. This call reads a container; it does not create
// or remove keyslots, so ErrLastKeyslot and the guards behind it mean exactly
// what they meant before.
func UnlockWithVolumeKey(device string, volumeKey *enclave.MemoryEnclave, name string) error {
	return unlockVolume(device, name,
		func() error { return validateVolumeKey(volumeKey) },
		func(_ *os.File, segmentID string, metadata *LUKS2Metadata) (*enclave.MemoryEnclave, func(), error) {
			if err := verifyVolumeKeyForSegment(volumeKey, segmentID, metadata); err != nil {
				return nil, nil, &UnlockError{Op: "open the volume with the supplied volume key", Err: err}
			}
			// The caller's enclave: released by the caller, never here.
			return volumeKey, func() {}, nil
		})
}

// validateVolumeKey rejects a volume key that cannot be one, before the device
// is read. It checks the SHAPE only; whether the key opens this volume is the
// digest's question, answered by verifyVolumeKeyForSegment.
func validateVolumeKey(volumeKey *enclave.MemoryEnclave) error {
	if volumeKey == nil {
		return &UnlockError{Op: "check the volume key", Err: ErrInvalidVolumeKey, Detail: "no enclave was given"}
	}
	if !volumeKey.IsAlive() {
		return &UnlockError{Op: "check the volume key", Err: ErrInvalidVolumeKey, Detail: "the enclave has been destroyed"}
	}
	if size := volumeKey.Size(); size <= 0 || size > MaxKeyslotKeySize {
		return &UnlockError{Op: "check the volume key", Err: ErrInvalidVolumeKey,
			Detail: fmt.Sprintf("a %d-byte key is outside the 1..%d bytes this package supports", size, MaxKeyslotKeySize)}
	}
	return nil
}

// unlockVolume is the one unlock path. Unlock and UnlockWithVolumeKey differ in
// exactly two places -- how the credential is validated and where the volume
// key comes from -- and those are the two functions they pass. Everything else,
// every validation and the whole mapping transaction, is this body, so the two
// entry points cannot drift in what they check.
//
// volumeKey is called once the header has been read and validated and the
// segment to map has been chosen. It receives the pinned descriptor to read
// keyslots through, the segment id and the metadata, and
// returns the key and a release function, which destroys a key this package
// derived and does nothing to a key the caller owns.
func unlockVolume(device, name string, validateCredential func() error,
	volumeKey func(f *os.File, segmentID string, metadata *LUKS2Metadata) (*enclave.MemoryEnclave, func(), error)) error {
	if err := ValidateDevicePath(device); err != nil {
		return err
	}

	// Validate the credential: the passphrase, or the shape of a supplied key.
	if err := validateCredential(); err != nil {
		return err
	}

	// Validate the mapping name. It reaches the dm ioctl, /dev/mapper/<name>,
	// the dm UUID and the identity behind the keyring reference; see
	// ValidateMappingName.
	if err := ValidateMappingName(name); err != nil {
		return err
	}

	// An early, cheap refusal before any key derivation. It is NOT what keeps
	// two unlocks of one name apart -- the create ioctl is, see unlockLoadTable
	// -- because this check and the create are not atomic.
	if IsUnlocked(name) {
		return &UnlockError{Op: "unlock", Err: ErrVolumeAlreadyUnlocked,
			Detail: fmt.Sprintf("the device-mapper name %q is already in use - close it first with: luks2 close %s", name, name)}
	}

	// THE DEVICE IS OPENED ONCE, and that descriptor is the device from here on
	// (#250, C6). The header, the size and the keyslot areas are read through
	// it, and the dm-crypt table names the device by the major:minor fstat
	// reports for it rather than by a path. This used to resolve the path four
	// separate times -- validation, EvalSymlinks, the header read and the size
	// probe -- and to hand the kernel a PATH, so a udev re-enumeration or a
	// replaced symlink between any two of them could map a device other than
	// the one whose header was read. The descriptor is held until the table is
	// loaded, so the device cannot be released and its number reused under it.
	f, err := openDevice("open the device to unlock", device, os.O_RDONLY)
	if err != nil {
		return err
	}
	defer func() { _ = f.Close() }()

	backingDevNo, err := blockDeviceOf(f)
	if err != nil {
		return &DeviceError{Device: device, Op: "identify the device to unlock", Err: err}
	}

	// THE METADATA IS READ UNDER CRYPTSETUP'S READ LOCK, from the header to
	// the last keyslot area the scan reads, and released before anything
	// touches device-mapper -- the step that needs no metadata, which is where
	// cryptsetup releases it too. A cryptsetup command rewriting this header
	// holds that lock exclusively, so the read waits for the write to finish
	// rather than parsing a header mid-rewrite or pairing it with keyslot
	// areas from another state. Shared, so other readers are not delayed.
	//
	// cryptsetup itself drops the lock between the header read and each
	// keyslot read and derives the key unlocked; it is held across the scan
	// here so the keyslot areas read are the ones the header that was read
	// describes. A writer waits at most one scan.
	readLock, err := acquireMetadataReadLock(f, device, backingDevNo, metadataReadLockWait, unlockClock)
	if err != nil {
		return &UnlockError{Op: "wait for the metadata", Err: err}
	}
	defer readLock.release()

	hdr, metadata, err := readUnlockHeader(f, LUKS2PrimaryHeaderOffset)
	if err != nil {
		return err
	}

	// A container that declares a mandatory requirement this package does not
	// implement is refused for ACTIVATION too, not only for writes (#250, C2).
	// The case that matters is an interrupted `cryptsetup reencrypt`, which
	// sets online-reencrypt-v2: the data is then partly under the new key and
	// partly under the old one, split across several segments, and mapping any
	// one segment with any one key returns garbage for the rest. Reads stay
	// allowed (ReadHeader), so an operator can still see the state.
	if err := metadata.CheckRequirementsImplemented(); err != nil {
		return &UnlockError{Op: "activate the volume", Err: err,
			Detail: "the container must be finished or recovered with the tool that set the requirement (for an interrupted reencryption: cryptsetup reencrypt --resume-only) before it can be activated"}
	}

	segmentID, segment, err := activationSegment(metadata)
	if err != nil {
		return err
	}

	masterKey, release, err := volumeKey(f, segmentID, metadata)
	if err != nil {
		return err
	}
	defer release()

	// Every metadata read is done: the rest is the passphrase-independent
	// device-mapper work, and nothing below reads the header or a keyslot.
	readLock.release()

	// The three fields that reach the device-mapper ioctl are obtained HERE,
	// through the validator, and not read off the segment at the table. The
	// header this came from has already been through the same check at the read
	// boundary; this is how the values are converted, not a second bound. See
	// segmentvalidation.go (#40).
	params, err := cryptTableParams(metadata, segmentID, segment)
	if err != nil {
		return err
	}

	offsetBytes, err := parseSize(segment.Offset)
	if err != nil {
		return &UnlockError{Op: "invalid segment offset", Err: err}
	}

	// The size of a dynamic segment comes from the pinned descriptor too.
	var sizeBytes int64
	if segment.Size == "dynamic" {
		devSize, err := deviceSizeFromFile(f)
		if err != nil {
			return &UnlockError{Op: "failed to get device size", Err: err}
		}
		sizeBytes = devSize - offsetBytes
	} else {
		sizeBytes, err = parseSize(segment.Size)
		if err != nil {
			return &UnlockError{Op: "invalid segment size", Err: err}
		}
	}

	length, err := SafeInt64ToUint64(sizeBytes)
	if err != nil {
		return &UnlockError{Op: "invalid segment size", Err: err}
	}
	backendOffset, err := SafeInt64ToUint64(offsetBytes)
	if err != nil {
		return &UnlockError{Op: "invalid segment offset", Err: err}
	}

	uuid := mappingUUID(hdr, name)

	backendMajor, backendMinor := decodeDevNo(backingDevNo)
	backend := strconv.FormatUint(uint64(backendMajor), 10) + ":" + strconv.FormatUint(uint64(backendMinor), 10)

	// THE KEY DOES NOT GO IN THE TABLE.
	//
	// dm-crypt accepts its volume key two ways: inline in the table it is
	// handed, or as a REFERENCE into the calling task's kernel keyrings. This
	// library only ever uses the reference, and the difference is the whole of
	// residual exposure 5. keyring.go has the detail: why the "logon" type, why
	// the session keyring, why the work runs on a thread that is then
	// discarded, why a pre-existing entry is refused rather than overwritten,
	// and why the entry is released the instant activation returns.
	//
	// There is NO FALLBACK, by owner ruling (2026-08-31): a keyring that cannot
	// hold the key fails the unlock with an error matching
	// ErrKeyringUnavailable. Nothing in this package assigns CryptTable.Key.
	//
	// FROM THE CREATE ON, THE MAPPING IS A TRANSACTION.
	//
	// Once this call's target exists, every failure below has to take it down
	// again, because the target is DECRYPTED DATA. A caller told "unlock
	// failed" is entitled to assume no plaintext device exists.
	//
	// But ONLY once this call's target exists. A create that failed because
	// the name is taken created nothing, and the target under that name belongs
	// to whoever won: rolling back there removed the WINNER's live mapping
	// whenever two unlocks raced for one name (#250, C4). So the rollback runs
	// only when unlockLoadTable reports that its own create succeeded, and it
	// is pinned to the device number that create returned.
	devNo, created, err := unlockLoadTable(name, uuid, backend, params, masterKey, length, backendOffset)
	if err != nil {
		if !created {
			return err
		}
		return errors.Join(err, removeCreatedMapping(name, uuid, devNo))
	}

	// The kernel has the key now, so give up ours immediately rather than at
	// function exit: nothing below needs it. Destroy is idempotent, so the
	// deferred release above stays correct. A caller-owned key is not ours to
	// give up, and its release does nothing.
	release()

	ours := &devmapper.DeviceInfo{Name: name, UUID: uuid, DevNo: devNo}

	// Ensure /dev/dm-N names this device (containers without udev need it).
	// Still NON-FATAL on its own -- the device may be reachable through
	// /dev/mapper/<name> without it -- but carried and reported alongside the
	// readiness failure it usually explains.
	nodeErr := dm.ensureNode(name, ours)

	// Wait until /dev/mapper/<name> is verifiably THIS device.
	if err := dm.waitReady(name, ours); err != nil {
		readiness := &UnlockError{Op: "device not ready after unlock", Err: err}
		if nodeErr != nil {
			readiness.Detail = fmt.Sprintf("creating the device node also failed: %v", nodeErr)
		}
		return errors.Join(readiness, removeCreatedMapping(name, uuid, devNo))
	}

	return nil
}

// dmUUIDMaxLength is the longest dm UUID the kernel stores: DM_UUID_LEN (129)
// less its terminating NUL.
const dmUUIDMaxLength = 128

// mappingUUID is the dm UUID of the mapping name of the volume hdr describes:
// "CRYPT-LUKS2-<header uuid without dashes>-<name>", cryptsetup's form, cut to
// what the kernel stores.
//
// It is cut HERE, once, because the kernel cuts it anyway and every later
// identity check compares against what the kernel holds. A 127-byte name is
// valid, and with the header UUID it made a 172-byte string; the create ioctl
// stored the first 128 bytes, the confirmation and the rollback compared the
// whole string, and an unlock under a long name failed and left its target
// behind as "not ours" (#250). The header UUID is cut at its first NUL for the
// same reason: the kernel reads the field as a C string. cryptsetup truncates
// to the same length.
//
// Two long names that agree in their first bytes then share a UUID. The kernel
// refuses the second create, and the rollback is pinned to the device number
// as well, so a shared UUID cannot make one activation remove the other.
func mappingUUID(hdr *LUKS2BinaryHeader, name string) string {
	headerUUID := hdr.UUID[:]
	if i := bytes.IndexByte(headerUUID, 0); i >= 0 {
		headerUUID = headerUUID[:i]
	}
	uuid := "CRYPT-LUKS2-" + strings.ReplaceAll(string(headerUUID), "-", "") + "-" + name
	if len(uuid) > dmUUIDMaxLength {
		uuid = uuid[:dmUUIDMaxLength]
	}
	return uuid
}

// unlockClock is the clock the activation's metadata lock waits on. A
// variable so the unit tests can make a contended lock time out without
// spending the wait; nothing else changes it.
var unlockClock clock.Clock = clock.System{}

// readUnlockHeader is how the activation reads the header, under its read
// lock. A variable so a test can see WHICH header the activation read -- the
// one a concurrent writer left, or the one it was replacing -- which no
// result of Unlock reveals. Same idiom as blockDeviceOf.
var readUnlockHeader = readHeaderCopyFrom

// blockDeviceOf reports the device number of the block device f is open on,
// and refuses anything else: dm-crypt maps a block device, so a regular file
// has to be attached to a loop device first. A seam so the unit tests, which
// cannot create block devices, can map a regular-file image through the fake
// device mapper.
var blockDeviceOf = func(f *os.File) (uint64, error) {
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return 0, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFBLK {
		return 0, ErrNotBlockDevice
	}
	return uint64(st.Rdev), nil //nolint:unconvert // Rdev is not uint64 on every GOARCH
}

// activationSegment returns the one segment a mapping is built from.
//
// A header activates only when it declares EXACTLY ONE segment and that
// segment is a crypt segment. It used to take the first crypt segment in
// sorted id order whatever else the header declared, and a container left
// mid-reencryption declares five: the first is the part already under the NEW
// key, sized to the progress so far, so mapping it with the old key -- which is
// what the keyslot scan found first -- produced garbage over a truncated
// device (#250, C2). Such a container is normally refused earlier by its
// requirements flag; this refuses any other multi-segment header outright
// rather than guessing which part to map.
//
// It is one function because two things must agree on the answer: the mapping,
// and the digest the key is verified against. A key attested for one segment
// and mapped over another would be exactly the wrong-key failure that
// verification exists to prevent.
func activationSegment(metadata *LUKS2Metadata) (string, *Segment, error) {
	if len(metadata.Segments) != 1 {
		return "", nil, &UnlockError{Op: "select the segment to activate", Err: ErrUnsupportedSegmentLayout,
			Detail: fmt.Sprintf("the header declares %d segments; activation maps exactly one crypt segment", len(metadata.Segments))}
	}
	for id, segment := range metadata.Segments {
		if segment == nil || segment.Type != "crypt" {
			continue
		}
		// A segment with an integrity member sits on dm-integrity: its
		// sectors interleave with integrity tags and a journal, and its
		// volume key is the cipher key and the integrity key together.
		// Mapping dm-crypt straight over the device, which is all this
		// package does, reads garbage, and every write through the mapping
		// destroys the tags cryptsetup would check. It is refused before any
		// key is derived; the container's keyslots stay manageable.
		if segment.HasIntegrity() {
			return "", nil, &UnlockError{Op: "select the segment to activate", Err: ErrUnsupportedSegmentLayout,
				Detail: segmentLabel(id) + " is authenticated by dm-integrity (cryptsetup --integrity), which this package does not implement; open it with cryptsetup"}
		}
		return id, segment, nil
	}
	return "", nil, &UnlockError{Op: "select the segment to activate", Err: ErrInvalidHeader,
		Detail: "the header declares no crypt segment, so there is nothing to map"}
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

// Lock closes a device-mapper mapping.
//
// There is deliberately nothing keyring-related here. The entry holding the
// volume key is released as soon as the activation ioctl returns, not kept for
// the mapping's lifetime, so by the time anything can be closed there is
// nothing left to release. See keyring.go.
func Lock(name string) error {
	// The name is validated before it reaches anything. dm's own lookup would
	// refuse most bad names, but the node cleanup below builds
	// /dev/mapper/<name>, and "../sdb" there is /dev/sdb (#250, C3).
	if err := ValidateMappingName(name); err != nil {
		return err
	}

	// The identity MUST be established before anything is removed, and
	// device-mapper is the only authority on it: there is no separate
	// "is it unlocked" pre-check any more, because the one that was here could
	// answer yes from a stale /dev/mapper node alone (#250, C5).
	//
	// No-such-device is the typed not-unlocked case, not a device-mapper
	// failure. Any other inspection error means the identity cannot be
	// established, and the only safe answer is to say so rather than to remove
	// something whose identity is unknown.
	//
	// The capture is RETRIED on EBUSY like everything else on this path: the
	// lookup goes through the same device-mapper control path as the close, so
	// it is subject to the same transient hold.
	var info *devmapper.DeviceInfo
	if _, err := retryWhileBusy(func() error {
		var err error
		info, err = dm.infoByName(name)
		return err
	}); err != nil {
		if isNoSuchDevice(err) {
			return &errs.Error{
				Kind:   ErrVolumeNotUnlocked,
				Detail: fmt.Sprintf("no device-mapper mapping named %q exists", name),
			}
		}
		return &errs.Error{
			Detail: fmt.Sprintf("cannot establish the identity of mapping %q, so it will not be removed", name),
			Err:    err,
		}
	}

	// A close rides out a transient hold rather than failing on it (#122).
	//
	// The identity is re-confirmed before EVERY attempt, for the same reason the
	// rollback does it: during a backoff another actor can remove this target
	// and create a DIFFERENT mapping under the same name, and removing that one
	// would destroy a plaintext device this caller never opened.
	//
	// If the identity changes, or the target disappears, the mapping this call
	// was asked to close is already gone: that is the goal, so it reports
	// success and does NOT remove whatever now holds the name. Node cleanup is
	// skipped in that case too.
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
		// The dm UUID is a function of the VOLUME and the NAME, not of this
		// activation, so DevNo is compared as well. This NARROWS the window
		// rather than closing it -- minors are reused eventually -- and the
		// residue is the race that inspect-then-remove-by-name always has.
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
			return &errs.Error{
				Kind: ErrMappingBusy,
				Detail: fmt.Sprintf("%q was still held after %d attempts over %v; find the holder with `lsof /dev/mapper/%s`, `mount | grep %s` or `dmsetup info -c %s`, or schedule the removal for when it frees with `dmsetup remove --deferred %s`",
					name, attempts, dmRemoveRetryBudget, name, name, name, name),
				Err: err,
			}
		}
		return &errs.Error{Detail: "failed to remove device-mapper", Err: err}
	}

	// Clean up device nodes that we may have created. This is the same cleanup
	// a rolled-back unlock performs, so the two leave the same state behind.
	removeMappingNodes(name, info)

	return nil
}

// IsUnlocked reports whether a device-mapper mapping named name exists.
//
// device-mapper is the only authority. This used to fall back to stat'ing
// /dev/mapper/<name> when the dm lookup failed, so a stale node -- or, before
// names were validated here, "../sdb", which is /dev/sdb -- answered "unlocked"
// for a mapping that does not exist (#250, C3 and C5). An invalid name is never
// unlocked, and a lookup that fails for any reason is not evidence that a
// mapping exists.
func IsUnlocked(name string) bool {
	if ValidateMappingName(name) != nil {
		return false
	}
	_, err := dm.infoByName(name)
	return err == nil
}

// GetMappedDevicePath returns the device node of an unlocked volume:
// /dev/mapper/<name> when it names the mapping, otherwise /dev/dm-<minor>.
//
// A node is returned only when its rdev equals the device number
// device-mapper reports for the mapping; see mappedDevicePath. A name that is
// not a valid mapping name is refused with ErrInvalidMappingName, a name with
// no mapping with ErrVolumeNotUnlocked, and a mapping whose nodes do not carry
// its device number -- a stale or planted /dev/mapper entry -- with
// ErrDeviceNodeUnverified, after waiting for udev for the same 5 seconds this
// always waited.
func GetMappedDevicePath(name string) (string, error) {
	path, _, err := mappedDevicePath(name)
	return path, err
}

// unlockLoadTable runs the whole activation -- create, keyring add, load,
// resume, keyring release -- with the master key borrowed from its enclave for
// the keyring add and the load, and reports the device number of the target it
// created and whether it created one at all.
//
// created is the line the caller's rollback is drawn on. It is false when the
// call failed before its own create succeeded, which is the case the rollback
// must NOT touch: a create refused because the name is taken leaves the name
// to its owner (#250, C4).
//
// THE CREATE COMES FIRST, before the key is borrowed or the keyring touched.
// DM_DEV_CREATE is atomic kernel-wide: of two unlocks racing for one name,
// exactly one gets past it, so only that one ever adds the volume key under
// the description both would use. With the keyring step first, the loser's
// add_key could UPDATE the winner's entry in place and its release then
// revoke the key the winner's table load was about to resolve, failing both.
// The empty target a later failure leaves behind holds no key and no table;
// the caller's rollback removes it.
//
// It runs on a thread of its own that is discarded afterwards. Linux keyrings
// are resolved from the credentials of the TASK issuing the syscall, so the
// add and the DM_TABLE_LOAD that resolves the reference must run on one OS
// thread; and resolving the session keyring can INSTALL one into that thread's
// credentials, which must not then go back to the Go scheduler for unrelated
// goroutines to inherit (#250, C9). See runOnDiscardedThread.
func unlockLoadTable(name, uuid, backend string, params cryptSegmentParams, masterKey *enclave.MemoryEnclave,
	length, backendOffset uint64) (devNo uint64, created bool, err error) {
	err = runOnDiscardedThread(func() error {
		var createErr error
		devNo, createErr = dm.create(name, uuid)
		if createErr != nil {
			if errors.Is(createErr, unix.EBUSY) {
				// The kernel's answer for a name or UUID already in use:
				// another activation got there first, and its mapping is its
				// own.
				return &UnlockError{Op: "unlock", Err: ErrVolumeAlreadyUnlocked,
					Detail: fmt.Sprintf("the device-mapper name %q was taken by another activation (%v) - close it first with: luks2 close %s", name, createErr, name)}
			}
			return &errs.Error{Detail: "failed to create device-mapper", Err: createErr}
		}
		created = true

		// loadErr is kept separate from the borrow's own error so that a failure
		// to reach protected memory is not reported as a device-mapper failure.
		// releaseErr is separate for the same reason again: a keyring entry that
		// could not be removed is neither of those things.
		var loadErr, releaseErr error

		borrowErr := secret.Borrow("master key", masterKey, func(key []byte) error {
			// Note: The devmapper library expects Length and BackendOffset in
			// BYTES (it converts them to sectors internally).
			table := devmapper.CryptTable{
				Start:  0,
				Length: length,
				// major:minor of the descriptor Unlock pinned, never a path.
				BackendDevice: backend,
				BackendOffset: backendOffset,
				// Validated at the header read boundary and converted by
				// cryptTableParams (#40).
				Encryption: params.Encryption,
				IVTweak:    params.IVTweak,
				SectorSize: params.SectorSize,
				// The header's persistent performance flags, as cryptsetup
				// passes them; see persistentCryptFlags.
				Flags: params.Flags,
			}

			// Key is deliberately NOT set, here or anywhere else in this
			// package. devmapper's buildSpec takes KeyID when it is non-empty
			// and only falls back to hex.EncodeToString(Key) when it is empty,
			// so an unassigned Key is what makes the hex encoding structurally
			// unreachable rather than merely unused.
			keyEntry, keyringErr := addVolumeKeyToKeyring(uuid, key)
			if keyringErr != nil {
				return keyringErr
			}

			// Released before this closure returns, on every path including a
			// panic, so the entry cannot outlive the activation.
			defer func() { releaseErr = keyEntry.release() }()
			table.KeyID = keyEntry.tableKeyID()

			loadErr = activateCreated(name, uuid, devNo, table)
			return loadErr
		})

		// The release is checked whatever the activation did. A keyring entry
		// left holding the volume key is a custody failure in its own right,
		// and one that a successful unlock would otherwise hide completely --
		// so it fails the unlock, and the caller rolls the mapping back.
		if borrowErr == nil {
			return releaseErr
		}
		if loadErr != nil {
			return errors.Join(&errs.Error{Detail: "failed to create device-mapper", Err: loadErr}, releaseErr)
		}
		return errors.Join(borrowErr, releaseErr)
	})
	return devNo, created, err
}

// activateCreated loads table into the target this call created and resumes
// it, confirming before each step that the name still names that target.
//
// devmapper addresses load and resume by NAME, so between this call's create
// and either step another process could remove the target and create its own
// under the same name; loading our table into it would make it our plaintext
// mapping under someone else's control. The check is not atomic with the
// ioctl that follows it, and the residual is the same one the rollback
// documents, but it is no longer the whole window from create to resume.
func activateCreated(name, uuid string, devNo uint64, table devmapper.Table) error {
	if err := confirmCreated(name, uuid, devNo); err != nil {
		return err
	}
	if err := dm.load(name, table); err != nil {
		return err
	}
	if err := confirmCreated(name, uuid, devNo); err != nil {
		return err
	}
	return dm.resume(name)
}

// confirmCreated reports an error unless name is still the target this call
// created: the same UUID and the device number the create returned.
func confirmCreated(name, uuid string, devNo uint64) error {
	current, err := dm.infoByName(name)
	if err != nil {
		return &VolumeError{Volume: name, Op: "confirm the identity of the target created for", Err: err}
	}
	if current.UUID != uuid || current.DevNo != devNo {
		return &VolumeError{Volume: name, Op: "activate", Err: &errs.Error{
			Detail: "the device-mapper target this unlock created was replaced before it was activated"}}
	}
	return nil
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
// which is already on the device; see areacipher.Transform.DecryptEnclave.
func unlockKeyslot(device string, keyslotID string, passphrase []byte, keyslot *Keyslot, digests map[string]*Digest) (*enclave.MemoryEnclave, error) {
	f, err := openDevice("read the keyslot area", device, os.O_RDONLY)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()

	return unlockKeyslotFrom(f, keyslotID, passphrase, keyslot, digests)
}

// unlockKeyslotFrom is unlockKeyslot reading the keyslot area through dev, a
// descriptor the caller already holds -- the locked one, for a keyslot operation
// pinned to the device it locked (#249, A10).
func unlockKeyslotFrom(dev io.ReaderAt, keyslotID string, passphrase []byte, keyslot *Keyslot, digests map[string]*Digest) (*enclave.MemoryEnclave, error) {
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

	// Derive the key that WRAPS the area, to the AREA's key size -- which is
	// not the volume key's (#249, A6). cryptsetup --keyslot-key-size writes
	// them differently, and deriving to keyslot.KeySize decrypted such a
	// keyslot with the wrong key. Through passphraseKDF so the injected-key
	// path's tests can prove it never gets here; see UnlockWithVolumeKey.
	passphraseKey, err := passphraseKDF(passphrase, keyslot.KDF, plan.areaKeySize)
	if err != nil {
		return nil, err
	}
	defer custody.Release(passphraseKey)

	return recoverKeyslotKey(dev, keyslotID, keyslot, plan, passphraseKey, digests)
}

// recoverKeyslotKey is unlockKeyslotFrom past the derivation: it reads the area
// the screen bounded, decrypts it under the area key, merges the stripes and
// verifies the result against the digests that attest the keyslot.
//
// It is split out so a keyslot just WRITTEN can be read back through exactly
// this path with the area key its writer already holds (verifyWrittenKeyslot):
// the read-back then proves what the next unlock will see without paying the
// KDF a second time.
func recoverKeyslotKey(dev io.ReaderAt, keyslotID string, keyslot *Keyslot, plan keyslotPlan,
	passphraseKey *enclave.MemoryEnclave, digests map[string]*Digest) (*enclave.MemoryEnclave, error) {
	// The area bounds come from the screen, which parsed and bounded them --
	// see screenKeyslot.
	encryptedKeyMaterial := make([]byte, plan.areaSize)
	defer clearBytes(encryptedKeyMaterial)
	if _, err := dev.ReadAt(encryptedKeyMaterial, plan.areaOffset); err != nil {
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
	decryptedKeyMaterial, err := plan.area.DecryptEnclave(custody, encryptedKeyMaterial[:plan.decryptLen], passphraseKey)
	if err != nil {
		return nil, err
	}
	defer custody.Release(decryptedKeyMaterial)

	if decryptedKeyMaterial.Size() < plan.afSplitSize {
		return nil, &UnlockError{Op: "decrypt keyslot " + keyslotID,
			Detail: fmt.Sprintf("decrypted data too small: got %d, need %d", decryptedKeyMaterial.Size(), plan.afSplitSize)}
	}

	masterKey, err := afCodec().Merge(decryptedKeyMaterial, keyslot.KeySize, af.Params{Stripes: keyslot.AF.Stripes, Hash: keyslot.AF.Hash})
	if err != nil {
		return nil, err
	}

	// Verify master key using the digests that authenticate THIS keyslot
	if err := verifyMasterKey(masterKey, keyslotID, digests); err != nil {
		custody.Release(masterKey)
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
	return verifyKeyAgainstDigests(masterKey, digests,
		func(digest *Digest) bool { return digestCovers(digest, keyslotID) },
		func(applicable int) error { return unverifiableKeyslotError(keyslotID, applicable) })
}

// verifyVolumeKeyForSegment verifies a volume key the CALLER supplied against
// the digests the header says authenticate the crypt segment being mapped.
//
// There is no keyslot on this path, so the keyslot association verifyMasterKey
// filters on does not exist. The association that does is the digest's
// "segments" array, and it is the one cryptsetup consults when it activates a
// volume by volume key: the key must be attested FOR THE SEGMENT IT WILL
// DECRYPT. Everything else -- which digests are usable, that an error folds
// into the same verdict as a mismatch, when a header fault may be named -- is
// verifyMasterKey's reasoning unchanged, because it is the same loop.
//
// # The key's LENGTH is checked separately, because the digest cannot check it
//
// The digest is PBKDF2-HMAC over the key, and HMAC zero-pads a key shorter than
// the hash's block size before using it. So a key and the same key with zero
// bytes appended -- up to the block size, 128 bytes for sha512 -- produce the
// SAME digest. On the passphrase path that cannot matter: the key comes out of
// a keyslot at exactly that keyslot's key_size. Here the caller chooses the
// length, and a 32-byte volume key padded with 32 zeros would verify and then
// be handed to dm-crypt as a 64-byte aes-xts key, mapping garbage as plaintext.
//
// The length is therefore required to equal the key_size recorded by a keyslot
// the attesting digest names, and a digest is only consulted if it names one of
// that size -- which is cryptsetup's rule too: it takes the volume key size
// from the keyslots and refuses a volume key of any other. A volume whose
// digest names no keyslot records no key size and cannot be checked, so it is
// refused as a header fault. The format seam never produces one: a volume
// formatted around an injected key always carries its recovery keyslot.
func verifyVolumeKeyForSegment(volumeKey *enclave.MemoryEnclave, segmentID string, metadata *LUKS2Metadata) error {
	size := volumeKey.Size()

	coversSegment := func(digest *Digest) bool {
		return digest != nil && slices.Contains(digest.Segments, segmentID)
	}
	namesKeyslotOfSize := func(digest *Digest) bool {
		return slices.ContainsFunc(digest.Keyslots, func(id string) bool {
			keyslot := metadata.Keyslots[id]
			return keyslot != nil && keyslot.KeySize == size
		})
	}

	// Whether the header records ANY key size for this segment, and whether
	// this key's is one of them. Both come off cleartext header fields, so
	// saying so tells a reader nothing the device does not.
	recorded, matches := false, false
	for _, digest := range metadata.Digests {
		if !coversSegment(digest) {
			continue
		}
		for _, id := range digest.Keyslots {
			if keyslot := metadata.Keyslots[id]; keyslot != nil && keyslot.KeySize > 0 {
				recorded = true
				matches = matches || keyslot.KeySize == size
			}
		}
	}
	if !recorded {
		return &UnlockError{Op: "verify the volume key", Err: ErrInvalidHeader,
			Detail: fmt.Sprintf("no keyslot named by a digest of segment %s records the volume key size, so a supplied volume key cannot be checked", segmentID)}
	}
	if !matches {
		return &UnlockError{Op: "verify the volume key", Err: ErrMasterKeyVerification,
			Detail: fmt.Sprintf("the supplied key is %d bytes, which no keyslot of segment %s records as the volume key size", size, segmentID)}
	}

	// Each digest is derived at most once here, and the header carries at most
	// LUKS2MaxKeyslots of them (validateObjectCounts), so this is within the
	// operation budget by construction (#26).
	return verifyKeyAgainstDigests(volumeKey, metadata.Digests,
		func(digest *Digest) bool { return coversSegment(digest) && namesKeyslotOfSize(digest) },
		func(applicable int) error {
			return &UnlockError{Op: "verify the volume key", Err: ErrInvalidHeader,
				Detail: fmt.Sprintf("all %d digests that authenticate segment %s are unusable, so a supplied volume key could not be compared against any of them", applicable, segmentID)}
		})
}

// verifyKeyAgainstDigests is the comparison loop both verifications share. It
// tries every digest `covers` selects, and reports through `unverifiable` the
// two header faults in which no comparison ran; see verifyMasterKey for why
// those, and only those, are distinguished.
func verifyKeyAgainstDigests(masterKey *enclave.MemoryEnclave, digests map[string]*Digest,
	covers func(*Digest) bool, unverifiable func(applicable int) error) error {
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
		if !covers(digest) {
			continue
		}
		applicable++

		// The screen, the derivation and the comparison are evaluateDigest's;
		// see it for why each is done the way it is.
		//
		// A digest that fails any of it is SKIPPED, not fatal -- the symmetry
		// #58 established -- so one unusable digest cannot hide a usable one
		// behind it.
		ok, matched := evaluateDigest(masterKey, digest)
		if !ok {
			continue // unusable digest -- try the next one (#58)
		}
		evaluated++
		if matched {
			return nil // Verification successful
		}
	}

	// No digest in the header attests this keyslot. That is a header defect, not
	// a credential verdict, and it must not be reported as one: an operator told
	// their passphrase failed would go looking at the passphrase, while the
	// actual state is that the container declares a keyslot nothing can verify.
	if applicable == 0 {
		return unverifiable(applicable)
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
		return unverifiable(applicable)
	}

	return ErrMasterKeyVerification
}

// evaluateDigest compares masterKey against ONE digest. evaluated is false when
// the digest could not be used at all -- it failed screenDigest, or its
// derivation was refused -- and in that case matched is false too and no
// comparison ran. verifyMasterKey counts the two outcomes separately; see its
// comments for why that difference is the line between a header fault and a
// credential verdict.
//
// It is the body of verifyMasterKey's loop, split out so MigrateToFIPS can ask
// "does this particular digest attest this key" before it replaces the digest,
// through the same screen and the same comparison the unlock uses.
func evaluateDigest(masterKey *enclave.MemoryEnclave, digest *Digest) (evaluated, matched bool) {
	// EVERY pre-derivation check lives in screenDigest, which the removal
	// guard also consumes -- see keyslotHasUsableDigest. This function used
	// to carry them inline, and the guard therefore had no way to ask the
	// question they answer: it settled for "is a digest ASSOCIATED with this
	// keyslot", counted a keyslot whose only digest could never be
	// evaluated, and authorized destroying the one that worked.
	//
	// It is consumed rather than repeated: `expected` and `kdf` are values
	// this function cannot obtain any other way, so the screen cannot be
	// skipped and a check added to it cannot fail to reach the guard.
	//
	// Deriving to the length ACTUALLY STORED, which screenDigest establishes,
	// is what cryptsetup does and is the only choice correct in both
	// directions. A cryptsetup-written sha512 volume stores 64 bytes and
	// needs 64 derived, which a hardcoded 32 could never produce (#73). A
	// volume written by an earlier version of THIS library stores 32 bytes
	// under a "sha512" label; deriving to the hash's natural 64 would render
	// every such volume unopenable.
	expected, kdf, err := screenDigest(digest)
	defer clearBytes(expected)
	if err != nil {
		return false, false
	}

	// The derivation borrows the master key in place; this package makes
	// no copy of it.
	//
	// It does leave protected memory once inside the KDF, though: pbkdf2
	// stringifies its password argument, so every digest tried here puts
	// the master key into an unwipeable Go string. See exposure 2 in
	// internal/secret. Trying N digests materializes it N times.
	derived, err := deriveKeySecret(masterKey, kdf, len(expected))
	if err != nil {
		return false, false // e.g. non-approved KDF in FIPS mode (#58)
	}

	// Compare using constant-time comparison to prevent timing attacks.
	// MemoryEnclave.EqualTo does exactly that, under the enclave's own read
	// lock, so the derived digest is never copied out to be compared. The
	// stored digest is a cleartext header field and is cleared anyway; the
	// derived one is destroyed before returning, so a caller trying several
	// digests never holds more than one locked region for them at a time.
	matched = derived.EqualTo(expected)
	custody.Release(derived)
	return true, matched
}

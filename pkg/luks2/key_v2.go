// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"fmt"
	"strconv"

	"github.com/jeremyhahn/go-enclave"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
)

// decodeDevNo splits a device-mapper device number into its major and
// minor, the exact inverse of the unix.Mkdev that creates nodes.
func decodeDevNo(devNo uint64) (major, minor uint32) {
	return unix.Major(devNo), unix.Minor(devNo)
}

// Key is a LUKS2 volume key bound to its volume and keyslot; its bytes are reachable only through volkey.Borrow inside this module.
type Key = volkey.Key

// Target is the dm-crypt activation parameters for an unlocked key. It
// carries no secret -- key is consulted only through Size(), never its
// bytes -- and that is the whole reason it is a plain, loggable struct.
type Target struct {
	Major, Minor   uint32
	Offset, Length uint64
	Cipher         string
	KeySize        int
	IVOffset       uint64
	SectorSize     int
	Flags          []string
}

// unlockHeader takes the shared lock, reads the primary header, checks requirements and selects the crypt segment; the caller unlocks the result.
func (v *Volume) unlockHeader(ctx context.Context, op string) (*device.Locked, string, *header.Metadata, error) {
	locked, err := v.lockFor(ctx, device.LockShared)
	if err != nil {
		return nil, "", nil, errAt(op, v.path, err)
	}

	// The current copy, not the primary alone: a torn primary must not refuse
	// a volume cryptsetup opens from the secondary (readCurrentHeader).
	cur, err := readCurrentHeader(locked.File())
	if err != nil {
		_ = locked.Unlock()
		return nil, "", nil, errAt(op, v.path, err)
	}
	metadata := cur.Metadata

	// A container mid an operation this package does not implement (an
	// interrupted cryptsetup reencrypt is the case that matters) must be
	// refused for activation, the same as for a write (#250, C2).
	if err := metadata.CheckRequirementsImplemented(); err != nil {
		_ = locked.Unlock()
		detail, _ := unsupportedRequirementDetail(err)
		return nil, "", nil, errAt(op, v.path, &errs.Error{Kind: ErrUnsupportedRequirement, Err: err,
			Detail: "activate the volume: " + detail + "; the container must be finished or recovered with the tool that set the requirement (for an interrupted reencryption: cryptsetup reencrypt --resume-only) before it can be activated"})
	}

	segmentID, _, err := activationSegment(metadata)
	if err != nil {
		_ = locked.Unlock()
		return nil, "", nil, errAt(op, v.path, err)
	}

	return locked, segmentID, metadata, nil
}

// Unlock tries the keyslots bound to the data segment against pass: PriorityPrefer, then PriorityNormal, each in id order; pass is only borrowed.
func (v *Volume) Unlock(ctx context.Context, pass enclave.ByteAccess) (*Key, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen("Volume.Unlock"); err != nil {
		return nil, err
	}

	const op = "Volume.Unlock"
	locked, _, metadata, err := v.unlockHeader(ctx, op)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locked.Unlock() }()

	var masterKey enclave.ByteAccess
	var slotID string
	err = secret.Borrow(op, pass, func(b []byte) error {
		var derr error
		masterKey, slotID, derr = getVolumeKey(ctx, locked.File(), v.path, b, metadata, v.sys)
		return derr
	})
	if err != nil {
		return nil, errAt(op, v.path, err)
	}

	slot, _ := strconv.Atoi(slotID) // slotID always came from header.CanonicalKeyslotID
	return volkey.New(masterKey, slot), nil
}

// UnlockKeyslot recovers the volume key from exactly keyslot, refusing with ErrKeyslotNotFound if it is missing or not bound to the data segment.
func (v *Volume) UnlockKeyslot(ctx context.Context, keyslot int, pass enclave.ByteAccess) (*Key, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen("Volume.UnlockKeyslot"); err != nil {
		return nil, err
	}

	const op = "Volume.UnlockKeyslot"
	locked, _, metadata, err := v.unlockHeader(ctx, op)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locked.Unlock() }()

	id := strconv.Itoa(keyslot)
	if !keyslotBoundToDataSegments(metadata, id) {
		return nil, errAt(op, v.path, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("keyslot %d does not exist or is not bound to the volume's data segment", keyslot)})
	}

	var masterKey enclave.ByteAccess
	err = secret.Borrow(op, pass, func(b []byte) error {
		var derr error
		masterKey, _, derr = getMasterKeySlot(ctx, locked.File(), v.path, b, metadata, []string{id}, v.sys)
		return derr
	})
	if err != nil {
		return nil, errAt(op, v.path, err)
	}
	return volkey.New(masterKey, keyslot), nil
}

// UnlockWithVolumeKey verifies vk against the digests and returns a Key bound to no keyslot (Keyslot() is -1) holding its own copy.
func (v *Volume) UnlockWithVolumeKey(ctx context.Context, vk enclave.ByteAccess) (*Key, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen("Volume.UnlockWithVolumeKey"); err != nil {
		return nil, err
	}

	const op = "Volume.UnlockWithVolumeKey"
	if err := validateVolumeKey(vk); err != nil {
		return nil, errAt(op, v.path, err)
	}

	locked, segmentID, metadata, err := v.unlockHeader(ctx, op)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locked.Unlock() }()

	if err := verifyVolumeKeyForSegment(ctx, vk, segmentID, metadata); err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, ErrWrongKey), Detail: "open the volume with the supplied volume key", Err: err})
	}

	var cloned enclave.ByteAccess
	err = secret.Borrow(op, vk, func(b []byte) error {
		var cerr error
		cloned, cerr = v.sys.custody.Clone(op, b)
		return cerr
	})
	if err != nil {
		return nil, errAt(op, v.path, err)
	}
	return volkey.New(cloned, -1), nil
}

// Target computes dm-crypt parameters from the re-read header and refuses with ErrWrongKey a key that header does not verify.
func (v *Volume) Target(ctx context.Context, key *Key) (*Target, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	if err := v.checkOpen("Volume.Target"); err != nil {
		return nil, err
	}

	const op = "Volume.Target"
	locked, segmentID, metadata, err := v.unlockHeader(ctx, op)
	if err != nil {
		return nil, err
	}
	defer func() { _ = locked.Unlock() }()

	if err := volkey.Verify(key, func(vk enclave.ByteAccess) error {
		return verifyVolumeKeyForSegment(ctx, vk, segmentID, metadata)
	}); err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, ErrWrongKey),
			Detail: "verify the key against the volume's current header (a header rewritten since the key was unlocked, or another volume's key, does not verify)", Err: err})
	}

	f := locked.File()
	segment := metadata.Segments[segmentID]

	params, err := header.CryptTableParams(metadata, segmentID, segment)
	if err != nil {
		return nil, errAt(op, v.path, err)
	}

	offsetBytes, err := parseSize(segment.Offset)
	if err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "invalid segment offset", Err: err})
	}

	var sizeBytes int64
	if segment.Size == "dynamic" {
		devSize, err := deviceSizeFromFile(f)
		if err != nil {
			return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to get device size", Err: err})
		}
		sizeBytes = devSize - offsetBytes
	} else {
		sizeBytes, err = parseSize(segment.Size)
		if err != nil {
			return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "invalid segment size", Err: err})
		}
	}

	length, err := safeInt64ToUint64(sizeBytes)
	if err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "invalid segment size", Err: err})
	}
	backendOffset, err := safeInt64ToUint64(offsetBytes)
	if err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "invalid segment offset", Err: err})
	}

	backingDevNo, err := v.sys.blockDeviceOf(f)
	if err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, ErrInvalidArgument), Detail: "identify the device to map " + v.path, Err: err})
	}
	major, minor := decodeDevNo(backingDevNo)

	sectorSize, err := safeUint64ToInt(params.SectorSize)
	if err != nil {
		return nil, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrInvalidHeader), Detail: "invalid segment sector size", Err: err})
	}

	return &Target{
		Major:      major,
		Minor:      minor,
		Offset:     backendOffset,
		Length:     length,
		Cipher:     params.Encryption,
		KeySize:    key.Size() * 8,
		IVOffset:   params.IVTweak,
		SectorSize: sectorSize,
		Flags:      params.Flags,
	}, nil
}

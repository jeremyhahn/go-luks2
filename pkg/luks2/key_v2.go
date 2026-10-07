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

// Key is a LUKS2 volume key: a capability obtained only by unlocking, bound
// to the volume and the keyslot it was recovered from. Its bytes are not
// exported; volkey.Borrow, reachable only inside this module, is the only
// route to them, so a consumer cannot extract the key through this type.
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

// unlockHeader takes the shared lock, reads the primary header, checks that
// every requirement it declares is implemented, and selects the one crypt
// segment activation maps. It is the common prefix every Unlock* method and
// Target need before they can derive or verify a key; the caller must
// unlock() the returned *device.Locked when done with it.
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
		return nil, "", nil, errAt(op, v.path, &errs.Error{Kind: ErrUnsupportedRequirement, Err: err,
			Detail: "activate the volume: the container must be finished or recovered with the tool that set the requirement (for an interrupted reencryption: cryptsetup reencrypt --resume-only) before it can be activated"})
	}

	segmentID, _, err := activationSegment(metadata)
	if err != nil {
		_ = locked.Unlock()
		return nil, "", nil, errAt(op, v.path, err)
	}

	return locked, segmentID, metadata, nil
}

// Unlock recovers the volume key by trying every keyslot bound to the
// volume's data segment against pass, in the same scan order the old
// Unlock uses. pass is the caller's enclave and stays the caller's: it is
// only ever borrowed.
func (v *Volume) Unlock(ctx context.Context, pass *enclave.MemoryEnclave) (*Key, error) {
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

	var masterKey *enclave.MemoryEnclave
	var slotID string
	err = secret.Borrow(op, pass, func(b []byte) error {
		var derr error
		masterKey, slotID, derr = getVolumeKey(ctx, locked.File(), v.path, b, metadata, v.sys)
		return derr
	})
	if err != nil {
		return nil, errAt(op, v.path, err)
	}

	slot, _ := strconv.Atoi(slotID) // slotID always came from canonicalKeyslotID
	return volkey.New(masterKey, slot), nil
}

// UnlockKeyslot recovers the volume key from exactly keyslot, refusing with
// ErrInvalidKeyslot if it is not bound to the volume's data segment --
// trying it anyway would risk recovering a key this volume's data segment
// was never encrypted with (#250).
func (v *Volume) UnlockKeyslot(ctx context.Context, keyslot int, pass *enclave.MemoryEnclave) (*Key, error) {
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

	var masterKey *enclave.MemoryEnclave
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

// UnlockWithVolumeKey verifies vk against the volume's digests and returns
// it as a Key bound to no keyslot (header.Keyslot() reports -1). vk is the
// caller's enclave and stays the caller's: the returned Key holds its own
// copy.
func (v *Volume) UnlockWithVolumeKey(ctx context.Context, vk *enclave.MemoryEnclave) (*Key, error) {
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

	var cloned *enclave.MemoryEnclave
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

// Target computes the dm-crypt activation parameters for the volume's
// current header, re-reading it under the shared lock. key is consulted
// only for its size.
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

	f := locked.File()
	segment := metadata.Segments[segmentID]

	params, err := cryptTableParams(metadata, segmentID, segment)
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

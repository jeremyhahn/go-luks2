// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package luks2

import (
	"context"
	"fmt"
	"os"
	"strconv"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	"github.com/jeremyhahn/go-luks2/internal/header"
	"github.com/jeremyhahn/go-luks2/internal/secret"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
)

// keyslotDeviceFor pins locked (already held by v.lockFor) as the
// keyslotDevice every write path below is built on, through the same
// requireLockableDevice check lockKeyslotDevice's callers already get.
func (v *Volume) keyslotDeviceFor(locked *device.Locked) (*keyslotDevice, error) {
	return pinnedKeyslotDevice(&deviceLock{locked: locked}, v.path, v.sys)
}

// onDiskPriority converts p to the *int addKeyslotWithMasterKeyAndPriority
// writes: nil for PriorityNormal, matching the on-disk convention that an
// absent priority member already means normal (see listKeyslotsFrom and
// the "NO PRIORITY IS WRITTEN" comment on addKeyslotWithMasterKeyAndPriority).
// onDiskPriority is the single rule every priority-writing path
// (AddKeyslot, ChangeKeyslot, Enroll, AddRecoveryKey) applies: an explicit
// member is written ONLY for PriorityPrefer.
//
// This is narrower than "write whatever p says" because DESIGN.md §B.2
// makes PriorityIgnore Priority's zero value -- the literal enum order --
// while this package's own, pre-existing convention (the on-disk
// keyslotPriorityIgnore/Normal/Prefer block above) has always read an
// ABSENT member as normal, specifically so a caller who never touches
// Priority does not get a silently-skipped keyslot. A caller that leaves
// KeyslotParams.Priority unset therefore produces the Go zero value
// PriorityIgnore, which is indistinguishable from an explicit request to
// ignore the slot; writing it literally would make every default-priority
// AddKeyslot/Enroll/AddRecoveryKey call silently create an ignored keyslot.
// Treating PriorityIgnore the same as PriorityNormal -- both absent, both
// read back as normal -- is the safe side of that ambiguity: no call
// through this field can ever create a keyslot an unlock silently skips.
//
// This is a genuine DESIGN.md defect (flagged in DECISIONS.md's H9e entry),
// not something resolved here by reordering the Priority enum unilaterally:
// that is the owner's call, since Priority is depended on by every §B.2
// keyslot-writing path, not just this one. Until then, a caller that wants
// PriorityIgnore in fact has no way to ask for it through KeyslotParams.
func onDiskPriority(p Priority) *int {
	if p != PriorityPrefer {
		return nil
	}
	v := int(p)
	return &v
}

// cloneKeyEnclave borrows key's bytes into a NEW enclave this call owns --
// the same pattern (*Volume).UnlockWithVolumeKey uses to hand back an
// independently destroyable copy. addKeyslotWithMasterKeyAndPriority and
// changeKeyslotCore need an *enclave.MemoryEnclave of their own; key's bytes
// are reachable only through volkey.Borrow's window, never as a value this
// package can hold past it.
func cloneKeyEnclave(op string, v *Volume, key *Key) (*enclave.MemoryEnclave, error) {
	var cloned *enclave.MemoryEnclave
	err := volkey.Borrow(op, key, func(b []byte) error {
		var cerr error
		cloned, cerr = v.sys.custody.Clone(op, b)
		return cerr
	})
	if err != nil {
		return nil, err
	}
	return cloned, nil
}

// keyslotInfoFor reads back the keyslot a write just created or changed, by
// id, through the same listKeyslotsFrom the read model's Keyslots() uses --
// so AddKeyslot and ChangeKeyslot report exactly what Keyslots() would.
func keyslotInfoFor(metadata *header.Metadata, slot int, op, path string) (KeyslotInfo, error) {
	slots, _ := listKeyslotsFrom(metadata)
	for _, s := range slots {
		if s.ID == slot {
			return s, nil
		}
	}
	return KeyslotInfo{}, errAt(op, path, &errs.Error{Kind: errs.ErrIO, Detail: fmt.Sprintf("keyslot %d written but not found while reading it back", slot)})
}

// AddKeyslot enrolls a new passphrase in a free keyslot (or p.Slot), wrapping
// the volume key key already holds (DESIGN.md §B.2). It takes no existing
// credential: key is the caller's proof of ownership, which is what AddKey's
// old passphrase argument was for.
func (v *Volume) AddKeyslot(ctx context.Context, key *Key, pass *enclave.MemoryEnclave, p KeyslotParams) (KeyslotInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	const op = "Volume.AddKeyslot"
	if err := v.checkOpen(op); err != nil {
		return KeyslotInfo{}, err
	}
	if err := v.checkWritable(op); err != nil {
		return KeyslotInfo{}, err
	}
	if err := p.KDF.Validate(); err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}

	opts := p.toAddKeyOptions()
	opts.Keyslot = p.Slot
	if err := refuseSHA1ForCreation(opts.KDFType, opts.Hash); err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	if err := validateArgon2CreateCost(callerArgon2Options(opts)); err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err})
	}

	clonedKey, err := cloneKeyEnclave(op, v, key)
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	defer v.sys.custody.Release(clonedKey)

	priority := onDiskPriority(p.Priority)

	var slot int
	err = secret.Borrow(op, pass, func(b []byte) error {
		if verr := validatePassphraseBytes(b); verr != nil {
			return verr
		}
		var aerr error
		slot, aerr = addKeyslotWithMasterKeyAndPriority(ctx, dev, hdr, metadata, clonedKey, b, opts, callerSuppliedCredential, priority)
		return aerr
	})
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}

	return keyslotInfoFor(metadata, slot, op, v.path)
}

// ChangeKeyslot re-wraps key's volume key under a new passphrase, in the
// keyslot key was recovered from (DESIGN.md §B.2: "the slot key came from").
// p.Slot is not consulted -- the slot is key's, not a choice this call
// makes -- and, as for the old ChangeKey this shares its write path with,
// the keyslot's existing KDF cost is preserved rather than re-read from p:
// a passphrase rotation is not a request to re-cost the slot (see
// changeKeyslotCore). p.Priority IS consulted and written (onDiskPriority),
// the same way AddKeyslot's is: a rotation can re-prioritize the slot even
// though it cannot re-cost it.
func (v *Volume) ChangeKeyslot(ctx context.Context, key *Key, pass *enclave.MemoryEnclave, p KeyslotParams) (KeyslotInfo, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	const op = "Volume.ChangeKeyslot"
	if err := v.checkOpen(op); err != nil {
		return KeyslotInfo{}, err
	}
	if err := v.checkWritable(op); err != nil {
		return KeyslotInfo{}, err
	}

	slot := key.Keyslot()
	if slot < 0 || slot >= MaxKeyslots {
		return KeyslotInfo{}, errAt(op, v.path, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("%d (must be 0-%d)", slot, MaxKeyslots-1)})
	}
	slotIDStr := strconv.Itoa(slot)

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err})
	}

	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return KeyslotInfo{}, errAt(op, v.path, &errs.Error{Kind: ErrKeyslotNotFound,
			Detail: fmt.Sprintf("keyslot %d does not exist", slot)})
	}

	clonedKey, err := cloneKeyEnclave(op, v, key)
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	defer v.sys.custody.Release(clonedKey)

	// A passphrase change is not a request to re-prioritize the slot. The
	// zero Priority -- which onDiskPriority already reads as "not asked for",
	// never as a request to ignore the slot -- keeps whatever priority the
	// keyslot has, "prefer" or a cryptsetup-written "ignore" alike; only an
	// explicit PriorityNormal or PriorityPrefer rewrites it.
	if p.Priority != PriorityIgnore {
		targetKeyslot.Priority = onDiskPriority(p.Priority)
	}

	err = secret.Borrow(op, pass, func(b []byte) error {
		if verr := validatePassphraseBytes(b); verr != nil {
			return verr
		}
		return changeKeyslotCore(ctx, dev, hdr, metadata, slotIDStr, slot, targetKeyslot, clonedKey, b)
	})
	if err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}

	return keyslotInfoFor(metadata, slot, op, v.path)
}

// RemoveKeyslot removes slot, refusing with ErrLastKeyslot if nothing else
// could still open the volume afterward. It takes no credential (owner
// ruling, DESIGN.md §B.2): authorization to remove a keyslot is the caller's
// policy, the same as the old KillKeyslot's.
func (v *Volume) RemoveKeyslot(ctx context.Context, slot int) error {
	v.mu.Lock()
	defer v.mu.Unlock()
	const op = "Volume.RemoveKeyslot"
	if err := v.checkOpen(op); err != nil {
		return err
	}
	if err := v.checkWritable(op); err != nil {
		return err
	}
	if slot < 0 || slot >= MaxKeyslots {
		return errAt(op, v.path, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("%d (must be 0-%d)", slot, MaxKeyslots-1)})
	}

	locked, err := v.lockFor(ctx, device.LockExclusive)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = locked.Unlock() }()

	dev, err := v.keyslotDeviceFor(locked)
	if err != nil {
		return errAt(op, v.path, err)
	}

	// Claimed EXCLUSIVELY (#246 D4): RemoveKeyslot takes no credential, so
	// this claim is the only thing standing between a volume that is open,
	// or a device something else holds, and a keyslot being destroyed out
	// from under it. The claim reopens the locked descriptor's own
	// /proc/self/fd entry (device.Locked.Claim), the same way Format and
	// Erase already claim theirs, so a path retargeted after the lock was
	// taken cannot move the claim to a different device than the one this
	// removal is proven against. Nothing below writes through claimed: the
	// write still goes through dev's own locked descriptor, exactly as
	// Format and Erase do.
	claimed, err := locked.Claim(ctx, "remove the keyslot", os.O_RDWR|os.O_EXCL, v.sys.openFile)
	if err != nil {
		return errAt(op, v.path, err)
	}
	defer func() { _ = claimed.Close() }()

	hdr, metadata, err := dev.readHeader()
	if err != nil {
		return errAt(op, v.path, &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to read header", Err: err})
	}

	slotIDStr := strconv.Itoa(slot)
	targetKeyslot, exists := metadata.Keyslots[slotIDStr]
	if !exists {
		return errAt(op, v.path, &errs.Error{Kind: ErrKeyslotNotFound, Detail: fmt.Sprintf("keyslot %d does not exist", slot)})
	}

	if err := removeKeyslotCore(ctx, dev, hdr, metadata, slotIDStr, targetKeyslot); err != nil {
		return errAt(op, v.path, err)
	}
	return nil
}

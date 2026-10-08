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
// and ChangeKeyslot write, the inverse of priorityFromDisk: nil (no member)
// for PriorityDefault and PriorityNormal, matching the on-disk convention
// that an absent priority means normal and cryptsetup's own omission of it;
// int(p)-1 for everything else, so PriorityIgnore writes 0 and
// PriorityPrefer writes 2. It is the single rule every priority-writing path
// (AddKeyslot, ChangeKeyslot, Enroll, AddRecoveryKey) applies.
//
// An undeclared Priority maps outside 0..2 and is refused by
// addKeyslotWithMasterKeyAndPriority (and by ChangeKeyslot before it writes),
// never written.
func onDiskPriority(p Priority) *int {
	if p == PriorityDefault || p == PriorityNormal {
		return nil
	}
	v := int(p) - 1
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
	if err := p.KDF.validateWith(v.sys.fipsMode); err != nil {
		return KeyslotInfo{}, errAt(op, v.path, err)
	}
	if !p.Priority.valid() {
		return KeyslotInfo{}, errAt(op, v.path, errInvalidPriority(p.Priority))
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
// makes. A zero p.KDF keeps the keyslot's existing KDF type and cost, as the
// old ChangeKey this shares its write path with does (a PBKDF2-SHA1 slot is
// still rewritten as PBKDF2-SHA256; see changeKeyslotCore). A non-zero p.KDF
// re-costs the slot exactly as AddKeyslot would write it -- the same
// validation, the same FIPS refusal of Argon2, the same benchmark when only
// IterTime is given -- which is cryptsetup luksChangeKey's --pbkdf* behavior.
// p.Priority is consulted too: PriorityDefault keeps the slot's existing
// priority, and any other value is written (onDiskPriority) the same way
// AddKeyslot's is.
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
	if !p.Priority.valid() {
		return KeyslotInfo{}, errAt(op, v.path, errInvalidPriority(p.Priority))
	}
	// An explicit KDF is held to everything AddKeyslot holds one to, before
	// the lock is taken; a zero one is the slot's own cost and needs none.
	var recost *addKeyOptionsForTest
	if p.KDF != (KDFParams{}) {
		if err := p.KDF.validateWith(v.sys.fipsMode); err != nil {
			return KeyslotInfo{}, errAt(op, v.path, err)
		}
		recost = p.toAddKeyOptions()
		if err := refuseSHA1ForCreation(recost.KDFType, recost.Hash); err != nil {
			return KeyslotInfo{}, errAt(op, v.path, err)
		}
		if err := validateArgon2CreateCost(callerArgon2Options(recost)); err != nil {
			return KeyslotInfo{}, errAt(op, v.path, err)
		}
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

	// A passphrase change is not a request to re-prioritize the slot:
	// PriorityDefault keeps whatever priority the keyslot has, "prefer" or a
	// cryptsetup-written "ignore" alike. Any explicit value rewrites it.
	if p.Priority != PriorityDefault {
		targetKeyslot.Priority = onDiskPriority(p.Priority)
	}

	err = secret.Borrow(op, pass, func(b []byte) error {
		if verr := validatePassphraseBytes(b); verr != nil {
			return verr
		}
		return changeKeyslotCore(ctx, dev, hdr, metadata, slotIDStr, slot, targetKeyslot, clonedKey, b, recost)
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

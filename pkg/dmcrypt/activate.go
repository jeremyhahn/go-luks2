// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package dmcrypt is activation: the kernel keyring plus device-mapper
// (root). It is the only way to keep pkg/luks2 rootless and exec-free.
//
// Activate calls (*luks2.Volume).Target, which re-reads the header under
// the volume's own shared lock, re-verifies the key against it -- a key the
// re-read header does not verify is refused with luks2.ErrWrongKey -- and
// re-derives the dm-crypt table parameters; it then maps the pinned descriptor's major:minor, never a
// path. The mapping is a transaction from the moment its create ioctl
// succeeds: every failure after that point rolls the target back, under a
// cancellation-proof context and its own clock budget, so a canceled
// caller never leaves a plaintext device behind.
package dmcrypt

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/anatol/devmapper.go"
	"golang.org/x/sys/unix"

	dmpkg "github.com/jeremyhahn/go-luks2/internal/dm"
	"github.com/jeremyhahn/go-luks2/internal/errs"
	keyringpkg "github.com/jeremyhahn/go-luks2/internal/keyring"
	"github.com/jeremyhahn/go-luks2/internal/volkey"
	"github.com/jeremyhahn/go-luks2/pkg/luks2"
)

// dmUUIDMaxLength is the longest dm UUID the kernel stores: DM_UUID_LEN
// (129) less its terminating NUL.
const dmUUIDMaxLength = 128

// mappingUUID is the dm UUID of the mapping name of a volume whose header
// UUID is headerUUID: "CRYPT-LUKS2-<header uuid without dashes>-<name>",
// cryptsetup's form, cut to what the kernel stores.
//
// It is cut HERE, once, because the kernel cuts it anyway and every later
// identity check compares against what it stored. headerUUID is already
// NUL-trimmed by (*luks2.Header).UUID, so there is no C-string truncation
// to repeat here the way the pre-split code had to.
func mappingUUID(headerUUID, name string) string {
	uuid := "CRYPT-LUKS2-" + strings.ReplaceAll(headerUUID, "-", "") + "-" + name
	if len(uuid) > dmUUIDMaxLength {
		uuid = uuid[:dmUUIDMaxLength]
	}
	return uuid
}

// Activate maps key as a dm-crypt target over v's backing device, naming it
// name.
//
// THE KEY DOES NOT GO IN THE TABLE. dm-crypt accepts its volume key two
// ways: inline in the table it is handed, or as a REFERENCE into the
// calling task's kernel keyrings. This package only ever uses the
// reference; see internal/keyring's package documentation for why. There
// is no fallback: a keyring that cannot hold the key fails the activation
// with an error matching ErrKeyringUnavailable, by owner ruling
// (2026-08-31).
// safeInt64ToUint64 converts int64 to uint64 safely, returning an error on
// overflow. Private copy of pkg/luks2/security.go's unexported helper of
// the same name: dmcrypt must not import luks2's internal narrowing
// helpers (clean-code 4.3), so each package owning a checked conversion
// keeps its own.
func safeInt64ToUint64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrIntegerOverflow
	}
	return uint64(v), nil
}

func Activate(ctx context.Context, v *luks2.Volume, key *luks2.Key, name string) (*Mapping, error) {
	const op = "Activate"
	if err := ctxErr(ctx); err != nil {
		return nil, errs.At(pkgName, op, "", err)
	}
	if err := ValidateName(name); err != nil {
		return nil, errs.At(pkgName, op, "", err)
	}
	// Before any device-mapper or keyring call, so a missing argument is the
	// same typed refusal whatever privilege the caller runs with.
	if v == nil {
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "volume is required"})
	}
	if key == nil {
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "key is required"})
	}

	// An early, cheap refusal before any key material is touched. It is
	// NOT what keeps two activations of one name apart -- the create
	// ioctl is, see activateTable -- because this check and the create are
	// not atomic.
	if _, err := sys.infoByName(name); err == nil {
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: ErrActive,
			Detail: fmt.Sprintf("the device-mapper name %q is already in use", name)})
	} else if !dmpkg.IsNoSuchDevice(err) {
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "inspect the device-mapper target of " + name, Err: err})
	}

	header, err := v.Header(ctx)
	if err != nil {
		return nil, errs.At(pkgName, op, "", err)
	}
	target, err := v.Target(ctx, key)
	if err != nil {
		return nil, errs.At(pkgName, op, "", err)
	}

	return activateTarget(ctx, name, mappingUUID(header.UUID(), name), target, key)
}

// activateTarget is the half of Activate that runs once the target is
// described and the key re-verified: the create, the keyring handoff, the
// load and resume, the node and the readiness wait. From the create on it is
// a transaction: every failure rolls the created target back, under
// context.WithoutCancel so a cancelled caller still gets the rollback.
func activateTarget(ctx context.Context, name, uuid string, target *luks2.Target, key *luks2.Key) (*Mapping, error) {
	const op = "Activate"
	backend := fmt.Sprintf("%d:%d", target.Major, target.Minor)

	devNo, created, err := activateTable(ctx, name, uuid, backend, target, key)
	if err != nil {
		if !created {
			return nil, errs.At(pkgName, op, "", err)
		}
		return nil, errs.At(pkgName, op, "", errors.Join(err, rollback(context.WithoutCancel(ctx), name, uuid, devNo)))
	}

	info := &devmapper.DeviceInfo{Name: name, UUID: uuid, DevNo: devNo}

	// Ensure /dev/dm-N names this device (containers without udev need
	// it). Still NON-FATAL on its own -- the device may be reachable
	// through /dev/mapper/<name> without it -- but carried and reported
	// alongside the readiness failure it usually explains.
	nodeErr := sys.ensureNode(ctx, name, info)

	// Wait until /dev/mapper/<name> is verifiably THIS device.
	if err := sys.waitReady(ctx, name, info); err != nil {
		readiness := &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "device not ready after activation", Err: err}
		if nodeErr != nil {
			readiness.Detail = fmt.Sprintf("%s (creating the device node also failed: %v)", readiness.Detail, nodeErr)
		}
		return nil, errs.At(pkgName, op, "", errors.Join(readiness, rollback(context.WithoutCancel(ctx), name, uuid, devNo)))
	}

	major, minor := unix.Major(devNo), unix.Minor(devNo)
	return &Mapping{Name: name, UUID: uuid, Major: major, Minor: minor}, nil
}

// activateTable runs the whole activation -- create, keyring add, load,
// resume, keyring release -- with the volume key borrowed from its enclave
// for the keyring add and the load, and reports the device number of the
// target it created and whether it created one at all.
//
// created is the line Activate's rollback is drawn on. It is false when
// the call failed before its own create succeeded, which is the case the
// rollback must NOT touch: a create refused because the name is taken
// leaves the name to its owner.
//
// It runs on a thread of its own that is discarded afterwards: see
// internal/keyring.RunOnDiscardedThread.
func activateTable(ctx context.Context, name, uuid, backend string, target *luks2.Target, key *luks2.Key) (devNo uint64, created bool, err error) {
	err = keyringpkg.RunOnDiscardedThread(func() error {
		var createErr error
		devNo, createErr = sys.create(ctx, name, uuid)
		if createErr != nil {
			if errors.Is(createErr, unix.EBUSY) {
				// The kernel's answer for a name or UUID already in use:
				// another activation got there first, and its mapping is
				// its own.
				return &errs.Error{Kind: ErrActive,
					Detail: fmt.Sprintf("the device-mapper name %q was taken by another activation (%v)", name, createErr)}
			}
			return &errs.Error{Kind: errs.KindOf(createErr, errs.ErrIO), Detail: "failed to create device-mapper", Err: createErr}
		}
		created = true

		// target.SectorSize came from luks2.Target as a validated int; the
		// checked conversion (the same one Target itself uses) is kept
		// here too rather than a bare uint64(...), so a future caller that
		// builds a Target by hand cannot smuggle a negative value into the
		// dm-crypt table.
		sectorSize, sizeErr := safeInt64ToUint64(int64(target.SectorSize))
		if sizeErr != nil {
			return &errs.Error{Kind: errs.KindOf(sizeErr, errs.ErrInvalidArgument), Detail: "invalid segment sector size", Err: sizeErr}
		}

		if sectorSize == 0 {
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "invalid segment sector size 0"}
		}

		var loadErr, releaseErr error
		borrowErr := volkey.Borrow("Activate", key, func(b []byte) error {
			// The devmapper library expects Length and BackendOffset in
			// BYTES (it converts them to sectors internally).
			table := devmapper.CryptTable{
				Start:         0,
				Length:        target.Length - target.Length%sectorSize, // rounded down: dm-crypt refuses a length that is not a sector multiple
				BackendDevice: backend,
				BackendOffset: target.Offset,
				Encryption:    target.Cipher,
				IVTweak:       target.IVOffset,
				SectorSize:    sectorSize,
				Flags:         target.Flags,
			}

			// Key is deliberately NOT set, here or anywhere else in this
			// package: devmapper's buildSpec takes KeyID when it is
			// non-empty and only falls back to hex.EncodeToString(Key)
			// when it is empty, so an unassigned Key makes the hex
			// encoding structurally unreachable rather than merely
			// unused.
			keyEntry, keyringErr := keyringpkg.AddVolumeKey(ctx, sys.keyring, uuid, b)
			if keyringErr != nil {
				return classifyKeyringErr(keyringErr)
			}

			// Released before this closure returns, on every path
			// including a panic, so the entry cannot outlive the
			// activation.
			defer func() { releaseErr = classifyKeyringErr(keyEntry.Release(sys.keyring)) }()
			table.KeyID = keyEntry.TableKeyID()

			loadErr = activateCreated(name, uuid, devNo, table)
			return loadErr
		})

		// The release is checked whatever the activation did. A keyring
		// entry left holding the volume key is a custody failure in its
		// own right, and one that a successful activation would
		// otherwise hide completely -- so it fails the activation, and
		// Activate rolls the mapping back.
		if borrowErr == nil {
			return releaseErr
		}
		if loadErr != nil {
			return errors.Join(&errs.Error{Kind: errs.KindOf(loadErr, errs.ErrIO), Detail: "failed to create device-mapper", Err: loadErr}, releaseErr)
		}
		return errors.Join(borrowErr, releaseErr)
	})
	return devNo, created, err
}

// activateCreated loads table into the target this call created and
// resumes it, confirming before each step that the name still names that
// target.
//
// devmapper addresses load and resume by NAME, so between this call's
// create and either step another process could remove the target and
// create its own under the same name; loading our table into it would make
// it our plaintext mapping under someone else's control.
func activateCreated(name, uuid string, devNo uint64, table devmapper.Table) error {
	if err := confirmCreated(name, uuid, devNo); err != nil {
		return err
	}
	if err := sys.load(name, table); err != nil {
		return err
	}
	if err := confirmCreated(name, uuid, devNo); err != nil {
		return err
	}
	return sys.resume(name)
}

// confirmCreated reports an error unless name is still the target this
// call created: the same UUID and the device number the create returned.
func confirmCreated(name, uuid string, devNo uint64) error {
	current, err := sys.infoByName(name)
	if err != nil {
		return &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "confirm the identity of the target created for " + name, Err: err}
	}
	if current.UUID != uuid || current.DevNo != devNo {
		return &errs.Error{Kind: ErrDeviceChanged, Detail: "the device-mapper target this activate created was replaced before it was activated"}
	}
	return nil
}

// rollback tears down a dm target that THIS Activate created, and refuses
// to touch anything else.
//
// rollback is never cancellable: Activate derives ctx with
// context.WithoutCancel before calling in, so a canceled caller still gets
// a clean rollback rather than an abandoned plaintext device. ctx is still
// threaded through to retryWhileBusy and removeMappingNodes -- it bounds
// internal/dm's own retry budget the same way everywhere else -- it is
// simply never the caller's cancellable one.
//
// The target is identified by the dm UUID this activation generated AND by
// the device number its own create returned, so a concurrent activation of
// the same volume under the same name -- which carries an identical UUID
// -- is never mistaken for this one. See the pre-split
// pkg/luks2.removeCreatedMapping, whose reasoning this reproduces exactly.
func rollback(ctx context.Context, name, uuid string, devNo uint64) error {
	var (
		info        *devmapper.DeviceInfo
		inspectErr  error
		nothingToDo bool
	)

	attempts, err := retryWhileBusy(ctx, func() error {
		current, err := sys.infoByName(name)
		inspectErr = nil
		if err != nil {
			if dmpkg.IsNoSuchDevice(err) {
				nothingToDo = true
				return nil
			}
			inspectErr = err
			return err
		}
		if current.UUID != uuid || current.DevNo != devNo {
			nothingToDo = true
			return nil
		}
		info = current
		return sys.remove(name)
	})

	switch {
	case nothingToDo:
		return nil
	case inspectErr != nil:
		return &errs.Error{Kind: ErrStillLive, Detail: fmt.Sprintf(
			"device-mapper target %q could not be inspected after a failed activate (%v), so it cannot be confirmed removed; check for it with: dmsetup info %s",
			name, inspectErr, name)}
	case err != nil:
		return &errs.Error{Kind: ErrStillLive, Detail: fmt.Sprintf(
			"the plaintext device-mapper target %q created by this activate could not be removed after %d attempt(s) over %v (%v) and is STILL LIVE; close it with dmcrypt.Deactivate(ctx, %q)",
			name, attempts, dmpkg.RemoveRetryBudget, err, name)}
	}

	removeMappingNodes(ctx, name, info)
	return nil
}

// Deactivate closes a device-mapper mapping.
//
// There is deliberately nothing keyring-related here: the entry holding
// the volume key is released as soon as the activation ioctl returns, not
// kept for the mapping's lifetime, so by the time anything can be closed
// there is nothing left to release.
func Deactivate(ctx context.Context, name string) error {
	const op = "Deactivate"
	if err := ctxErr(ctx); err != nil {
		return errs.At(pkgName, op, "", err)
	}
	if err := ValidateName(name); err != nil {
		return errs.At(pkgName, op, "", err)
	}

	// The identity MUST be established before anything is removed, and
	// device-mapper is the only authority on it. No-such-device is the
	// typed not-active case, not a device-mapper failure.
	//
	// The capture is RETRIED on EBUSY like everything else on this path:
	// the lookup goes through the same device-mapper control path as the
	// close, so it is subject to the same transient hold (#122).
	var info *devmapper.DeviceInfo
	if _, err := retryWhileBusy(ctx, func() error {
		var err error
		info, err = sys.infoByName(name)
		return err
	}); err != nil {
		if dmpkg.IsNoSuchDevice(err) {
			return errs.At(pkgName, op, "", &errs.Error{Kind: ErrNotActive,
				Detail: fmt.Sprintf("no device-mapper mapping named %q exists", name)})
		}
		return errs.At(pkgName, op, "", &errs.Error{
			Kind:   errs.KindOf(err, errs.ErrIO),
			Detail: fmt.Sprintf("cannot establish the identity of mapping %q, so it will not be removed", name),
			Err:    err})
	}

	// A close rides out a transient hold rather than failing on it
	// (#122). The identity is re-confirmed before EVERY attempt: during a
	// backoff another actor can remove this target and create a
	// DIFFERENT mapping under the same name, and removing that one would
	// destroy a plaintext device this caller never opened.
	replaced := false
	attempts, err := retryWhileBusy(ctx, func() error {
		current, err := sys.infoByName(name)
		if err != nil {
			if dmpkg.IsNoSuchDevice(err) {
				replaced = true
				return nil
			}
			return err
		}
		if current.UUID != info.UUID || current.DevNo != info.DevNo {
			replaced = true
			return nil
		}
		return sys.remove(name)
	})
	if replaced {
		return nil
	}
	if err != nil {
		if errors.Is(err, unix.EBUSY) {
			return errs.At(pkgName, op, "", &errs.Error{
				Kind: ErrBusy,
				Detail: fmt.Sprintf(
					"%q was still held after %d attempts over %v; find the holder with `lsof /dev/mapper/%s`, `mount | grep %s` or `dmsetup info -c %s`, or schedule the removal for when it frees with `dmsetup remove --deferred %s`",
					name, attempts, dmpkg.RemoveRetryBudget, name, name, name, name),
				Err: err,
			})
		}
		return errs.At(pkgName, op, "", &errs.Error{Kind: errs.KindOf(err, errs.ErrIO), Detail: "failed to remove device-mapper", Err: err})
	}

	// Clean up device nodes that we may have created. This is the same
	// cleanup a rolled-back Activate performs, so the two leave the same
	// state behind.
	removeMappingNodes(ctx, name, info)

	return nil
}

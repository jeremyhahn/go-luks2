// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package dmcrypt activates a LUKS2 volume through the kernel keyring and device-mapper, rolling back any target it created on failure.
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

// mappingUUID is cryptsetup's dm UUID for mapping name of headerUUID, cut to what the kernel stores.
func mappingUUID(headerUUID, name string) string {
	uuid := "CRYPT-LUKS2-" + strings.ReplaceAll(headerUUID, "-", "") + "-" + name
	if len(uuid) > dmUUIDMaxLength {
		uuid = uuid[:dmUUIDMaxLength]
	}
	return uuid
}

// safeInt64ToUint64 converts int64 to uint64, returning an error on overflow.
func safeInt64ToUint64(v int64) (uint64, error) {
	if v < 0 {
		return 0, ErrIntegerOverflow
	}
	return uint64(v), nil
}

// Activate maps v's data segment as name with key, passing the key to dm-crypt as a kernel-keyring reference.
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

	// An early, cheap refusal; the create ioctl is what keeps two activations apart.
	if _, err := sys.infoByName(name); err == nil {
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: ErrActive,
			Detail: fmt.Sprintf("the device-mapper name %q is already in use", name)})
	} else if !dmpkg.IsNoSuchDevice(err) {
		return nil, errs.At(pkgName, op, "", &errs.Error{Kind: dmKind(err, errs.ErrIO), Detail: "inspect the device-mapper target of " + name, Err: err})
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

// activateTarget creates, keys, loads, resumes and verifies the target, rolling it back uncancellably on any failure after the create.
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

	// Ensure /dev/dm-N names this device; non-fatal, but reported with any readiness failure.
	nodeErr := sys.ensureNode(ctx, name, info)

	// Wait until /dev/mapper/<name> is verifiably this device.
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

// activateTable runs the whole activation on a discarded thread and reports the target's device number and whether it created one.
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
			return &errs.Error{Kind: dmKind(createErr, errs.ErrIO), Detail: "failed to create device-mapper", Err: createErr}
		}
		created = true

		// Checked conversion, so a hand-built Target cannot carry a negative sector size.
		sectorSize, sizeErr := safeInt64ToUint64(int64(target.SectorSize))
		if sizeErr != nil {
			return &errs.Error{Kind: errs.KindOf(sizeErr, errs.ErrInvalidArgument), Detail: "invalid segment sector size", Err: sizeErr}
		}

		if sectorSize == 0 {
			return &errs.Error{Kind: errs.ErrInvalidArgument, Detail: "invalid segment sector size 0"}
		}

		var loadErr, releaseErr error
		borrowErr := volkey.Borrow("Activate", key, func(b []byte) error {
			// devmapper takes Length and BackendOffset in bytes.
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

			// Key is never set: KeyID is used, so the hex encoding is unreachable.
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

		// A keyring entry left holding the key fails the activation, which then rolls back.
		if borrowErr == nil {
			return releaseErr
		}
		if loadErr != nil {
			return errors.Join(&errs.Error{Kind: dmKind(loadErr, errs.ErrIO), Detail: "failed to create device-mapper", Err: loadErr}, releaseErr)
		}
		return errors.Join(borrowErr, releaseErr)
	})
	return devNo, created, err
}

// activateCreated loads and resumes the target this call created, confirming before each step that the name still names it.
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
		return &errs.Error{Kind: dmKind(err, errs.ErrIO), Detail: "confirm the identity of the target created for " + name, Err: err}
	}
	if current.UUID != uuid || current.DevNo != devNo {
		return &errs.Error{Kind: ErrDeviceChanged, Detail: "the device-mapper target this activate created was replaced before it was activated"}
	}
	return nil
}

// rollback removes only the target this Activate created, matched by dm UUID and device number; ctx is never cancellable.
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

// Deactivate closes a device-mapper mapping; the keyring entry was already released at activation.
func Deactivate(ctx context.Context, name string) error {
	const op = "Deactivate"
	if err := ctxErr(ctx); err != nil {
		return errs.At(pkgName, op, "", err)
	}
	if err := ValidateName(name); err != nil {
		return errs.At(pkgName, op, "", err)
	}

	// Establish identity before removing anything, retrying on EBUSY; no such device is ErrNotActive.
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
			Kind:   dmKind(err, errs.ErrIO),
			Detail: fmt.Sprintf("cannot establish the identity of mapping %q, so it will not be removed", name),
			Err:    err})
	}

	// Retry a transient hold, re-confirming identity before every attempt.
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
		return errs.At(pkgName, op, "", &errs.Error{Kind: dmKind(err, errs.ErrIO), Detail: "failed to remove device-mapper", Err: err})
	}

	// Clean up device nodes that we may have created. This is the same
	// cleanup a rolled-back Activate performs, so the two leave the same
	// state behind.
	removeMappingNodes(ctx, name, info)

	return nil
}

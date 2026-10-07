// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

// Package device owns the LUKS2 device descriptor: pinning a path to an open
// file, the node flock and cryptsetup's own metadata lock taken on top of it,
// the O_EXCL claim that proves nothing else holds the device, its size, and
// reading its medium past the page cache. pkg/luks2 re-exports this
// package's sentinels and LockTimeoutError by value, so a caller's
// errors.Is/As is unaffected by where the classification happens to live.
package device

import (
	"errors"
	"fmt"
	"time"
)

// Sentinels shared by every package that opens, locks or reads a device.
// Defined once here (owner ruling, 2026-10-05: ErrMetadataLockUnavailable
// was already settled this way; the rest follow the same reasoning) and
// re-exported by value from pkg/luks2, so errors.Is holds regardless of
// which package's name a caller matches against.
var (
	// ErrNotFound indicates the device path doesn't exist.
	ErrNotFound = errors.New("luks2: device not found")

	// ErrPermissionDenied indicates that an operation could not open the
	// device because the process lacks access to it.
	ErrPermissionDenied = errors.New("luks2: permission denied")

	// ErrInUse indicates a destructive or exclusive operation refused a
	// block device that something else holds: it is mounted, it backs a
	// device-mapper mapping or an md array, or another process opened it
	// exclusively. The kernel reports this when the device is opened with
	// O_EXCL.
	ErrInUse = errors.New("luks2: the device is in use: it is mounted, mapped, or held open exclusively")

	// ErrChanged indicates that a device path resolved to a different file
	// when it was opened again than when it was locked: a symlink
	// re-pointed in between.
	ErrChanged = errors.New("luks2: the device path now names a different file than the one locked")

	// ErrCacheStale indicates that bytes read from the device through the
	// page cache differ from the same bytes read past it: another process
	// holds the device mapped, or an earlier write failed and left bytes in
	// the cache that never reached the medium.
	ErrCacheStale = errors.New("luks2: the device's page cache does not match what is on the medium")

	// ErrUnsupported indicates the device cannot be read past the page
	// cache: O_DIRECT is refused and the device is not on a memory
	// filesystem (where the cache is the only copy there is), or the
	// platform has no O_DIRECT at all. What is on the medium therefore
	// cannot be confirmed, and an operation that needs it confirmed refuses.
	ErrUnsupported = errors.New("luks2: the device cannot be read past the page cache, so what is on the medium cannot be confirmed")

	// ErrLockContended indicates that a lock on a device could not be taken
	// within the caller's wait budget, because another holder kept it for
	// the whole of that budget. See LockTimeoutError.
	ErrLockContended = errors.New("luks2: device lock is held by another process and did not become available")

	// ErrMetadataLockUnavailable indicates that cryptsetup's metadata lock
	// for a block device could not be taken at all: its directory
	// (/run/cryptsetup) is missing and cannot be created, is not a
	// directory, is a symlink, or does not admit the caller. Nothing was
	// read or written.
	ErrMetadataLockUnavailable = errors.New("luks2: cryptsetup's metadata lock for the device cannot be taken")
)

// PermissionRemedy is the operator guidance carried by every permission
// failure: an operator should be able to act on the error without reading
// the source.
const PermissionRemedy = "A LUKS2 container's header, keyslots and data segment are read and written on the RAW BLOCK DEVICE rather than through a filesystem, " +
	"so every operation in this library needs direct access to the device node -- there is no unprivileged path that does less. " +
	"Run as root, or give this process access to the node itself (on most distributions the node is owned by root and the `disk` group)"

// Error is a device/op/cause failure: what went wrong, doing what, to which
// device. pkg/luks2's DeviceError is a type alias of it, so every existing
// construction and type assertion in that package keeps working unchanged.
type Error struct {
	Device string
	Op     string
	Err    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s %s: %v", e.Op, e.Device, e.Err)
}

func (e *Error) Unwrap() error {
	return e.Err
}

// LockTimeoutError reports that a device lock could not be taken within the
// wait budget, and carries what an operator needs to act. pkg/luks2's
// LockTimeoutError is a type alias of it.
type LockTimeoutError struct {
	Path     string
	Waited   time.Duration
	Attempts int
	Err      error
}

func (e *LockTimeoutError) Error() string {
	return fmt.Sprintf("could not lock %s after waiting %s over %d attempts: %v (find the holder with `fuser -v %s` or `lsof %s`)",
		e.Path, e.Waited, e.Attempts, e.Err, e.Path, e.Path)
}

// Unwrap reports every LockTimeoutError as ErrLockContended -- so a caller
// can match the sentinel without depending on this type -- and keeps the
// underlying errno reachable too, so a caller that genuinely wants to know
// it was EWOULDBLOCK still can.
func (e *LockTimeoutError) Unwrap() []error {
	return []error{ErrLockContended, e.Err}
}

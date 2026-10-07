// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package wipe

import (
	"errors"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Error is the one error shape of this module (internal/errs): the sentinel
// that classifies the failure, Op and Path set at the exported entry, and the
// cause.
type Error = errs.Error

// LockTimeoutError reports that the exclusive lock on a device could not be
// taken within the wait budget. A type alias of internal/device's.
type LockTimeoutError = device.LockTimeoutError

var (
	// ErrVerification indicates that what was read back from the medium,
	// past every cache in front of it, is not what the last pass wrote.
	ErrVerification = errors.New("wipe: the medium does not hold what the last pass wrote")

	// ErrDeviceInUse indicates that Sanitize refused a device something
	// else holds open: it is mounted, mapped, or held exclusively. Defined
	// once in internal/device and re-exported by value (DESIGN.md C.2.6),
	// so errors.Is holds regardless of which package's name a caller
	// matches against.
	ErrDeviceInUse = device.ErrInUse

	// ErrDeviceChanged indicates that the device path resolved to a
	// different file when it was reopened for the exclusive claim than when
	// it was locked: a symlink re-pointed in between. Sanitize claims the
	// locked descriptor's own inode (never the path again), so this is
	// declared for API consistency with luks2 and dmcrypt rather than ever
	// raised by this package's own code.
	ErrDeviceChanged = device.ErrChanged

	// ErrPermissionDenied indicates that Sanitize could not open the device
	// because the process lacks access to it.
	ErrPermissionDenied = device.ErrPermissionDenied

	// ErrLockContended indicates that the exclusive lock on the device
	// could not be taken within the wait budget, because another holder
	// kept it for the whole of that budget. See LockTimeoutError.
	ErrLockContended = device.ErrLockContended
)

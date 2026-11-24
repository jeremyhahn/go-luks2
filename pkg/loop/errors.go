// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package loop

import (
	"errors"

	"github.com/jeremyhahn/go-luks2/internal/device"
	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Error is the one error shape of this module (internal/errs): the sentinel
// that classifies the failure, Op and Path set at the exported entry, and the
// cause.
type Error = errs.Error

// Sentinels that can be checked with errors.Is. Detail carries the object and
// the reason; these name only the classification.
var (
	// ErrNotFound indicates no loop device is attached to the file [Find] was
	// asked about. The text is matched by existing callers, so it is kept
	// exactly as it reads: "no loop device found".
	ErrNotFound = errors.New("loop: no loop device found")

	// ErrDetachIncomplete indicates the detach was accepted but something still held the device when the wait expired.
	ErrDetachIncomplete = errors.New("loop: detach did not become observable")

	// ErrNodeAbsent indicates a loop device was allocated but its /dev node did not appear within the wait budget.
	ErrNodeAbsent = errors.New("loop: allocated device's node did not appear under /dev")

	// ErrDeviceReassigned indicates [Device.Detach] refused because the device is now backed by another file.
	ErrDeviceReassigned = errors.New("loop: the device is now attached to a different file")

	// ErrPermissionDenied indicates an operation could not open a device
	// because the process lacks access to it. Defined once, in
	// internal/device, and re-exported by value.
	ErrPermissionDenied = device.ErrPermissionDenied
)

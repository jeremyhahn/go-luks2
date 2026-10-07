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
// the reason; these name only the classification (DESIGN.md C.2).
var (
	// ErrNotFound indicates no loop device is attached to the file [Find] was
	// asked about. The text is matched by existing callers, so it is kept
	// exactly as it reads: "no loop device found".
	ErrNotFound = errors.New("loop: no loop device found")

	// ErrDetachIncomplete indicates a loop device was told to detach and the
	// kernel had not released it before the wait expired. It is deliberately
	// distinct from a failed detach: the request succeeded, and something
	// else still holds the device open. An operator who reads "detach
	// failed" goes looking at the detach; this one has to go looking at what
	// else has the device.
	ErrDetachIncomplete = errors.New("loop: detach did not become observable")

	// ErrNodeAbsent indicates that the kernel allocated a loop device but no
	// device node for it appeared under /dev within the wait budget.
	//
	// THE ALLOCATION SUCCEEDED. LOOP_CTL_GET_FREE reserves a minor number and
	// returns it; creating the node is a separate job belonging to devtmpfs
	// or to udev, and neither is guaranteed to have finished -- or to be
	// running at all. So this is not "no loop devices available", which is
	// the reading the bare ENOENT invited: it means the number is ours and
	// the path to it does not exist yet.
	//
	// It is invisible until allocation passes the PRE-CREATED range,
	// typically loop0-loop7, because those nodes exist from boot. That is
	// why it presents as "works for the first N, fails past them", with N
	// depending on how many loop devices the host already has in use.
	ErrNodeAbsent = errors.New("loop: allocated device's node did not appear under /dev")

	// ErrPermissionDenied indicates an operation could not open a device
	// because the process lacks access to it. Defined once, in
	// internal/device, and re-exported by value.
	ErrPermissionDenied = device.ErrPermissionDenied
)

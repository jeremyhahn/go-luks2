// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"
)

// blkDiscard is the BLKDISCARD ioctl number for TRIM/discard on block
// devices.
const blkDiscard = 0x1277

// Discard issues BLKDISCARD for [0, size) of f, telling an SSD or a
// thin-provisioned device that the range holds nothing worth preserving. It
// is advisory: a device that does not support it has already been
// overwritten by whatever wrote f, so callers treat a failure as best-effort.
func Discard(f *os.File, size int64) error {
	if size <= 0 {
		return &Error{Device: f.Name(), Op: "BLKDISCARD", Err: unix.EINVAL}
	}

	// BLKDISCARD takes a uint64[2] array: [offset, length].
	discardRange := [2]uint64{0, uint64(size)} // #nosec G115 -- size was just checked positive

	// #nosec G103 -- unsafe.Pointer required for IOCTL syscall to pass array to kernel
	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		f.Fd(),
		uintptr(blkDiscard),
		uintptr(unsafe.Pointer(&discardRange[0])),
	)
	if errno != 0 {
		return &Error{Device: f.Name(), Op: "BLKDISCARD", Err: errno}
	}
	return nil
}

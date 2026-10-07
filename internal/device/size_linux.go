// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"os"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-luks2/internal/errs"
)

// Size reports the size of f: a block device's own size (BLKGETSIZE64), or a
// regular file's.
func Size(f *os.File) (int64, error) {
	var size int64
	// #nosec G103 -- unsafe.Pointer required for ioctl syscall
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, f.Fd(), unix.BLKGETSIZE64, uintptr(unsafe.Pointer(&size)))
	if errno == 0 {
		return size, nil
	}

	stat, err := f.Stat()
	if err != nil {
		return 0, &errs.Error{Kind: errs.ErrIO, Detail: "failed to get device/file size", Err: err}
	}
	return stat.Size(), nil
}

// Copyright (c) 2025 Jeremy Hahn
//
// SPDX-License-Identifier: Apache-2.0

package device

import (
	"os"

	"golang.org/x/sys/unix"
)

// DropCache evicts f's clean pages from the page cache; call it only after the device is synced.
func DropCache(f *os.File) error {
	return unix.Fadvise(int(f.Fd()), 0, 0, unix.FADV_DONTNEED)
}
